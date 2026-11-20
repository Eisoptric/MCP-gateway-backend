from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ActionStatus, ExecutionState, RunStatus
from app.core.ids import utcnow
from app.features.execution.approvals.models.approval import Approval
from app.features.execution.approvals.models.transitions import RELEASE, SETTLE
from app.features.execution.approvals.services.approval_arguments import seal_result
from app.features.execution.approvals.services.lifecycle import approval_lifecycle
from app.features.mcp.servers.services.mcp_remote import McpTimeout, split_reply
from app.models import Action, Run

logger = logging.getLogger(__name__)


class OutcomeUncertain(Exception):
    """The call may have reached the upstream. It is settled as uncertain and is never sent again by itself."""


class OutcomeUnrecorded(OutcomeUncertain):
    """The call ran, but saving what it returned failed."""


class NotSent(Exception):
    """Raised by `send` when it stopped before anything left Eisoptric. The reason is its __cause__."""


@dataclass(frozen=True)
class Executed:
    result: dict[str, Any]  # what the tool answered
    raw: dict[str, Any]  # the reply as the upstream sent it


def is_uncertain(exc: BaseException) -> bool:
    """Whether a failed call may still have run. A timeout says nothing about what the upstream did."""
    if isinstance(exc, McpTimeout):
        return True
    return isinstance(exc, TimeoutError) or type(exc).__name__ in {
        "TimeoutException",
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
    }


class ClaimedCall:
    """Sends the call of an approval that was just claimed, and records how it ended.

    The claim is already committed when this starts, so the call is sent at most once. Whatever
    happens next ends in exactly one settled state:

    - executed: the upstream answered and the answer is stored;
    - failed: the upstream refused or could not be reached, and the error is raised as it came;
    - uncertain: the upstream may have run (a timeout, or its answer could not be saved).

    One case gives the claim back instead: the call never left Eisoptric, for example because the
    key service was down while its credentials were read. The approval stays approved, so the
    agent can send the call again once the cause is gone, and the error is raised as it came.

    The last vote of a quorum and an agent sending an approved call again both end here. They
    differ only in what they write to the audit log and how they report the outcome.
    """

    def __init__(
        self,
        session: AsyncSession,
        approval: Approval,
        action: Action,
        run: Run | None,
        *,
        organization_id: str,
    ) -> None:
        self._session = session
        self._approval = approval
        self._action = action
        self._run = run
        self._organization_id = organization_id

    async def run(
        self,
        send: Callable[[], Awaitable[dict[str, Any]]],
        audit: Callable[[Executed], Awaitable[None]],
    ) -> Executed:
        """Send the call and store its answer. `audit` is written with the answer, or not at all."""
        try:
            reply = await send()
        except NotSent as exc:
            await self._release()
            raise (exc.__cause__ or exc) from None
        except Exception as exc:
            if is_uncertain(exc):
                await self._settle_uncertain()
                raise OutcomeUncertain() from exc
            await self._settle_failed()
            raise
        # The session is rolled back if recording fails; the id is read while it can still be trusted.
        approval_id = self._approval.id
        try:
            return await self._record(reply, audit)
        except Exception as exc:
            # The upstream already ran. Losing the claim here would let the call be sent a second time.
            await approval_lifecycle.mark_unrecorded(self._session, approval_id)
            raise OutcomeUnrecorded() from exc

    async def _record(self, reply: dict[str, Any], audit: Callable[[Executed], Awaitable[None]]) -> Executed:
        raw, result = split_reply(reply)
        executed = Executed(result=result, raw=raw)
        self._action.status = ActionStatus.COMPLETED.value
        self._action.result = seal_result(self._organization_id, result)
        self._close_run(RunStatus.COMPLETED)
        await approval_lifecycle.settle(self._session, self._approval, ExecutionState.EXECUTED, commit=False)
        await audit(executed)
        await self._session.commit()
        return executed

    async def _release(self) -> None:
        try:
            await approval_lifecycle.move(self._session, self._approval, RELEASE)
            if self._approval.resubmit_expires_at is None:
                # A quorum's last vote claims at once, so its resubmit window was never set.
                from app.features.execution.approvals.services.expiration import arm_resubmit

                await arm_resubmit(self._session, self._approval, self._organization_id)
            await self._session.commit()
        except Exception:
            # Still claimed: settle_stuck_claims turns it uncertain later. Never sent twice.
            logger.exception("Could not release the claim on approval %s", self._approval.id)

    async def _settle_uncertain(self) -> None:
        await approval_lifecycle.settle(self._session, self._approval, ExecutionState.UNCERTAIN)
        if self._run is not None:
            from app.features.identity.auth.services.notices import notify_task_outcome

            await notify_task_outcome(self._session, self._run, "failed")

    async def _settle_failed(self) -> None:
        self._action.status = ActionStatus.FAILED.value
        self._close_run(RunStatus.FAILED)
        await approval_lifecycle.settle(self._session, self._approval, ExecutionState.FAILED)

    def _close_run(self, status: RunStatus) -> None:
        if self._run is not None:
            self._run.status = status.value
            self._run.updated_at = utcnow()


# Far longer than a call can take: credentials (with a token refresh), initialize sent at most
# twice and tools/call once, each with a 60 s timeout, then a 401, a refresh and the same again.
STUCK_AFTER = timedelta(minutes=15)
STUCK_BATCH = 500


async def settle_stuck_claims(session: AsyncSession, now: datetime | None = None) -> int:
    """Settle claims that nothing will ever settle, as uncertain. Returns how many.

    A claim is committed before its call is sent. If the request dies after that (the instance
    is stopped during a deploy, the request is cancelled), nothing records how the call ended,
    and the agent would be told "execution_in_progress" forever. The call may have run, so the
    claim becomes uncertain: never failed, and never free to send again.
    """
    moment = now or utcnow()
    stuck = (
        select(Approval)
        .where(
            Approval.execution_state == ExecutionState.CLAIMED.value,
            Approval.claimed_at.is_not(None),
            Approval.claimed_at <= moment - STUCK_AFTER,
        )
        .order_by(Approval.claimed_at)
        .limit(STUCK_BATCH)
    )
    settled = 0
    for approval in list(await session.scalars(stuck)):
        if not await approval_lifecycle.move(session, approval, SETTLE[ExecutionState.UNCERTAIN]):
            continue  # its request settled it after all
        logger.warning("Approval %s was claimed at %s and never settled; marked uncertain", approval.id, approval.claimed_at)
        run = await session.get(Run, approval.run_id)
        if run is not None:
            from app.features.identity.auth.services.notices import notify_task_outcome

            await notify_task_outcome(session, run, "failed")
        settled += 1
    return settled
