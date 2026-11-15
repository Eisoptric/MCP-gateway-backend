"""Keeps organizations.policy_revision in step with everything the policy engine reads.

The engine caches an organization's policies, rules and agent links in memory and reuses them only
while the stored revision is unchanged. A missed change would leave a stale allow in force, so the
revision is replaced in the same transaction as each such write:

* ORM changes to a Policy, a PolicyRule, an Agent's policy links or an Agent's removal are caught
  in before_flush below, whichever code path makes them.
* Bulk statements (delete(PolicyRule), insert(agent_policies), ...) do not pass through a flush.
  Their callers call bump_policy_revision first; a bulk write on those tables in a transaction that
  has not done so raises, so a forgotten path fails loudly instead of serving old policies.

Approval policies are not cached (the engine reads them live), so they need no revision.
"""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import event, inspect, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import ORMExecuteState, Session, SessionTransaction

from app.core.ids import new_revision
from app.features.agent.agents.models.agent import Agent
from app.features.organization.org.models.organization import Organization
from app.features.policy.policies.models.policy import Policy, PolicyRule

# Set in Session.info once this transaction has replaced a revision.
BUMPED = "policy_revision_bumped"
_WATCHED_TABLES = frozenset({"policies", "policy_rules", "agent_policies"})
_organizations = Organization.__table__
_policies = Policy.__table__


def _revision_update(organization_ids: Iterable[str]):
    return (
        update(_organizations)
        .where(_organizations.c.id.in_(sorted(organization_ids)))
        .values(policy_revision=new_revision())
    )


async def bump_policy_revision(session: AsyncSession, organization_id: str) -> None:
    """Call before a bulk write to policies, policy_rules or agent_policies, in the same transaction."""
    await session.execute(_revision_update([organization_id]))
    session.info[BUMPED] = True


def _values(obj: Any, attribute: str) -> set[Any]:
    """The attribute's current value and any value it had earlier in this flush."""
    found = set(inspect(obj).attrs[attribute].history.deleted or ())
    found.add(getattr(obj, attribute))
    found.discard(None)
    return found


def _policy_links_changed(agent: Agent) -> bool:
    return inspect(agent).attrs["policies"].history.has_changes()


@event.listens_for(Session, "before_flush")
def _bump_on_flush(session: Session, _context: Any, _instances: Any) -> None:
    organizations: set[str] = set()
    policy_ids: set[str] = set()
    deleted = set(session.deleted)
    for obj in (*session.new, *session.dirty, *deleted):
        if isinstance(obj, Policy):
            if obj in session.dirty and not session.is_modified(obj):
                continue
            organizations |= _values(obj, "organization_id")
        elif isinstance(obj, PolicyRule):
            if obj in session.dirty and not session.is_modified(obj):
                continue
            parent = obj.__dict__.get("policy")
            if parent is not None and parent.organization_id:
                organizations.add(parent.organization_id)
            policy_ids |= _values(obj, "policy_id")
        elif isinstance(obj, Agent):
            # Only the links and the agent's removal matter: the engine matches agents by id.
            if obj in deleted or _policy_links_changed(obj):
                organizations |= _values(obj, "organization_id")
    if policy_ids:
        rows = session.connection().execute(
            select(_policies.c.organization_id).where(_policies.c.id.in_(sorted(policy_ids)))
        )
        organizations.update(row[0] for row in rows if row[0])
    if organizations:
        session.connection().execute(_revision_update(organizations))
        session.info[BUMPED] = True


@event.listens_for(Session, "do_orm_execute")
def _require_bump_for_bulk_writes(state: ORMExecuteState) -> None:
    if not (state.is_insert or state.is_update or state.is_delete):
        return
    table = getattr(getattr(state.statement, "table", None), "name", None)
    if table in _WATCHED_TABLES and not state.session.info.get(BUMPED):
        raise RuntimeError(
            f"bulk write to {table} without bump_policy_revision in the same transaction; "
            "the policy engine would keep serving the old policies"
        )


@event.listens_for(Session, "after_transaction_end")
def _forget_bump(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is None:
        session.info.pop(BUMPED, None)
