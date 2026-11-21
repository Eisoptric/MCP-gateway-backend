from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Action, Agent, Run, Tool
from app.core.enums import ActorType, AuditEvent, PolicyDecision
from app.features.execution.activity.services.audit_service import audit_service
from app.features.execution.activity.services.content_seal import policy_fields
from app.features.execution.approvals.services.approval_arguments import ArgumentsUnavailable, stored_arguments
from app.features.policy.policies.services.policy_engine import EvaluationResult, policy_engine


class RunService:
    """What approvals need from a gateway run: load it, re-check its policy, and find its tool.

    Runs are created by MCP Gateway's tools/call. The Saturn-era runner that planned and executed
    runs itself, and the REST endpoints that drove it, are gone.
    """

    async def load_run(self, session: AsyncSession, run_id: str) -> Run:
        result = await session.execute(
            select(Run)
            .options(selectinload(Run.actions), selectinload(Run.approvals))
            .where(Run.id == run_id)
        )
        run = result.scalar_one_or_none()
        if run is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")
        return run

    async def evaluate_action_policy(
        self,
        session: AsyncSession,
        action: Action,
        *,
        agent: Agent,
        arguments: dict | None = None,
    ):
        tool = await self.get_tool(session, agent.organization_id, action.tool)
        from app.features.execution.activity.services.zero_access import action_digest, is_zero_access
        from app.models import Policy

        if arguments is None and (is_zero_access(action.arguments) or action_digest(action.arguments)):
            current_version = action.policy_version
            if action.policy_id:
                policy = await session.get(Policy, action.policy_id)
                if policy is not None:
                    current_version = policy.version
            decision = EvaluationResult(
                decision=PolicyDecision(action.policy_decision) if action.policy_decision in PolicyDecision._value2member_map_ else PolicyDecision.APPROVAL_REQUIRED,
                policy_id=action.policy_id,
                policy_version=current_version,
                matched_rule_id=action.policy_rule_id,
                reason=action.policy_reason,
            )
            return tool, decision
        if arguments is not None:
            resolved = arguments
        else:
            try:
                resolved = stored_arguments(agent.organization_id, action.arguments)
            except ArgumentsUnavailable:
                # Fail closed: never evaluate policy on {} because the stored arguments cannot be opened.
                return tool, EvaluationResult(
                    decision=PolicyDecision.DENY,
                    policy_id=action.policy_id,
                    policy_version=action.policy_version,
                    matched_rule_id=action.policy_rule_id,
                    reason="Stored arguments could not be opened",
                )
        decision = await policy_engine.evaluate(
            session,
            organization_id=agent.organization_id,
            agent=agent,
            tool=tool,
            arguments=resolved,
        )
        action.policy_decision = decision.decision.value
        action.policy_id = decision.policy_id
        action.policy_rule_id = decision.matched_rule_id
        action.policy_version = decision.policy_version
        action.policy_reason = decision.reason
        await session.flush()
        await audit_service.log(
            session,
            event=AuditEvent.POLICY_EVALUATED,
            actor_type=ActorType.SYSTEM,
            actor_id="policy_engine",
            organization_id=agent.organization_id,
            run_id=action.run_id,
            action_id=action.id,
            tool=action.tool,
            result=decision.decision.value,
            payload={
                "policy_id": decision.policy_id,
                "policy_name": decision.policy_name,
                "policy_version": decision.policy_version,
                "matched_rule_id": decision.matched_rule_id,
                "reason": decision.reason,
                "arguments": resolved,
                "policy_fields": policy_fields(decision.matched_rule),
            },
        )
        return tool, decision

    async def get_tool(self, session: AsyncSession, organization_id: str, name: str) -> Tool:
        result = await session.execute(
            select(Tool).where(Tool.organization_id == organization_id, Tool.name == name)
        )
        tool = result.scalar_one_or_none()
        if tool is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Tool not found: {name}")
        return tool


run_service = RunService()
