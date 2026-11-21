from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Agent, Employee, User
from app.schemas import AgentUpdate
from app.features.organization.org.services.access import may_edit_agent
from app.features.organization.org.services.mapping_service import mapping_service


class AgentService:
    async def list_agents(
        self, session: AsyncSession, user: User, *, limit: int | None = None, offset: int = 0
    ) -> list[Agent]:
        return await mapping_service.list_org_agents(
            session, user.organization_id, limit=limit, offset=offset
        )

    async def get_agent(self, session: AsyncSession, user: User, agent_id: str) -> Agent:
        return await mapping_service.require_org_agent(session, user, agent_id)

    async def update_agent(
        self,
        session: AsyncSession,
        user: User,
        employee: Employee,
        agent_id: str,
        body: AgentUpdate,
    ) -> Agent:
        agent = await mapping_service.require_org_agent(session, user, agent_id)
        from app.features.tooling.tool_sets.services.tool_set_service import tool_set_service

        set_only = body.model_fields_set == {"tool_set_id"}
        if not may_edit_agent(employee, agent.id) and not (set_only and tool_set_service.owns_profile(user, agent)):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot modify this agent")
        if body.name is not None:
            name = body.name.strip()
            if name:
                agent.name = name
        if body.description is not None:
            agent.description = body.description
        if "tool_set_id" in body.model_fields_set:
            await tool_set_service.assign(session, user, employee, agent, body.tool_set_id)
        await session.flush()
        return agent


agent_service = AgentService()
