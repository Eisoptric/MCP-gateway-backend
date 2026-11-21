from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, Response, status

from app.features.agent.agents.controllers.agents import serialize_agent
from app.features.identity.auth.controllers.deps import PlatformAdmin, SessionDep
from app.features.mcp.servers.controllers.mcp_servers import serialize_mcp_server
from app.features.organization.org.controllers.org import serialize_member
from app.models import AuditLog, User
from app.features.execution.activity.services.zero_access import admin_audit_payload
from app.schemas import (
    AdminActivityRead,
    AdminAllowedHost,
    AdminApprovalCounts,
    AdminEventRead,
    AdminHealthCheck,
    AdminMemberCreateRequest,
    AdminMcpSummary,
    AdminOrgDetail,
    AdminOrgOnboardRequest,
    AdminOrgSummary,
    AdminOrgUpdateRequest,
    AdminOverviewRead,
    AdminPlatformRead,
    AdminPolicySummary,
    AdminServiceStatus,
    AdminStatsRead,
    AdminUserRead,
    AdminWebhookSummary,
    AgentRead,
    MemberPasswordResetRequest,
    MemberRead,
    MemberUpdateRequest,
)
from app.features.platform.admin.services.admin_service import admin_service
from app.features.execution.activity.services.audit_service import audit_service
from app.features.organization.org.services.member_service import member_service
from app.core.enums import ActorType, AuditEvent
from app.shared.pagination import Page

router = APIRouter(prefix="/admin", tags=["admin"])


def serialize_org(snap: dict) -> AdminOrgSummary:
    return AdminOrgSummary(**snap)


def _platform_payload(event: str, payload):
    """What a platform admin may see of a tenant's audit payload: never sealed content."""
    return admin_audit_payload(payload)


def serialize_event(item: AuditLog) -> AdminEventRead:
    org = item.organization
    return AdminEventRead(
        id=item.id,
        event=item.event,
        actor_type=item.actor_type,
        actor_id=item.actor_id,
        organization_id=item.organization_id,
        organization_name=org.name if org is not None else None,
        result=item.result,
        payload=_platform_payload(item.event, item.payload),
        created_at=item.created_at,
    )


def serialize_admin_user(user: User, security: dict | None = None) -> AdminUserRead:
    employee = user.employee
    org = user.organization
    security = security or {}
    return AdminUserRead(
        passkeys=security.get("passkeys", 0),
        totp_enabled=bool(user.totp_enabled and user.totp_secret),
        email_mfa=bool(user.email_mfa),
        last_sign_in_at=security.get("last_sign_in_at"),
        id=user.id,
        email=user.email,
        name=user.name,
        status=user.status,
        is_platform_admin=user.is_platform_admin,
        organization_id=user.organization_id,
        organization_name=org.name if org is not None else "",
        employee_id=employee.id if employee is not None else None,
        title=employee.title if employee is not None else None,
        role=employee.role if employee is not None else None,
        created_at=user.created_at,
    )


@router.get("/overview", response_model=AdminOverviewRead)
async def get_overview(session: SessionDep, _admin: PlatformAdmin):
    payload = await admin_service.overview(session)
    return AdminOverviewRead(
        stats=AdminStatsRead(**payload["stats"]),
        services=[AdminServiceStatus(**item) for item in payload["services"]],
        events=[serialize_event(item) for item in payload["events"]],
    )


@router.get("/stats", response_model=AdminStatsRead)
async def get_stats(session: SessionDep, _admin: PlatformAdmin):
    return AdminStatsRead(**await admin_service.stats(session))


@router.get("/orgs", response_model=list[AdminOrgSummary])
async def list_orgs(session: SessionDep, _admin: PlatformAdmin, page: Page):
    rows = await admin_service.list_orgs(session, limit=page.limit, offset=page.offset)
    return [serialize_org(item) for item in rows]


@router.post("/orgs", response_model=AdminOrgDetail, status_code=status.HTTP_201_CREATED)
async def onboard_org(body: AdminOrgOnboardRequest, session: SessionDep, admin: PlatformAdmin):
    org, employee = await admin_service.onboard_org(
        session,
        admin,
        name=body.name,
        admin_email=body.admin_email,
        admin_name=body.admin_name,
        admin_password=body.admin_password,
        admin_title=body.admin_title,
        kind=body.kind,
    )
    snap = await admin_service.org_snapshot(session, org)
    return AdminOrgDetail(
        **snap,
        members=[serialize_member(employee)],
        agents=[],
        health=AdminHealthCheck(**await admin_service.org_health(session, org)),
        mcp_servers=[],
    )


@router.get("/orgs/{organization_id}", response_model=AdminOrgDetail)
async def get_org(organization_id: str, session: SessionDep, _admin: PlatformAdmin):
    org = await admin_service.get_org(session, organization_id)
    snap = await admin_service.org_snapshot(session, org)
    members = await member_service.list_members(session, org.id)
    agents = await admin_service.list_agents(session, org.id)
    servers = await admin_service.list_mcp_servers(session, org.id)
    users = await admin_service.org_users(session, org.id)
    security = await admin_service.user_security(session, [user.id for user in users])
    return AdminOrgDetail(
        **snap,
        members=[serialize_member(item) for item in members],
        users=[serialize_admin_user(user, security.get(user.id)) for user in users],
        agents=[serialize_agent(item) for item in agents],
        health=AdminHealthCheck(**await admin_service.org_health(session, org)),
        mcp_servers=[serialize_mcp_server(item) for item in servers],
        policies=[AdminPolicySummary(**item) for item in await admin_service.org_policies(session, org.id)],
        tool_set_count=await admin_service.org_tool_set_count(session, org.id),
        approvals=AdminApprovalCounts(**await admin_service.org_approvals(session, org.id)),
        webhooks=AdminWebhookSummary(**await admin_service.org_webhooks(session, org.id)),
        allowed_hosts=[AdminAllowedHost(**item) for item in await admin_service.allowed_hosts(session, org.id)],
    )


@router.patch("/orgs/{organization_id}", response_model=AdminOrgSummary)
async def update_org(
    organization_id: str,
    body: AdminOrgUpdateRequest,
    session: SessionDep,
    admin: PlatformAdmin,
):
    org = await admin_service.update_org(
        session,
        admin,
        organization_id,
        name=body.name,
        status=body.status,
    )
    return serialize_org(await admin_service.org_snapshot(session, org))


@router.get("/orgs/{organization_id}/members", response_model=list[MemberRead])
async def list_org_members(organization_id: str, session: SessionDep, _admin: PlatformAdmin):
    await admin_service.get_org(session, organization_id)
    members = await member_service.list_members(session, organization_id)
    return [serialize_member(item) for item in members]


@router.post(
    "/orgs/{organization_id}/members",
    response_model=MemberRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_org_member(
    organization_id: str,
    body: AdminMemberCreateRequest,
    session: SessionDep,
    admin: PlatformAdmin,
):
    org = await admin_service.get_org(session, organization_id)
    employee = await admin_service.create_member(
        session,
        organization=org,
        email=body.email,
        name=body.name,
        password=body.password,
        title=body.title,
        role=body.role,
        permissions=body.permissions.model_dump() if body.permissions is not None else None,
        status=body.status,
        agent_ids=body.agent_ids,
        mcp_server_ids=body.mcp_server_ids,
        actor=admin,
    )
    return serialize_member(employee)


@router.patch("/orgs/{organization_id}/members/{employee_id}", response_model=MemberRead)
async def update_org_member(
    organization_id: str,
    employee_id: str,
    body: MemberUpdateRequest,
    session: SessionDep,
    admin: PlatformAdmin,
):
    await admin_service.get_org(session, organization_id)
    employee = await member_service.update_member(
        session,
        admin,
        employee_id,
        name=body.name,
        title=body.title,
        role=body.role,
        permissions=body.permissions.model_dump() if body.permissions is not None else None,
        status=body.status,
        agent_ids=body.agent_ids,
        agent_edit_ids=body.agent_edit_ids,
        mcp_server_ids=body.mcp_server_ids,
        organization_id=organization_id,
    )
    await audit_service.log(
        session,
        event=AuditEvent.MEMBER_UPDATED,
        actor_type=ActorType.USER,
        actor_id=admin.id,
        organization_id=organization_id,
        payload={"employee_id": employee_id, "status": employee.status, "role": employee.role, "platform_admin": True},
    )
    return serialize_member(employee)


@router.post("/orgs/{organization_id}/members/{employee_id}/password", response_model=MemberRead)
async def reset_org_member_password(
    organization_id: str,
    employee_id: str,
    session: SessionDep,
    admin: PlatformAdmin,
    body: MemberPasswordResetRequest | None = None,
):
    # body.password is accepted for compatibility and ignored: the admin never sets a
    # tenant user's password. The user's sessions are revoked and they are emailed a reset code.
    await admin_service.get_org(session, organization_id)
    employee = await member_service.reset_password(
        session,
        employee_id,
        organization_id=organization_id,
    )
    await audit_service.log(
        session,
        event=AuditEvent.MEMBER_PASSWORD_RESET,
        actor_type=ActorType.USER,
        actor_id=admin.id,
        organization_id=organization_id,
        payload={"employee_id": employee_id, "method": "email_code", "platform_admin": True},
    )
    return serialize_member(employee)


@router.get("/orgs/{organization_id}/agents", response_model=list[AgentRead])
async def list_org_agents(organization_id: str, session: SessionDep, _admin: PlatformAdmin):
    await admin_service.get_org(session, organization_id)
    agents = await admin_service.list_agents(session, organization_id)
    return [serialize_agent(item) for item in agents]


@router.get("/users", response_model=list[AdminUserRead])
async def list_users(session: SessionDep, _admin: PlatformAdmin, page: Page):
    users = await admin_service.list_users(session, limit=page.limit, offset=page.offset)
    security = await admin_service.user_security(session, [user.id for user in users])
    return [serialize_admin_user(user, security.get(user.id)) for user in users]


@router.get("/mcp", response_model=AdminMcpSummary)
async def get_mcp(session: SessionDep, _admin: PlatformAdmin):
    return AdminMcpSummary(**await admin_service.mcp_summary(session))


@router.get("/audit", response_model=list[AdminEventRead])
async def get_audit(
    session: SessionDep,
    _admin: PlatformAdmin,
    response: Response,
    page: Page,
    organization_id: Annotated[str | None, Query(max_length=64)] = None,
    event: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
):
    """Newest first. The body stays a plain list; X-Total-Count carries how many events match."""
    filters = {"organization_id": organization_id, "event": event, "since": since}
    response.headers["X-Total-Count"] = str(await admin_service.count_events(session, **filters))
    events = await admin_service.list_events(session, limit=page.limit, offset=page.offset, **filters)
    return [serialize_event(item) for item in events]


@router.get("/audit/events", response_model=list[str])
async def list_audit_event_names(session: SessionDep, _admin: PlatformAdmin):
    """Every event name present in the audit log, for the audit view's filter."""
    return await admin_service.event_names(session)


@router.get("/activity", response_model=AdminActivityRead)
async def get_activity(
    session: SessionDep,
    _admin: PlatformAdmin,
    days: Annotated[int, Query(ge=1, le=366)] = 30,
):
    """Per organization over the last `days` days: tool calls by policy decision, approval
    outcomes and webhook deliveries, and the platform's tool calls per day."""
    return AdminActivityRead(**await admin_service.activity(session, days=days))


@router.get("/platform", response_model=AdminPlatformRead)
async def get_platform(session: SessionDep, _admin: PlatformAdmin):
    payload = await admin_service.platform(session)
    admins = payload.pop("admins")
    security = await admin_service.user_security(session, [user.id for user in admins])
    return AdminPlatformRead(**payload, admins=[serialize_admin_user(user, security.get(user.id)) for user in admins])
