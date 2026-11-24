from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from app.shared.threads import in_thread
from fastapi import HTTPException, status as http_status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.ids import new_id
from app.models import (
    Agent,
    Approval,
    AuditLog,
    AuthSession,
    Employee,
    McpAllowedHost,
    McpServer,
    Organization,
    Passkey,
    Policy,
    PolicyRule,
    Run,
    Tool,
    ToolSet,
    User,
    WebhookDelivery,
    WebhookEndpoint,
)
from app.core.enums import ActorType, AuditEvent
from app.features.organization.org.services.access import permissions_for_role, resolve_permissions
from app.features.execution.activity.services.audit_service import audit_service
from app.features.identity.auth.services.auth_service import hash_password
from app.features.mcp.servers.services.mcp_gateway import mcp_gateway
from app.features.mcp.servers.services.mcp_endpoint import ALLOWED_MCP_HOSTS
from app.features.mcp.servers.services.mcp_remote import redact_url
from app.features.identity.auth.services import mailer
from app.features.organization.org.services.member_service import (
    member_service,
    require_password_policy,
    unusable_password_hash,
)
from app.shared import runtime
from app.features.organization.org.services.accounts import account_kind

settings = get_settings()
ORG_STATUSES = {"active", "trial", "suspended"}
WEBHOOK_FAILED = ("failed", "dead")


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# Every gateway tools/call is evaluated exactly once, whatever the decision, and only a call held
# for approval gets an Action row. So tool calls are counted from these audit events.
_DECIDED = (AuditLog.event == "policy_evaluated", AuditLog.source == "gateway_mcp")


def _ago(days: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _utc(value: datetime) -> datetime:
    aware = _aware(value)
    assert aware is not None
    return aware.astimezone(timezone.utc)


class AdminService:
    async def stats(self, session: AsyncSession) -> dict[str, int]:
        organizations = await session.scalar(select(func.count()).select_from(Organization))
        users = await session.scalar(
            select(func.count()).select_from(User).where(User.status == "active")
        )
        agents = await session.scalar(select(func.count()).select_from(Agent))
        connections = await session.scalar(
            select(func.count()).select_from(McpServer).where(McpServer.status == "active")
        )
        personal = await session.scalar(
            select(func.count()).select_from(Organization).where(Organization.kind == "personal")
        )
        teams = await session.scalar(
            select(func.count()).select_from(Organization).where(Organization.kind == "organization")
        )
        tool_calls = await session.scalar(
            select(func.count()).select_from(AuditLog).where(*_DECIDED, AuditLog.created_at >= _ago(1))
        )
        pending = await session.scalar(
            select(func.count()).select_from(Approval).where(Approval.status == "pending")
        )
        webhook_failures = await session.scalar(
            select(func.count())
            .select_from(WebhookDelivery)
            .where(WebhookDelivery.status.in_(WEBHOOK_FAILED), WebhookDelivery.updated_at >= _ago(1))
        )
        mcp_errors = 0
        for org_id in (await session.execute(select(Organization.id))).scalars():
            snap = mcp_gateway.snapshot(org_id)
            mcp_errors += max(0, int(snap["total"] or 0) - int(snap["connected"] or 0))
        return {
            "organizations": int(organizations or 0),
            "users": int(users or 0),
            "agents": int(agents or 0),
            "connections": int(connections or 0),
            "mcp_errors": mcp_errors,
            "personal": int(personal or 0),
            "teams": int(teams or 0),
            "tool_calls_24h": int(tool_calls or 0),
            "approvals_pending": int(pending or 0),
            "webhook_failures_24h": int(webhook_failures or 0),
        }

    async def overview(self, session: AsyncSession) -> dict:
        from app.core import status as platform_status

        await self._bind_all_mcp(session)
        stats = await self.stats(session)
        report = await platform_status.report()
        history = await platform_status.history(session, 30)
        uptime = {item["id"]: item["uptime"] for item in history["services"]}
        services = [{**item, "uptime_30d": uptime.get(item["id"])} for item in report["services"]]
        # Servers the gateway cannot reach are the organizations' problem, not an outage, so the
        # gateway reads as degraded rather than down.
        services.append(
            {
                "id": "gateway",
                "name": "MCP Gateway",
                "status": "degraded" if stats["mcp_errors"] else "operational",
                "uptime_30d": None,
            }
        )
        events = await self.list_events(session, limit=12)
        return {"stats": stats, "services": services, "events": events}

    async def _bind_all_mcp(self, session: AsyncSession) -> None:
        result = await session.execute(select(Organization.id))
        for org_id in result.scalars():
            await mcp_gateway.connect_organization(session, org_id)

    async def list_orgs(
        self, session: AsyncSession, *, limit: int | None = None, offset: int = 0
    ) -> list[dict]:
        await self._bind_all_mcp(session)
        statement = select(Organization).order_by(Organization.created_at.asc(), Organization.id.asc())
        if limit is not None:
            statement = statement.limit(limit).offset(offset)
        result = await session.execute(statement)
        orgs = list(result.scalars().all())
        rows = []
        for org in orgs:
            rows.append(await self.org_snapshot(session, org))
        return rows

    async def org_snapshot(self, session: AsyncSession, org: Organization) -> dict:
        user_count, agent_count = await self.org_counts(session, org.id)
        tool_count = int(
            await session.scalar(
                select(func.count()).select_from(Tool).where(Tool.organization_id == org.id)
            )
            or 0
        )
        mcp_count = int(
            await session.scalar(
                select(func.count()).select_from(McpServer).where(McpServer.organization_id == org.id)
            )
            or 0
        )
        snap = mcp_gateway.snapshot(org.id)
        mcp_status = snap["status"] if int(snap["total"] or 0) else "none"
        calls = await session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(*_DECIDED, AuditLog.organization_id == org.id, AuditLog.created_at >= _ago(30))
        )
        last_run = await session.scalar(select(func.max(Run.created_at)).where(Run.organization_id == org.id))
        last_seen = await session.scalar(select(func.max(Agent.last_seen_at)).where(Agent.organization_id == org.id))
        moments = [_aware(item) for item in (last_run, last_seen) if item is not None]
        return {
            "id": org.id,
            "name": org.name,
            "status": org.status,
            "kind": account_kind(org.kind),
            "created_at": org.created_at,
            "user_count": user_count,
            "agent_count": agent_count,
            "tool_count": tool_count,
            "connection_count": mcp_count,
            "mcp_status": mcp_status,
            "mcp_error_count": max(0, int(snap["total"] or 0) - int(snap["connected"] or 0)),
            "tool_calls_30d": int(calls or 0),
            "last_activity_at": max(moments) if moments else None,
        }

    async def get_org(self, session: AsyncSession, organization_id: str) -> Organization:
        org = await session.get(Organization, organization_id)
        if org is None:
            raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Organization not found")
        return org

    async def org_counts(self, session: AsyncSession, organization_id: str) -> tuple[int, int]:
        users = await session.scalar(
            select(func.count()).select_from(User).where(User.organization_id == organization_id)
        )
        agents = await session.scalar(
            select(func.count()).select_from(Agent).where(Agent.organization_id == organization_id)
        )
        return int(users or 0), int(agents or 0)

    async def org_health(self, session: AsyncSession, org: Organization) -> dict:
        await mcp_gateway.connect_organization(session, org.id)
        snap = mcp_gateway.snapshot(org.id)
        summary = await self.org_snapshot(session, org)
        issues: list[str] = []
        agents = summary["agent_count"]
        policies = await session.scalar(
            select(func.count()).select_from(Policy).where(Policy.organization_id == org.id)
        )
        mcp = snap["status"] if int(snap["total"] or 0) else "none"
        checks = {
            "mcp": mcp,
            "agents": "ok" if int(agents or 0) else "none",
            "policies": "ok" if int(policies or 0) else "none",
            "database": "ok",
        }
        if org.status == "suspended":
            issues.append("Organization is suspended")
        if int(snap["total"] or 0) > 0 and snap["status"] != "connected":
            missing = int(snap["total"]) - int(snap["connected"])
            if missing:
                issues.append(f"{missing} MCP server{'s' if missing != 1 else ''} unreachable")
        score = 100
        if org.status == "suspended":
            score -= 40
        if checks["mcp"] == "degraded":
            score -= 15
        if checks["mcp"] == "disconnected":
            score -= 25
        return {**checks, "score": max(score, 0), "issues": issues}

    async def list_agents(self, session: AsyncSession, organization_id: str) -> list[Agent]:
        result = await session.execute(
            select(Agent)
            .where(Agent.organization_id == organization_id)
            .order_by(Agent.created_at.asc())
        )
        return list(result.scalars().all())

    async def list_mcp_servers(self, session: AsyncSession, organization_id: str) -> list[McpServer]:
        result = await session.execute(
            select(McpServer)
            .options(selectinload(McpServer.tools))
            .where(McpServer.organization_id == organization_id)
            .order_by(McpServer.name.asc())
        )
        return list(result.scalars().unique().all())

    async def onboard_org(
        self,
        session: AsyncSession,
        actor: User,
        *,
        name: str,
        admin_email: str,
        admin_name: str,
        admin_password: str | None,
        admin_title: str,
        kind: str | None = None,
    ) -> tuple[Organization, Employee]:
        cleaned_name = name.strip()
        if not cleaned_name:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Organization name is required")
        employee = await self.create_member(
            session,
            organization=None,
            org_name=cleaned_name,
            email=admin_email,
            name=admin_name,
            password=admin_password,
            title=admin_title.strip() or "Admin",
            role="admin",
            permissions=None,
            status="active",
            agent_ids=[],
            mcp_server_ids=[],
            kind=kind,
        )
        org = await session.get(Organization, employee.organization_id)
        if org is None:
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create organization")
        await audit_service.log(
            session,
            event="org_onboarded",
            actor_type=ActorType.USER,
            actor_id=actor.id,
            organization_id=org.id,
            payload={"name": org.name, "kind": org.kind},
        )
        return org, employee

    async def update_org(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: str,
        *,
        name: str | None,
        status: str | None = None,
    ) -> Organization:
        org = await self.get_org(session, organization_id)
        changed: dict[str, str] = {}
        if name is not None:
            cleaned = name.strip()
            if not cleaned:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Organization name is required")
            org.name = cleaned
            changed["name"] = cleaned
        if status is not None:
            cleaned = status.strip().lower()
            if cleaned not in ORG_STATUSES:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Status must be active, trial, or suspended")
            org.status = cleaned
            changed["status"] = cleaned
        await session.flush()
        if changed:
            await audit_service.log(
                session,
                event=AuditEvent.ORG_UPDATED,
                actor_type=ActorType.USER,
                actor_id=actor.id,
                organization_id=org.id,
                payload={**changed, "platform_admin": True},
            )
        return org

    async def list_users(
        self, session: AsyncSession, *, limit: int | None = None, offset: int = 0
    ) -> list[User]:
        statement = (
            select(User)
            .options(selectinload(User.organization), selectinload(User.employee))
            .order_by(User.created_at.asc(), User.id.asc())
        )
        if limit is not None:
            statement = statement.limit(limit).offset(offset)
        result = await session.execute(statement)
        return list(result.scalars().unique().all())

    @staticmethod
    def _event_filters(
        statement,
        *,
        organization_id: str | None = None,
        event: str | None = None,
        since: datetime | None = None,
    ):
        if organization_id:
            statement = statement.where(AuditLog.organization_id == organization_id)
        if event:
            statement = statement.where(AuditLog.event == event)
        if since is not None:
            statement = statement.where(AuditLog.created_at >= _utc(since))
        return statement

    async def list_events(
        self,
        session: AsyncSession,
        limit: int = 50,
        *,
        offset: int = 0,
        organization_id: str | None = None,
        event: str | None = None,
        since: datetime | None = None,
    ) -> list[AuditLog]:
        statement = self._event_filters(
            select(AuditLog).options(selectinload(AuditLog.organization)),
            organization_id=organization_id,
            event=event,
            since=since,
        )
        result = await session.execute(
            statement.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().unique().all())

    async def count_events(
        self,
        session: AsyncSession,
        *,
        organization_id: str | None = None,
        event: str | None = None,
        since: datetime | None = None,
    ) -> int:
        statement = self._event_filters(
            select(func.count()).select_from(AuditLog),
            organization_id=organization_id,
            event=event,
            since=since,
        )
        return int(await session.scalar(statement) or 0)

    async def event_names(self, session: AsyncSession) -> list[str]:
        result = await session.execute(select(AuditLog.event).distinct().order_by(AuditLog.event.asc()))
        return [str(name) for name in result.scalars().all()]

    async def mcp_summary(self, session: AsyncSession) -> dict:
        await self._bind_all_mcp(session)
        result = await session.execute(
            select(McpServer)
            .options(selectinload(McpServer.tools), selectinload(McpServer.organization))
            .order_by(McpServer.name.asc())
        )
        servers = list(result.scalars().unique().all())
        items = []
        healthy = 0
        errors = 0
        tools = 0
        for server in servers:
            link = mcp_gateway.link_for(server.id)
            host = (urlparse(server.endpoint).hostname or "").lower()
            tool_count = len(server.tools or [])
            tools += tool_count
            connected = bool(link and link.connected)
            if connected:
                healthy += 1
            else:
                errors += 1
            items.append(
                {
                    "id": server.id,
                    "name": server.name,
                    "organization_id": server.organization_id,
                    "organization_name": server.organization.name if server.organization else "",
                    "status": "connected" if connected else "error",
                    "tools": tool_count,
                    "endpoint": redact_url(server.endpoint),
                    "host": host,
                    # A marketplace host is approved for everyone; anything else an admin added.
                    "source": "marketplace" if host in ALLOWED_MCP_HOSTS else "custom",
                    "error": None if connected else (link.error if link else "Disconnected"),
                }
            )
        return {
            "servers": len(servers),
            "tools": tools,
            "healthy": healthy,
            "errors": errors,
            "items": items,
            "builtin_hosts": sorted(ALLOWED_MCP_HOSTS),
            "allowed_hosts": await self.allowed_hosts(session),
        }

    async def user_security(self, session: AsyncSession, user_ids: list[str]) -> dict[str, dict]:
        """Per user: how many passkeys, and the last time a session was signed in."""
        if not user_ids:
            return {}
        passkeys = dict(
            (await session.execute(
                select(Passkey.user_id, func.count()).where(Passkey.user_id.in_(user_ids)).group_by(Passkey.user_id)
            )).all()
        )
        signed_in = dict(
            (await session.execute(
                select(AuthSession.user_id, func.max(AuthSession.created_at))
                .where(AuthSession.user_id.in_(user_ids))
                .group_by(AuthSession.user_id)
            )).all()
        )
        return {
            user_id: {"passkeys": int(passkeys.get(user_id, 0)), "last_sign_in_at": _aware(signed_in.get(user_id))}
            for user_id in user_ids
        }

    async def org_users(self, session: AsyncSession, organization_id: str) -> list[User]:
        result = await session.execute(
            select(User)
            .options(selectinload(User.organization), selectinload(User.employee))
            .where(User.organization_id == organization_id)
            .order_by(User.created_at.asc(), User.id.asc())
        )
        return list(result.scalars().unique().all())

    async def org_policies(self, session: AsyncSession, organization_id: str) -> list[dict]:
        rules = (
            select(PolicyRule.policy_id, func.count().label("rules"))
            .group_by(PolicyRule.policy_id)
            .subquery()
        )
        rows = (
            await session.execute(
                select(Policy, func.coalesce(rules.c.rules, 0))
                .outerjoin(rules, rules.c.policy_id == Policy.id)
                .where(Policy.organization_id == organization_id)
                .order_by(Policy.updated_at.desc())
            )
        ).all()
        return [
            {
                "id": policy.id,
                "name": policy.name,
                "status": policy.status,
                "version": policy.version,
                "rule_count": int(count),
                "updated_at": policy.updated_at,
            }
            for policy, count in rows
        ]

    async def org_tool_set_count(self, session: AsyncSession, organization_id: str) -> int:
        return int(
            await session.scalar(select(func.count()).select_from(ToolSet).where(ToolSet.organization_id == organization_id))
            or 0
        )

    async def org_approvals(self, session: AsyncSession, organization_id: str) -> dict:
        rows = (
            await session.execute(
                select(Approval.status, func.count())
                .join(Run, Approval.run_id == Run.id)
                .where(Run.organization_id == organization_id)
                .where((Approval.status == "pending") | (Approval.created_at >= _ago(30)))
                .group_by(Approval.status)
            )
        ).all()
        counts = {status: int(count) for status, count in rows}
        return {
            "pending": counts.get("pending", 0),
            "approved_30d": counts.get("approved", 0),
            "rejected_30d": counts.get("rejected", 0),
            "expired_30d": counts.get("expired", 0),
        }

    async def org_webhooks(self, session: AsyncSession, organization_id: str) -> dict:
        endpoints = (
            await session.execute(select(WebhookEndpoint.enabled).where(WebhookEndpoint.organization_id == organization_id))
        ).scalars().all()
        rows = (
            await session.execute(
                select(WebhookDelivery.status, func.count())
                .where(WebhookDelivery.organization_id == organization_id, WebhookDelivery.created_at >= _ago(30))
                .group_by(WebhookDelivery.status)
            )
        ).all()
        counts = {status: int(count) for status, count in rows}
        failure = (
            await session.execute(
                select(WebhookDelivery.updated_at, WebhookDelivery.last_error)
                .where(WebhookDelivery.organization_id == organization_id, WebhookDelivery.status.in_(WEBHOOK_FAILED))
                .order_by(WebhookDelivery.updated_at.desc())
                .limit(1)
            )
        ).first()
        return {
            "endpoints": len(endpoints),
            "enabled": sum(1 for item in endpoints if item),
            "delivered_30d": counts.get("delivered", 0),
            "failed_30d": sum(counts.get(item, 0) for item in WEBHOOK_FAILED),
            "last_failure_at": _aware(failure[0]) if failure else None,
            # Only the first line: the endpoint's own response body is the customer's data.
            "last_error": (failure[1] or "").splitlines()[0][:200] if failure and failure[1] else None,
        }

    async def allowed_hosts(self, session: AsyncSession, organization_id: str | None = None) -> list[dict]:
        statement = (
            select(McpAllowedHost, Organization.name)
            .join(Organization, Organization.id == McpAllowedHost.organization_id)
            .order_by(McpAllowedHost.host.asc())
        )
        if organization_id is not None:
            statement = statement.where(McpAllowedHost.organization_id == organization_id)
        return [
            {"host": item.host, "organization_id": item.organization_id, "organization_name": name, "created_at": item.created_at}
            for item, name in (await session.execute(statement)).all()
        ]

    async def activity(self, session: AsyncSession, *, days: int = 30) -> dict:
        """Tool calls, policy decisions, approval outcomes and webhook deliveries per organization."""
        since = _ago(days)
        decisions = (
            await session.execute(
                select(AuditLog.organization_id, AuditLog.result, func.count())
                .where(*_DECIDED, AuditLog.created_at >= since)
                .group_by(AuditLog.organization_id, AuditLog.result)
            )
        ).all()
        approvals = (
            await session.execute(
                select(Run.organization_id, Approval.status, func.count())
                .join(Run, Approval.run_id == Run.id)
                .where(Approval.created_at >= since)
                .group_by(Run.organization_id, Approval.status)
            )
        ).all()
        deliveries = (
            await session.execute(
                select(WebhookDelivery.organization_id, WebhookDelivery.status, func.count())
                .where(WebhookDelivery.created_at >= since)
                .group_by(WebhookDelivery.organization_id, WebhookDelivery.status)
            )
        ).all()
        per: dict[str, dict[str, int]] = {}
        for org_id, decision, count in decisions:
            row = per.setdefault(org_id, {})
            row["tool_calls"] = row.get("tool_calls", 0) + int(count)
            key = {"allow": "allowed", "approval_required": "approval_required", "deny": "denied"}.get(decision or "")
            if key:
                row[key] = row.get(key, 0) + int(count)
        for org_id, state, count in approvals:
            key = {"approved": "approvals_approved", "rejected": "approvals_rejected", "expired": "approvals_expired"}.get(state)
            if key:
                per.setdefault(org_id, {})[key] = int(count)
        for org_id, state, count in deliveries:
            key = "webhooks_delivered" if state == "delivered" else "webhooks_failed" if state in WEBHOOK_FAILED else None
            if key:
                row = per.setdefault(org_id, {})
                row[key] = row.get(key, 0) + int(count)
        rows = []
        for org in (await session.execute(select(Organization).order_by(Organization.name.asc()))).scalars():
            rows.append(
                {
                    "organization_id": org.id,
                    "organization_name": org.name,
                    "kind": account_kind(org.kind),
                    **per.get(org.id, {}),
                }
            )
        day = func.date(AuditLog.created_at)
        daily_rows = (
            await session.execute(
                select(day, AuditLog.result, func.count())
                .where(*_DECIDED, AuditLog.created_at >= since)
                .group_by(day, AuditLog.result)
            )
        ).all()
        daily: dict[str, dict[str, int]] = {}
        for when, decision, count in daily_rows:
            item = daily.setdefault(str(when), {"tool_calls": 0, "denied": 0, "approval_required": 0})
            item["tool_calls"] += int(count)
            if decision == "deny":
                item["denied"] += int(count)
            elif decision == "approval_required":
                item["approval_required"] += int(count)
        return {
            "days": days,
            "rows": rows,
            "daily": [{"day": key, **value} for key, value in sorted(daily.items())],
        }

    async def platform(self, session: AsyncSession) -> dict:
        """The configuration this deployment runs with. Never a secret's value, only whether it is set."""
        import os

        from app.features.policy.policies.services.policy_llm import policy_model_status

        def present(name: str) -> bool:
            return bool(os.environ.get(name, "").strip())

        admins = [user for user in await self.list_users(session) if user.is_platform_admin]
        sender = (settings.resend_from or "").strip()
        return {
            "revision": os.environ.get("K_REVISION", "local"),
            "service": os.environ.get("K_SERVICE", "local"),
            "cors_origins": [item.strip() for item in settings.cors_origins.split(",") if item.strip()],
            "webauthn_rp_id": (settings.webauthn_rp_id or "").strip() or "per origin",
            "session_ttl_days": settings.session_ttl_days,
            "policy_model": policy_model_status(),
            "email": {
                "configured": bool(settings.resend_api_key and sender),
                "from_domain": sender.rsplit("@", 1)[-1].rstrip(">") if "@" in sender else "",
            },
            "sign_in": {
                "google": present("GATEWAY_GOOGLE_OAUTH_CLIENT_ID"),
                "github": present("GATEWAY_GITHUB_OAUTH_CLIENT_ID"),
                "seed_email": bool((settings.seed_user_email or "").strip()),
            },
            "secrets": {
                "kms_key": present("GATEWAY_KMS_KEY"),
                "origin_auth": present("ORIGIN_AUTH_SECRET"),
                "console_proxy": present("CONSOLE_PROXY_SECRET"),
                "redis_ca": bool(os.environ.get("REDIS_CA_PATH", "").strip()) or present("REDIS_CA"),
            },
            "admins": admins,
        }

    async def create_member(
        self,
        session: AsyncSession,
        *,
        organization: Organization | None,
        org_name: str | None = None,
        email: str,
        name: str,
        password: str | None,
        title: str,
        role: str,
        permissions: dict | None,
        status: str,
        agent_ids: list[str],
        mcp_server_ids: list[str],
        actor: User | None = None,
        kind: str | None = None,
        self_service: bool = False,
    ) -> Employee:
        """Create a user, its employee row and (when organization is None) a new organization.

        self_service: the person is choosing their own password (sign-up).
        Otherwise a platform admin is creating the account. An admin-chosen password is used
        only in local development and tests; in production the admin never knows the password:
        the account gets an unusable one and the user is emailed a one-time reset code.
        """
        use_password = self_service or (runtime.local_dev_mode() and bool(password))
        if use_password:
            require_password_policy(password or "")
        normalized = email.strip().lower()
        if not normalized:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Email is required")
        cleaned_name = name.strip()
        if not cleaned_name:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Name is required")

        existing = await session.execute(select(User).where(User.email == normalized))
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(http_status.HTTP_409_CONFLICT, "Email is already used")

        cleaned_status = (status or "active").strip().lower()
        if cleaned_status not in {"active", "disabled"}:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Status must be active or disabled")

        resolved_role, resolved_perms = resolve_permissions(role, permissions)

        if organization is not None and organization.kind == "personal":
            raise HTTPException(http_status.HTTP_403_FORBIDDEN, "Personal accounts cannot add members")
        resolved_kind = ""
        if organization is None:
            resolved_kind = (kind or "").strip().lower() or "personal"
            if resolved_kind not in {"personal", "organization"}:
                raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Account type must be personal or team")
        else:
            await member_service._validate_ids(session, organization.id, agent_ids, mcp_server_ids)

        reset_code: str | None = None
        if use_password:
            password_hash = await in_thread(hash_password, password or "")
        else:
            password_hash = unusable_password_hash()
            if cleaned_status == "active":
                if not runtime.email_configured():
                    raise HTTPException(http_status.HTTP_503_SERVICE_UNAVAILABLE, "Email delivery is not configured")
                # Sent before anything is written, so a failed send leaves no half-made account.
                reset_code = f"{secrets.randbelow(1_000_000):06d}"
                await mailer.send_reset_code(normalized, reset_code, None)

        if organization is None:
            organization = Organization(
                id=new_id("org"),
                name=(org_name or "").strip() or cleaned_name,
                status="active",
                kind=resolved_kind,
            )
            session.add(organization)
            await session.flush()
            from app.features.policy.policies.services.default_policy import ensure_default_policy

            await ensure_default_policy(session, organization.id)

        user = User(
            id=new_id("user"),
            organization_id=organization.id,
            email=normalized,
            name=cleaned_name,
            password_hash=password_hash,
            status=cleaned_status,
            is_platform_admin=False,
        )
        session.add(user)
        await session.flush()
        employee = Employee(
            id=new_id("emp"),
            organization_id=organization.id,
            user_id=user.id,
            title=title.strip() or "Operator",
            role=resolved_role,
            permissions=resolved_perms or permissions_for_role(resolved_role),
            status=cleaned_status,
        )
        session.add(employee)
        await session.flush()
        loaded = await member_service.load_member(session, employee.id)
        if loaded is None:
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create member")
        await member_service._set_assignments(
            session,
            loaded,
            organization_id=organization.id,
            agent_ids=agent_ids,
            # No servers given: the first workspace bind assigns the org's servers once.
            mcp_server_ids=list(mcp_server_ids or []) or None,
        )
        if reset_code is not None:
            await member_service.store_reset_code(session, normalized, reset_code)
        created = await member_service.load_member(session, loaded.id)
        assert created is not None
        if actor is not None:
            await audit_service.log(
                session,
                event=AuditEvent.MEMBER_CREATED,
                actor_type=ActorType.USER,
                actor_id=actor.id,
                organization_id=organization.id,
                payload={
                    "employee_id": created.id,
                    "email": created.user.email if created.user else normalized,
                    "role": created.role,
                    "platform_admin": True,
                },
            )
        return created

    async def register_self(
        self,
        session: AsyncSession,
        *,
        name: str,
        email: str,
        password: str,
        organization: str | None = None,
    ) -> User:
        """Public sign-up. With an organization name the account is a team the new user owns;
        otherwise it is personal."""
        org_name = (organization or "").strip()
        kind = "organization" if org_name else "personal"
        employee = await self.create_member(
            session,
            organization=None,
            org_name=org_name or name.strip() or "Personal",
            email=email,
            name=name,
            password=password,
            title="Owner",
            role="admin",
            permissions=None,
            status="active",
            agent_ids=[],
            mcp_server_ids=[],
            kind=kind,
            self_service=True,
        )
        user = employee.user
        if user is None:
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create account")
        loaded = await session.execute(
            select(User).options(selectinload(User.organization)).where(User.id == user.id)
        )
        account = loaded.scalar_one()
        await audit_service.log(
            session,
            event="org_registered",
            actor_type=ActorType.USER,
            actor_id=account.id,
            organization_id=account.organization_id,
            payload={"kind": kind},
        )
        return account


admin_service = AdminService()
