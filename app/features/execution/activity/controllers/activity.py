from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import func, or_, select, tuple_

from app.core.ids import utcnow
from app.features.identity.auth.controllers.deps import AgentsRead, CurrentUser, SessionDep, TeamRead
from app.features.organization.org.services.plans import audit_retention_days
from app.features.execution.activity.services.activity_cursor import decode_cursor, encode_cursor
from app.features.execution.activity.services.audit_service import audit_service
from app.features.execution.activity.services.zero_access import public_audit_payload
from app.core.enums import ActorType, AuditEvent
from app.models import AuditLog, Organization
from app.schemas import ActivityEventRead

router = APIRouter(prefix="/activity", tags=["activity"])

SATURN_MCP_SOURCE = "saturn_mcp"


def recorded_by_saturn_mcp(entry: AuditLog) -> bool:
    payload = entry.payload if isinstance(entry.payload, dict) else {}
    return payload.get("source") == SATURN_MCP_SOURCE


def _read(item: AuditLog) -> ActivityEventRead:
    payload = item.payload if isinstance(item.payload, dict) else None
    return ActivityEventRead(
        id=item.id,
        event=item.event,
        actor_type=item.actor_type,
        actor_id=item.actor_id,
        run_id=item.run_id,
        action_id=item.action_id,
        tool=item.tool,
        result=item.result,
        payload=public_audit_payload(payload),
        created_at=item.created_at,
    )


LIST_DEFAULT_LIMIT = 500
LIST_MAX_LIMIT = 1000
EXPORT_DEFAULT_LIMIT = 5000
EXPORT_MAX_LIMIT = 10000


def _contains(column, needle: str):
    return func.lower(func.coalesce(column, "")).contains(needle.lower(), autoescape=True)


# Accepted for one more release so clients still sending ?offset= keep working; use ?cursor=.
OFFSET_PARAM = Query(0, ge=0, deprecated=True, description="Deprecated: use cursor.")
CURSOR_PARAM = Query(None, description="next_cursor from the X-Next-Cursor header of the previous page.")


def _page(stmt, cursor: str | None, offset: int, limit: int):
    """Newest first. With a cursor, only rows strictly after it in (created_at, id) order."""
    if cursor is not None:
        if offset:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Use cursor or offset, not both")
        created_at, row_id = decode_cursor(cursor)
        # A row-value comparison, which PostgreSQL matches against the index's trailing columns.
        stmt = stmt.where(tuple_(AuditLog.created_at, AuditLog.id) < tuple_(created_at, row_id))
    stmt = stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    if offset:
        stmt = stmt.offset(offset)
    return stmt.limit(limit + 1)


async def _fetch(session, stmt, cursor: str | None, offset: int, limit: int) -> tuple[list[AuditLog], bool]:
    rows = list((await session.execute(_page(stmt, cursor, offset, limit))).scalars().all())
    return rows[:limit], len(rows) > limit


async def _rows(
    session,
    user,
    *,
    run_id: str | None,
    q: str | None,
    tool: str | None,
    agent: str | None,
    limit: int,
    offset: int,
    cursor: str | None,
) -> tuple[list[AuditLog], bool]:
    """Matching rows newest first, filtered in SQL. Returns one page and whether more exist."""
    org = await session.get(Organization, user.organization_id)
    plan = org.plan if org is not None else None
    days = audit_retention_days(plan)
    stmt = select(AuditLog).where(
        AuditLog.organization_id == user.organization_id,
        AuditLog.source == SATURN_MCP_SOURCE,
    )
    if run_id:
        stmt = stmt.where(AuditLog.run_id == run_id)
    if days is not None:
        stmt = stmt.where(AuditLog.created_at >= utcnow() - timedelta(days=days))
    if tool and tool.strip():
        stmt = stmt.where(AuditLog.tool.contains(tool.strip(), autoescape=True))
    if agent and agent.strip():
        stmt = stmt.where(AuditLog.actor_id.contains(agent.strip(), autoescape=True))
    needle = (q or "").strip()
    if needle:
        stmt = stmt.where(
            or_(
                *(
                    _contains(column, needle)
                    for column in (AuditLog.event, AuditLog.tool, AuditLog.result, AuditLog.actor_id, AuditLog.actor_type)
                )
            )
        )
    return await _fetch(session, stmt, cursor, offset, limit)


def _page_headers(response: Response, rows: list[AuditLog], more: bool, *, offset: int, cursor: str | None) -> None:
    if not more:
        return
    last = rows[-1]
    response.headers["X-Next-Cursor"] = encode_cursor(last.created_at, last.id)
    if cursor is None:
        response.headers["X-Next-Offset"] = str(offset + len(rows))


@router.get("", response_model=list[ActivityEventRead])
async def list_activity(
    session: SessionDep,
    user: CurrentUser,
    _access: AgentsRead,
    response: Response,
    run_id: str | None = None,
    q: str | None = None,
    tool: str | None = None,
    agent: str | None = None,
    limit: int = Query(LIST_DEFAULT_LIMIT, ge=1, le=LIST_MAX_LIMIT),
    cursor: str | None = CURSOR_PARAM,
    offset: int = OFFSET_PARAM,
):
    rows, more = await _rows(
        session, user, run_id=run_id, q=q, tool=tool, agent=agent, limit=limit, offset=offset, cursor=cursor
    )
    _page_headers(response, rows, more, offset=offset, cursor=cursor)
    return [_read(item) for item in rows]


# Changes people made to what agents may do. Ids, names and before/after states; no tool content.
CHANGE_EVENTS = (
    AuditEvent.POLICY_CREATED.value,
    AuditEvent.POLICY_UPDATED.value,
    AuditEvent.POLICY_ACTIVATED.value,
    AuditEvent.POLICY_PAUSED.value,
    AuditEvent.POLICY_DELETED.value,
    AuditEvent.TOOL_SET_CREATED.value,
    AuditEvent.TOOL_SET_UPDATED.value,
    AuditEvent.TOOL_SET_DELETED.value,
    AuditEvent.TOOL_SET_ASSIGNED.value,
    AuditEvent.MEMBER_INVITED.value,
    AuditEvent.MEMBER_UPDATED.value,
    # What the platform did inside this organization. The tenant must be able to see it:
    # a member the platform creates as an admin can approve keys and read content.
    AuditEvent.MEMBER_CREATED.value,
    AuditEvent.MEMBER_PASSWORD_RESET.value,
    AuditEvent.ORG_UPDATED.value,
    AuditEvent.INVITE_REVOKED.value,
    AuditEvent.AGENT_DELETED.value,
    AuditEvent.MCP_SERVER_DELETED.value,
    AuditEvent.GROUP_UPDATED.value,
)


@router.get("/changes", response_model=list[ActivityEventRead])
async def list_changes(
    session: SessionDep,
    user: CurrentUser,
    _access: TeamRead,
    response: Response,
    limit: int = Query(100, ge=1, le=500),
    cursor: str | None = CURSOR_PARAM,
    offset: int = OFFSET_PARAM,
):
    """Who changed a policy, a tool set, a member's access, or removed an agent or server."""
    org = await session.get(Organization, user.organization_id)
    days = audit_retention_days(org.plan if org is not None else None)
    stmt = select(AuditLog).where(
        AuditLog.organization_id == user.organization_id,
        AuditLog.event.in_(CHANGE_EVENTS),
    )
    if days is not None:
        stmt = stmt.where(AuditLog.created_at >= utcnow() - timedelta(days=days))
    rows, more = await _fetch(session, stmt, cursor, offset, limit)
    _page_headers(response, rows, more, offset=offset, cursor=cursor)
    return [_read(item) for item in rows]


@router.get("/export")
async def export_activity(
    session: SessionDep,
    user: CurrentUser,
    _access: AgentsRead,
    run_id: str | None = None,
    q: str | None = None,
    tool: str | None = None,
    agent: str | None = None,
    limit: int = Query(EXPORT_DEFAULT_LIMIT, ge=1, le=EXPORT_MAX_LIMIT),
    cursor: str | None = CURSOR_PARAM,
    offset: int = OFFSET_PARAM,
):
    rows, more = await _rows(
        session, user, run_id=run_id, q=q, tool=tool, agent=agent, limit=limit, offset=offset, cursor=cursor
    )
    body = json.dumps(
        [_read(item).model_dump(mode="json") for item in rows],
        ensure_ascii=False,
    )
    response = Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="activity.json"'},
    )
    _page_headers(response, rows, more, offset=offset, cursor=cursor)
    return response


@router.post("/{event_id}/reveal")
async def reveal_activity(
    event_id: str,
    session: SessionDep,
    user: CurrentUser,
    _access: AgentsRead,
):
    entry = await session.get(AuditLog, event_id)
    if entry is None or entry.organization_id != user.organization_id or not recorded_by_saturn_mcp(entry):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Record not found")
    payload = entry.payload if isinstance(entry.payload, dict) else {}
    envelope = payload.get("envelope") if isinstance(payload.get("envelope"), dict) else None
    if envelope is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Record content is not encrypted")
    await audit_service.log(
        session,
        event=AuditEvent.CONTENT_REVEALED,
        actor_type=ActorType.USER,
        actor_id=user.id,
        organization_id=user.organization_id,
        run_id=entry.run_id,
        action_id=entry.action_id,
        tool=entry.tool,
        result="ciphertext",
        payload={"event_id": entry.id, "source": "saturn_mcp", "org_key_version": envelope.get("org_key_version")},
    )
    return {"envelope": envelope, "decrypt": "client"}
