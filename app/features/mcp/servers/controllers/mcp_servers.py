import logging
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from app.core.public_origin import public_origin
from app.features.identity.auth.controllers.session_cookie import cookie_secure
from app.core.enums import AuditEvent
from app.features.execution.activity.services.change_log import record_change
from app.features.identity.auth.controllers.deps import AgentsRead, CurrentUser, SessionDep, TeamRead, TeamWrite
from app.features.identity.auth.controllers.session_cookie import COOKIE_NAME
from app.features.mcp.servers.services import mcp_hosts
from app.features.mcp.servers.services.mcp_endpoint import ALLOWED_MCP_HOSTS
from app.models import McpServer
from app.schemas import (
    McpAllowedHostCreate,
    McpAllowedHostRead,
    McpAllowedHostsRead,
    McpConnect,
    McpOAuthAttemptRead,
    McpOAuthBegin,
    McpOAuthStart,
    McpServerRead,
    McpToolRead,
)
from app.features.organization.org.services.mapping_service import mapping_service
from app.features.mcp.servers.services.mcp_connect import mcp_connect_service
from app.features.mcp.oauth.services.mcp_oauth import (
    CALLBACK_PATH,
    PENDING_TTL,
    browser_cookie_domain,
    callback_origin,
    mcp_oauth,
)
from app.features.organization.org.services.removal_service import removal_service
from app.features.credentials.vault.services.secret_vault import reconnect_status
from app.features.mcp.servers.services.mcp_gateway import mcp_gateway

router = APIRouter(prefix="/mcp-servers", tags=["mcp-servers"])
logger = logging.getLogger(__name__)


def serialize_mcp_server(server: McpServer, *, secret_status: str = "ok") -> McpServerRead:  # noqa: S107
    active = [tool for tool in (server.tools or []) if tool.status == "active"]
    tools = sorted(tool.name for tool in active)
    link = mcp_gateway.link_for(server.id)
    return McpServerRead(
        id=server.id,
        name=server.name,
        endpoint=server.endpoint,
        status=server.status,
        connected=bool(link and link.connected),
        has_authorization=bool(server.credential_id),
        secret_status=secret_status,
        gateway="mcp-gateway",
        organization_id=server.organization_id,
        tools=tools,
        catalog=[
            McpToolRead(id=tool.id, name=tool.name, description=tool.description or "")
            for tool in sorted(active, key=lambda item: item.name)
        ],
    )


@router.get("", response_model=list[McpServerRead])
async def list_mcp_servers(session: SessionDep, user: CurrentUser, _access: AgentsRead):
    await mapping_service.bind_workspace(session, user)
    servers = await mapping_service.list_mcp_servers(session, user)
    listed = []
    for server in servers:
        status_name = await reconnect_status(session, server.credential_id, server.organization_id)
        listed.append(serialize_mcp_server(server, secret_status=status_name))
    return listed


_bearer = HTTPBearer(auto_error=False)


async def _hosts_read(session, organization_id: str) -> McpAllowedHostsRead:
    rows = await mcp_hosts.list_hosts(session, organization_id)
    endpoints = await session.scalars(select(McpServer.endpoint).where(McpServer.organization_id == organization_id))
    in_use: dict[str, int] = {}
    for endpoint in endpoints:
        host = mcp_hosts.endpoint_host(endpoint)
        in_use[host] = in_use.get(host, 0) + 1
    return McpAllowedHostsRead(
        hosts=[
            McpAllowedHostRead(
                id=row.id,
                host=row.host,
                created_by_user_id=row.created_by_user_id,
                created_at=row.created_at,
                servers=in_use.get(row.host, 0),
            )
            for row in rows
        ],
        builtin=sorted(ALLOWED_MCP_HOSTS),
        limit=mcp_hosts.MAX_HOSTS,
    )


@router.get("/allowed-hosts", response_model=McpAllowedHostsRead)
async def list_allowed_hosts(session: SessionDep, user: CurrentUser, _access: TeamRead):
    return await _hosts_read(session, user.organization_id)


@router.post("/allowed-hosts", response_model=McpAllowedHostRead, status_code=201)
async def add_allowed_host(
    body: McpAllowedHostCreate,
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    _access: TeamWrite,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    from app.features.identity.auth.services.auth_service import auth_service

    # Approving a host widens where Eisoptric sends requests, credentials included, for everyone in
    # the organization. A stolen session alone must not be enough.
    token = creds.credentials if creds is not None and creds.scheme.lower() == "bearer" else request.cookies.get(COOKIE_NAME, "")
    await auth_service.require_recent_auth(session, token)
    row = await mcp_hosts.add_host(session, user.organization_id, user.id, body.host)
    await record_change(session, user, AuditEvent.MCP_HOST_ADDED, result=row.host, host_id=row.id)
    return McpAllowedHostRead(
        id=row.id, host=row.host, created_by_user_id=row.created_by_user_id, created_at=row.created_at
    )


@router.delete("/allowed-hosts/{host_id}", status_code=204)
async def remove_allowed_host(host_id: str, session: SessionDep, user: CurrentUser, _access: TeamWrite):
    # Removing only narrows what Eisoptric reaches, so it needs no fresh sign-in. Connections on the
    # host stay listed and fail on their next call until the host is approved again.
    row = await mcp_hosts.remove_host(session, user.organization_id, host_id)
    await record_change(session, user, AuditEvent.MCP_HOST_REMOVED, result=row.host, host_id=row.id)
    return Response(status_code=204)


@router.post("/oauth/start", response_model=McpOAuthStart)
async def start_mcp_oauth(
    body: McpOAuthBegin,
    request: Request,
    response: Response,
    session: SessionDep,
    user: CurrentUser,
    _access: TeamWrite,
):
    try:
        result = await mcp_oauth.begin(
            session,
            user,
            name=body.name,
            endpoint=body.endpoint,
            origin=callback_origin(public_origin(request)),
            nonce=body.nonce,
        )
    except HTTPException as exc:
        # The access log shows only the status. Say which step refused and for which host.
        logger.warning(
            "MCP sign-in start refused: %s %s (host=%s)",
            exc.status_code,
            exc.detail,
            urlsplit(body.endpoint.strip()).hostname or "",
        )
        raise
    if result.get("authorization_url"):
        binding = result["binding"]
        origin = callback_origin(public_origin(request))
        # Only this browser can finish the sign-in: the callback must present this cookie.
        response.set_cookie(
            key=binding.name,
            value=binding.value,
            max_age=int(PENDING_TTL.total_seconds()),
            path=CALLBACK_PATH,
            domain=browser_cookie_domain(request.headers.get("origin", ""), origin),
            httponly=True,
            secure=cookie_secure(request),
            samesite="lax",
        )
        return McpOAuthStart(authorization_url=result["authorization_url"])
    return McpOAuthStart(server=serialize_mcp_server(result["server"]))


@router.get("/oauth/callback", response_class=HTMLResponse)
async def finish_mcp_oauth(request: Request, session: SessionDep) -> HTMLResponse:
    return await mcp_oauth.finish(
        session,
        code=request.query_params.get("code", ""),
        state=request.query_params.get("state", ""),
        error=request.query_params.get("error", ""),
        cookies=dict(request.cookies),
    )


@router.get("/oauth/attempts/{nonce}", response_model=McpOAuthAttemptRead)
async def read_mcp_oauth_attempt(nonce: str, response: Response, session: SessionDep, user: CurrentUser):
    # The console polls this while the provider's page is open; the popup window cannot tell it.
    response.headers["Cache-Control"] = "no-store"
    return McpOAuthAttemptRead(**await mcp_oauth.attempt(session, user, nonce))


@router.post("", response_model=McpServerRead, status_code=201)
async def connect_mcp_server(body: McpConnect, session: SessionDep, user: CurrentUser, _access: TeamWrite):
    server = await mcp_connect_service.connect(
        session,
        user,
        name=body.name,
        endpoint=body.endpoint,
        authorization=body.authorization,
    )
    return serialize_mcp_server(server)


@router.post("/{server_id}/refresh", response_model=McpServerRead)
async def refresh_mcp_server(server_id: str, session: SessionDep, user: CurrentUser, _access: TeamWrite):
    server = await mcp_connect_service.refresh(session, user, server_id)
    return serialize_mcp_server(server)


@router.delete("/{server_id}", status_code=204)
async def delete_mcp_server(server_id: str, session: SessionDep, user: CurrentUser, _access: TeamWrite):
    from app.core.enums import AuditEvent
    from app.features.execution.activity.services.change_log import record_change
    from app.models import McpServer

    server = await session.get(McpServer, server_id)
    name = server.name if server is not None and server.organization_id == user.organization_id else ""
    await removal_service.delete_mcp_server(session, user, server_id)
    await record_change(session, user, AuditEvent.MCP_SERVER_DELETED, result=name, mcp_server_id=server_id)
