"""Hosts an organization's admins approve for MCP servers, beside Saturn's own list.

Approving a host only lets its name through. Each request to it still has to pass every check in
mcp_endpoint.py: HTTPS on port 443, no credentials in the URL, and only public addresses, resolved
and pinned per request.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from urllib.parse import urlsplit

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ids import new_id
from app.features.mcp.servers.models.mcp_allowed_host import McpAllowedHost
from app.features.mcp.servers.services import mcp_endpoint

# Enough for any real organization, and it bounds the work an admin can make Saturn do.
MAX_HOSTS = 50

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# Names that only mean something inside a network, never on the public internet.
_PRIVATE_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".home.arpa",
    ".arpa",
    ".test",
    ".invalid",
    ".example",
    ".onion",
)


def _bad(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, detail)


def normalize_host(value: str) -> str:
    """The host name in the form it is stored and compared in, or 400.

    Takes a bare name (`mcp.example.com`) or an HTTPS URL, whose host is used.
    """
    text = (value or "").strip()
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme.lower() != "https":
            raise _bad("Enter a host name or an HTTPS URL")
        if parts.username or parts.password:
            raise _bad("Enter the host without a user name or password")
        try:
            port = parts.port
        except ValueError as exc:
            raise _bad("Enter a valid host name") from exc
        if port not in (None, 443):
            raise _bad("MCP endpoint must use port 443")
        text = parts.hostname or ""
    elif any(char in text for char in "/:@?#") or any(char.isspace() for char in text):
        raise _bad("Enter only the host name, such as mcp.example.com")
    host = text.lower().rstrip(".")
    if not host:
        raise _bad("Enter a host name")
    if "*" in host:
        raise _bad("Wildcards are not allowed. Add each host by name")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise _bad("Enter a host name, not an IP address")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _bad("Enter a valid host name") from exc
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise _bad("Enter a valid host name")
    if labels[-1].isdigit():
        raise _bad("Enter a host name, not an IP address")
    if host == "localhost" or host in mcp_endpoint._METADATA_HOSTS or host.endswith(_PRIVATE_SUFFIXES):
        raise _bad("This host is not reachable from the public internet")
    return host


async def organization_hosts(session: AsyncSession, organization_id: str) -> frozenset[str]:
    """The hosts this organization's admins approved. Read on every check, so a removed host
    stops working at once, for connections made before it was removed too."""
    if not organization_id:
        return frozenset()
    rows = await session.scalars(
        select(McpAllowedHost.host).where(McpAllowedHost.organization_id == organization_id)
    )
    return frozenset(rows)


async def list_hosts(session: AsyncSession, organization_id: str) -> list[McpAllowedHost]:
    rows = await session.scalars(
        select(McpAllowedHost)
        .where(McpAllowedHost.organization_id == organization_id)
        .order_by(McpAllowedHost.host)
    )
    return list(rows)


async def add_host(session: AsyncSession, organization_id: str, user_id: str, value: str) -> McpAllowedHost:
    host = normalize_host(value)
    if host in mcp_endpoint.ALLOWED_MCP_HOSTS:
        raise HTTPException(status.HTTP_409_CONFLICT, "Saturn already approves this host")
    existing = await session.scalar(
        select(McpAllowedHost).where(
            McpAllowedHost.organization_id == organization_id, McpAllowedHost.host == host
        )
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This host is already approved")
    count = await session.scalar(
        select(func.count()).select_from(McpAllowedHost).where(McpAllowedHost.organization_id == organization_id)
    )
    if (count or 0) >= MAX_HOSTS:
        raise HTTPException(status.HTTP_409_CONFLICT, f"An organization can approve at most {MAX_HOSTS} hosts")
    # Refuse early a name that points inside a network. Each request checks again, since the
    # answer can change after this.
    found = await asyncio.to_thread(mcp_endpoint.addresses_for, host, 443)
    if not found or any(mcp_endpoint.address_blocked(item) for item in found):
        raise _bad("MCP endpoint address is not allowed")
    row = McpAllowedHost(id=new_id("mah"), organization_id=organization_id, host=host, created_by_user_id=user_id)
    try:
        async with session.begin_nested():
            session.add(row)
            await session.flush()
    except IntegrityError as exc:
        # Another admin approved the same host at the same moment.
        raise HTTPException(status.HTTP_409_CONFLICT, "This host is already approved") from exc
    return row


async def remove_host(session: AsyncSession, organization_id: str, host_id: str) -> McpAllowedHost:
    row = await session.get(McpAllowedHost, host_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approved host not found")
    await session.delete(row)
    await session.flush()
    return row


def endpoint_host(endpoint: str) -> str:
    return (urlsplit((endpoint or "").strip()).hostname or "").lower().rstrip(".")
