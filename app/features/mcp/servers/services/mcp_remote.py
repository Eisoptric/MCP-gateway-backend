from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import itertools
import json
from http.cookiejar import CookieJar, DefaultCookiePolicy
import re
import time
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import HTTPException, status

from app.features.mcp.servers.services.mcp_endpoint import credential_param, pin_mcp_url, require_mcp_endpoint

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_SECRET_QUERY = re.compile(
    r"(?i)((?:api[_-]?key|access[_-]?token|token|key|secret|signature|sig|password|passwd|pwd|auth|authorization|credentials?|jwt|bearer)=)[^&\s'\"]+"
)


class McpTimeout(HTTPException):
    """The upstream may have run the call but no answer came back. Callers must not retry automatically."""

    def __init__(self, detail: str = "MCP server did not answer in time") -> None:
        super().__init__(status.HTTP_504_GATEWAY_TIMEOUT, detail)


class McpOutcomeUnknown(McpTimeout):
    """tools/call reached the server and something came back that cannot be used as the result.

    The server may well have run the call, so this is treated like a timeout: recorded as
    uncertain and never retried automatically.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status.HTTP_502_BAD_GATEWAY


def redact(text: str, *secrets: str) -> str:
    """Remove credentials from text that may reach an error detail, a log or the audit trail."""
    cleaned = _SECRET_QUERY.sub(r"\1***", str(text or ""))
    for secret in secrets:
        value = (secret or "").strip()
        if value.lower().startswith("bearer "):
            value = value[7:].strip()
        if len(value) >= 4:
            cleaned = cleaned.replace(value, "***")
    return cleaned


def redact_url(url: str) -> str:
    """The URL with the value of every credential query parameter replaced.

    Uses the same rule that keeps credentials out of a stored endpoint, so an endpoint stored
    before that rule covered a name is still never shown with its key.
    """
    parts = urlsplit(url or "")
    if not parts.query:
        return url
    pieces = []
    for piece in parts.query.split("&"):
        name, separator, _value = piece.partition("=")
        pieces.append(f"{name}=***" if separator and credential_param(unquote(name)) else piece)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, redact("&".join(pieces)), ""))


def sec_api_request(endpoint: str, authorization: str) -> tuple[str, str]:
    """SEC-API.io reads the key from apiKey, not from Authorization."""
    url = endpoint.strip()
    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = urlsplit(url)
    if parts.hostname != "api.sec-api.io" or not token:
        return url, authorization
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if query.get("apiKey"):
        return url, ""
    query["apiKey"] = token
    signed = urlunsplit((parts.scheme, parts.netloc, parts.path or "/mcp", urlencode(query), ""))
    return signed, ""


def _headers(authorization: str, session_id: str = "") -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
    }
    token = authorization.strip()
    if token:
        headers["authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
    if session_id:
        headers["mcp-session-id"] = session_id
    return headers


def _unreadable(detail: str, call: bool) -> HTTPException:
    # After tools/call the server has had the request, whatever it then sent back.
    return McpOutcomeUnknown(detail) if call else HTTPException(status.HTTP_502_BAD_GATEWAY, detail)


def _payload(response: httpx.Response, *, call: bool = False) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        try:
            text = response.text
        except ValueError:
            text = ""
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            raw = line[5:].strip()
            if not raw or raw == "[DONE]":
                continue
            try:
                parsed = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            if isinstance(parsed, dict) and ("result" in parsed or "error" in parsed):
                return parsed
        raise _unreadable("MCP server returned an empty stream", call)
    try:
        body = response.json()
    except (ValueError, RecursionError) as exc:
        # ValueError covers bad JSON and bytes that are not text; very deep nesting raises RecursionError.
        raise _unreadable("MCP server did not return JSON", call) from exc
    if not isinstance(body, dict):
        raise _unreadable("MCP server did not return JSON", call)
    return body


def _tools(body: dict[str, Any]) -> list[dict[str, Any]]:
    if body.get("error"):
        message = body["error"].get("message") if isinstance(body["error"], dict) else "MCP tools/list failed"
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, redact(str(message or "MCP tools/list failed"))[:500])
    result = body.get("result") if isinstance(body.get("result"), dict) else {}
    raw = result.get("tools") if isinstance(result.get("tools"), list) else []
    tools: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"].strip():
            continue
        schema = item.get("inputSchema") if isinstance(item.get("inputSchema"), dict) else {"type": "object", "properties": {}}
        annotations = item.get("annotations") if isinstance(item.get("annotations"), dict) else {}
        tools.append(
            {
                "name": item["name"].strip(),
                "description": str(item.get("description") or ""),
                "inputSchema": schema,
                "permissions": permissions_for(annotations),
            }
        )
    return tools


def permissions_for(annotations: dict[str, Any] | None) -> list[str]:
    """Saturn permissions for an upstream tool, from its MCP annotations.

    Only a tool that declares itself read-only (readOnlyHint true, and not destructive) is read.
    A tool that says nothing is treated as write, so the default policy holds it for approval
    instead of allowing it.
    """
    hints = annotations if isinstance(annotations, dict) else {}
    if hints.get("readOnlyHint") is True and hints.get("destructiveHint") is not True:
        return ["read"]
    return ["write"]


class McpUnauthorized(Exception):
    def __init__(self, www_authenticate: str, endpoint: str) -> None:
        self.www_authenticate = www_authenticate
        self.endpoint = endpoint


def _unauthorized(response: httpx.Response, endpoint: str) -> None:
    if response.status_code == 401:
        raise McpUnauthorized(response.headers.get("www-authenticate", ""), endpoint)


def _raise_for_status(response: httpx.Response, endpoint: str, *, call: bool = False) -> None:
    _unauthorized(response, endpoint)
    if call and response.status_code in {504, 524}:
        raise McpTimeout(f"MCP server returned HTTP {response.status_code}")
    if call and response.status_code >= 500:
        # A server error after it received the call does not say whether the call ran.
        raise McpOutcomeUnknown(f"MCP server returned HTTP {response.status_code}")
    if response.status_code >= 400:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"MCP server returned HTTP {response.status_code}")


# Errors raised before the request reaches the server. Any other failure after tools/call was sent is uncertain.
_NOT_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.UnsupportedProtocol, httpx.InvalidURL)


# A kept connection the server has since closed fails like this on its next use.
_STALE = (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError, httpx.CloseError)

# One client per upstream host name, so calls reuse its TLS connections instead of opening a
# new one each time. Never one client for all hosts: requests go to a pinned address, and the
# pool finds connections by address, so a shared pool could send a request for one name over a
# connection whose certificate was checked for another name on the same address. The names come
# from ALLOWED_MCP_HOSTS, which bounds how many clients exist.
_clients: dict[str, httpx.AsyncClient] = {}
# A kept session's tools/call can be the first request on a reused connection, and a failure
# there is uncertain, never resent. Node's HTTP server, which the TypeScript MCP SDK runs on,
# closes idle connections after 5 s by default, so a connection is never kept idle that long:
# a call should not race the server closing the socket it is written to.
_LIMITS = httpx.Limits(max_connections=50, max_keepalive_connections=10, keepalive_expiry=4)


def _no_cookies() -> CookieJar:
    """A jar that keeps nothing. The shared client serves every organization calling this host,
    so a cookie it kept from one organization's call would go out on the next organization's."""
    return CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))


def _client_for(host: str) -> httpx.AsyncClient:
    client = _clients.get(host)
    if client is None or client.is_closed:
        client = httpx.AsyncClient(follow_redirects=False, trust_env=False, limits=_LIMITS, cookies=_no_cookies())
        _clients[host] = client
    return client


async def close_clients() -> None:
    """Close every kept connection and forget every upstream session. Called when the application stops."""
    _sessions.clear()
    clients = list(_clients.values())
    _clients.clear()
    for client in clients:
        await client.aclose()


async def _rpc(
    client: httpx.AsyncClient,
    endpoint: str,
    headers: dict[str, str],
    method: str,
    params: dict[str, Any],
    request_id: int,
    sni: str = "",
    *,
    cookies: httpx.Cookies,
    timeout: float = 60,  # noqa: ASYNC109 (httpx's per-phase timeouts for this request, not a deadline for the coroutine)
) -> httpx.Response:
    # initialize and tools/list change nothing upstream, so they are sent again when a kept
    # connection turns out to be dead. tools/call never is: a failure there leaves the outcome
    # unknown, now that it may be the first request of a call on a reused session.
    attempts = 1 if method == "tools/call" else 2
    for attempt in range(attempts):
        try:
            return await _send(client, endpoint, headers, method, params, request_id, sni, timeout, cookies)
        except _STALE as exc:
            if attempt + 1 < attempts:
                continue
            raise _transport_error(exc, method) from None
        except httpx.HTTPError as exc:
            raise _transport_error(exc, method) from None
    raise AssertionError("unreachable")


def _transport_error(exc: httpx.HTTPError, method: str) -> HTTPException:
    # Never put str(exc) in the detail: it can carry the request URL, and SEC-API keys live in its query.
    kind = type(exc).__name__
    if method == "tools/call" and not isinstance(exc, _NOT_SENT):
        return McpTimeout(f"MCP server did not answer ({kind})")
    return HTTPException(status.HTTP_502_BAD_GATEWAY, f"Could not reach MCP server ({kind})")


async def _send(
    client: httpx.AsyncClient,
    endpoint: str,
    headers: dict[str, str],
    method: str,
    params: dict[str, Any],
    request_id: int,
    sni: str,
    timeout: float,  # noqa: ASYNC109
    cookies: httpx.Cookies,
) -> httpx.Response:
    request = client.build_request(
        "POST",
        endpoint,
        headers=headers,
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
        extensions={"sni_hostname": sni} if sni else None,
        timeout=timeout,
    )
    # Cookies come from the call's own jar (a copy of what its session's initialize set), never
    # the shared client's. Some upstreams route the session by cookie.
    cookies.set_cookie_header(request)
    response = await client.send(request, stream=True)
    cookies.extract_cookies(response)
    try:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise _unreadable("MCP server response is too large", method == "tools/call")
    finally:
        await response.aclose()
    kept = {
        key: value
        for key, value in response.headers.items()
        if key.lower() not in {"content-encoding", "content-length", "transfer-encoding"}
    }
    return httpx.Response(response.status_code, headers=kept, content=bytes(body), request=request)


@dataclass
class _Session:
    """An upstream MCP session, kept so a call does not have to send initialize first."""

    session_id: str  # "" when the server is stateless and returned none
    cookies: httpx.Cookies  # what initialize set; never the shared client's jar
    protocol_version: str
    created: float


# Upstream sessions by (host, digest of pinned URL, host and credential). Only the exact credential
# that opened a session may use it, so organizations never share a session, its id or its cookies.
# The URL is part of the digest rather than kept in clear because SEC-API keys travel in its query.
_sessions: OrderedDict[tuple[str, str], _Session] = OrderedDict()
MAX_SESSIONS = 1024
SESSION_MAX_AGE = 600.0  # seconds; after this initialize is sent again
_clock = time.monotonic
# JSON-RPC ids must not repeat within a session, and a reused session spans many calls.
_request_ids = itertools.count(1)

_INITIALIZE = {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "Saturn", "version": "0.1.0"},
}

# How servers word "that session id is unknown" when they answer 400 instead of 404 (the
# TypeScript and Python SDK examples say "No valid session ID provided").
_MISSING_SESSION = re.compile(
    r"(?i)(?:no valid|invalid|unknown|missing|expired|required)\W+(?:\w+\W+){0,3}session"
    r"|session\W+(?:\w+\W+){0,3}(?:not found|invalid|expired|missing|required|unknown|terminated)"
)


def _session_key(request_url: str, host: str, header_auth: str) -> tuple[str, str]:
    digest = hashlib.sha256("\0".join((request_url, host, header_auth)).encode()).hexdigest()
    return host, digest


def _cached_session(key: tuple[str, str]) -> _Session | None:
    entry = _sessions.get(key)
    if entry is None:
        return None
    if _clock() - entry.created >= SESSION_MAX_AGE:
        _sessions.pop(key, None)
        return None
    _sessions.move_to_end(key)
    return entry


def _remember(key: tuple[str, str], entry: _Session) -> None:
    _sessions[key] = entry
    _sessions.move_to_end(key)
    while len(_sessions) > MAX_SESSIONS:
        _sessions.popitem(last=False)


def _forget(key: tuple[str, str], entry: _Session) -> None:
    # Only the entry this call used: a concurrent call may already have stored a newer one.
    if _sessions.get(key) is entry:
        del _sessions[key]


def _session_gone(response: httpx.Response) -> bool:
    """Whether the server says the session id it was sent is unknown or expired."""
    if response.status_code == 404:
        return True
    if response.status_code != 400:
        return False
    # A 400 counts only as the SDKs send it: a JSON-RPC error with no id, because the request was
    # refused before it was read, and a message about the session. A 400 that echoes the
    # request's id was read, and maybe acted on, so it never leads to a resend.
    try:
        body = json.loads(response.content[:65536])
    except ValueError:
        return False
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict) or body.get("id") is not None:
        return False
    return bool(_MISSING_SESSION.search(str(error.get("message") or "")))


async def _initialize(
    client: httpx.AsyncClient, request_url: str, url: str, header_auth: str, host: str, timeout: float  # noqa: ASYNC109
) -> tuple[_Session, bool]:
    """Open a session. Returns it and whether it may be kept for later calls."""
    cookies = httpx.Cookies()
    headers = {**_headers(header_auth), "Host": host}
    init = await _rpc(
        client, request_url, headers, "initialize", _INITIALIZE, next(_request_ids), host, cookies=cookies, timeout=timeout
    )
    _raise_for_status(init, url)
    # As before, a call goes ahead whatever initialize's body says; only a clean result is kept.
    try:
        body = _payload(init)
    except HTTPException:
        body = {}
    result = body.get("result")
    keep = isinstance(result, dict) and not body.get("error")
    version = result.get("protocolVersion") if isinstance(result, dict) else None
    session = _Session(
        session_id=init.headers.get("mcp-session-id", ""),
        cookies=cookies,
        protocol_version=version if isinstance(version, str) else "",
        created=_clock(),
    )
    return session, keep


async def _send_in(
    session: _Session,
    client: httpx.AsyncClient,
    request_url: str,
    header_auth: str,
    host: str,
    method: str,
    params: dict[str, Any],
    timeout: float,  # noqa: ASYNC109
) -> httpx.Response:
    headers = {**_headers(header_auth, session.session_id), "Host": host}
    if session.protocol_version:
        # Required on every request after initialize from protocol revision 2025-06-18.
        headers["MCP-Protocol-Version"] = session.protocol_version
    # A copy, so concurrent calls in one session never write to each other's jar.
    cookies = httpx.Cookies(session.cookies)
    return await _rpc(client, request_url, headers, method, params, next(_request_ids), host, cookies=cookies, timeout=timeout)


async def _session_request(
    endpoint: str, authorization: str, method: str, params: dict[str, Any], *, timeout: float  # noqa: ASYNC109
) -> tuple[str, httpx.Response]:
    """Send one request in an upstream session, reusing a kept one when there is one.

    Returns (checked endpoint, response). The caller checks the status.
    """
    url, request_url, header_auth, host = await asyncio.to_thread(_target, endpoint, authorization)
    client = _client_for(host)
    # Without a credential nothing tells one organization's calls from another's, so each call
    # gets its own session, as before sessions were kept.
    key = _session_key(request_url, host, header_auth) if authorization.strip() else None
    cached = _cached_session(key) if key else None
    if cached is not None:
        try:
            response = await _send_in(cached, client, request_url, header_auth, host, method, params, timeout)
        except HTTPException:
            _forget(key, cached)
            raise
        if not (cached.session_id and _session_gone(response)):
            if not response.is_success:
                # 401 means the credential changed; anything else may mean a broken session.
                # Opening a new one next time costs one round trip.
                _forget(key, cached)
            return url, response
        # The server no longer knows the session. Open a new one and send the request once
        # more, tools/call included. This is the only case a tools/call is ever sent twice, and
        # it is safe: per the MCP Streamable HTTP transport, Session Management (spec revisions
        # 2025-03-26 and 2025-06-18), a server that ended a session MUST answer requests carrying
        # its id with 404, and a client that gets 404 MUST start a new session with initialize.
        # The request was refused before it ran. Servers that answer 400 "No valid session ID"
        # refuse it at the same point. Any other failure after tools/call was sent stays
        # uncertain and is never resent.
        _forget(key, cached)
    session, keep = await _initialize(client, request_url, url, header_auth, host, timeout)
    if key and keep:
        _remember(key, session)
    try:
        response = await _send_in(session, client, request_url, header_auth, host, method, params, timeout)
    except HTTPException:
        if key:
            _forget(key, session)
        raise
    if key and not response.is_success:
        _forget(key, session)
    return url, response


def _target(endpoint: str, authorization: str) -> tuple[str, str, str, str]:
    """Check the endpoint and pin it to an address. Both steps resolve DNS, which blocks."""
    url = require_mcp_endpoint(endpoint)
    request_url, header_auth = sec_api_request(url, authorization)
    request_url, host = pin_mcp_url(request_url)
    return url, request_url, header_auth, host


async def list_remote_tools(endpoint: str, authorization: str = "") -> list[dict[str, Any]]:
    url, listed = await _session_request(endpoint, authorization, "tools/list", {}, timeout=20)
    _raise_for_status(listed, url)
    tools = _tools(_payload(listed))
    if not tools:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "MCP server did not list any tools")
    return tools


def split_reply(body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """(reply as sent, tool result). Real MCP replies are a JSON-RPC envelope. Test doubles return the tool result itself."""
    if "result" in body and ("jsonrpc" in body or "id" in body):
        result = body.get("result")
        tool = result if isinstance(result, dict) else ({"value": result} if result is not None else {})
        return body, tool
    return body, body


async def call_remote_tool(
    endpoint: str,
    name: str,
    arguments: dict[str, Any],
    authorization: str = "",
) -> dict[str, Any]:
    url, called = await _session_request(endpoint, authorization, "tools/call", {"name": name, "arguments": arguments}, timeout=60)
    _raise_for_status(called, url, call=True)
    body = _payload(called, call=True)
    if body.get("error"):
        message = body["error"].get("message") if isinstance(body["error"], dict) else "MCP tools/call failed"
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, redact(str(message or "MCP tools/call failed"), authorization)[:500])
    return body
