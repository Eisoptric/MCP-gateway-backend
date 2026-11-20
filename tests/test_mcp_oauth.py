from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from app.features.mcp.servers.services.mcp_remote import McpUnauthorized, list_remote_tools


def _response(status_code: int, body: dict) -> httpx.Response:
    return httpx.Response(status_code, json=body)


@pytest.mark.asyncio
async def test_marketplace_connect_opens_provider_consent_and_stores_the_token(client, monkeypatch):
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    async def listed(endpoint, authorization="", **_kwargs):
        assert endpoint == "https://mcp.notion.com/mcp"
        if authorization != "access-1":
            raise McpUnauthorized(
                'Bearer resource_metadata="https://mcp.notion.com/.well-known/oauth-protected-resource"',
                endpoint,
            )
        return [{"name": "repo.read", "description": "Read", "inputSchema": {"type": "object", "properties": {}}}]

    async def requested(method, url, **kwargs):
        if url == "https://mcp.notion.com/.well-known/oauth-protected-resource":
            return _response(
                200,
                {
                    "resource": "https://mcp.notion.com/mcp",
                    "authorization_servers": ["https://auth.example"],
                    "scopes_supported": ["mcp"],
                },
            )
        if url == "https://auth.example/.well-known/oauth-authorization-server":
            return _response(
                200,
                {
                    "authorization_endpoint": "https://auth.example/authorize",
                    "token_endpoint": "https://auth.example/token",
                    "registration_endpoint": "https://auth.example/register",
                },
            )
        if method == "POST" and url == "https://auth.example/register":
            assert kwargs["json"]["redirect_uris"] == ["http://test/mcp-servers/oauth/callback"]
            assert kwargs["json"]["token_endpoint_auth_method"] == "none"
            return _response(201, {"client_id": "gateway-client"})
        if method == "POST" and url == "https://auth.example/token":
            form = kwargs["data"]
            assert form["grant_type"] == "authorization_code"
            assert form["code"] == "code-1"
            assert form["client_id"] == "gateway-client"
            assert form["resource"] == "https://mcp.notion.com/mcp"
            assert form["code_verifier"]
            return _response(200, {"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 3600})
        raise AssertionError(url)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", requested)

    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "GitHub", "endpoint": "https://mcp.notion.com/mcp", "nonce": "nonce-12345678"},
    )
    assert started.status_code == 200, started.text
    authorize = urlparse(started.json()["authorization_url"])
    assert authorize.netloc == "auth.example"
    query = parse_qs(authorize.query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["mcp"]
    assert query["resource"] == ["https://mcp.notion.com/mcp"]

    page = await client.get("/mcp-servers/oauth/callback", params={"code": "code-1", "state": query["state"][0]})
    assert page.status_code == 200, page.text
    assert "gateway-mcp-oauth" in page.text
    assert "nonce-12345678" in page.text
    assert "Connected" in page.text

    servers = (await client.get("/mcp-servers")).json()
    github = next(item for item in servers if item["name"] == "GitHub")
    assert github["has_authorization"] is True
    assert github["tools"] == ["repo.read"]

    again = await client.get("/mcp-servers/oauth/callback", params={"code": "code-1", "state": query["state"][0]})
    assert "expired" in again.text


@pytest.mark.asyncio
async def test_marketplace_connects_without_a_popup_when_the_mcp_is_public(client, monkeypatch):
    async def listed(endpoint, authorization="", **_kwargs):
        return [{"name": "docs", "description": "Docs", "inputSchema": {"type": "object", "properties": {}}}]

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)

    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "Context7", "endpoint": "https://mcp.context7.com/mcp", "nonce": "nonce-12345678"},
    )
    assert started.status_code == 200, started.text
    body = started.json()
    assert body["authorization_url"] is None
    assert body["server"]["tools"] == ["docs"]
    assert body["server"]["has_authorization"] is False


@pytest.mark.asyncio
async def test_provider_denial_does_not_store_a_token(client, monkeypatch):
    async def listed(endpoint, authorization="", **_kwargs):
        raise McpUnauthorized('Bearer resource_metadata="https://mcp.notion.com/.well-known/oauth-protected-resource"', endpoint)

    async def requested(method, url, **kwargs):
        if "oauth-protected-resource" in url:
            return _response(200, {"resource": "https://mcp.notion.com/mcp", "authorization_servers": ["https://auth.example"]})
        if url.endswith("oauth-authorization-server"):
            return _response(
                200,
                {
                    "authorization_endpoint": "https://auth.example/authorize",
                    "token_endpoint": "https://auth.example/token",
                    "registration_endpoint": "https://auth.example/register",
                },
            )
        if url.endswith("/register"):
            return _response(201, {"client_id": "gateway-client"})
        raise AssertionError(url)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", requested)

    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "Notion", "endpoint": "https://mcp.notion.com/mcp", "nonce": "nonce-87654321"},
    )
    state = parse_qs(urlparse(started.json()["authorization_url"]).query)["state"][0]
    page = await client.get("/mcp-servers/oauth/callback", params={"error": "access_denied", "state": state})
    assert "did not grant" in page.text
    assert "nonce-87654321" in page.text
    names = [item["name"] for item in (await client.get("/mcp-servers")).json()]
    assert "Notion" not in names


@pytest.mark.asyncio
async def test_github_401_asks_for_sign_in_instead_of_failing(monkeypatch):
    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def build_request(self, method, url, **kwargs):
            kwargs.pop("timeout", None)  # a client setting, not part of the request
            return httpx.Request(method, url, **kwargs)

        async def send(self, request, **kwargs):
            return httpx.Response(
                401,
                headers={
                    "www-authenticate": 'Bearer resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"'
                },
                text="bad request: missing required Authorization header",
                request=request,
            )

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_remote.httpx.AsyncClient", Client)
    with pytest.raises(McpUnauthorized) as caught:
        await list_remote_tools("https://api.githubcopilot.com/mcp/", "")
    assert "oauth-protected-resource/mcp/" in caught.value.www_authenticate


@pytest.mark.asyncio
async def test_github_sign_in_uses_the_configured_oauth_app(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_GITHUB_OAUTH_CLIENT_ID", "Iv1.gateway")
    monkeypatch.setenv("GATEWAY_GITHUB_OAUTH_CLIENT_SECRET", "secret-value")
    monkeypatch.setenv("PUBLIC_WS_URL", "https://gateway-backend-clcae2l2mq-de.a.run.app")

    async def listed(endpoint, authorization="", **_kwargs):
        raise McpUnauthorized(
            'Bearer resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"',
            endpoint,
        )

    async def requested(method, url, **kwargs):
        if url == "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/":
            return _response(
                200,
                {
                    "resource": "https://api.githubcopilot.com/mcp/",
                    "authorization_servers": ["https://github.com/login/oauth"],
                    "scopes_supported": ["repo", "read:user"],
                },
            )
        if url == "https://github.com/.well-known/oauth-authorization-server/login/oauth":
            return _response(
                200,
                {
                    "authorization_endpoint": "https://github.com/login/oauth/authorize",
                    "token_endpoint": "https://github.com/login/oauth/access_token",
                },
            )
        raise AssertionError(url)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", requested)
    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "GitHub", "endpoint": "https://api.githubcopilot.com/mcp/", "nonce": "nonce-github1"},
    )
    assert started.status_code == 200, started.text
    authorize = urlparse(started.json()["authorization_url"])
    assert authorize.netloc == "github.com"
    query = parse_qs(authorize.query)
    assert query["client_id"] == ["Iv1.gateway"]
    assert "client_secret" not in query
    assert query["scope"] == ["repo read:user"]
    assert query["redirect_uri"] == ["https://gateway-backend-clcae2l2mq-de.a.run.app/mcp-servers/oauth/callback"]


@pytest.mark.asyncio
async def test_github_without_an_oauth_app_asks_for_a_pasted_token(client, monkeypatch):
    monkeypatch.delenv("GATEWAY_GITHUB_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GATEWAY_GITHUB_OAUTH_CLIENT_SECRET", raising=False)

    async def listed(endpoint, authorization="", **_kwargs):
        raise McpUnauthorized(
            'Bearer resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"',
            endpoint,
        )

    async def requested(method, url, **kwargs):
        if "oauth-protected-resource" in url:
            return _response(
                200,
                {
                    "resource": "https://api.githubcopilot.com/mcp/",
                    "authorization_servers": ["https://github.com/login/oauth"],
                },
            )
        if "oauth-authorization-server" in url:
            return _response(
                200,
                {
                    "authorization_endpoint": "https://github.com/login/oauth/authorize",
                    "token_endpoint": "https://github.com/login/oauth/access_token",
                },
            )
        raise AssertionError(url)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", requested)
    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "GitHub", "endpoint": "https://api.githubcopilot.com/mcp/", "nonce": "nonce-github2"},
    )
    assert started.status_code == 400
    assert started.json()["detail"] == "This MCP server does not let Eisoptric start sign-in"


async def _google_metadata(method, url, **kwargs):
    if url == "https://gmailmcp.googleapis.com/.well-known/oauth-protected-resource/mcp/v1":
        return _response(
            200,
            {
                "resource": "https://gmailmcp.googleapis.com/mcp/v1",
                "authorization_servers": ["https://accounts.google.com/"],
                "scopes_supported": [
                    "https://mail.google.com/",
                    "https://www.googleapis.com/auth/gmail.compose",
                    "https://www.googleapis.com/auth/gmail.modify",
                    "https://www.googleapis.com/auth/gmail.readonly",
                ],
            },
        )
    if url == "https://accounts.google.com/.well-known/oauth-authorization-server":
        return _response(404, {})
    if url == "https://accounts.google.com/.well-known/openid-configuration":
        return _response(
            200,
            {
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
            },
        )
    raise AssertionError(url)


@pytest.mark.asyncio
async def test_google_sign_in_uses_the_configured_oauth_client(client, monkeypatch):
    monkeypatch.setenv("GATEWAY_GOOGLE_OAUTH_CLIENT_ID", "gateway.apps.googleusercontent.com")
    monkeypatch.setenv("GATEWAY_GOOGLE_OAUTH_CLIENT_SECRET", "google-secret")
    monkeypatch.setenv("PUBLIC_WS_URL", "https://gateway-backend-629072855899.asia-east1.run.app")

    async def listed(endpoint, authorization="", **_kwargs):
        assert authorization == ""
        return [{"name": "search_threads", "description": "Search", "inputSchema": {"type": "object", "properties": {}}}]

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", _google_metadata)
    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "Gmail", "endpoint": "https://gmailmcp.googleapis.com/mcp/v1", "nonce": "nonce-google1"},
    )
    assert started.status_code == 200, started.text
    authorize = urlparse(started.json()["authorization_url"])
    assert authorize.netloc == "accounts.google.com"
    query = parse_qs(authorize.query)
    assert query["client_id"] == ["gateway.apps.googleusercontent.com"]
    assert "client_secret" not in query
    # Only gmail.modify: it covers reading, drafts and labels. Full mail.google.com is never asked for.
    assert query["scope"] == ["https://www.googleapis.com/auth/gmail.modify"]
    assert query["access_type"] == ["offline"]
    assert query["redirect_uri"] == [
        "https://gateway-backend-629072855899.asia-east1.run.app/mcp-servers/oauth/callback"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "scope"),
    [
        ("run.googleapis.com", "https://www.googleapis.com/auth/run"),
        ("redis.googleapis.com", "https://www.googleapis.com/auth/redis.read-write"),
        ("sqladmin.googleapis.com", "https://www.googleapis.com/auth/cloudsql"),
    ],
)
async def test_google_cloud_servers_request_their_own_scope(client, monkeypatch, host, scope):
    monkeypatch.setenv("GATEWAY_GOOGLE_OAUTH_CLIENT_ID", "gateway.apps.googleusercontent.com")
    monkeypatch.setenv("GATEWAY_GOOGLE_OAUTH_CLIENT_SECRET", "google-secret")

    async def listed(endpoint, authorization="", **_kwargs):
        return [{"name": "list_services", "description": "List", "inputSchema": {"type": "object", "properties": {}}}]

    async def requested(method, url, **kwargs):
        if url == f"https://{host}/.well-known/oauth-protected-resource/mcp":
            return _response(
                200,
                {
                    "resource": f"https://{host}/mcp",
                    "authorization_servers": ["https://accounts.google.com/"],
                    "scopes_supported": [scope, "https://www.googleapis.com/auth/cloud-platform"],
                },
            )
        return await _google_metadata(method, url, **kwargs)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", requested)
    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": host, "endpoint": f"https://{host}/mcp", "nonce": "nonce-gcloud1"},
    )
    assert started.status_code == 200, started.text
    query = parse_qs(urlparse(started.json()["authorization_url"]).query)
    assert query["client_id"] == ["gateway.apps.googleusercontent.com"]
    # cloud-platform is broader than the server needs, so it is never requested.
    assert query["scope"] == [scope]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "advertised", "wanted"),
    [
        (
            "drivemcp.googleapis.com",
            ["drive", "drive.readonly", "drive.file"],
            ["drive.readonly", "drive.file"],
        ),
        (
            "sheetsmcp.googleapis.com",
            ["drive.readonly", "spreadsheets.readonly", "drive", "spreadsheets"],
            ["spreadsheets"],
        ),
        (
            "calendarmcp.googleapis.com",
            [
                "calendar",
                "calendar.acls",
                "calendar.calendarlist.readonly",
                "calendar.events",
                "calendar.events.freebusy",
                "calendar.events.readonly",
            ],
            ["calendar.calendarlist.readonly", "calendar.events", "calendar.events.freebusy"],
        ),
        # A Google host Eisoptric has no entry for gets nothing, even scopes another host may have.
        ("bigquery.googleapis.com", ["gmail.readonly", "bigquery"], []),
    ],
)
async def test_each_google_host_gets_only_its_own_scopes(host, advertised, wanted, monkeypatch):
    from app.features.mcp.oauth.services import mcp_oauth

    google = "https://www.googleapis.com/auth/"

    async def requested(method, url, **kwargs):
        if url == f"https://{host}/.well-known/oauth-protected-resource/mcp/v1":
            return _response(
                200,
                {
                    "resource": f"https://{host}/mcp/v1",
                    "authorization_servers": ["https://accounts.google.com/"],
                    "scopes_supported": [google + item for item in advertised],
                },
            )
        return await _google_metadata(method, url, **kwargs)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", requested)
    found = await mcp_oauth.discover(f"https://{host}/mcp/v1", "")
    assert found.scope.split() == [google + item for item in wanted]


@pytest.mark.asyncio
async def test_google_without_an_oauth_client_asks_for_a_pasted_token(client, monkeypatch):
    monkeypatch.delenv("GATEWAY_GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GATEWAY_GOOGLE_OAUTH_CLIENT_SECRET", raising=False)

    async def listed(endpoint, authorization="", **_kwargs):
        return [{"name": "search_threads", "description": "Search", "inputSchema": {"type": "object", "properties": {}}}]

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", _google_metadata)
    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "Gmail", "endpoint": "https://gmailmcp.googleapis.com/mcp/v1", "nonce": "nonce-google2"},
    )
    assert started.status_code == 400
    assert started.json()["detail"] == "This MCP server does not let Eisoptric start sign-in"


async def test_authorization_requests_connect_to_the_checked_address(monkeypatch):
    from app.features.mcp.oauth.services import mcp_oauth

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(url=str(request.url), host=request.headers.get("host"), sni=request.extensions.get("sni_hostname"))
        return httpx.Response(200, json={})

    real = httpx.AsyncClient

    def build(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.httpx.AsyncClient", build)
    await mcp_oauth._request("POST", "https://auth.example.com/token?x=1", data={"a": "b"})
    assert seen["url"] == "https://1.1.1.1/token?x=1"
    assert seen["host"] == "auth.example.com"
    assert seen["sni"] == "auth.example.com"


async def test_authorization_server_responses_are_capped(monkeypatch):
    from fastapi import HTTPException

    from app.features.mcp.oauth.services import mcp_oauth

    monkeypatch.setattr(mcp_oauth, "MAX_OAUTH_RESPONSE_BYTES", 1024)
    real = httpx.AsyncClient

    def build(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 5000))
        return real(*args, **kwargs)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.httpx.AsyncClient", build)
    with pytest.raises(HTTPException) as caught:
        await mcp_oauth._request("GET", "https://auth.example.com/.well-known/oauth-authorization-server")
    assert "too large" in str(caught.value.detail)


def _notion_flow(monkeypatch, exchanged: list):
    async def listed(endpoint, authorization="", **_kwargs):
        if authorization != "access-1":
            raise McpUnauthorized(
                'Bearer resource_metadata="https://mcp.notion.com/.well-known/oauth-protected-resource"',
                endpoint,
            )
        return [{"name": "repo.read", "description": "Read", "inputSchema": {"type": "object", "properties": {}}}]

    async def requested(method, url, **kwargs):
        if url == "https://mcp.notion.com/.well-known/oauth-protected-resource":
            return _response(200, {"resource": "https://mcp.notion.com/mcp", "authorization_servers": ["https://auth.example"]})
        if url == "https://auth.example/.well-known/oauth-authorization-server":
            return _response(
                200,
                {
                    "authorization_endpoint": "https://auth.example/authorize",
                    "token_endpoint": "https://auth.example/token",
                    "registration_endpoint": "https://auth.example/register",
                },
            )
        if method == "POST" and url == "https://auth.example/register":
            return _response(201, {"client_id": "gateway-client"})
        if method == "POST" and url == "https://auth.example/token":
            exchanged.append(kwargs["data"]["code"])
            return _response(200, {"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 3600})
        raise AssertionError(url)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", requested)


@pytest.mark.asyncio
async def test_a_sign_in_link_opened_in_another_browser_stores_nothing(client, monkeypatch):
    # An admin starts a sign-in and sends the provider link to someone else. When that person
    # consents, their browser lacks the starting browser's cookie, so no token is stored.
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    exchanged: list = []
    _notion_flow(monkeypatch, exchanged)
    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "Notion", "endpoint": "https://mcp.notion.com/mcp", "nonce": "nonce-12345678"},
    )
    assert started.status_code == 200, started.text
    set_cookie = started.headers.get("set-cookie", "")
    assert "gateway_mcp_moa_" in set_cookie
    assert "HttpOnly" in set_cookie and "Path=/mcp-servers/oauth/callback" in set_cookie
    state = parse_qs(urlparse(started.json()["authorization_url"]).query)["state"][0]

    victim = httpx.AsyncClient(transport=client._transport, base_url=str(client.base_url))
    try:
        page = await victim.get("/mcp-servers/oauth/callback", params={"code": "victim-code", "state": state})
    finally:
        await victim.aclose()
    assert page.status_code == 200
    assert "another browser" in page.text
    assert exchanged == []
    assert all(item["name"] != "Notion" for item in (await client.get("/mcp-servers")).json())
    # The link is spent: the starting browser cannot finish it either.
    again = await client.get("/mcp-servers/oauth/callback", params={"code": "code-1", "state": state})
    assert "expired" in again.text
    from sqlalchemy import select

    from app.db.database import get_session
    from app.main import app
    from app.models import AuditLog

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        refused = (await session.scalars(select(AuditLog).where(AuditLog.event == "mcp_oauth_refused"))).all()
    finally:
        await generator.aclose()
    assert [item.result for item in refused] == ["browser_mismatch"]


def test_browser_cookie_reaches_the_callback_host():
    from app.features.mcp.oauth.services.mcp_oauth import browser_cookie_domain

    assert browser_cookie_domain("https://dashboard.eisoptric.com", "https://api.eisoptric.com") == "eisoptric.com"
    assert browser_cookie_domain("https://api.eisoptric.com", "https://api.eisoptric.com") is None
    assert browser_cookie_domain("http://localhost:3000", "http://localhost:8000") is None
    assert browser_cookie_domain("https://a.example.com", "https://b.other.com") is None
    # Never a public suffix alone.
    assert browser_cookie_domain("https://a.com", "https://b.com") is None
    assert browser_cookie_domain("http://127.0.0.1:3000", "http://127.0.0.2:8000") is None


async def _expired_connection(session, server_id: str = "mcp_email"):
    from datetime import timedelta

    from app.core.ids import utcnow
    from app.features.mcp.servers.services.mcp_grant import write_grant
    from app.models import McpServer

    server = await session.get(McpServer, server_id)
    server.oauth_client_id = "gateway-client"
    server.oauth_token_endpoint = "https://auth.example/token"
    server.token_expires_at = utcnow() - timedelta(minutes=1)
    await write_grant(session, server, {"access_token": "access-1", "refresh_token": "refresh-1", "client_secret": ""})
    await session.commit()


async def test_two_calls_refreshing_at_once_present_the_refresh_token_once(client, monkeypatch):
    """A provider that rotates refresh tokens revokes the grant when an old one is presented again."""
    import asyncio

    from app.db.database import get_session
    from app.features.mcp.oauth.services import mcp_oauth as module
    from app.features.mcp.servers.services.mcp_grant import read_grant
    from app.main import app
    from app.models import McpServer

    presented: list[str] = []

    async def token(_url, form):
        presented.append(form["refresh_token"])
        await asyncio.sleep(0.05)
        if form["refresh_token"] != "refresh-1":
            raise AssertionError("an old refresh token was presented again")
        return {"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600}

    monkeypatch.setattr(module, "_token", token)

    async def call():
        generator = app.dependency_overrides[get_session]()
        session = await anext(generator)
        try:
            return await module.mcp_oauth.authorization_for(session, await session.get(McpServer, "mcp_email"))
        finally:
            await generator.aclose()

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        await _expired_connection(session)
    finally:
        await generator.aclose()

    assert await asyncio.gather(call(), call()) == ["access-2", "access-2"]
    assert presented == ["refresh-1"]

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        grant = await read_grant(session, await session.get(McpServer, "mcp_email"))
        assert grant["refresh_token"] == "refresh-2" and grant["access_token"] == "access-2"
    finally:
        await generator.aclose()


async def test_a_rotated_refresh_token_survives_a_request_that_fails_afterwards(client, monkeypatch):
    from app.db.database import get_session
    from app.features.mcp.oauth.services import mcp_oauth as module
    from app.features.mcp.servers.services.mcp_grant import read_grant
    from app.main import app
    from app.models import McpServer

    async def token(_url, _form):
        return {"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600}

    monkeypatch.setattr(module, "_token", token)
    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        await _expired_connection(session)
        server = await session.get(McpServer, "mcp_email")
        assert await module.mcp_oauth.refresh_after_reject(session, server, "access-1") == "access-2"
        # The request goes on to fail. The provider has already retired refresh-1.
        await session.rollback()
        session.expire_all()
        grant = await read_grant(session, await session.get(McpServer, "mcp_email"), fresh=True)
        assert grant["refresh_token"] == "refresh-2"
        # A second caller that was refused the same old token takes the stored one; nothing is exchanged again.
        monkeypatch.setattr(module, "_token", None)
        assert await module.mcp_oauth.refresh_after_reject(session, server, "access-1") == "access-2"
    finally:
        await generator.aclose()


async def _start_notion(client, nonce: str) -> str:
    started = await client.post(
        "/mcp-servers/oauth/start",
        json={"name": "Notion", "endpoint": "https://mcp.notion.com/mcp", "nonce": nonce},
    )
    assert started.status_code == 200, started.text
    return parse_qs(urlparse(started.json()["authorization_url"]).query)["state"][0]


@pytest.mark.asyncio
async def test_the_console_reads_a_finished_sign_in_by_its_nonce(client, monkeypatch):
    # Some provider pages cut the popup off from the console, so the console asks the API instead.
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    _notion_flow(monkeypatch, [])
    state = await _start_notion(client, "attempt-ok-1")

    waiting = await client.get("/mcp-servers/oauth/attempts/attempt-ok-1")
    assert waiting.status_code == 200, waiting.text
    assert waiting.json()["status"] == "pending"
    assert waiting.json()["expires_at"]
    assert waiting.headers["cache-control"] == "no-store"

    await client.get("/mcp-servers/oauth/callback", params={"code": "code-1", "state": state})
    done = (await client.get("/mcp-servers/oauth/attempts/attempt-ok-1")).json()
    assert done["status"] == "connected"
    assert done["reason"] is None and done["message"] is None

    from sqlalchemy import select

    from app.db.database import get_session
    from app.main import app
    from app.models import McpOAuthPending

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        row = await session.scalar(select(McpOAuthPending).where(McpOAuthPending.nonce == "attempt-ok-1"))
    finally:
        await generator.aclose()
    # The outcome is kept; the secrets that finished it are not.
    assert row.verifier_ciphertext == "" and row.client_secret_ciphertext == ""


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("params", "reason", "text"),
    [
        ({"error": "access_denied"}, "access_denied", "did not grant"),
        ({"error": "server_error"}, "provider_error", "(server_error)"),
        ({"error": "<script>bad</script>"}, "provider_error", "reported an error."),
        ({}, "no_code", "authorization code"),
    ],
)
async def test_a_failed_sign_in_tells_the_console_why(client, monkeypatch, params, reason, text):
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    _notion_flow(monkeypatch, [])
    state = await _start_notion(client, "attempt-fail-1")
    await client.get("/mcp-servers/oauth/callback", params={**params, "state": state})
    body = (await client.get("/mcp-servers/oauth/attempts/attempt-fail-1")).json()
    assert body["status"] == "failed"
    assert body["reason"] == reason
    assert text in body["message"]
    assert "<script>" not in body["message"]


@pytest.mark.asyncio
async def test_a_failed_token_exchange_reaches_the_console_without_secrets(client, monkeypatch):
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    _notion_flow(monkeypatch, [])
    from app.features.mcp.oauth.services import mcp_oauth as module

    original = module._request

    async def refusing(method, url, **kwargs):
        if url == "https://auth.example/token":
            return _response(400, {"error": "invalid_grant", "access_token": "", "client_secret": "leak"})
        return await original(method, url, **kwargs)

    monkeypatch.setattr("app.features.mcp.oauth.services.mcp_oauth._request", refusing)
    state = await _start_notion(client, "attempt-token-1")
    await client.get("/mcp-servers/oauth/callback", params={"code": "code-1", "state": state})
    body = (await client.get("/mcp-servers/oauth/attempts/attempt-token-1")).json()
    assert body["status"] == "failed"
    assert body["reason"] == "token_exchange_failed"
    assert body["message"] == "MCP provider did not return an access token"


@pytest.mark.asyncio
async def test_a_sign_in_opened_elsewhere_is_reported_to_the_member_who_started_it(client, monkeypatch):
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    _notion_flow(monkeypatch, [])
    state = await _start_notion(client, "attempt-elsewhere")
    other = httpx.AsyncClient(transport=client._transport, base_url=str(client.base_url))
    try:
        await other.get("/mcp-servers/oauth/callback", params={"code": "x", "state": state})
    finally:
        await other.aclose()
    body = (await client.get("/mcp-servers/oauth/attempts/attempt-elsewhere")).json()
    assert body["status"] == "failed"
    assert body["reason"] == "browser_mismatch"


@pytest.mark.asyncio
async def test_an_unfinished_sign_in_expires(client, monkeypatch):
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    _notion_flow(monkeypatch, [])
    await _start_notion(client, "attempt-late-1")
    from datetime import timedelta

    from app.core.ids import utcnow

    monkeypatch.setattr(
        "app.features.mcp.oauth.services.mcp_oauth.utcnow", lambda: utcnow() + timedelta(minutes=16)
    )
    body = (await client.get("/mcp-servers/oauth/attempts/attempt-late-1")).json()
    assert body["status"] == "expired"
    assert body["reason"] == "expired"


@pytest.mark.asyncio
async def test_a_sign_in_attempt_is_readable_only_by_the_member_who_started_it(client, monkeypatch):
    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    _notion_flow(monkeypatch, [])
    await _start_notion(client, "attempt-mine-1")

    assert (await client.get("/mcp-servers/oauth/attempts/attempt-unknown")).status_code == 404
    assert (await client.get("/mcp-servers/oauth/attempts/bad nonce!")).status_code == 404

    from tests.test_org_hardening import _member

    colleague = await _member(client, "colleague@example.com", role="operator")
    seen = await client.get("/mcp-servers/oauth/attempts/attempt-mine-1", headers=colleague)
    assert seen.status_code == 404
    anonymous = httpx.AsyncClient(transport=client._transport, base_url=str(client.base_url))
    try:
        assert (await anonymous.get("/mcp-servers/oauth/attempts/attempt-mine-1")).status_code == 401
    finally:
        await anonymous.aclose()
