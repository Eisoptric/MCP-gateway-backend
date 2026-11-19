from datetime import timedelta

import pytest
from fastapi import HTTPException

from app.features.mcp.servers.services.mcp_endpoint import require_mcp_endpoint
from app.features.mcp.servers.services.mcp_hosts import MAX_HOSTS, normalize_host
from tests.oauth_access import oauth_access

CUSTOM = "mcp.example-tools.dev"


def _tools():
    return [{"name": "lookup", "description": "Look up", "inputSchema": {"type": "object", "properties": {}}}]


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        ("mcp.example-tools.dev", "mcp.example-tools.dev"),
        ("  MCP.Example-Tools.DEV. ", "mcp.example-tools.dev"),
        ("https://mcp.example-tools.dev/mcp?x=1", "mcp.example-tools.dev"),
        ("https://mcp.example-tools.dev:443/mcp", "mcp.example-tools.dev"),
        ("bücher.example.com", "xn--bcher-kva.example.com"),
    ],
)
def test_hosts_are_stored_in_one_form(given, stored):
    assert normalize_host(given) == stored


@pytest.mark.parametrize(
    "given",
    [
        "",
        "localhost",
        "10.0.0.5",
        "[::1]",
        "https://[::1]/mcp",
        "1.2.3.4",
        "http://mcp.example-tools.dev/mcp",
        "https://mcp.example-tools.dev:8443/mcp",
        "https://user:pass@mcp.example-tools.dev/mcp",
        "mcp.example-tools.dev/mcp",
        "*.example-tools.dev",
        "intranet",
        "metadata.google.internal",
        "db.corp",
        "printer.local",
        "-bad.example.com",
        "a" * 64 + ".example.com",
    ],
)
def test_hosts_that_are_not_a_public_name_are_refused(given):
    with pytest.raises(HTTPException) as refused:
        normalize_host(given)
    assert refused.value.status_code == 400


def test_an_approved_host_passes_only_for_the_organization_that_approved_it():
    with pytest.raises(HTTPException) as refused:
        require_mcp_endpoint(f"https://{CUSTOM}/mcp")
    assert refused.value.detail == "MCP endpoint host is not approved"
    assert require_mcp_endpoint(f"https://{CUSTOM}/mcp", frozenset({CUSTOM})) == f"https://{CUSTOM}/mcp"
    # Approval is for the name only; the other checks still apply.
    with pytest.raises(HTTPException):
        require_mcp_endpoint(f"http://{CUSTOM}/mcp", frozenset({CUSTOM}))
    with pytest.raises(HTTPException):
        require_mcp_endpoint(f"https://{CUSTOM}:8443/mcp", frozenset({CUSTOM}))


def test_an_approved_host_that_resolves_inside_the_network_is_refused(monkeypatch):
    monkeypatch.setattr(
        "app.features.mcp.servers.services.mcp_endpoint.addresses_for", lambda _host, _port: ["10.0.0.7"]
    )
    with pytest.raises(HTTPException) as refused:
        require_mcp_endpoint(f"https://{CUSTOM}/mcp", frozenset({CUSTOM}))
    assert refused.value.detail == "MCP endpoint address is not allowed"


async def test_an_admin_approves_a_host_and_then_connects_a_server_on_it(client, monkeypatch):
    async def listed(endpoint, authorization="", **kwargs):
        # The real check, with the hosts the caller passed.
        require_mcp_endpoint(endpoint, kwargs.get("extra_hosts", ()))
        return _tools()

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    body = {"name": "Example", "endpoint": f"https://{CUSTOM}/mcp", "authorization": "key-1"}

    refused = await client.post("/mcp-servers", json=body)
    assert refused.status_code == 400
    assert refused.json()["detail"] == "MCP endpoint host is not approved"

    added = await client.post("/mcp-servers/allowed-hosts", json={"host": f"https://{CUSTOM}/mcp"})
    assert added.status_code == 201, added.text
    assert added.json()["host"] == CUSTOM

    connected = await client.post("/mcp-servers", json=body)
    assert connected.status_code == 201, connected.text

    listed_hosts = (await client.get("/mcp-servers/allowed-hosts")).json()
    assert [(item["host"], item["servers"]) for item in listed_hosts["hosts"]] == [(CUSTOM, 1)]
    assert "api.githubcopilot.com" in listed_hosts["builtin"]
    assert listed_hosts["limit"] == MAX_HOSTS

    changes = (await client.get("/activity/changes")).json()
    assert any(item.get("event") == "mcp_host_added" for item in changes), changes


async def test_removing_a_host_stops_calls_to_servers_on_it(client, monkeypatch):
    async def listed(endpoint, authorization="", **kwargs):
        require_mcp_endpoint(endpoint, kwargs.get("extra_hosts", ()))
        return _tools()

    sent = []

    async def called(endpoint, name, arguments, authorization="", **kwargs):
        require_mcp_endpoint(endpoint, kwargs.get("extra_hosts", ()))
        sent.append(name)
        return {"content": [{"type": "text", "text": "ok"}]}

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.saturn.services.saturn_mcp.call_remote_tool", called)
    host_id = (await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM})).json()["id"]
    connected = await client.post(
        "/mcp-servers", json={"name": "Example", "endpoint": f"https://{CUSTOM}/mcp", "authorization": "key-1"}
    )
    assert connected.status_code == 201, connected.text
    server_id = connected.json()["id"]
    tool_id = connected.json()["catalog"][0]["id"]

    access = await oauth_access(client, "Cursor")
    headers = {"Authorization": f"Bearer {access}"}
    opened = await client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert opened.status_code == 200, opened.text
    agent_id = next(item["id"] for item in (await client.get("/agents")).json() if item["name"] == "Cursor")
    tool_set = await client.post("/tool-sets", json={"name": "Example", "items": [{"tool_id": tool_id, "approval": False}]})
    assert (await client.patch(f"/agents/{agent_id}", json={"tool_set_id": tool_set.json()["id"]})).status_code == 200

    def call(request_id):
        return client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": "lookup", "arguments": {}}},
        )

    assert "result" in (await call(2)).json()
    assert sent == ["lookup"]

    removed = await client.delete(f"/mcp-servers/allowed-hosts/{host_id}")
    assert removed.status_code == 204, removed.text
    blocked = await call(3)
    assert blocked.status_code == 400, blocked.text
    assert blocked.json()["detail"] == "MCP endpoint host is not approved"
    assert sent == ["lookup"]
    # Refreshing the connection is refused the same way.
    refreshed = await client.post(f"/mcp-servers/{server_id}/refresh")
    assert refreshed.status_code == 400
    assert refreshed.json()["detail"] == "MCP endpoint host is not approved"


async def test_one_organizations_host_is_not_approved_for_another(client):
    from sqlalchemy import select

    from app.db.database import get_session
    from app.main import app
    from app.models import McpAllowedHost
    from app.features.mcp.servers.services.mcp_hosts import organization_hosts

    assert (await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM})).status_code == 201
    generator = app.dependency_overrides[get_session]()
    session = await generator.__anext__()
    try:
        row = await session.scalar(select(McpAllowedHost))
        assert await organization_hosts(session, row.organization_id) == frozenset({CUSTOM})
        assert await organization_hosts(session, "org_someone_else") == frozenset()
        assert await organization_hosts(session, "") == frozenset()
    finally:
        await generator.aclose()


async def test_approving_a_host_needs_a_recent_sign_in(client, monkeypatch):
    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", timedelta(seconds=-1))
    blocked = await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM})
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Reauthentication required"
    assert (await client.get("/mcp-servers/allowed-hosts")).json()["hosts"] == []


async def test_hosts_that_are_already_approved_or_resolve_privately_are_refused(client, monkeypatch):
    builtin = await client.post("/mcp-servers/allowed-hosts", json={"host": "mcp.sentry.dev"})
    assert builtin.status_code == 409
    assert (await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM})).status_code == 201
    again = await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM.upper()})
    assert again.status_code == 409

    monkeypatch.setattr(
        "app.features.mcp.servers.services.mcp_endpoint.addresses_for", lambda _host, _port: ["192.168.1.4"]
    )
    private = await client.post("/mcp-servers/allowed-hosts", json={"host": "router.example.com"})
    assert private.status_code == 400
    assert private.json()["detail"] == "MCP endpoint address is not allowed"


async def test_an_organization_can_approve_at_most_the_limit(client, monkeypatch):
    monkeypatch.setattr("app.features.mcp.servers.services.mcp_hosts.MAX_HOSTS", 2)
    for index in range(2):
        assert (await client.post("/mcp-servers/allowed-hosts", json={"host": f"h{index}.example-tools.dev"})).status_code == 201
    over = await client.post("/mcp-servers/allowed-hosts", json={"host": "h9.example-tools.dev"})
    assert over.status_code == 409


async def test_only_admins_manage_hosts(client):
    invited = await client.post("/org/invites", json={"email": "ops@saturn.ai", "name": "Ops", "role": "operator"})
    assert invited.status_code == 201, invited.text
    accepted = await client.post("/auth/accept-invite", json={"token": invited.json()["token"], "password": "password1"})
    assert accepted.status_code == 200, accepted.text
    admin = client.headers["Authorization"]
    login = await client.post("/auth/login", json={"email": "ops@saturn.ai", "password": "password1"})
    assert login.status_code == 200, login.text
    client.headers["Authorization"] = f"Bearer {login.json()['token']}"
    try:
        assert (await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM})).status_code == 403
        assert (await client.get("/mcp-servers/allowed-hosts")).status_code == 403
        assert (await client.delete("/mcp-servers/allowed-hosts/mah_x")).status_code == 403
    finally:
        client.headers["Authorization"] = admin
    assert (await client.delete("/mcp-servers/allowed-hosts/mah_missing")).status_code == 404


async def test_the_least_recently_used_upstream_client_is_retired(monkeypatch):
    from app.features.mcp.servers.services import mcp_remote

    closed = []
    monkeypatch.setattr(mcp_remote, "MAX_CLIENTS", 2)
    monkeypatch.setattr(mcp_remote, "_RETIRE_AFTER", 0)
    first = mcp_remote._client_for("a.example.com")
    mcp_remote._client_for("b.example.com")
    assert mcp_remote._client_for("a.example.com") is first
    retired = mcp_remote._clients["b.example.com"]
    original = retired.aclose

    async def track():
        closed.append("b")
        await original()

    monkeypatch.setattr(retired, "aclose", track)
    mcp_remote._client_for("c.example.com")
    assert list(mcp_remote._clients) == ["a.example.com", "c.example.com"]
    for task in list(mcp_remote._retiring):
        await task
    assert closed == ["b"]
    assert not mcp_remote._retired
    await mcp_remote.close_clients()
