import pytest

from tests.oauth_access import oauth_tokens


def _claude(agents: list[dict]) -> list[dict]:
    return [item for item in agents if item["name"] == "Claude"]


@pytest.mark.asyncio
async def test_claude_reconnect_reuses_the_client_and_the_agent(client):
    first = await client.post(
        "/oauth/register",
        json={"client_name": "Claude", "redirect_uris": ["http://127.0.0.1:8765/callback"]},
    )
    second = await client.post(
        "/oauth/register",
        json={"client_name": "Claude", "redirect_uris": ["http://127.0.0.1:8765/callback"]},
    )
    assert first.status_code == 201
    assert second.json()["client_id"] == first.json()["client_id"]

    phone = await oauth_tokens(client, "Claude", redirect_uri="http://127.0.0.1:8765/callback")
    again = await oauth_tokens(client, "Claude", redirect_uri="http://127.0.0.1:8765/callback")
    assert phone[2] == again[2]

    opened = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {phone[0]}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"clientInfo": {"name": "Claude"}},
        },
    )
    assert opened.status_code == 200, opened.text
    assert opened.json()["result"]["capabilities"]["tools"]["listChanged"] is True
    session_id = opened.headers["mcp-session-id"]
    created = _claude((await client.get("/agents")).json())
    assert len(created) == 1
    agent_id = created[0]["id"]

    reconnected = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {again[0]}"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"clientInfo": {"name": "Claude"}},
        },
    )
    assert reconnected.status_code == 200, reconnected.text
    session_id = reconnected.headers["mcp-session-id"]
    still = _claude((await client.get("/agents")).json())
    assert [item["id"] for item in still] == [agent_id]

    other = await oauth_tokens(client, "Not Claude", redirect_uri="http://127.0.0.1:9321/callback")
    separate = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {other[0]}"},
        json={"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}},
    )
    assert separate.status_code == 200, separate.text
    named = {item["name"] for item in (await client.get("/agents")).json()}
    assert "Claude" in named
    assert "Not Claude" in named

    assigned = await client.post(
        "/tool-sets",
        json={"name": "Phone", "items": [{"tool_id": "tool_crm_get_customer", "approval": False}]},
    )
    assert assigned.status_code == 201, assigned.text
    saved = await client.patch(f"/agents/{agent_id}", json={"tool_set_id": assigned.json()["id"]})
    assert saved.status_code == 200, saved.text
    from app.features.mcp.saturn.services.mcp_sessions import mcp_sessions

    record = await mcp_sessions.get(session_id, (await client.get("/auth/me")).json()["id"], again[2])
    assert record is not None
    queued = record.queue.get_nowait()
    assert queued == {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("owner_redirect", "new_redirect", "extra_redirects"),
    [
        ("https://claude.ai/api/mcp/auth_callback", "https://other.example/callback", []),
        (
            "https://claude.ai/api/mcp/auth_callback",
            "https://other.example/callback",
            ["https://claude.ai/api/mcp/auth_callback"],
        ),
        ("https://app.example/first", "https://app.example/second", []),
        ("http://127.0.0.1:8765/callback", "http://127.0.0.1:9876/callback", []),
    ],
    ids=["different-host", "overlapping-redirects", "same-host", "different-loopback-port"],
)
async def test_another_app_with_the_same_name_gets_its_own_empty_agent(
    client, owner_redirect, new_redirect, extra_redirects
):
    owner = await oauth_tokens(client, "Claude", redirect_uri=owner_redirect)
    first = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {owner[0]}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "Claude"}}},
    )
    assert first.status_code == 200, first.text
    agent_id = _claude((await client.get("/agents")).json())[0]["id"]
    created = await client.post(
        "/tool-sets",
        json={"name": "Phone", "items": [{"tool_id": "tool_crm_get_customer", "approval": False}]},
    )
    assert (await client.patch(f"/agents/{agent_id}", json={"tool_set_id": created.json()["id"]})).status_code == 200

    # A different client ID cannot inherit assignments, even with overlapping redirect hosts.
    intruder = await oauth_tokens(
        client,
        "Claude",
        redirect_uri=new_redirect,
        redirect_uris=[new_redirect, *extra_redirects],
    )
    assert intruder[2] != owner[2]
    joined = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {intruder[0]}"},
        json={"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"clientInfo": {"name": "Claude"}}},
    )
    assert joined.status_code == 200, joined.text
    listed = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {intruder[0]}"},
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    )
    assert listed.json()["result"]["tools"] == []

    agents = _claude((await client.get("/agents")).json())
    assert len(agents) == 2
    original = next(item for item in agents if item["id"] == agent_id)
    assert original["client_id"] == owner[2]
    assert original["tool_set_id"] == created.json()["id"]
    still = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {owner[0]}"},
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
    )
    assert [tool["name"] for tool in still.json()["result"]["tools"]] == ["crm.get_customer"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "step",
    # Before the existing-id check, and between that check and the insert.
    ["_over_agent_limit", "_insert_client_agent"],
)
async def test_two_initializes_at_once_share_one_agent(client, monkeypatch, step):
    from app.features.mcp.saturn.services.saturn_mcp import SaturnMcp

    access, _refresh, client_id = await oauth_tokens(client, "Claude")
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "Claude"}}}
    headers = {"Authorization": f"Bearer {access}"}
    real = getattr(SaturnMcp, step)
    inner: list = []

    async def raced(self, *args):
        if not inner:
            inner.append(None)
            # The second initialize runs to completion in its own session after this one found
            # no agent: the order production saw.
            inner[0] = await client.post("/mcp", headers=headers, json=initialize)
        return await real(self, *args)

    monkeypatch.setattr(SaturnMcp, step, raced)
    outer = await client.post("/mcp", headers=headers, json=initialize)

    assert inner[0].status_code == 200, inner[0].text
    assert outer.status_code == 200, outer.text
    assert "result" in outer.json() and outer.headers["mcp-session-id"]
    agents = _claude((await client.get("/agents")).json())
    assert len(agents) == 1
    assert agents[0]["client_id"] == client_id
    # The request that lost the race is bound to the winner's agent rather than to none.
    from app.features.mcp.saturn.services.mcp_sessions import mcp_sessions

    me = (await client.get("/auth/me")).json()["id"]
    record = await mcp_sessions.get(outer.headers["mcp-session-id"], me, client_id)
    assert record is not None and record.agent_id == agents[0]["id"]


class _SharedRedis:
    """Enough of Redis for the session hub. Published events reach the hub as its listener would."""

    def __init__(self, hub) -> None:
        self.hub = hub
        self.values: dict[str, str] = {}

    async def get(self, key: str):
        return self.values.get(key)

    async def set(self, key: str, value: str, ex=None, nx=False, xx=False):
        if (nx and key in self.values) or (xx and key not in self.values):
            return None
        self.values[key] = value
        return True

    async def delete(self, key: str) -> int:
        return int(self.values.pop(key, None) is not None)

    async def publish(self, _channel: str, raw: str) -> int:
        import json

        body = json.loads(raw)
        if body["kind"] == "notify":
            self.hub._notify_local(body["agent_ids"])
        elif body["kind"] == "close":
            self.hub._close_local(body["session_id"])
        return 1


@pytest.mark.asyncio
async def test_an_old_stream_ending_does_not_detach_the_new_one():
    from app.features.mcp.saturn.services.mcp_sessions import LIST_CHANGED, McpSessionHub

    hub = McpSessionHub()
    hub._redis = _SharedRedis(hub)
    assert await hub.open("s1", "user_1", "agent_1", "client_1") is not None

    # The client reconnects on this instance before the old stream's cleanup has run.
    old = await hub.get("s1", "user_1", "client_1")
    old_stream = hub.listen(old)
    new = await hub.get("s1", "user_1", "client_1")
    new_stream = hub.listen(new)
    await hub.detach(old, old_stream)

    await hub.notify(["agent_1"])
    assert new.queue.get_nowait() == LIST_CHANGED

    # The newest stream still cleans up after itself, and the session lives on in Redis.
    await hub.detach(new, new_stream)
    assert "s1" not in hub._items
    rebuilt = await hub.get("s1", "user_1", "client_1")
    assert rebuilt is not None and rebuilt is not new
    await hub.notify(["agent_1"])
    assert rebuilt.queue.get_nowait() == LIST_CHANGED


@pytest.mark.asyncio
async def test_without_redis_a_finished_stream_keeps_the_session():
    from app.features.mcp.saturn.services.mcp_sessions import McpSessionHub

    hub = McpSessionHub()
    record = await hub.open("s1", "user_1", "agent_1", "client_1")
    await hub.detach(record, hub.listen(record))
    assert await hub.get("s1", "user_1", "client_1") is record
