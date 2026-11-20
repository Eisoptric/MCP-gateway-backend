"""With no policy rule for a tool, the agent's tool set decides: approval, or allow."""

import pytest

from app.core.config import get_settings
from app.features.policy.policies.services.policy_engine import TOOL_SET_ALLOW, TOOL_SET_APPROVAL
from tests.oauth_access import oauth_access
from tests.policy_helpers import activate_created


@pytest.fixture
def default_deny():
    # Production default. The test settings turn it off.
    settings = get_settings()
    previous = settings.policy_default_deny
    settings.policy_default_deny = True
    yield
    settings.policy_default_deny = previous


async def _setup(client, monkeypatch, approvals: dict[str, bool]):
    sent = []

    async def listed(endpoint, authorization="", **_kwargs):
        return [{"name": name, "description": name, "inputSchema": {"type": "object", "properties": {}}} for name in approvals]

    async def called(endpoint, name, arguments, authorization="", **_kwargs):
        sent.append(name)
        return {"content": [{"type": "text", "text": "ok"}], "tool": name}

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.gateway.services.gateway_mcp.call_remote_tool", called)
    connected = await client.post(
        "/mcp-servers",
        json={"name": "Notes", "endpoint": "https://api.githubcopilot.com/mcp", "authorization": "token-1"},
    )
    assert connected.status_code == 201, connected.text
    ids = {item["name"]: item["id"] for item in connected.json()["catalog"]}
    access = await oauth_access(client, "Cursor")
    opened = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert opened.status_code == 200, opened.text
    agent_id = next(item["id"] for item in (await client.get("/agents")).json() if item["name"] == "Cursor")
    created = await client.post(
        "/tool-sets",
        json={"name": "Notes", "items": [{"tool_id": ids[name], "approval": needs} for name, needs in approvals.items()]},
    )
    assert created.status_code == 201, created.text
    assert (await client.patch(f"/agents/{agent_id}", json={"tool_set_id": created.json()["id"]})).status_code == 200
    return access, created.json()["id"], ids, sent


async def _call(client, access, name, run_id=""):
    arguments = {"gatewayRunId": run_id} if run_id else {}
    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def test_without_a_policy_the_tool_set_allows_or_holds_for_approval(client, monkeypatch, default_deny):
    access, _set_id, _ids, sent = await _setup(client, monkeypatch, {"notes.read": False, "notes.delete": True})

    allowed = await _call(client, access, "notes.read")
    assert allowed["result"]["tool"] == "notes.read", allowed
    assert sent == ["notes.read"]

    held = await _call(client, access, "notes.delete")
    assert "error" in held, held
    approval_id = held["error"]["data"]["approval_id"]
    assert sent == ["notes.read"]
    approval = (await client.get(f"/approvals/{approval_id}")).json()
    assert approval["status"] == "pending"

    approved = await client.post(f"/approvals/{approval_id}/approve")
    assert approved.status_code == 200, approved.text
    ran = await _call(client, access, "notes.delete", run_id=held["error"]["data"]["gatewayRunId"])
    assert ran["result"]["tool"] == "notes.delete", ran
    assert sent == ["notes.read", "notes.delete"]

    reasons = [
        item["payload"].get("reason")
        for item in (await client.get("/activity?limit=100")).json()
        if item["event"] == "policy_evaluated" and item.get("payload")
    ]
    assert TOOL_SET_ALLOW in reasons and TOOL_SET_APPROVAL in reasons, reasons


async def test_a_policy_rule_for_the_tool_still_decides(client, monkeypatch, default_deny):
    access, _set_id, _ids, sent = await _setup(client, monkeypatch, {"notes.read": False})
    created = await client.post(
        "/policies",
        json={"name": "No reading", "rules": [{"tool": "notes.read", "condition": "true", "decision": "deny"}]},
    )
    await activate_created(client, created)
    denied = await _call(client, access, "notes.read")
    assert "error" in denied, denied
    assert sent == []


async def test_a_policy_with_rules_for_other_tools_does_not_block_the_fallback(client, monkeypatch, default_deny):
    access, _set_id, _ids, sent = await _setup(client, monkeypatch, {"notes.read": False, "notes.list": False})
    created = await client.post(
        "/policies",
        json={"name": "Listing", "rules": [{"tool": "notes.list", "condition": "true", "decision": "deny"}]},
    )
    await activate_created(client, created)
    allowed = await _call(client, access, "notes.read")
    assert allowed["result"]["tool"] == "notes.read", allowed
    assert "error" in await _call(client, access, "notes.list")
    assert sent == ["notes.read"]


async def test_turning_approval_on_in_the_tool_set_applies_to_the_next_call(client, monkeypatch, default_deny):
    access, set_id, ids, sent = await _setup(client, monkeypatch, {"notes.read": False})
    assert "result" in await _call(client, access, "notes.read")
    changed = await client.patch(
        f"/tool-sets/{set_id}", json={"items": [{"tool_id": ids["notes.read"], "approval": True}]}
    )
    assert changed.status_code == 200, changed.text
    held = await _call(client, access, "notes.read")
    assert held["error"]["data"]["approval_id"], held
    assert sent == ["notes.read"]


async def test_an_approved_call_does_not_run_once_the_tool_leaves_the_set(client, monkeypatch, default_deny):
    access, set_id, ids, sent = await _setup(client, monkeypatch, {"notes.delete": True, "notes.read": False})
    held = await _call(client, access, "notes.delete")
    approval_id = held["error"]["data"]["approval_id"]
    assert (await client.post(f"/approvals/{approval_id}/approve")).status_code == 200
    removed = await client.patch(
        f"/tool-sets/{set_id}", json={"items": [{"tool_id": ids["notes.read"], "approval": False}]}
    )
    assert removed.status_code == 200, removed.text
    retried = await _call(client, access, "notes.delete", run_id=held["error"]["data"]["gatewayRunId"])
    assert retried["error"]["message"] == "Agent is not allowed to call this tool", retried
    assert sent == []


async def test_the_engine_falls_back_only_for_tools_in_the_set(client, monkeypatch, default_deny):
    from sqlalchemy import select

    from app.core.enums import PolicyDecision
    from app.db.database import get_session
    from app.features.policy.policies.services.policy_engine import policy_engine
    from app.main import app
    from app.models import Agent

    await _setup(client, monkeypatch, {"notes.read": True})
    generator = app.dependency_overrides[get_session]()
    session = await generator.__anext__()
    try:
        agent = await session.scalar(select(Agent).where(Agent.name == "Cursor"))
        inside = await policy_engine.evaluate_named(
            session, organization_id=agent.organization_id, agent=agent, tool_name="notes.read", arguments={}
        )
        assert inside.decision == PolicyDecision.APPROVAL_REQUIRED
        assert inside.reason == TOOL_SET_APPROVAL
        outside = await policy_engine.evaluate_named(
            session, organization_id=agent.organization_id, agent=agent, tool_name="notes.other", arguments={}
        )
        assert outside.decision == PolicyDecision.DENY
        agent.tool_set_id = None
        without_set = await policy_engine.evaluate_named(
            session, organization_id=agent.organization_id, agent=agent, tool_name="notes.read", arguments={}
        )
        assert without_set.decision == PolicyDecision.DENY
    finally:
        await generator.aclose()


async def test_a_tool_added_without_saying_waits_for_approval(client, monkeypatch, default_deny):
    access, set_id, ids, sent = await _setup(client, monkeypatch, {"notes.read": False, "notes.write": False})
    # The tool is added with no approval setting.
    changed = await client.patch(
        f"/tool-sets/{set_id}",
        json={"items": [{"tool_id": ids["notes.read"], "approval": False}, {"tool_id": ids["notes.write"]}]},
    )
    assert changed.status_code == 200, changed.text
    modes = {item["tool_id"]: item["approval"] for item in changed.json()["items"]}
    assert modes == {ids["notes.read"]: False, ids["notes.write"]: True}
    held = await _call(client, access, "notes.write")
    assert held["error"]["data"]["approval_id"], held
    assert sent == []


async def test_deleting_the_default_policy_leaves_the_tool_set_in_charge(client, monkeypatch, default_deny):
    from sqlalchemy import select

    from app.db.database import get_session
    from app.features.policy.policies.services.default_policy import MARKER, ensure_default_policy
    from app.main import app
    from app.models import Policy

    access, _set_id, _ids, sent = await _setup(client, monkeypatch, {"notes.read": False})
    org_id = (await client.get("/auth/me")).json()["organization"]["id"]
    generator = app.dependency_overrides[get_session]()
    session = await generator.__anext__()
    try:
        default = await ensure_default_policy(session, org_id)
        await session.commit()
        default_id = default.id
    finally:
        await generator.aclose()

    # The default policy has a rule for the tool (unknown permissions: approval), so it decides.
    held = await _call(client, access, "notes.read")
    assert held["error"]["data"]["approval_id"], held
    assert sent == []

    deleted = await client.delete(f"/policies/{default_id}")
    assert deleted.status_code == 204, deleted.text
    allowed = await _call(client, access, "notes.read")
    assert allowed["result"]["tool"] == "notes.read", allowed
    assert sent == ["notes.read"]

    # Connecting another server does not bring the default policy back.
    connected = await client.post(
        "/mcp-servers",
        json={"name": "Notes 2", "endpoint": "https://mcp.linear.app/mcp", "authorization": "token-2"},
    )
    assert connected.status_code == 201, connected.text
    generator = app.dependency_overrides[get_session]()
    session = await generator.__anext__()
    try:
        assert await session.scalar(select(Policy).where(Policy.description == MARKER)) is None
    finally:
        await generator.aclose()
