"""Tool calls the way production makes them: an agent signed in with OAuth calls a tool through
POST /mcp, the policy decides, and an approved call is sent to a stand-in MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field

from tests.oauth_access import oauth_access
from tests.policy_helpers import create_active_policy

TOOL = "refund.create"
ENDPOINT = "https://mcp.stripe.com/mcp"

# The refund policy the old simulated runs exercised: small refunds run, larger ones wait for a
# person, and very large ones are refused.
REFUND_POLICY = {
    "name": "Refund limits",
    "rules": [
        {"tool": TOOL, "condition": "amount <= 100", "decision": "allow"},
        {"tool": TOOL, "condition": "amount > 100 AND amount <= 1000", "decision": "approval_required"},
        {"tool": TOOL, "condition": "amount > 1000", "decision": "deny"},
    ],
}


@dataclass
class Agent:
    access: str
    id: str
    sent: list[dict] = field(default_factory=list)


async def connected_agent(client, monkeypatch, *, name: str = "Refund Agent", approval: bool = False, policy: dict | None = None) -> Agent:
    """Connects a stand-in MCP server with TOOL, puts it in a tool set for a new OAuth agent, and
    returns that agent. `sent` collects the arguments of every call that reached the server."""
    sent: list[dict] = []

    async def listed(endpoint, authorization="", **_kwargs):
        schema = {"type": "object", "properties": {"amount": {"type": "number"}, "customer": {"type": "string"}}}
        return [{"name": TOOL, "description": "Refund a charge", "inputSchema": schema}]

    async def called(endpoint, name, arguments, authorization="", **_kwargs):
        sent.append(dict(arguments))
        return {"content": [{"type": "text", "text": "refunded"}], "tool": name}

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    monkeypatch.setattr("app.features.mcp.gateway.services.gateway_mcp.call_remote_tool", called)
    connected = await client.post("/mcp-servers", json={"name": "Refunds", "endpoint": ENDPOINT, "authorization": "token-1"})
    assert connected.status_code == 201, connected.text
    tool_id = next(item["id"] for item in connected.json()["catalog"] if item["name"] == TOOL)
    tool_set = await client.post("/tool-sets", json={"name": f"{name} tools", "items": [{"tool_id": tool_id, "approval": approval}]})
    assert tool_set.status_code == 201, tool_set.text
    if policy is not None:
        await create_active_policy(client, policy)
    access = await oauth_access(client, name)
    opened = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": name}}},
    )
    assert opened.status_code == 200, opened.text
    agent_id = next(item["id"] for item in (await client.get("/agents")).json() if item["name"] == name)
    assigned = await client.patch(f"/agents/{agent_id}", json={"tool_set_id": tool_set.json()["id"]})
    assert assigned.status_code == 200, assigned.text
    return Agent(access=access, id=agent_id, sent=sent)


async def call(client, agent: Agent, arguments: dict, *, run_id: str = "") -> dict:
    """One tools/call for TOOL. Returns the JSON-RPC body."""
    payload = dict(arguments)
    if run_id:
        payload["gatewayRunId"] = run_id
    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {agent.access}", "X-Eisoptric-Agent-Id": agent.id},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": TOOL, "arguments": payload}},
    )
    assert response.status_code == 200, response.text
    return response.json()


def held(body: dict) -> tuple[str, str]:
    """The approval id and run id of a call the policy held for approval."""
    data = body["error"]["data"]
    assert data["code"] == "approval_pending", body
    return data["approval_id"], data["gatewayRunId"]
