async def test_me_includes_enterprise_employee_agents_and_mcp(client):
    me = (await client.get("/auth/me")).json()
    assert me["id"] == "user_operator"
    assert me["profile_id"] == "org_default:user_operator"
    assert me["organization"]["id"] == "org_default"
    assert me["enterprise"]["id"] == "org_default"
    assert me["enterprise"]["name"] == me["organization"]["name"]
    assert me["employee"]["id"] == "emp_operator"
    assert me["employee"]["title"] == "Operator"
    assert {agent["id"] for agent in me["agents"]} >= {"agent_customer_ops", "agent_unmapped"}
    assert "agent_customer_ops" in me["assigned_agent_ids"]
    assert "agent_unmapped" not in me["assigned_agent_ids"]
    names = {server["name"] for server in me["mcp_servers"]}
    assert names == {"Billing", "CRM", "Email"}
    billing = next(server for server in me["mcp_servers"] if server["id"] == "mcp_billing")
    assert "billing.refund" in billing["tools"]
    assert billing["connected"] is True
    assert me["mcp_gateway"]["status"] == "connected"
    assert me["mcp_gateway"]["connected"] == 3
    assert me["mcp_gateway"]["total"] == 3
    assert any(user["email"] == "rick@example.com" for user in me["users"])


async def test_catalog_is_scoped_to_org(client):
    agents = (await client.get("/agents")).json()
    assert {agent["id"] for agent in agents} >= {"agent_customer_ops", "agent_unmapped"}
    assert (await client.get("/agents/agent_unmapped")).status_code == 200

    tools = (await client.get("/tools")).json()
    assert {tool["name"] for tool in tools} == {
        "billing.get_payment",
        "billing.refund",
        "crm.get_customer",
        "email.send",
    }
    refund = next(tool for tool in tools if tool["name"] == "billing.refund")
    assert refund["mcp_server_id"] == "mcp_billing"

    servers = (await client.get("/mcp-servers")).json()
    assert {server["id"] for server in servers} == {"mcp_billing", "mcp_crm", "mcp_email"}
    assert all(server["connected"] is True for server in servers)

    org = (await client.get("/org")).json()
    assert {agent["id"] for agent in org["agents"]} >= {"agent_customer_ops"}
    assert {server["id"] for server in org["mcp_servers"]} == {"mcp_billing", "mcp_crm", "mcp_email"}
    assert any(user["email"] == "rick@example.com" for user in org["users"])
    users = (await client.get("/org/users")).json()
    assert any(user["email"] == "rick@example.com" for user in users)


async def test_retired_run_and_agent_creation_routes_are_gone(client):
    assert (await client.post("/runs", json={"agent_id": "agent_unmapped", "input": "Refund 50 for Acme"})).status_code == 404
    assert (await client.get("/runs")).status_code == 404
    assert (
        await client.post(
            "/agents",
            json={"name": "Broke Ops", "description": "No funds", "model": "claude-sonnet"},
        )
    ).status_code == 405
    assert (await client.patch("/agents/agent_customer_ops", json={"model": "claude-sonnet"})).status_code == 422


async def test_connecting_mcp_client_registers_agent_in_catalog(client):
    from tests.oauth_access import oauth_access

    access = await oauth_access(client, "Broke Ops")
    opened = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "Broke Ops"}}},
    )
    assert opened.status_code == 200, opened.text

    agents = (await client.get("/agents")).json()
    agent = next(item for item in agents if item["name"] == "Broke Ops")
    assert agent["origin"] == "gateway_mcp"
    assert agent["enrolled"] is True
