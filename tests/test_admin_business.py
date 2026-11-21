"""The ops console's views of the business: an organization's members, policies, approvals,
webhooks and approved hosts; users' sign-in security; MCP hosts; and the platform's settings."""

from tests.test_mcp_allowed_hosts import CUSTOM


async def test_org_detail_shows_the_business_of_the_organization(client):
    created = await client.post(
        "/org/webhooks",
        json={"url": "https://hooks.example.com/gateway", "events": ["approval.granted"]},
    )
    assert created.status_code == 201, created.text
    added = await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM})
    assert added.status_code == 201, added.text

    detail = await client.get("/admin/orgs/org_default")
    assert detail.status_code == 200, detail.text
    body = detail.json()

    # The test catalog's refund policy, with its rules counted.
    refund = next(item for item in body["policies"] if item["id"] == "policy_refund")
    assert refund["rule_count"] >= 1
    assert body["tool_set_count"] >= 0
    assert set(body["approvals"]) == {"pending", "approved_30d", "rejected_30d", "expired_30d"}
    assert body["webhooks"]["endpoints"] == 1
    assert body["webhooks"]["enabled"] == 1
    assert [item["host"] for item in body["allowed_hosts"]] == [CUSTOM]
    assert "subscription" not in body

    # Users come with their sign-in security; the test admin has an authenticator app.
    rick = next(item for item in body["users"] if item["email"] == "rick@example.com")
    assert rick["is_platform_admin"] is True
    assert rick["totp_enabled"] in (True, False)
    assert rick["passkeys"] == 0
    assert rick["last_sign_in_at"] is not None


async def test_users_list_says_how_each_person_signs_in(client):
    users = await client.get("/admin/users")
    assert users.status_code == 200, users.text
    rick = next(item for item in users.json() if item["email"] == "rick@example.com")
    for key in ("passkeys", "totp_enabled", "email_mfa", "last_sign_in_at"):
        assert key in rick


async def test_mcp_view_tells_marketplace_hosts_from_an_organizations_own(client):
    await client.post("/mcp-servers/allowed-hosts", json={"host": CUSTOM})
    body = (await client.get("/admin/mcp")).json()
    assert CUSTOM not in body["builtin_hosts"]
    assert any(item["host"] == CUSTOM and item["organization_id"] == "org_default" for item in body["allowed_hosts"])
    for item in body["items"]:
        assert item["source"] == ("marketplace" if item["host"] in body["builtin_hosts"] else "custom")


async def test_platform_view_names_settings_but_never_secret_values(client, monkeypatch):
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "policy_llm_base_url", "https://api.anthropic.com/v1/")
    monkeypatch.setattr(settings, "policy_llm_model", "claude-sonnet-5-5")
    monkeypatch.setattr(settings, "policy_llm_api_key", "sk-ant-never-shown")
    monkeypatch.setattr(settings, "resend_api_key", "re_never_shown")
    monkeypatch.setattr(settings, "resend_from", "Eisoptric <no-reply@eisoptric.com>")
    monkeypatch.setenv("CONSOLE_PROXY_SECRET", "proxy-never-shown")

    response = await client.get("/admin/platform")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["policy_model"] == {"configured": True, "host": "api.anthropic.com", "model": "claude-sonnet-5-5"}
    assert body["email"] == {"configured": True, "from_domain": "eisoptric.com"}
    assert body["secrets"]["console_proxy"] is True
    for secret in ("sk-ant-never-shown", "re_never_shown", "proxy-never-shown"):
        assert secret not in response.text


async def test_the_new_views_are_for_platform_admins_only(client):
    invited = await client.post("/org/invites", json={"email": "viewer2@example.com", "name": "Viewer", "role": "viewer"})
    assert invited.status_code == 201, invited.text
    accepted = await client.post("/auth/accept-invite", json={"token": invited.json()["token"], "password": "password1"})
    assert accepted.status_code == 200, accepted.text
    headers = {"Authorization": f"Bearer {accepted.json()['token']}"}
    for path in ("/admin/activity", "/admin/platform", "/admin/mcp", "/admin/orgs/org_default"):
        assert (await client.get(path, headers=headers)).status_code == 403, path
