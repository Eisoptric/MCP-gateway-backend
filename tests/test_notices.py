from tests.gateway_calls import REFUND_POLICY, TOOL, call, connected_agent, held


def _capture(sent: list):
    async def capture(email, *, kind, tool, agent, link, locale=None, lines=(), detail=""):
        sent.append({"email": email, "kind": kind, "tool": tool, "detail": detail, "lines": lines, "link": link})
        return True

    return capture


async def test_profile_notices_email_only_the_selected_events(client, monkeypatch):
    sent: list[dict] = []
    monkeypatch.setattr("app.features.identity.auth.services.notices.send_notice", _capture(sent))

    current = await client.get("/auth/notices")
    assert current.status_code == 200
    assert current.json() == {"approval": False, "execute": False, "audit": False}
    saved = await client.patch("/auth/notices", json={"approval": True, "execute": False, "audit": False})
    assert saved.status_code == 200
    assert saved.json()["approval"] is True

    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    held(await call(client, agent, {"amount": 840}))
    # A denied call is a security event, which this person did not choose.
    await call(client, agent, {"amount": 5000})
    assert [item["kind"] for item in sent] == ["approval"]
    assert sent[0]["email"] == "rick@example.com"
    assert sent[0]["tool"] == TOOL
    assert "/approvals" in sent[0]["link"]
    assert "sk-" not in " ".join(str(value) for value in sent[0].values())


async def test_a_denied_call_sends_a_security_alert(client, monkeypatch):
    sent: list[dict] = []
    monkeypatch.setattr("app.features.identity.auth.services.notices.send_notice", _capture(sent))
    saved = await client.patch("/auth/notices", json={"approval": False, "execute": True, "audit": True})
    assert saved.status_code == 200
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    body = await call(client, agent, {"amount": 5000})
    assert body["error"]["data"]["code"] == "policy_denied"
    assert [item["kind"] for item in sent] == ["security"]
    assert TOOL in sent[0]["tool"]


async def test_approving_a_call_does_not_claim_it_completed(client, monkeypatch):
    sent: list[dict] = []
    monkeypatch.setattr("app.features.identity.auth.services.notices.send_notice", _capture(sent))
    saved = await client.patch("/auth/notices", json={"approval": True, "execute": True, "audit": True})
    assert saved.status_code == 200
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    approval_id, _run_id = held(await call(client, agent, {"amount": 840}))
    assert [item["kind"] for item in sent] == ["approval"]
    approved = await client.post(f"/approvals/{approval_id}/approve")
    assert approved.status_code == 200, approved.text
    # Approval only lets the agent resubmit; nothing has run yet, so no completion email.
    assert [item["kind"] for item in sent] == ["approval"]


async def test_email_delivery_failure_leaves_the_call_and_its_audit(client, monkeypatch):
    from app.features.execution.activity.services.audit_service import audit_service

    audits: list[str] = []
    original = audit_service.log

    async def record(*args, **kwargs):
        event = kwargs.get("event")
        audits.append(getattr(event, "value", event))
        return await original(*args, **kwargs)

    async def broken(*args, **kwargs):
        raise RuntimeError("mailbox down")

    monkeypatch.setattr(audit_service, "log", record)
    monkeypatch.setattr("app.features.identity.auth.services.notices.send_notice", broken)
    saved = await client.patch("/auth/notices", json={"approval": True, "execute": True, "audit": True})
    assert saved.status_code == 200
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    approval_id, _run_id = held(await call(client, agent, {"amount": 840}))
    assert (await client.get(f"/approvals/{approval_id}")).json()["status"] == "pending"
    assert "approval_requested" in audits


def test_task_notice_does_not_include_secrets():
    from types import SimpleNamespace

    from app.features.identity.auth.services.mailer import _notice_message
    from app.features.identity.auth.services.notices import _approval_lines, _public_text

    lines = _approval_lines(SimpleNamespace(payload={"arguments": {"api_key": "sk_live_secret", "amount": 50}}), None, {})
    assert lines == ("Status · Pending",)
    assert "sk_live_secret" not in " ".join(lines)
    assert _public_text("Bearer sk_live_secret", 80) == ""
    _subject, text, html = _notice_message(
        "completed",
        "Refund 50 for Acme",
        "Acme Ops",
        "https://console.eisoptric.com/activity?event=run_1",
        "en-US",
        lines=lines,
        detail="",
    )
    assert "sk_live_secret" not in text
    assert "sk_live_secret" not in html
    assert "Task completed" in text
    assert "https://console.eisoptric.com/activity?event=run_1" in html
