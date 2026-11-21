from tests.gateway_calls import REFUND_POLICY, TOOL, call, connected_agent, held
from tests.policy_helpers import activate_created


async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_status_reports_each_service(client):
    response = await client.get("/status")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["checked_at"]
    # No Redis in this test runtime, so it is not listed as if it were being checked.
    assert body["services"] == [
        {"id": "api", "name": "API", "status": "operational"},
        {"id": "database", "name": "Database", "status": "operational"},
    ]


async def test_a_dependency_outage_shows_in_status_and_never_in_health(client, monkeypatch):
    """A probe that fails with the database gets the API restarted for something a restart cannot fix."""
    from app.core import rate_limit
    from app.core import status as service_status

    async def down():
        return "down"

    class Redis:
        async def ping(self):
            return True

    monkeypatch.setattr(service_status, "_database", down)
    monkeypatch.setattr(rate_limit, "_use_redis", lambda: True)
    monkeypatch.setattr(rate_limit, "_redis_client", lambda: Redis())
    report = await client.get("/status")
    assert report.status_code == 200
    assert report.json()["status"] == "error"
    assert {item["id"]: item["status"] for item in report.json()["services"]} == {
        "api": "operational",
        "database": "down",
        "redis": "operational",
    }
    for path in ("/health", "/healthz"):
        probe = await client.get(path)
        assert probe.status_code == 200 and probe.json() == {"status": "ok"}


async def test_status_is_reused_for_a_few_seconds_and_a_slow_check_is_cut_short(client, monkeypatch):
    import asyncio

    from app.core import status as service_status

    calls = []

    async def counted():
        calls.append(1)
        return "operational"

    monkeypatch.setattr(service_status, "_database", counted)
    first = (await client.get("/status")).json()
    assert (await client.get("/status")).json() == first
    assert len(calls) == 1  # public and unauthenticated: a burst of requests is one query

    class Stuck:
        def connect(self):
            return self

        async def __aenter__(self):
            await asyncio.sleep(60)

        async def __aexit__(self, *_args):
            return False

    monkeypatch.undo()
    service_status.reset()
    monkeypatch.setattr(service_status, "CHECK_SECONDS", 0.05)
    monkeypatch.setattr("app.db.database.engine", Stuck())
    assert await service_status._database() == "down"


async def test_seeded_catalog(client):
    agents = (await client.get("/agents")).json()
    tools = (await client.get("/tools")).json()
    policies = (await client.get("/policies")).json()
    assert any(agent["id"] == "agent_customer_ops" for agent in agents)
    assert any(tool["name"] == "billing.refund" for tool in tools)
    refund = next(policy for policy in policies if policy["id"] == "policy_refund")
    assert [rule["decision"] for rule in refund["rules"]] == ["allow", "approval", "deny"]


async def test_a_call_above_the_limit_waits_for_approval_and_runs_once_approved(client, monkeypatch):
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    approval_id, run_id = held(await call(client, agent, {"amount": 840, "customer": "Acme"}))
    assert agent.sent == []

    approved = await client.post(f"/approvals/{approval_id}/approve")
    assert approved.status_code == 200, approved.text
    assert (await client.get(f"/approvals/{approval_id}")).json()["status"] == "approved"
    # Approval does not run the tool: the agent sends the call again under the same run.
    assert agent.sent == []
    again = await call(client, agent, {"amount": 840, "customer": "Acme"}, run_id=run_id)
    assert again["result"]["content"][0]["text"] == "refunded"
    assert agent.sent == [{"amount": 840, "customer": "Acme"}]


async def test_a_call_within_the_limit_runs_without_approval(client, monkeypatch):
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    body = await call(client, agent, {"amount": 50, "customer": "Acme"})
    assert body["result"]["content"][0]["text"] == "refunded"
    assert agent.sent == [{"amount": 50, "customer": "Acme"}]


async def test_a_call_over_the_hard_limit_is_denied(client, monkeypatch):
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    body = await call(client, agent, {"amount": 5000, "customer": "Acme"})
    assert body["error"]["data"]["code"] == "policy_denied"
    assert agent.sent == []


async def test_a_rejected_call_is_never_sent(client, monkeypatch):
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    approval_id, run_id = held(await call(client, agent, {"amount": 840}))
    rejected = await client.post(f"/approvals/{approval_id}/reject")
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "rejected"
    again = await call(client, agent, {"amount": 840}, run_id=run_id)
    assert "error" in again
    assert agent.sent == []


async def test_approve_rechecks_policy(client, monkeypatch):
    agent = await connected_agent(client, monkeypatch, policy=REFUND_POLICY)
    approval_id, run_id = held(await call(client, agent, {"amount": 840}))
    tightened = await client.post(
        "/policies",
        json={"name": "Block refunds", "rules": [{"tool": TOOL, "condition": "amount > 0", "decision": "deny"}]},
    )
    await activate_created(client, tightened)
    # Whether the approval is refused at once or the resubmitted call is, the refund never goes out.
    await client.post(f"/approvals/{approval_id}/approve")
    again = await call(client, agent, {"amount": 840}, run_id=run_id)
    assert "error" in again, again
    assert agent.sent == []


async def _session():
    from app.db.database import get_session
    from app.main import app

    generator = app.dependency_overrides[get_session]()
    return generator, await anext(generator)


async def test_samples_become_daily_uptime_in_the_history(client, monkeypatch):
    from datetime import timedelta

    from app.core import status as service_status
    from app.core.ids import utcnow
    from app.shared.models.status_day import StatusDay

    today = utcnow().date()
    generator, session = await _session()
    try:
        # Three samples today: the database fails one of them. Redis is not part of this deployment.
        await service_status.record(session, {"api": "operational", "database": "operational"})
        await service_status.record(session, {"api": "operational", "database": "down"})
        await service_status.record(session, {"api": "operational", "database": "operational"})
        # An older day inside the window, and one outside it.
        session.add(StatusDay(day=today - timedelta(days=5), service_id="database", checks=1440, failures=144))
        session.add(StatusDay(day=today - timedelta(days=120), service_id="database", checks=1440, failures=1440))
        await session.commit()
    finally:
        await generator.aclose()

    body = (await client.get("/status/history")).json()
    assert body["days"] == 90 and body["to"] == today.isoformat()
    assert [item["id"] for item in body["services"]] == ["api", "database"]
    api, database = body["services"]
    assert api["uptime"] == 100.0 and api["days"] == [{"day": today.isoformat(), "uptime": 100.0, "checks": 3, "failures": 0}]
    assert [item["day"] for item in database["days"]] == [(today - timedelta(days=5)).isoformat(), today.isoformat()]
    assert database["days"][0]["uptime"] == 90.0
    assert database["days"][1] == {"day": today.isoformat(), "uptime": 66.667, "checks": 3, "failures": 1}
    # 1443 checks, 145 failures. The day outside the window is not counted.
    assert database["uptime"] == round(100 * (1443 - 145) / 1443, 3)

    assert (await client.get("/status/history", params={"days": 91})).status_code == 422
    service_status._history.clear()
    week = (await client.get("/status/history", params={"days": 3})).json()
    assert [len(item["days"]) for item in week["services"]] == [1, 1]


async def test_a_sample_taken_while_the_database_is_down_is_written_when_it_returns(client):
    """The outage is the sample that matters most, and it cannot be stored while it lasts."""
    from sqlalchemy import select

    from app.core import status as service_status
    from app.shared.models.status_day import StatusDay

    class Broken:
        async def execute(self, *_args, **_kwargs):
            raise ConnectionError("database is down")

        async def rollback(self):
            return None

    await service_status.record(Broken(), {"api": "operational", "database": "down"})
    await service_status.record(Broken(), {"api": "operational", "database": "down"})
    assert sorted(service_status._pending.values()) == [[2, 0], [2, 2]]

    generator, session = await _session()
    try:
        await service_status.record(session, {"api": "operational", "database": "operational"})
        rows = {row.service_id: (row.checks, row.failures) for row in await session.scalars(select(StatusDay))}
    finally:
        await generator.aclose()
    assert rows == {"api": (3, 0), "database": (3, 2)}
    assert service_status._pending == {}


async def test_the_api_is_sampled_from_outside_when_it_has_a_public_address(monkeypatch):
    import httpx

    from app.core import status as service_status

    monkeypatch.delenv("PUBLIC_WS_URL", raising=False)
    assert await service_status._api_from_outside() == "operational"

    asked: list[str] = []
    answers = iter([httpx.Response(200, json={"status": "ok"}), httpx.Response(503), httpx.ConnectError("refused")])
    real = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(str(request.url))
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(service_status.httpx, "AsyncClient", lambda **kwargs: real(transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setenv("PUBLIC_WS_URL", "wss://api.eisoptric.com")
    assert [await service_status._api_from_outside() for _ in range(3)] == ["operational", "down", "down"]
    assert asked == ["https://api.eisoptric.com/health"] * 3


async def test_two_samples_recorded_at_once_are_each_counted_once(client):
    import asyncio

    from sqlalchemy import select

    from app.core import status as service_status
    from app.shared.models.status_day import StatusDay

    first_generator, first = await _session()
    second_generator, second = await _session()
    try:
        await asyncio.gather(
            service_status.record(first, {"api": "operational", "database": "down"}),
            service_status.record(second, {"api": "operational", "database": "operational"}),
        )
        rows = {row.service_id: (row.checks, row.failures) for row in await first.scalars(select(StatusDay))}
    finally:
        await first_generator.aclose()
        await second_generator.aclose()
    assert rows == {"api": (2, 0), "database": (2, 1)}
