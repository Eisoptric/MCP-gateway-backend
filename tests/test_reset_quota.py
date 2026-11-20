"""Other people's reset requests must not use up the quota the account owner needs."""

from datetime import timedelta

from app.core.ids import utcnow
from app.features.identity.auth.models.throttle import AuthThrottle


async def _quiet(monkeypatch) -> list[str]:
    sent: list[str] = []

    async def capture(_email, code, _locale=None):
        sent.append(code)

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_reset_code", capture)
    return sent


async def _flood(bucket: str, count: int) -> None:
    from app.db.database import get_session
    from app.main import app

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        for index in range(count):
            session.add(
                AuthThrottle(
                    id=f"thr_flood_{index}",
                    bucket=bucket,
                    created_at=utcnow() - timedelta(hours=1, minutes=index),
                )
            )
        await session.commit()
    finally:
        await generator.aclose()


async def test_requests_from_another_address_do_not_block_the_owner(client, monkeypatch):
    sent = await _quiet(monkeypatch)
    client.headers.pop("Authorization", None)
    attacker = {"X-Forwarded-For": "203.0.113.66"}
    first = await client.post("/auth/forgot-password", headers=attacker, json={"email": "rick@example.com"})
    assert first.status_code == 204
    again = await client.post("/auth/forgot-password", headers=attacker, json={"email": "rick@example.com"})
    assert again.status_code == 429
    # The owner, a moment later from their own address, still gets a code, and it works.
    owner = {"X-Forwarded-For": "198.51.100.20"}
    mine = await client.post("/auth/forgot-password", headers=owner, json={"email": "rick@example.com"})
    assert mine.status_code == 204, mine.text
    reset = await client.post(
        "/auth/reset-password",
        headers=owner,
        json={"email": "rick@example.com", "code": sent[-1], "password": "a-new-password"},
    )
    assert reset.status_code == 204, reset.text


async def test_past_the_daily_ceiling_only_a_known_address_may_ask(client, monkeypatch):
    await _quiet(monkeypatch)
    # The owner signed in from home before.
    home = {"X-Forwarded-For": "198.51.100.20"}
    signed = await client.post("/auth/login", headers=home, json={"email": "rick@example.com", "password": "gateway"})
    assert signed.status_code == 200, signed.text
    client.headers.pop("Authorization", None)
    await _flood("email-all:reset:rick@example.com", 30)

    stranger = await client.post(
        "/auth/forgot-password", headers={"X-Forwarded-For": "203.0.113.9"}, json={"email": "rick@example.com"}
    )
    assert stranger.status_code == 429
    owner = await client.post("/auth/forgot-password", headers=home, json={"email": "rick@example.com"})
    assert owner.status_code == 204, owner.text
