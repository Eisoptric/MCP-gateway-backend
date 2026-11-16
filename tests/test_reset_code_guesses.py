"""Wrong reset codes are counted per (account, address), so a stranger cannot burn the owner's code."""

OWNER = {"X-Forwarded-For": "198.51.100.20"}
EMAIL = "rick@saturn.ai"


async def _requested(client, monkeypatch) -> list[str]:
    sent: list[str] = []

    async def capture(_email, code, _locale=None):
        sent.append(code)

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_reset_code", capture)
    client.headers.pop("Authorization", None)
    response = await client.post("/auth/forgot-password", headers=OWNER, json={"email": EMAIL})
    assert response.status_code == 204, response.text
    return sent


def _wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


async def _guess(client, headers: dict, code: str):
    return await client.post(
        "/auth/reset-password",
        headers=headers,
        json={"email": EMAIL, "code": code, "password": "a-new-password-1"},
    )


async def test_a_strangers_guesses_do_not_stop_the_owner(client, monkeypatch):
    sent = await _requested(client, monkeypatch)
    wrong = _wrong(sent[-1])
    # Several addresses spend their whole budget, short of the code's own ceiling.
    for n in range(4):
        stranger = {"X-Forwarded-For": f"203.0.113.{n}"}
        for _ in range(5):
            assert (await _guess(client, stranger, wrong)).status_code == 400
        assert (await _guess(client, stranger, wrong)).status_code == 429
    reset = await _guess(client, OWNER, sent[-1])
    assert reset.status_code == 204, reset.text


async def test_the_code_dies_at_its_ceiling_across_addresses(client, monkeypatch):
    from app.features.identity.auth.services.auth_service import RESET_CODE_CEILING

    sent = await _requested(client, monkeypatch)
    wrong = _wrong(sent[-1])
    for n in range(RESET_CODE_CEILING):
        assert (await _guess(client, {"X-Forwarded-For": f"10.9.{n // 5}.{n % 5}"}, wrong)).status_code == 400
    # Even the right code no longer works; the owner asks for a new one.
    assert (await _guess(client, OWNER, sent[-1])).status_code == 400


async def test_the_owners_own_wrong_guesses_still_count(client, monkeypatch):
    sent = await _requested(client, monkeypatch)
    for _ in range(5):
        assert (await _guess(client, OWNER, _wrong(sent[-1]))).status_code == 400
    assert (await _guess(client, OWNER, sent[-1])).status_code == 429


async def test_a_right_code_does_not_use_up_the_budget(client, monkeypatch):
    from app.core import rate_limit
    from starlette.requests import Request

    sent = await _requested(client, monkeypatch)
    for _ in range(4):
        assert (await _guess(client, OWNER, _wrong(sent[-1]))).status_code == 400
    assert (await _guess(client, OWNER, sent[-1])).status_code == 204
    scope = {"type": "http", "headers": [(b"x-forwarded-for", OWNER["X-Forwarded-For"].encode())], "client": None}
    # Four wrong guesses stay counted; the right one was given back.
    assert await rate_limit.reset_code_allowed(Request(scope), EMAIL)
    assert not await rate_limit.reset_code_allowed(Request(scope), EMAIL)


async def test_past_the_account_ceiling_only_a_known_address_may_guess(client, monkeypatch):
    monkeypatch.setattr("app.core.rate_limit.RESET_CODE_ACCOUNT_CEILING", 3)
    signed = await client.post("/auth/login", headers=OWNER, json={"email": EMAIL, "password": "saturn"})
    assert signed.status_code == 200, signed.text
    sent = await _requested(client, monkeypatch)
    for n in range(3):
        assert (await _guess(client, {"X-Forwarded-For": f"203.0.113.{n}"}, _wrong(sent[-1]))).status_code == 400
    assert (await _guess(client, {"X-Forwarded-For": "203.0.113.50"}, sent[-1])).status_code == 429
    assert (await _guess(client, OWNER, sent[-1])).status_code == 204
