"""A token family ends a fixed time after sign-in, and a replayed code ends the tokens it issued."""

import re
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from app.features.identity.oauth.services.oauth_service import REFRESH_FAMILY_TTL, pkce_s256

REDIRECT = "http://127.0.0.1:8765/callback"
VERIFIER = "c" * 43


async def _code(client) -> tuple[str, str]:
    """An authorization code and its client_id, through the real sign-in and consent pages."""
    client.headers.pop("Authorization", None)
    registered = await client.post("/oauth/register", json={"client_name": "Family Agent", "redirect_uris": [REDIRECT]})
    query = {
        "response_type": "code",
        "client_id": registered.json()["client_id"],
        "redirect_uri": REDIRECT,
        "code_challenge": pkce_s256(VERIFIER),
        "code_challenge_method": "S256",
        "state": "s",
    }
    await client.get("/oauth/authorize", params=query)
    signed = await client.post(
        "/oauth/login", data={**query, "email": "rick@example.com", "password": "gateway"}, follow_redirects=False
    )
    assert signed.status_code == 303, signed.text
    consent = await client.get(signed.headers["location"])
    csrf = re.search(r'name="csrf" value="([^"]+)"', consent.text).group(1)
    allowed = await client.post("/oauth/consent", data={**query, "csrf": csrf, "decision": "allow"}, follow_redirects=False)
    return parse_qs(urlparse(allowed.headers["location"]).query)["code"][0], query["client_id"]


async def _exchange(client, code: str, client_id: str):
    return await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
        },
    )


async def _refresh(client, refresh: str, client_id: str):
    return await client.post(
        "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": client_id}
    )


async def _mcp(client, access: str) -> int:
    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {access}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    return response.status_code


async def test_a_replayed_code_revokes_the_tokens_it_issued(client):
    code, client_id = await _code(client)
    first = await _exchange(client, code, client_id)
    assert first.status_code == 200, first.text
    tokens = first.json()
    # Refreshed once, so the family has moved on from the tokens the code returned.
    rotated = await _refresh(client, tokens["refresh_token"], client_id)
    assert rotated.status_code == 200, rotated.text
    assert await _mcp(client, rotated.json()["access_token"]) == 200

    replay = await _exchange(client, code, client_id)
    assert replay.status_code == 400
    assert replay.json()["detail"] == "invalid_grant"
    # Everything issued from that code is gone: the rotated access token and refresh token too.
    assert await _mcp(client, rotated.json()["access_token"]) == 401
    assert (await _refresh(client, rotated.json()["refresh_token"], client_id)).status_code == 400


async def test_a_replay_leaves_other_sign_ins_alone(client):
    code, client_id = await _code(client)
    kept = (await _exchange(client, code, client_id)).json()
    other_code, _same_client = await _code(client)
    assert (await _exchange(client, other_code, client_id)).status_code == 200
    await _exchange(client, other_code, client_id)
    assert await _mcp(client, kept["access_token"]) == 200


async def test_refreshing_never_extends_the_family_past_its_lifetime(client, monkeypatch):
    from app.features.identity.oauth.services import oauth_service as module

    code, client_id = await _code(client)
    tokens = (await _exchange(client, code, client_id)).json()
    real_now = module.utcnow
    # Refresh every 29 days: each one is inside the 30-day refresh lifetime.
    for days in (29, 58, 87):
        monkeypatch.setattr(module, "utcnow", lambda days=days: real_now() + timedelta(days=days))
        refreshed = await _refresh(client, tokens["refresh_token"], client_id)
        assert refreshed.status_code == 200, (days, refreshed.text)
        tokens = refreshed.json()
    # The last one was capped at the family's end: about 3 days of access, not a full hour past it.
    assert tokens["expires_in"] <= 3600
    monkeypatch.setattr(module, "utcnow", lambda: real_now() + REFRESH_FAMILY_TTL + timedelta(minutes=1))
    late = await _refresh(client, tokens["refresh_token"], client_id)
    assert late.status_code == 400
    assert late.json()["detail"] == "invalid_grant"
