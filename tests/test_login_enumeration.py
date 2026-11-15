"""Sign-in answers must not tell unknown, current and legacy (PBKDF2) accounts apart."""

import hashlib
import secrets

from app.core.config import get_settings

V2 = "v2." + ("ab" * 32)
V1 = "v1." + hashlib.sha256(b"saturn-login-v1\nwrong horse").hexdigest()


async def _make_legacy(email: str, raw: str) -> None:
    from app.core.ids import new_id
    from app.db.database import get_session
    from app.main import app
    from app.models import User

    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw.encode(), bytes.fromhex(salt), 210_000)
    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        session.add(
            User(
                id=new_id("user"),
                organization_id=get_settings().default_org_id,
                email=email,
                name="Legacy",
                password_hash=f"pbkdf2_sha256$210000${salt}${digest.hex()}",
                status="active",
            )
        )
        await session.commit()
    finally:
        await generator.aclose()


def _count_hashes(monkeypatch) -> dict[str, int]:
    """Count the slow hashes each request runs; the response time is nearly all of these."""
    from app.features.identity.auth.services import auth_service

    counts = {"argon2": 0, "pbkdf2": 0}
    real_verify = auth_service._hasher.verify
    real_pbkdf2 = auth_service._pbkdf2_ok

    class Hasher:
        def verify(self, *args):
            counts["argon2"] += 1
            return real_verify(*args)

        def __getattr__(self, name):
            return getattr(real_verify.__self__, name)

    def pbkdf2(*args):
        counts["pbkdf2"] += 1
        return real_pbkdf2(*args)

    monkeypatch.setattr(auth_service, "_hasher", Hasher())
    monkeypatch.setattr(auth_service, "_pbkdf2_ok", pbkdf2)
    return counts


async def test_probe_gives_every_address_the_same_answer_and_work(client, legacy_window, monkeypatch):
    await _make_legacy("legacy-probe@saturn.ai", "correct horse")
    client.headers.pop("Authorization", None)
    counts = _count_hashes(monkeypatch)
    seen = []
    for email in ("nobody-at-all@saturn.ai", "rick@saturn.ai", "legacy-probe@saturn.ai"):
        for extra in ({}, {"legacy_v1": V1}, {"legacy_v1": V1, "legacy_password": "wrong horse"}):
            counts.update(argon2=0, pbkdf2=0)
            response = await client.post("/auth/login/migration", json={"email": email, "password": V2, **extra})
            assert response.status_code == 200, response.text
            seen.append((tuple(extra), response.json(), dict(counts), email))
    for extra in ({}, ("legacy_v1",), ("legacy_v1", "legacy_password")):
        answers = {(str(body), str(work)) for key, body, work, _ in seen if key == tuple(extra)}
        # One answer and one amount of hashing per request shape, whichever address was asked.
        assert len(answers) == 1, [row for row in seen if row[0] == tuple(extra)]
    assert seen[0][1] == {"migration": "v1"}


async def test_failed_sign_in_looks_the_same_for_unknown_current_and_legacy(client, monkeypatch):
    await _make_legacy("legacy-login@saturn.ai", "correct horse")
    client.headers.pop("Authorization", None)
    counts = _count_hashes(monkeypatch)
    for extra in ({}, {"legacy_v1": V1}, {"legacy_v1": V1, "legacy_password": "wrong horse"}):
        seen = set()
        for n, email in enumerate(("nobody-else@saturn.ai", "rick@saturn.ai", "legacy-login@saturn.ai")):
            counts.update(argon2=0, pbkdf2=0)
            response = await client.post(
                "/auth/login",
                headers={"X-Forwarded-For": f"10.9.{len(extra)}.{n}"},
                json={"email": email, "password": V2, **extra},
            )
            assert response.status_code == 401, response.text
            seen.add((response.text, str(counts)))
        assert len(seen) == 1, seen


async def test_legacy_accounts_still_sign_in_with_the_hinted_proofs(client, legacy_window):
    await _make_legacy("legacy-ok@saturn.ai", "correct horse")
    client.headers.pop("Authorization", None)
    probe = await client.post("/auth/login/migration", json={"email": "legacy-ok@saturn.ai", "password": V2})
    assert probe.json() == {"migration": "v1"}
    # What the console and the OAuth page send after the hint: both legacy proofs at once.
    v1 = "v1." + hashlib.sha256(b"saturn-login-v1\ncorrect horse").hexdigest()
    signed = await client.post(
        "/auth/login",
        json={"email": "legacy-ok@saturn.ai", "password": V2, "legacy_v1": v1, "legacy_password": "correct horse"},
    )
    assert signed.status_code == 200, signed.text
    # Rewritten onto the verifier, so the next sign-in needs no legacy proof.
    again = await client.post("/auth/login", json={"email": "legacy-ok@saturn.ai", "password": V2})
    assert again.status_code == 200, again.text
    assert (await client.post("/auth/login/migration", json={"email": "legacy-ok@saturn.ai", "password": V2})).json() == {
        "migration": None
    }


async def test_no_hint_after_the_legacy_deadline(client, monkeypatch):
    from app.features.identity.auth.services import auth_service as auth_module

    monkeypatch.setattr(auth_module, "legacy_password_allowed", lambda: False)
    client.headers.pop("Authorization", None)
    for email in ("nobody-late@saturn.ai", "rick@saturn.ai"):
        probe = await client.post("/auth/login/migration", json={"email": email, "password": V2})
        assert probe.json() == {"migration": None}
        refused = await client.post("/auth/login", json={"email": email, "password": V2})
        assert refused.json()["detail"] == "Invalid email or password"


async def test_without_a_legacy_date_a_failed_sign_in_asks_for_nothing_more(client):
    """No deadline set (a new install): legacy hashes are refused, so a failed sign-in never
    asks the browser for the raw password."""
    from app.features.identity.auth.services.auth_service import legacy_password_allowed, sign_in_hint

    assert get_settings().legacy_password_until in ("", None)
    assert not legacy_password_allowed()
    assert sign_in_hint(legacy_v1=None, legacy_password=None) is None
    assert sign_in_hint(legacy_v1="x" * 64, legacy_password=None) is None

