"""Step-up (POST /auth/reauth) asks for the same second factor as sign-in."""

from datetime import timedelta

from app.core.config import get_settings
from tests.passkey_access import ORIGIN, enrol
from tests.totp_access import finish_totp, next_code


async def _session():
    from app.db.database import get_session
    from app.main import app

    generator = app.dependency_overrides[get_session]()
    return await anext(generator), generator


async def _with_totp(client) -> str:
    from app.models import User

    # The test catalog marks the operator's TOTP on without a secret; start from no authenticator.
    session, generator = await _session()
    try:
        user = await session.get(User, get_settings().default_actor_id)
        user.totp_enabled = False
        await session.commit()
    finally:
        await generator.aclose()
    return await finish_totp(client, {})


async def _stale(monkeypatch) -> None:
    # Every session counts as signed in long ago, so only a step-up can open the guarded routes.
    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", timedelta(seconds=-1))


async def test_an_account_with_totp_needs_its_code_as_well_as_the_password(client, monkeypatch):
    secret = await _with_totp(client)

    await _stale(monkeypatch)
    alone = await client.post("/auth/reauth", json={"password": "saturn"})
    assert alone.status_code == 403, alone.text
    assert alone.json()["detail"]["second_factor"] == "totp"

    wrong = await client.post("/auth/reauth", json={"password": "saturn", "totp_code": "000000"})
    assert wrong.status_code == 400, wrong.text

    # A right code with a wrong password is still refused, and it is checked first.
    bad_password = await client.post("/auth/reauth", json={"password": "nope-nope", "totp_code": next_code(secret)})
    assert bad_password.status_code == 401

    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", timedelta(minutes=10))
    ok = await client.post("/auth/reauth", json={"password": "saturn", "totp_code": next_code(secret)})
    assert ok.status_code == 204, ok.text
    # The step-up now covers adding a passkey.
    options = await client.post("/auth/passkeys/options", headers={"Origin": ORIGIN})
    assert options.status_code == 200, options.text


async def test_a_backup_code_also_completes_step_up(client, monkeypatch):
    from app.features.identity.auth.services.totp import hash_backup_code
    from app.models import TotpBackupCode

    await _with_totp(client)
    session, generator = await _session()
    try:
        session.add(
            TotpBackupCode(
                id="tbc_step_up",
                user_id=get_settings().default_actor_id,
                code_hash=hash_backup_code("0123456789abcdef"),
            )
        )
        await session.commit()
    finally:
        await generator.aclose()
    ok = await client.post("/auth/reauth", json={"password": "saturn", "totp_code": "0123456789abcdef"})
    assert ok.status_code == 204, ok.text
    again = await client.post("/auth/reauth", json={"password": "saturn", "totp_code": "0123456789abcdef"})
    assert again.status_code == 400


async def test_the_emailed_code_does_not_replace_the_authenticator(client, monkeypatch):
    sent = []

    async def capture(_email, code, _locale=None):
        sent.append(code)

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_reauth_code", capture)
    secret = await _with_totp(client)
    assert (await client.post("/auth/reauth/email/code")).status_code == 204
    alone = await client.post("/auth/reauth", json={"code": sent[-1]})
    assert alone.status_code == 403
    assert alone.json()["detail"]["second_factor"] == "totp"
    # Refused before the emailed code was checked, so it still works with the authenticator code.
    both = await client.post("/auth/reauth", json={"code": sent[-1], "totp_code": next_code(secret)})
    assert both.status_code == 204, both.text


async def test_an_account_whose_strong_factor_is_a_passkey_confirms_with_it(client):
    from app.models import User

    session, generator = await _session()
    try:
        user = await session.get(User, get_settings().default_actor_id)
        passkey = await enrol(session, user.id)
        await session.commit()
    finally:
        await generator.aclose()

    alone = await client.post("/auth/reauth", json={"password": "saturn"})
    assert alone.status_code == 403
    assert alone.json()["detail"]["second_factor"] == "passkey"

    options = await client.post("/auth/reauth/passkey/options", headers={"Origin": ORIGIN})
    assert options.status_code == 200, options.text
    confirmed = await client.post(
        "/auth/reauth",
        headers={"Origin": ORIGIN},
        json={"credential": passkey.answer(options.json())},
    )
    assert confirmed.status_code == 204, confirmed.text


async def test_an_account_without_a_second_factor_still_uses_the_password_alone(client):
    assert (await client.post("/auth/reauth", json={"password": "saturn"})).status_code == 204


async def _with_email_mfa() -> None:
    from app.models import User

    session, generator = await _session()
    try:
        user = await session.get(User, get_settings().default_actor_id)
        user.email_mfa = True
        await session.commit()
    finally:
        await generator.aclose()


async def test_an_account_with_emailed_codes_needs_the_code_as_well_as_the_password(client, monkeypatch):
    sent = []

    async def capture(_email, code, _locale=None):
        sent.append(code)

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_reauth_code", capture)
    await _with_email_mfa()

    # A wrong password sends nothing.
    assert (await client.post("/auth/reauth", json={"password": "nope-nope"})).status_code == 401
    assert sent == []

    alone = await client.post("/auth/reauth", json={"password": "saturn"})
    assert alone.status_code == 403, alone.text
    assert alone.json()["detail"]["second_factor"] == "email"
    assert len(sent) == 1
    # Asking again within the minute is answered the same way; the code already sent still works.
    again = await client.post("/auth/reauth", json={"password": "saturn"})
    assert again.status_code == 403
    assert len(sent) == 1

    # The emailed code alone is not enough either, and is refused before it is checked.
    code_only = await client.post("/auth/reauth", json={"code": sent[-1]})
    assert code_only.status_code == 403
    assert code_only.json()["detail"]["second_factor"] == "email"

    wrong = await client.post("/auth/reauth", json={"password": "saturn", "code": f"{(int(sent[-1]) + 1) % 1_000_000:06d}"})
    assert wrong.status_code == 400

    await _stale(monkeypatch)
    ok = await client.post("/auth/reauth", json={"password": "saturn", "code": sent[-1]})
    assert ok.status_code == 204, ok.text
    monkeypatch.setattr("app.features.identity.auth.services.auth_service.RECENT_AUTH", timedelta(minutes=10))
    options = await client.post("/auth/passkeys/options", headers={"Origin": ORIGIN})
    assert options.status_code == 200, options.text
    # The code was used up.
    assert (await client.post("/auth/reauth", json={"password": "saturn", "code": sent[-1]})).status_code == 400


async def test_a_right_code_with_a_wrong_password_is_refused(client, monkeypatch):
    sent = []

    async def capture(_email, code, _locale=None):
        sent.append(code)

    monkeypatch.setattr("app.features.identity.auth.controllers.auth.send_reauth_code", capture)
    await _with_email_mfa()
    assert (await client.post("/auth/reauth/email/code")).status_code == 204
    refused = await client.post("/auth/reauth", json={"password": "nope-nope", "code": sent[-1]})
    assert refused.status_code == 401


async def test_step_up_with_a_passkey_requires_user_verification(client):
    from app.models import User

    session, generator = await _session()
    try:
        user = await session.get(User, get_settings().default_actor_id)
        passkey = await enrol(session, user.id)
        await session.commit()
    finally:
        await generator.aclose()

    options = await client.post("/auth/reauth/passkey/options", headers={"Origin": ORIGIN})
    assert options.status_code == 200, options.text
    assert options.json()["userVerification"] == "required"
    # Touching the key without its PIN or biometric is only one factor.
    unverified = await client.post(
        "/auth/reauth",
        headers={"Origin": ORIGIN},
        json={"credential": passkey.answer(options.json(), verified=False)},
    )
    assert unverified.status_code == 400, unverified.text

    options = await client.post("/auth/reauth/passkey/options", headers={"Origin": ORIGIN})
    verified = await client.post(
        "/auth/reauth",
        headers={"Origin": ORIGIN},
        json={"credential": passkey.answer(options.json())},
    )
    assert verified.status_code == 204, verified.text


async def test_changing_the_password_does_not_count_as_step_up(client):
    """A stolen session plus a known password must not skip the second factor."""
    from sqlalchemy import update

    from app.core.ids import utcnow
    from app.models import AuthSession

    await _with_totp(client)
    session, generator = await _session()
    try:
        # Signed in an hour ago: the guarded routes need a step-up.
        await session.execute(update(AuthSession).values(authenticated_at=utcnow() - timedelta(hours=1)))
        await session.commit()
    finally:
        await generator.aclose()
    assert (await client.post("/auth/passkeys/options", headers={"Origin": ORIGIN})).status_code == 403

    changed = await client.patch("/auth/password", json={"current_password": "saturn", "new_password": "saturn-changed-1"})
    assert changed.status_code == 204, changed.text
    # Still signed in, and still asked for the second factor.
    assert (await client.get("/auth/me")).status_code == 200
    assert (await client.post("/auth/passkeys/options", headers={"Origin": ORIGIN})).status_code == 403
