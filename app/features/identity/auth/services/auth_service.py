from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from app.shared.threads import in_thread
from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.ids import new_id, utcnow
from app.models import Organization, PasswordReset, User
from app.features.identity.auth.models.session import AuthSession
from app.features.identity.auth.services.throttle import consume

settings = get_settings()
PBKDF2_ROUNDS = 210_000
RECENT_AUTH = timedelta(minutes=10)
_LOGIN_PREFIX = "v1."
_LOGIN_LABEL = b"saturn-login-v1\n"
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16)
# Verified against when the email is unknown, so a missing account costs the same time as a wrong password.
_DUMMY_HASH = _hasher.hash("saturn-missing-account")
OAUTH_SESSION_TTL = timedelta(minutes=15)
# A console session ends after this long without a request, even before its fixed expiry.
IDLE_TIMEOUT = timedelta(hours=24)
# last_seen_at is written at most this often, so most requests do not write the row.
SEEN_EVERY = timedelta(minutes=5)
# Guesses one reset code takes from every address together before it dies. Each address has its
# own small budget (rate_limit.reset_code_allowed), so a stranger cannot burn the owner's code
# with a handful of wrong guesses. A code is one of 10^6, so this ceiling leaves a guesser at
# most 50 / 10^6 = 0.005% per code.
RESET_CODE_CEILING = 50


def login_secret(password: str) -> str:
    """The first hash. A browser sends this; a raw password is hashed here."""
    body = password[len(_LOGIN_PREFIX) :]
    if password.startswith(_LOGIN_PREFIX) and len(body) == 64 and all(char in "0123456789abcdef" for char in body):
        return body
    return hashlib.sha256(_LOGIN_LABEL + password.encode("utf-8")).hexdigest()


_V2_PREFIX = "v2."


def verifier_material(password: str) -> str:
    """What the password hash covers. A v2 verifier is already a key; anything else is the v1 digest."""
    body = password[len(_V2_PREFIX) :]
    if password.startswith(_V2_PREFIX) and len(body) == 64 and all(char in "0123456789abcdef" for char in body):
        return body
    return login_secret(password)


def hash_password(password: str) -> str:
    return _hasher.hash(verifier_material(password))


def _pbkdf2_parts(stored: str) -> tuple[str, str, str] | None:
    try:
        algo, rounds, salt, digest = stored.split("$", 3)
    except ValueError:
        return None
    if algo != "pbkdf2_sha256":
        return None
    return rounds, salt, digest


def _pbkdf2_ok(material: str, stored: str) -> bool:
    parts = _pbkdf2_parts(stored)
    if parts is None:
        return False
    rounds, salt, digest = parts
    check = hashlib.pbkdf2_hmac("sha256", material.encode("utf-8"), bytes.fromhex(salt), int(rounds))
    return hmac.compare_digest(check.hex(), digest)


def verify_password(password: str, stored: str) -> bool:
    secret = verifier_material(password)
    if stored.startswith("$argon2"):
        try:
            _hasher.verify(stored, secret)
            return True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
    if _pbkdf2_parts(stored) is not None and not legacy_password_allowed():
        # After LEGACY_PASSWORD_UNTIL no pre-argon2 hash signs in, whichever field carries the proof.
        return False
    if _pbkdf2_ok(secret, stored):
        return True
    if password != secret and _pbkdf2_ok(password, stored):
        return True
    return False


def _stores_verifier(stored: str, password: str) -> bool:
    if not stored.startswith("$argon2id$"):
        return False
    try:
        _hasher.verify(stored, verifier_material(password))
        return not _hasher.check_needs_rehash(stored)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def legacy_password_allowed() -> bool:
    # Off unless a deadline is set. While it is on, every failed sign-in asks the browser for the
    # legacy proofs (raw password included), so an install with no legacy accounts must not pay
    # that. Only accounts created before 2026-10-16 have legacy hashes.
    raw = (get_settings().legacy_password_until or "").strip()
    if not raw:
        return False
    from datetime import date

    return date.today() <= date.fromisoformat(raw[:10])


# Checked against when the account has no PBKDF2 hash, so a legacy check costs the same either way.
_DUMMY_PBKDF2 = f"pbkdf2_sha256${PBKDF2_ROUNDS}${'00' * 16}${'00' * 32}"


def _is_v2(password: str) -> bool:
    return password.startswith(_V2_PREFIX) and verifier_material(password) == password[len(_V2_PREFIX) :]


def _argon2_matches(material: str, stored: str) -> bool:
    real = stored.startswith("$argon2")
    try:
        _hasher.verify(stored if real else _DUMMY_HASH, material)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return real


def _pbkdf2_matches(material: str, stored: str) -> bool:
    real = _pbkdf2_parts(stored) is not None
    return _pbkdf2_ok(material, stored if real else _DUMMY_PBKDF2) and real


def check_sign_in(
    stored: str,
    password: str,
    *,
    legacy_v1: str | None,
    legacy_password: str | None,
) -> tuple[bool, bool]:
    """(matches the current hash, matches a pre-argon2 hash), for the proofs a sign-in carried.

    Which hashes run depends only on which proofs were sent and their form, never on the
    account: an unknown address, an argon2 account and a PBKDF2 account cost the same. A v2
    verifier was never stored as PBKDF2, so it skips the legacy check. The deadline is the
    caller's to apply.
    """
    modern = _argon2_matches(verifier_material(password), stored)
    legacy = False
    if not _is_v2(password):
        # API clients send the raw password or a v1 verifier, which older hashes covered.
        legacy = _pbkdf2_matches(verifier_material(password), stored)
        if password != verifier_material(password):
            legacy = _pbkdf2_matches(password, stored) or legacy
    if legacy_v1:
        modern = _argon2_matches(verifier_material(legacy_v1), stored) or modern
        legacy = _pbkdf2_matches(verifier_material(legacy_v1), stored) or legacy
    if legacy_password:
        legacy = _pbkdf2_matches(legacy_password, stored) or legacy
    return modern, legacy


def sign_in_hint(*, legacy_v1: str | None, legacy_password: str | None) -> str | None:
    """What a failed sign-in asks the browser to add next, while legacy hashes are accepted.

    Given for every failure, whether the address is unknown, current or legacy, so it reveals
    nothing about the account. The browser then sends the legacy proofs; only a hash that one
    of them matches can tell legacy apart, and that needs the password.
    """
    if not legacy_password_allowed() or legacy_password:
        return None
    return "password" if legacy_v1 else "v1"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthService:
    async def authenticate(
        self,
        session: AsyncSession,
        email: str,
        password: str,
        legacy_password: str | None = None,
        legacy_v1: str | None = None,
    ) -> User:
        normalized = email.strip().lower()
        result = await session.execute(
            select(User)
            .options(selectinload(User.organization))
            .where(User.email == normalized)
        )
        user = result.scalar_one_or_none()
        stored = user.password_hash if user is not None else _DUMMY_HASH
        active = user is not None and user.status == "active"
        modern, legacy = await in_thread(
            check_sign_in, stored, password, legacy_v1=legacy_v1, legacy_password=legacy_password
        )
        allowed = legacy_password_allowed()
        ok = active and (modern or (legacy and allowed))
        if not ok or user is None:
            if active and legacy and not allowed:
                # The caller proved the legacy password, so telling them to reset reveals nothing new.
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    {"message": "請重設密碼。 Reset your password.", "migration": "reset"},
                )
            hint = sign_in_hint(legacy_v1=legacy_v1, legacy_password=legacy_password)
            if hint:
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    {"message": "Invalid email or password", "migration": hint},
                )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
        # Only a v2 verifier replaces the stored hash. A v1 sign-in keeps the old hash so the
        # browser can still prove it and move the account onto the split key.
        if password.startswith(_V2_PREFIX) and not _stores_verifier(user.password_hash, password):
            user.password_hash = await in_thread(hash_password, password)
            await session.flush()
        return user

    async def login(self, session: AsyncSession, email: str, password: str) -> tuple[str, User]:
        user = await self.authenticate(session, email, password)
        return await self.issue_session(session, user)

    async def issue_session(
        self,
        session: AsyncSession,
        user: User,
        *,
        purpose: str = "",
        ttl: timedelta | None = None,
    ) -> tuple[str, User]:
        raw = "sat_" + secrets.token_urlsafe(32)
        lifetime = ttl if ttl is not None else timedelta(days=settings.session_ttl_days)
        record = AuthSession(
            id=new_id("sess"),
            user_id=user.id,
            token_hash=hash_token(raw),
            expires_at=utcnow() + lifetime,
            authenticated_at=utcnow(),
            purpose=purpose,
        )
        session.add(record)
        await session.flush()
        if user.organization is None:
            result = await session.execute(
                select(User).options(selectinload(User.organization)).where(User.id == user.id)
            )
            user = result.scalar_one()
        return raw, user

    async def logout(self, session: AsyncSession, token: str) -> None:
        result = await session.execute(
            select(AuthSession).where(AuthSession.token_hash == hash_token(token))
        )
        record = result.scalar_one_or_none()
        if record is None or record.revoked_at is not None:
            return
        record.revoked_at = utcnow()
        await session.flush()

    async def update_profile(self, session: AsyncSession, user: User, *, name: str, email: str) -> User:
        cleaned = name.strip()
        if not cleaned or len(cleaned) > 255:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Name is required")
        normalized = email.strip().lower()
        domain = normalized.split("@")[-1] if "@" in normalized else ""
        if not domain or "." not in domain or " " in normalized:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email is invalid")
        user.name = cleaned
        await session.flush()
        return user

    async def user_from_token(self, session: AsyncSession, token: str, *, purpose: str = "") -> User | None:
        result = await session.execute(
            select(AuthSession)
            .options(selectinload(AuthSession.user).selectinload(User.organization))
            .where(AuthSession.token_hash == hash_token(token))
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None
        expires = record.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if (
            record.revoked_at is not None
            or (record.purpose or "") != purpose
            or expires <= utcnow()
            or record.user is None
            or record.user.status != "active"
        ):
            return None
        if not purpose:
            now = utcnow()
            seen = record.last_seen_at or record.authenticated_at or record.created_at
            if seen is not None and seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            if seen is not None and now - seen > IDLE_TIMEOUT:
                return None
            if record.last_seen_at is None or seen is None or now - seen > SEEN_EVERY:
                record.last_seen_at = now
                await session.flush()
        return record.user

    async def revoke_user_sessions(
        self,
        session: AsyncSession,
        user_id: str,
        *,
        keep_hash: str | None = None,
    ) -> None:
        result = await session.execute(
            select(AuthSession).where(
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
            )
        )
        now = utcnow()
        for record in result.scalars():
            if keep_hash is not None and record.token_hash == keep_hash:
                continue
            record.revoked_at = now
        await session.flush()

    async def request_password_reset(self, session: AsyncSession, email: str, request: Request) -> str | None:
        normalized = email.strip().lower()
        await consume(session, request, "reset", normalized)
        user = await self._active_user(session, normalized)
        if user is None:
            await in_thread(hash_password, f"{secrets.randbelow(1_000_000):06d}")
            return None
        open_codes = await session.execute(
            select(PasswordReset).where(
                PasswordReset.email == normalized,
                PasswordReset.used_at.is_(None),
            )
        )
        now = utcnow()
        for record in open_codes.scalars():
            record.used_at = now
        code = f"{secrets.randbelow(1_000_000):06d}"
        session.add(
            PasswordReset(
                id=new_id("rst"),
                email=normalized,
                code_hash=await in_thread(hash_password, code),
                expires_at=now + timedelta(minutes=10),
                attempts=0,
            )
        )
        await session.flush()
        return code

    async def discard_password_reset(self, session: AsyncSession, email: str) -> None:
        normalized = email.strip().lower()
        result = await session.execute(
            select(PasswordReset)
            .where(PasswordReset.email == normalized, PasswordReset.used_at.is_(None))
            .order_by(PasswordReset.created_at.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()
        if record is not None:
            await session.delete(record)
            await session.flush()

    async def reset_password(
        self,
        session: AsyncSession,
        email: str,
        code: str,
        password: str,
    ) -> None:
        self._require_password(password)
        normalized = email.strip().lower()
        result = await session.execute(
            select(PasswordReset)
            .where(PasswordReset.email == normalized, PasswordReset.used_at.is_(None))
            .order_by(PasswordReset.created_at.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()
        now = utcnow()
        expires = record.expires_at if record is not None else None
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if record is None or expires is None or expires <= now or record.attempts >= RESET_CODE_CEILING:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        from app.features.identity.auth.services.attempts import reserve_attempt

        used = await reserve_attempt(session, record, "attempts", RESET_CODE_CEILING)
        if used is None or not await in_thread(verify_password, code.strip(), record.code_hash):
            if used is None or used >= RESET_CODE_CEILING:
                record.used_at = now
            await session.flush()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        user = await self._active_user(session, normalized)
        if user is None:
            record.used_at = now
            await session.flush()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification code is incorrect or expired")
        user.password_hash = await in_thread(hash_password, password)
        record.used_at = now
        await self.revoke_user_sessions(session, user.id)
        await self._revoke_oauth(session, user.id)

    async def change_password(
        self,
        session: AsyncSession,
        user: User,
        current_password: str,
        new_password: str,
        *,
        keep_token: str | None,
    ) -> None:
        from app.core.rate_limit import reauth_allowed

        if not await reauth_allowed(user.id):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts", headers={"Retry-After": "900"})
        if not await in_thread(verify_password, current_password, user.password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
        self._require_password(new_password)
        user.password_hash = await in_thread(hash_password, new_password)
        keep_hash = hash_token(keep_token) if keep_token else None
        await self.revoke_user_sessions(session, user.id, keep_hash=keep_hash)
        if keep_token:
            await self.mark_session_authenticated(session, keep_token)
        await self._revoke_oauth(session, user.id)

    async def check_rekey(self, user: User, current_password: str, new_password: str) -> None:
        """Whether the caller may replace the stored password value. Changes nothing."""
        from app.core.rate_limit import reauth_allowed

        if not await reauth_allowed(user.id):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts", headers={"Retry-After": "900"})
        if not current_password or not await in_thread(verify_password, current_password, user.password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
        self._require_password(new_password)

    async def store_password(self, user: User, new_password: str) -> None:
        user.password_hash = await in_thread(hash_password, new_password)

    async def _session_record(self, session: AsyncSession, token: str) -> AuthSession | None:
        if not token:
            return None
        result = await session.execute(
            select(AuthSession).where(AuthSession.token_hash == hash_token(token))
        )
        record = result.scalar_one_or_none()
        if record is None or record.revoked_at is not None or (record.purpose or "") != "":
            return None
        return record

    async def require_recent_auth(self, session: AsyncSession, token: str) -> None:
        record = await self._session_record(session, token)
        if record is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
        stamp = record.authenticated_at
        if stamp is not None and stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        if stamp is None or utcnow() - stamp > RECENT_AUTH:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Reauthentication required")

    async def mark_session_authenticated(self, session: AsyncSession, token: str) -> None:
        record = await self._session_record(session, token)
        if record is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
        record.authenticated_at = utcnow()
        await session.flush()

    async def _revoke_oauth(self, session: AsyncSession, user_id: str) -> None:
        from app.features.identity.oauth.services.oauth_service import oauth_service

        await oauth_service.revoke_user_tokens(session, user_id)

    async def _active_user(self, session: AsyncSession, email: str) -> User | None:
        result = await session.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if user is None or user.status != "active":
            return None
        return user

    @staticmethod
    def _require_password(password: str) -> None:
        if len(password) < 8:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must be at least 8 characters")

    async def ensure_seed_user(self, session: AsyncSession) -> None:
        existing = await session.get(User, settings.default_actor_id)
        if existing is not None:
            # Created once. A later demotion or offboarding must stick, so never re-promote here.
            return
        email = (settings.seed_user_email or "").strip().lower()
        password = settings.seed_user_password or ""
        if not email or not password:
            return
        import os

        if os.environ.get("K_SERVICE", "").strip() and len(password) < 16:
            import logging

            logging.getLogger(__name__).error("SEED_USER_PASSWORD must be at least 16 characters; seed admin not created")
            return
        org = await session.get(Organization, settings.default_org_id)
        if org is None:
            return
        session.add(
            User(
                id=settings.default_actor_id,
                organization_id=org.id,
                email=email,
                name=(settings.seed_user_name or "Admin").strip() or "Admin",
                password_hash=await in_thread(hash_password, password),
                status="active",
                is_platform_admin=True,
            )
        )
        await session.flush()


auth_service = AuthService()
