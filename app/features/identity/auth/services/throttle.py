from __future__ import annotations

import hashlib
from datetime import timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ids import new_id, utcnow
from app.core.rate_limit import client_ip, known_address, limit_address
from app.features.identity.auth.models.throttle import AuthThrottle

# Per (email, client address): one code a minute and ten a day. Keyed by the pair, so requests
# from other addresses never use up the quota the owner needs for their own code.
EMAIL_LIMIT = 1
EMAIL_WINDOW = timedelta(seconds=60)
CLIENT_LIMIT = 8
CLIENT_WINDOW = timedelta(minutes=10)
EMAIL_DAILY_LIMIT = 10
EMAIL_DAILY_WINDOW = timedelta(days=1)
# Per email from every address together. Each code allows 5 guesses, so this bounds how often
# one account's codes can be guessed against in a day, and how much mail it can be sent. Past it,
# only an address the account has signed in from may still ask: each new code replaces the
# older ones, so the owner can always get one that works.
EMAIL_DAILY_CEILING = 30
_WAIT = "Wait a minute before requesting another code"


def _device(request: Request) -> str:
    raw = f"{client_ip(request)}\n{request.headers.get('user-agent', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


async def _hit(
    session: AsyncSession,
    bucket: str,
    *,
    limit: int,
    window: timedelta,
    exempt: bool = False,
) -> None:
    cutoff = utcnow() - window
    count = await session.scalar(
        select(func.count())
        .select_from(AuthThrottle)
        .where(AuthThrottle.bucket == bucket, AuthThrottle.created_at >= cutoff)
    )
    if int(count or 0) >= limit and not exempt:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, _WAIT)
    session.add(AuthThrottle(id=new_id("thr"), bucket=bucket))
    await session.flush()


def _pair(email: str, ip: str) -> str:
    # Hashed: the bucket column is 255 characters and an email alone can be that long.
    return hashlib.sha256(f"{email}\n{ip}".encode()).hexdigest()[:32]


async def consume(session: AsyncSession, request: Request, purpose: str, email: str) -> None:
    ip = limit_address(request)
    device = _device(request)
    pair = _pair(email, ip)
    await _hit(session, f"email:{purpose}:{pair}", limit=EMAIL_LIMIT, window=EMAIL_WINDOW)
    await _hit(session, f"email-day:{purpose}:{pair}", limit=EMAIL_DAILY_LIMIT, window=EMAIL_DAILY_WINDOW)
    await _hit(session, f"ip:{purpose}:{ip}", limit=CLIENT_LIMIT, window=CLIENT_WINDOW)
    await _hit(session, f"device:{purpose}:{device}", limit=CLIENT_LIMIT, window=CLIENT_WINDOW)
    await _hit(
        session,
        f"email-all:{purpose}:{email}",
        limit=EMAIL_DAILY_CEILING,
        window=EMAIL_DAILY_WINDOW,
        exempt=await known_address(request, email),
    )
    await maybe_purge(session)


_RETAIN = timedelta(days=1)


async def purge_expired(session: AsyncSession) -> None:
    """Drop throttle rows and spent sign-in codes. Without this the tables grow forever."""
    from sqlalchemy import delete

    from app.features.identity.auth.models.mfa import EmailCode, LoginChallenge, WebAuthnChallenge
    from app.features.identity.auth.models.password_reset import PasswordReset

    cutoff = utcnow() - _RETAIN
    await session.execute(delete(AuthThrottle).where(AuthThrottle.created_at < cutoff))
    for model in (EmailCode, LoginChallenge, WebAuthnChallenge, PasswordReset):
        await session.execute(delete(model).where(model.expires_at < cutoff))
    # Sessions and agent tokens that can no longer be used. Every sign-in and every token
    # refresh adds a row, and nothing removed them. A revoked refresh token is kept until it
    # would have expired anyway, because presenting it again is how reuse is detected.
    from app.features.identity.auth.models.session import AuthSession
    from app.features.identity.oauth.models.oauth import OAuthAccess, OAuthGrant

    await session.execute(delete(AuthSession).where(AuthSession.expires_at < cutoff))
    await session.execute(delete(OAuthGrant).where(OAuthGrant.expires_at < cutoff))
    await session.execute(delete(OAuthAccess).where(OAuthAccess.refresh_expires_at < cutoff))
    await session.flush()


async def maybe_purge(session: AsyncSession) -> None:
    import secrets

    if secrets.randbelow(64) == 0:
        await purge_expired(session)
