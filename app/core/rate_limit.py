import hashlib
import hmac
import ipaddress
import os
import time
from collections import defaultdict

from fastapi import Request

from app.core.config import get_settings

WINDOW_SECONDS = 600
MAX_HITS = 20
_PRUNE_EVERY = 1024

_hits: dict[str, list[float]] = defaultdict(list)
_calls = 0
_redis = None

# Give one hit back, never below zero and never creating the key.
_DECR_FLOOR = """
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
"""

# INCR and EXPIRE in one step, so a key can never be left without a TTL.
_INCR_WITH_TTL = """
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


def behind_cloudflare() -> bool:
    """CF-Connecting-IP is only meaningful when every request must carry the Cloudflare origin secret."""
    return bool(os.environ.get("ORIGIN_AUTH_SECRET", "").strip())


CONSOLE_AUTH_HEADER = "x-eisoptric-console-auth"
CONSOLE_CLIENT_IP_HEADER = "x-eisoptric-client-ip"


def _console_secret_ok(presented: str) -> bool:
    accepted = [
        os.environ.get("CONSOLE_PROXY_SECRET", "").strip(),
        os.environ.get("CONSOLE_PROXY_SECRET_PREVIOUS", "").strip(),
    ]
    digest = hashlib.sha256(presented.encode()).digest()
    return any(hmac.compare_digest(digest, hashlib.sha256(value.encode()).digest()) for value in accepted if value)


def console_client_ip(request: Request) -> str:
    """The browser's address as the console proxy reported it, or "" when it cannot be trusted.

    Every console request reaches the API from the console's own address, so Cloudflare's
    CF-Connecting-IP names the console, not the browser. The console sends the browser's address
    with a secret only it holds; without that secret the header is ignored.
    """
    presented = request.headers.get(CONSOLE_AUTH_HEADER, "")
    if not presented or not _console_secret_ok(presented):
        return ""
    value = request.headers.get(CONSOLE_CLIENT_IP_HEADER, "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def client_ip(request: Request) -> str:
    """The address used for rate limits and throttles.

    The console proxy's report wins when its secret matches. Cloudflare overwrites CF-Connecting-IP, so it
    is trusted only when origin auth proves the request came through Cloudflare. Otherwise the rightmost
    X-Forwarded-For entry is the one the nearest proxy appended. Any value a client chose itself is never used.
    """
    console = console_client_ip(request)
    if console:
        return console
    if behind_cloudflare():
        cf_ip = request.headers.get("cf-connecting-ip", "").strip()
        if cf_ip:
            return cf_ip
    forwarded = request.headers.get("x-forwarded-for", "")
    parts = [part.strip() for part in forwarded.split(",") if part.strip()]
    if parts:
        return parts[-1]
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def limit_address(request: Request) -> str:
    """The address a limit is counted against.

    One IPv6 customer is normally given a whole /64, and can pick any of its 2^64 addresses per
    request. Counting each address separately would give them unlimited buckets, so IPv6 is
    counted per /64. An IPv4 address written as IPv6 is counted as that IPv4 address.
    """
    value = client_ip(request)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return f"{ipaddress.ip_network(f'{address}/64', strict=False).network_address}/64"


def _use_redis() -> bool:
    settings = get_settings()
    return bool(settings.redis_url) and not settings.in_process_runtime


def _redis_client():
    global _redis
    if _redis is None:
        import redis.asyncio as redis_async

        # Asynchronous, so a slow Redis delays only the request that is waiting for it. The
        # synchronous client this replaced stopped the whole event loop for up to its timeout.
        # The timeouts stay short: a limiter that cannot answer refuses, and should do so quickly.
        _redis = redis_async.Redis.from_url(
            get_settings().redis_url,
            socket_timeout=0.5,
            socket_connect_timeout=0.5,
        )
    return _redis


def _prune(now: float, window: int) -> None:
    for key in list(_hits):
        kept = [stamp for stamp in _hits[key] if now - stamp < max(window, WINDOW_SECONDS)]
        if kept:
            _hits[key] = kept
        else:
            del _hits[key]


def _memory_allow(key: str, *, limit: int, window: int) -> bool:
    global _calls
    now = time.monotonic()
    _calls += 1
    if _calls % _PRUNE_EVERY == 0:
        _prune(now, window)
    bucket = [stamp for stamp in _hits[key] if now - stamp < window]
    if len(bucket) >= limit:
        _hits[key] = bucket
        return False
    bucket.append(now)
    _hits[key] = bucket
    return True


async def _redis_allow(key: str, *, limit: int, window: int) -> bool:
    client = _redis_client()
    count = int(await client.eval(_INCR_WITH_TTL, 1, f"gateway:rate:{key}", int(window)))
    return count <= limit


def _memory_count(key: str, window: int) -> int:
    now = time.monotonic()
    return sum(1 for stamp in _hits.get(key, []) if now - stamp < window)


async def under_limit(key: str, *, limit: int, window: int = WINDOW_SECONDS) -> bool:
    """Whether key has fewer than limit hits in the window, without adding one."""
    if _use_redis():
        try:
            raw = await _redis_client().get(f"gateway:rate:{key}")
            return int(raw or 0) < limit
        except Exception:
            return False
    if not get_settings().in_process_runtime:
        return False
    return _memory_count(key, window) < limit


async def allow(key: str, *, limit: int = MAX_HITS, window: int = WINDOW_SECONDS) -> bool:
    if _use_redis():
        try:
            return await _redis_allow(key, limit=limit, window=window)
        except Exception:
            return False
    if not get_settings().in_process_runtime:
        return False
    return _memory_allow(key, limit=limit, window=window)


async def release(key: str) -> None:
    """Hand back one hit that allow() counted. Used when the attempt turned out not to be a failure."""
    if _use_redis():
        try:
            await _redis_client().eval(_DECR_FLOOR, 1, f"gateway:rate:{key}")
        except Exception:  # noqa: S110
            # The hit stays counted and expires with its window: the safe direction.
            pass
        return
    bucket = _hits.get(key)
    if bucket:
        bucket.pop()


async def registration_allowed(request: Request) -> bool:
    return await allow(f"oauth-register:{limit_address(request)}")


async def signup_allowed(request: Request) -> bool:
    """Account sign-up. Its own budget, so agent client registrations cannot use it up."""
    return await allow(f"signup:{limit_address(request)}")


# Wrong passwords for one account from one address (an IPv4 address or an IPv6 /64).
LOGIN_ACCOUNT_FAILURES = 10
# Wrong passwords for one account from every address together. Past it only addresses that
# signed in to the account before may keep trying, so many addresses cannot lock the owner out.
LOGIN_ACCOUNT_CEILING = 50
KNOWN_ADDRESS_SECONDS = 30 * 86_400

_marks: dict[str, float] = {}


def _account(email: str) -> str:
    return email.strip().lower()


def _pair_digest(email: str, address: str) -> str:
    # Hashed so the key stays short and bounded whatever the email length.
    return hashlib.sha256(f"{_account(email)}\n{address}".encode()).hexdigest()[:32]


async def _mark(key: str, seconds: int) -> None:
    if _use_redis():
        try:
            await _redis_client().set(f"gateway:mark:{key}", "1", ex=seconds)
        except Exception:  # noqa: S110
            # Only an exemption is lost; the limits still apply.
            pass
        return
    _marks[key] = time.monotonic() + seconds


async def _marked(key: str) -> bool:
    if _use_redis():
        try:
            return bool(await _redis_client().get(f"gateway:mark:{key}"))
        except Exception:
            return False
    until = _marks.get(key)
    if until is None:
        return False
    if until <= time.monotonic():
        _marks.pop(key, None)
        return False
    return True


async def known_address(request: Request, email: str) -> bool:
    """Whether the account signed in from this address within KNOWN_ADDRESS_SECONDS."""
    return await _marked(f"known:{_pair_digest(email, limit_address(request))}")


async def _account_attempt(
    prefix: str,
    request: Request,
    email: str,
    *,
    pair_limit: int,
    pair_window: int = WINDOW_SECONDS,
    ceiling: int = LOGIN_ACCOUNT_CEILING,
    ceiling_window: int = WINDOW_SECONDS,
) -> bool:
    """One guess against an account: per (account, address), then a shared ceiling for the account.

    Keyed by the pair, so someone else's wrong guesses never use up the owner's attempts. The
    ceiling still bounds guesses spread over many addresses; once it is reached, the owner's own
    known addresses keep their per-address allowance.
    """
    address = limit_address(request)
    if not await allow(f"{prefix}-pair:{_pair_digest(email, address)}", limit=pair_limit, window=pair_window):
        return False
    if await allow(f"{prefix}-account:{_account(email)}", limit=ceiling, window=ceiling_window):
        return True
    return await known_address(request, email)


async def login_allowed(request: Request, email: str | None = None) -> bool:
    """Whether this sign-in attempt may go ahead. With an email, it also takes the account's slots.

    The slots are taken here, before the password is checked: counting a failure only afterwards
    let every request that was already in flight through, so a burst of guesses passed the
    limit. A correct password gives them back (login_succeeded), so an owner who signs in often
    is never locked out.
    """
    if not await allow(f"login:{limit_address(request)}"):
        return False
    if not (email or "").strip():
        return True
    return await _account_attempt("login", request, email or "", pair_limit=LOGIN_ACCOUNT_FAILURES)


async def login_succeeded(request: Request, email: str | None, *, signed_in: bool = True) -> None:
    """The password was right, or (signed_in=False) the attempt failed for another reason.

    A right password also marks this address as the owner's, which lets it past the ceiling.
    """
    if not email:
        return
    address = limit_address(request)
    await release(f"login-pair:{_pair_digest(email, address)}")
    await release(f"login-account:{_account(email)}")
    if signed_in:
        await _mark(f"known:{_pair_digest(email, address)}", KNOWN_ADDRESS_SECONDS)


async def migration_allowed(request: Request, email: str | None = None) -> bool:
    if not await allow(f"login-migration:{limit_address(request)}", limit=24):
        return False
    if email is None:
        return True
    # It answers whether a password is right, so it is limited per account the way sign-in is.
    return await _account_attempt("login-migration", request, email, pair_limit=10)


async def code_check_allowed(request: Request, subject: str | None = None) -> bool:
    """Checking an emailed, reset or authenticator code. Per address, and per account when known.

    Each code is also capped at a few guesses; this stops one address from spreading guesses
    over many codes and accounts.
    """
    if not await allow(f"code-check:{limit_address(request)}", limit=30):
        return False
    if not subject:
        return True
    return await allow(f"code-check-account:{subject.strip().lower()}", limit=15)


# Wrong reset codes from one (account, address) pair in an hour. An hour outlasts a code, so one
# address never gets more than this against any one code. Keyed by the pair: a stranger's wrong
# guesses no longer use up the owner's, as the old per-account budget of 15 did.
RESET_CODE_PAIR_FAILURES = 5
RESET_CODE_PAIR_SECONDS = 3600
# Wrong reset codes for one account from every address in a day: at most 100 / 10^6 = 0.01% a
# day to guess one. Past it only addresses that signed in to the account before may keep trying.
RESET_CODE_ACCOUNT_CEILING = 100


async def reset_code_allowed(request: Request, email: str) -> bool:
    """Whether this reset-code guess may go ahead. Takes its slots before the code is checked.

    A right code gives them back (reset_code_succeeded), so only wrong guesses stay counted.
    """
    if not await allow(f"code-check:{limit_address(request)}", limit=30):
        return False
    return await _account_attempt(
        "reset-code",
        request,
        email,
        pair_limit=RESET_CODE_PAIR_FAILURES,
        pair_window=RESET_CODE_PAIR_SECONDS,
        ceiling=RESET_CODE_ACCOUNT_CEILING,
        ceiling_window=_DAY_SECONDS,
    )


async def reset_code_succeeded(request: Request, email: str) -> None:
    await release(f"reset-code-pair:{_pair_digest(email, limit_address(request))}")
    await release(f"reset-code-account:{_account(email)}")


# Wrong emailed sign-in codes one account may collect in a day, across every challenge and
# address. Each code already allows only a few guesses, but a new code can be requested once
# those are spent, and whoever is guessing already has the password.
LOGIN_CODE_DAILY_FAILURES = 30
_DAY_SECONDS = 86_400


async def login_code_open(user_id: str) -> bool:
    return await under_limit(f"login-code-fail:{user_id}", limit=LOGIN_CODE_DAILY_FAILURES, window=_DAY_SECONDS)


async def login_code_failed(user_id: str) -> None:
    await allow(f"login-code-fail:{user_id}", limit=LOGIN_CODE_DAILY_FAILURES * 10, window=_DAY_SECONDS)


async def reauth_allowed(user_id: str) -> bool:
    return await allow(f"reauth:{user_id}", limit=8, window=900)


async def accept_invite_allowed(request: Request) -> bool:
    return await allow(f"accept-invite:{limit_address(request)}", limit=20)


def reset() -> None:
    global _redis, _calls
    _hits.clear()
    _marks.clear()
    _calls = 0
    _redis = None
