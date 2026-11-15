import secrets
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    # 128 random bits. Ids are primary keys and appear in links, so they must not collide or be guessable.
    return f"{prefix}_{secrets.token_hex(16)}"


def new_revision() -> str:
    # Random rather than a counter: a counter can repeat after a rolled-back write, a restored
    # backup or a fresh database, and a cache keyed on it would then serve an old copy.
    return secrets.token_hex(16)
