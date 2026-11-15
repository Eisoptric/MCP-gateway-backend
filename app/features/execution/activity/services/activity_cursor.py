"""Opaque cursors for the activity lists.

A cursor names the last row of a page by (created_at, id), the order the lists use. The next
page is everything strictly after it, so rows written meanwhile or rows sharing a timestamp
neither repeat nor go missing, as they did with OFFSET.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timezone

from fastapi import HTTPException, status

# A real cursor is about 70 characters. Anything far longer is not one of ours.
MAX_CURSOR_LENGTH = 256
MAX_ID_LENGTH = 64


def _aware(value: datetime) -> datetime:
    # SQLite hands back naive datetimes; every stored time is UTC.
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def encode_cursor(created_at: datetime, row_id: str) -> str:
    raw = json.dumps([_aware(created_at).isoformat(), row_id], separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    """(created_at, id) from a cursor, or 400 when it is not one this API issued."""
    invalid = HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor")
    if not cursor or len(cursor) > MAX_CURSOR_LENGTH:
        raise invalid
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        stamp, row_id = json.loads(raw.decode())
        created_at = datetime.fromisoformat(stamp)
    except (binascii.Error, UnicodeDecodeError, ValueError, TypeError):
        raise invalid from None
    if not isinstance(row_id, str) or not 0 < len(row_id) <= MAX_ID_LENGTH:
        raise invalid
    return _aware(created_at), row_id
