"""Keep how each MCP sign-in ended, for the console that started it.

The console could only tell that the sign-in window had closed, which some providers' pages
report almost at once, and never learned why a sign-in failed. The pending row now records its
outcome and stays a little after the callback so the console can read it by the nonce it sent.
Existing rows default to pending.

Revision ID: 064_mcp_oauth_outcome
Revises: 063_audit_log_source
Create Date: 2026-11-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "064_mcp_oauth_outcome"
down_revision: Union[str, Sequence[str], None] = "063_audit_log_source"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "mcp_oauth_pending"
_COLUMNS = (
    ("status", lambda: sa.Column("status", sa.String(length=16), nullable=False, server_default="pending")),
    ("reason", lambda: sa.Column("reason", sa.String(length=32), nullable=False, server_default="")),
    ("message", lambda: sa.Column("message", sa.String(length=255), nullable=False, server_default="")),
    ("finished_at", lambda: sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True)),
)


def _columns() -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns(_TABLE)}


def upgrade() -> None:
    present = _columns()
    for name, column in _COLUMNS:
        if name not in present:
            op.add_column(_TABLE, column())


def downgrade() -> None:
    present = _columns()
    for name, _column in reversed(_COLUMNS):
        if name in present:
            op.drop_column(_TABLE, name)
