"""When an approval's call was claimed.

A claim is committed before the call is sent. If the request dies after that, nothing settles
it, so the worker looks for claims older than a few minutes and marks them uncertain. Claims
already open when this runs count from now. One nullable column and a small partial index.

Revision ID: 061_approval_claimed_at
Revises: 060_status_days
Create Date: 2026-11-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "061_approval_claimed_at"
down_revision: Union[str, Sequence[str], None] = "060_status_days"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OPEN = "execution_state = 'claimed'"


def _columns() -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns("approvals")}


def _indexes() -> set[str]:
    return {index["name"] for index in inspect(op.get_bind()).get_indexes("approvals")}


def upgrade() -> None:
    if "claimed_at" not in _columns():
        op.add_column("approvals", sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(sa.text("UPDATE approvals SET claimed_at = CURRENT_TIMESTAMP WHERE execution_state = 'claimed' AND claimed_at IS NULL"))
    if "ix_approvals_open_claims" not in _indexes():
        op.create_index(
            "ix_approvals_open_claims",
            "approvals",
            ["claimed_at"],
            postgresql_where=sa.text(_OPEN),
            sqlite_where=sa.text(_OPEN),
        )


def downgrade() -> None:
    if "ix_approvals_open_claims" in _indexes():
        op.drop_index("ix_approvals_open_claims", table_name="approvals")
    if "claimed_at" in _columns():
        op.drop_column("approvals", "claimed_at")
