"""Link OAuth tokens to the authorization code they came from.

grant_id lets a replayed authorization code revoke every token issued from it (RFC 6749
section 4.1.2). family_started_at is when that code was exchanged; refreshing carries it
forward, so a token family ends a fixed time after sign-in however often it is refreshed.
Tokens issued before this have no code to link to; their family counts from their own
created_at. Two nullable columns and an index.

Revision ID: 062_oauth_token_family
Revises: 061_approval_claimed_at
Create Date: 2026-11-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "062_oauth_token_family"
down_revision: Union[str, Sequence[str], None] = "061_approval_claimed_at"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "oauth_access_tokens"
_INDEX = "ix_oauth_access_tokens_grant_id"


def _columns() -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns(_TABLE)}


def _indexes() -> set[str]:
    return {index["name"] for index in inspect(op.get_bind()).get_indexes(_TABLE)}


def upgrade() -> None:
    columns = _columns()
    if "grant_id" not in columns:
        op.add_column(_TABLE, sa.Column("grant_id", sa.String(length=64), nullable=True))
    if "family_started_at" not in columns:
        op.add_column(_TABLE, sa.Column("family_started_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(sa.text("UPDATE oauth_access_tokens SET family_started_at = created_at WHERE family_started_at IS NULL"))
    if _INDEX not in _indexes():
        op.create_index(_INDEX, _TABLE, ["grant_id"])


def downgrade() -> None:
    if _INDEX in _indexes():
        op.drop_index(_INDEX, table_name=_TABLE)
    columns = _columns()
    if "family_started_at" in columns:
        op.drop_column(_TABLE, "family_started_at")
    if "grant_id" in columns:
        op.drop_column(_TABLE, "grant_id")
