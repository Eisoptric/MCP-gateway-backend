"""Hosts an organization's admins approve for MCP servers.

Eisoptric's own list (ALLOWED_MCP_HOSTS) stays as it is. A new, empty table; no existing row changes,
so the previous revision keeps working while this one rolls out.

Revision ID: 067_mcp_allowed_hosts
Revises: 066_drop_audit_source_trigger
Create Date: 2026-11-19

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "067_mcp_allowed_hosts"
down_revision: Union[str, Sequence[str], None] = "066_drop_audit_source_trigger"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "mcp_allowed_hosts"
_INDEX = "ix_mcp_allowed_hosts_organization_id"


def upgrade() -> None:
    if _TABLE not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            _TABLE,
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("organization_id", sa.String(length=64), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("host", sa.String(length=253), nullable=False),
            sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("organization_id", "host", name="uq_mcp_allowed_hosts_org_host"),
        )
    indexes = {index["name"] for index in inspect(op.get_bind()).get_indexes(_TABLE)}
    if _INDEX not in indexes:
        op.create_index(_INDEX, _TABLE, ["organization_id"])


def downgrade() -> None:
    if _TABLE in inspect(op.get_bind()).get_table_names():
        op.drop_table(_TABLE)
