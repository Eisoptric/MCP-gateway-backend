"""Stop requiring the columns of plans, billing, per-customer runtimes and Saturn agent settings.

The code no longer reads or writes organizations.plan, billing, deployment_mode, runtime_region
and runtime_version, or agents.model. The previous revision still writes them while this one rolls
out, so the columns stay and only lose NOT NULL; a later migration drops them once no deployed
revision uses them (docs/migrations.md, "expand, then contract"). Both tables are small.

Revision ID: 068_retire_plans_and_saturn
Revises: 067_mcp_allowed_hosts
Create Date: 2026-11-21

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "068_retire_plans_and_saturn"
down_revision: Union[str, Sequence[str], None] = "067_mcp_allowed_hosts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, column, type, value an old row gets back on downgrade)
_COLUMNS = (
    ("organizations", "plan", sa.String(32), "'free'"),
    ("organizations", "billing", sa.JSON(), "'{}'"),
    ("organizations", "deployment_mode", sa.String(32), "'cloud'"),
    ("organizations", "runtime_region", sa.String(64), "'asia-east1'"),
    ("organizations", "runtime_version", sa.String(32), "'0.1.0'"),
    ("agents", "model", sa.String(128), "''"),
)


def _present(table: str, column: str) -> bool:
    return column in {item["name"] for item in inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    for table, column, kind, _fill in _COLUMNS:
        if _present(table, column):
            with op.batch_alter_table(table) as batch:
                batch.alter_column(column, existing_type=kind, nullable=True)


def downgrade() -> None:
    for table, column, kind, fill in _COLUMNS:
        if _present(table, column):
            op.execute(f"UPDATE {table} SET {column} = {fill} WHERE {column} IS NULL")
            with op.batch_alter_table(table) as batch:
                batch.alter_column(column, existing_type=kind, nullable=False)
