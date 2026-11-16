"""Drop the insert trigger that migration 063 left on audit_logs.

063 copied payload->>'source' into the new column for rows that arrived without it, so that
the API revision still running during that deploy (which did not set the column) wrote rows
the list could find. Every running revision now sets the column itself, so the trigger only
costs a function call per insert. The downgrade puts it back.

Revision ID: 066_drop_audit_source_trigger
Revises: 065_policy_revision
Create Date: 2026-11-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "066_drop_audit_source_trigger"
down_revision: Union[str, Sequence[str], None] = "065_policy_revision"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "audit_logs"
TRIGGER = "audit_logs_source_from_payload"
FUNCTION = "audit_logs_source_from_payload()"

# The same function 063 created.
_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION {FUNCTION} RETURNS trigger AS $$
BEGIN
    IF NEW.source IS NULL THEN
        NEW.source := NULLIF(LEFT(NEW.payload ->> 'source', 64), '');
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql
"""


def upgrade() -> None:
    # Only PostgreSQL ever had the trigger.
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS {TRIGGER} ON {TABLE}"))
    op.execute(sa.text(f"DROP FUNCTION IF EXISTS {FUNCTION}"))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(_FUNCTION_SQL))
    exists = bind.execute(
        sa.text("SELECT 1 FROM pg_trigger WHERE tgname = :name AND tgrelid = CAST(:table AS regclass)"),
        {"name": TRIGGER, "table": TABLE},
    ).first()
    if exists is None:
        op.execute(sa.text(f"CREATE TRIGGER {TRIGGER} BEFORE INSERT ON {TABLE} FOR EACH ROW EXECUTE FUNCTION {FUNCTION}"))
