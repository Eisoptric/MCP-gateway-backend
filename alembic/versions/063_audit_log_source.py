"""audit_logs.source: the payload's "source" as a column, and an index to page on it.

The activity list filtered on payload->>'source' and paged with OFFSET, so every page read
and threw away all the rows before it, and the JSON filter could use no index. The list now
pages by (created_at, id) on ix_audit_logs_org_source_created. The payload key stays.

On PostgreSQL, in this order:

1. Add the column, nullable and without a default: a catalog change, no table rewrite.
2. A BEFORE INSERT trigger copies payload->>'source' into rows that arrive without it. The
   previous API revision keeps writing until the deploy finishes and does not know the column;
   without the trigger its rows would be missing from the list. Drop it once no running
   revision predates this one.
3. Backfill existing rows outside the migration transaction, walking the primary key
   BATCH rows at a time. Each UPDATE commits on its own, so row locks are short and a failure
   keeps the batches already done; a second run skips them (source IS NULL).
4. CREATE INDEX CONCURRENTLY, which does not block writes. A build that failed earlier left
   an INVALID index behind, which is dropped and built again.

Steps 1 and 2 commit when step 3 starts; they are idempotent, so a retry repeats nothing.
Other databases (the SQLite tests) take the same steps without trigger and CONCURRENTLY.

Revision ID: 063_audit_log_source
Revises: 061_approval_claimed_at
Create Date: 2026-11-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "063_audit_log_source"
down_revision: Union[str, Sequence[str], None] = "061_approval_claimed_at"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "audit_logs"
INDEX = "ix_audit_logs_org_source_created"
INDEX_COLUMNS = ("organization_id", "source", "created_at", "id")
TRIGGER = "audit_logs_source_from_payload"
FUNCTION = "audit_logs_source_from_payload()"
BATCH = 5000
SOURCE_LENGTH = 64

_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION {FUNCTION} RETURNS trigger AS $$
BEGIN
    IF NEW.source IS NULL THEN
        NEW.source := NULLIF(LEFT(NEW.payload ->> 'source', {SOURCE_LENGTH}), '');
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql
"""


def _source_expression(dialect: str) -> str:
    if dialect == "postgresql":
        # ->> on a payload that is not an object gives NULL, not an error.
        return f"NULLIF(LEFT(payload ->> 'source', {SOURCE_LENGTH}), '')"
    return (
        "CASE WHEN json_valid(payload) AND json_type(payload) = 'object' "
        f"THEN NULLIF(substr(json_extract(payload, '$.source'), 1, {SOURCE_LENGTH}), '') END"
    )


def _columns() -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns(TABLE)}


def _indexes() -> set[str]:
    return {index["name"] for index in inspect(op.get_bind()).get_indexes(TABLE)}


def _has_trigger(bind) -> bool:
    found = bind.execute(
        sa.text("SELECT 1 FROM pg_trigger WHERE tgname = :name AND tgrelid = CAST(:table AS regclass)"),
        {"name": TRIGGER, "table": TABLE},
    )
    return found.first() is not None


def _index_valid(bind) -> bool | None:
    """True or False when the index exists on PostgreSQL, None when it does not."""
    return bind.execute(
        sa.text(
            "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
            "WHERE c.relname = :name AND i.indrelid = CAST(:table AS regclass)"
        ),
        {"name": INDEX, "table": TABLE},
    ).scalar()


def backfill(bind, batch: int) -> int:
    """Copy payload source into rows without one, one primary-key range per statement."""
    source = _source_expression(bind.dialect.name)
    last = ""
    filled = 0
    while True:
        upper = bind.execute(
            sa.text("SELECT MAX(id) FROM (SELECT id FROM audit_logs WHERE id > :last ORDER BY id LIMIT :batch) AS chunk"),
            {"last": last, "batch": batch},
        ).scalar()
        if upper is None:
            return filled
        # `source` is one of the two fixed expressions above; the values are bound parameters.
        # Rows with no source are left alone rather than rewritten with NULL.
        result = bind.execute(
            sa.text(
                f"UPDATE audit_logs SET source = {source} "  # noqa: S608
                f"WHERE id > :last AND id <= :upper AND source IS NULL AND {source} IS NOT NULL"
            ),
            {"last": last, "upper": upper},
        )
        filled += max(result.rowcount or 0, 0)
        last = upper


def upgrade() -> None:
    bind = op.get_bind()
    postgres = bind.dialect.name == "postgresql"
    if "source" not in _columns():
        op.add_column(TABLE, sa.Column("source", sa.String(SOURCE_LENGTH), nullable=True))
    if postgres:
        op.execute(sa.text(_FUNCTION_SQL))
        if not _has_trigger(bind):
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {TRIGGER} BEFORE INSERT ON {TABLE} "
                    f"FOR EACH ROW EXECUTE FUNCTION {FUNCTION}"
                )
            )

    with op.get_context().autocommit_block():
        backfill(bind, BATCH)
        if postgres:
            valid = _index_valid(bind)
            if valid is False:
                op.execute(sa.text(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX}"))
            if valid is not True:
                op.execute(sa.text(f"CREATE INDEX CONCURRENTLY {INDEX} ON {TABLE} ({', '.join(INDEX_COLUMNS)})"))

    if not postgres and INDEX not in _indexes():
        op.create_index(INDEX, TABLE, list(INDEX_COLUMNS))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS {TRIGGER} ON {TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION IF EXISTS {FUNCTION}"))
        with op.get_context().autocommit_block():
            op.execute(sa.text(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX}"))
    elif INDEX in _indexes():
        op.drop_index(INDEX, table_name=TABLE)
    # The payload still holds every source, so nothing is lost.
    if "source" in _columns():
        op.drop_column(TABLE, "source")
