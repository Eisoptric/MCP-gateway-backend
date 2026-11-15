"""Organization policy revision.

The policy engine keeps each organization's compiled policies in memory and checks one column per
tool call instead of reloading every policy and rule. The column changes in the same transaction as
any write that can change a decision. Each existing organization gets its own random value; a NULL
one (a row written outside the ORM) is never cached, so the engine reads it from the database.

Revision ID: 065_policy_revision
Revises: 061_approval_claimed_at
Create Date: 2026-11-16

"""

import secrets
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "065_policy_revision"
down_revision: Union[str, Sequence[str], None] = "061_approval_claimed_at"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns() -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns("organizations")}


def upgrade() -> None:
    if "policy_revision" not in _columns():
        op.add_column("organizations", sa.Column("policy_revision", sa.String(length=32), nullable=True))
    bind = op.get_bind()
    organizations = sa.table("organizations", sa.column("id", sa.String), sa.column("policy_revision", sa.String))
    missing = bind.execute(sa.select(organizations.c.id).where(organizations.c.policy_revision.is_(None))).scalars().all()
    for organization_id in missing:
        bind.execute(
            organizations.update()
            .where(organizations.c.id == organization_id, organizations.c.policy_revision.is_(None))
            .values(policy_revision=secrets.token_hex(16))
        )


def downgrade() -> None:
    if "policy_revision" in _columns():
        op.drop_column("organizations", "policy_revision")
