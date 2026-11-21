from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Organization, User
from app.features.organization.org.services.mapping_service import mapping_service

settings = get_settings()


async def seed_if_empty(session: AsyncSession) -> None:
    """Bootstrap an empty control plane: the default organization, no users, no catalog.

    The first platform admin signs up by email at SEED_USER_EMAIL (see promote_seed_admin).
    """
    existing = await session.get(Organization, settings.default_org_id)
    if existing is None:
        session.add(
            Organization(
                id=settings.default_org_id,
                name="Eisoptric",
                status="active",
                kind="organization",
            )
        )
        await session.flush()

    # A database seeded before sign-up promotion keeps its admin and that admin's membership.
    user = await session.get(User, settings.default_actor_id)
    if user is not None:
        await mapping_service.ensure_bootstrap_employee(session, user)
