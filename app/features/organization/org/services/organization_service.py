from __future__ import annotations

from app.features.organization.org.models.organization import Organization
from app.schemas import OrganizationRead
from app.features.organization.org.services.accounts import account_kind


def serialize_organization(org: Organization) -> OrganizationRead:
    return OrganizationRead(
        id=org.id,
        name=org.name,
        kind=account_kind(org.kind),
        photo=org.photo or None,
    )
