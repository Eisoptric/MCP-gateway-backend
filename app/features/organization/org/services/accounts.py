from __future__ import annotations

# An account is a person's own (personal) or a team's (organization). Only a team account has
# members, invites and groups. There are no plans: every account has every feature.
ACCOUNT_KINDS = {"personal", "organization"}


def account_kind(kind: str | None) -> str:
    resolved = (kind or "").strip().lower()
    return resolved if resolved in ACCOUNT_KINDS else "personal"


def profile_identity(user_id: str, organization_id: str, kind: str | None) -> str:
    """Who an agent's sign-in belongs to: the person on a personal account, the person within
    the organization on a team account."""
    if account_kind(kind) == "personal":
        return user_id
    return f"{organization_id}:{user_id}"


def suspended(org) -> bool:
    """A platform admin turned this organization off. Its members and agents are refused until it is active again."""
    return str(getattr(org, "status", "") or "").strip().lower() == "suspended"
