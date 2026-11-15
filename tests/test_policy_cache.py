"""The policy engine's per-organization cache, keyed on organizations.policy_revision."""

from types import SimpleNamespace

import pytest
from sqlalchemy import delete, event, select

from app.core.enums import PolicyDecision
from app.core.ids import new_id
from app.features.policy.policies.services.policy_engine import PolicyCache, policy_engine
from app.models import Agent, Organization, Policy, PolicyRule
from tests.policy_helpers import create_active_policy

AGENT = "agent_customer_ops"


async def _db_session():
    from app.db.database import get_session
    from app.main import app

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    return generator, session


async def _decide(org_id: str, amount: int, *, agent_id: str = AGENT, tool: str = "billing.refund"):
    generator, session = await _db_session()
    try:
        return await policy_engine.evaluate_named(
            session,
            organization_id=org_id,
            agent=SimpleNamespace(id=agent_id),
            tool_name=tool,
            arguments={"amount": amount},
        )
    finally:
        await generator.aclose()


async def _org_id(client) -> str:
    return (await client.get("/auth/me")).json()["organization"]["id"]


@pytest.fixture
def loads(monkeypatch):
    """Counts full policy loads."""
    calls: list[str] = []
    original = policy_engine._load_policies

    async def counting(session, organization_id):
        calls.append(organization_id)
        return await original(session, organization_id)

    monkeypatch.setattr(policy_engine, "_load_policies", counting)
    return calls


async def test_a_cache_hit_skips_the_policy_load(client, loads):
    org_id = await _org_id(client)
    assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW
    assert loads == [org_id]

    generator, session = await _db_session()
    statements: list[str] = []
    sync_engine = (await session.connection()).engine.sync_engine

    def record(_conn, _cursor, statement, *_args):
        statements.append(statement)

    event.listen(sync_engine, "before_cursor_execute", record)
    try:
        for amount in (50, 840, 5000):
            await policy_engine.evaluate_named(
                session, organization_id=org_id, agent=SimpleNamespace(id=AGENT), tool_name="billing.refund",
                arguments={"amount": amount},
            )
    finally:
        event.remove(sync_engine, "before_cursor_execute", record)
        await generator.aclose()
    assert loads == [org_id]
    # Only the revision is read on a hit.
    assert len(statements) == 3 and all("policy_revision" in item for item in statements), statements


async def test_a_policy_change_is_seen_on_the_next_call(client, loads):
    org_id = await _org_id(client)
    assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW
    blocker = await create_active_policy(
        client, {"name": "Block refunds", "rules": [{"tool": "billing.refund", "decision": "deny"}]}
    )
    assert (await _decide(org_id, 50)).decision == PolicyDecision.DENY

    # Scoping the blocker to another agent goes through a bulk write on agent_policies.
    scoped = await client.patch(f"/policies/{blocker['id']}", json={"agent_ids": ["agent_unmapped"]})
    assert scoped.status_code == 200, scoped.text
    assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW
    blocked = await _decide(org_id, 50, agent_id="agent_unmapped")
    assert blocked.decision == PolicyDecision.DENY and blocked.policy_id == blocker["id"]

    paused = await client.patch(f"/policies/{blocker['id']}", json={"status": "paused"})
    assert paused.status_code == 200, paused.text
    assert (await _decide(org_id, 50, agent_id="agent_unmapped")).policy_id != blocker["id"]

    validated = await client.post(f"/policies/{blocker['id']}/validate")
    assert validated.status_code == 200, validated.text
    activated = await client.post(f"/policies/{blocker['id']}/activate", json={"confirm": True})
    assert activated.status_code == 200, activated.text
    assert (await _decide(org_id, 50, agent_id="agent_unmapped")).policy_id == blocker["id"]

    # Deleting a policy that names an agent used to fail with a 500.
    deleted = await client.delete(f"/policies/{blocker['id']}")
    assert deleted.status_code in {200, 204}, deleted.text
    assert (await _decide(org_id, 50, agent_id="agent_unmapped")).policy_id != blocker["id"]
    before = len(loads)
    assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW
    assert len(loads) == before


async def test_a_direct_orm_edit_of_a_rule_is_seen_on_the_next_call(client, loads):
    org_id = await _org_id(client)
    assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW
    before = len(loads)

    generator, session = await _db_session()
    try:
        rule = await session.scalar(
            select(PolicyRule).where(PolicyRule.policy_id == "policy_refund", PolicyRule.decision == "allow")
        )
        rule.decision = "deny"
        await session.commit()
    finally:
        await generator.aclose()
    assert (await _decide(org_id, 50)).decision == PolicyDecision.DENY
    assert len(loads) == before + 1

    # The refund policy names only one agent. Unlinking it from the agent's side makes the policy
    # apply to every agent, which the next call must see.
    assert (await _decide(org_id, 50, agent_id="agent_unmapped")).policy_id != "policy_refund"
    generator, session = await _db_session()
    try:
        agent = await session.get(Agent, AGENT)
        policy = await session.get(Policy, "policy_refund")
        await session.refresh(agent, ["policies"])
        agent.policies.remove(policy)
        await session.commit()
    finally:
        await generator.aclose()
    assert (await _decide(org_id, 50, agent_id="agent_unmapped")).policy_id == "policy_refund"


async def test_a_rolled_back_change_never_reaches_the_cache(client):
    org_id = await _org_id(client)
    assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW

    generator, session = await _db_session()
    try:
        rule = await session.scalar(
            select(PolicyRule).where(PolicyRule.policy_id == "policy_refund", PolicyRule.decision == "allow")
        )
        rule.decision = "deny"
        await session.flush()
        inside = await policy_engine.evaluate_named(
            session, organization_id=org_id, agent=SimpleNamespace(id=AGENT), tool_name="billing.refund",
            arguments={"amount": 50},
        )
        assert inside.decision == PolicyDecision.DENY
        await session.rollback()
    finally:
        await generator.aclose()
    assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW


async def test_organizations_do_not_share_cached_policies(client, loads):
    org_id = await _org_id(client)
    generator, session = await _db_session()
    try:
        other = Organization(id=new_id("org"), name="Other", status="active")
        session.add(other)
        await session.flush()
        policy = Policy(id=new_id("policy"), organization_id=other.id, name="Other refunds", status="active")
        session.add(policy)
        await session.flush()
        session.add(
            PolicyRule(
                id=new_id("rule"), policy_id=policy.id, tool="billing.refund", condition="true", decision="deny", position=0
            )
        )
        other_id = other.id
        await session.commit()
        own_revision = await session.scalar(select(Organization.policy_revision).where(Organization.id == org_id))
        other_revision = await session.scalar(select(Organization.policy_revision).where(Organization.id == other_id))
    finally:
        await generator.aclose()
    assert own_revision and other_revision and own_revision != other_revision

    for _ in range(2):
        assert (await _decide(org_id, 50)).decision == PolicyDecision.ALLOW
        assert (await _decide(other_id, 50)).decision == PolicyDecision.DENY
    assert sorted(loads) == sorted([org_id, other_id])
    # An entry is never served for another organization or another revision.
    assert policy_engine.cache.get(other_id, own_revision) is None
    assert policy_engine.cache.get(org_id, other_revision) is None


async def test_a_bulk_policy_write_without_a_bump_is_refused(client):
    generator, session = await _db_session()
    try:
        with pytest.raises(RuntimeError, match="bump_policy_revision"):
            await session.execute(delete(PolicyRule).where(PolicyRule.policy_id == "policy_refund"))
        await session.rollback()
    finally:
        await generator.aclose()


def test_the_cache_is_bounded_and_exact_about_revisions():
    cache = PolicyCache(size=2)
    cache.put("org_a", "r1", ())
    cache.put("org_b", "r1", ())
    assert cache.get("org_a", "r1") == ()
    assert cache.get("org_a", "r2") is None
    cache.put("org_c", "r1", ())
    # org_b was the least recently used.
    assert cache.get("org_b", "r1") is None
    assert cache.get("org_a", "r1") == () and cache.get("org_c", "r1") == ()
