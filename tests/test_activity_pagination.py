"""The activity lists page by (created_at, id) cursors and filter on the source column."""

import base64
import importlib.util
import json
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from app.core.ids import utcnow
from app.features.execution.activity.services.activity_cursor import decode_cursor, encode_cursor
from app.models import AuditLog


async def _db(client):
    from app.db.database import get_session
    from app.main import app

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    return generator, session


async def _org_id(client) -> str:
    return (await client.get("/org")).json()["organization"]["id"]


async def _plant(client, rows: list[dict]) -> None:
    generator, session = await _db(client)
    try:
        org = await _org_id(client)
        for row in rows:
            session.add(AuditLog(organization_id=org, actor_type="agent", **row))
        await session.commit()
    finally:
        await generator.aclose()


async def _walk(client, path: str, limit: int, **params) -> list[str]:
    """Every id, following X-Next-Cursor until it stops."""
    seen: list[str] = []
    cursor = None
    for _ in range(100):
        query = {"limit": limit, **params, **({"cursor": cursor} if cursor else {})}
        page = await client.get(path, params=query)
        assert page.status_code == 200, page.text
        seen += [item["id"] for item in page.json()]
        cursor = page.headers.get("X-Next-Cursor")
        if cursor is None:
            assert "X-Next-Offset" not in page.headers or len(page.json()) < limit
            return seen
        assert len(page.json()) == limit
    raise AssertionError("the cursor never ran out")


def _mcp(row_id: str, at, **extra) -> dict:
    return {
        "id": row_id,
        "event": "tool_requested",
        "created_at": at,
        "source": "saturn_mcp",
        "payload": {"source": "saturn_mcp"},
        **extra,
    }


async def test_every_row_once_across_pages_with_shared_timestamps(client):
    same = utcnow().replace(microsecond=0) - timedelta(minutes=5)
    rows = [_mcp(f"evt_same_{index:02d}", same) for index in range(7)]
    rows += [_mcp(f"evt_before_{index}", same - timedelta(seconds=index + 1)) for index in range(3)]
    rows += [_mcp(f"evt_after_{index}", same + timedelta(seconds=index + 1)) for index in range(2)]
    await _plant(client, rows)

    everything = (await client.get("/activity", params={"limit": 1000})).json()
    expected = [item["id"] for item in everything]
    assert {row["id"] for row in rows} <= set(expected)
    # Newest first; ties on created_at fall back to id, descending.
    shared = [item for item in expected if item.startswith("evt_same_")]
    assert shared == sorted(shared, reverse=True)

    for limit in (1, 2, 3, 7):
        walked = await _walk(client, "/activity", limit)
        assert walked == expected, limit
        assert len(walked) == len(set(walked))

    # A row written after the first page was read moves nothing: it is newer than the cursor.
    first = await client.get("/activity", params={"limit": 4})
    await _plant(client, [_mcp("evt_late", utcnow())])
    rest = await _walk(client, "/activity", 4, cursor=first.headers["X-Next-Cursor"])
    assert [item["id"] for item in first.json()] + rest == expected


async def test_filters_still_apply_on_every_page(client):
    at = utcnow() - timedelta(minutes=1)
    await _plant(client, [_mcp(f"evt_tool_{index}", at, tool="billing.refund") for index in range(5)])
    walked = await _walk(client, "/activity", 2, tool="billing")
    assert sorted(walked) == [f"evt_tool_{index}" for index in range(5)]


async def test_the_source_filter_reads_the_column_not_the_payload(client):
    at = utcnow()
    await _plant(
        client,
        [
            _mcp("evt_column_only", at, payload={}),
            {"id": "evt_payload_only", "event": "tool_requested", "created_at": at, "payload": {"source": "saturn_mcp"}},
            _mcp("evt_console", at, source="console", payload={"source": "console"}),
        ],
    )
    # On PostgreSQL migration 063's insert trigger copies the payload's source into the column,
    # so clear it afterwards to get a row that has the source only in its payload.
    from sqlalchemy import update

    generator, session = await _db(client)
    try:
        await session.execute(update(AuditLog).where(AuditLog.id == "evt_payload_only").values(source=None))
        await session.commit()
    finally:
        await generator.aclose()
    listed = {item["id"] for item in (await client.get("/activity", params={"limit": 1000})).json()}
    assert "evt_column_only" in listed
    assert "evt_payload_only" not in listed
    assert "evt_console" not in listed


async def test_new_audit_rows_carry_their_source(client):
    from app.core.enums import ActorType, AuditEvent
    from app.features.execution.activity.services.audit_service import audit_service

    generator, session = await _db(client)
    try:
        org = await _org_id(client)
        made = await audit_service.log(
            session, event=AuditEvent.TOOL_REQUESTED, actor_type=ActorType.AGENT, organization_id=org, payload={"source": "saturn_mcp"}
        )
        plain = await audit_service.log(session, event=AuditEvent.TOOL_REQUESTED, actor_type=ActorType.AGENT, organization_id=org)
        await session.commit()
        assert made.source == "saturn_mcp" and made.payload["source"] == "saturn_mcp"
        assert plain.source is None
    finally:
        await generator.aclose()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.mark.parametrize(
    "cursor",
    [
        "not base64 !",
        _b64(b"\xff\xfe"),
        _b64(b"{}"),
        _b64(json.dumps(["yesterday", "evt_1"]).encode()),
        _b64(json.dumps(["2026-11-16T00:00:00+00:00", 7]).encode()),
        _b64(json.dumps(["2026-11-16T00:00:00+00:00", ""]).encode()),
        _b64(json.dumps(["2026-11-16T00:00:00+00:00", "x" * 65]).encode()),
        _b64(json.dumps(["2026-11-16T00:00:00+00:00", "evt_1", "extra"]).encode()),
        "A" * 300,
    ],
)
async def test_an_invalid_cursor_is_a_400(client, cursor):
    for path in ("/activity", "/activity/changes", "/activity/export"):
        response = await client.get(path, params={"cursor": cursor})
        assert response.status_code == 400, (path, response.text)


async def test_cursor_and_offset_together_are_refused(client):
    cursor = encode_cursor(utcnow(), "evt_1")
    response = await client.get("/activity", params={"cursor": cursor, "offset": 3})
    assert response.status_code == 400


def test_cursor_round_trip_keeps_microseconds_and_assumes_utc_for_naive_times():
    at = utcnow()
    assert decode_cursor(encode_cursor(at, "evt_x")) == (at, "evt_x")
    naive = at.replace(tzinfo=None)
    assert decode_cursor(encode_cursor(naive, "evt_x")) == (at, "evt_x")
    assert "=" not in encode_cursor(at, "evt_x")


async def test_changes_and_export_page_by_cursor(client):
    at = utcnow() - timedelta(minutes=2)
    await _plant(
        client,
        [
            {"id": f"evt_change_{index}", "event": "policy_updated", "created_at": at, "source": "console", "payload": {"source": "console"}}
            for index in range(5)
        ]
        + [_mcp(f"evt_export_{index}", at) for index in range(5)],
    )
    changes = [item["id"] for item in (await client.get("/activity/changes", params={"limit": 500})).json()]
    assert {f"evt_change_{index}" for index in range(5)} <= set(changes)
    assert await _walk(client, "/activity/changes", 2) == changes

    exported = [item["id"] for item in (await client.get("/activity/export", params={"limit": 10000})).json()]
    assert await _walk(client, "/activity/export", 3) == exported


async def test_offset_paging_still_works_for_one_release(client):
    at = utcnow()
    await _plant(client, [_mcp(f"evt_offset_{index}", at) for index in range(4)])
    everything = [item["id"] for item in (await client.get("/activity")).json()]
    first = await client.get("/activity", params={"limit": 2})
    assert first.headers["X-Next-Offset"] == "2"
    assert "X-Next-Cursor" in first.headers
    second = await client.get("/activity", params={"limit": 2, "offset": 2})
    assert [item["id"] for item in second.json()] == everything[2:4]


# The migration ---------------------------------------------------------------------------------


def _migration():
    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "063_audit_log_source.py"
    spec = importlib.util.spec_from_file_location("migration_063", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, step) -> None:
    with engine.connect() as connection:
        # As alembic/env.py runs it: one transaction per migration, which autocommit_block leaves.
        context = MigrationContext.configure(connection, opts={"transaction_per_migration": True})
        with Operations.context(context):
            with context.begin_transaction(_per_migration=True):
                step()


def test_migration_backfills_the_column_in_batches_and_reverses(tmp_path):
    migration = _migration()
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "CREATE TABLE audit_logs (id VARCHAR(64) PRIMARY KEY, organization_id VARCHAR(64), "
                "created_at DATETIME, payload JSON)"
            )
        )
        rows = [
            {"id": "evt_a", "payload": json.dumps({"source": "saturn_mcp"})},
            {"id": "evt_b", "payload": json.dumps({"source": "console", "x": 1})},
            {"id": "evt_c", "payload": json.dumps({"other": True})},
            {"id": "evt_d", "payload": None},
            {"id": "evt_e", "payload": json.dumps(["not", "an", "object"])},
            {"id": "evt_f", "payload": json.dumps({"source": ""})},
            {"id": "evt_g", "payload": json.dumps({"source": "s" * 80})},
        ] + [{"id": f"evt_z{index:03d}", "payload": json.dumps({"source": "saturn_mcp"})} for index in range(23)]
        connection.execute(
            sa.text("INSERT INTO audit_logs (id, organization_id, created_at, payload) VALUES (:id, 'org', '2026-01-01', :payload)"),
            rows,
        )

    migration.BATCH = 4  # several batches, and a last one that is not full
    _run(engine, migration.upgrade)
    _run(engine, migration.upgrade)  # a second run finds nothing to do

    with engine.connect() as connection:
        sources = dict(connection.execute(sa.text("SELECT id, source FROM audit_logs")).all())
        indexes = {index["name"] for index in sa.inspect(connection).get_indexes("audit_logs")}
    assert sources["evt_a"] == "saturn_mcp"
    assert sources["evt_b"] == "console"
    assert sources["evt_c"] is None and sources["evt_d"] is None and sources["evt_e"] is None
    assert sources["evt_f"] is None
    assert sources["evt_g"] == "s" * 64
    assert all(sources[f"evt_z{index:03d}"] == "saturn_mcp" for index in range(23))
    assert "ix_audit_logs_org_source_created" in indexes

    _run(engine, migration.downgrade)
    with engine.connect() as connection:
        columns = {column["name"] for column in sa.inspect(connection).get_columns("audit_logs")}
        indexes = {index["name"] for index in sa.inspect(connection).get_indexes("audit_logs")}
    assert "source" not in columns
    assert "ix_audit_logs_org_source_created" not in indexes
