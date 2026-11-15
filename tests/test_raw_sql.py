"""Hand-written SQL that only PostgreSQL would refuse.

The suite runs on SQLite, which never checks parameter types. PostgreSQL does: when one bind
parameter is used twice and nothing states its type, it can read one use as varchar and the
other as text, and it refuses the whole statement with "inconsistent types deduced for
parameter $1". The gateway's audit counter did exactly that on an organization's first tool
call. Nothing here can run that statement on PostgreSQL, so this reads the source instead.
"""

import ast
import re
from collections import Counter
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"
_PARAMETER = re.compile(r"(?<![:\w]):([a-z_][a-z0-9_]*)")


def _statements():
    for path in sorted(APP.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            first = node.args[0]
            if name == "text" and isinstance(first, ast.Constant) and isinstance(first.value, str):
                yield f"{path.relative_to(APP.parent)}:{node.lineno}", first.value


def _untyped_reuse(sql: str) -> list[str]:
    """Parameters used more than once with a use that is not inside CAST(:name AS ...)."""
    uses = Counter(_PARAMETER.findall(sql))
    typed = Counter(re.findall(r"CAST\(\s*:([a-z_][a-z0-9_]*)\s+AS\s", sql, flags=re.IGNORECASE))
    return sorted(name for name, count in uses.items() if count > 1 and typed[name] != count)


def test_the_check_itself_tells_typed_reuse_from_untyped():
    assert _untyped_reuse("SELECT 1 WHERE a = :x AND b = :y") == []
    assert _untyped_reuse("INSERT INTO t VALUES (:x, (SELECT 1 WHERE a = :x))") == ["x"]
    assert _untyped_reuse("INSERT INTO t VALUES (CAST(:x AS VARCHAR), (SELECT 1 WHERE a = :x))") == ["x"]
    assert _untyped_reuse("INSERT INTO t VALUES (CAST(:x AS VARCHAR), (SELECT 1 WHERE a = cast(:x as varchar)))") == []
    # A PostgreSQL cast written with :: is not a parameter.
    assert _untyped_reuse("SELECT now()::date, now()::date") == []


def test_a_parameter_used_twice_in_raw_sql_states_its_type_each_time():
    found = list(_statements())
    assert any("audit_counters" in sql for _where, sql in found), "the scan no longer finds the gateway's counter statements"
    untyped = {where: names for where, sql in found if (names := _untyped_reuse(sql))}
    assert not untyped, f"PostgreSQL will refuse these statements; wrap each use in CAST(:name AS type): {untyped}"
