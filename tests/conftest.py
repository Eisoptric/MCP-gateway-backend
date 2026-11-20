import os

os.environ["SKIP_DB_BOOTSTRAP"] = "true"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"
os.environ["IN_PROCESS_RUNTIME"] = "true"
os.environ["POLICY_DEFAULT_DENY"] = "false"
os.environ["SEED_USER_EMAIL"] = "rick@example.com"
os.environ["SEED_USER_PASSWORD"] = "gateway"
os.environ["SEED_USER_NAME"] = "Rick"

from app.features.credentials.vault.services.pq_crypto import install_root

install_root(b"\x11" * 32)

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.database import Base, get_session
from app.main import app
from app.models import *  # noqa: F401,F403
from app.features.mcp.servers.services.mcp_gateway import mcp_gateway
from tests.catalog import seed_test_catalog


@pytest.fixture(autouse=True)
def reset_rate_limits():
    from app.core.rate_limit import reset
    from app.core.status import reset as reset_status
    from app.features.identity.auth.services.totp import reset as reset_totp

    reset()
    reset_totp()
    reset_status()
    yield
    reset()
    reset_totp()


@pytest.fixture(autouse=True)
def fresh_mcp_clients():
    # Kept upstream clients belong to the event loop and transport of the test that made them.
    from app.features.mcp.servers.services import mcp_remote

    mcp_remote._clients.clear()
    mcp_remote._sessions.clear()
    mcp_remote._retired.clear()
    yield
    mcp_remote._clients.clear()
    mcp_remote._sessions.clear()
    mcp_remote._retired.clear()


@pytest.fixture(autouse=True)
def public_mcp_dns(monkeypatch):
    monkeypatch.setattr(
        "app.features.mcp.servers.services.mcp_endpoint.addresses_for",
        lambda _host, _port: ["1.1.1.1"],
    )


@pytest.fixture
async def client():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _fk(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        await seed_test_catalog(session)
        await session.commit()

    async def override_session():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception as exc:
                from fastapi import HTTPException

                if isinstance(exc, HTTPException):
                    await session.commit()
                    raise
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = override_session
    mcp_gateway.reset()
    from app.features.mcp.gateway.services.mcp_sessions import mcp_sessions

    mcp_sessions.reset()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        login = await async_client.post(
            "/auth/login",
            json={"email": "rick@example.com", "password": "gateway"},
        )
        assert login.status_code == 200, login.text
        async_client.headers["Authorization"] = f"Bearer {login.json()['token']}"
        yield async_client

    app.dependency_overrides.clear()
    mcp_gateway.reset()
    mcp_sessions.reset()
    await engine.dispose()


@pytest.fixture
def legacy_window(monkeypatch):
    """Accept legacy (pre-argon2) passwords, as a deployment with old accounts does until its
    LEGACY_PASSWORD_UNTIL date. They are refused when no date is set."""
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "legacy_password_until", "2999-12-31")

