"""One passkey for the console and ops: the relying party can be the parent domain of both."""

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.config import get_settings
from app.features.identity.auth.services.passkeys import relying_party

TRUSTED = "https://console.eisoptric.com,https://ops.eisoptric.com,http://localhost:3000"


def _request(origin: str) -> Request:
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [(b"origin", origin.encode())]})


@pytest.fixture
def shared(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "cors_origins", TRUSTED)
    monkeypatch.setattr(settings, "webauthn_rp_id", "eisoptric.com")


@pytest.mark.parametrize("origin", ["https://console.eisoptric.com", "https://ops.eisoptric.com"])
def test_console_and_ops_share_one_relying_party(shared, origin):
    assert relying_party(_request(origin)) == ("eisoptric.com", origin)


def test_an_origin_outside_the_shared_domain_keeps_its_own_host(shared):
    # Local development still works: localhost is not under eisoptric.com.
    assert relying_party(_request("http://localhost:3000")) == ("localhost", "http://localhost:3000")


def test_a_subdomain_that_is_not_trusted_cannot_use_the_shared_passkey(shared):
    with pytest.raises(HTTPException):
        relying_party(_request("https://evil.eisoptric.com"))


def test_a_lookalike_domain_is_not_under_the_shared_one(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "cors_origins", "https://console.noteisoptric.com")
    monkeypatch.setattr(settings, "webauthn_rp_id", "eisoptric.com")
    assert relying_party(_request("https://console.noteisoptric.com"))[0] == "console.noteisoptric.com"


def test_without_a_shared_domain_each_origin_has_its_own(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "cors_origins", TRUSTED)
    monkeypatch.setattr(settings, "webauthn_rp_id", "")
    assert relying_party(_request("https://ops.eisoptric.com"))[0] == "ops.eisoptric.com"


async def test_registration_options_name_the_shared_relying_party(client, shared):
    options = await client.post("/auth/passkeys/options", headers={"Origin": "https://ops.eisoptric.com"})
    assert options.status_code == 200, options.text
    assert "eisoptric.com" in options.text
    assert "ops.eisoptric.com" not in options.text
