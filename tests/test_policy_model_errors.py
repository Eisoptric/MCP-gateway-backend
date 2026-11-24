"""Anthropic Workload Identity Federation policy model: OIDC exchange, JTI safety, streaming and refusals."""

import asyncio
import json
import logging
import threading

import httpx
import pytest
from fastapi import HTTPException
from google.auth.exceptions import DefaultCredentialsError

from app.core.config import get_settings
from app.features.policy.policies.services import policy_llm

ACCESS_TOKEN = "test-wif-access-token-123"
OIDC_ASSERTION = "eyJhbGciOiJSUzI1NiJ9.fake-google-oidc-jwt.signature"


@pytest.fixture
def model(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "anthropic_organization_id", "00000000-0000-0000-0000-000000000001")
    monkeypatch.setattr(settings, "anthropic_federation_rule_id", "fdrl_01TESTRULE")
    monkeypatch.setattr(settings, "anthropic_service_account_id", "svac_01TESTSA")
    monkeypatch.setattr(settings, "anthropic_workspace_id", "")
    monkeypatch.setattr(settings, "anthropic_audience", "https://api.anthropic.com")
    monkeypatch.setattr(settings, "policy_llm_model", "claude-sonnet-4-6")
    policy_llm._reset_credentials()

    monkeypatch.setattr(policy_llm, "_fetch_oidc_assertion", lambda audience: OIDC_ASSERTION)

    real = httpx.AsyncClient

    def answer_with(messages_handler, token_handler=None):
        def router(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/oauth/token":
                if token_handler is not None:
                    return token_handler(request)
                return httpx.Response(
                    200,
                    json={"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600},
                )
            return messages_handler(request)

        def client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(router)
            return real(*args, **kwargs)

        monkeypatch.setattr(policy_llm.httpx, "AsyncClient", client)

    yield answer_with
    policy_llm._reset_credentials()


@pytest.mark.parametrize(
    ("code", "says"),
    [
        (401, "rejected the Workload Identity token"),
        (403, "rejected the Workload Identity token"),
        (404, "not found on Anthropic"),
        (429, "rate limited"),
        (400, "rejected the request"),
        (503, "provider had an error"),
        (418, "HTTP 418"),
    ],
)
async def test_each_refusal_says_why(model, caplog, code, says):
    model(lambda request: httpx.Response(code, json={"error": {"message": f"Invalid token {ACCESS_TOKEN}"}}))
    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as refused:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert refused.value.status_code == 502
    assert says in refused.value.detail
    # The provider's text is in the log for whoever runs Eisoptric, with the bearer token removed.
    assert f"HTTP {code}" in caplog.text
    assert "Invalid token" in caplog.text
    assert ACCESS_TOKEN not in caplog.text
    # The provider's own words never reach the person in the console.
    assert "Invalid token" not in refused.value.detail


async def test_streaming_refusals_say_why_too(model):
    model(lambda request: httpx.Response(404, text="model not found"))
    with pytest.raises(HTTPException) as refused:
        async for _event in policy_llm._iter_deltas([{"role": "user", "content": "hi"}]):
            pass
    assert "not found on Anthropic" in refused.value.detail


async def test_a_timeout_and_an_unreachable_model_are_told_apart(model):
    def slow(request):
        raise httpx.ReadTimeout("slow", request=request)

    model(slow)
    with pytest.raises(HTTPException) as timed_out:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert timed_out.value.status_code == 504

    def down(request):
        raise httpx.ConnectError("refused", request=request)

    model(down)
    with pytest.raises(HTTPException) as unreachable:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert unreachable.value.status_code == 502
    assert "Could not reach Anthropic API" in unreachable.value.detail


async def test_a_non_json_success_is_unreadable_not_a_crash(model):
    model(lambda request: httpx.Response(200, text="<html>gateway</html>"))
    with pytest.raises(HTTPException) as unreadable:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert unreadable.value.detail == "Policy model returned an unreadable response"


async def test_wif_exchanges_oidc_jwt_and_calls_anthropic_messages(model, monkeypatch):
    monkeypatch.setattr(get_settings(), "anthropic_workspace_id", "wrkspc_01TESTWS")
    seen_exchange = {}
    seen_messages = {}

    def on_token(request: httpx.Request) -> httpx.Response:
        seen_exchange["url"] = str(request.url)
        seen_exchange["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600},
        )

    def on_messages(request: httpx.Request) -> httpx.Response:
        seen_messages["url"] = str(request.url)
        seen_messages["auth"] = request.headers.get("authorization")
        seen_messages["version"] = request.headers.get("anthropic-version")
        seen_messages["x_api_key"] = request.headers.get("x-api-key")
        seen_messages["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "type": "message",
                "content": [
                    {"type": "thinking", "thinking": "Checking schema."},
                    {"type": "text", "text": '{"tools": []}'},
                ],
            },
        )

    model(on_messages, token_handler=on_token)
    parsed = await policy_llm._chat(
        [
            {"role": "system", "content": "Follow policy rules."},
            {"role": "user", "content": '{"tools": []}'},
        ]
    )
    assert parsed == {"tools": []}
    assert seen_exchange["url"] == "https://api.anthropic.com/v1/oauth/token"
    assert seen_exchange["body"] == {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": OIDC_ASSERTION,
        "federation_rule_id": "fdrl_01TESTRULE",
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "service_account_id": "svac_01TESTSA",
        "workspace_id": "wrkspc_01TESTWS",
    }
    assert seen_messages["url"] == "https://api.anthropic.com/v1/messages"
    assert seen_messages["auth"] == f"Bearer {ACCESS_TOKEN}"
    assert seen_messages["version"] == "2023-06-01"
    assert seen_messages["x_api_key"] is None
    assert seen_messages["body"] == {
        "model": "claude-sonnet-4-6",
        "max_tokens": 16384,
        "system": "Follow policy rules.",
        "messages": [{"role": "user", "content": '{"tools": []}'}],
    }
    assert "temperature" not in seen_messages["body"]


async def test_streaming_messages_parses_anthropic_sse_deltas(model):
    seen = {}
    sse = "\n".join(
        [
            "event: message_start",
            'data: {"type":"message_start","message":{"id":"msg_1","content":[]}}',
            "",
            "event: content_block_delta",
            'data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Inspecting tools."}}',
            "",
            "event: content_block_delta",
            'data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"{\\"tools\\": "}}',
            "",
            "event: content_block_delta",
            'data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"[]}"}}',
            "",
            "event: message_stop",
            'data: {"type":"message_stop"}',
            "",
        ]
    )

    def answer(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=sse)

    model(answer)
    events = [item async for item in policy_llm.stream_chat([{"role": "user", "content": "hi"}])]
    assert events == [("result", {"tools": []})]
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["body"]["stream"] is True


async def test_concurrent_calls_exchange_once_to_avoid_jti_replay_and_refresh_after_401(model, monkeypatch):
    from google.oauth2 import id_token

    policy_llm._reset_credentials()
    threads: list[int] = []
    assertions_minted = 0
    exchanges = 0

    def fake_fetch_id_token(_request, audience: str) -> str:
        nonlocal assertions_minted
        assert audience == "https://api.anthropic.com"
        threads.append(threading.get_ident())
        assertions_minted += 1
        return f"oidc-jwt-{assertions_minted}"

    monkeypatch.undo()  # restore real _fetch_oidc_assertion? No, just re-patch id_token directly:

    # Re-apply fixture settings and patch google.oauth2.id_token.fetch_id_token directly.
    settings = get_settings()
    monkeypatch.setattr(settings, "anthropic_organization_id", "00000000-0000-0000-0000-000000000001")
    monkeypatch.setattr(settings, "anthropic_federation_rule_id", "fdrl_01TESTRULE")
    monkeypatch.setattr(settings, "anthropic_service_account_id", "svac_01TESTSA")
    monkeypatch.setattr(settings, "policy_llm_model", "claude-sonnet-4-6")
    monkeypatch.delenv("ANTHROPIC_IDENTITY_TOKEN_FILE", raising=False)
    monkeypatch.delenv("ANTHROPIC_IDENTITY_TOKEN", raising=False)
    monkeypatch.setattr(id_token, "fetch_id_token", fake_fetch_id_token)

    def on_token(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        exchanges += 1
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={"access_token": f"oat-{exchanges}-from-{body['assertion']}", "expires_in": 3600},
        )

    real = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(on_token)
        return real(*args, **kwargs)

    monkeypatch.setattr(policy_llm.httpx, "AsyncClient", client)

    tokens = await asyncio.gather(*(policy_llm._access_token() for _ in range(5)))
    assert tokens == ["oat-1-from-oidc-jwt-1"] * 5
    assert assertions_minted == 1
    assert exchanges == 1
    assert threads and threading.get_ident() not in threads

    # A 401 on /v1/messages drops the cached access token so the next request fetches a new OIDC JWT.
    policy_llm._model_refused(401, "expired", "https://api.anthropic.com/v1/messages", tokens[0])
    refreshed = await policy_llm._access_token()
    assert refreshed == "oat-2-from-oidc-jwt-2"
    assert assertions_minted == 2
    assert exchanges == 2


async def test_token_exchange_refusal_redacts_assertion_and_missing_oidc_returns_502(model, monkeypatch, caplog):
    from google.oauth2 import id_token

    def refused_exchange(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": f"subject token rejected: {OIDC_ASSERTION}"})

    model(lambda request: httpx.Response(200, json={}), token_handler=refused_exchange)
    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as refused:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert refused.value.status_code == 502
    assert "Anthropic Workload Identity token exchange failed" in refused.value.detail
    assert OIDC_ASSERTION not in caplog.text
    assert OIDC_ASSERTION not in refused.value.detail

    policy_llm._reset_credentials()

    def no_metadata(_request, _audience):
        raise DefaultCredentialsError("no metadata server")

    monkeypatch.setattr(
        policy_llm,
        "_fetch_oidc_assertion",
        lambda audience: id_token.fetch_id_token(None, audience),
    )
    monkeypatch.setattr(id_token, "fetch_id_token", no_metadata)
    with pytest.raises(HTTPException) as missing:
        await policy_llm._access_token()
    assert missing.value.status_code == 502
    assert "OIDC identity token" in missing.value.detail
