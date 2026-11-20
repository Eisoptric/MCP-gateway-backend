"""A failing policy model says why: in the response by status, and in the log with the provider's text."""

import logging

import httpx
import pytest
from fastapi import HTTPException

from app.core.config import get_settings
from app.features.policy.policies.services import policy_llm

KEY = "sk-test-secret-key-123"


@pytest.fixture
def model(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "policy_llm_base_url", "https://llm.example.com/v1")
    monkeypatch.setattr(settings, "policy_llm_api_key", KEY)
    monkeypatch.setattr(settings, "policy_llm_model", "some-model")

    real = httpx.AsyncClient

    def answer_with(handler):
        def client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real(*args, **kwargs)

        monkeypatch.setattr(policy_llm.httpx, "AsyncClient", client)

    return answer_with


@pytest.mark.parametrize(
    ("code", "says"),
    [
        (401, "rejected the API key"),
        (403, "rejected the API key"),
        (404, "not found"),
        (429, "rate limited"),
        # The body says the key is wrong, so a 400 is about the key too.
        (400, "rejected the API key"),
        (503, "provider had an error"),
        (418, "HTTP 418"),
    ],
)
async def test_each_refusal_says_why(model, caplog, code, says):
    model(lambda request: httpx.Response(code, json={"error": {"message": f"Incorrect API key provided: {KEY}"}}))
    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as refused:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert refused.value.status_code == 502
    assert says in refused.value.detail
    # The provider's text is in the log for whoever runs Eisoptric, with the key removed.
    assert f"HTTP {code}" in caplog.text
    assert "Incorrect API key provided" in caplog.text
    assert KEY not in caplog.text
    # The provider's own words never reach the person in the console.
    assert "Incorrect API key provided" not in refused.value.detail


async def test_streaming_refusals_say_why_too(model):
    model(lambda request: httpx.Response(404, text="model not found"))
    with pytest.raises(HTTPException) as refused:
        async for _event in policy_llm._iter_deltas([{"role": "user", "content": "hi"}]):
            pass
    assert "not found" in refused.value.detail


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
    assert "Could not reach" in unreachable.value.detail


async def test_a_non_json_success_is_unreadable_not_a_crash(model):
    model(lambda request: httpx.Response(200, text="<html>gateway</html>"))
    with pytest.raises(HTTPException) as unreadable:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert unreadable.value.detail == "Policy model returned an unreadable response"


async def test_a_bad_key_answered_with_400_says_to_check_the_key(model):
    # Gemini's OpenAI-compatible endpoint answers an invalid key with 400 INVALID_ARGUMENT.
    model(lambda request: httpx.Response(400, json=[{"error": {"code": 400, "message": "Please pass a valid API key", "status": "INVALID_ARGUMENT"}}]))
    with pytest.raises(HTTPException) as refused:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert "POLICY_LLM_API_KEY" in refused.value.detail


@pytest.mark.parametrize(
    ("base_url", "sends_temperature"),
    [("https://api.anthropic.com/v1/", False), ("https://generativelanguage.googleapis.com/v1beta/openai/", True), ("https://llm.example.com/v1", True)],
)
async def test_temperature_is_left_out_only_for_anthropic(model, monkeypatch, base_url, sends_temperature):
    import json

    monkeypatch.setattr(get_settings(), "policy_llm_base_url", base_url)
    seen = {}

    def answer(request):
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"rules": []}'}}]})

    model(answer)
    try:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    except HTTPException:
        pass  # Whether the answer parses is not what this test is about.
    assert ("temperature" in seen) is sends_temperature
    assert seen["model"] == "some-model"


async def test_another_400_still_points_at_the_model(model):
    model(lambda request: httpx.Response(400, json={"error": {"message": "Unknown model: some-model"}}))
    with pytest.raises(HTTPException) as refused:
        await policy_llm._chat([{"role": "user", "content": "hi"}])
    assert "rejected the request" in refused.value.detail
    assert "POLICY_LLM_MODEL" in refused.value.detail
