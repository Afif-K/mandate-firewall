"""LLM extractor over raw HTTP: request shape, response parsing, failures, no leaks."""

import json
import logging
import socket
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mandate_firewall.capture.extractor import (
    API_VERSION,
    DRAFT_SCHEMA,
    FALLBACK_BETA,
    MAX_RESPONSE_BYTES,
    SYSTEM_PROMPT,
    AnthropicExtractor,
    ExtractionError,
    FakeExtractor,
)
from mandate_firewall.capture.settings import CaptureSettings
from mandate_firewall.mandate.draft import Draft, DraftIntent

SENTINEL = "sk-ant-SENTINEL-must-never-appear-0123456789"
INSTRUCTION = "send 50 USDC to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
DRAFT_JSON = {
    "intents": [
        {
            "kind": "transfer",
            "asset_symbol": "USDC",
            "amount_text": "50",
            "recipient_text": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "buy_symbol": None,
            "min_out_text": None,
            "venue_name": None,
        }
    ],
    "ambiguities": [],
    "unsupported": None,
}


def settings(**overrides: Any) -> CaptureSettings:
    # _env_file=None: tests never read the developer's real .env.
    values: dict[str, Any] = {"llm_api_key": SENTINEL} | overrides
    return CaptureSettings(_env_file=None, **values)  # type: ignore[call-arg]


def message(*blocks: dict[str, Any], stop_reason: str = "end_turn", **extra: Any) -> dict[str, Any]:
    return {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": list(blocks),
        "stop_reason": stop_reason,
        "stop_details": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    } | extra


def text(value: Any) -> dict[str, Any]:
    return {"type": "text", "text": value if isinstance(value, str) else json.dumps(value)}


THINKING = {"type": "thinking", "thinking": "", "signature": "sig"}


class Recorder:
    """An httpx MockTransport that answers with one fixed response."""

    def __init__(self, status: int = 200, body: Any = None, headers: dict[str, str] | None = None):
        self.requests: list[httpx.Request] = []
        self.status = status
        self.body = message(THINKING, text(DRAFT_JSON)) if body is None else body
        self.headers = {"request-id": "req_011ABC"} | (headers or {})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        content = self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()
        return httpx.Response(self.status, content=content, headers=self.headers)


def extract(recorder: Recorder | Callable[[httpx.Request], httpx.Response], **kw: Any) -> Draft:
    extractor = AnthropicExtractor(settings(**kw), transport=httpx.MockTransport(recorder))
    return extractor.extract(INSTRUCTION)


def failure(recorder: Any, **kw: Any) -> ExtractionError:
    with pytest.raises(ExtractionError) as info:
        extract(recorder, **kw)
    error = info.value
    assert SENTINEL not in str(error) and SENTINEL not in repr(error)
    return error


# --- the schema sent to the API --------------------------------------------------


def _objects(schema: Any) -> Iterator[dict[str, Any]]:
    if isinstance(schema, dict):
        if schema.get("type") == "object":
            yield schema
        for value in schema.values():
            yield from _objects(value)
    elif isinstance(schema, list):
        for item in schema:
            yield from _objects(item)


def test_schema_matches_the_draft_models() -> None:
    assert set(DRAFT_SCHEMA["properties"]) == set(Draft.model_fields)
    intent = DRAFT_SCHEMA["properties"]["intents"]["items"]
    assert set(intent["properties"]) == set(DraftIntent.model_fields)
    assert intent["properties"]["kind"]["enum"] == ["transfer", "swap"]


def test_schema_follows_the_api_limits() -> None:
    # docs: additionalProperties must be false; no length or numeric limits;
    # optional parameters <= 24 and union types <= 16 per request.
    objects = list(_objects(DRAFT_SCHEMA))
    assert len(objects) == 2
    for obj in objects:
        assert obj["additionalProperties"] is False
        assert set(obj["required"]) == set(obj["properties"])  # nothing optional
    dumped = json.dumps(DRAFT_SCHEMA)
    for keyword in ("minLength", "maxLength", "maxItems", "minimum", "maximum", "multipleOf"):
        assert keyword not in dumped
    assert dumped.count('["string", "null"]') <= 16


def test_every_valid_schema_output_is_parsed_by_draft() -> None:
    Draft.model_validate(DRAFT_JSON)
    Draft.model_validate({"intents": [], "ambiguities": ["which token?"], "unsupported": None})


# --- the request ----------------------------------------------------------------


def test_request_shape() -> None:
    recorder = Recorder()
    extract(recorder)
    (request,) = recorder.requests
    assert request.method == "POST"
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    assert request.headers["authorization"] == f"Bearer {SENTINEL}"
    assert request.headers["anthropic-version"] == API_VERSION == "2026-10-21"
    assert request.headers["anthropic-beta"] == FALLBACK_BETA
    assert request.headers["content-type"] == "application/json"
    assert "x-api-key" not in request.headers
    body = json.loads(request.content)
    assert body == {
        "model": "claude-opus-5-5",
        "max_tokens": 16000,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": INSTRUCTION}],
        "output_config": {"format": {"type": "json_schema", "schema": DRAFT_SCHEMA}},
        "fallbacks": "default",
    }


def test_model_and_base_url_come_from_settings() -> None:
    recorder = Recorder()
    extract(recorder, llm_model="claude-sonnet-5-5", llm_base_url="https://llm.example/proxy")
    (request,) = recorder.requests
    assert str(request.url) == "https://llm.example/proxy/v1/messages"
    assert json.loads(request.content)["model"] == "claude-sonnet-5-5"


def test_no_key_fails_without_a_request() -> None:
    recorder = Recorder()
    error = failure(recorder, llm_api_key=None)
    assert error.kind == "config"
    assert recorder.requests == []


def test_too_long_instruction_is_not_sent() -> None:
    recorder = Recorder()
    extractor = AnthropicExtractor(settings(), transport=httpx.MockTransport(recorder))
    with pytest.raises(ExtractionError) as info:
        extractor.extract("x" * 4001)
    assert info.value.kind == "input"
    assert recorder.requests == []


# --- successful responses -------------------------------------------------------


def test_draft_is_parsed_after_thinking_blocks() -> None:
    draft = extract(Recorder())
    (intent,) = draft.intents
    assert (intent.kind, intent.asset_symbol, intent.amount_text) == ("transfer", "USDC", "50")
    assert intent.recipient_text == "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def test_fallback_block_before_the_text_is_fine() -> None:
    fallback = {
        "type": "fallback",
        "from": {"model": "claude-opus-5-5"},
        "to": {"model": "claude-opus-4-8"},
        "trigger": {"type": "refusal", "category": "cyber"},
    }
    body = message(fallback, text(DRAFT_JSON), model="claude-opus-4-8")
    assert extract(Recorder(body=body)).intents[0].amount_text == "50"


# --- failures --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (401, "auth"),
        (403, "auth"),
        (429, "rate_limit"),
        (400, "status"),
        (500, "status"),
        (529, "status"),
    ],
)
def test_http_errors(status: int, kind: str) -> None:
    body = {
        "type": "error",
        "error": {"type": "some_error", "message": f"echo of {SENTINEL} and the input"},
        "request_id": "req_011ABC",
    }
    error = failure(Recorder(status=status, body=body))
    assert (error.kind, error.status_code, error.detail) == (kind, status, "some_error")
    assert error.request_id == "req_011ABC"
    assert "echo" not in str(error)


@pytest.mark.parametrize("error_type", ["Not An Identifier", "x" * 100, "\x1b[2J", 5])
def test_odd_error_types_are_not_shown(error_type: Any) -> None:
    body = {"type": "error", "error": {"type": error_type, "message": "m"}}
    assert failure(Recorder(status=400, body=body)).detail is None


def test_odd_request_id_is_not_shown() -> None:
    error = failure(Recorder(status=500, body={}, headers={"request-id": "req_<script>"}))
    assert error.request_id is None


def test_non_json_error_body() -> None:
    error = failure(Recorder(status=502, body=b"<html>Bad Gateway</html>"))
    assert (error.kind, error.status_code, error.detail) == ("status", 502, None)


def test_redirects_are_not_followed() -> None:
    recorder = Recorder(status=307, body=b"", headers={"location": "https://evil.example/"})
    error = failure(recorder)
    assert (error.kind, error.status_code) == ("status", 307)
    assert len(recorder.requests) == 1


def test_refusal() -> None:
    body = message(
        stop_reason="refusal",
        stop_details={"type": "refusal", "category": "cyber", "explanation": "declined"},
    )
    error = failure(Recorder(body=body))
    assert (error.kind, error.detail) == ("refusal", "cyber")


def test_refusal_with_null_category() -> None:
    body = message(stop_reason="refusal", stop_details={"type": "refusal", "category": None})
    assert failure(Recorder(body=body)).detail is None


@pytest.mark.parametrize("reason", ["max_tokens", "model_context_window_exceeded"])
def test_truncated(reason: str) -> None:
    body = message(text('{"intents": ['), stop_reason=reason)
    assert failure(Recorder(body=body)).kind == "truncated"


@pytest.mark.parametrize("reason", ["tool_use", "pause_turn", "stop_sequence", None, "new_reason"])
def test_other_stop_reasons_are_invalid(reason: str | None) -> None:
    assert failure(Recorder(body=message(text(DRAFT_JSON), stop_reason=reason))).kind == (
        "invalid_output"
    )  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "blocks",
    [(), (THINKING,), (text(DRAFT_JSON), text(DRAFT_JSON)), ({"type": "text", "text": 5},)],
)
def test_exactly_one_text_block(blocks: tuple[dict[str, Any], ...]) -> None:
    assert failure(Recorder(body=message(*blocks))).kind == "invalid_output"


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[]",
        json.dumps(DRAFT_JSON | {"extra": 1}),
        json.dumps(DRAFT_JSON | {"intents": [DRAFT_JSON["intents"][0] | {"kind": "Transfer"}]}),
        json.dumps(DRAFT_JSON | {"intents": [DRAFT_JSON["intents"][0]] * 6}),  # over 5
        '{"intents": [], "ambiguities": [], "unsupported": null, "unsupported": "x"}',
    ],
)
def test_output_that_is_not_a_draft(payload: str) -> None:
    error = failure(Recorder(body=message(text(payload))))
    assert error.kind == "invalid_output"


def test_invalid_output_names_the_field_not_the_value() -> None:
    bad = DRAFT_JSON | {"intents": [DRAFT_JSON["intents"][0] | {"amount_text": "A" * 300}]}
    error = failure(Recorder(body=message(text(bad))))
    assert error.detail == "invalid at intents.0.amount_text"
    assert "AAAA" not in str(error)


def test_oversized_response() -> None:
    # Valid Draft JSON, padded: only the size cap can reject it.
    body = message(text(json.dumps(DRAFT_JSON) + " " * (MAX_RESPONSE_BYTES + 1)))
    assert failure(Recorder(body=body)).kind == "invalid_output"


def test_200_with_non_json_body() -> None:
    assert failure(Recorder(body=b"<html>")).kind == "invalid_output"


@pytest.mark.parametrize(
    ("exc", "kind"),
    [
        (httpx.ReadTimeout("slow"), "timeout"),
        (httpx.ConnectTimeout("slow"), "timeout"),
        (httpx.ConnectError("refused"), "connection"),
        (httpx.RemoteProtocolError("bad"), "connection"),
    ],
)
def test_transport_errors(exc: Exception, kind: str) -> None:
    def raise_(request: httpx.Request) -> httpx.Response:
        raise exc

    assert failure(raise_).kind == kind


# --- settings --------------------------------------------------------------------


def test_settings_repr_hides_the_key() -> None:
    s = settings()
    assert SENTINEL not in repr(s) and SENTINEL not in str(s)
    assert SENTINEL not in repr(AnthropicExtractor(s))


def test_settings_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", SENTINEL)
    monkeypatch.setenv("LLM_MODEL", "claude-haiku-5-5")
    s = CaptureSettings(_env_file=None)  # type: ignore[call-arg]
    assert s.llm_api_key is not None and s.llm_api_key.get_secret_value() == SENTINEL
    assert s.llm_model == "claude-haiku-5-5"


def test_proxy_settings_ignore_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from mandate_firewall.config import Settings

    monkeypatch.setenv("LLM_API_KEY", SENTINEL)
    proxy = Settings(_env_file=None)  # type: ignore[call-arg]
    assert SENTINEL not in repr(proxy.model_dump())


@pytest.mark.parametrize(
    "overrides",
    [
        {"llm_api_key": SENTINEL + " x"},
        {"llm_api_key": SENTINEL + "\nInjected: 1"},
        {"llm_api_key": ""},
        {"llm_base_url": "http://api.anthropic.com"},
        {"llm_base_url": "https://user:pw@api.anthropic.com"},
        {"llm_base_url": "https://api.anthropic.com?x=1"},
        {"llm_model": "Claude Opus"},
        {"llm_model": "../etc"},
        {"llm_timeout_seconds": 0},
    ],
)
def test_bad_settings_are_rejected_without_echoing_the_key(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as info:
        settings(**overrides)
    assert SENTINEL not in str(info.value)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080", "http://localhost", "http://[::1]:9"])
def test_plain_http_only_to_loopback(url: str) -> None:
    settings(llm_base_url=url)


# --- the key never leaks, even with debug logging on -----------------------------


class _Handler(BaseHTTPRequestHandler):
    responses: list[tuple[int, bytes]] = []

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers["content-length"]))
        status, body = self.responses.pop(0)
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def local_server() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_sentinel_key_never_logged_or_raised(
    local_server: str, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    """Real HTTP through httpx and httpcore, every logger at DEBUG: auth
    failure, malformed output, a refusal, success, and a refused connection."""
    caplog.set_level(logging.DEBUG)
    _Handler.responses = [
        (
            401,
            json.dumps(
                {"type": "error", "error": {"type": "authentication_error", "message": SENTINEL}}
            ).encode(),
        ),
        (200, json.dumps(message(text("{not json " + SENTINEL))).encode()),
        (200, json.dumps(message(stop_reason="refusal", stop_details={"category": None})).encode()),
        (200, json.dumps(message(text(DRAFT_JSON))).encode()),
    ]
    extractor = AnthropicExtractor(settings(llm_base_url=local_server))
    errors = []
    for _ in range(3):
        with pytest.raises(ExtractionError) as info:
            extractor.extract(INSTRUCTION)
        errors.append(info.value)
    assert [e.kind for e in errors] == ["auth", "invalid_output", "refusal"]
    assert extractor.extract(INSTRUCTION).intents[0].amount_text == "50"

    with socket.socket() as s:  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        closed = f"http://127.0.0.1:{s.getsockname()[1]}"
    with pytest.raises(ExtractionError) as info:
        AnthropicExtractor(settings(llm_base_url=closed)).extract(INSTRUCTION)
    errors.append(info.value)
    assert errors[-1].kind == "connection"

    assert any(r.name.startswith(("httpx", "httpcore")) for r in caplog.records)
    captured = capsys.readouterr()
    for haystack in (
        caplog.text,
        captured.out,
        captured.err,
        *map(str, errors),
        *map(repr, errors),
    ):
        assert SENTINEL not in haystack
    for error in errors:
        # No chained exception gets printed with it in a traceback.
        assert error.__cause__ is None
        assert error.__context__ is None or error.__suppress_context__


# --- the fake --------------------------------------------------------------------


def test_fake_extractor() -> None:
    draft = Draft.model_validate(DRAFT_JSON)
    fake = FakeExtractor([draft, ExtractionError("timeout")])
    assert fake.extract("one") is draft
    with pytest.raises(ExtractionError):
        fake.extract("two")
    assert fake.instructions == ["one", "two"]


def test_proxy_environment_is_ignored(local_server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # trust_env=False: proxy variables (and ~/.netrc) can't redirect the key.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "all_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    _Handler.responses = [(200, json.dumps(message(text(DRAFT_JSON))).encode())]
    extractor = AnthropicExtractor(settings(llm_base_url=local_server))
    assert extractor.extract(INSTRUCTION).intents[0].amount_text == "50"
