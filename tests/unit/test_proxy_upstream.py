"""UpstreamClient against a mocked node: only well-formed replies get through."""

import json
from typing import Any

import httpx
import pytest
import respx

from mandate_firewall.proxy import upstream as upstream_module
from mandate_firewall.proxy.upstream import UpstreamClient, UpstreamError

URL = "http://upstream.test:8545/v2/SECRET-API-KEY"


def reply(request: httpx.Request, **fields: Any) -> httpx.Response:
    request_id = json.loads(request.content)["id"]
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": request_id, **fields})


@pytest.fixture
async def client() -> Any:
    c = UpstreamClient(URL)
    yield c
    await c.aclose()


@respx.mock
async def test_sends_a_fresh_request_and_returns_result(client: UpstreamClient) -> None:
    route = respx.post(URL).mock(side_effect=lambda r: reply(r, result="0x10"))
    result = await client.call("eth_blockNumber", [])
    assert result.result == "0x10" and result.error is None
    sent = json.loads(route.calls.last.request.content)
    assert sent == {"jsonrpc": "2.0", "id": sent["id"], "method": "eth_blockNumber", "params": []}


@respx.mock
async def test_returns_upstream_error_object(client: UpstreamClient) -> None:
    respx.post(URL).mock(
        side_effect=lambda r: reply(r, error={"code": -32000, "message": "nonce too low"})
    )
    result = await client.call("eth_sendRawTransaction", ["0x00"])
    assert result.error is not None
    assert (result.error.code, result.error.message) == (-32000, "nonce too low")


@respx.mock
async def test_null_result_is_a_valid_result(client: UpstreamClient) -> None:
    respx.post(URL).mock(side_effect=lambda r: reply(r, result=None))
    result = await client.call("eth_getTransactionReceipt", ["0x" + "00" * 32])
    assert result.result is None and result.error is None


def _shifted_id(r: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": json.loads(r.content)["id"] + 1, "result": "0x1"}
    )


def _true_id(r: httpx.Request) -> httpx.Response:
    # True == 1 in Python; it must still be rejected.
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": True, "result": "0x1"})


@pytest.mark.parametrize(
    "respond",
    [
        lambda r: httpx.Response(500, json={"error": "boom"}),
        lambda r: httpx.Response(429, text="rate limited"),
        lambda r: httpx.Response(302, headers={"location": "http://evil.test/"}),
        lambda r: httpx.Response(200, text="not json"),
        lambda r: httpx.Response(200, json=[1, 2]),
        lambda r: reply(r, jsonrpc="1.0", result="0x1"),
        _shifted_id,
        _true_id,
        lambda r: reply(r),  # neither result nor error
        lambda r: reply(r, result="0x1", error={"code": 1, "message": "x"}),
        lambda r: reply(r, error={"code": "bad", "message": "x"}),
        lambda r: reply(r, error="just a string"),
    ],
)
@respx.mock
async def test_malformed_replies_raise(client: UpstreamClient, respond: Any) -> None:
    respx.post(URL).mock(side_effect=respond)
    with pytest.raises(UpstreamError):
        await client.call("eth_blockNumber", [])


@respx.mock
async def test_oversized_reply_raises(
    client: UpstreamClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upstream_module, "MAX_UPSTREAM_RESPONSE_BYTES", 100)
    respx.post(URL).mock(side_effect=lambda r: reply(r, result="0x" + "ab" * 100))
    with pytest.raises(UpstreamError, match="exceeds"):
        await client.call("eth_getLogs", [{}])


@respx.mock
async def test_connection_error_does_not_leak_the_url(client: UpstreamClient) -> None:
    respx.post(URL).mock(side_effect=httpx.ConnectError(f"cannot connect to {URL}"))
    with pytest.raises(UpstreamError) as excinfo:
        await client.call("eth_blockNumber", [])
    assert "SECRET-API-KEY" not in str(excinfo.value)


@pytest.mark.parametrize("result", ["0x14a34", "0x1"])
@respx.mock
async def test_fetch_chain_id(client: UpstreamClient, result: str) -> None:
    respx.post(URL).mock(side_effect=lambda r: reply(r, result=result))
    assert await client.fetch_chain_id() == int(result, 16)


@pytest.mark.parametrize("result", [None, 84532, "84532", "0x", "0xzz", "0x0", ""])
@respx.mock
async def test_fetch_chain_id_rejects_bad_results(client: UpstreamClient, result: Any) -> None:
    respx.post(URL).mock(side_effect=lambda r: reply(r, result=result))
    with pytest.raises(UpstreamError):
        await client.fetch_chain_id()
