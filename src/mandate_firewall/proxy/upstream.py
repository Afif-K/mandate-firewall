"""Client for the upstream JSON-RPC node.

Each call is sent as its own single request, with an id we choose, and the
reply must echo that id. We don't trust the upstream to be well-behaved:
responses are size-capped and shape-checked, and anything odd becomes an
UpstreamError rather than being passed through to the agent.
"""

import itertools
import json
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from mandate_firewall.proxy.jsonrpc import JsonRpcErrorObject

DEFAULT_TIMEOUT_SECONDS = 30.0
# eth_getLogs and full blocks can be large; this bounds memory, not normal use.
MAX_UPSTREAM_RESPONSE_BYTES = 16 * 1024 * 1024


class UpstreamError(Exception):
    """The upstream could not be reached or returned something that isn't a
    valid JSON-RPC response to our request."""


class UpstreamResult(BaseModel):
    """A valid upstream reply. If error is set, result is meaningless."""

    model_config = ConfigDict(frozen=True)

    result: Any = None
    error: JsonRpcErrorObject | None = None


class UpstreamClient:
    def __init__(self, url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._url = url
        self._ids = itertools.count(1)
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            # Never follow redirects: a redirect could send a signed transaction
            # to a host the operator didn't configure.
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def call(self, method: str, params: list[Any] | dict[str, Any] | None) -> UpstreamResult:
        request_id = next(self._ids)
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params

        try:
            async with self._client.stream("POST", self._url, json=payload) as response:
                if response.status_code != 200:
                    raise UpstreamError(f"upstream returned HTTP {response.status_code}")
                body = await _read_capped(response)
        except httpx.HTTPError as exc:
            # Exception text can include the URL, which may contain an API key.
            raise UpstreamError(f"upstream request failed: {type(exc).__name__}") from exc

        return _parse_response(body, request_id)

    async def fetch_chain_id(self) -> int:
        reply = await self.call("eth_chainId", [])
        if reply.error is not None:
            raise UpstreamError(f"eth_chainId returned error {reply.error.code}")
        result = reply.result
        if not isinstance(result, str) or not result.startswith("0x") or len(result) < 3:
            raise UpstreamError("eth_chainId returned a non-hex result")
        try:
            chain_id = int(result, 16)
        except ValueError as exc:
            raise UpstreamError("eth_chainId returned a non-hex result") from exc
        if chain_id <= 0:
            raise UpstreamError("eth_chainId returned a non-positive chain id")
        return chain_id


async def _read_capped(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > MAX_UPSTREAM_RESPONSE_BYTES:
            raise UpstreamError(f"upstream response exceeds {MAX_UPSTREAM_RESPONSE_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_response(body: bytes, request_id: int) -> UpstreamResult:
    try:
        obj = json.loads(body)
    except ValueError as exc:
        raise UpstreamError("upstream returned invalid JSON") from exc
    if not isinstance(obj, dict) or obj.get("jsonrpc") != "2.0":
        raise UpstreamError("upstream returned a non-JSON-RPC response")
    # Exact type check: in Python, True == 1 and 1.0 == 1.
    if type(obj.get("id")) is not int or obj["id"] != request_id:
        raise UpstreamError("upstream response id does not match the request")

    has_result, has_error = "result" in obj, "error" in obj
    if has_result == has_error:
        raise UpstreamError("upstream response must have exactly one of result or error")
    if has_result:
        return UpstreamResult(result=obj["result"])
    try:
        return UpstreamResult(error=JsonRpcErrorObject.model_validate(obj["error"]))
    except ValidationError as exc:
        raise UpstreamError("upstream returned a malformed error object") from exc
