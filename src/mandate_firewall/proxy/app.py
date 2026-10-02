"""The proxy's HTTP app: one POST endpoint that speaks JSON-RPC 2.0.

Request flow:
    HTTP body -> size/content-type checks -> JSON parse -> single or batch
    -> per request: validate -> classify method -> deny | forward | intercept

Run it (commit 5 adds a `serve` command):
    uv run uvicorn mandate_firewall.proxy.app:create_app --factory --port 8546
"""

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from mandate_firewall.config import Settings, redact_url
from mandate_firewall.decode.calldata import decode_calldata
from mandate_firewall.decode.transaction import TransactionDecodeError, decode_raw_transaction
from mandate_firewall.proxy.jsonrpc import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    RESOURCE_UNAVAILABLE,
    TRANSACTION_REJECTED,
    JsonRpcProtocolError,
    JsonRpcRequest,
    error_response,
    parse_request,
    result_response,
)
from mandate_firewall.proxy.methods import MethodClass, classify
from mandate_firewall.proxy.upstream import UpstreamClient, UpstreamError

logger = logging.getLogger(__name__)

# A max-size raw transaction (128 KiB) is 256 KiB as hex; leave room for a batch.
MAX_REQUEST_BYTES = 1024 * 1024
MAX_BATCH_SIZE = 100


class UpstreamUnavailableError(RuntimeError):
    """Raised at startup when the upstream chain id can't be fetched."""


class Proxy:
    """Per-request JSON-RPC handling. Holds the upstream client and the chain id
    that was verified at startup."""

    def __init__(self, upstream: UpstreamClient, chain_id: int, settings: Settings) -> None:
        self.upstream = upstream
        self.chain_id = chain_id
        self.settings = settings

    async def handle(self, obj: Any) -> dict[str, Any]:
        """Handle one request object. Always returns a response; never raises."""
        try:
            request = parse_request(obj)
        except JsonRpcProtocolError as exc:
            return error_response(exc.request_id, exc.code, exc.message)

        method_class = classify(request.method)
        if method_class is MethodClass.FORWARD:
            return await self._forward(request.id, request.method, request.params)
        if method_class is MethodClass.INTERCEPT:
            return await self._send_raw_transaction(request)

        logger.warning("denied method %r", request.method)
        return error_response(
            request.id,
            METHOD_NOT_FOUND,
            f"method {request.method!r} is not allowed by the firewall",
        )

    async def _forward(
        self, request_id: Any, method: str, params: list[Any] | dict[str, Any] | None
    ) -> dict[str, Any]:
        try:
            reply = await self.upstream.call(method, params)
        except UpstreamError as exc:
            logger.error("upstream error on %s: %s", method, exc)
            return error_response(request_id, RESOURCE_UNAVAILABLE, f"upstream unavailable: {exc}")
        if reply.error is not None:
            err = reply.error
            return error_response(request_id, err.code, err.message, err.data)
        return result_response(request_id, reply.result)

    async def _send_raw_transaction(self, request: JsonRpcRequest) -> dict[str, Any]:
        params = request.params
        if not (isinstance(params, list) and len(params) == 1 and isinstance(params[0], str)):
            return error_response(
                request.id, INVALID_PARAMS, "eth_sendRawTransaction expects [<signed tx hex>]"
            )

        try:
            tx = decode_raw_transaction(params[0])
        except TransactionDecodeError as exc:
            logger.warning("blocked undecodable transaction: %s", exc)
            return error_response(request.id, TRANSACTION_REJECTED, f"transaction rejected: {exc}")

        if tx.chain_id is None and not self.settings.allow_legacy_unprotected:
            reason = "legacy transaction without EIP-155 chain id (replayable on any chain)"
        elif tx.chain_id is not None and tx.chain_id != self.chain_id:
            reason = f"chain id {tx.chain_id} does not match upstream chain id {self.chain_id}"
        else:
            reason = None
        if reason is not None:
            logger.warning("blocked transaction %s: %s", tx.hash, reason)
            return error_response(
                request.id, TRANSACTION_REJECTED, f"transaction rejected: {reason}"
            )

        call = decode_calldata(bytes.fromhex(tx.data[2:]))
        logger.info(
            "intercepted tx %s type=%d chain=%s from=%s to=%s value=%d nonce=%d call=%s%s",
            tx.hash,
            tx.tx_type,
            tx.chain_id,
            tx.sender,
            tx.to or "<contract creation>",
            tx.value,
            tx.nonce,
            call.kind,
            f" {call.signature}" if call.signature else "",
        )

        # Forward the exact bytes we decoded, never a re-encoding: what we
        # checked must be byte-for-byte what the node receives.
        response = await self._forward(request.id, "eth_sendRawTransaction", [tx.raw])
        returned_hash = response.get("result")
        if returned_hash is not None and returned_hash != tx.hash:
            logger.error("upstream returned hash %s, expected %s", returned_hash, tx.hash)
        return response


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    _configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        upstream_name = redact_url(settings.upstream_rpc_url)
        upstream = UpstreamClient(str(settings.upstream_rpc_url))
        try:
            # Fail closed: without the upstream's chain id we can't check that
            # transactions are for this chain, so we refuse to start at all.
            chain_id = await upstream.fetch_chain_id()
        except UpstreamError as exc:
            await upstream.aclose()
            raise UpstreamUnavailableError(
                f"cannot fetch chain id from upstream {upstream_name}: {exc}"
            ) from exc
        logger.info("upstream %s, chain id %d", upstream_name, chain_id)
        app.state.proxy = Proxy(upstream, chain_id, settings)
        try:
            yield
        finally:
            await upstream.aclose()

    # No /docs or /openapi.json: the only endpoint is POST /.
    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/")
    async def rpc(request: Request) -> Response:
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            # Also stops browsers from sending "simple" cross-origin POSTs
            # (text/plain, form data) to a proxy listening on localhost.
            return JSONResponse(
                error_response(None, INVALID_REQUEST, "Content-Type must be application/json"),
                status_code=415,
            )

        body = await _read_body(request)
        if body is None:
            return JSONResponse(
                error_response(None, INVALID_REQUEST, f"request exceeds {MAX_REQUEST_BYTES} bytes"),
                status_code=413,
            )

        try:
            obj = json.loads(body, parse_constant=_reject_constant)
        except ValueError:
            return JSONResponse(error_response(None, PARSE_ERROR, "parse error"))

        proxy: Proxy = request.app.state.proxy
        if not isinstance(obj, list):
            return JSONResponse(await proxy.handle(obj))
        if not obj:
            return JSONResponse(error_response(None, INVALID_REQUEST, "empty batch"))
        if len(obj) > MAX_BATCH_SIZE:
            return JSONResponse(
                error_response(None, INVALID_REQUEST, f"batch exceeds {MAX_BATCH_SIZE} requests")
            )
        # Sequential, in order: a batch may hold several transactions from one
        # sender, and nonce order only holds if we forward them in order.
        return JSONResponse([await proxy.handle(item) for item in obj])

    return app


async def _read_body(request: Request) -> bytes | None:
    """The request body, or None if it is larger than MAX_REQUEST_BYTES."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
        return None
    # Content-Length can be absent (chunked) or wrong, so count while reading too.
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_REQUEST_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _reject_constant(name: str) -> Any:
    # Python's json accepts NaN/Infinity, which aren't JSON.
    raise ValueError(f"invalid JSON constant {name}")


def _configure_logging(level: str) -> None:
    package_logger = logging.getLogger("mandate_firewall")
    package_logger.setLevel(level)
    if not package_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        package_logger.addHandler(handler)
