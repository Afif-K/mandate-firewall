"""The proxy's HTTP app: one POST endpoint that speaks JSON-RPC 2.0.

Request flow:
    HTTP body -> size/content-type checks -> JSON parse -> single or batch
    -> per request: validate -> classify method -> deny | forward | intercept

An intercepted transaction is decoded, checked, matched to its sender's
active mandate, simulated on the private fork, charged to the mandate,
audited, and only then forwarded. It is blocked if any step fails, if the
sender has no active mandate, or if it reverts in simulation.

Until M4, a transaction from a sender that has an active mandate is not yet
compared with the mandate's content: the gate checks that a confirmed,
unexpired mandate exists and has transactions left, nothing more.

Run it with `mandate-firewall serve` (see cli.py), which also sets up logging.
"""

import json
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from typing import Any, Protocol

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from mandate_firewall.audit import AuditLog, AuditLogError, AuditRecord
from mandate_firewall.config import Settings, redact_url
from mandate_firewall.decode.calldata import decode_calldata
from mandate_firewall.decode.transaction import TransactionDecodeError, decode_raw_transaction
from mandate_firewall.mandate.store import (
    MandateIntegrityError,
    MandateNotActiveError,
    MandateStatus,
    MandateStore,
    MandateStoreError,
    StoredMandate,
)
from mandate_firewall.models import (
    Decision,
    DecodedCall,
    DecodedTransaction,
    Effects,
    SimulationStatus,
)
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
from mandate_firewall.simulate.node import SimulatorNode, SimulatorStartupError, resolve_network
from mandate_firewall.simulate.simulator import SimulationError, Simulator

logger = logging.getLogger(__name__)

# A max-size raw transaction (128 KiB) is 256 KiB as hex; leave room for a batch.
MAX_REQUEST_BYTES = 1024 * 1024
MAX_BATCH_SIZE = 100
# How long a transaction waits for the mandate store's write lock (held
# briefly by `mandate new`/`revoke`) before it is blocked. The store is
# synchronous, so this is also how long the event loop can stall.
MANDATE_STORE_BUSY_TIMEOUT_SECONDS = 1.0


class UpstreamUnavailableError(RuntimeError):
    """Raised at startup when the upstream chain id can't be fetched."""


class TransactionSimulator(Protocol):
    async def simulate(self, tx: DecodedTransaction) -> Effects: ...


# Starts a simulator for the verified upstream and stops it on exit. Tests
# substitute a fake; there is deliberately no setting that skips simulation.
SimulatorFactory = Callable[
    [Settings, UpstreamClient, int], AbstractAsyncContextManager[TransactionSimulator]
]


@asynccontextmanager
async def start_simulator(
    settings: Settings, upstream: UpstreamClient, chain_id: int
) -> AsyncIterator[TransactionSimulator]:
    """The real simulator: a private anvil fork of the upstream."""
    network = resolve_network(settings.simulator_network, chain_id)
    node = SimulatorNode(settings.anvil_path, str(settings.upstream_rpc_url), chain_id, network)
    await node.start(upstream)  # SimulatorStartupError: refuse to start
    try:
        yield Simulator(
            node,
            upstream,
            timeout_seconds=settings.simulation_timeout_seconds,
            max_token_state_checks=settings.max_token_state_checks,
        )
    finally:
        await node.stop()


class Proxy:
    """Per-request JSON-RPC handling. Holds the upstream client, the chain id
    that was verified at startup, the audit log, the mandate store (opened
    counters-only) and the simulator."""

    def __init__(
        self,
        upstream: UpstreamClient,
        chain_id: int,
        settings: Settings,
        audit: AuditLog,
        mandates: MandateStore,
        simulator: TransactionSimulator,
    ) -> None:
        self.upstream = upstream
        self.chain_id = chain_id
        self.settings = settings
        self.audit = audit
        self.mandates = mandates
        self.simulator = simulator

    async def handle(self, obj: Any) -> dict[str, Any]:
        """Handle one request object. Always returns a response; never raises."""
        try:
            request = parse_request(obj)
        except JsonRpcProtocolError as exc:
            return error_response(exc.request_id, exc.code, exc.message)

        method_class = classify(request.method)
        if method_class is MethodClass.FORWARD:
            logger.debug("forwarding %s", request.method)
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
            return self._block(request.id, AuditRecord.undecodable(params[0], str(exc)))

        call = decode_calldata(bytes.fromhex(tx.data[2:]))
        reason = self._check(tx)
        if reason is not None:
            return self._block(
                request.id, AuditRecord.for_transaction(tx, call, Decision.BLOCK, reason)
            )

        mandate, reason = self._find_mandate(tx)
        if mandate is None:
            return self._block(
                request.id, AuditRecord.for_transaction(tx, call, Decision.BLOCK, reason)
            )
        mid = mandate.id

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
        logger.info("tx %s is covered by mandate %s", tx.hash, mid)
        try:
            effects = await self.simulator.simulate(tx)
        except SimulationError as exc:
            # Fail closed. The message is safe to return (see SimulationError).
            record = AuditRecord.for_transaction(
                tx, call, Decision.BLOCK, str(exc), simulation_error=str(exc), mandate_id=mid
            )
            return self._block(request.id, record)
        except Exception:
            # A bug, not a verdict on the transaction. Still fail closed.
            logger.exception("simulator crashed on tx %s", tx.hash)
            reason = "simulation failed: internal error"
            record = AuditRecord.for_transaction(
                tx, call, Decision.BLOCK, reason, simulation_error=reason, mandate_id=mid
            )
            return self._block(request.id, record)

        if effects.status is SimulationStatus.REVERTED:
            # At best it wastes gas. At worst it succeeds on chain because
            # state changed after we simulated, doing something we never saw.
            record = AuditRecord.for_transaction(
                tx,
                call,
                Decision.BLOCK,
                "transaction reverts in simulation",
                effects=effects,
                mandate_id=mid,
            )
            return self._block(request.id, record)

        # Charge the mandate. This is the check that counts: the lookup above
        # ran before simulation, and the mandate may have been revoked, run out
        # or expired since. record_transaction checks and increments in one
        # SQLite transaction, so two transactions racing for the last slot
        # can't both get it.
        try:
            charged = self.mandates.record_transaction(mid)
        except MandateNotActiveError as exc:
            record = AuditRecord.for_transaction(
                tx, call, Decision.BLOCK, str(exc), effects=effects, mandate_id=mid
            )
            return self._block(request.id, record)
        except MandateStoreError as exc:
            return self._block(
                request.id, self._store_failure(tx, call, exc, effects=effects, mandate_id=mid)
            )

        # The counter is charged before the audit write, so if the write
        # fails, a slot is spent on a transaction we then block. The other
        # order is worse: an "allow" record for a transaction we couldn't
        # charge. A lost slot fails closed (the agent can do less, not more).
        record = AuditRecord.for_transaction(
            tx,
            call,
            Decision.ALLOW,
            effects=effects,
            mandate_id=mid,
            mandate_transaction=charged.transactions,
        )
        try:
            self.audit.write(record)
        except AuditLogError as exc:
            # Fail closed: nothing reaches the chain without an audit record.
            logger.error("blocked transaction %s: %s", tx.hash, exc)
            return error_response(
                request.id, TRANSACTION_REJECTED, "transaction rejected: audit log unavailable"
            )

        # Forward the exact bytes we decoded, never a re-encoding: what we
        # checked must be byte-for-byte what the node receives.
        response = await self._forward(request.id, "eth_sendRawTransaction", [tx.raw])
        if "error" in response:
            logger.warning("upstream rejected tx %s: %s", tx.hash, response["error"]["message"])
        elif response.get("result") != tx.hash:
            logger.error("upstream returned hash %s, expected %s", response.get("result"), tx.hash)
        return response

    def _check(self, tx: DecodedTransaction) -> str | None:
        """The reason to block this transaction, or None to allow it."""
        if tx.chain_id is None and not self.settings.allow_legacy_unprotected:
            return "legacy transaction without EIP-155 chain id (replayable on any chain)"
        if tx.chain_id is not None and tx.chain_id != self.chain_id:
            return f"chain id {tx.chain_id} does not match upstream chain id {self.chain_id}"
        return None

    def _find_mandate(self, tx: DecodedTransaction) -> tuple[StoredMandate | None, str]:
        """The sender's active mandate, or None and the reason to block.

        The key is (chain, sender). The sender is recovered from the
        signature, so the agent can't claim to be someone else, and nothing
        the agent sends can pick which mandate applies. The chain is the
        upstream's: _check() has already made sure the transaction is for it.
        """
        try:
            active = self.mandates.active_for(self.chain_id, tx.sender)
            if active is not None:
                return active, ""
            latest = self.mandates.latest_for(self.chain_id, tx.sender)
        except MandateStoreError as exc:
            return None, self._store_failure_reason(tx, exc)
        if latest is None:
            return None, f"no mandate for sender {tx.sender} on chain {self.chain_id}"
        if latest.status is MandateStatus.EXHAUSTED:
            used = f"{latest.transactions} of {latest.mandate.limits.max_transactions}"
            return None, f"mandate {latest.id} is exhausted ({used} transactions used)"
        return None, f"mandate {latest.id} is {latest.status}"

    def _store_failure_reason(self, tx: DecodedTransaction, exc: MandateStoreError) -> str:
        # The details (which row, which check) go to the operator's log. The
        # agent and the audit record get a fixed reason.
        if isinstance(exc, MandateIntegrityError):
            logger.error("mandate store integrity failure on tx %s: %s", tx.hash, exc)
            return "mandate store integrity failure"
        logger.error("mandate store error on tx %s: %s", tx.hash, exc)
        return "mandate store unavailable"

    def _store_failure(
        self,
        tx: DecodedTransaction,
        call: DecodedCall,
        exc: MandateStoreError,
        **fields: Any,
    ) -> AuditRecord:
        reason = self._store_failure_reason(tx, exc)
        return AuditRecord.for_transaction(tx, call, Decision.BLOCK, reason, **fields)

    def _block(self, request_id: Any, record: AuditRecord) -> dict[str, Any]:
        logger.warning("blocked transaction %s: %s", record.hash or "<undecodable>", record.reason)
        try:
            self.audit.write(record)
        except AuditLogError as exc:
            # Already blocked, so nothing to fail closed on; make sure it's seen.
            logger.error("audit record lost for blocked transaction: %s", exc)
        return error_response(
            request_id, TRANSACTION_REJECTED, f"transaction rejected: {record.reason}"
        )


def create_app(
    settings: Settings | None = None, simulator_factory: SimulatorFactory | None = None
) -> FastAPI:
    settings = settings or Settings()
    start = simulator_factory or start_simulator

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        upstream_name = redact_url(settings.upstream_rpc_url)
        async with AsyncExitStack() as stack:
            # Opened first, so an unwritable audit log stops startup like an
            # unreachable upstream does: we never run without either.
            audit = AuditLog(settings.audit_log_path)
            stack.callback(audit.close)
            # Then the mandate store: no store, no firewall. Counters-only, so
            # the proxy can't create, change or revoke mandates. Every row is
            # checked now, so a tampered store stops startup loudly instead of
            # only blocking the one sender whose row was edited.
            mandates = MandateStore(
                settings.mandate_db_path,
                counters_only=True,
                busy_timeout=MANDATE_STORE_BUSY_TIMEOUT_SECONDS,
            )
            stack.callback(mandates.close)
            stored = mandates.all()
            active = sum(1 for m in stored if m.status is MandateStatus.ACTIVE)
            upstream = UpstreamClient(str(settings.upstream_rpc_url))
            stack.push_async_callback(upstream.aclose)
            try:
                # Fail closed: without the upstream's chain id we can't check that
                # transactions are for this chain, so we refuse to start at all.
                chain_id = await upstream.fetch_chain_id()
            except UpstreamError as exc:
                # "from None": the server prints the whole exception chain, and the
                # underlying httpx error text can contain the URL and its API key.
                raise UpstreamUnavailableError(
                    f"cannot fetch chain id from upstream {upstream_name}: {exc}"
                ) from None
            logger.info("upstream %s, chain id %d", upstream_name, chain_id)
            logger.info("audit log %s", settings.audit_log_path)
            logger.info(
                "mandate store %s: %d mandates, %d active",
                settings.mandate_db_path,
                len(stored),
                active,
            )
            try:
                # Fail closed: no simulator, no firewall.
                simulator = await stack.enter_async_context(start(settings, upstream, chain_id))
            except SimulatorStartupError as exc:
                raise SimulatorStartupError(str(exc)) from None  # same reason as above
            app.state.proxy = Proxy(upstream, chain_id, settings, audit, mandates, simulator)
            yield

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
