"""The proxy's HTTP app: one POST endpoint that speaks JSON-RPC 2.0.

Request flow:
    HTTP body -> size/content-type checks -> JSON parse -> single or batch
    -> per request: validate -> classify method -> deny | forward | intercept

An intercepted transaction goes through these steps, in this order:

    decode, check the chain id
    -> re-send? (these exact bytes were already charged: forward them again)
    -> find the sender's active mandate
    -> simulate on the private fork (an error or a revert blocks)
    -> verify the effects against the mandate (verify/matcher.py)
    -> not allowed: explain, audit, refuse with the violation codes
    -> charge the mandate (the store re-checks every budget atomically)
    -> explain, audit, and only then forward the exact bytes

It is blocked if any step fails. Escalate (an anomaly) is a block with a
louder explanation: nothing is held for a human to release later; the human
acts on the mandate instead (docs/m4-plan.md §3).

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
from mandate_firewall.mandate.registry import Registry, RegistryError, load_registry
from mandate_firewall.mandate.store import (
    ChargeRefusedError,
    MandateIntegrityError,
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
from mandate_firewall.verify.explain import agent_reason, explain
from mandate_firewall.verify.matcher import match
from mandate_firewall.verify.models import Verdict

logger = logging.getLogger(__name__)

# A max-size raw transaction (128 KiB) is 256 KiB as hex; leave room for a batch.
MAX_REQUEST_BYTES = 1024 * 1024
MAX_BATCH_SIZE = 100
# How long a transaction waits for the mandate store's write lock (held
# briefly by `mandate new`/`revoke`) before it is blocked. The store is
# synchronous, so this is also how long the event loop can stall.
MANDATE_STORE_BUSY_TIMEOUT_SECONDS = 1.0
# The verifier or the explanation raised: a bug, not a verdict. Fail closed.
VERIFICATION_FAILED = "verification failed: internal error"
# A re-send can be forwarded only while its mandate still stands. Exhausted
# counts: the transaction that used the mandate up is the one most likely to
# be retried, and it was already charged. Revoked and expired mean "stop".
RESEND_STATUSES = frozenset({MandateStatus.ACTIVE, MandateStatus.EXHAUSTED})


class RegistryUnavailableError(RuntimeError):
    """Raised at startup when there is no valid registry for the upstream's chain."""


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
    counters-only), the simulator and the registry for that chain."""

    def __init__(
        self,
        upstream: UpstreamClient,
        chain_id: int,
        settings: Settings,
        audit: AuditLog,
        mandates: MandateStore,
        simulator: TransactionSimulator,
        registry: Registry,
    ) -> None:
        self.upstream = upstream
        self.chain_id = chain_id
        self.settings = settings
        self.audit = audit
        self.mandates = mandates
        self.simulator = simulator
        self.registry = registry  # names in explanations only; never decides

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

        previous, reason = self._charged_before(tx)
        if reason is not None:
            record = AuditRecord.for_transaction(
                tx,
                call,
                Decision.BLOCK,
                reason,
                mandate_id=previous.id if previous else None,
            )
            return self._block(request.id, record)
        if previous is not None:
            # These exact bytes were verified and charged before, and they
            # can be mined only once, so there is nothing new to check: an
            # agent retrying after a timeout must not pay twice.
            logger.info("re-send of tx %s, charged to mandate %s", tx.hash, previous.id)
            record = AuditRecord.for_transaction(
                tx,
                call,
                Decision.ALLOW,
                "re-send of a transaction already charged",
                resend=True,
                mandate_id=previous.id,
            )
            return await self._audit_and_forward(request.id, tx, record)

        mandate, reason = self._find_mandate(tx)
        if reason is not None or mandate is None:
            # Name the mandate in the record whenever one was identified
            # (expired, revoked, exhausted), not only when it was charged.
            record = AuditRecord.for_transaction(
                tx,
                call,
                Decision.BLOCK,
                reason or "no active mandate",
                mandate_id=mandate.id if mandate else None,
            )
            return self._block(request.id, record)
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

        # Verify: the effects against the mandate, with the spending read
        # before simulation. Pure, so it only fails on a bug.
        try:
            verdict = match(mandate.mandate, mandate.spent, tx, effects)
        except Exception:
            logger.exception("verifier crashed on tx %s", tx.hash)
            record = AuditRecord.for_transaction(
                tx, call, Decision.BLOCK, VERIFICATION_FAILED, effects=effects, mandate_id=mid
            )
            return self._block(request.id, record)
        if verdict.decision is not Decision.ALLOW:
            return self._refuse(request.id, tx, call, effects, mandate, verdict)

        # Charge the mandate. This is the check that counts: the lookup and
        # the verdict used what was read before simulation, and since then
        # the mandate may have been revoked, run out or expired, or another
        # transaction may have spent the budget. record_transaction checks
        # and charges in one SQLite transaction, so two transactions racing
        # for the last of a budget can't both get it.
        charges = {c.intent_index: c.amount for c in verdict.charges}
        try:
            charged = self.mandates.record_transaction(
                mid,
                charges=charges,
                approval_limits={a.intent_index: a.amount for a in verdict.approval_limits},
                tx_hash=tx.hash,
            )
        except ChargeRefusedError as exc:
            # Not active, over budget or charged already. The verdict stays on
            # record (it said allow, from older spending); the decision is the
            # store's. Its message names no amounts, so the agent may see it.
            record = AuditRecord.for_transaction(
                tx, call, Decision.BLOCK, str(exc), effects=effects, verdict=verdict, mandate_id=mid
            )
            return self._block(request.id, record)
        except MandateStoreError as exc:
            return self._block(
                request.id,
                self._store_failure(
                    tx, call, exc, effects=effects, verdict=verdict, mandate_id=mid
                ),
            )

        # Explained after the charge, with what was left just before it as the
        # store saw it, so the text is right even if another transaction
        # charged in between.
        spent_before = tuple(
            spent - charges.get(index, 0) for index, spent in enumerate(charged.spent)
        )
        try:
            explanation = explain(
                verdict,
                mandate.mandate,
                spent_before,
                self.registry,
                tx_hash=tx.hash,
                mandate_id=mid,
            )
        except Exception:
            # Already charged, so a slot is lost: that fails closed.
            logger.exception("explanation failed for tx %s", tx.hash)
            record = AuditRecord.for_transaction(
                tx, call, Decision.BLOCK, VERIFICATION_FAILED, effects=effects, verdict=verdict,
                mandate_id=mid,
            )  # fmt: skip
            return self._block(request.id, record)

        # The charge comes before the audit write, so if the write fails, a
        # slot and budget are spent on a transaction we then block. The other
        # order is worse: an "allow" record for a transaction we couldn't
        # charge. A lost charge fails closed (the agent can do less, not more).
        logger.info("allowed tx %s under mandate %s", tx.hash, mid)
        record = AuditRecord.for_transaction(
            tx,
            call,
            Decision.ALLOW,
            effects=effects,
            verdict=verdict,
            explanation=explanation,
            mandate_id=mid,
            mandate_transaction=charged.transactions,
        )
        return await self._audit_and_forward(request.id, tx, record)

    async def _audit_and_forward(
        self, request_id: Any, tx: DecodedTransaction, record: AuditRecord
    ) -> dict[str, Any]:
        try:
            self.audit.write(record)
        except AuditLogError as exc:
            # Fail closed: nothing reaches the chain without an audit record.
            logger.error("blocked transaction %s: %s", tx.hash, exc)
            return error_response(
                request_id, TRANSACTION_REJECTED, "transaction rejected: audit log unavailable"
            )

        # Forward the exact bytes we decoded, never a re-encoding: what we
        # checked must be byte-for-byte what the node receives.
        response = await self._forward(request_id, "eth_sendRawTransaction", [tx.raw])
        if "error" in response:
            logger.warning("upstream rejected tx %s: %s", tx.hash, response["error"]["message"])
        elif response.get("result") != tx.hash:
            logger.error("upstream returned hash %s, expected %s", response.get("result"), tx.hash)
        return response

    def _refuse(
        self,
        request_id: Any,
        tx: DecodedTransaction,
        call: DecodedCall,
        effects: Effects,
        mandate: StoredMandate,
        verdict: Verdict,
    ) -> dict[str, Any]:
        """Block or escalate. The operator gets the full explanation (log and
        audit record). The agent gets fixed phrases and the codes, never a
        mandate value (docs/m4-plan.md, Decision 6)."""
        try:
            explanation = explain(
                verdict,
                mandate.mandate,
                mandate.spent,
                self.registry,
                tx_hash=tx.hash,
                mandate_id=mandate.id,
            )
            reason = agent_reason(verdict)
        except Exception:
            logger.exception("explanation failed for tx %s", tx.hash)
            record = AuditRecord.for_transaction(
                tx, call, Decision.BLOCK, VERIFICATION_FAILED, effects=effects, verdict=verdict,
                mandate_id=mandate.id,
            )  # fmt: skip
            return self._block(request_id, record)
        record = AuditRecord.for_transaction(
            tx,
            call,
            verdict.decision,
            reason,
            effects=effects,
            verdict=verdict,
            explanation=explanation,
            mandate_id=mandate.id,
        )
        data = {
            "decision": str(verdict.decision),
            "violations": list(dict.fromkeys(str(v.code) for v in verdict.violations)),
            "anomalies": list(dict.fromkeys(str(a.code) for a in verdict.anomalies)),
        }
        return self._block(request_id, record, data)

    def _charged_before(self, tx: DecodedTransaction) -> tuple[StoredMandate | None, str | None]:
        """Whether these exact bytes were charged before. (None, None): no,
        verify them. (mandate, None): yes, forward them as a re-send.
        (mandate or None, reason): block."""
        try:
            mid = self.mandates.charged_to(tx.hash)
            if mid is None:
                return None, None
            previous = self.mandates.get(mid)
        except MandateStoreError as exc:
            return None, self._store_failure_reason(tx, exc)
        if (previous.mandate.chain_id, previous.mandate.principal) != (self.chain_id, tx.sender):
            # The hash commits to the sender and chain, so the store is wrong.
            logger.error("tx %s is charged to mandate %s of another account", tx.hash, mid)
            return None, "mandate store integrity failure"
        if previous.status not in RESEND_STATUSES:
            return previous, (
                f"re-send of a transaction charged to mandate {mid}, which is {previous.status}"
            )
        return previous, None

    def _check(self, tx: DecodedTransaction) -> str | None:
        """The reason to block this transaction, or None to allow it."""
        if tx.chain_id is None and not self.settings.allow_legacy_unprotected:
            return "legacy transaction without EIP-155 chain id (replayable on any chain)"
        if tx.chain_id is not None and tx.chain_id != self.chain_id:
            return f"chain id {tx.chain_id} does not match upstream chain id {self.chain_id}"
        return None

    def _find_mandate(self, tx: DecodedTransaction) -> tuple[StoredMandate | None, str | None]:
        """(mandate, reason to block). An active mandate comes with no reason.
        Otherwise the reason is set, and the mandate is the sender's latest
        one if there is any (to name it in the audit record), else None.
        After a store or integrity error it is None: nothing read is trusted.

        The key is (chain, sender). The sender is recovered from the
        signature, so the agent can't claim to be someone else, and nothing
        the agent sends can pick which mandate applies. The chain is the
        upstream's: _check() has already made sure the transaction is for it.
        """
        try:
            active = self.mandates.active_for(self.chain_id, tx.sender)
            if active is not None:
                return active, None
            latest = self.mandates.latest_for(self.chain_id, tx.sender)
        except MandateStoreError as exc:
            return None, self._store_failure_reason(tx, exc)
        if latest is None:
            return None, f"no mandate for sender {tx.sender} on chain {self.chain_id}"
        if latest.status is MandateStatus.EXHAUSTED:
            used = f"{latest.transactions} of {latest.mandate.limits.max_transactions}"
            return latest, f"mandate {latest.id} is exhausted ({used} transactions used)"
        return latest, f"mandate {latest.id} is {latest.status}"

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

    def _block(
        self, request_id: Any, record: AuditRecord, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if record.explanation is not None:
            # Starts with BLOCKED or ESCALATED and the transaction hash.
            logger.warning("%s", record.explanation)
        else:
            logger.warning(
                "blocked transaction %s: %s", record.hash or "<undecodable>", record.reason
            )
        try:
            self.audit.write(record)
        except AuditLogError as exc:
            # Already blocked, so nothing to fail closed on; make sure it's seen.
            logger.error("audit record lost for blocked transaction: %s", exc)
        return error_response(
            request_id, TRANSACTION_REJECTED, f"transaction rejected: {record.reason}", data
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
            try:
                # Fail closed: an invalid registry is a typo that would put a
                # wrong name in front of the operator; without one, capture
                # can't create mandates for this chain either.
                registry = load_registry(chain_id, settings.registry_path)
            except RegistryError as exc:
                raise RegistryUnavailableError(f"cannot load the registry: {exc}") from None
            logger.info(
                "registry: %s (%s)",
                registry.chain_name,
                settings.registry_path or "shipped",
            )
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
            app.state.proxy = Proxy(
                upstream, chain_id, settings, audit, mandates, simulator, registry
            )
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
