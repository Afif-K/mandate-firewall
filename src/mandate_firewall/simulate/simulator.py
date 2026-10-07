"""Run a signed transaction on the private fork and return its Effects.

One simulation at a time, on one long-lived anvil (approach B in
docs/m2-plan.md):

1. Fetch the upstream head N (number and hash).
2. If the fork is dirty or pinned elsewhere, fork at N (anvil_reset, then
   verify) and take a snapshot. Otherwise verify it is still a clean fork at
   N: the last simulation reverted to the snapshot.
3. Send the exact raw transaction and mine block N+1 with evm_mine.
4. Read the receipt and the callTracer trace. Decode logs and frames. Read
   ETH balances and the token state checks at N and N+1. Anvil keeps both
   states, so nothing has to be read before sending.
5. Drop the txpool and revert to the snapshot.

Fail closed: every failure raises a SimulationError, whose message is safe
to log and to return to the agent. Any failure inside the lock marks the fork
dirty, so the next simulation starts from a fresh anvil_reset. A dead node is
restarted inline by the next simulation, inside the same time limit.

A transaction that *reverts* is not an error. Its Effects have status
REVERTED, and the proxy decides what to do (it blocks).
"""

import asyncio
import logging
import re
import time
from collections.abc import Awaitable
from typing import Any

from eth_utils import to_checksum_address
from pydantic import ValidationError

from mandate_firewall.models import (
    DecodedTransaction,
    Effects,
    NativeBalanceChange,
    SimulationStatus,
    TokenStateCheck,
)
from mandate_firewall.proxy.upstream import UpstreamClient
from mandate_firewall.simulate.claims import StateCheckPlan, plan_state_checks
from mandate_firewall.simulate.logs import LogDecodeError, decode_logs
from mandate_firewall.simulate.node import (
    ForkPoint,
    SimulatorError,
    SimulatorNode,
    SimulatorStartupError,
    fetch_fork_point,
)
from mandate_firewall.simulate.trace import ParsedTrace, TraceParseError, parse_call_trace

logger = logging.getLogger(__name__)

# Callers allowed inside simulate() at once (running plus waiting for the
# lock). One more is refused at once, rather than queueing to time out.
DEFAULT_MAX_PENDING = 16
# Concurrent reads against the node within one simulation.
READ_CONCURRENCY = 8

BALANCE_OF = "0x70a08231"  # balanceOf(address)
ALLOWANCE = "0xdd62ed3e"  # allowance(address,address)

_WORD = re.compile(r"0x[0-9a-fA-F]{64}")
_DATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")
# Anvil's rejection messages ("nonce too low", "insufficient funds for gas *
# price + value") are passed on. Anything else is replaced: anvil can quote
# the upstream URL.
_SAFE_MESSAGE = re.compile(r"[A-Za-z0-9 ,.:;_()'*+=-]{1,200}")


class SimulationError(Exception):
    """The transaction couldn't be simulated. The proxy blocks it. The
    message is safe to log and to return to the agent."""


class SimulationTimeoutError(SimulationError):
    pass


class SimulatorBusyError(SimulationError):
    pass


class SimulatorUnavailableError(SimulationError):
    pass


class TransactionRejectedError(SimulationError):
    """The fork refused or never mined the transaction (bad nonce, too
    little ETH, fee below base fee). The real chain would refuse it too."""


class TooManyStateChecksError(SimulationError):
    pass


class Simulator:
    def __init__(
        self,
        node: SimulatorNode,
        upstream: UpstreamClient,
        *,
        timeout_seconds: float,
        max_token_state_checks: int,
        max_pending: int = DEFAULT_MAX_PENDING,
    ) -> None:
        self._node = node
        self._upstream = upstream
        self.timeout_seconds = timeout_seconds
        self._max_checks = max_token_state_checks
        self._max_pending = max_pending
        self._lock = asyncio.Lock()
        self._pending = 0
        # The fork's state between simulations: pinned at _point, with a
        # snapshot of the clean state. Dirty means "unknown: reset first".
        self._point: ForkPoint | None = None
        self._snapshot: str | None = None
        self._dirty = True

    @property
    def dirty(self) -> bool:
        """True when the next simulation must reset the fork first."""
        return self._dirty

    async def simulate(self, tx: DecodedTransaction) -> Effects:
        if self._pending >= self._max_pending:
            raise SimulatorBusyError("too many transactions are waiting for the simulator")
        self._pending += 1
        started = time.monotonic()
        try:
            # The limit covers the wait for the lock too.
            effects = await asyncio.wait_for(self._simulate_locked(tx), self.timeout_seconds)
        except TimeoutError as exc:
            raise SimulationTimeoutError(
                f"simulation did not finish within {self.timeout_seconds:g}s"
            ) from exc
        finally:
            self._pending -= 1
        logger.info(
            "simulated tx %s on block %d: %s in %.0f ms",
            tx.hash,
            effects.fork_block_number,
            effects.status,
            (time.monotonic() - started) * 1000,
        )
        return effects

    async def _simulate_locked(self, tx: DecodedTransaction) -> Effects:
        async with self._lock:
            try:
                return await self._run(tx)
            except BaseException:
                # Including cancellation by the timeout, mid-request.
                self._dirty = True
                raise

    async def _run(self, tx: DecodedTransaction) -> Effects:
        try:
            point = await fetch_fork_point(self._upstream)
            await self._prepare(point)
            effects = await self._execute(tx, point)
            await self._clean_up()
            return effects
        except SimulationError:
            raise
        except (SimulatorError, LogDecodeError, TraceParseError) as exc:
            # These messages never contain the upstream URL or node text.
            raise SimulationError(f"simulation failed: {exc}") from exc
        except ValidationError as exc:
            raise SimulationError("simulation produced effects that fail validation") from exc

    async def _prepare(self, point: ForkPoint) -> None:
        if not self._node.is_running():
            await self._restart()
        if self._dirty or self._point != point or self._snapshot is None:
            try:
                await self._node.fork(point)
            except SimulatorError:
                # A failed anvil_reset leaves the node in an unknown state.
                await self._restart()
                await self._node.fork(point)
            self._point, self._snapshot = point, await self._node.call("evm_snapshot", [])
            self._dirty = False
        else:
            await self._node.verify(point)

    async def _restart(self) -> None:
        logger.warning("restarting the simulation node")
        try:
            await self._node.restart(self._upstream)
        except SimulatorStartupError as exc:
            raise SimulatorUnavailableError(
                "the simulation node is down and could not be restarted"
            ) from exc
        self._point = self._snapshot = None

    async def _clean_up(self) -> None:
        # evm_revert leaves the txpool alone (see the spike findings).
        await self._node.call("anvil_dropAllTransactions", [])
        if await self._node.call("evm_revert", [self._snapshot]) is not True:
            raise SimulationError("simulation failed: could not revert the fork")
        # A snapshot is used up by reverting to it.
        self._snapshot = await self._node.call("evm_snapshot", [])

    async def _execute(self, tx: DecodedTransaction, point: ForkPoint) -> Effects:
        node = self._node
        reply = await node.try_call("eth_sendRawTransaction", [tx.raw])
        if reply.error is not None:
            message = reply.error.message
            reason = message if _SAFE_MESSAGE.fullmatch(message) else f"error {reply.error.code}"
            raise TransactionRejectedError(
                f"the simulated chain rejected the transaction: {reason}"
            )
        if not isinstance(reply.result, str) or reply.result.lower() != tx.hash.lower():
            raise SimulationError("simulation failed: the node reported a different tx hash")

        await node.call("evm_mine", [])
        mined = point.number + 1
        receipt = await node.call("eth_getTransactionReceipt", [tx.hash])
        if receipt is None:
            # Accepted but not mined: queued behind a missing nonce.
            raise TransactionRejectedError(
                "the simulated chain did not mine the transaction (its nonce may be too high)"
            )
        if not isinstance(receipt, dict) or _quantity(receipt.get("blockNumber")) != mined:
            raise SimulationError("simulation failed: unexpected receipt")
        if str(receipt.get("from")).lower() != tx.sender.lower():
            raise SimulationError("simulation failed: receipt sender does not match")

        raw_trace = await node.call("debug_traceTransaction", [tx.hash, {"tracer": "callTracer"}])
        trace = parse_call_trace(raw_trace)
        logs = decode_logs(receipt.get("logs"), tx.hash)

        status = {"0x1": SimulationStatus.SUCCESS, "0x0": SimulationStatus.REVERTED}.get(
            receipt.get("status")  # type: ignore[arg-type]
        )
        if status is None or (status is SimulationStatus.REVERTED) != trace.calls[0].reverted:
            raise SimulationError("simulation failed: receipt and trace disagree on the outcome")

        # Fail before reading anything, not by running into the timeout.
        plans = plan_state_checks(logs)
        if len(plans) > self._max_checks:
            raise TooManyStateChecksError(
                f"the transaction needs {len(plans)} token state checks; "
                f"the limit is {self._max_checks}"
            )

        gas_used = _quantity(receipt.get("gasUsed"))
        price = _quantity(receipt.get("effectiveGasPrice"))
        block = await node.call("eth_getBlockByNumber", [hex(mined), False])
        if not isinstance(block, dict):
            raise SimulationError("simulation failed: mined block not found")
        priority_fees = gas_used * (price - _quantity(block.get("baseFeePerGas")))
        if priority_fees < 0:
            raise SimulationError("simulation failed: gas price below the base fee")

        balance_changes = await self._native_balance_changes(
            tx, trace, point, _address(block.get("miner")), priority_fees
        )
        state_checks = await self._token_state_checks(plans, point, set(trace.created))

        return Effects(
            tx_hash=tx.hash,
            sender=tx.sender,
            chain_id=self._node.chain_id,
            fork_block_number=point.number,
            fork_block_hash=point.hash,
            status=status,
            revert_data=_revert_data(raw_trace) if status is SimulationStatus.REVERTED else None,
            gas_used=gas_used,
            effective_gas_price=price,
            gas_cost=gas_used * price,
            native_balance_changes=balance_changes,
            token_transfers=logs.transfers,
            token_approvals=logs.approvals,
            operator_approvals=logs.operator_approvals,
            calls=trace.calls,
            contracts_created=trace.created,
            unrecognized_logs=logs.unrecognized,
            token_state_checks=state_checks,
        )

    async def _native_balance_changes(
        self,
        tx: DecodedTransaction,
        trace: ParsedTrace,
        point: ForkPoint,
        coinbase: str,
        priority_fees: int,
    ) -> tuple[NativeBalanceChange, ...]:
        """ETH moves only through frames in the trace and through fees, so
        the trace's addresses plus the coinbase cover every change."""
        addresses = list(dict.fromkeys([tx.sender, *trace.touched, coinbase]))
        reads: list[Awaitable[int]] = []
        for address in addresses:
            reads.append(self._balance(address, point.number))
            reads.append(self._balance(address, point.number + 1))
        values = await _gather_limited(reads)

        changes = []
        for i, address in enumerate(addresses):
            delta = values[2 * i + 1] - values[2 * i]
            if address == coinbase:
                # The priority fee is the block producer's pay, not an effect
                # of the transaction. Anything beyond it (ETH sent to the
                # coinbase address) is.
                delta -= priority_fees
            if delta != 0:
                changes.append(NativeBalanceChange(address=address, delta=delta))
        return tuple(changes)

    async def _token_state_checks(
        self, plans: tuple[StateCheckPlan, ...], point: ForkPoint, created: set[str]
    ) -> tuple[TokenStateCheck, ...]:
        reads: list[Awaitable[int]] = []
        for plan in plans:
            data = _encode_call(plan)
            # A token created by this transaction has no code at block N.
            reads.append(self._token_read(plan, data, point.number, plan.token in created))
            reads.append(self._token_read(plan, data, point.number + 1, False))
        values = await _gather_limited(reads)

        checks = []
        for i, plan in enumerate(plans):
            before, after = values[2 * i], values[2 * i + 1]
            measured = after if plan.kind == "allowance" else after - before
            checks.append(
                TokenStateCheck(
                    token=plan.token,
                    kind=plan.kind,
                    owner=plan.owner,
                    spender=plan.spender,
                    before=before,
                    after=after,
                    claimed=plan.claimed,
                    consistent=measured == plan.claimed,
                )
            )
        return tuple(checks)

    async def _balance(self, address: str, block: int) -> int:
        return _quantity(await self._node.call("eth_getBalance", [address, hex(block)]))

    async def _token_read(
        self, plan: StateCheckPlan, data: str, block: int, may_be_absent: bool
    ) -> int:
        try:
            result = await self._node.call(
                "eth_call", [{"to": plan.token, "data": data}, hex(block)]
            )
        except SimulatorError as exc:
            raise SimulationError(
                f"simulation failed: {plan.kind} read on token {plan.token} reverted"
            ) from exc
        if result == "0x" and may_be_absent:
            return 0
        if not isinstance(result, str) or not _WORD.fullmatch(result):
            raise SimulationError(
                f"simulation failed: token {plan.token} returned a malformed {plan.kind}"
            )
        return int(result, 16)


async def _gather_limited(reads: list[Awaitable[int]]) -> list[int]:
    semaphore = asyncio.Semaphore(READ_CONCURRENCY)

    async def limited(read: Awaitable[int]) -> int:
        async with semaphore:
            return await read

    return list(await asyncio.gather(*(limited(read) for read in reads)))


def _encode_call(plan: StateCheckPlan) -> str:
    def word(address: str) -> str:
        return address[2:].lower().rjust(64, "0")

    if plan.kind == "balance":
        return BALANCE_OF + word(plan.owner)
    if plan.spender is None:
        raise SimulationError("simulation failed: allowance check without a spender")
    return ALLOWANCE + word(plan.owner) + word(plan.spender)


def _revert_data(raw_trace: Any) -> str | None:
    """The top frame's return data: the raw revert payload, kept as hex and
    never decoded (anvil's own decoding is the attacker-chosen revertReason)."""
    output = raw_trace.get("output") if isinstance(raw_trace, dict) else None
    if output is None:
        return None
    if not isinstance(output, str) or not _DATA.fullmatch(output):
        raise SimulationError("simulation failed: malformed revert data")
    return output


def _quantity(value: Any) -> int:
    if not isinstance(value, str) or not _QUANTITY.fullmatch(value):
        raise SimulationError("simulation failed: expected a hex quantity from the node")
    return int(value, 16)


def _address(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise SimulationError("simulation failed: expected an address from the node")
    return to_checksum_address(value)
