"""The firewall's private simulation node: an anvil subprocess that it owns.

The agent can never reach this node. The proxy forwards only to the upstream;
this module is the only code that knows the node's URL, and it calls
anvil_*/evm_*/debug_* directly rather than through methods.classify(), which
keeps denying them to agents.

How the node is started, and why. Each choice was checked against anvil 1.8.3
in the M2 commit 1 spike (see docs/m2-plan.md):

- No --fork-url. Upstream URLs often embed an API key, and every local user
  can read command lines with `ps`. We start a plain dev node and switch it
  into fork mode with anvil_reset over RPC instead.
- --quiet, with output sent to /dev/null. Without --quiet, anvil logs each
  request in full, including the anvil_reset that carries the URL.
- --no-mining. With automine, anvil returns a transaction's hash before the
  block that contains it exists, so the receipt isn't there yet. We mine with
  evm_mine instead, which returns once the block is mined.
- --accounts 0. By default anvil sets its ten dev accounts to 10000 ETH, even
  on a fork, overwriting their real balances. Those addresses are public and
  widely used, and a simulation must see their real state. It also leaves
  the node with no keys to sign with.
- HOME set to a private temp dir. anvil caches forked state on disk under
  ~/.foundry/cache/rpc/<chain>/<block>, keyed only by chain and block number
  and shared with every other Foundry tool. A stale or tampered file there
  would make simulations lie. A private cache is deleted with the node.
- Nothing else from our environment, so the node gets none of our secrets.
"""

import asyncio
import logging
import re
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any

from eth_account import Account
from pydantic import BaseModel, ConfigDict, Field

from mandate_firewall.proxy.upstream import UpstreamClient, UpstreamError, UpstreamResult

logger = logging.getLogger(__name__)

STARTUP_TIMEOUT_SECONDS = 15.0
STOP_TIMEOUT_SECONDS = 10.0
SIMPLE_TRANSFER_GAS = 21_000

_HASH = re.compile(r"0x[0-9a-f]{64}")


class SimulatorError(Exception):
    """The simulation node failed or returned something we can't trust.

    Messages never include the upstream URL or text from anvil's errors:
    anvil quotes the URL it failed to reach."""


class SimulatorStartupError(SimulatorError):
    """The node could not be started and verified. The firewall must not start."""


class ForkPoint(BaseModel):
    """The upstream block a fork is pinned to. The hash makes it exact: after a
    reorg, the same number can name a different block."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=0)
    hash: str = Field(pattern=_HASH.pattern)  # 0x-prefixed, lowercase


async def fetch_fork_point(upstream: UpstreamClient) -> ForkPoint:
    """The upstream's current head, to fork from."""
    try:
        reply = await upstream.call("eth_getBlockByNumber", ["latest", False])
    except UpstreamError as exc:
        raise SimulatorError(f"could not fetch the upstream head: {exc}") from exc
    if reply.error is not None:
        raise SimulatorError(f"eth_getBlockByNumber returned error {reply.error.code}")
    block = reply.result
    if not isinstance(block, dict):
        raise SimulatorError("upstream returned no latest block")
    return ForkPoint(number=_quantity(block.get("number")), hash=_block_hash(block))


class SimulatorNode:
    """One anvil process, forked from the upstream and verified against it.

    start() refuses to finish unless the fork has the upstream's chain id and
    the same block hash at the fork point, and unless callTracer traces work.
    fork() moves it to a new upstream block with the same checks.
    """

    def __init__(self, anvil_path: str, upstream_url: str, chain_id: int) -> None:
        self._anvil_path = anvil_path
        self._upstream_url = upstream_url
        self._chain_id = chain_id
        self._process: subprocess.Popen[bytes] | None = None
        self._client: UpstreamClient | None = None
        self._home: str | None = None
        self._url: str | None = None

    @property
    def chain_id(self) -> int:
        """The upstream chain id, which every fork is verified to have."""
        return self._chain_id

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process is not None else None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    async def start(self, upstream: UpstreamClient) -> None:
        """Spawn anvil, fork it at the upstream's head and verify it. On any
        failure the process is stopped and SimulatorStartupError is raised."""
        binary = shutil.which(self._anvil_path)
        if binary is None:
            raise SimulatorStartupError(f"anvil not found: {self._anvil_path!r}")
        try:
            self._spawn(binary)
            await self._wait_until_ready()
            point = await fetch_fork_point(upstream)
            await self.fork(point)
            await self._probe_call_tracer(point)
        except SimulatorError as exc:
            await self.stop()
            raise SimulatorStartupError(f"simulation node failed to start: {exc}") from exc
        except BaseException:
            await self.stop()
            raise
        logger.info("simulation node ready (pid %d), forked at block %d", self.pid, point.number)

    async def fork(self, point: ForkPoint) -> None:
        """Reset the node to a fresh fork of the upstream at `point`.

        If this raises, the node's state is unknown (a failed anvil_reset
        leaves the previous fork in place). Don't simulate on it until a
        later fork() succeeds."""
        reset = {"forking": {"jsonRpcUrl": self._upstream_url, "blockNumber": point.number}}
        await self.call("anvil_reset", [reset])
        await self.verify(point)

    async def restart(self, upstream: UpstreamClient) -> None:
        """Stop and start again, forked at the upstream's current head."""
        await self.stop()
        await self.start(upstream)

    async def call(self, method: str, params: list[Any]) -> Any:
        """Call the node and return the result. Errors carry only the method
        and error code (see SimulatorError)."""
        reply = await self.try_call(method, params)
        if reply.error is not None:
            raise SimulatorError(f"simulation node returned error {reply.error.code} on {method}")
        return reply.result

    async def try_call(self, method: str, params: list[Any]) -> UpstreamResult:
        """Like call(), but a JSON-RPC error is returned, not raised. The
        error's message is anvil's own text, which can quote the upstream
        URL: never pass it on unfiltered."""
        if self._client is None or not self.is_running():
            raise SimulatorError("simulation node is not running")
        try:
            return await self._client.call(method, params)
        except UpstreamError as exc:
            raise SimulatorError(f"simulation node request {method} failed") from exc

    async def stop(self) -> None:
        """Stop the process and delete its private home. Safe to call twice."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._process is not None:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    await asyncio.to_thread(self._process.wait, STOP_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    await asyncio.to_thread(self._process.wait)
            self._process = None
        if self._home is not None:
            shutil.rmtree(self._home, ignore_errors=True)
            self._home = None
        self._url = None

    def _spawn(self, binary: str) -> None:
        # mkdtemp creates the directory with mode 0700: only we can read it.
        self._home = tempfile.mkdtemp(prefix="mandate-firewall-anvil-")
        port = _free_port()
        argv = [
            binary,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--quiet",
            "--no-mining",
            "--accounts",
            "0",
        ]
        self._process = subprocess.Popen(  # noqa: S603 - fixed argv, resolved binary
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"HOME": self._home},
        )
        self._url = f"http://127.0.0.1:{port}"
        self._client = UpstreamClient(self._url)

    async def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self._process is None or self._process.poll() is not None:
                # Its output went to /dev/null, so all we have is the exit code.
                # The usual cause is the port being taken between our check and
                # anvil binding it; starting again picks a new port.
                code = self._process.returncode if self._process is not None else None
                raise SimulatorError(f"anvil exited with code {code}")
            try:
                await self.call("eth_chainId", [])
                return
            except SimulatorError:
                await asyncio.sleep(0.1)
        raise SimulatorError(f"anvil not ready after {STARTUP_TIMEOUT_SECONDS}s")

    async def verify(self, point: ForkPoint) -> None:
        """Check the node is a clean fork of the upstream at `point`."""
        chain_id = _quantity(await self.call("eth_chainId", []))
        if chain_id != self._chain_id:
            raise SimulatorError(
                f"fork chain id {chain_id} does not match upstream chain id {self._chain_id}"
            )
        head = _quantity(await self.call("eth_blockNumber", []))
        if head != point.number:
            raise SimulatorError(f"fork head is block {head}, expected {point.number}")
        block = await self.call("eth_getBlockByNumber", [hex(point.number), False])
        if not isinstance(block, dict) or _block_hash(block) != point.hash:
            raise SimulatorError(f"fork block {point.number} hash does not match the upstream")
        # evm_revert doesn't clear the txpool, so a queued transaction (say,
        # one with a future nonce) could survive into a later simulation.
        pool = await self.call("txpool_status", [])
        if not isinstance(pool, dict) or any(
            _quantity(pool.get(key)) != 0 for key in ("pending", "queued")
        ):
            raise SimulatorError("fork txpool is not empty")

    async def _probe_call_tracer(self, point: ForkPoint) -> None:
        """Send, mine and trace a throwaway transaction, then revert it, to
        prove the whole path (raw tx -> evm_mine -> receipt -> callTracer)
        works before we rely on it."""
        snapshot = await self.call("evm_snapshot", [])
        try:
            # A fresh random key: nonce 0, no code, and no chance of clashing
            # with a real account on the fork. It is never stored or logged.
            account = Account.create()
            latest = await self.call("eth_getBlockByNumber", ["latest", False])
            if not isinstance(latest, dict):
                raise SimulatorError("fork returned no latest block")
            max_fee = 2 * _quantity(latest.get("baseFeePerGas")) + 1
            await self.call(
                "anvil_setBalance", [account.address, hex(SIMPLE_TRANSFER_GAS * max_fee)]
            )
            signed = account.sign_transaction(
                {
                    "type": 2,
                    "chainId": self._chain_id,
                    "nonce": 0,
                    "to": account.address,
                    "value": 0,
                    "gas": SIMPLE_TRANSFER_GAS,
                    "maxFeePerGas": max_fee,
                    "maxPriorityFeePerGas": 0,
                    "data": b"",
                }
            )
            tx_hash = await self.call(
                "eth_sendRawTransaction", ["0x" + bytes(signed.raw_transaction).hex()]
            )
            await self.call("evm_mine", [])

            receipt = await self.call("eth_getTransactionReceipt", [tx_hash])
            if not isinstance(receipt, dict) or receipt.get("status") != "0x1":
                raise SimulatorError("probe transaction was not mined successfully")
            if _quantity(receipt.get("blockNumber")) != point.number + 1:
                raise SimulatorError("probe transaction was mined in an unexpected block")

            trace = await self.call("debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
            me = account.address.lower()
            if not (
                isinstance(trace, dict)
                and trace.get("type") == "CALL"
                and str(trace.get("from")).lower() == me
                and str(trace.get("to")).lower() == me
            ):
                raise SimulatorError("callTracer returned an unexpected trace")
        finally:
            # Anvil returns false, not an error, for an unknown snapshot id.
            if await self.call("evm_revert", [snapshot]) is not True:
                raise SimulatorError("evm_revert failed after the probe")
        await self.verify(point)


def _quantity(value: Any) -> int:
    """A JSON-RPC quantity: 0x-prefixed hex, no leading zeros required."""
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
        raise SimulatorError("expected a hex quantity")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise SimulatorError("expected a hex quantity") from exc


def _block_hash(block: dict[str, Any]) -> str:
    value = block.get("hash")
    if not isinstance(value, str) or not _HASH.fullmatch(value.lower()):
        raise SimulatorError("block has no valid hash")
    return value.lower()


def _free_port() -> int:
    """A TCP port that was free a moment ago. Another process can take it
    before anvil binds it; anvil then exits and start() fails closed."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
