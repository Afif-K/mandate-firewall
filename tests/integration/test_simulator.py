"""The simulator end to end: a real "upstream" anvil with the test contracts
deployed, and our private fork of it. Simulated transactions never reach the
upstream."""

import asyncio
import os
import statistics
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from mandate_firewall.decode.transaction import decode_raw_transaction
from mandate_firewall.models import CallType, Effects, SimulationStatus, TokenStandard
from mandate_firewall.proxy.upstream import UpstreamClient
from mandate_firewall.simulate.node import SimulatorNode, SimulatorStartupError
from mandate_firewall.simulate.simulator import (
    SimulationTimeoutError,
    Simulator,
    SimulatorBusyError,
    SimulatorUnavailableError,
    TooManyStateChecksError,
    TransactionRejectedError,
)
from tests.contracts import load
from tests.integration.chain import ALICE, BOB, THIEF, balance, deploy, sign, transact
from tests.integration.conftest import Service, rpc_result, start, stop
from tests.net import free_port

pytestmark = pytest.mark.anvil

CHAIN_ID = 31337
ZERO = "0x0000000000000000000000000000000000000000"
ERC20 = load("MockERC20")
ERC721 = load("MockERC721")
LYING = load("LyingToken")
FORWARDER = load("EthForwarder")


@dataclass
class Chain:
    url: str
    token: str
    nft: str
    lying: str
    forwarder: str


@pytest.fixture(scope="module")
def chain(workdir: Path) -> Iterator[Chain]:
    """An upstream anvil with ALICE holding 100 USDC-like tokens, NFT #7 and
    100 LyingTokens."""
    port = free_port()
    service: Service = start("upstream", ["anvil", "--port", str(port), "--quiet"], port, workdir)
    url = service.url
    token = deploy(url, ERC20)
    transact(url, ERC20, token, "mint", ALICE, 100_000_000)
    nft = deploy(url, ERC721)
    transact(url, ERC721, nft, "mint", ALICE, 7)
    lying = deploy(url, LYING, THIEF)
    transact(url, LYING, lying, "mint", ALICE, 100)
    forwarder = deploy(url, FORWARDER)
    yield Chain(url, token, nft, lying, forwarder)
    stop(service)


@pytest.fixture
async def upstream(chain: Chain) -> AsyncIterator[UpstreamClient]:
    client = UpstreamClient(chain.url)
    yield client
    await client.aclose()


@pytest.fixture
async def node(chain: Chain, upstream: UpstreamClient) -> AsyncIterator[SimulatorNode]:
    node = SimulatorNode("anvil", chain.url, CHAIN_ID)
    await node.start(upstream)
    yield node
    await node.stop()


def make_simulator(node: SimulatorNode, upstream: UpstreamClient, **overrides: Any) -> Simulator:
    settings: dict[str, Any] = {"timeout_seconds": 10.0, "max_token_state_checks": 50}
    return Simulator(node, upstream, **(settings | overrides))


@pytest.fixture
def simulator(node: SimulatorNode, upstream: UpstreamClient) -> Simulator:
    return make_simulator(node, upstream)


async def simulate(sim: Simulator, chain: Chain, to: str | None, data: str = "0x", **kw: Any):
    return await sim.simulate(decode_raw_transaction(sign(chain.url, to, data, **kw)))


def checks(effects: Effects) -> dict[tuple[str, str], tuple[int, bool]]:
    """{(kind, owner): (claimed, consistent)}"""
    return {(c.kind, c.owner): (c.claimed, c.consistent) for c in effects.token_state_checks}


def head(url: str) -> int:
    return int(rpc_result(url, "eth_blockNumber"), 16)


# --- what each kind of transaction does ---------------------------------------------


async def test_eth_send(simulator: Simulator, chain: Chain) -> None:
    nonce_before = rpc_result(chain.url, "eth_getTransactionCount", [ALICE, "latest"])
    bob_before = balance(chain.url, BOB)

    effects = await simulate(simulator, chain, BOB, value=10**18)

    assert effects.status is SimulationStatus.SUCCESS
    assert (effects.chain_id, effects.fork_block_number) == (CHAIN_ID, head(chain.url))
    assert effects.gas_used == 21_000
    assert effects.gas_cost == 21_000 * effects.effective_gas_price
    changes = {c.address: c.delta for c in effects.native_balance_changes}
    # The fee is split out, not hidden in "ALICE lost 1.0000x ETH".
    assert changes == {ALICE: -(10**18) - effects.gas_cost, BOB: 10**18}
    (frame,) = effects.calls
    assert (frame.call_type, frame.target, frame.value) == (CallType.CALL, BOB, 10**18)
    assert effects.token_transfers == effects.token_state_checks == ()

    # The upstream never saw it.
    assert rpc_result(chain.url, "eth_getTransactionCount", [ALICE, "latest"]) == nonce_before
    assert balance(chain.url, BOB) == bob_before


async def test_erc20_transfer(simulator: Simulator, chain: Chain) -> None:
    data = ERC20.call_data("transfer", BOB, 50_000_000)
    effects = await simulate(simulator, chain, chain.token, data)

    (transfer,) = effects.token_transfers
    assert (transfer.token, transfer.sender, transfer.recipient, transfer.amount) == (
        chain.token,
        ALICE,
        BOB,
        50_000_000,
    )
    assert checks(effects) == {
        ("balance", ALICE): (-50_000_000, True),
        ("balance", BOB): (50_000_000, True),
    }
    assert effects.calls[0].selector == "0xa9059cbb"
    # Only gas moved ETH.
    assert [(c.address, c.delta) for c in effects.native_balance_changes] == [
        (ALICE, -effects.gas_cost)
    ]


async def test_erc20_unlimited_approve(simulator: Simulator, chain: Chain) -> None:
    effects = await simulate(
        simulator, chain, chain.token, ERC20.call_data("approve", BOB, 2**256 - 1)
    )
    (approval,) = effects.token_approvals
    assert (approval.owner, approval.spender, approval.amount) == (ALICE, BOB, 2**256 - 1)
    (check,) = effects.token_state_checks
    assert (check.kind, check.spender, check.before, check.after, check.consistent) == (
        "allowance",
        BOB,
        0,
        2**256 - 1,
        True,
    )


async def test_nft_set_approval_for_all(simulator: Simulator, chain: Chain) -> None:
    data = ERC721.call_data("setApprovalForAll", THIEF, True)
    effects = await simulate(simulator, chain, chain.nft, data)
    (approval,) = effects.operator_approvals
    assert (approval.token, approval.owner, approval.operator, approval.approved) == (
        chain.nft,
        ALICE,
        THIEF,
        True,
    )
    assert effects.token_state_checks == ()  # not state-checked; see claims.py


async def test_nft_transfer_is_balance_checked(simulator: Simulator, chain: Chain) -> None:
    data = ERC721.call_data("transferFrom", ALICE, BOB, 7)
    effects = await simulate(simulator, chain, chain.nft, data)
    (transfer,) = effects.token_transfers
    assert (transfer.standard, transfer.token_id) == (TokenStandard.ERC721, 7)
    assert checks(effects) == {("balance", ALICE): (-1, True), ("balance", BOB): (1, True)}


async def test_internal_eth_move_through_forwarder(simulator: Simulator, chain: Chain) -> None:
    data = FORWARDER.call_data("forward", BOB)
    effects = await simulate(simulator, chain, chain.forwarder, data, value=3 * 10**17)
    changes = {c.address: c.delta for c in effects.native_balance_changes}
    # The tx says "0.3 ETH to the forwarder". The ETH ended up with Bob, and
    # the forwarder's net change is zero, so it isn't listed.
    assert changes == {ALICE: -(3 * 10**17) - effects.gas_cost, BOB: 3 * 10**17}
    assert [(c.depth, c.target, c.value) for c in effects.calls] == [
        (0, chain.forwarder, 3 * 10**17),
        (1, BOB, 3 * 10**17),
    ]
    assert effects.token_transfers == effects.unrecognized_logs == ()


async def test_lying_token_redirect_is_caught(simulator: Simulator, chain: Chain) -> None:
    # The event says Bob got 10. The token debits Alice correctly and
    # credits the thief, so a sender-only check would pass it.
    effects = await simulate(simulator, chain, chain.lying, LYING.call_data("transfer", BOB, 10))
    assert checks(effects) == {("balance", ALICE): (-10, True), ("balance", BOB): (10, False)}


async def test_lying_token_fake_transfer_is_caught(simulator: Simulator, chain: Chain) -> None:
    data = LYING.call_data("fakeTransfer", BOB, 5)
    effects = await simulate(simulator, chain, chain.lying, data)
    assert checks(effects) == {("balance", ALICE): (-5, False), ("balance", BOB): (5, False)}


async def test_revert(simulator: Simulator, chain: Chain) -> None:
    data = ERC20.call_data("transfer", BOB, 10**30)  # more than Alice has
    effects = await simulate(simulator, chain, chain.token, data)
    assert effects.status is SimulationStatus.REVERTED
    # Solidity 0.8 underflow: Panic(uint256) with code 0x11, kept as raw hex.
    assert effects.revert_data == "0x4e487b71" + "11".rjust(64, "0")
    assert effects.token_transfers == effects.token_state_checks == ()
    assert [(c.address, c.delta) for c in effects.native_balance_changes] == [
        (ALICE, -effects.gas_cost)  # a reverted tx still pays for gas
    ]


async def test_contract_creation(simulator: Simulator, chain: Chain) -> None:
    effects = await simulate(simulator, chain, None, ERC20.deploy_data())
    (created,) = effects.contracts_created
    assert (effects.calls[0].call_type, effects.calls[0].target) == (CallType.CREATE, created)
    assert rpc_result(chain.url, "eth_getCode", [created, "latest"]) == "0x"  # not upstream


async def test_eth_sent_to_the_coinbase_is_not_hidden(simulator: Simulator, chain: Chain) -> None:
    # anvil mines with coinbase 0x0. It also earns the priority fee, which is
    # subtracted; the 5 wei sent to it is an effect and must stay visible.
    effects = await simulate(simulator, chain, ZERO, value=5)
    changes = {c.address: c.delta for c in effects.native_balance_changes}
    assert changes[ZERO] == 5


# --- clean state between simulations ----------------------------------------------


async def test_back_to_back_simulations_do_not_leak_state(
    simulator: Simulator, chain: Chain
) -> None:
    data = ERC20.call_data("transfer", BOB, 60_000_000)
    first = await simulate(simulator, chain, chain.token, data)
    # Same nonce, same transfer: if the first had stuck, Alice (100) couldn't
    # send 60 twice and this would revert.
    second = await simulate(simulator, chain, chain.token, data)
    assert first == second
    assert first.status is SimulationStatus.SUCCESS


async def test_queued_transaction_does_not_leak_into_the_next(
    simulator: Simulator, chain: Chain
) -> None:
    nonce = int(rpc_result(chain.url, "eth_getTransactionCount", [ALICE, "pending"]), 16)
    with pytest.raises(TransactionRejectedError, match="did not mine"):
        await simulate(simulator, chain, BOB, value=1, nonce=nonce + 1)
    assert simulator.dirty
    # The queued tx (nonce + 1) would be mined right after this one if it
    # were still in the pool, adding a second transfer to Bob.
    effects = await simulate(simulator, chain, BOB, value=1, nonce=nonce)
    assert {c.address: c.delta for c in effects.native_balance_changes}[BOB] == 1
    assert not simulator.dirty


async def test_fork_follows_the_upstream_head(simulator: Simulator, chain: Chain) -> None:
    first = await simulate(simulator, chain, BOB, value=1)
    rpc_result(chain.url, "evm_mine")
    second = await simulate(simulator, chain, BOB, value=1)
    assert second.fork_block_number == first.fork_block_number + 1
    assert second.fork_block_hash != first.fork_block_hash


# --- failures ---------------------------------------------------------------------


async def test_nonce_too_low_is_rejected(simulator: Simulator, chain: Chain) -> None:
    nonce = int(rpc_result(chain.url, "eth_getTransactionCount", [ALICE, "latest"]), 16)
    with pytest.raises(TransactionRejectedError, match="nonce too low"):
        await simulate(simulator, chain, BOB, value=1, nonce=nonce - 1)


async def test_too_many_state_checks_blocks_up_front(
    node: SimulatorNode, upstream: UpstreamClient, chain: Chain
) -> None:
    simulator = make_simulator(node, upstream, max_token_state_checks=1)
    data = ERC20.call_data("transfer", BOB, 1)  # needs 2 checks: Alice and Bob
    with pytest.raises(TooManyStateChecksError, match="needs 2 token state checks; the limit is 1"):
        await simulate(simulator, chain, chain.token, data)


async def test_timeout_marks_dirty_and_recovers(simulator: Simulator, chain: Chain) -> None:
    await simulate(simulator, chain, BOB, value=1)
    assert not simulator.dirty  # so the assertion below means something
    simulator.timeout_seconds = 0.001
    with pytest.raises(SimulationTimeoutError):
        await simulate(simulator, chain, BOB, value=1)
    assert simulator.dirty  # cancelled part-way: state unknown
    simulator.timeout_seconds = 10.0
    effects = await simulate(simulator, chain, BOB, value=1)
    assert effects.status is SimulationStatus.SUCCESS
    assert not simulator.dirty


async def test_killed_node_is_restarted(
    simulator: Simulator, node: SimulatorNode, chain: Chain
) -> None:
    await simulate(simulator, chain, BOB, value=1)
    old_pid = node.pid
    assert old_pid is not None
    os.kill(old_pid, 9)
    for _ in range(50):
        if not node.is_running():
            break
        await asyncio.sleep(0.05)

    effects = await simulate(simulator, chain, BOB, value=1)
    assert effects.status is SimulationStatus.SUCCESS
    assert node.pid not in (None, old_pid)


async def test_node_that_cannot_restart_is_unavailable(
    simulator: Simulator, node: SimulatorNode, chain: Chain, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken_restart(_: UpstreamClient) -> None:
        raise SimulatorStartupError("simulated failure")

    await node.stop()
    monkeypatch.setattr(node, "restart", broken_restart)
    with pytest.raises(SimulatorUnavailableError):
        await simulate(simulator, chain, BOB, value=1)


async def test_too_many_waiters_is_refused_at_once(
    node: SimulatorNode, upstream: UpstreamClient, chain: Chain
) -> None:
    simulator = make_simulator(node, upstream, max_pending=1)
    tx = decode_raw_transaction(sign(chain.url, BOB, value=1))
    results = await asyncio.gather(
        simulator.simulate(tx), simulator.simulate(tx), return_exceptions=True
    )
    assert isinstance(results[0], Effects)
    assert isinstance(results[1], SimulatorBusyError)


# --- latency ------------------------------------------------------------------------


async def test_latency(simulator: Simulator, chain: Chain, capsys: pytest.CaptureFixture) -> None:
    """Prints p50 latency. Against a local upstream, so this is a floor: a
    hosted RPC adds a round trip for every cold state read."""
    data = ERC20.call_data("transfer", BOB, 1)
    await simulate(simulator, chain, chain.token, data)  # warm up

    async def timed() -> float:
        started = time.monotonic()
        await simulate(simulator, chain, chain.token, data)
        return (time.monotonic() - started) * 1000

    same_head = [await timed() for _ in range(10)]
    new_head = []
    for _ in range(10):
        rpc_result(chain.url, "evm_mine")  # the head moves, as on Base: anvil_reset each time
        new_head.append(await timed())

    with capsys.disabled():
        print(
            f"\nsimulation p50: {statistics.median(same_head):.0f} ms same head (revert), "
            f"{statistics.median(new_head):.0f} ms new head (anvil_reset); local upstream"
        )
