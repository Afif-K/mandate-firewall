"""The proxy with its real simulator: `mandate-firewall serve` in front of an
upstream anvil, simulating every transaction on its own anvil fork before
deciding whether to forward it."""

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from eth_utils import keccak

from mandate_firewall.proxy.jsonrpc import METHOD_NOT_FOUND, TRANSACTION_REJECTED
from tests.contracts import load
from tests.integration.chain import ALICE, BOB, THIEF, balance, deploy, sign, transact
from tests.integration.conftest import (
    Proxy,
    Service,
    rpc_call,
    rpc_result,
    start,
    start_proxy,
    stop,
)
from tests.mandates import mandate_with, native_transfer_mandate, replace_mandate, token_transfer
from tests.net import free_port

pytestmark = pytest.mark.anvil

ERC20 = load("MockERC20")
LYING = load("LyingToken")


@dataclass
class Setup:
    upstream: Service
    proxy: Proxy
    token: str
    lying: str


@pytest.fixture(scope="module")
def setup(anvil: Service, proxy: Proxy) -> Setup:
    """Contracts are deployed on the upstream directly, not through the proxy.
    The mandate names them, so what these tests send is on-mandate: only the
    simulation (a revert, a lying token) decides."""
    token = deploy(anvil.url, ERC20)
    transact(anvil.url, ERC20, token, "mint", ALICE, 100_000_000)
    lying = deploy(anvil.url, LYING, THIEF)
    transact(anvil.url, LYING, lying, "mint", ALICE, 100)
    chain_id = int(rpc_result(anvil.url, "eth_chainId"), 16)
    eth = native_transfer_mandate(chain_id, ALICE).intents[0]
    covers = mandate_with(
        chain_id,
        ALICE,
        eth,
        token_transfer(chain_id, token, 100_000_000),
        token_transfer(chain_id, lying, 100),
        minutes=24 * 60,
        max_transactions=1000,
    )
    replace_mandate(proxy.mandate_db, covers)
    return Setup(anvil, proxy, token, lying)


def send_via_proxy(setup: Setup, to: str, data: str = "0x", value: int = 0) -> tuple[str, Any]:
    raw = sign(setup.proxy.url, to, data, value)
    return "0x" + keccak(hexstr=raw).hex(), rpc_call(
        setup.proxy.url, "eth_sendRawTransaction", [raw]
    )


def record_for(proxy: Proxy, tx_hash: str) -> dict[str, Any]:
    (record,) = [r for r in proxy.audit_records() if r["hash"] == tx_hash]
    return record


def wait_for_receipt(url: str, tx_hash: str) -> dict[str, Any]:
    for _ in range(100):
        receipt = rpc_result(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.05)
    pytest.fail(f"{tx_hash} not mined")


def simulator_pid(proxy: Proxy) -> int:
    """The proxy's anvil child: its private simulation fork."""
    out = subprocess.run(  # noqa: S603
        ["pgrep", "-P", str(proxy.process.pid)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    (pid,) = out.stdout.split()
    return int(pid)


def command_line(pid: int) -> str:
    out = subprocess.run(  # noqa: S603
        ["ps", "-o", "args=", "-p", str(pid)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout


def kill_and_wait(pid: int) -> None:
    """SIGKILL and wait until the process is dead. It's the proxy's child, so
    until the proxy reaps it, it lingers as a zombie ("Z"), which still
    answers os.kill(pid, 0)."""
    os.kill(pid, signal.SIGKILL)
    for _ in range(100):
        state = subprocess.run(  # noqa: S603
            ["ps", "-o", "stat=", "-p", str(pid)],  # noqa: S607
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not state or state.startswith("Z"):
            return
        time.sleep(0.02)
    pytest.fail(f"process {pid} did not die")


# --- decisions ----------------------------------------------------------------------


def test_forwarded_transaction_has_effects_in_its_audit_record(setup: Setup) -> None:
    tx_hash, response = send_via_proxy(
        setup, setup.token, ERC20.call_data("transfer", BOB, 25_000_000)
    )
    assert response["result"] == tx_hash
    assert wait_for_receipt(setup.upstream.url, tx_hash)["status"] == "0x1"

    record = record_for(setup.proxy, tx_hash)
    assert record["decision"] == "allow"
    effects = record["effects"]
    assert effects["status"] == "success"
    (transfer,) = effects["token_transfers"]
    assert (transfer["sender"], transfer["recipient"], transfer["amount"]) == (
        ALICE,
        BOB,
        "25000000",
    )
    assert {(c["owner"], c["consistent"]) for c in effects["token_state_checks"]} == {
        (ALICE, True),
        (BOB, True),
    }


def test_reverting_transaction_is_blocked_and_never_mined(setup: Setup) -> None:
    tx_hash, response = send_via_proxy(setup, setup.token, ERC20.call_data("transfer", BOB, 10**30))
    assert response["error"]["code"] == TRANSACTION_REJECTED
    assert response["error"]["message"] == "transaction rejected: transaction reverts in simulation"
    assert rpc_result(setup.upstream.url, "eth_getTransactionByHash", [tx_hash]) is None

    record = record_for(setup.proxy, tx_hash)
    assert record["decision"] == "block"
    assert record["effects"]["status"] == "reverted"
    assert record["effects"]["revert_data"].startswith("0x4e487b71")  # Panic(uint256)


def test_lying_token_escalates_and_is_never_mined(setup: Setup) -> None:
    """M2 recorded the lie and forwarded; M4 acts on it. The transfer is on
    mandate (10 of the lying token to Bob), but its events disagree with its
    storage, so nothing built from them can be trusted: escalate."""
    tx_hash, response = send_via_proxy(setup, setup.lying, LYING.call_data("transfer", BOB, 10))
    assert response["error"]["code"] == TRANSACTION_REJECTED
    assert response["error"]["data"] == {
        "decision": "escalate",
        "violations": [],
        "anomalies": ["inconsistent_token_state"],
    }
    assert rpc_result(setup.upstream.url, "eth_getTransactionByHash", [tx_hash]) is None
    record = record_for(setup.proxy, tx_hash)
    assert record["decision"] == "escalate"
    assert record["mandate_transaction"] is None  # not charged
    checks = record["effects"]["token_state_checks"]
    assert {(c["owner"], c["claimed"], c["consistent"]) for c in checks} == {
        (ALICE, "-10", True),
        (BOB, "10", False),  # the events said Bob got 10; he got nothing
    }
    assert f"its events disagree with its balances for {BOB}" in record["explanation"]


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("anvil_setBalance", [ALICE, hex(10**30)]),
        ("anvil_setCode", [BOB, "0x00"]),
        ("anvil_reset", [{"forking": {"jsonRpcUrl": "http://127.0.0.1:1"}}]),
        ("anvil_nodeInfo", []),
        ("anvil_impersonateAccount", [BOB]),
        ("evm_snapshot", []),
        ("evm_revert", ["0x0"]),
        ("evm_mine", []),
        ("debug_traceTransaction", ["0x" + "11" * 32, {"tracer": "callTracer"}]),
        ("debug_traceCall", [{"to": BOB}, "latest", {"tracer": "callTracer"}]),
    ],
)
def test_agents_cannot_reach_simulator_methods(setup: Setup, method: str, params: Any) -> None:
    response = rpc_call(setup.proxy.url, method, params)
    assert response["error"]["code"] == METHOD_NOT_FOUND
    # Had anvil_setBalance gone anywhere, Alice would now hold 10**30 wei.
    assert balance(setup.upstream.url, ALICE) < 10**30


# --- the simulation node ---------------------------------------------------------------


def test_simulator_runs_in_ethereum_mode_for_a_non_op_chain(setup: Setup) -> None:
    args = command_line(simulator_pid(setup.proxy))
    assert "--network ethereum" in args
    assert setup.upstream.url not in args


def test_killed_simulator_is_restarted(setup: Setup) -> None:
    old = simulator_pid(setup.proxy)
    kill_and_wait(old)

    tx_hash, response = send_via_proxy(setup, BOB, value=1)

    assert response["result"] == tx_hash
    assert record_for(setup.proxy, tx_hash)["effects"]["status"] == "success"
    assert simulator_pid(setup.proxy) != old


def test_simulator_that_cannot_restart_blocks_transactions(
    anvil: Service, workdir: Path, setup: Setup
) -> None:
    # ANVIL_PATH is a symlink we delete after startup, so a restart can't work.
    link = workdir / "anvil-link"
    anvil_binary = shutil.which("anvil")
    assert anvil_binary is not None
    link.symlink_to(anvil_binary)
    proxy = start_proxy(anvil, workdir, "proxy-fragile", os.environ | {"ANVIL_PATH": str(link)})
    try:
        link.unlink()
        kill_and_wait(simulator_pid(proxy))

        raw = sign(proxy.url, BOB, value=3)
        response = rpc_call(proxy.url, "eth_sendRawTransaction", [raw])

        assert response["error"]["code"] == TRANSACTION_REJECTED
        assert "could not be restarted" in response["error"]["message"]
        tx_hash = "0x" + keccak(hexstr=raw).hex()
        assert rpc_result(anvil.url, "eth_getTransactionByHash", [tx_hash]) is None
        assert record_for(proxy, tx_hash)["decision"] == "block"
    finally:
        stop(proxy)


@pytest.fixture(scope="module")
def base_sepolia(workdir: Path) -> Iterator[tuple[Service, Proxy]]:
    port = free_port()
    argv = ["anvil", "--port", str(port), "--chain-id", "84532", "--quiet"]
    upstream = start("upstream-84532", argv, port, workdir)
    proxy = start_proxy(upstream, workdir, "proxy-84532")
    yield upstream, proxy
    stop(proxy)
    stop(upstream)


def test_op_stack_chain_runs_simulator_in_optimism_mode(
    base_sepolia: tuple[Service, Proxy],
) -> None:
    upstream, proxy = base_sepolia
    assert "--network optimism" in command_line(simulator_pid(proxy))

    raw = sign(proxy.url, BOB, value=10**15)  # signed for chain 84532
    tx_hash = "0x" + keccak(hexstr=raw).hex()
    assert rpc_result(proxy.url, "eth_sendRawTransaction", [raw]) == tx_hash
    assert wait_for_receipt(upstream.url, tx_hash)["status"] == "0x1"
    changes = {
        c["address"]: c["delta"]
        for c in record_for(proxy, tx_hash)["effects"]["native_balance_changes"]
    }
    assert changes[BOB] == str(10**15)
