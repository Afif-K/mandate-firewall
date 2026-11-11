"""The simulation node against a real "upstream" anvil.

The upstream runs with chain id 84532 (Base Sepolia) rather than anvil's
default 31337, so a fork that reports 84532 got it from the upstream.
"""

import asyncio
import os
import subprocess
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from mandate_firewall.proxy.upstream import UpstreamClient
from mandate_firewall.simulate.node import (
    ForkPoint,
    SimulatorError,
    SimulatorNode,
    SimulatorStartupError,
    fetch_fork_point,
)
from tests.integration.services import Service, rpc_result, start, stop
from tests.net import free_port

pytestmark = pytest.mark.anvil

UPSTREAM_CHAIN_ID = 84532
DEV_ACCOUNT_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # anvil's public dev account


@pytest.fixture(scope="module")
def upstream(workdir: Path) -> Iterator[Service]:
    port = free_port()
    argv = ["anvil", "--port", str(port), "--chain-id", str(UPSTREAM_CHAIN_ID), "--quiet"]
    service = start("upstream", argv, port, workdir)
    # Spend some of dev account 0's ETH, so its real balance differs from the
    # 10000 ETH anvil would give it, and move past the genesis block.
    rpc_result(
        service.url,
        "eth_sendTransaction",
        [{"from": DEV_ACCOUNT_0, "to": "0x" + "00" * 19 + "01", "value": hex(10**18)}],
    )
    rpc_result(service.url, "evm_mine")
    yield service
    stop(service)


@pytest.fixture
async def upstream_client(upstream: Service) -> AsyncIterator[UpstreamClient]:
    client = UpstreamClient(upstream.url)
    yield client
    await client.aclose()


@pytest.fixture
async def node(upstream: Service, upstream_client: UpstreamClient) -> AsyncIterator[SimulatorNode]:
    node = SimulatorNode("anvil", upstream.url, UPSTREAM_CHAIN_ID)
    await node.start(upstream_client)
    yield node
    await node.stop()


def head(url: str) -> ForkPoint:
    block = rpc_result(url, "eth_getBlockByNumber", ["latest", False])
    return ForkPoint(number=int(block["number"], 16), hash=block["hash"])


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def test_start_forks_at_upstream_head(node: SimulatorNode, upstream: Service) -> None:
    point = head(upstream.url)
    assert int(await node.call("eth_chainId", []), 16) == UPSTREAM_CHAIN_ID
    assert int(await node.call("eth_blockNumber", []), 16) == point.number
    block = await node.call("eth_getBlockByNumber", [hex(point.number), False])
    assert block["hash"] == point.hash
    # The probe transaction was reverted: nothing left in the pool.
    assert await node.call("txpool_status", []) == {"pending": "0x0", "queued": "0x0"}


async def test_fork_shows_real_balances_of_dev_accounts(
    node: SimulatorNode, upstream: Service
) -> None:
    # Without --accounts 0, anvil would reset this to 10000 ETH on the fork.
    real = rpc_result(upstream.url, "eth_getBalance", [DEV_ACCOUNT_0, "latest"])
    assert await node.call("eth_getBalance", [DEV_ACCOUNT_0, "latest"]) == real
    assert int(real, 16) < 10_000 * 10**18
    assert await node.call("eth_accounts", []) == []


async def test_upstream_url_is_not_on_the_command_line(
    node: SimulatorNode, upstream: Service
) -> None:
    assert node.pid is not None
    ps = subprocess.run(  # noqa: S603
        ["ps", "-o", "args=", "-p", str(node.pid)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    command_line = ps.stdout
    assert "anvil" in command_line
    assert upstream.url not in command_line
    assert "fork" not in command_line


async def test_fork_moves_to_a_new_upstream_head(node: SimulatorNode, upstream: Service) -> None:
    rpc_result(upstream.url, "evm_mine")
    point = head(upstream.url)
    await node.fork(point)
    assert int(await node.call("eth_blockNumber", []), 16) == point.number


async def test_fork_rejects_a_block_hash_mismatch(node: SimulatorNode, upstream: Service) -> None:
    point = head(upstream.url)
    wrong = ForkPoint(number=point.number, hash="0x" + "ab" * 32)
    with pytest.raises(SimulatorError, match="hash does not match"):
        await node.fork(wrong)


async def test_fetch_fork_point_reads_upstream_head(
    upstream_client: UpstreamClient, upstream: Service
) -> None:
    assert await fetch_fork_point(upstream_client) == head(upstream.url)


async def test_wrong_chain_id_refuses_to_start(
    upstream: Service, upstream_client: UpstreamClient
) -> None:
    node = SimulatorNode("anvil", upstream.url, chain_id=1)
    with pytest.raises(SimulatorStartupError, match="does not match upstream chain id"):
        await node.start(upstream_client)
    assert not node.is_running()


async def test_failed_reset_refuses_to_start_without_leaking_the_url(
    upstream_client: UpstreamClient,
) -> None:
    # The upstream client works, but the URL anvil is told to fork from doesn't.
    dead_url = f"http://127.0.0.1:{free_port()}/v2/SECRET-API-KEY"
    node = SimulatorNode("anvil", dead_url, UPSTREAM_CHAIN_ID)
    with pytest.raises(SimulatorStartupError) as excinfo:
        await node.start(upstream_client)
    message = str(excinfo.value)
    assert "anvil_reset" in message
    assert "SECRET" not in message and "127.0.0.1" not in message
    assert not node.is_running()


async def test_stop_kills_the_process_and_deletes_its_home(
    upstream: Service, upstream_client: UpstreamClient
) -> None:
    node = SimulatorNode("anvil", upstream.url, UPSTREAM_CHAIN_ID)
    await node.start(upstream_client)
    pid, home = node.pid, node._home
    assert pid is not None and home is not None and Path(home).is_dir()
    assert oct(Path(home).stat().st_mode & 0o777) == "0o700"

    await node.stop()
    assert not process_exists(pid)
    assert not Path(home).exists()
    await node.stop()  # idempotent
    with pytest.raises(SimulatorError, match="not running"):
        await node.call("eth_chainId", [])


async def test_dead_node_fails_closed(node: SimulatorNode) -> None:
    assert node.pid is not None
    os.kill(node.pid, 9)
    await _wait_for_exit(node)
    with pytest.raises(SimulatorError, match="not running"):
        await node.call("eth_chainId", [])


async def _wait_for_exit(node: SimulatorNode) -> None:
    for _ in range(50):
        if not node.is_running():
            return
        await asyncio.sleep(0.05)
    pytest.fail("anvil did not exit after SIGKILL")
