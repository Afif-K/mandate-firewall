"""Simulation node pieces that don't need a real anvil."""

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError

from mandate_firewall.proxy.upstream import UpstreamClient
from mandate_firewall.simulate import node as node_module
from mandate_firewall.simulate.node import (
    ForkPoint,
    SimulatorError,
    SimulatorNode,
    SimulatorStartupError,
    fetch_fork_point,
    resolve_network,
)

URL = "http://upstream.test:8545/v2/SECRET-API-KEY"
HASH = "0x" + "ab" * 32


def reply(request: httpx.Request, **fields: Any) -> httpx.Response:
    request_id = json.loads(request.content)["id"]
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": request_id, **fields})


@pytest.fixture
async def client() -> Any:
    c = UpstreamClient(URL)
    yield c
    await c.aclose()


@respx.mock
async def test_fetch_fork_point(client: UpstreamClient) -> None:
    route = respx.post(URL).mock(
        side_effect=lambda r: reply(r, result={"number": "0x1f", "hash": HASH.upper()[2:]})
    )
    # A hash without 0x is not a hash.
    with pytest.raises(SimulatorError, match="no valid hash"):
        await fetch_fork_point(client)

    route.mock(side_effect=lambda r: reply(r, result={"number": "0x1f", "hash": "0x" + "AB" * 32}))
    assert await fetch_fork_point(client) == ForkPoint(number=31, hash=HASH)
    sent = json.loads(route.calls.last.request.content)
    assert (sent["method"], sent["params"]) == ("eth_getBlockByNumber", ["latest", False])


@pytest.mark.parametrize(
    "result",
    [
        None,
        "0x1",
        {"hash": HASH},
        {"number": 31, "hash": HASH},
        {"number": "0x", "hash": HASH},
        {"number": "0xzz", "hash": HASH},
        {"number": "0x1", "hash": "0x" + "ab" * 31},
    ],
)
@respx.mock
async def test_fetch_fork_point_rejects_malformed_blocks(
    client: UpstreamClient, result: Any
) -> None:
    respx.post(URL).mock(side_effect=lambda r: reply(r, result=result))
    with pytest.raises(SimulatorError):
        await fetch_fork_point(client)


@respx.mock
async def test_fetch_fork_point_errors_do_not_leak_the_url(client: UpstreamClient) -> None:
    respx.post(URL).mock(side_effect=httpx.ConnectError("cannot connect to " + URL))
    with pytest.raises(SimulatorError) as excinfo:
        await fetch_fork_point(client)
    assert "SECRET" not in str(excinfo.value)


def test_fork_point_requires_an_exact_hash() -> None:
    with pytest.raises(ValidationError):
        ForkPoint(number=1, hash="0x1234")
    with pytest.raises(ValidationError):
        ForkPoint(number=-1, hash=HASH)


async def test_missing_anvil_binary_refuses_to_start(client: UpstreamClient) -> None:
    node = SimulatorNode("/nonexistent/anvil", URL, chain_id=1)
    with pytest.raises(SimulatorStartupError, match="anvil not found"):
        await node.start(client)
    assert not node.is_running()


async def test_call_before_start_fails_closed() -> None:
    node = SimulatorNode("anvil", URL, chain_id=1)
    with pytest.raises(SimulatorError, match="not running"):
        await node.call("eth_chainId", [])


async def test_spawns_anvil_hardened(
    client: UpstreamClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flags and environment that keep the upstream URL, our secrets and
    the shared Foundry cache away from the node (see the node.py docstring)."""
    captured: dict[str, Any] = {}

    class FakePopen:
        pid = 4242
        returncode = 1

        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            captured.update(argv=argv, **kwargs)

        def poll(self) -> int:
            return 1  # "exited", so start() stops after spawning

    monkeypatch.setattr(node_module.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(node_module.shutil, "which", lambda _: "/opt/foundry/anvil")
    node = SimulatorNode("anvil", URL, chain_id=1)
    with pytest.raises(SimulatorStartupError, match="exited with code 1"):
        await node.start(client)

    argv = captured["argv"]
    assert argv[0] == "/opt/foundry/anvil"
    assert argv[argv.index("--host") + 1] == "127.0.0.1"
    assert argv[argv.index("--accounts") + 1] == "0"
    assert {"--quiet", "--no-mining"} <= set(argv)
    assert argv[argv.index("--network") + 1] == "ethereum"  # the default
    assert not any("fork" in arg or "SECRET" in arg for arg in argv)

    home = captured["env"]["HOME"]
    assert set(captured["env"]) == {"HOME"}
    assert "mandate-firewall-anvil-" in home
    for stream in ("stdin", "stdout", "stderr"):
        assert captured[stream] is subprocess.DEVNULL
    assert not Path(home).exists()  # deleted when start() gave up


@pytest.mark.parametrize(
    ("setting", "chain_id", "expected"),
    [
        ("auto", 8453, "optimism"),  # Base
        ("auto", 84532, "optimism"),  # Base Sepolia
        ("auto", 10, "optimism"),  # OP Mainnet
        ("auto", 11155420, "optimism"),  # OP Sepolia
        ("auto", 1, "ethereum"),
        ("auto", 31337, "ethereum"),
        ("auto", 7777777, "ethereum"),  # an OP-stack chain we don't know: set it explicitly
        ("optimism", 7777777, "optimism"),
        ("ethereum", 8453, "ethereum"),  # an explicit setting wins
    ],
)
def test_resolve_network(setting: Any, chain_id: int, expected: str) -> None:
    assert resolve_network(setting, chain_id) == expected
