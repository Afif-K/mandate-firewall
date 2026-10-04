"""Fixtures that run a real anvil node and a real `mandate-firewall serve`
process in front of it. Both start once per module (a second or two)."""

import json
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.net import free_port

STARTUP_TIMEOUT_SECONDS = 15.0


def rpc_call(url: str, method: str, params: Any = None) -> dict[str, Any]:
    """Send one JSON-RPC request and return the whole response object."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    return httpx.post(url, json=payload, timeout=10).json()


def rpc_result(url: str, method: str, params: Any = None) -> Any:
    response = rpc_call(url, method, params)
    assert "error" not in response, response
    return response["result"]


@dataclass
class Service:
    url: str
    process: subprocess.Popen[bytes]
    log: Path


def start(name: str, argv: list[str], port: int, workdir: Path) -> Service:
    log = workdir / f"{name}.log"
    with open(log, "wb") as out:
        process = subprocess.Popen(argv, cwd=workdir, stdout=out, stderr=subprocess.STDOUT)  # noqa: S603
    service = Service(f"http://127.0.0.1:{port}", process, log)

    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(f"{name} exited with {process.returncode}:\n{log.read_text()}")
        try:
            if "result" in rpc_call(service.url, "eth_chainId"):
                return service
        except httpx.TransportError:
            time.sleep(0.1)
    stop(service)
    pytest.fail(f"{name} not ready after {STARTUP_TIMEOUT_SECONDS}s:\n{log.read_text()}")


def stop(service: Service) -> None:
    service.process.terminate()
    try:
        service.process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        service.process.kill()
        service.process.wait()


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("anvil")


@pytest.fixture(scope="module")
def anvil(workdir: Path) -> Iterator[Service]:
    port = free_port()
    # Automine (the default): each accepted transaction is mined at once.
    service = start("anvil", ["anvil", "--port", str(port), "--quiet"], port, workdir)
    yield service
    stop(service)


@dataclass
class Proxy(Service):
    audit_log: Path

    def audit_records(self) -> list[dict[str, Any]]:
        if not self.audit_log.exists():
            return []
        return [json.loads(line) for line in self.audit_log.read_text().splitlines()]


@pytest.fixture(scope="module")
def proxy(anvil: Service, workdir: Path) -> Iterator[Proxy]:
    port = free_port()
    audit_log = workdir / "audit.jsonl"
    argv = [
        sys.executable,
        "-m",
        "mandate_firewall",
        "serve",
        "--upstream",
        anvil.url,
        "--port",
        str(port),
        "--audit-log",
        str(audit_log),
    ]
    service = start("proxy", argv, port, workdir)
    yield Proxy(service.url, service.process, service.log, audit_log)
    stop(service)
