"""Run a real anvil node and a real `mandate-firewall serve` process in front
of it, and talk JSON-RPC to them.

No pytest here: the integration fixtures (conftest.py) and the v0.1 scenario
suite (benchmark/) both use these. A service that doesn't start raises
ServiceError, with its log attached."""

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from mandate_firewall.mandate.registry import RegistryError, load_registry
from tests.mandates import native_transfer_mandate, seed_store
from tests.net import free_port

STARTUP_TIMEOUT_SECONDS = 15.0
# anvil's dev account 0, the sender in the M1/M2 integration tests (public key).
DEV_ACCOUNT_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


class ServiceError(RuntimeError):
    """A service exited or wasn't ready in time."""


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


def start(
    name: str, argv: list[str], port: int, workdir: Path, env: dict[str, str] | None = None
) -> Service:
    log = workdir / f"{name}.log"
    with open(log, "wb") as out:
        process = subprocess.Popen(  # noqa: S603
            argv, cwd=workdir, stdout=out, stderr=subprocess.STDOUT, env=env
        )
    service = Service(f"http://127.0.0.1:{port}", process, log)

    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ServiceError(f"{name} exited with {process.returncode}:\n{log.read_text()}")
        try:
            if "result" in rpc_call(service.url, "eth_chainId"):
                return service
        except httpx.TransportError:
            time.sleep(0.1)
    stop(service)
    raise ServiceError(f"{name} not ready after {STARTUP_TIMEOUT_SECONDS}s:\n{log.read_text()}")


def stop(service: Service) -> None:
    service.process.terminate()
    try:
        service.process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        service.process.kill()
        service.process.wait()


@dataclass
class Proxy(Service):
    audit_log: Path
    mandate_db: Path

    def audit_records(self) -> list[dict[str, Any]]:
        if not self.audit_log.exists():
            return []
        return [json.loads(line) for line in self.audit_log.read_text().splitlines()]


def start_proxy(
    upstream: Service,
    workdir: Path,
    name: str = "proxy",
    env: dict[str, str] | None = None,
    mandate_db: Path | None = None,
    registry: Path | None = None,
) -> Proxy:
    """`mandate-firewall serve` in front of `upstream`, with its own private
    simulation fork (an anvil child process).

    Without `mandate_db`, the proxy gets its own store holding a broad
    mandate for dev account 0 (24 hours, 1000 transactions), so tests from
    before the M3 gate run unchanged. Tests of the gate pass their own.

    `registry` is a directory with the chain's registry file. Without it,
    the shipped registry is used, or a minimal one if none ships."""
    port = free_port()
    audit_log = workdir / f"{name}-audit.jsonl"
    if mandate_db is None:
        mandate_db = workdir / f"{name}-state" / "mandates.db"
        if not mandate_db.exists():
            chain_id = int(rpc_result(upstream.url, "eth_chainId"), 16)
            broad = native_transfer_mandate(
                chain_id, DEV_ACCOUNT_0, minutes=24 * 60, max_transactions=1000
            )
            seed_store(mandate_db, broad)
    if registry is None:
        registry = registry_dir(int(rpc_result(upstream.url, "eth_chainId"), 16), workdir)
    argv = [
        sys.executable,
        "-m",
        "mandate_firewall",
        "serve",
        "--upstream",
        upstream.url,
        "--port",
        str(port),
        "--audit-log",
        str(audit_log),
        "--mandate-db",
        str(mandate_db),
    ]
    if registry is not None:
        argv += ["--registry", str(registry)]
    service = start(name, argv, port, workdir, env)
    return Proxy(service.url, service.process, service.log, audit_log, mandate_db)


def registry_dir(chain_id: int, workdir: Path) -> Path | None:
    """Where the proxy finds a registry for `chain_id`: None for chains the
    firewall ships one for, else a directory with a minimal one (native ETH,
    no tokens or venues). Since M4 the proxy refuses to start without a
    registry for its chain, and anvil's default chain (31337) has none."""
    try:
        load_registry(chain_id)
        return None
    except RegistryError:
        pass
    directory = workdir / "registry"
    directory.mkdir(exist_ok=True)
    minimal = {
        "schema_version": 1,
        "chain_id": chain_id,
        "chain_name": f"local anvil (chain {chain_id})",
        "native": {"symbol": "ETH", "decimals": 18},
        "tokens": [],
        "venues": [],
    }
    (directory / f"{chain_id}.json").write_text(json.dumps(minimal))
    return directory
