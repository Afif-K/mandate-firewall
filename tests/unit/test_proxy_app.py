"""End-to-end proxy behaviour against a mocked upstream node.

FakeNode records every request the proxy forwards, so tests can assert not
just what the agent got back but what did (or did not) reach the node.
"""

import json
import logging
import sqlite3
import traceback
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from eth_account import Account
from eth_utils import keccak
from fastapi.testclient import TestClient

from mandate_firewall.audit import AuditLog, AuditLogError
from mandate_firewall.config import Settings
from mandate_firewall.mandate.store import MandateStore, MandateStoreError
from mandate_firewall.models import (
    CallFrame,
    CallType,
    DecodedTransaction,
    Effects,
    NativeBalanceChange,
    SimulationStatus,
)
from mandate_firewall.proxy import app as app_module
from mandate_firewall.proxy.app import UpstreamUnavailableError, create_app
from mandate_firewall.proxy.jsonrpc import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    RESOURCE_UNAVAILABLE,
    TRANSACTION_REJECTED,
)
from mandate_firewall.proxy.upstream import UpstreamClient
from mandate_firewall.simulate.node import SimulatorStartupError
from mandate_firewall.simulate.simulator import TransactionRejectedError
from tests.mandates import native_transfer_mandate, seed_store

UPSTREAM = "http://upstream.test:8545"
CHAIN_ID = 84532  # Base Sepolia
# Throwaway key used only in tests; never funded anywhere.
TEST_KEY = "0x" + "11" * 32
SENDER = Account.from_key(TEST_KEY).address
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


AUDIT_PATH = "logs/audit.jsonl"  # the default, relative to the working directory
MANDATE_DB = Path("state/mandates.db")  # likewise


@pytest.fixture(autouse=True)
def mandate_id(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    """Every test runs in its own directory, with an active mandate for
    SENDER in the default store: without one the proxy blocks everything."""
    # The proxy writes its audit log and reads its store relative to the
    # working directory; keep them out of the repo.
    monkeypatch.chdir(tmp_path)
    (mid,) = seed_store(MANDATE_DB, native_transfer_mandate(CHAIN_ID, SENDER, max_transactions=100))
    return mid


def audit_records() -> list[dict[str, Any]]:
    try:
        with open(AUDIT_PATH) as f:
            return [json.loads(line) for line in f]
    except FileNotFoundError:
        return []


class FakeNode:
    """A minimal JSON-RPC node: answers from `handlers`, records every call."""

    def __init__(self, chain_id: int = CHAIN_ID) -> None:
        self.calls: list[dict[str, Any]] = []
        self.errors: dict[str, dict[str, Any]] = {}  # method -> JSON-RPC error object
        self.handlers: dict[str, Callable[[Any], Any]] = {
            "eth_chainId": lambda params: hex(chain_id),
            "eth_getBalance": lambda params: "0xde0b6b3a7640000",
            "eth_getTransactionReceipt": lambda params: None,
            "eth_sendRawTransaction": self._send_raw,
        }

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.calls.append(body)
        handler = self.handlers.get(body["method"])
        if body["method"] in self.errors:
            payload = {"error": self.errors[body["method"]]}
        elif handler is None:
            payload = {"error": {"code": -32601, "message": "method not found"}}
        else:
            payload = {"result": handler(body.get("params"))}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], **payload})

    @staticmethod
    def _send_raw(params: list[str]) -> str:
        return "0x" + keccak(hexstr=params[0]).hex()  # a node returns the tx hash

    @property
    def methods(self) -> list[str]:
        return [c["method"] for c in self.calls]


class FakeSimulator:
    """Stands in for the anvil fork: records what it was asked to simulate
    and returns plausible effects, a revert, or raises `outcome`."""

    def __init__(self) -> None:
        self.txs: list[DecodedTransaction] = []
        self.outcome: str | BaseException = "success"
        self.chain_id: int | None = None  # what the proxy started it with

    async def simulate(self, tx: DecodedTransaction) -> Effects:
        self.txs.append(tx)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        reverted = self.outcome == "revert"
        return Effects(
            tx_hash=tx.hash,
            sender=tx.sender,
            chain_id=CHAIN_ID,
            fork_block_number=1234,
            fork_block_hash="0x" + "22" * 32,
            status=SimulationStatus.REVERTED if reverted else SimulationStatus.SUCCESS,
            revert_data="0x" if reverted else None,
            gas_used=21_000,
            effective_gas_price=1,
            gas_cost=21_000,
            native_balance_changes=(NativeBalanceChange(address=tx.sender, delta=-21_000),),
            calls=(CallFrame(depth=0, call_type=CallType.CALL, caller=tx.sender, target=tx.to),),
        )

    def factory(self, settings: Settings, upstream: UpstreamClient, chain_id: int) -> Any:
        @asynccontextmanager
        async def running() -> AsyncIterator["FakeSimulator"]:
            self.chain_id = chain_id
            yield self

        return running()


def make_client(node: FakeNode, simulator: FakeSimulator | None = None, **settings: Any):
    cfg = Settings(_env_file=None, upstream_rpc_url=UPSTREAM, **settings)  # type: ignore[call-arg]
    return TestClient(create_app(cfg, (simulator or FakeSimulator()).factory))


@pytest.fixture
def node() -> FakeNode:
    return FakeNode()


@pytest.fixture
def mock_upstream(node: FakeNode) -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.post(UPSTREAM).mock(side_effect=node)
        yield router


@pytest.fixture
def simulator() -> FakeSimulator:
    return FakeSimulator()


@pytest.fixture
def client(
    node: FakeNode, simulator: FakeSimulator, mock_upstream: respx.MockRouter
) -> Iterator[TestClient]:
    with make_client(node, simulator) as c:
        assert node.methods == ["eth_chainId"]  # the startup check
        node.calls.clear()
        yield c


def rpc(method: str, params: Any = None, request_id: Any = 1) -> dict[str, Any]:
    req: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        req["params"] = params
    return req


def sign(**overrides: Any) -> str:
    tx: dict[str, Any] = {
        "type": 2,
        "chainId": CHAIN_ID,
        "nonce": 0,
        "maxPriorityFeePerGas": 1_000_000_000,
        "maxFeePerGas": 3_000_000_000,
        "gas": 21_000,
        "to": RECIPIENT,
        "value": 10**15,
        "data": b"",
    }
    tx.update(overrides)
    for key in [k for k, v in tx.items() if v is None]:
        del tx[key]
    return "0x" + bytes(Account.sign_transaction(tx, TEST_KEY).raw_transaction).hex()


def error_code(response: dict[str, Any]) -> int:
    assert "result" not in response
    return response["error"]["code"]


# --- startup ----------------------------------------------------------------------


def test_startup_fetches_chain_id(client: TestClient) -> None:
    assert client.app.state.proxy.chain_id == CHAIN_ID  # type: ignore[attr-defined]


def test_refuses_to_start_when_upstream_unreachable(node: FakeNode) -> None:
    with respx.mock() as router:
        router.post(UPSTREAM).mock(side_effect=httpx.ConnectError("connection refused"))
        with pytest.raises(UpstreamUnavailableError, match="cannot fetch chain id"):
            with make_client(node):
                pass


def test_refuses_to_start_when_chain_id_call_fails(node: FakeNode) -> None:
    del node.handlers["eth_chainId"]
    with respx.mock() as router:
        router.post(UPSTREAM).mock(side_effect=node)
        with pytest.raises(UpstreamUnavailableError):
            with make_client(node):
                pass


def test_refuses_to_start_when_audit_log_unwritable(
    node: FakeNode, mock_upstream: respx.MockRouter, tmp_path: Any
) -> None:
    (tmp_path / "not-a-dir").write_text("")
    with pytest.raises(AuditLogError, match="cannot open audit log"):
        with make_client(node, audit_log_path=tmp_path / "not-a-dir" / "audit.jsonl"):
            pass
    assert node.calls == []


def test_startup_error_does_not_leak_url_path() -> None:
    url = "http://upstream.test:8545/v2/SECRET-API-KEY"
    with respx.mock() as router:
        router.post(url).mock(side_effect=httpx.ConnectError(f"failed: {url}"))
        cfg = Settings(_env_file=None, upstream_rpc_url=url)  # type: ignore[call-arg]
        with pytest.raises(UpstreamUnavailableError) as excinfo:
            with TestClient(create_app(cfg, FakeSimulator().factory)):
                pass
    # The server logs the whole traceback, chained causes included.
    full_traceback = "".join(traceback.format_exception(excinfo.value))
    assert "SECRET-API-KEY" not in full_traceback
    assert "upstream.test:8545" in str(excinfo.value)


# --- forwarding -------------------------------------------------------------------


def test_forwards_read_only_method(client: TestClient, node: FakeNode) -> None:
    response = client.post("/", json=rpc("eth_getBalance", [SENDER, "latest"], request_id="abc"))
    assert response.status_code == 200
    assert response.json() == {"jsonrpc": "2.0", "id": "abc", "result": "0xde0b6b3a7640000"}
    assert node.calls[0]["params"] == [SENDER, "latest"]


def test_forwarded_request_is_rebuilt(client: TestClient, node: FakeNode) -> None:
    request = rpc("eth_getBalance", [SENDER, "latest"], request_id=7) | {"extra": "smuggled"}
    client.post("/", json=request)
    (forwarded,) = node.calls
    assert set(forwarded) == {"jsonrpc", "id", "method", "params"}
    assert "extra" not in forwarded


def test_null_result_is_returned(client: TestClient) -> None:
    body = client.post("/", json=rpc("eth_getTransactionReceipt", ["0x" + "00" * 32])).json()
    assert body == {"jsonrpc": "2.0", "id": 1, "result": None}


def test_upstream_error_is_passed_through(client: TestClient, node: FakeNode) -> None:
    body = client.post("/", json=rpc("eth_blockNumber", [])).json()
    assert body["error"] == {"code": -32601, "message": "method not found"}
    assert node.methods == ["eth_blockNumber"]


def test_upstream_down_after_startup(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    mock_upstream.routes.clear()
    mock_upstream.post(UPSTREAM).mock(side_effect=httpx.ConnectError("gone"))
    body = client.post("/", json=rpc("eth_getBalance", [SENDER, "latest"])).json()
    assert error_code(body) == RESOURCE_UNAVAILABLE


# --- default deny -----------------------------------------------------------------


@pytest.mark.parametrize(
    "method", ["eth_sendTransaction", "eth_sign", "anvil_setBalance", "eth_accounts", "foo"]
)
def test_denied_methods_never_reach_upstream(
    client: TestClient, node: FakeNode, method: str
) -> None:
    body = client.post("/", json=rpc(method, [])).json()
    assert error_code(body) == METHOD_NOT_FOUND
    assert body["id"] == 1
    assert node.calls == []
    assert audit_records() == []


# --- malformed requests -----------------------------------------------------------


def post_raw(client: TestClient, content: bytes | str, **headers: str) -> httpx.Response:
    return client.post(
        "/", content=content, headers={"content-type": "application/json", **headers}
    )


@pytest.mark.parametrize("content", ["{", "", '{"id": NaN}', "[1,", "nul"])
def test_parse_error(client: TestClient, node: FakeNode, content: str) -> None:
    body = post_raw(client, content).json()
    assert body["id"] is None and error_code(body) == PARSE_ERROR
    assert node.calls == []


@pytest.mark.parametrize(
    ("request_obj", "echo_id"),
    [
        ("just a string", None),
        (42, None),
        ({"jsonrpc": "2.0", "method": "eth_getBalance"}, None),  # notification
        ({"id": 1, "method": "eth_blockNumber"}, 1),  # no jsonrpc
        ({"jsonrpc": "1.0", "id": 1, "method": "eth_blockNumber"}, 1),
        ({"jsonrpc": "2.0", "id": 1}, 1),  # no method
        ({"jsonrpc": "2.0", "id": 1, "method": 5}, 1),
        ({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": "x"}, 1),
        ({"jsonrpc": "2.0", "id": True, "method": "eth_blockNumber"}, None),
        ({"jsonrpc": "2.0", "id": 1.5, "method": "eth_blockNumber"}, None),
        ({"jsonrpc": "2.0", "id": [1], "method": "eth_blockNumber"}, None),
        ({"jsonrpc": "2.0", "id": 1, "method": "eth_" + "x" * 200}, 1),
    ],
)
def test_invalid_requests(
    client: TestClient, node: FakeNode, request_obj: Any, echo_id: Any
) -> None:
    body = client.post("/", json=request_obj).json()
    assert error_code(body) == INVALID_REQUEST
    assert body["id"] == echo_id
    assert node.calls == []


@pytest.mark.parametrize("content_type", [None, "text/plain", "application/x-www-form-urlencoded"])
def test_requires_json_content_type(
    client: TestClient, node: FakeNode, content_type: str | None
) -> None:
    headers = {"content-type": content_type} if content_type else {}
    response = client.post("/", content=json.dumps(rpc("eth_chainId", [])), headers=headers)
    assert response.status_code == 415
    assert node.calls == []


def test_accepts_json_content_type_with_charset(client: TestClient) -> None:
    response = post_raw(
        client,
        json.dumps(rpc("eth_getBalance", [SENDER, "latest"])),
        **{"content-type": "application/json; charset=utf-8"},
    )
    assert "result" in response.json()


def test_no_cors_preflight(client: TestClient) -> None:
    # A browser sends this before a cross-origin JSON POST. Without an
    # Access-Control-Allow-Origin reply, it never sends the POST.
    response = client.options(
        "/",
        headers={
            "origin": "https://evil.example",
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type",
        },
    )
    assert response.status_code == 405
    assert "access-control-allow-origin" not in response.headers


def test_rejects_oversized_body(
    client: TestClient, node: FakeNode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "MAX_REQUEST_BYTES", 64)
    response = client.post("/", json=rpc("eth_getBalance", [SENDER, "latest"]))
    assert response.status_code == 413
    assert node.calls == []


def test_only_post_root(client: TestClient) -> None:
    assert client.get("/").status_code == 405
    assert client.get("/docs").status_code == 404
    assert client.post("/other", json=rpc("eth_chainId", [])).status_code == 404


# --- batches ----------------------------------------------------------------------


def test_batch_mixed(client: TestClient, node: FakeNode) -> None:
    batch = [
        rpc("eth_getBalance", [SENDER, "latest"], request_id=1),
        rpc("anvil_setBalance", [SENDER, "0x1"], request_id=2),
        {"jsonrpc": "2.0", "id": 3},
        "garbage",
        rpc("eth_getTransactionReceipt", ["0x" + "00" * 32], request_id="four"),
    ]
    body = client.post("/", json=batch).json()
    assert [r["id"] for r in body] == [1, 2, 3, None, "four"]
    assert body[0]["result"] == "0xde0b6b3a7640000"
    assert error_code(body[1]) == METHOD_NOT_FOUND
    assert error_code(body[2]) == INVALID_REQUEST
    assert error_code(body[3]) == INVALID_REQUEST
    assert body[4]["result"] is None
    assert node.methods == ["eth_getBalance", "eth_getTransactionReceipt"]


def test_batch_forwards_transactions_in_order(client: TestClient, node: FakeNode) -> None:
    txs = [sign(nonce=n) for n in range(3)]
    batch = [rpc("eth_sendRawTransaction", [tx], request_id=i) for i, tx in enumerate(txs)]
    body = client.post("/", json=batch).json()
    assert all("result" in r for r in body)
    assert [c["params"][0] for c in node.calls] == txs
    assert [r["raw"] for r in audit_records()] == txs


def test_empty_batch(client: TestClient, node: FakeNode) -> None:
    body = client.post("/", json=[]).json()
    assert isinstance(body, dict) and error_code(body) == INVALID_REQUEST


def test_batch_too_large(client: TestClient, node: FakeNode) -> None:
    batch = [rpc("eth_chainId", [], request_id=i) for i in range(app_module.MAX_BATCH_SIZE + 1)]
    body = client.post("/", json=batch).json()
    assert isinstance(body, dict) and error_code(body) == INVALID_REQUEST
    assert node.calls == []


# --- eth_sendRawTransaction -------------------------------------------------------


def test_valid_transaction_is_decoded_logged_and_forwarded(
    client: TestClient, node: FakeNode, caplog: pytest.LogCaptureFixture
) -> None:
    raw = sign()
    with caplog.at_level(logging.INFO, logger="mandate_firewall"):
        body = client.post("/", json=rpc("eth_sendRawTransaction", [raw])).json()
    tx_hash = "0x" + keccak(hexstr=raw).hex()
    assert body == {"jsonrpc": "2.0", "id": 1, "result": tx_hash}
    assert node.calls[0]["params"] == [raw]
    assert f"intercepted tx {tx_hash}" in caplog.text
    assert f"from={SENDER}" in caplog.text


def test_allowed_transaction_is_audited_once(client: TestClient, mandate_id: str) -> None:
    transfer = "0xa9059cbb" + "00" * 12 + RECIPIENT[2:].lower() + f"{10**30:064x}"
    raw = sign(to=RECIPIENT, value=0, gas=60_000, data=transfer)
    client.post("/", json=rpc("eth_sendRawTransaction", [raw]))
    (record,) = audit_records()
    assert record["decision"] == "allow"
    assert record["reason"] is None
    assert (record["mandate_id"], record["mandate_transaction"]) == (mandate_id, 1)
    assert record["hash"] == "0x" + keccak(hexstr=raw).hex()
    assert record["tx_type"] == 2
    assert record["chain_id"] == str(CHAIN_ID)
    assert record["sender"] == SENDER
    assert record["to"] == RECIPIENT
    assert record["value"] == "0"
    assert record["gas_limit"] == "60000"
    assert record["max_fee_per_gas"] == "3000000000"
    assert record["max_priority_fee_per_gas"] == "1000000000"
    assert record["gas_price"] is None
    assert record["selector"] == "0xa9059cbb"
    assert record["call"]["signature"] == "transfer(address,uint256)"
    # uint256 arguments are strings: 10**30 doesn't survive a float round-trip.
    assert record["call"]["args"][1] == {
        "name": "amount",
        "abi_type": "uint256",
        "value": str(10**30),
    }
    assert record["raw"] == raw


def test_upstream_rejection_still_audited_as_allowed(client: TestClient, node: FakeNode) -> None:
    # The audit line records the firewall's decision, written before forwarding.
    node.errors["eth_sendRawTransaction"] = {"code": -32000, "message": "nonce too low"}
    client.post("/", json=rpc("eth_sendRawTransaction", [sign()]))
    assert [r["decision"] for r in audit_records()] == ["allow"]


def test_audit_write_failure_blocks_transaction(
    client: TestClient, node: FakeNode, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(self: AuditLog, record: Any) -> None:
        raise AuditLogError("disk full")

    monkeypatch.setattr(AuditLog, "write", fail)
    body = client.post("/", json=rpc("eth_sendRawTransaction", [sign()])).json()
    assert error_code(body) == TRANSACTION_REJECTED
    assert "audit log unavailable" in body["error"]["message"]
    assert node.calls == []


def test_read_methods_are_not_audited(client: TestClient) -> None:
    client.post("/", json=rpc("eth_getBalance", [SENDER, "latest"]))
    client.post("/", json=rpc("eth_sendRawTransaction", [123]))  # invalid params: not a tx
    assert audit_records() == []


def test_forwards_the_exact_decoded_bytes(client: TestClient, node: FakeNode) -> None:
    raw = sign()
    client.post("/", json=rpc("eth_sendRawTransaction", ["0x" + raw[2:].upper()]))
    assert node.calls[0]["params"] == [raw]  # normalised to what the decoder saw


def test_upstream_rejection_is_passed_through(client: TestClient, node: FakeNode) -> None:
    error = {"code": -32000, "message": "nonce too low", "data": {"nonce": 5}}
    node.errors["eth_sendRawTransaction"] = error
    body = client.post("/", json=rpc("eth_sendRawTransaction", [sign()])).json()
    assert body == {"jsonrpc": "2.0", "id": 1, "error": error}


def test_wrong_chain_id_is_rejected(client: TestClient, node: FakeNode) -> None:
    body = client.post("/", json=rpc("eth_sendRawTransaction", [sign(chainId=1)])).json()
    assert error_code(body) == TRANSACTION_REJECTED
    assert "chain id 1 does not match upstream chain id 84532" in body["error"]["message"]
    assert node.calls == []
    (record,) = audit_records()
    assert record["decision"] == "block"
    assert record["chain_id"] == "1"
    assert record["reason"] == "chain id 1 does not match upstream chain id 84532"


def unprotected_legacy() -> str:
    return sign(
        type=None, chainId=None, maxPriorityFeePerGas=None, maxFeePerGas=None, gasPrice=10**9
    )


def test_unprotected_legacy_is_rejected_by_default(client: TestClient, node: FakeNode) -> None:
    body = client.post("/", json=rpc("eth_sendRawTransaction", [unprotected_legacy()])).json()
    assert error_code(body) == TRANSACTION_REJECTED
    assert "EIP-155" in body["error"]["message"]
    assert node.calls == []


def test_unprotected_legacy_allowed_when_opted_in(
    node: FakeNode, mock_upstream: respx.MockRouter
) -> None:
    with make_client(node, allow_legacy_unprotected=True) as c:
        body = c.post("/", json=rpc("eth_sendRawTransaction", [unprotected_legacy()])).json()
    assert "result" in body


def test_eip155_legacy_is_accepted(client: TestClient, node: FakeNode) -> None:
    raw = sign(type=None, maxPriorityFeePerGas=None, maxFeePerGas=None, gasPrice=10**9)
    body = client.post("/", json=rpc("eth_sendRawTransaction", [raw])).json()
    assert "result" in body
    assert node.methods == ["eth_sendRawTransaction"]


@pytest.mark.parametrize(
    "raw",
    [
        "0x",
        "0xzz",
        "deadbeef",  # missing 0x
        "0x03c0",  # blob transaction type
        "0x04c0",  # EIP-7702 set-code type
        "0xc0",  # empty legacy list
    ],
)
def test_undecodable_transactions_are_rejected(
    client: TestClient, node: FakeNode, raw: str
) -> None:
    body = client.post("/", json=rpc("eth_sendRawTransaction", [raw])).json()
    assert error_code(body) == TRANSACTION_REJECTED
    assert node.calls == []
    (record,) = audit_records()
    assert record["decision"] == "block"
    assert record["hash"] is None and record["call"] is None
    assert record["raw"] == raw


@pytest.mark.parametrize("params", [None, [], ["0x00", "0x00"], [123], {"tx": "0x00"}, [["0x00"]]])
def test_bad_send_raw_params(client: TestClient, node: FakeNode, params: Any) -> None:
    body = client.post("/", json=rpc("eth_sendRawTransaction", params)).json()
    assert error_code(body) == INVALID_PARAMS
    assert node.calls == []


# --- simulation -------------------------------------------------------------------


def test_simulator_starts_with_the_verified_chain_id(
    client: TestClient, simulator: FakeSimulator
) -> None:
    assert simulator.chain_id == CHAIN_ID


def test_refuses_to_start_when_simulator_fails(node: FakeNode) -> None:
    def failing(settings: Settings, upstream: UpstreamClient, chain_id: int) -> Any:
        @asynccontextmanager
        async def running() -> AsyncIterator[None]:
            secret = ValueError("cannot reach http://upstream.test/v2/SECRET-API-KEY")
            raise SimulatorStartupError("simulation node failed to start") from secret
            yield

        return running()

    with respx.mock() as router:
        router.post(UPSTREAM).mock(side_effect=node)
        cfg = Settings(_env_file=None, upstream_rpc_url=UPSTREAM)  # type: ignore[call-arg]
        with pytest.raises(SimulatorStartupError) as excinfo:
            with TestClient(create_app(cfg, failing)):
                pass
    assert "SECRET-API-KEY" not in "".join(traceback.format_exception(excinfo.value))


def test_allowed_transaction_is_simulated_and_its_effects_audited(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    raw = sign()
    body = client.post("/", json=rpc("eth_sendRawTransaction", [raw])).json()
    assert "result" in body
    (tx,) = simulator.txs
    assert tx.raw == raw
    assert node.methods == ["eth_sendRawTransaction"]
    (record,) = audit_records()
    assert record["decision"] == "allow"
    assert record["simulation_error"] is None
    effects = record["effects"]
    assert (effects["tx_hash"], effects["status"]) == (tx.hash, "success")
    assert effects["native_balance_changes"] == [{"address": SENDER, "delta": "-21000"}]


def test_reverting_transaction_is_blocked(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    simulator.outcome = "revert"
    body = client.post("/", json=rpc("eth_sendRawTransaction", [sign()])).json()
    assert error_code(body) == TRANSACTION_REJECTED
    assert body["error"]["message"] == "transaction rejected: transaction reverts in simulation"
    assert node.calls == []
    (record,) = audit_records()
    assert record["decision"] == "block"
    assert record["effects"]["status"] == "reverted"  # what it would have done


def test_simulation_error_blocks_with_its_reason(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    reason = "the simulated chain rejected the transaction: nonce too low"
    simulator.outcome = TransactionRejectedError(reason)
    body = client.post("/", json=rpc("eth_sendRawTransaction", [sign()])).json()
    assert error_code(body) == TRANSACTION_REJECTED
    assert body["error"]["message"] == f"transaction rejected: {reason}"
    assert node.calls == []
    (record,) = audit_records()
    assert (record["decision"], record["simulation_error"], record["effects"]) == (
        "block",
        reason,
        None,
    )


def test_simulator_crash_blocks_without_leaking_details(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    simulator.outcome = RuntimeError("internal detail: http://upstream.test/v2/SECRET")
    body = client.post("/", json=rpc("eth_sendRawTransaction", [sign()])).json()
    assert error_code(body) == TRANSACTION_REJECTED
    assert body["error"]["message"] == "transaction rejected: simulation failed: internal error"
    assert "SECRET" not in json.dumps(audit_records())
    assert node.calls == []


def test_transactions_blocked_by_checks_are_not_simulated(
    client: TestClient, simulator: FakeSimulator
) -> None:
    client.post("/", json=rpc("eth_sendRawTransaction", [sign(chainId=1)]))
    client.post("/", json=rpc("eth_sendRawTransaction", ["0xdeadbeef"]))
    assert simulator.txs == []


# --- mandate gate (M3) --------------------------------------------------------------

OTHER_KEY = "0x" + "22" * 32  # a second throwaway sender, with no mandate
OTHER = Account.from_key(OTHER_KEY).address


def sign_as(key: str, **overrides: Any) -> str:
    tx: dict[str, Any] = {
        "type": 2,
        "chainId": CHAIN_ID,
        "nonce": 0,
        "maxPriorityFeePerGas": 1_000_000_000,
        "maxFeePerGas": 3_000_000_000,
        "gas": 21_000,
        "to": RECIPIENT,
        "value": 10**15,
    } | overrides
    return "0x" + bytes(Account.sign_transaction(tx, key).raw_transaction).hex()


def send(client: TestClient, raw: str) -> dict[str, Any]:
    return client.post("/", json=rpc("eth_sendRawTransaction", [raw])).json()


def writer() -> MandateStore:
    """The store as the capture CLI opens it, next to the running proxy."""
    return MandateStore(MANDATE_DB)


def assert_blocked(
    body: dict[str, Any], node: FakeNode, simulator: FakeSimulator, reason: str
) -> dict[str, Any]:
    """Blocked with -32003 before simulation, never forwarded, audited once."""
    assert error_code(body) == TRANSACTION_REJECTED
    assert body["error"]["message"] == f"transaction rejected: {reason}"
    assert node.calls == []
    assert simulator.txs == []
    (record,) = audit_records()
    assert (record["decision"], record["reason"]) == ("block", reason)
    assert record["mandate_transaction"] is None
    return record


def test_refuses_to_start_without_mandate_store(
    node: FakeNode, mock_upstream: respx.MockRouter, tmp_path: Path
) -> None:
    with pytest.raises(MandateStoreError, match="does not exist"):
        with make_client(node, mandate_db_path=tmp_path / "missing.db"):
            pass
    assert node.calls == []  # checked before the upstream is even contacted
    assert not (tmp_path / "missing.db").exists()  # and never created


def test_refuses_to_start_with_an_uninitialized_store(
    node: FakeNode, mock_upstream: respx.MockRouter, tmp_path: Path
) -> None:
    empty = tmp_path / "empty.db"
    empty.touch(mode=0o600)
    with pytest.raises(MandateStoreError, match="not an initialized mandate store"):
        with make_client(node, mandate_db_path=empty):
            pass
    assert empty.stat().st_size == 0  # the proxy never creates the schema


def test_refuses_to_start_with_a_tampered_store(
    node: FakeNode, mock_upstream: respx.MockRouter
) -> None:
    tamper_expiry(MANDATE_DB)
    with pytest.raises(MandateStoreError, match="lookup columns do not match"):
        with make_client(node):
            pass
    assert node.calls == []


def test_proxy_opens_the_store_counters_only(client: TestClient) -> None:
    proxy = client.app.state.proxy  # type: ignore[attr-defined]
    assert proxy.mandates.counters_only
    with pytest.raises(MandateStoreError, match="counters-only"):
        proxy.mandates.add(native_transfer_mandate(CHAIN_ID, OTHER))
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        proxy.mandates._db.execute("DROP TRIGGER mandates_no_update")


def test_no_mandate_is_blocked(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    body = send(client, sign_as(OTHER_KEY))
    reason = f"no mandate for sender {OTHER} on chain {CHAIN_ID}"
    record = assert_blocked(body, node, simulator, reason)
    assert record["mandate_id"] is None


def test_mandate_for_another_chain_does_not_count(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    seed_store(MANDATE_DB, native_transfer_mandate(1, OTHER))
    body = send(client, sign_as(OTHER_KEY))
    assert_blocked(body, node, simulator, f"no mandate for sender {OTHER} on chain {CHAIN_ID}")


def test_expired_mandate_is_blocked(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    created = datetime.now(UTC) - timedelta(hours=2)
    (mid,) = seed_store(
        MANDATE_DB,
        native_transfer_mandate(CHAIN_ID, OTHER, created_at=created, minutes=60),
        at=created + timedelta(minutes=1),  # written while it was still valid
    )
    body = send(client, sign_as(OTHER_KEY))
    record = assert_blocked(body, node, simulator, f"mandate {mid} is expired")
    assert record["mandate_id"] is None  # nothing was charged to it


def test_revoked_mandate_is_blocked(
    client: TestClient, node: FakeNode, simulator: FakeSimulator, mandate_id: str
) -> None:
    assert writer().revoke(mandate_id)  # while the proxy is running
    body = send(client, sign())
    assert_blocked(body, node, simulator, f"mandate {mandate_id} is revoked")


def test_transaction_cap_is_enforced(
    client: TestClient, node: FakeNode, simulator: FakeSimulator
) -> None:
    (mid,) = seed_store(MANDATE_DB, native_transfer_mandate(CHAIN_ID, OTHER, max_transactions=2))
    for nonce in (0, 1):
        assert "result" in send(client, sign_as(OTHER_KEY, nonce=nonce))
    assert [r["mandate_transaction"] for r in audit_records()] == [1, 2]
    assert writer().get(mid).status == "exhausted"

    node.calls.clear()
    simulator.txs.clear()
    body = send(client, sign_as(OTHER_KEY, nonce=2))
    assert error_code(body) == TRANSACTION_REJECTED
    reason = f"mandate {mid} is exhausted (2 of 2 transactions used)"
    assert body["error"]["message"] == f"transaction rejected: {reason}"
    assert node.calls == [] and simulator.txs == []
    assert audit_records()[-1]["reason"] == reason


def test_blocked_transactions_are_not_charged(
    client: TestClient, node: FakeNode, simulator: FakeSimulator, mandate_id: str
) -> None:
    simulator.outcome = "revert"
    send(client, sign())
    simulator.outcome = TransactionRejectedError("nonce too low")
    send(client, sign())
    assert node.calls == []
    assert writer().get(mandate_id).transactions == 0
    # Blocked after the gate: the record says which mandate it was checked against.
    assert [(r["decision"], r["mandate_id"]) for r in audit_records()] == [
        ("block", mandate_id),
        ("block", mandate_id),
    ]


def test_mandate_revoked_during_simulation_is_blocked(
    client: TestClient, node: FakeNode, simulator: FakeSimulator, mandate_id: str
) -> None:
    # The lookup passes, then the user revokes while the fork is simulating.
    # The charge after simulation re-checks, so the transaction is blocked.
    original = simulator.simulate

    async def revoke_then_simulate(tx: DecodedTransaction) -> Effects:
        assert writer().revoke(mandate_id)
        return await original(tx)

    simulator.simulate = revoke_then_simulate  # type: ignore[method-assign]
    body = send(client, sign())
    assert error_code(body) == TRANSACTION_REJECTED
    assert body["error"]["message"] == f"transaction rejected: mandate {mandate_id} is revoked"
    assert node.calls == []
    (record,) = audit_records()
    assert (record["decision"], record["mandate_id"]) == ("block", mandate_id)
    assert record["effects"] is not None  # what it would have done


def tamper_expiry(path: Path) -> None:
    """Edit a lookup column the way someone with write access to the file
    could: drop the trigger that stops UPDATE, then extend the expiry."""
    db = sqlite3.connect(path, isolation_level=None)
    db.execute("DROP TRIGGER mandates_no_update")
    db.execute("UPDATE mandates SET expires_at = '2099-01-01T00:00:00Z'")
    db.close()


def test_tampered_store_row_is_blocked(
    client: TestClient,
    node: FakeNode,
    simulator: FakeSimulator,
    caplog: pytest.LogCaptureFixture,
) -> None:
    tamper_expiry(MANDATE_DB)  # after startup, so the startup scan can't catch it
    with caplog.at_level(logging.ERROR, logger="mandate_firewall"):
        body = send(client, sign())
    assert_blocked(body, node, simulator, "mandate store integrity failure")
    assert "lookup columns do not match content" in caplog.text  # details: operator only


def test_store_error_is_blocked(
    client: TestClient,
    node: FakeNode,
    simulator: FakeSimulator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(self: MandateStore, chain_id: int, principal: str) -> None:
        raise MandateStoreError("cannot read mandate store: disk I/O error")

    monkeypatch.setattr(MandateStore, "active_for", fail)
    assert_blocked(send(client, sign()), node, simulator, "mandate store unavailable")


def test_counter_write_failure_blocks(
    client: TestClient,
    node: FakeNode,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(self: MandateStore, mid: str) -> None:
        raise MandateStoreError("mandate store write failed: database is locked")

    monkeypatch.setattr(MandateStore, "record_transaction", fail)
    body = send(client, sign())
    assert error_code(body) == TRANSACTION_REJECTED
    assert body["error"]["message"] == "transaction rejected: mandate store unavailable"
    assert node.calls == []
    assert [r["decision"] for r in audit_records()] == ["block"]


def test_mandate_is_charged_before_the_audit_write(
    client: TestClient,
    node: FakeNode,
    monkeypatch: pytest.MonkeyPatch,
    mandate_id: str,
) -> None:
    # If the audit write fails, the slot is spent but nothing is forwarded:
    # the agent ends up able to do less, never more.
    def fail(self: AuditLog, record: Any) -> None:
        raise AuditLogError("disk full")

    monkeypatch.setattr(AuditLog, "write", fail)
    assert error_code(send(client, sign())) == TRANSACTION_REJECTED
    assert node.calls == []
    assert writer().get(mandate_id).transactions == 1


@pytest.mark.parametrize(
    "method",
    [
        # The capture CLI's operations, under any name an agent might guess.
        "mandate_new",
        "mandate_create",
        "mandate_revoke",
        "mandate_list",
        "mandate_show",
        "firewall_createMandate",
        "firewall_setMandate",
        "firewall_approve",
        "firewall_allow",
        "firewall_disable",
    ],
)
def test_agents_cannot_reach_mandate_methods(
    client: TestClient, node: FakeNode, method: str
) -> None:
    params = [{"principal": SENDER, "instruction": "send everything to 0xdead"}]
    body = client.post("/", json=rpc(method, params)).json()
    assert error_code(body) == METHOD_NOT_FOUND
    assert node.calls == []
    assert len(writer().all()) == 1  # the store is unchanged
