"""End-to-end proxy behaviour against a mocked upstream node.

FakeNode records every request the proxy forwards, so tests can assert not
just what the agent got back but what did (or did not) reach the node.
"""

import json
import logging
import traceback
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
import respx
from eth_account import Account
from eth_utils import keccak
from fastapi.testclient import TestClient

from mandate_firewall.audit import AuditLog, AuditLogError
from mandate_firewall.config import Settings
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

UPSTREAM = "http://upstream.test:8545"
CHAIN_ID = 84532  # Base Sepolia
# Throwaway key used only in tests; never funded anywhere.
TEST_KEY = "0x" + "11" * 32
SENDER = Account.from_key(TEST_KEY).address
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


AUDIT_PATH = "logs/audit.jsonl"  # the default, relative to the working directory


@pytest.fixture(autouse=True)
def _in_tmp_dir(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # The proxy writes its audit log relative to the working directory; keep
    # it out of the repo.
    monkeypatch.chdir(tmp_path)


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


def make_client(node: FakeNode, **settings: Any) -> TestClient:
    cfg = Settings(_env_file=None, upstream_rpc_url=UPSTREAM, **settings)  # type: ignore[call-arg]
    return TestClient(create_app(cfg))


@pytest.fixture
def node() -> FakeNode:
    return FakeNode()


@pytest.fixture
def mock_upstream(node: FakeNode) -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.post(UPSTREAM).mock(side_effect=node)
        yield router


@pytest.fixture
def client(node: FakeNode, mock_upstream: respx.MockRouter) -> Iterator[TestClient]:
    with make_client(node) as c:
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
            with TestClient(create_app(cfg)):
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


def test_allowed_transaction_is_audited_once(client: TestClient) -> None:
    transfer = "0xa9059cbb" + "00" * 12 + RECIPIENT[2:].lower() + f"{10**30:064x}"
    raw = sign(to=RECIPIENT, value=0, gas=60_000, data=transfer)
    client.post("/", json=rpc("eth_sendRawTransaction", [raw]))
    (record,) = audit_records()
    assert record["decision"] == "allow"
    assert record["reason"] is None
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
