"""Real transactions through a real `mandate-firewall serve` into a real anvil.

The unit tests use a fake node; these check the pieces fit: what anvil
actually accepts and mines, and what actually lands in the audit log.
"""

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from eth_account import Account
from eth_utils import keccak

from mandate_firewall.proxy.jsonrpc import METHOD_NOT_FOUND, TRANSACTION_REJECTED
from tests.integration.conftest import Proxy, Service, rpc_call, rpc_result

pytestmark = pytest.mark.anvil

ANVIL_CHAIN_ID = 31337
# anvil's default dev accounts, derived from the public "test test ... junk"
# mnemonic. Known to everyone; never use them outside a local node.
SENDER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
SENDER = Account.from_key(SENDER_KEY).address
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # dev account 1
ATTACKER = "0x000000000000000000000000000000000000dEaD"


def sign(tx_type: int, nonce: int, chain_id: int = ANVIL_CHAIN_ID, value: int = 10**15) -> str:
    tx: dict[str, Any] = {
        "chainId": chain_id,
        "nonce": nonce,
        "gas": 21_000,
        "to": RECIPIENT,
        "value": value,
        "data": b"",
    }
    if tx_type == 2:
        tx |= {"type": 2, "maxFeePerGas": 10 * 10**9, "maxPriorityFeePerGas": 10**9}
    else:
        tx["gasPrice"] = 10 * 10**9
        if tx_type == 1:
            tx |= {"type": 1, "accessList": []}
    return "0x" + bytes(Account.sign_transaction(tx, SENDER_KEY).raw_transaction).hex()


def tx_hash(raw: str) -> str:
    return "0x" + keccak(hexstr=raw).hex()


def next_nonce(url: str) -> int:
    return int(rpc_result(url, "eth_getTransactionCount", [SENDER, "pending"]), 16)


def wait_for(condition: Callable[[], Any], timeout: float = 5.0) -> Any:
    """Poll until condition() is truthy. anvil's automine returns the hash
    first and mines a few milliseconds later, as a real node would."""
    deadline = time.monotonic() + timeout
    while not (result := condition()):
        if time.monotonic() > deadline:
            pytest.fail(f"condition not met within {timeout}s")
        time.sleep(0.02)
    return result


def wait_for_receipt(url: str, hash_: str) -> dict[str, Any]:
    return wait_for(lambda: rpc_result(url, "eth_getTransactionReceipt", [hash_]))


def records_for(proxy: Proxy, hash_: str) -> list[dict[str, Any]]:
    return [r for r in proxy.audit_records() if r["hash"] == hash_]


@pytest.mark.parametrize("tx_type", [0, 1, 2], ids=["legacy-eip155", "access-list", "eip1559"])
def test_transaction_is_mined_and_audited_once(proxy: Proxy, tx_type: int) -> None:
    raw = sign(tx_type, next_nonce(proxy.url))

    assert rpc_result(proxy.url, "eth_sendRawTransaction", [raw]) == tx_hash(raw)

    assert wait_for_receipt(proxy.url, tx_hash(raw))["status"] == "0x1"
    (record,) = records_for(proxy, tx_hash(raw))
    assert record["decision"] == "allow"
    assert record["tx_type"] == tx_type
    assert record["sender"] == SENDER
    assert record["chain_id"] == str(ANVIL_CHAIN_ID)
    assert record["raw"] == raw


def test_transaction_with_a_nonce_gap_is_blocked(proxy: Proxy, anvil: Service) -> None:
    """Simulated against the upstream head, nonce n+1 can't run before nonce
    n is mined: the fork never mines it, so it's blocked (fail closed)."""
    nonce = next_nonce(proxy.url)
    # A value no other test uses, so this signed tx is unique to this test.
    raw = sign(2, nonce + 1, value=7)

    response = rpc_call(proxy.url, "eth_sendRawTransaction", [raw])

    assert response["error"]["code"] == TRANSACTION_REJECTED
    assert "nonce may be too high" in response["error"]["message"]
    assert rpc_result(anvil.url, "eth_getTransactionByHash", [tx_hash(raw)]) is None
    (record,) = records_for(proxy, tx_hash(raw))
    assert record["decision"] == "block"


def test_batch_of_dependent_transactions(proxy: Proxy, anvil: Service) -> None:
    """Each transaction is simulated alone against the upstream head. Whether
    nonce n+1 passes depends on whether anvil has mined nonce n by the time
    it's simulated (a few milliseconds either way), so both outcomes are
    allowed here. A known M2 limitation (docs/m2-plan.md, Roadmap pushback 2):
    M4's pending state should make every one of them pass."""
    first = next_nonce(proxy.url)
    raws = [sign(2, first + i) for i in range(3)]
    batch = [
        {"jsonrpc": "2.0", "id": i, "method": "eth_sendRawTransaction", "params": [raw]}
        for i, raw in enumerate(raws)
    ]

    responses = _post(proxy.url, batch)

    assert responses[0]["result"] == tx_hash(raws[0])
    forwarded = []
    for raw, response in zip(raws, responses, strict=True):
        (record,) = records_for(proxy, tx_hash(raw))
        if "result" in response:
            assert record["decision"] == "allow"
            forwarded.append(raw)
        else:
            assert "nonce may be too high" in response["error"]["message"]
            assert record["decision"] == "block"
            assert rpc_result(anvil.url, "eth_getTransactionByHash", [tx_hash(raw)]) is None
    # Forwarded ones are a prefix: once one is blocked, its successors can't run.
    assert forwarded == raws[: len(forwarded)]
    for raw in forwarded:
        assert wait_for_receipt(proxy.url, tx_hash(raw))["status"] == "0x1"


def test_wrong_chain_transaction_never_reaches_anvil(proxy: Proxy, anvil: Service) -> None:
    nonce = next_nonce(proxy.url)
    raw = sign(2, nonce, chain_id=1)

    response = rpc_call(proxy.url, "eth_sendRawTransaction", [raw])

    assert response["error"]["code"] == TRANSACTION_REJECTED
    # Ask anvil directly, not through the proxy.
    assert rpc_result(anvil.url, "eth_getTransactionByHash", [tx_hash(raw)]) is None
    assert next_nonce(anvil.url) == nonce
    (record,) = records_for(proxy, tx_hash(raw))
    assert record["decision"] == "block"


def test_batch_with_hidden_denied_methods_mines_nothing(proxy: Proxy, anvil: Service) -> None:
    # anvil holds unlocked dev keys, so eth_sendTransaction there signs and
    # mines a transfer from the user's account without any signature from the
    # agent. Tucked between harmless reads, it must still never reach anvil.
    send_from_node = {"from": SENDER, "to": ATTACKER, "value": hex(10**18)}
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
        {"jsonrpc": "2.0", "id": 2, "method": "eth_sendTransaction", "params": [send_from_node]},
        {"jsonrpc": "2.0", "id": 3, "method": "anvil_mine", "params": ["0x5"]},
        {"jsonrpc": "2.0", "id": 4, "method": "evm_mine", "params": []},
        {"jsonrpc": "2.0", "id": 5, "method": "anvil_setBalance", "params": [ATTACKER, "0x1"]},
        {"jsonrpc": "2.0", "id": 6, "method": "eth_getBalance", "params": [ATTACKER, "latest"]},
    ]
    block_before = rpc_result(anvil.url, "eth_blockNumber")
    balance_before = rpc_result(anvil.url, "eth_getBalance", [ATTACKER, "latest"])
    audit_before = len(proxy.audit_records())

    responses = _post(proxy.url, batch)

    assert [r["id"] for r in responses] == [1, 2, 3, 4, 5, 6]
    assert "result" in responses[0] and "result" in responses[5]
    assert [r["error"]["code"] for r in responses[1:5]] == [METHOD_NOT_FOUND] * 4
    # Mining is asynchronous, so give anything that slipped through time to land.
    time.sleep(0.5)
    assert rpc_result(anvil.url, "eth_blockNumber") == block_before
    assert rpc_result(anvil.url, "eth_getBalance", [ATTACKER, "latest"]) == balance_before
    assert len(proxy.audit_records()) == audit_before

    # Control: the same call sent straight to anvil does mine. Without this,
    # the test would also pass if the payload were simply broken.
    control_hash = rpc_result(anvil.url, "eth_sendTransaction", [send_from_node])
    assert wait_for_receipt(anvil.url, control_hash)["status"] == "0x1"
    assert rpc_result(anvil.url, "eth_getBalance", [ATTACKER, "latest"]) != balance_before


def _post(url: str, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return httpx.post(url, json=batch, timeout=10).json()
