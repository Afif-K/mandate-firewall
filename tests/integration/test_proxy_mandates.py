"""The M3 gate against a real anvil and a real `mandate-firewall serve`.

Mandates are written to the store by the test process while the proxy runs,
as the capture CLI would. Each test uses its own anvil dev account as the
sender, so each starts with its own (lack of) mandate and its own nonces.
"""

import sqlite3
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account
from eth_utils import keccak

from mandate_firewall.mandate.store import MandateStore
from mandate_firewall.proxy.jsonrpc import METHOD_NOT_FOUND, TRANSACTION_REJECTED
from tests.integration.conftest import Proxy, Service, rpc_call, rpc_result, start_proxy, stop
from tests.mandates import BOB, native_transfer_mandate, seed_store

pytestmark = pytest.mark.anvil

CHAIN_ID = 31337
# anvil's dev accounts 2-6 (public "test test ... junk" mnemonic; local only).
KEYS = {
    "carol": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "dave": "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "erin": "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "frank": "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "grace": "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d43b8cdb8c4fe1b9e0",
}


@pytest.fixture(scope="module")
def mandate_db(workdir: Path) -> Path:
    path = workdir / "gate-state" / "mandates.db"
    # The proxy refuses to start without a store; give it one with no
    # mandate for any of the accounts above.
    seed_store(path, native_transfer_mandate(CHAIN_ID, BOB))
    return path


@pytest.fixture(scope="module")
def proxy(anvil: Service, workdir: Path, mandate_db: Path) -> Iterator[Proxy]:
    service = start_proxy(anvil, workdir, "proxy-gate", mandate_db=mandate_db)
    yield service
    stop(service)


def address(who: str) -> str:
    return Account.from_key(KEYS[who]).address


def sign(url: str, who: str, value: int = 10**15) -> str:
    sender = address(who)
    nonce = int(rpc_result(url, "eth_getTransactionCount", [sender, "pending"]), 16)
    tx: dict[str, Any] = {
        "type": 2,
        "chainId": CHAIN_ID,
        "nonce": nonce,
        "gas": 21_000,
        "maxFeePerGas": 10 * 10**9,
        "maxPriorityFeePerGas": 10**9,
        "to": BOB,
        "value": value,
    }
    return "0x" + bytes(Account.sign_transaction(tx, KEYS[who]).raw_transaction).hex()


def tx_hash(raw: str) -> str:
    return "0x" + keccak(hexstr=raw).hex()


def record_for(proxy: Proxy, hash_: str) -> dict[str, Any]:
    (record,) = [r for r in proxy.audit_records() if r["hash"] == hash_]
    return record


def assert_blocked_and_never_mined(
    proxy: Proxy, anvil: Service, raw: str, reason: str
) -> dict[str, Any]:
    response = rpc_call(proxy.url, "eth_sendRawTransaction", [raw])
    assert response["error"]["code"] == TRANSACTION_REJECTED
    assert response["error"]["message"] == f"transaction rejected: {reason}"
    # Never reached the chain: anvil doesn't know the transaction at all.
    assert rpc_result(anvil.url, "eth_getTransactionByHash", [tx_hash(raw)]) is None
    record = record_for(proxy, tx_hash(raw))
    assert (record["decision"], record["reason"]) == ("block", reason)
    assert record["effects"] is None  # blocked before simulation
    return record


def mined(anvil: Service, raw: str) -> dict[str, Any]:
    for _ in range(100):
        receipt = rpc_result(anvil.url, "eth_getTransactionReceipt", [tx_hash(raw)])
        if receipt is not None:
            return receipt
        time.sleep(0.05)
    pytest.fail("not mined")


def test_no_mandate_is_blocked_and_never_mined(proxy: Proxy, anvil: Service) -> None:
    raw = sign(proxy.url, "carol")
    reason = f"no mandate for sender {address('carol')} on chain {CHAIN_ID}"
    record = assert_blocked_and_never_mined(proxy, anvil, raw, reason)
    assert record["mandate_id"] is None


def test_with_a_mandate_it_is_forwarded_and_audited(
    proxy: Proxy, anvil: Service, mandate_db: Path
) -> None:
    (mid,) = seed_store(mandate_db, native_transfer_mandate(CHAIN_ID, address("dave")))
    raw = sign(proxy.url, "dave")
    assert rpc_result(proxy.url, "eth_sendRawTransaction", [raw]) == tx_hash(raw)
    assert mined(anvil, raw)["status"] == "0x1"
    record = record_for(proxy, tx_hash(raw))
    assert (record["decision"], record["mandate_id"], record["mandate_transaction"]) == (
        "allow",
        mid,
        1,
    )
    assert MandateStore(mandate_db).get(mid).transactions == 1


def test_expired_mandate_is_blocked(proxy: Proxy, anvil: Service, mandate_db: Path) -> None:
    created = datetime.now(UTC) - timedelta(hours=2)
    (mid,) = seed_store(
        mandate_db,
        native_transfer_mandate(CHAIN_ID, address("erin"), created_at=created, minutes=60),
        at=created + timedelta(minutes=1),
    )
    raw = sign(proxy.url, "erin")
    assert_blocked_and_never_mined(proxy, anvil, raw, f"mandate {mid} is expired")


def test_transaction_cap_is_enforced(proxy: Proxy, anvil: Service, mandate_db: Path) -> None:
    mandate = native_transfer_mandate(CHAIN_ID, address("frank"), max_transactions=2)
    (mid,) = seed_store(mandate_db, mandate)
    for n in (1, 2):
        raw = sign(proxy.url, "frank")
        assert rpc_result(proxy.url, "eth_sendRawTransaction", [raw]) == tx_hash(raw)
        mined(anvil, raw)
        assert record_for(proxy, tx_hash(raw))["mandate_transaction"] == n
    raw = sign(proxy.url, "frank")
    reason = f"mandate {mid} is exhausted (2 of 2 transactions used)"
    assert_blocked_and_never_mined(proxy, anvil, raw, reason)


def test_tampered_store_row_is_blocked(proxy: Proxy, anvil: Service, mandate_db: Path) -> None:
    created = datetime.now(UTC) - timedelta(hours=2)
    seed_store(
        mandate_db,
        native_transfer_mandate(CHAIN_ID, address("grace"), created_at=created, minutes=60),
        at=created + timedelta(minutes=1),
    )
    # Someone with write access to the file "extends" the expired mandate.
    db = sqlite3.connect(mandate_db, isolation_level=None)
    db.execute("DROP TRIGGER IF EXISTS mandates_no_update")
    db.execute(
        "UPDATE mandates SET expires_at = '2099-01-01T00:00:00Z' WHERE principal = ?",
        (address("grace"),),
    )
    db.close()
    raw = sign(proxy.url, "grace")
    assert_blocked_and_never_mined(proxy, anvil, raw, "mandate store integrity failure")
    assert "lookup columns do not match content" in proxy.log.read_text()


@pytest.mark.parametrize("method", ["mandate_new", "mandate_revoke", "firewall_createMandate"])
def test_agents_cannot_reach_mandate_methods(proxy: Proxy, method: str) -> None:
    response = rpc_call(proxy.url, method, [{"principal": address("carol")}])
    assert response["error"]["code"] == METHOD_NOT_FOUND
