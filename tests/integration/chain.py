"""Helpers for driving a real anvil from tests: sign as anvil's dev account 0,
send, wait for the receipt, read contract state."""

import time
from typing import Any

import pytest
from eth_account import Account
from eth_utils import to_checksum_address

from tests.contracts import Contract
from tests.integration.conftest import rpc_result

# anvil's public dev key 0 (the "test test ... junk" mnemonic). Local only.
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ALICE = Account.from_key(KEY).address
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # dev account 1
THIEF = "0x000000000000000000000000000000000000dEaD"


def sign(
    url: str,
    to: str | None,
    data: str = "0x",
    value: int = 0,
    nonce: int | None = None,
    **fields: Any,
) -> str:
    """A signed type-2 transaction from ALICE, as raw hex. Not sent."""
    chain_id = int(rpc_result(url, "eth_chainId"), 16)
    if nonce is None:
        nonce = int(rpc_result(url, "eth_getTransactionCount", [ALICE, "pending"]), 16)
    tx: dict[str, Any] = {
        "type": 2,
        "chainId": chain_id,
        "nonce": nonce,
        "gas": 3_000_000,
        "maxFeePerGas": 100 * 10**9,
        "maxPriorityFeePerGas": 10**9,
        "value": value,
        "data": data,
        **fields,
    }
    if to is not None:
        tx["to"] = to
    return "0x" + bytes(Account.sign_transaction(tx, KEY).raw_transaction).hex()


def send(url: str, to: str | None, data: str = "0x", value: int = 0) -> dict[str, Any]:
    """Sign as ALICE, send, and wait for the receipt (anvil's automine returns
    the hash before the block exists)."""
    tx_hash = rpc_result(url, "eth_sendRawTransaction", [sign(url, to, data, value)])
    for _ in range(100):
        receipt = rpc_result(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.05)
    pytest.fail(f"transaction {tx_hash} was not mined")


def deploy(url: str, contract: Contract, *args: Any) -> str:
    receipt = send(url, None, contract.deploy_data(*args))
    assert receipt["status"] == "0x1", receipt
    return to_checksum_address(receipt["contractAddress"])


def call(url: str, contract: Contract, address: str, function: str, *args: Any) -> int:
    data = contract.call_data(function, *args)
    return int(rpc_result(url, "eth_call", [{"to": address, "data": data}, "latest"]), 16)


def transact(
    url: str, contract: Contract, address: str, function: str, *args: Any, value: int = 0
) -> dict[str, Any]:
    receipt = send(url, address, contract.call_data(function, *args), value)
    assert receipt["status"] == "0x1", receipt
    return receipt


def balance(url: str, address: str) -> int:
    return int(rpc_result(url, "eth_getBalance", [address, "latest"]), 16)
