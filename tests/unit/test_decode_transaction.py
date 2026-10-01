"""Decoder tests.

Valid transactions are signed with eth_account (an independent implementation),
so every assertion cross-checks our decoder against a second source of truth.
"""

from typing import Any

import pytest
import rlp
from eth_account import Account
from eth_utils import keccak

from mandate_firewall.decode.transaction import (
    SECP256K1_N,
    TransactionDecodeError,
    UnsupportedTransactionType,
    decode_raw_transaction,
)
from mandate_firewall.models import TxType

# Throwaway key used only in tests; never funded anywhere.
TEST_KEY = "0x" + "11" * 32
TEST_ACCOUNT = Account.from_key(TEST_KEY)
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
CHAIN_ID = 31337
ERC20_TRANSFER_DATA = bytes.fromhex(
    "a9059cbb"
    "000000000000000000000000beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
    "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
)

LEGACY_TX: dict[str, Any] = {
    "nonce": 7,
    "gasPrice": 1_000_000_000,
    "gas": 21_000,
    "to": RECIPIENT,
    "value": 10**17,
    "data": b"",
    "chainId": CHAIN_ID,
}
ACCESS_LIST_TX: dict[str, Any] = {
    "type": 1,
    "chainId": CHAIN_ID,
    "nonce": 1,
    "gasPrice": 2_000_000_000,
    "gas": 60_000,
    "to": RECIPIENT,
    "value": 0,
    "data": ERC20_TRANSFER_DATA,
    "accessList": [{"address": RECIPIENT, "storageKeys": ["0x" + "00" * 31 + "01"]}],
}
DYNAMIC_FEE_TX: dict[str, Any] = {
    "type": 2,
    "chainId": CHAIN_ID,
    "nonce": 0,
    "maxPriorityFeePerGas": 1_000_000_000,
    "maxFeePerGas": 3_000_000_000,
    "gas": 60_000,
    "to": RECIPIENT,
    "value": 0,
    "data": ERC20_TRANSFER_DATA,
}


def sign(tx: dict[str, Any]) -> bytes:
    return bytes(Account.sign_transaction(tx, TEST_KEY).raw_transaction)


def assert_matches_reference(raw: bytes) -> None:
    """Sender and hash must agree with eth_account's own recovery."""
    decoded = decode_raw_transaction(raw)
    assert decoded.sender == Account.recover_transaction(raw) == TEST_ACCOUNT.address
    assert decoded.hash == "0x" + keccak(raw).hex()
    assert decoded.raw == "0x" + raw.hex()


# --- valid transactions ---------------------------------------------------------


def test_decodes_eip1559_transaction() -> None:
    raw = sign(DYNAMIC_FEE_TX)
    assert raw[0] == 0x02
    decoded = decode_raw_transaction(raw)

    assert decoded.tx_type is TxType.DYNAMIC_FEE
    assert decoded.chain_id == CHAIN_ID
    assert decoded.nonce == 0
    assert decoded.to == RECIPIENT
    assert decoded.value == 0
    assert decoded.data == "0x" + ERC20_TRANSFER_DATA.hex()
    assert decoded.gas_limit == 60_000
    assert decoded.max_priority_fee_per_gas == 1_000_000_000
    assert decoded.max_fee_per_gas == 3_000_000_000
    assert decoded.gas_price is None
    assert_matches_reference(raw)


def test_decodes_access_list_transaction() -> None:
    raw = sign(ACCESS_LIST_TX)
    assert raw[0] == 0x01
    decoded = decode_raw_transaction(raw)

    assert decoded.tx_type is TxType.ACCESS_LIST
    assert decoded.chain_id == CHAIN_ID
    assert decoded.gas_price == 2_000_000_000
    assert len(decoded.access_list) == 1
    assert decoded.access_list[0].address == RECIPIENT
    assert decoded.access_list[0].storage_keys == ("0x" + "00" * 31 + "01",)
    assert_matches_reference(raw)


def test_decodes_eip155_legacy_transaction() -> None:
    raw = sign(LEGACY_TX)
    assert raw[0] >= 0xC0  # no type byte: the whole tx is one RLP list
    decoded = decode_raw_transaction(raw)

    assert decoded.tx_type is TxType.LEGACY
    assert decoded.chain_id == CHAIN_ID  # recovered from v = chainId * 2 + 35/36
    assert decoded.nonce == 7
    assert decoded.value == 10**17
    assert decoded.gas_price == 1_000_000_000
    assert_matches_reference(raw)


def test_decodes_unprotected_legacy_transaction_with_no_chain_id() -> None:
    # Decoding succeeds; rejecting replayable txs is a policy check in the proxy.
    tx = {k: v for k, v in LEGACY_TX.items() if k != "chainId"}
    raw = sign(tx)
    decoded = decode_raw_transaction(raw)

    assert decoded.chain_id is None
    assert_matches_reference(raw)


def test_decodes_contract_creation_as_to_none() -> None:
    tx = {**DYNAMIC_FEE_TX, "data": b"\x60\x00"}
    del tx["to"]
    decoded = decode_raw_transaction(sign(tx))
    assert decoded.to is None


def test_accepts_hex_string_input() -> None:
    raw = sign(DYNAMIC_FEE_TX)
    assert decode_raw_transaction("0x" + raw.hex()) == decode_raw_transaction(raw)


def test_tampered_field_recovers_a_different_sender() -> None:
    """Changing a signed field doesn't make decoding fail: recovery returns a
    different (random) address. This is why the sender must always be recovered,
    never taken from what the agent claims."""
    fields = rlp.decode(sign(DYNAMIC_FEE_TX)[1:])
    fields[6] = (10**18).to_bytes(8, "big")  # value: 0 -> 1 ETH
    tampered = b"\x02" + rlp.encode(fields)

    try:
        decoded = decode_raw_transaction(tampered)
    except TransactionDecodeError:
        return  # also acceptable: some (r, s) pairs have no valid recovery
    assert decoded.sender != TEST_ACCOUNT.address


# --- rejected inputs ------------------------------------------------------------


@pytest.mark.parametrize("type_byte", [0x00, 0x03, 0x04, 0x05, 0x7F])
def test_rejects_unsupported_types(type_byte: int) -> None:
    # 0x03 = blob (EIP-4844), 0x04 = set-code (EIP-7702). The body is irrelevant:
    # we refuse on the type byte before parsing anything else.
    with pytest.raises(UnsupportedTransactionType) as exc_info:
        decode_raw_transaction(bytes([type_byte]) + rlp.encode([b"\x01"]))
    assert exc_info.value.tx_type == type_byte


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x80",  # first byte 0x80-0xbf: an RLP string, not a list or a type
        b"\x02",  # type byte with no payload
        b"\x02" + rlp.encode(b"not a list"),
    ],
)
def test_rejects_malformed_envelopes(raw: bytes) -> None:
    with pytest.raises(TransactionDecodeError):
        decode_raw_transaction(raw)


@pytest.mark.parametrize("raw", ["", "02f8", "0xzz", "0x123", "0x02 f8", "0x02\nf8"])
def test_rejects_bad_hex(raw: str) -> None:
    with pytest.raises(TransactionDecodeError):
        decode_raw_transaction(raw)


def test_rejects_oversized_input() -> None:
    with pytest.raises(TransactionDecodeError, match="exceeds"):
        decode_raw_transaction(b"\x02" + b"\x00" * (128 * 1024))


def test_rejects_truncated_transaction() -> None:
    with pytest.raises(TransactionDecodeError):
        decode_raw_transaction(sign(DYNAMIC_FEE_TX)[:-5])


def test_rejects_trailing_bytes() -> None:
    with pytest.raises(TransactionDecodeError):
        decode_raw_transaction(sign(DYNAMIC_FEE_TX) + b"\x00")


def test_rejects_wrong_field_count() -> None:
    fields = rlp.decode(sign(DYNAMIC_FEE_TX)[1:])
    with pytest.raises(TransactionDecodeError, match="12 fields"):
        decode_raw_transaction(b"\x02" + rlp.encode(fields[:-1]))


def test_rejects_integer_with_leading_zero() -> None:
    """0x0007 and 0x07 are the same number. A node rejects the padded form; if we
    accepted it, our view of the tx and the node's could diverge."""
    fields = rlp.decode(sign(DYNAMIC_FEE_TX)[1:])
    fields[1] = b"\x00\x07"  # nonce
    with pytest.raises(TransactionDecodeError, match="leading zero"):
        decode_raw_transaction(b"\x02" + rlp.encode(fields))


def test_rejects_non_canonical_rlp_length() -> None:
    # 0x81 0x05 encodes the single byte 0x05, which must be written as just 0x05.
    fields_payload = b"\x81\x05" + b"\x80" * 11
    raw = b"\x02" + bytes([0xC0 + len(fields_payload)]) + fields_payload
    with pytest.raises(TransactionDecodeError, match="RLP"):
        decode_raw_transaction(raw)


def test_rejects_high_s_signature() -> None:
    """(r, N - s) with flipped parity is also a valid ECDSA signature for the same
    key (malleability). EIP-2 makes nodes reject it, so we must too."""
    fields = rlp.decode(sign(DYNAMIC_FEE_TX)[1:])
    s = int.from_bytes(fields[11], "big")
    fields[9] = b"" if fields[9] == b"\x01" else b"\x01"
    fields[11] = (SECP256K1_N - s).to_bytes(32, "big")
    with pytest.raises(TransactionDecodeError, match="high-s"):
        decode_raw_transaction(b"\x02" + rlp.encode(fields))


def test_rejects_invalid_y_parity() -> None:
    fields = rlp.decode(sign(DYNAMIC_FEE_TX)[1:])
    fields[9] = b"\x02"
    with pytest.raises(TransactionDecodeError, match="yParity"):
        decode_raw_transaction(b"\x02" + rlp.encode(fields))


def test_rejects_invalid_legacy_v() -> None:
    fields = rlp.decode(sign(LEGACY_TX))
    fields[6] = b"\x1d"  # 29: neither 27/28 nor >= 35
    with pytest.raises(TransactionDecodeError, match="v value"):
        decode_raw_transaction(rlp.encode(fields))


def test_rejects_wrong_length_to_address() -> None:
    fields = rlp.decode(sign(DYNAMIC_FEE_TX)[1:])
    fields[5] = fields[5][:19]
    with pytest.raises(TransactionDecodeError, match="20 bytes"):
        decode_raw_transaction(b"\x02" + rlp.encode(fields))
