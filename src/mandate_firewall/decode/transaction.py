"""Decode raw signed transactions (the `eth_sendRawTransaction` payload).

Layouts (EIP-2718 envelopes):
    legacy (0):  rlp([nonce, gasPrice, gas, to, value, data, v, r, s])
    type 1:      0x01 || rlp([chainId, nonce, gasPrice, gas, to, value, data,
                              accessList, yParity, r, s])
    type 2:      0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
                              gas, to, value, data, accessList, yParity, r, s])

The decoder is deliberately strict. If it accepts bytes that a node would
interpret differently (a "parser differential"), an attacker could show the
firewall one transaction while the chain executes another. So we only accept
canonical encodings, and we reject anything else, including transaction types
we don't support.
"""

import string
from typing import Any

import rlp
from eth_keys import keys
from eth_keys.exceptions import BadSignature
from eth_utils import keccak, to_checksum_address

from mandate_firewall.models import AccessListEntry, DecodedTransaction, TxType

# Same limit geth applies to incoming transactions; bounds decoding work.
MAX_RAW_TX_BYTES = 128 * 1024

# Order of the secp256k1 curve. Valid signatures have 1 <= r, s < N, and
# (EIP-2) s <= N/2, so each transaction has exactly one valid signature.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_FIELD_COUNTS = {TxType.LEGACY: 9, TxType.ACCESS_LIST: 11, TxType.DYNAMIC_FEE: 12}


class TransactionDecodeError(ValueError):
    """The bytes are not a well-formed, supported, signed transaction."""


class UnsupportedTransactionType(TransactionDecodeError):
    """A well-formed envelope whose type we refuse to handle (e.g. 3, 4)."""

    def __init__(self, tx_type: int) -> None:
        super().__init__(f"unsupported transaction type 0x{tx_type:02x}")
        self.tx_type = tx_type


def decode_raw_transaction(raw: str | bytes) -> DecodedTransaction:
    """Decode a raw signed transaction and recover its sender.

    Raises TransactionDecodeError (or its subclass UnsupportedTransactionType)
    on any malformed, non-canonical, or unsupported input.
    """
    raw_bytes = _parse_hex(raw) if isinstance(raw, str) else bytes(raw)
    if not raw_bytes:
        raise TransactionDecodeError("empty transaction")
    if len(raw_bytes) > MAX_RAW_TX_BYTES:
        raise TransactionDecodeError(f"transaction exceeds {MAX_RAW_TX_BYTES} bytes")

    first = raw_bytes[0]
    if first >= 0xC0:
        # An RLP list prefix: a legacy transaction with no type byte.
        tx_type, payload = TxType.LEGACY, raw_bytes
    elif first in (TxType.ACCESS_LIST, TxType.DYNAMIC_FEE):
        tx_type, payload = TxType(first), raw_bytes[1:]
    elif first <= 0x7F:
        # EIP-2718 reserves 0x00-0x7f for type bytes; 3 (blob), 4 (set-code) etc.
        raise UnsupportedTransactionType(first)
    else:
        raise TransactionDecodeError(f"invalid first byte 0x{first:02x}")

    fields = _rlp_decode_list(payload)
    expected = _FIELD_COUNTS[tx_type]
    if len(fields) != expected:
        raise TransactionDecodeError(
            f"type {tx_type} transaction must have {expected} fields, got {len(fields)}"
        )

    if tx_type is TxType.LEGACY:
        return _decode_legacy(fields, raw_bytes)
    return _decode_typed(tx_type, fields, raw_bytes)


def _decode_legacy(fields: list[Any], raw_bytes: bytes) -> DecodedTransaction:
    nonce, gas_price, gas, to, value, data, v_raw, r_raw, s_raw = fields
    v = _uint(v_raw, "v")

    if v in (27, 28):
        # Pre-EIP-155: no chain id, so the signature is valid on every chain.
        chain_id = None
        recovery_id = v - 27
        signing_payload = rlp.encode(fields[:6])
    elif v >= 35:
        # EIP-155: v = chainId * 2 + 35 + recovery_id, and the signed payload
        # includes (chainId, 0, 0) so it can't be replayed on another chain.
        chain_id = (v - 35) // 2
        recovery_id = (v - 35) % 2
        signing_payload = rlp.encode([*fields[:6], chain_id, 0, 0])
    else:
        raise TransactionDecodeError(f"invalid legacy v value {v}")

    sender = _recover_sender(keccak(signing_payload), recovery_id, r_raw, s_raw)
    return DecodedTransaction(
        tx_type=TxType.LEGACY,
        hash=_hex(keccak(raw_bytes)),
        chain_id=chain_id,
        nonce=_uint(nonce, "nonce"),
        sender=sender,
        to=_to_address(to),
        value=_uint(value, "value"),
        data=_hex(_bytes(data, "data")),
        gas_limit=_uint(gas, "gas"),
        gas_price=_uint(gas_price, "gasPrice"),
        raw=_hex(raw_bytes),
    )


def _decode_typed(tx_type: TxType, fields: list[Any], raw_bytes: bytes) -> DecodedTransaction:
    *unsigned, y_parity_raw, r_raw, s_raw = fields
    y_parity = _uint(y_parity_raw, "yParity")
    if y_parity not in (0, 1):
        raise TransactionDecodeError(f"invalid yParity {y_parity}")

    # Typed transactions sign keccak256(type_byte || rlp(unsigned fields)).
    signing_payload = bytes([tx_type]) + rlp.encode(unsigned)
    sender = _recover_sender(keccak(signing_payload), y_parity, r_raw, s_raw)

    fee_fields: dict[str, int]
    if tx_type is TxType.ACCESS_LIST:
        chain_id, nonce, gas_price, gas, to, value, data, access_list = unsigned
        fee_fields = {"gas_price": _uint(gas_price, "gasPrice")}
    else:
        chain_id, nonce, max_prio, max_fee, gas, to, value, data, access_list = unsigned
        fee_fields = {
            "max_priority_fee_per_gas": _uint(max_prio, "maxPriorityFeePerGas"),
            "max_fee_per_gas": _uint(max_fee, "maxFeePerGas"),
        }

    return DecodedTransaction(
        tx_type=tx_type,
        hash=_hex(keccak(raw_bytes)),
        chain_id=_uint(chain_id, "chainId"),
        nonce=_uint(nonce, "nonce"),
        sender=sender,
        to=_to_address(to),
        value=_uint(value, "value"),
        data=_hex(_bytes(data, "data")),
        gas_limit=_uint(gas, "gas"),
        access_list=_access_list(access_list),
        raw=_hex(raw_bytes),
        **fee_fields,
    )


def _parse_hex(raw: str) -> bytes:
    if not raw.startswith("0x"):
        raise TransactionDecodeError("hex string must start with 0x")
    # bytes.fromhex silently skips whitespace; we accept only bare hex digits.
    if not all(c in string.hexdigits for c in raw[2:]):
        raise TransactionDecodeError("invalid hex string")
    try:
        return bytes.fromhex(raw[2:])
    except ValueError as exc:
        raise TransactionDecodeError("invalid hex string") from exc


def _rlp_decode_list(payload: bytes) -> list[Any]:
    try:
        # strict=True rejects trailing bytes; rlp also rejects non-canonical
        # length prefixes (e.g. a single byte wrapped in a string prefix).
        decoded = rlp.decode(payload, strict=True)
    except rlp.exceptions.DecodingError as exc:
        raise TransactionDecodeError(f"invalid RLP: {exc}") from exc
    if not isinstance(decoded, list):
        raise TransactionDecodeError("transaction payload is not an RLP list")
    # Belt and braces: canonical input must re-encode to the exact same bytes.
    if rlp.encode(decoded) != payload:
        raise TransactionDecodeError("non-canonical RLP encoding")
    return decoded


def _bytes(item: Any, name: str) -> bytes:
    if not isinstance(item, bytes):
        raise TransactionDecodeError(f"{name} must be a byte string, got a list")
    return item


def _uint(item: Any, name: str, max_bytes: int = 32) -> int:
    """RLP integers are big-endian with no leading zeros; zero is empty bytes."""
    b = _bytes(item, name)
    if b[:1] == b"\x00":
        raise TransactionDecodeError(f"{name} has leading zero bytes")
    if len(b) > max_bytes:
        raise TransactionDecodeError(f"{name} exceeds {max_bytes} bytes")
    return int.from_bytes(b, "big")


def _to_address(item: Any) -> str | None:
    b = _bytes(item, "to")
    if not b:
        return None  # contract creation
    if len(b) != 20:
        raise TransactionDecodeError(f"to must be 20 bytes, got {len(b)}")
    return to_checksum_address(b)


def _access_list(item: Any) -> tuple[AccessListEntry, ...]:
    if not isinstance(item, list):
        raise TransactionDecodeError("accessList must be a list")
    entries = []
    for entry in item:
        if not isinstance(entry, list) or len(entry) != 2:
            raise TransactionDecodeError("accessList entry must be [address, storageKeys]")
        address, storage_keys = entry
        address_bytes = _bytes(address, "accessList address")
        if len(address_bytes) != 20 or not isinstance(storage_keys, list):
            raise TransactionDecodeError("malformed accessList entry")
        key_hexes = []
        for key in storage_keys:
            key_bytes = _bytes(key, "storage key")
            if len(key_bytes) != 32:
                raise TransactionDecodeError("storage key must be 32 bytes")
            key_hexes.append(_hex(key_bytes))
        entries.append(
            AccessListEntry(
                address=to_checksum_address(address_bytes), storage_keys=tuple(key_hexes)
            )
        )
    return tuple(entries)


def _recover_sender(msg_hash: bytes, recovery_id: int, r_raw: Any, s_raw: Any) -> str:
    r = _uint(r_raw, "r")
    s = _uint(s_raw, "s")
    if not 1 <= r < SECP256K1_N:
        raise TransactionDecodeError("signature r out of range")
    if not 1 <= s <= SECP256K1_N // 2:
        # EIP-2: high-s signatures are valid ECDSA but rejected by every node.
        raise TransactionDecodeError("signature s out of range (high-s or zero)")
    try:
        signature = keys.Signature(vrs=(recovery_id, r, s))
        public_key = signature.recover_public_key_from_msg_hash(msg_hash)
    except (BadSignature, ValueError) as exc:
        raise TransactionDecodeError(f"signature recovery failed: {exc}") from exc
    return public_key.to_checksum_address()


def _hex(b: bytes) -> str:
    return "0x" + b.hex()
