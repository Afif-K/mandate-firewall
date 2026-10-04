"""Pydantic models for structured data passed between firewall components."""

from enum import IntEnum, StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, PlainSerializer

# An integer that serializes to JSON as a decimal string. Onchain integers go up
# to 2**256, and many JSON consumers (JavaScript, some jq builds) parse numbers
# as 64-bit floats, silently rounding anything above 2**53.
BigInt = Annotated[int, PlainSerializer(str, return_type=str, when_used="json")]


class TxType(IntEnum):
    """EIP-2718 transaction types the decoder supports."""

    LEGACY = 0
    ACCESS_LIST = 1  # EIP-2930
    DYNAMIC_FEE = 2  # EIP-1559


class AccessListEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: str  # checksummed
    storage_keys: tuple[str, ...]  # 0x-prefixed 32-byte hex


class DecodedTransaction(BaseModel):
    """A signed transaction decoded from raw bytes, plus its recovered sender.

    Every field is derived from the raw bytes alone; nothing is taken from the
    agent's claims. `sender` comes from signature recovery, so it is only as
    trustworthy as the signature check that produced it.
    """

    model_config = ConfigDict(frozen=True)

    tx_type: TxType
    hash: str  # keccak256 of the raw bytes, 0x-prefixed
    chain_id: int | None  # None only for pre-EIP-155 legacy transactions (replayable)
    nonce: int
    sender: str  # checksummed, recovered from the signature
    to: str | None  # checksummed; None means contract creation
    value: int  # wei
    data: str  # calldata, 0x-prefixed hex
    gas_limit: int
    gas_price: int | None = None  # types 0 and 1
    max_fee_per_gas: int | None = None  # type 2
    max_priority_fee_per_gas: int | None = None  # type 2
    access_list: tuple[AccessListEntry, ...] = ()
    raw: str  # the exact bytes we decoded, 0x-prefixed hex


class CallKind(StrEnum):
    EMPTY = "empty"  # no calldata: a plain ETH transfer (or a call to receive/fallback)
    KNOWN = "known"  # selector in our registry and arguments decoded
    UNKNOWN_SELECTOR = "unknown_selector"  # we don't guess at selectors we don't know
    MALFORMED = "malformed"  # known selector, or partial selector, with undecodable arguments


class DecodedArg(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    abi_type: str
    value: BigInt | str  # uint256 -> int; address -> checksummed str


class DecodedCall(BaseModel):
    """What the calldata *claims* to call. Not what the call does: the target
    contract decides that. Simulated effects (M2) are the ground truth."""

    model_config = ConfigDict(frozen=True)

    kind: CallKind
    selector: str | None = None  # 0x-prefixed 4 bytes
    signature: str | None = None  # e.g. "transfer(address,uint256)"
    args: tuple[DecodedArg, ...] = ()
    trailing_bytes: int = 0  # bytes after the expected arguments (ignored by Solidity)
    error: str | None = None


class Decision(StrEnum):
    """What the firewall does with a transaction. M4 adds "escalate"."""

    ALLOW = "allow"  # forward to the upstream node
    BLOCK = "block"  # refuse; the node never sees it
