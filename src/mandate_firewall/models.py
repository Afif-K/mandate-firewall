"""Pydantic models for structured data passed between firewall components."""

from enum import IntEnum

from pydantic import BaseModel, ConfigDict


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
