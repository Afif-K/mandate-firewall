"""Pydantic models for structured data passed between firewall components."""

import re
from enum import IntEnum, StrEnum
from typing import Annotated, Any, Literal, Self

from eth_utils import to_checksum_address
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    model_validator,
)

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


# --- Simulated effects (M2) -------------------------------------------------
#
# Effects come from running the exact signed transaction on a private fork. M4
# compares them against the mandate, so their shape is part of the security
# boundary:
# - Every string field is a constrained hex value or an address. There is no
#   field that can hold free text, so attacker-chosen text (token names, revert
#   messages) can't reach the verifier through effects.
# - Values are canonical: addresses EIP-55 checksummed, other hex lowercase.
#   One spelling per value, so "is X in this set" checks can't miss on case.
# - Amounts are range-checked integers, serialized as decimal strings (BigInt).

UINT256_MAX = 2**256 - 1
_DECIMAL = re.compile(r"-?(0|[1-9][0-9]{0,77})")


def _strict_int(value: Any) -> Any:
    """Accept an int (not a bool) or a canonical decimal string, as written by
    the JSON serializer. Plain int fields would also take True, 1.0 or "1_0"."""
    if isinstance(value, bool):
        raise ValueError("expected an integer, not a bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _DECIMAL.fullmatch(value):
        return int(value)
    raise ValueError("expected an integer or a decimal string")


def _checksum(value: str) -> str:
    """EIP-55 checksum. Mixed-case input must already be a valid checksum: a
    wrong one usually means a corrupted address."""
    checksummed = to_checksum_address(value)
    digits = value[2:]  # not the "0x": uppercasing it would give "0X"
    if digits != digits.lower() and digits != digits.upper() and value != checksummed:
        raise ValueError("address has an invalid EIP-55 checksum")
    return checksummed


_IntJson = PlainSerializer(str, return_type=str, when_used="json")
Uint256 = Annotated[int, BeforeValidator(_strict_int), Field(ge=0, le=UINT256_MAX), _IntJson]
# A change in a uint256 balance: anywhere from -(2**256 - 1) to 2**256 - 1.
Uint256Delta = Annotated[
    int, BeforeValidator(_strict_int), Field(ge=-UINT256_MAX, le=UINT256_MAX), _IntJson
]
Address = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{40}$"), AfterValidator(_checksum)]
Hash32 = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{64}$"), AfterValidator(str.lower)]
HexData = Annotated[str, Field(pattern=r"^0x(?:[0-9a-fA-F]{2})*$"), AfterValidator(str.lower)]
Selector = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{8}$"), AfterValidator(str.lower)]


class _Effect(BaseModel):
    # extra="forbid": a stored effects record with fields we don't know about
    # is not one we wrote, so reading it back must fail.
    model_config = ConfigDict(frozen=True, extra="forbid")


class SimulationStatus(StrEnum):
    SUCCESS = "success"
    REVERTED = "reverted"


class TokenStandard(StrEnum):
    # ERC-20 and ERC-721 share the Transfer and Approval event signatures; only
    # the number of indexed topics tells them apart (3 vs 4).
    ERC20 = "erc20"
    ERC721 = "erc721"


class CallType(StrEnum):
    """callTracer frame types."""

    CALL = "CALL"
    DELEGATECALL = "DELEGATECALL"  # runs the target's code with the caller's storage and ETH
    STATICCALL = "STATICCALL"
    CALLCODE = "CALLCODE"
    CREATE = "CREATE"
    CREATE2 = "CREATE2"
    SELFDESTRUCT = "SELFDESTRUCT"


class NativeBalanceChange(_Effect):
    """An ETH balance change, measured by reading balances before and after.
    Gas fees are included; Effects.gas_cost says how much of it they are."""

    address: Address
    delta: Uint256Delta  # signed, in wei; never zero

    @model_validator(mode="after")
    def _nonzero(self) -> Self:
        if self.delta == 0:
            raise ValueError("a balance change of zero is not a change")
        return self


class TokenTransfer(_Effect):
    """A Transfer event. A *claim* by the token contract: see TokenStateCheck."""

    token: Address  # the contract that emitted the event
    standard: TokenStandard
    sender: Address  # the zero address for a mint
    recipient: Address  # the zero address for a burn
    amount: Uint256 | None = None  # ERC-20 only
    token_id: Uint256 | None = None  # ERC-721 only
    log_index: int = Field(ge=0)

    @model_validator(mode="after")
    def _amount_matches_standard(self) -> Self:
        _check_amount_or_id(self.standard, self.amount, self.token_id)
        return self


class TokenApproval(_Effect):
    """An Approval event: ERC-20 allowance, or ERC-721 approval of one token."""

    token: Address
    standard: TokenStandard
    owner: Address
    spender: Address  # for ERC-721, the zero address clears the approval
    amount: Uint256 | None = None  # ERC-20 only; UINT256_MAX means "unlimited"
    token_id: Uint256 | None = None  # ERC-721 only
    log_index: int = Field(ge=0)

    @model_validator(mode="after")
    def _amount_matches_standard(self) -> Self:
        _check_amount_or_id(self.standard, self.amount, self.token_id)
        return self


class OperatorApproval(_Effect):
    """An ApprovalForAll event: `operator` may move *every* token `owner` holds
    in this collection, now and later. The classic NFT drainer."""

    token: Address
    owner: Address
    operator: Address
    approved: bool
    log_index: int = Field(ge=0)


class CallFrame(_Effect):
    """One frame of the call tree, in depth-first order (depth 0 is the
    transaction itself)."""

    depth: int = Field(ge=0)
    call_type: CallType
    caller: Address
    # For CREATE/CREATE2 the new contract (None if creation failed); for
    # SELFDESTRUCT the address that receives the balance.
    target: Address | None
    value: Uint256 = 0
    selector: Selector | None = None  # first 4 bytes of input, if there are 4
    reverted: bool = False


class RawLog(_Effect):
    """A log we don't decode. Kept, never dropped: M4 treats effects it can't
    interpret as a reason to escalate."""

    address: Address
    topics: tuple[Hash32, ...] = Field(max_length=4)  # the EVM allows at most 4
    data: HexData
    log_index: int = Field(ge=0)


class TokenStateCheck(_Effect):
    """balanceOf/allowance read before and after, compared with what the
    token's events claim. consistent=False means the events lied (or the
    token did something events don't show)."""

    token: Address
    kind: Literal["balance", "allowance"]
    owner: Address
    spender: Address | None = None  # allowance checks only
    before: Uint256
    after: Uint256
    consistent: bool

    @model_validator(mode="after")
    def _spender_matches_kind(self) -> Self:
        if (self.kind == "allowance") != (self.spender is not None):
            raise ValueError("spender is required for allowance checks and only for them")
        return self


class Effects(_Effect):
    """What a transaction did when run on a fork of the upstream at a known
    block. The ground truth M4 checks against the mandate, within the limits
    in THREAT_MODEL.md (state can change before the real inclusion)."""

    tx_hash: Hash32
    sender: Address
    chain_id: int = Field(gt=0)
    fork_block_number: int = Field(ge=0)  # the state we simulated against...
    fork_block_hash: Hash32  # ...pinned exactly
    status: SimulationStatus
    revert_data: HexData | None = None  # raw bytes, never decoded to text
    gas_used: Uint256
    effective_gas_price: Uint256
    gas_cost: Uint256  # gas_used * effective_gas_price, paid by the sender
    native_balance_changes: tuple[NativeBalanceChange, ...] = ()
    token_transfers: tuple[TokenTransfer, ...] = ()
    token_approvals: tuple[TokenApproval, ...] = ()
    operator_approvals: tuple[OperatorApproval, ...] = ()
    calls: tuple[CallFrame, ...] = Field(min_length=1)
    contracts_created: tuple[Address, ...] = ()
    unrecognized_logs: tuple[RawLog, ...] = ()
    token_state_checks: tuple[TokenStateCheck, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.gas_cost != self.gas_used * self.effective_gas_price:
            raise ValueError("gas_cost must equal gas_used * effective_gas_price")

        if self.status is SimulationStatus.SUCCESS and self.revert_data is not None:
            raise ValueError("a successful transaction has no revert data")
        if self.status is SimulationStatus.REVERTED and (
            self.token_transfers
            or self.token_approvals
            or self.operator_approvals
            or self.unrecognized_logs
            or self.contracts_created
        ):
            # A reverted transaction emits no logs and creates nothing.
            raise ValueError("a reverted transaction can't have logs or created contracts")

        top = self.calls[0]
        if top.depth != 0 or top.caller != self.sender:
            raise ValueError("the first call frame must be the sender's transaction")
        if any(frame.depth == 0 for frame in self.calls[1:]):
            raise ValueError("a transaction has exactly one top-level call frame")

        addresses = [change.address for change in self.native_balance_changes]
        if len(addresses) != len(set(addresses)):
            raise ValueError("at most one native balance change per address")

        # Each receipt log lands in exactly one list. A repeated index means a
        # log was counted twice (and maybe another one dropped).
        log_indexes = [
            item.log_index
            for group in (
                self.token_transfers,
                self.token_approvals,
                self.operator_approvals,
                self.unrecognized_logs,
            )
            for item in group
        ]
        if len(log_indexes) != len(set(log_indexes)):
            raise ValueError("each log index may appear only once")
        return self


def _check_amount_or_id(standard: TokenStandard, amount: int | None, token_id: int | None) -> None:
    if standard is TokenStandard.ERC20 and (amount is None or token_id is not None):
        raise ValueError("an ERC-20 event has an amount and no token id")
    if standard is TokenStandard.ERC721 and (token_id is None or amount is not None):
        raise ValueError("an ERC-721 event has a token id and no amount")
