"""Decode a simulated receipt's logs into token effects.

Log layout: an event `Transfer(address indexed from, address indexed to,
uint256 value)` becomes
    topics[0] = keccak256("Transfer(address,address,uint256)")  # the signature
    topics[1:] = one 32-byte word per *indexed* argument
    data = the ABI encoding of the non-indexed arguments
so the same signature can produce different layouts depending on which
arguments a contract marks `indexed`.

Rules, in the same style as decode/calldata.py:
- A fixed registry of three events, matched exactly: topic count, data
  length, address padding and bool encoding. A log that is close but not
  exact is not "probably a transfer". It goes to `unrecognized`, never dropped.
- ERC-20 and ERC-721 share the Transfer and Approval signatures. The only
  difference is that ERC-721 indexes the third argument: 4 topics and no
  data, versus 3 topics and a 32-byte amount. So `standard` is a guess from
  the log's shape, and a token that indexes its amount would look like an
  NFT. M4's registry of known token addresses is the authority on what a
  token is.
- Every event is a claim made by the contract that emitted it. A malicious
  token can emit a Transfer that never happened. The simulator checks these
  claims against balanceOf/allowance (TokenStateCheck).
- A log the node returned in an invalid shape raises LogDecodeError: our own
  fork sent nonsense, so the simulation can't be trusted.
"""

import re
from dataclasses import dataclass
from typing import Any

from eth_utils import keccak, to_checksum_address
from pydantic import BaseModel, ConfigDict

from mandate_firewall.models import (
    OperatorApproval,
    RawLog,
    TokenApproval,
    TokenStandard,
    TokenTransfer,
)

WORD = 32
MAX_TOPICS = 4  # LOG0..LOG4

TRANSFER_TOPIC = keccak(text="Transfer(address,address,uint256)")
APPROVAL_TOPIC = keccak(text="Approval(address,address,uint256)")
APPROVAL_FOR_ALL_TOPIC = keccak(text="ApprovalForAll(address,address,bool)")

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_WORD_HEX = re.compile(r"0x[0-9a-fA-F]{64}")
_DATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")


class LogDecodeError(ValueError):
    """The node returned something that isn't a valid log of this transaction."""


class DecodedLogs(BaseModel):
    """Every receipt log, in exactly one of the four lists."""

    model_config = ConfigDict(frozen=True)

    transfers: tuple[TokenTransfer, ...] = ()
    approvals: tuple[TokenApproval, ...] = ()
    operator_approvals: tuple[OperatorApproval, ...] = ()
    unrecognized: tuple[RawLog, ...] = ()


@dataclass(frozen=True)
class _Log:
    address: str
    topics: tuple[bytes, ...]
    data: bytes
    log_index: int


Event = TokenTransfer | TokenApproval | OperatorApproval


def decode_logs(logs: Any, tx_hash: str) -> DecodedLogs:
    """Decode a receipt's `logs` array. `tx_hash` is the transaction we
    simulated; every log must belong to it."""
    if not isinstance(logs, list):
        raise LogDecodeError("receipt logs must be a list")

    transfers: list[TokenTransfer] = []
    approvals: list[TokenApproval] = []
    operator_approvals: list[OperatorApproval] = []
    unrecognized: list[RawLog] = []
    previous_index = -1
    for obj in logs:
        log = _parse_log(obj, tx_hash)
        # Receipt logs come in emission order. Anything else means the node
        # reordered or duplicated them.
        if log.log_index <= previous_index:
            raise LogDecodeError("receipt log indexes must be strictly increasing")
        previous_index = log.log_index

        event = _decode_event(log)
        if isinstance(event, TokenTransfer):
            transfers.append(event)
        elif isinstance(event, TokenApproval):
            approvals.append(event)
        elif isinstance(event, OperatorApproval):
            operator_approvals.append(event)
        else:
            unrecognized.append(
                RawLog(
                    address=log.address,
                    topics=tuple("0x" + topic.hex() for topic in log.topics),
                    data="0x" + log.data.hex(),
                    log_index=log.log_index,
                )
            )
    return DecodedLogs(
        transfers=tuple(transfers),
        approvals=tuple(approvals),
        operator_approvals=tuple(operator_approvals),
        unrecognized=tuple(unrecognized),
    )


def _parse_log(obj: Any, tx_hash: str) -> _Log:
    if not isinstance(obj, dict):
        raise LogDecodeError("a receipt log must be an object")
    if obj.get("removed") not in (None, False):
        # Only a reorg removes logs, and our fork has no reorgs.
        raise LogDecodeError("receipt log is marked removed")
    log_tx_hash = obj.get("transactionHash")
    if not isinstance(log_tx_hash, str) or log_tx_hash.lower() != tx_hash.lower():
        raise LogDecodeError("receipt log belongs to a different transaction")

    address = obj.get("address")
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address):
        raise LogDecodeError("receipt log has an invalid address")

    topics = obj.get("topics")
    if not isinstance(topics, list) or len(topics) > MAX_TOPICS:
        raise LogDecodeError(f"receipt log topics must be a list of at most {MAX_TOPICS}")
    if not all(isinstance(t, str) and _WORD_HEX.fullmatch(t) for t in topics):
        raise LogDecodeError("receipt log has an invalid topic")

    data = obj.get("data")
    if not isinstance(data, str) or not _DATA.fullmatch(data):
        raise LogDecodeError("receipt log has invalid data")

    log_index = obj.get("logIndex")
    if not isinstance(log_index, str) or not _QUANTITY.fullmatch(log_index):
        raise LogDecodeError("receipt log has an invalid logIndex")

    return _Log(
        address=to_checksum_address(address),
        topics=tuple(bytes.fromhex(t[2:]) for t in topics),
        data=bytes.fromhex(data[2:]),
        log_index=int(log_index, 16),
    )


def _decode_event(log: _Log) -> Event | None:
    """The registered event this log is, or None if it isn't exactly one."""
    if not log.topics:
        return None  # LOG0, or an anonymous event with no indexed arguments
    signature, indexed = log.topics[0], log.topics[1:]

    if signature in (TRANSFER_TOPIC, APPROVAL_TOPIC):
        amount: int | None = None
        token_id: int | None = None
        if len(indexed) == 2 and len(log.data) == WORD:
            standard, amount = TokenStandard.ERC20, int.from_bytes(log.data, "big")
        elif len(indexed) == 3 and not log.data:
            standard, token_id = TokenStandard.ERC721, int.from_bytes(indexed[2], "big")
        else:
            return None
        first, second = _address(indexed[0]), _address(indexed[1])
        if first is None or second is None:
            return None
        if signature == TRANSFER_TOPIC:
            return TokenTransfer(
                token=log.address,
                standard=standard,
                sender=first,
                recipient=second,
                amount=amount,
                token_id=token_id,
                log_index=log.log_index,
            )
        return TokenApproval(
            token=log.address,
            standard=standard,
            owner=first,
            spender=second,
            amount=amount,
            token_id=token_id,
            log_index=log.log_index,
        )

    if signature == APPROVAL_FOR_ALL_TOPIC:
        if len(indexed) != 2 or len(log.data) != WORD:
            return None
        owner, operator = _address(indexed[0]), _address(indexed[1])
        approved = int.from_bytes(log.data, "big")
        # The ABI encodes a bool as exactly 0 or 1. Anything else is not a
        # well-formed ApprovalForAll, whatever the contract meant by it.
        if owner is None or operator is None or approved not in (0, 1):
            return None
        return OperatorApproval(
            token=log.address,
            owner=owner,
            operator=operator,
            approved=bool(approved),
            log_index=log.log_index,
        )

    return None


def _address(word: bytes) -> str | None:
    """An indexed address: 20 bytes, left-padded with 12 zero bytes. Dirty
    padding is ambiguous (old compilers dropped it, new ones never write it),
    so it's not decoded."""
    if word[:12] != b"\x00" * 12:
        return None
    return to_checksum_address(word[12:])
