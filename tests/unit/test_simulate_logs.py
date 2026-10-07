"""Receipt log decoding on hand-built logs."""

from typing import Any

import pytest

from mandate_firewall.models import (
    UINT256_MAX,
    CallFrame,
    CallType,
    Effects,
    RawLog,
    SimulationStatus,
    TokenStandard,
)
from mandate_firewall.simulate.logs import (
    APPROVAL_FOR_ALL_TOPIC,
    APPROVAL_TOPIC,
    TRANSFER_TOPIC,
    DecodedLogs,
    LogDecodeError,
    decode_logs,
)

TX_HASH = "0x" + "11" * 32
TOKEN = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
NFT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ZERO = "0x0000000000000000000000000000000000000000"


def word(value: int | str) -> str:
    """A 32-byte topic or data word: an int, or an address left-padded."""
    if isinstance(value, str):
        return "0x" + "00" * 12 + value[2:].lower()
    return "0x" + value.to_bytes(32, "big").hex()


def log(
    topics: list[str],
    data: str = "0x",
    index: int = 0,
    address: str = TOKEN,
    **overrides: Any,
) -> dict[str, Any]:
    """A log object as eth_getTransactionReceipt returns it."""
    return {
        "address": address.lower(),
        "topics": topics,
        "data": data,
        "blockHash": "0x" + "22" * 32,
        "blockNumber": "0x4d3",
        "transactionHash": TX_HASH,
        "transactionIndex": "0x0",
        "logIndex": hex(index),
        "removed": False,
        **overrides,
    }


def transfer20(sender: str = ALICE, recipient: str = BOB, amount: int = 50_000_000, **kw: Any):
    return log(["0x" + TRANSFER_TOPIC.hex(), word(sender), word(recipient)], word(amount), **kw)


def decode_one(entry: dict[str, Any]) -> DecodedLogs:
    decoded = decode_logs([entry], TX_HASH)
    total = sum(
        len(group)
        for group in (
            decoded.transfers,
            decoded.approvals,
            decoded.operator_approvals,
            decoded.unrecognized,
        )
    )
    assert total == 1  # never dropped, never duplicated
    return decoded


def test_registry_topics_are_the_standard_ones() -> None:
    # Pinned literally, so a typo in a signature string can't go unnoticed.
    assert TRANSFER_TOPIC.hex() == (
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert APPROVAL_TOPIC.hex() == (
        "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
    )
    assert APPROVAL_FOR_ALL_TOPIC.hex() == (
        "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
    )


# --- recognized events ----------------------------------------------------------


def test_erc20_transfer() -> None:
    (transfer,) = decode_one(transfer20(index=7)).transfers
    assert transfer.token == TOKEN  # checksummed, from the lowercase log address
    assert transfer.standard is TokenStandard.ERC20
    assert (transfer.sender, transfer.recipient) == (ALICE, BOB)
    assert (transfer.amount, transfer.token_id, transfer.log_index) == (50_000_000, None, 7)


def test_erc721_transfer_is_told_apart_by_topic_count() -> None:
    entry = log(["0x" + TRANSFER_TOPIC.hex(), word(ALICE), word(BOB), word(42)], address=NFT)
    (transfer,) = decode_one(entry).transfers
    assert transfer.standard is TokenStandard.ERC721
    assert (transfer.token, transfer.token_id, transfer.amount) == (NFT, 42, None)


def test_mint_and_burn() -> None:
    (mint,) = decode_one(transfer20(sender=ZERO)).transfers
    (burn,) = decode_one(transfer20(recipient=ZERO)).transfers
    assert mint.sender == ZERO and burn.recipient == ZERO


def test_erc20_unlimited_approval() -> None:
    entry = log(["0x" + APPROVAL_TOPIC.hex(), word(ALICE), word(BOB)], word(UINT256_MAX))
    (approval,) = decode_one(entry).approvals
    assert approval.standard is TokenStandard.ERC20
    assert (approval.owner, approval.spender, approval.amount) == (ALICE, BOB, UINT256_MAX)


def test_erc721_single_token_approval() -> None:
    entry = log(["0x" + APPROVAL_TOPIC.hex(), word(ALICE), word(BOB), word(0)], address=NFT)
    (approval,) = decode_one(entry).approvals
    assert approval.standard is TokenStandard.ERC721
    assert (approval.spender, approval.token_id, approval.amount) == (BOB, 0, None)


@pytest.mark.parametrize("flag", [0, 1])
def test_approval_for_all(flag: int) -> None:
    entry = log(
        ["0x" + APPROVAL_FOR_ALL_TOPIC.hex(), word(ALICE), word(BOB)], word(flag), address=NFT
    )
    (approval,) = decode_one(entry).operator_approvals
    assert (approval.token, approval.owner, approval.operator) == (NFT, ALICE, BOB)
    assert approval.approved is bool(flag)


# --- valid logs we don't recognize --------------------------------------------------

T, A, AFA = ("0x" + t.hex() for t in (TRANSFER_TOPIC, APPROVAL_TOPIC, APPROVAL_FOR_ALL_TOPIC))
DIRTY = "0x" + "00" * 11 + "01" + BOB[2:].lower()  # BOB with a non-zero padding byte


@pytest.mark.parametrize(
    ("topics", "data"),
    [
        pytest.param(["0x" + "ab" * 32, word(ALICE), word(BOB)], word(1), id="unknown topic0"),
        pytest.param([], "0x1234", id="no topics (LOG0)"),
        pytest.param(
            [T], "0x" + word(ALICE)[2:] + word(BOB)[2:] + word(1)[2:], id="nothing indexed"
        ),
        pytest.param([T, word(ALICE)], word(1), id="transfer, 2 topics"),
        pytest.param([T, word(ALICE), word(BOB)], "0x" + "00" * 31, id="erc20 data 31 bytes"),
        pytest.param([T, word(ALICE), word(BOB)], "0x" + "00" * 33, id="erc20 data 33 bytes"),
        pytest.param([T, word(ALICE), word(BOB)], "0x", id="erc20 no data"),
        pytest.param([T, word(ALICE), word(BOB), word(1)], word(1), id="erc721 with data"),
        pytest.param([T, word(ALICE), DIRTY], word(1), id="dirty recipient padding"),
        pytest.param([T, DIRTY, word(BOB), word(1)], "0x", id="erc721 dirty sender padding"),
        pytest.param([A, DIRTY, word(BOB)], word(1), id="approval dirty owner padding"),
        pytest.param([A, word(ALICE), word(BOB)], word(1) + "00", id="approval odd data length"),
        pytest.param([AFA, word(ALICE), word(BOB)], word(2), id="approval-for-all bool is 2"),
        pytest.param(
            [AFA, word(ALICE), word(BOB), word(1)], word(1), id="approval-for-all 4 topics"
        ),
        pytest.param([AFA, word(ALICE)], word(1), id="approval-for-all 2 topics"),
        pytest.param([AFA, word(ALICE), DIRTY], word(1), id="approval-for-all dirty operator"),
    ],
)
def test_near_misses_are_kept_as_unrecognized(topics: list[str], data: str) -> None:
    entry = log(topics, data, index=3)
    (raw,) = decode_one(entry).unrecognized
    assert raw == RawLog(address=TOKEN, topics=tuple(topics), data=data, log_index=3)


def test_mixed_receipt_keeps_every_log_in_order() -> None:
    entries = [
        transfer20(index=0),
        log(["0x" + "ab" * 32], index=1),
        log([A, word(ALICE), word(BOB)], word(5), index=2),
        transfer20(amount=1, index=3),
        log([AFA, word(ALICE), word(BOB)], word(1), index=4, address=NFT),
    ]
    decoded = decode_logs(entries, TX_HASH)
    assert [t.log_index for t in decoded.transfers] == [0, 3]
    assert [a.log_index for a in decoded.approvals] == [2]
    assert [o.log_index for o in decoded.operator_approvals] == [4]
    assert [r.log_index for r in decoded.unrecognized] == [1]

    # The result fits straight into Effects, whose invariants re-check it.
    Effects(
        tx_hash=TX_HASH,
        sender=ALICE,
        chain_id=84532,
        fork_block_number=1234,
        fork_block_hash="0x" + "22" * 32,
        status=SimulationStatus.SUCCESS,
        gas_used=1,
        effective_gas_price=1,
        gas_cost=1,
        calls=(CallFrame(depth=0, call_type=CallType.CALL, caller=ALICE, target=TOKEN),),
        token_transfers=decoded.transfers,
        token_approvals=decoded.approvals,
        operator_approvals=decoded.operator_approvals,
        unrecognized_logs=decoded.unrecognized,
    )


def test_no_logs() -> None:
    assert decode_logs([], TX_HASH) == DecodedLogs()


def test_uppercase_hex_from_the_node_is_accepted() -> None:
    entry = transfer20()
    entry["topics"] = [t.upper().replace("0X", "0x") for t in entry["topics"]]
    entry["transactionHash"] = TX_HASH.upper().replace("0X", "0x")
    (transfer,) = decode_one(entry).transfers
    assert transfer.recipient == BOB


# --- logs the node shouldn't have sent ------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"removed": True}, id="removed"),
        pytest.param({"transactionHash": "0x" + "33" * 32}, id="other tx"),
        pytest.param({"transactionHash": None}, id="no tx hash"),
        pytest.param({"address": TOKEN[:-2]}, id="short address"),
        pytest.param({"address": None}, id="no address"),
        pytest.param({"topics": [T] * 5}, id="5 topics"),
        pytest.param({"topics": T}, id="topics not a list"),
        pytest.param({"topics": [T[:-2]]}, id="short topic"),
        pytest.param({"topics": [T + "00"]}, id="long topic"),
        pytest.param({"data": "0x0"}, id="odd data"),
        pytest.param({"data": "1234"}, id="data without 0x"),
        pytest.param({"data": None}, id="no data"),
        pytest.param({"logIndex": None}, id="no logIndex"),
        pytest.param({"logIndex": 0}, id="logIndex not hex"),
        pytest.param({"logIndex": "0x01"}, id="logIndex leading zero"),
        pytest.param({"logIndex": "0x"}, id="logIndex empty"),
    ],
)
def test_malformed_logs_raise(overrides: dict[str, Any]) -> None:
    entry = transfer20() | overrides
    with pytest.raises(LogDecodeError):
        decode_logs([entry], TX_HASH)


@pytest.mark.parametrize("logs", [None, {}, "0x", [None], [[]]])
def test_malformed_log_list_raises(logs: Any) -> None:
    with pytest.raises(LogDecodeError):
        decode_logs(logs, TX_HASH)


@pytest.mark.parametrize("indexes", [[0, 0], [1, 0]])
def test_log_indexes_must_increase(indexes: list[int]) -> None:
    with pytest.raises(LogDecodeError, match="strictly increasing"):
        decode_logs([transfer20(index=i) for i in indexes], TX_HASH)
