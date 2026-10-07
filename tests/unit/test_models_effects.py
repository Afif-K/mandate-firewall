"""Effects models: canonical values, range checks, invariants, JSON round trip."""

import json
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from mandate_firewall.models import (
    UINT256_MAX,
    CallFrame,
    CallType,
    Effects,
    NativeBalanceChange,
    OperatorApproval,
    RawLog,
    SimulationStatus,
    TokenApproval,
    TokenStandard,
    TokenStateCheck,
    TokenTransfer,
)

SENDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TOKEN = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
NFT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
TX_HASH = "0x" + "11" * 32
BLOCK_HASH = "0x" + "22" * 32
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
GAS_USED = 51_000
GAS_PRICE = 1_000_000_007


def effects(**overrides: Any) -> Effects:
    """A successful ERC-20 transfer of 50 USDC (6 decimals) from SENDER to BOB."""
    fields: dict[str, Any] = {
        "tx_hash": TX_HASH,
        "sender": SENDER,
        "chain_id": 84532,
        "fork_block_number": 1234,
        "fork_block_hash": BLOCK_HASH,
        "status": SimulationStatus.SUCCESS,
        "gas_used": GAS_USED,
        "effective_gas_price": GAS_PRICE,
        "gas_cost": GAS_USED * GAS_PRICE,
        "native_balance_changes": (
            NativeBalanceChange(address=SENDER, delta=-GAS_USED * GAS_PRICE),
        ),
        "token_transfers": (
            TokenTransfer(
                token=TOKEN,
                standard=TokenStandard.ERC20,
                sender=SENDER,
                recipient=BOB,
                amount=50_000_000,
                log_index=0,
            ),
        ),
        "calls": (
            CallFrame(
                depth=0,
                call_type=CallType.CALL,
                caller=SENDER,
                target=TOKEN,
                selector="0xa9059cbb",
            ),
        ),
        "token_state_checks": (
            TokenStateCheck(
                token=TOKEN,
                kind="balance",
                owner=SENDER,
                before=100_000_000,
                after=50_000_000,
                consistent=True,
            ),
        ),
    }
    return Effects(**(fields | overrides))


def test_json_round_trip() -> None:
    original = effects(
        token_approvals=(
            TokenApproval(
                token=TOKEN,
                standard=TokenStandard.ERC20,
                owner=SENDER,
                spender=BOB,
                amount=UINT256_MAX,
                log_index=1,
            ),
        ),
        operator_approvals=(
            OperatorApproval(token=NFT, owner=SENDER, operator=BOB, approved=True, log_index=2),
        ),
        unrecognized_logs=(
            RawLog(address=NFT, topics=(TRANSFER_TOPIC,), data="0x00ff", log_index=3),
        ),
        contracts_created=(NFT,),
    )
    assert Effects.model_validate_json(original.model_dump_json()) == original


def test_big_and_signed_integers_serialize_as_decimal_strings() -> None:
    loss = -(UINT256_MAX)  # the largest possible loss of a uint256 balance
    e = effects(
        native_balance_changes=(
            NativeBalanceChange(address=SENDER, delta=loss),
            NativeBalanceChange(address=BOB, delta=UINT256_MAX),
        )
    )
    data = json.loads(e.model_dump_json())
    assert [c["delta"] for c in data["native_balance_changes"]] == [str(loss), str(UINT256_MAX)]
    assert data["gas_cost"] == str(GAS_USED * GAS_PRICE)
    assert data["token_transfers"][0]["amount"] == "50000000"
    # Python mode keeps real ints.
    assert e.model_dump()["native_balance_changes"][0]["delta"] == loss


def test_models_are_frozen() -> None:
    e = effects()
    with pytest.raises(ValidationError):
        e.status = SimulationStatus.REVERTED  # type: ignore[misc]
    with pytest.raises(ValidationError):
        e.calls[0].target = BOB  # type: ignore[misc]
    assert isinstance(e.calls, tuple)


def test_unknown_fields_are_rejected() -> None:
    data = json.loads(effects().model_dump_json())
    data["note"] = "trust me"
    with pytest.raises(ValidationError):
        Effects.model_validate(data)


# --- canonical values ---------------------------------------------------------


def test_addresses_are_checksummed_and_hex_is_lowercased() -> None:
    frame = CallFrame(
        depth=0,
        call_type=CallType.CALL,
        caller=SENDER.lower(),
        target=BOB.upper().replace("0X", "0x"),
        selector="0xA9059CBB",
    )
    assert (frame.caller, frame.target, frame.selector) == (SENDER, BOB, "0xa9059cbb")
    log = RawLog(
        address=NFT,
        topics=(TRANSFER_TOPIC.upper().replace("0X", "0x"),),
        data="0xABCD",
        log_index=0,
    )
    assert (log.topics, log.data) == ((TRANSFER_TOPIC,), "0xabcd")


@pytest.mark.parametrize(
    "address",
    [
        SENDER.replace("f39F", "F39F"),  # mixed case with a broken checksum
        SENDER[2:],  # no 0x
        "0X" + SENDER[2:],
        SENDER + "00",  # 21 bytes
        SENDER[:-2],  # 19 bytes
        "0x" + "g" * 40,
        SENDER + "\n",
    ],
)
def test_invalid_addresses_are_rejected(address: str) -> None:
    with pytest.raises(ValidationError):
        NativeBalanceChange(address=address, delta=1)


@pytest.mark.parametrize("data", ["0x0", "0xabc", "abcd", "0xzz", "0x00\n"])
def test_hex_data_must_be_whole_bytes(data: str) -> None:
    with pytest.raises(ValidationError):
        RawLog(address=NFT, topics=(), data=data, log_index=0)


def test_raw_log_topics() -> None:
    with pytest.raises(ValidationError):  # the EVM allows at most 4 topics
        RawLog(address=NFT, topics=(TRANSFER_TOPIC,) * 5, data="0x", log_index=0)
    with pytest.raises(ValidationError):  # a topic is exactly 32 bytes
        RawLog(address=NFT, topics=("0x" + "ab" * 31,), data="0x", log_index=0)


def test_no_field_can_hold_free_text() -> None:
    """Attacker-chosen text (token names, revert reasons) must not be able to
    ride along in effects to the verifier. Every string anywhere in the schema
    is either pattern-constrained (hex, address) or an enum."""
    schema = Effects.model_json_schema()

    def free_strings(node: Any, path: str) -> list[str]:
        found: list[str] = []
        if isinstance(node, dict):
            if (
                node.get("type") == "string"
                and "pattern" not in node
                and "enum" not in node
                and "const" not in node
            ):
                found.append(path)
            for key, child in node.items():
                found += free_strings(child, f"{path}/{key}")
        elif isinstance(node, list):
            for i, child in enumerate(node):
                found += free_strings(child, f"{path}/{i}")
        return found

    assert free_strings(schema, "#") == []
    # And the check above does see strings: the schema has plenty.
    assert '"pattern"' in json.dumps(schema)


# --- integer ranges -------------------------------------------------------------


@pytest.mark.parametrize("value", [True, 1.0, "1_000", "0x10", "01", " 1", "", UINT256_MAX + 1, -1])
def test_amounts_are_strict_uint256(value: Any) -> None:
    with pytest.raises(ValidationError):
        TokenTransfer(
            token=TOKEN,
            standard=TokenStandard.ERC20,
            sender=SENDER,
            recipient=BOB,
            amount=value,
            log_index=0,
        )


def test_amounts_accept_ints_and_decimal_strings() -> None:
    transfer = TokenTransfer(
        token=TOKEN,
        standard=TokenStandard.ERC20,
        sender=SENDER,
        recipient=BOB,
        amount=str(UINT256_MAX),
        log_index=0,
    )
    assert transfer.amount == UINT256_MAX


@pytest.mark.parametrize("delta", [0, UINT256_MAX + 1, -UINT256_MAX - 1, False])
def test_balance_change_range_and_nonzero(delta: Any) -> None:
    with pytest.raises(ValidationError):
        NativeBalanceChange(address=SENDER, delta=delta)


# --- per-model invariants -------------------------------------------------------


@pytest.mark.parametrize("model", [TokenTransfer, TokenApproval])
def test_erc20_has_amount_and_erc721_has_token_id(model: type[BaseModel]) -> None:
    people = (
        {"sender": SENDER, "recipient": BOB}
        if model is TokenTransfer
        else {"owner": SENDER, "spender": BOB}
    )
    base = {"token": TOKEN, "log_index": 0, **people}
    model(**base, standard=TokenStandard.ERC20, amount=1)
    model(**base, standard=TokenStandard.ERC721, token_id=0)  # token id 0 is a real token
    for bad in (
        {"standard": TokenStandard.ERC20},
        {"standard": TokenStandard.ERC20, "amount": 1, "token_id": 1},
        {"standard": TokenStandard.ERC721},
        {"standard": TokenStandard.ERC721, "amount": 1},
    ):
        with pytest.raises(ValidationError):
            model(**base, **bad)


def test_state_check_spender_only_for_allowances() -> None:
    base = {"token": TOKEN, "owner": SENDER, "before": 0, "after": 5, "consistent": False}
    TokenStateCheck(**base, kind="allowance", spender=BOB)
    with pytest.raises(ValidationError):
        TokenStateCheck(**base, kind="allowance")
    with pytest.raises(ValidationError):
        TokenStateCheck(**base, kind="balance", spender=BOB)
    with pytest.raises(ValidationError):
        TokenStateCheck(**base, kind="name", spender=None)  # type: ignore[arg-type]


# --- Effects invariants ---------------------------------------------------------


def test_reverted_transaction() -> None:
    reverted = effects(
        status=SimulationStatus.REVERTED,
        revert_data="0x08c379a0",
        token_transfers=(),
        token_state_checks=(),
    )
    assert reverted.revert_data == "0x08c379a0"
    with pytest.raises(ValidationError, match="can't have logs"):
        effects(status=SimulationStatus.REVERTED)  # still has the token transfer
    with pytest.raises(ValidationError, match="can't have logs"):
        effects(status=SimulationStatus.REVERTED, token_transfers=(), contracts_created=(NFT,))
    with pytest.raises(ValidationError, match="no revert data"):
        effects(revert_data="0x")


def test_gas_cost_must_match() -> None:
    with pytest.raises(ValidationError, match="gas_cost"):
        effects(gas_cost=GAS_USED * GAS_PRICE - 1)


def test_call_tree_shape() -> None:
    top = effects().calls[0]
    inner = CallFrame(depth=1, call_type=CallType.DELEGATECALL, caller=TOKEN, target=NFT)
    effects(calls=(top, inner))
    with pytest.raises(ValidationError):
        effects(calls=())
    with pytest.raises(ValidationError, match="first call frame"):
        effects(calls=(inner,))
    with pytest.raises(ValidationError, match="first call frame"):
        effects(calls=(top.model_copy(update={"caller": BOB}),))
    with pytest.raises(ValidationError, match="exactly one top-level"):
        effects(calls=(top, top))


def test_one_balance_change_per_address() -> None:
    with pytest.raises(ValidationError, match="one native balance change"):
        effects(
            native_balance_changes=(
                NativeBalanceChange(address=SENDER, delta=-1),
                NativeBalanceChange(address=SENDER.lower(), delta=-2),  # same address, other case
            )
        )


def test_each_log_lands_in_one_list() -> None:
    duplicate = RawLog(address=NFT, topics=(), data="0x", log_index=0)  # index 0 is the transfer
    with pytest.raises(ValidationError, match="log index"):
        effects(unrecognized_logs=(duplicate,))
