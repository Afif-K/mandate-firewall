"""Flows: the principal's movements of money and the anomalies, from Effects."""

from typing import Any

import pytest

from mandate_firewall.models import (
    CallFrame,
    CallType,
    Effects,
    NativeBalanceChange,
    RawLog,
    SimulationStatus,
    TokenStandard,
    TokenStateCheck,
    TokenTransfer,
)
from mandate_firewall.verify.flows import INFORMATIONAL_EVENTS, FlowAnalysis, analyze
from mandate_firewall.verify.models import (
    NATIVE,
    Anomaly,
    AnomalyCode,
    Asset,
    Flow,
    FlowDirection,
)
from tests.schema import free_string_paths

ALICE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # the principal
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
THIEF = "0x000000000000000000000000000000000000dEaD"
TOKEN = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
NFT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ROUTER = "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"
POOL = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
GAS = 21_000 * 10**9
ETH = 10**18

OUT, IN = FlowDirection.OUT, FlowDirection.IN
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
UNISWAP_SWAP = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
WETH_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
WETH_WITHDRAWAL = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"


def word(address: str) -> str:
    """An address as the ABI encodes it in a topic or a data word."""
    return "0x" + "00" * 12 + address[2:].lower()


def frame(depth: int, caller: str, target: str | None, value: int = 0, **kw: Any) -> CallFrame:
    call_type = kw.pop("call_type", CallType.CALL)
    return CallFrame(
        depth=depth, call_type=call_type, caller=caller, target=target, value=value, **kw
    )


def effects(
    *calls: CallFrame, alice_delta: int | None = None, gas: int = GAS, **overrides: Any
) -> Effects:
    """Effects of a transaction from ALICE. By default a plain call to ROUTER
    with no value. `alice_delta` is ALICE's measured ETH change; by default
    the one that reconciles with the frames and the gas."""
    calls = calls or (frame(0, ALICE, ROUTER),)
    if alice_delta is None:
        live = [f for f in calls if not f.reverted and f.target is not None]
        alice_delta = (
            sum(f.value for f in live if f.target == ALICE and f.caller != ALICE)
            - sum(f.value for f in live if f.caller == ALICE and f.target != ALICE)
            - gas
        )
    changes = (NativeBalanceChange(address=ALICE, delta=alice_delta),) if alice_delta else ()
    fields: dict[str, Any] = {
        "tx_hash": "0x" + "11" * 32,
        "sender": ALICE,
        "chain_id": 84532,
        "fork_block_number": 1,
        "fork_block_hash": "0x" + "22" * 32,
        "status": SimulationStatus.SUCCESS,
        "gas_used": gas // 10**9,
        "effective_gas_price": 10**9,
        "gas_cost": gas,
        "native_balance_changes": changes,
        "calls": calls,
    }
    return Effects(**(fields | overrides))


def erc20(sender: str, recipient: str, amount: int, log_index: int, token: str = TOKEN):
    return TokenTransfer(
        token=token,
        standard=TokenStandard.ERC20,
        sender=sender,
        recipient=recipient,
        amount=amount,
        log_index=log_index,
    )


def balance_check(owner: str, claimed: int, consistent: bool = True, token: str = TOKEN):
    before = 10**12
    after = before + claimed if consistent else before
    return TokenStateCheck(
        token=token,
        kind="balance",
        owner=owner,
        before=before,
        after=after,
        claimed=claimed,
        consistent=consistent,
    )


def raw_log(topics: tuple[str, ...], data: str = "0x", log_index: int = 0) -> RawLog:
    return RawLog(address=POOL, topics=topics, data=data, log_index=log_index)


def codes(analysis: FlowAnalysis) -> list[AnomalyCode]:
    return [a.code for a in analysis.anomalies]


# --- ETH ------------------------------------------------------------------------------


def test_plain_eth_send() -> None:
    result = analyze(effects(frame(0, ALICE, BOB, ETH)), ALICE)
    assert result.flows == (Flow(asset=NATIVE, direction=OUT, counterparty=BOB, amount=ETH),)
    assert result.anomalies == ()


def test_gas_is_not_a_flow() -> None:
    result = analyze(effects(frame(0, ALICE, BOB, 0)), ALICE)
    assert result == FlowAnalysis(flows=(), anomalies=())


def test_eth_forwarded_by_a_contract_is_a_flow_to_that_contract() -> None:
    # The principal's view: ETH left it for the forwarder. Where the
    # forwarder sent it next isn't the principal's flow (it is in the
    # effects, and the matcher's target rule decides about the forwarder).
    result = analyze(effects(frame(0, ALICE, ROUTER, ETH), frame(1, ROUTER, THIEF, ETH)), ALICE)
    assert result.flows == (Flow(asset=NATIVE, direction=OUT, counterparty=ROUTER, amount=ETH),)
    assert result.anomalies == ()


def test_eth_sent_back_by_a_contract_is_an_inflow() -> None:
    # A router unwrapping WETH and paying the principal in ETH.
    result = analyze(effects(frame(0, ALICE, ROUTER), frame(1, ROUTER, ALICE, 3 * ETH)), ALICE)
    assert result.flows == (Flow(asset=NATIVE, direction=IN, counterparty=ROUTER, amount=3 * ETH),)
    assert result.anomalies == ()


def test_reverted_frames_move_nothing() -> None:
    calls = (
        frame(0, ALICE, ROUTER),
        frame(1, ROUTER, ALICE, ETH, reverted=True),
        frame(1, ROUTER, BOB, ETH, reverted=True),
    )
    result = analyze(effects(*calls), ALICE)
    assert result == FlowAnalysis(flows=(), anomalies=())


def test_eth_to_oneself_is_not_a_flow() -> None:
    result = analyze(effects(frame(0, ALICE, ALICE, ETH)), ALICE)
    assert result == FlowAnalysis(flows=(), anomalies=())


def test_flows_to_one_counterparty_are_summed() -> None:
    calls = (
        frame(0, ALICE, ROUTER),
        frame(1, ROUTER, ALICE, 2),
        frame(1, ROUTER, ALICE, 3),
        frame(1, POOL, ALICE, 7),
    )
    result = analyze(effects(*calls), ALICE)
    assert result.flows == (
        Flow(asset=NATIVE, direction=IN, counterparty=ROUTER, amount=5),
        Flow(asset=NATIVE, direction=IN, counterparty=POOL, amount=7),
    )


@pytest.mark.parametrize("off_by", [1, -1, -ETH])
def test_eth_the_trace_does_not_explain_is_an_anomaly(off_by: int) -> None:
    # -ETH: the account lost a whole ether that no frame shows leaving.
    result = analyze(effects(frame(0, ALICE, BOB, ETH), alice_delta=-ETH - GAS + off_by), ALICE)
    assert codes(result) == [AnomalyCode.NATIVE_BALANCE_UNRECONCILED]


def test_no_measured_change_when_the_arithmetic_says_none() -> None:
    # Zero gas price (possible on a dev chain): no balance change at all.
    result = analyze(effects(frame(0, ALICE, BOB, 0), gas=0), ALICE)
    assert result == FlowAnalysis(flows=(), anomalies=())


@pytest.mark.parametrize(
    "inner",
    [
        frame(1, ALICE, THIEF, ETH),  # the account itself sends ETH from inside the tx
        frame(1, ALICE, THIEF, call_type=CallType.DELEGATECALL),
        frame(1, ALICE, THIEF, reverted=True),  # even rolled back, the account ran code
    ],
)
def test_the_principal_running_code_is_an_anomaly(inner: CallFrame) -> None:
    calls = (frame(0, ALICE, ALICE), inner, inner.model_copy(update={"value": 0}))
    result = analyze(effects(*calls), ALICE)
    assert codes(result) == [AnomalyCode.PRINCIPAL_RUNS_CODE]  # once, however many frames


def test_eth_the_principal_sends_from_inside_is_still_a_flow() -> None:
    calls = (frame(0, ALICE, ALICE), frame(1, ALICE, THIEF, ETH))
    result = analyze(effects(*calls), ALICE)
    assert result.flows == (Flow(asset=NATIVE, direction=OUT, counterparty=THIEF, amount=ETH),)


# --- tokens ---------------------------------------------------------------------------


def test_erc20_out_and_in() -> None:
    result = analyze(
        effects(
            token_transfers=(erc20(ALICE, POOL, 100, 0), erc20(POOL, ALICE, 31, 1, token=NFT)),
            token_state_checks=(balance_check(ALICE, -100), balance_check(ALICE, 31, token=NFT)),
        ),
        ALICE,
    )
    assert result.flows == (
        Flow(asset=Asset(token=TOKEN), direction=OUT, counterparty=POOL, amount=100),
        Flow(asset=Asset(token=NFT), direction=IN, counterparty=POOL, amount=31),
    )
    assert result.anomalies == ()


def test_token_flows_are_summed_per_counterparty_and_direction() -> None:
    result = analyze(
        effects(
            token_transfers=(
                erc20(ALICE, BOB, 10, 0),
                erc20(ALICE, BOB, 5, 1),
                erc20(ALICE, THIEF, 1, 2),
                erc20(BOB, ALICE, 4, 3),
            ),
            token_state_checks=(balance_check(ALICE, -12),),
        ),
        ALICE,
    )
    assert [(f.direction, f.counterparty, f.amount) for f in result.flows] == [
        (OUT, BOB, 15),
        (OUT, THIEF, 1),
        (IN, BOB, 4),
    ]


def test_an_nft_counts_as_one() -> None:
    nft = TokenTransfer(
        token=NFT,
        standard=TokenStandard.ERC721,
        sender=ALICE,
        recipient=THIEF,
        token_id=7,
        log_index=0,
    )
    result = analyze(
        effects(token_transfers=(nft,), token_state_checks=(balance_check(ALICE, -1, token=NFT),)),
        ALICE,
    )
    assert result.flows == (
        Flow(asset=Asset(token=NFT), direction=OUT, counterparty=THIEF, amount=1),
    )


def test_transfers_that_move_nothing_are_not_flows() -> None:
    result = analyze(
        effects(
            token_transfers=(
                erc20(ALICE, ALICE, 10, 0),  # to oneself
                erc20(ALICE, BOB, 0, 1),  # zero amount
                erc20(BOB, POOL, 99, 2),  # not the principal's
            ),
        ),
        ALICE,
    )
    assert result == FlowAnalysis(flows=(), anomalies=())


def test_mint_to_the_principal_is_an_inflow_from_the_zero_address() -> None:
    zero = "0x0000000000000000000000000000000000000000"
    result = analyze(
        effects(
            token_transfers=(erc20(zero, ALICE, 8, 0),),
            token_state_checks=(balance_check(ALICE, 8),),
        ),
        ALICE,
    )
    assert result.flows == (
        Flow(asset=Asset(token=TOKEN), direction=IN, counterparty=zero, amount=8),
    )


def test_inconsistent_state_anywhere_is_an_anomaly() -> None:
    # The LyingToken pattern: Alice's debit is honest, Bob never got paid.
    result = analyze(
        effects(
            token_transfers=(erc20(ALICE, BOB, 10, 0),),
            token_state_checks=(balance_check(ALICE, -10), balance_check(BOB, 10, False)),
        ),
        ALICE,
    )
    assert result.anomalies == (
        Anomaly(code=AnomalyCode.INCONSISTENT_TOKEN_STATE, contract=TOKEN, account=BOB),
    )
    # The flow is still reported, so the audit record shows the claim.
    assert len(result.flows) == 1


def test_a_token_flow_without_a_balance_check_for_the_principal_is_an_anomaly() -> None:
    # M2 always plans one, so this means the effects were built some other way.
    result = analyze(effects(token_transfers=(erc20(ALICE, BOB, 10, 0),)), ALICE)
    assert result.anomalies == (
        Anomaly(code=AnomalyCode.INCONSISTENT_TOKEN_STATE, contract=TOKEN, account=ALICE),
    )


def test_an_inconsistent_principal_check_is_reported_once() -> None:
    result = analyze(
        effects(
            token_transfers=(erc20(ALICE, BOB, 10, 0),),
            token_state_checks=(balance_check(ALICE, -10, False),),
        ),
        ALICE,
    )
    assert codes(result) == [AnomalyCode.INCONSISTENT_TOKEN_STATE]


# --- unrecognized logs ---------------------------------------------------------------


@pytest.mark.parametrize(
    "log",
    [
        raw_log(("0x" + "ab" * 32, word(ALICE))),  # an indexed argument
        raw_log((word(ALICE),)),  # topic 0 of an anonymous event
        raw_log((), data=word(ALICE)),  # LOG0, data only
        raw_log(("0x" + "ab" * 32,), data="0x" + "00" * 32 + word(ALICE)[2:]),  # 2nd data word
        raw_log((WETH_WITHDRAWAL, word(ALICE)), data="0x" + "00" * 31 + "05"),  # WETH out
    ],
)
def test_an_unrecognized_event_about_the_principal_is_an_anomaly(log: RawLog) -> None:
    result = analyze(effects(unrecognized_logs=(log,)), ALICE)
    assert result.anomalies == (
        Anomaly(code=AnomalyCode.UNRECOGNIZED_EVENT, contract=POOL, log_index=0),
    )


@pytest.mark.parametrize(
    "log",
    [
        raw_log(("0x" + "ab" * 32, word(BOB))),  # about someone else
        raw_log(("0x" + "ab" * 32,), data="0x00" + word(ALICE)[2:]),  # unaligned: a known limit
        raw_log((UNISWAP_SWAP, word(ROUTER), word(ALICE)), data="0x" + "00" * 160),
        raw_log((WETH_DEPOSIT, word(ALICE)), data="0x" + "00" * 31 + "05"),
    ],
)
def test_other_unrecognized_events_are_not_anomalies(log: RawLog) -> None:
    assert analyze(effects(unrecognized_logs=(log,)), ALICE).anomalies == ()


def test_informational_signatures_are_the_known_topics() -> None:
    # Pinned against the well-known topic hashes, so a typo in a signature
    # string can't silently suppress the wrong event.
    assert set(INFORMATIONAL_EVENTS) == {UNISWAP_SWAP, WETH_DEPOSIT}
    assert WETH_WITHDRAWAL not in INFORMATIONAL_EVENTS
    assert TRANSFER_TOPIC not in INFORMATIONAL_EVENTS


# --- contracts created, and inputs ------------------------------------------------------


def test_created_contracts_are_anomalies() -> None:
    calls = (
        frame(0, ALICE, ROUTER),
        frame(1, ROUTER, NFT, call_type=CallType.CREATE),
        frame(1, ROUTER, POOL, call_type=CallType.CREATE2),
    )
    result = analyze(effects(*calls, contracts_created=(NFT, POOL)), ALICE)
    assert result.anomalies == (
        Anomaly(code=AnomalyCode.CONTRACT_CREATED, contract=NFT),
        Anomaly(code=AnomalyCode.CONTRACT_CREATED, contract=POOL),
    )


def test_anomalies_come_together() -> None:
    result = analyze(
        effects(
            frame(0, ALICE, ROUTER),
            frame(1, ALICE, THIEF),
            alice_delta=-1,
            unrecognized_logs=(raw_log((word(ALICE),)),),
            contracts_created=(NFT,),
        ),
        ALICE,
    )
    assert codes(result) == [
        AnomalyCode.PRINCIPAL_RUNS_CODE,
        AnomalyCode.NATIVE_BALANCE_UNRECONCILED,
        AnomalyCode.UNRECOGNIZED_EVENT,
        AnomalyCode.CONTRACT_CREATED,
    ]


def test_reverted_effects_are_refused() -> None:
    reverted = effects(status=SimulationStatus.REVERTED, revert_data="0x")
    with pytest.raises(ValueError, match="successful"):
        analyze(reverted, ALICE)


def test_effects_of_another_sender_are_refused() -> None:
    with pytest.raises(ValueError, match="principal"):
        analyze(effects(), BOB)


def test_the_analysis_holds_no_free_text() -> None:
    assert free_string_paths(FlowAnalysis.model_json_schema()) == []
