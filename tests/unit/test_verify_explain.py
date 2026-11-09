"""Explanations (docs/m4-plan.md §5): fixed templates, full addresses, exact
amounts, registry names only, and an agent message without mandate values."""

import re
from typing import Any

import pytest

from mandate_firewall.mandate.models import (
    AssetRef,
    Budget,
    Mandate,
    Ratio,
    SwapIntent,
    TransferIntent,
)
from mandate_firewall.mandate.registry import load_registry
from mandate_firewall.models import UINT256_MAX, Decision
from mandate_firewall.verify.explain import AGENT_ANOMALY, AGENT_VIOLATION, agent_reason, explain
from mandate_firewall.verify.matcher import match
from mandate_firewall.verify.models import (
    NATIVE,
    Anomaly,
    AnomalyCode,
    ApprovalLimit,
    Asset,
    Charge,
    Flow,
    FlowDirection,
    Verdict,
    Violation,
    ViolationCode,
)
from tests.unit import test_verify_matcher as M
from tests.unit.test_verify_matcher import (
    ALICE,
    BOB,
    CHAIN,
    DAI,
    NFT,
    POOL,
    ROUTER,
    THIEF,
    TX_HASH,
    USD,
    USDC,
    WETH,
)

REGISTRY = load_registry(CHAIN)  # knows ETH, USDC, WETH and SwapRouter02 (= ROUTER)
MID = "0x" + "3f" * 32
V = ViolationCode
A = AnomalyCode


def ref(token: str | None, decimals: int) -> AssetRef:
    return AssetRef(chain_id=CHAIN, address=token, decimals=decimals)


SEND_ETH = TransferIntent(
    kind="transfer", asset=ref(None, 18), budget=Budget(max=10**16, period=None), recipient=BOB
)
SEND_USDC = TransferIntent(
    kind="transfer", asset=ref(USDC, 6), budget=Budget(max=50 * USD, period=None), recipient=BOB
)
SWAP = SwapIntent(
    kind="swap",
    sell=ref(USDC, 6),
    sell_budget=Budget(max=100 * USD, period=None),
    buy=ref(WETH, 18),
    min_buy_per_sell=Ratio(numerator=3 * 10**16, denominator=100 * USD),
    venues=(ROUTER,),
)


def mandate(*intents: TransferIntent | SwapIntent, instruction: str = "pay Bob") -> Mandate:
    return M.mandate(*intents).model_copy(update={"instruction": instruction})


# intent 1: 0.01 ETH to Bob, 0.004 spent; intent 2: 50 USDC to Bob; intent 3: the swap, 40 spent.
THREE = mandate(SEND_ETH, SEND_USDC, SWAP)
SPENT = (4 * 10**15, 0, 40 * USD)


def blocked(*violations: Violation, flows: tuple[Flow, ...] = ()) -> Verdict:
    return Verdict(decision=Decision.BLOCK, flows=flows, violations=violations)


def why(v: Verdict, m: Mandate = THREE, spent: tuple[int, ...] = SPENT) -> list[str]:
    """The lines under "Why:"."""
    lines = explain(v, m, spent, REGISTRY, tx_hash=TX_HASH, mandate_id=MID).splitlines()
    start = lines.index("Why:") + 1
    end = lines.index("Nothing was charged.")
    return [line.removeprefix("  - ") for line in lines[start:end]]


# --- whole explanations (golden) ------------------------------------------------------


def test_demo_step_6_block() -> None:
    """docs/m4-plan.md §7 step 4: 0.001 ETH to dEaD under "0.01 ETH to Bob"."""
    m = mandate(SEND_ETH)
    t = M.tx(THIEF, value=10**15)
    v = match(m, (4 * 10**15,), t, M.effects(t))
    text = explain(v, m, (4 * 10**15,), REGISTRY, tx_hash=TX_HASH, mandate_id=MID)
    assert text == (
        f"BLOCKED  tx {TX_HASH}\n"
        f"  under mandate {MID}\n"
        "You asked:\n"
        '  you said: "pay Bob"\n'
        "  1. SEND at most 0.01 ETH (native)\n"
        f"       to {BOB}\n"
        "       left before this transaction: 0.006 ETH\n"
        "This transaction:\n"
        f"  sends 0.001 ETH (native) to {THIEF}\n"
        "Why:\n"
        f"  - it calls {THIEF}, which your mandate doesn't name\n"
        f"  - it sends 0.001 ETH (native) to {THIEF}, a recipient your mandate doesn't name\n"
        "Nothing was charged."
    )
    assert (
        agent_reason(v) == "off-mandate: target contract not in mandate; recipient not in mandate"
    )


def test_allowed_shows_the_charge_and_what_is_left() -> None:
    m = mandate(SEND_ETH)
    t = M.tx(BOB, value=4 * 10**15)
    v = match(m, (0,), t, M.effects(t))
    text = explain(v, m, (0,), REGISTRY, tx_hash=TX_HASH, mandate_id=MID)
    assert text.splitlines()[0] == f"ALLOWED  tx {TX_HASH}"
    assert text.endswith(
        "       left before this transaction: 0.01 ETH\n"
        "This transaction:\n"
        f"  sends 0.004 ETH (native) to {BOB}\n"
        "Charged:\n"
        "  intent 1: 0.004 ETH (native), 0.006 ETH left"
    )
    with pytest.raises(ValueError, match="no rejection reason"):
        agent_reason(v)


def test_allowed_swap_with_approval() -> None:
    v = Verdict(
        decision=Decision.ALLOW,
        flows=(
            Flow(
                asset=Asset(token=USDC), direction=FlowDirection.OUT, counterparty=POOL, amount=USD
            ),
            Flow(asset=Asset(token=WETH), direction=FlowDirection.IN, counterparty=POOL, amount=3),
        ),
        charges=(Charge(intent_index=2, amount=USD),),
        approval_limits=(ApprovalLimit(intent_index=2, amount=59 * USD),),
    )
    text = explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)
    assert text.endswith(
        "This transaction:\n"
        f"  sends 1 USDC (token {USDC}) to {POOL}\n"
        f"  receives 0.000000000000000003 WETH (token {WETH}) from {POOL}\n"
        "Charged:\n"
        f"  intent 3: 1 USDC (token {USDC}), 59 USDC left\n"
        f"  intent 3: approves its venues to spend up to 59 USDC (token {USDC}) "
        "(not charged; the swap that uses it is)"
    )


def test_allowed_with_no_charge() -> None:
    v = Verdict(decision=Decision.ALLOW)
    text = explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)
    assert text.endswith(
        "This transaction:\n"
        "  moves no assets into or out of your account (apart from gas)\n"
        "Charged: nothing."
    )


def test_swap_mandate_you_asked_is_the_capture_text() -> None:
    """ "You asked" reuses render.py's intent lines: what the user confirmed."""
    text = explain(blocked(Violation(code=V.AMBIGUOUS_SWAP)), THREE, SPENT, REGISTRY,
                   tx_hash=TX_HASH, mandate_id=MID)  # fmt: skip
    assert (
        "  3. SWAP sell at most 100 USDC (token 0x036CbD53842c5426634e7929541eC2318f3dCF7e)\n"
        "       buy WETH (token 0x4200000000000000000000000000000000000006)\n"
        "       minimum: at least 0.03 WETH per 100 USDC sold\n"
        "       only via:\n"
        f"         Uniswap v3 SwapRouter02 ({ROUTER})\n"
        "       left before this transaction: 60 USDC\n"
    ) in text
    assert "  2. SEND at most 50 USDC (token 0x036CbD53842c5426634e7929541eC2318f3dCF7e)\n" in text


def test_escalation() -> None:
    v = Verdict(
        decision=Decision.ESCALATE,
        violations=(Violation(code=V.CONTRACT_CREATION),),
        anomalies=(Anomaly(code=A.CONTRACT_CREATED, contract=NFT),),
    )
    text = explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)
    assert text.splitlines()[0] == f"ESCALATED (blocked, needs your attention)  tx {TX_HASH}"
    assert text.endswith(
        "Why:\n"
        f"  - a contract was created at {NFT} during the transaction\n"
        "  - it deploys a contract, which no mandate allows\n"
        "Nothing was charged.\n"
        "The transaction stays blocked; it can't be approved after the fact. If you\n"
        "expected it, lock a new mandate that covers it. If you didn't, revoke this one."
    )
    assert agent_reason(v) == (
        "escalated: contract created during the transaction; "
        "off-mandate: contract creation not allowed"
    )


# --- one golden line per code ---------------------------------------------------------

U = f"(token {USDC})"
W = f"(token {WETH})"
SR02 = f"Uniswap v3 SwapRouter02 ({ROUTER})"

VIOLATIONS: list[tuple[dict[str, Any], str]] = [
    (
        {"code": V.UNNAMED_TARGET, "counterparty": THIEF},
        f"it calls {THIEF}, which your mandate doesn't name",
    ),
    ({"code": V.CONTRACT_CREATION}, "it deploys a contract, which no mandate allows"),
    (
        {"code": V.CALLDATA_TO_RECIPIENT, "intent_index": 0, "counterparty": BOB},
        f"it calls {BOB} with data; intent 1 allows sending ETH to it, not calling it",
    ),
    (
        {"code": V.WRONG_RECIPIENT, "intent_index": 0, "asset": NATIVE, "counterparty": THIEF,
         "amount": 10**15},
        f"it sends 0.001 ETH (native) to {THIEF}, a recipient your mandate doesn't name",
    ),
    (
        {"code": V.OVER_BUDGET, "intent_index": 0, "asset": NATIVE, "amount": 7 * 10**15,
         "limit": 6 * 10**15},
        "it spends 0.007 ETH (native) under intent 1, but only 0.006 ETH (native) is left",
    ),
    (
        {"code": V.SELL_OUTSIDE_VENUE, "intent_index": 2, "asset": Asset(token=USDC),
         "amount": 100 * USD},
        f"it sends 100 USDC {U} without calling a venue of intent 3; what a swap sells may "
        "leave only in a call to one of its venues",
    ),
    (
        {"code": V.NOTHING_RECEIVED, "intent_index": 2, "asset": Asset(token=USDC),
         "amount": 60 * USD},
        f"it sells 60 USDC {U} under intent 3, but no WETH {W} arrived at your account",
    ),
    (
        {"code": V.BELOW_MINIMUM, "intent_index": 2, "asset": Asset(token=WETH),
         "amount": 299 * 10**14, "limit": 3 * 10**16},
        f"it receives 0.0299 WETH {W} under intent 3, below the 0.03 WETH {W} your minimum "
        "requires for what it sells",
    ),
    (
        {"code": V.AMBIGUOUS_SWAP},
        "it sells the assets of more than one swap at once, so it's unclear which budget it "
        "spends",
    ),
    (
        {"code": V.APPROVAL_NOT_ALLOWED, "asset": Asset(token=WETH), "counterparty": ROUTER},
        f"it approves {SR02} to spend WETH {W}; your mandate allows approvals only of a swap's "
        "sell token, to that swap's venues",
    ),
    (
        {"code": V.UNLIMITED_APPROVAL, "asset": Asset(token=USDC), "counterparty": ROUTER},
        f"it approves {SR02} to spend an unlimited amount of USDC {U}",
    ),
    (
        {"code": V.APPROVAL_OVER_BUDGET, "intent_index": 2, "asset": Asset(token=USDC),
         "counterparty": ROUTER, "amount": 61 * USD, "limit": 60 * USD},
        f"it approves {SR02} to spend 61 USDC {U} (in total, to the venues of intent 3), but "
        f"only 60 USDC {U} is left",
    ),
    (
        {"code": V.NFT_APPROVAL, "asset": Asset(token=NFT), "counterparty": THIEF},
        f"it approves {THIEF} to transfer an NFT of UNREGISTERED TOKEN (token {NFT})",
    ),
    (
        {"code": V.OPERATOR_APPROVAL, "asset": Asset(token=NFT), "counterparty": THIEF},
        f"it lets {THIEF} transfer every token you hold of UNREGISTERED TOKEN (token {NFT})",
    ),
    (
        {"code": V.UNCOVERED_OUTFLOW, "asset": Asset(token=DAI), "counterparty": THIEF,
         "amount": 12345},
        f"it sends 12345 base units of UNREGISTERED TOKEN (token {DAI}) to {THIEF}; no intent "
        "in your mandate covers that asset",
    ),
]  # fmt: skip

ANOMALIES: list[tuple[dict[str, Any], str]] = [
    (
        {"code": A.INCONSISTENT_TOKEN_STATE, "contract": USDC, "account": ALICE},
        f"the USDC token contract ({USDC}): its events disagree with its balances for your "
        f"account ({ALICE}), so the flows above can't be trusted",
    ),
    (
        {"code": A.UNRECOGNIZED_EVENT, "contract": POOL, "log_index": 3},
        f"{POOL} emitted an event (log 3) that mentions your account and that the firewall "
        "can't decode",
    ),
    (
        {"code": A.NATIVE_BALANCE_UNRECONCILED},
        "your account's ETH balance changed in a way the call trace doesn't show",
    ),
    (
        {"code": A.PRINCIPAL_RUNS_CODE},
        "your account ran code during the transaction (for example an EIP-7702 delegation); "
        "the firewall expects a plain key-controlled account",
    ),
    (
        {"code": A.CONTRACT_CREATED, "contract": NFT},
        f"a contract was created at {NFT} during the transaction",
    ),
]


def test_every_code_has_a_golden_line() -> None:
    assert {f["code"] for f, _ in VIOLATIONS} == set(ViolationCode)
    assert {f["code"] for f, _ in ANOMALIES} == set(AnomalyCode)
    assert set(AGENT_VIOLATION) == set(ViolationCode)
    assert set(AGENT_ANOMALY) == set(AnomalyCode)


@pytest.mark.parametrize(("fields", "line"), VIOLATIONS, ids=[f["code"] for f, _ in VIOLATIONS])
def test_violation_line(fields: dict[str, Any], line: str) -> None:
    assert why(blocked(Violation(**fields))) == [line]


@pytest.mark.parametrize(("fields", "line"), ANOMALIES, ids=[f["code"] for f, _ in ANOMALIES])
def test_anomaly_line(fields: dict[str, Any], line: str) -> None:
    v = Verdict(decision=Decision.ESCALATE, anomalies=(Anomaly(**fields),))
    assert why(v) == [line]


# --- names, addresses and amounts -----------------------------------------------------


def all_verdicts() -> list[Verdict]:
    return [blocked(Violation(**f)) for f, _ in VIOLATIONS] + [
        Verdict(decision=Decision.ESCALATE, anomalies=(Anomaly(**f),)) for f, _ in ANOMALIES
    ]


def test_addresses_are_never_shortened() -> None:
    for v in all_verdicts():
        text = explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)
        assert "…" not in text and "..." not in text
        for address in re.findall(r"0x[0-9a-fA-F]+", text):
            assert len(address) in (42, 66), address  # an address or a 32-byte hash


def test_counterparties_get_trusted_names() -> None:
    flows = tuple(
        Flow(asset=NATIVE, direction=FlowDirection.IN, counterparty=who, amount=1)
        for who in (ROUTER, WETH, ALICE, THIEF)
    )
    text = explain(Verdict(decision=Decision.ALLOW, flows=flows), THREE, SPENT, REGISTRY,
                   tx_hash=TX_HASH, mandate_id=MID)  # fmt: skip
    assert f"from {SR02}\n" in text
    assert f"from the WETH token contract ({WETH})\n" in text
    assert f"from your account ({ALICE})\n" in text
    assert f"from {THIEF}\n" in text


@pytest.mark.parametrize(
    ("amount", "shown"),
    [
        (1, "0.000000000000000001 ETH (native)"),
        (10**18, "1 ETH (native)"),
        (123456789 * 10**18 + 1, "123456789.000000000000000001 ETH (native)"),
        (UINT256_MAX, "115792089237316195423570985008687907853269984665640564039457.584007913129639935 ETH (native)"),  # noqa: E501
    ],
)  # fmt: skip
def test_amounts_are_exact(amount: int, shown: str) -> None:
    flow = Flow(asset=NATIVE, direction=FlowDirection.OUT, counterparty=BOB, amount=amount)
    text = explain(Verdict(decision=Decision.ALLOW, flows=(flow,)), THREE, SPENT, REGISTRY,
                   tx_hash=TX_HASH, mandate_id=MID)  # fmt: skip
    assert f"  sends {shown} to {BOB}\n" in text


def test_unregistered_token_in_flows_shows_base_units() -> None:
    flow = Flow(asset=Asset(token=NFT), direction=FlowDirection.OUT, counterparty=THIEF, amount=1)
    v = blocked(
        Violation(code=V.UNCOVERED_OUTFLOW, asset=Asset(token=NFT), counterparty=THIEF, amount=1),
        flows=(flow,),
    )
    text = explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)
    assert f"  sends 1 base units of UNREGISTERED TOKEN (token {NFT}) to {THIEF}\n" in text


def test_mandate_decimals_scale_an_unregistered_mandate_asset() -> None:
    """A mandate locked its asset's decimals at capture. If that token isn't
    in today's registry, the name says so, but the amount is still scaled."""
    send_dai = TransferIntent(
        kind="transfer", asset=ref(DAI, 18), budget=Budget(max=2 * 10**18, period=None),
        recipient=BOB,
    )  # fmt: skip
    m = mandate(send_dai)
    v = blocked(
        Violation(code=V.WRONG_RECIPIENT, intent_index=0, asset=Asset(token=DAI),
                  counterparty=THIEF, amount=15 * 10**17),
    )  # fmt: skip
    assert why(v, m, (0,)) == [
        f"it sends 1.5 UNREGISTERED TOKEN (token {DAI}) to {THIEF}, a recipient your "
        "mandate doesn't name"
    ]


def test_registry_names_not_token_symbols() -> None:
    """Effects carry no token names at all, so there is nothing to show but
    the registry's. A token the registry lacks is never named."""
    text = explain(blocked(*(Violation(**f) for f, _ in VIOLATIONS)), THREE, SPENT, REGISTRY,
                   tx_hash=TX_HASH, mandate_id=MID)  # fmt: skip
    symbols = set(re.findall(r"\d (\S+) \((?:native|token)", text))
    assert symbols <= {"ETH", "USDC", "WETH", "TOKEN"}  # "UNREGISTERED TOKEN"


def test_instruction_is_made_safe_for_the_terminal() -> None:
    m = mandate(SEND_ETH, instruction="pay Bob\x1b[2J\nnow‮")
    text = explain(blocked(Violation(code=V.CONTRACT_CREATION)), m, (0,), REGISTRY,
                   tx_hash=TX_HASH, mandate_id=MID)  # fmt: skip
    assert '  you said: "pay Bob?[2J now?"\n' in text
    assert "\x1b" not in text and "‮" not in text


# --- what the agent is told -----------------------------------------------------------

# Distinctive values on the mandate's side, to look for in the agent's message.
SENTINEL_LIMIT = 987654321987654321


def test_agent_message_has_no_mandate_values() -> None:
    """Decision 6: codes and fixed phrases only. No digit can appear, so no
    budget, remaining amount, minimum, intent number, amount or address can."""
    for fields, _ in VIOLATIONS:
        loaded = dict(fields)
        if "limit" in loaded:
            loaded["limit"] = SENTINEL_LIMIT
        reason = agent_reason(blocked(Violation(**loaded)))
        assert reason == f"off-mandate: {AGENT_VIOLATION[fields['code']]}"
        assert not re.search(r"\d|0x", reason), reason
    for fields, _ in ANOMALIES:
        reason = agent_reason(Verdict(decision=Decision.ESCALATE, anomalies=(Anomaly(**fields),)))
        assert reason == f"escalated: {AGENT_ANOMALY[fields['code']]}"
        assert not re.search(r"\d|0x", reason), reason


def test_agent_phrases_are_distinct() -> None:
    """One phrase per code, so the agent's message names the codes exactly."""
    assert len(set(AGENT_VIOLATION.values())) == len(AGENT_VIOLATION)
    assert len(set(AGENT_ANOMALY.values())) == len(AGENT_ANOMALY)


def test_agent_message_lists_each_phrase_once_in_order() -> None:
    v = blocked(
        Violation(code=V.UNCOVERED_OUTFLOW, asset=Asset(token=DAI), counterparty=THIEF, amount=1),
        Violation(code=V.CONTRACT_CREATION),
        Violation(code=V.UNCOVERED_OUTFLOW, asset=Asset(token=NFT), counterparty=THIEF, amount=1),
    )
    assert agent_reason(v) == (
        "off-mandate: asset not covered by mandate; contract creation not allowed"
    )


def test_the_operator_sees_the_limit() -> None:
    """The opposite of the agent: the operator gets the mandate's side."""
    v = blocked(
        Violation(code=V.OVER_BUDGET, intent_index=0, asset=NATIVE, amount=7 * 10**15,
                  limit=6 * 10**15),
    )  # fmt: skip
    assert "only 0.006 ETH (native) is left" in why(v)[0]
    assert "0.006" not in agent_reason(v)


# --- matcher verdicts explain end to end ----------------------------------------------


def test_matcher_attacks_explain() -> None:
    """The headline attack: a real swap through the right router, the output
    sent to the attacker."""
    m = mandate(SWAP)
    t, kw = M.swap_tx(to_whom=THIEF)
    v = match(m, (0,), t, M.effects(t, **kw))
    assert why(v, m, (0,)) == [
        f"it sells 100 USDC {U} under intent 1, but no WETH {W} arrived at your account"
    ]
    assert agent_reason(v) == "off-mandate: swap output did not arrive at the sender"


# --- inputs that don't belong together ------------------------------------------------


def test_intent_index_past_the_mandate() -> None:
    v = blocked(Violation(code=V.CALLDATA_TO_RECIPIENT, intent_index=3, counterparty=BOB))
    with pytest.raises(ValueError, match="intent the mandate doesn't have"):
        explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)


def test_swap_code_pointing_at_a_transfer() -> None:
    v = blocked(
        Violation(code=V.NOTHING_RECEIVED, intent_index=0, asset=NATIVE, amount=1),
    )
    with pytest.raises(ValueError, match="swap was expected"):
        explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)


def test_charge_for_a_missing_intent() -> None:
    v = Verdict(decision=Decision.ALLOW, charges=(Charge(intent_index=5, amount=1),))
    with pytest.raises(ValueError, match="intent the mandate doesn't have"):
        explain(v, THREE, SPENT, REGISTRY, tx_hash=TX_HASH, mandate_id=MID)


def test_registry_for_another_chain() -> None:
    other = REGISTRY.model_copy(update={"chain_id": 1})
    with pytest.raises(ValueError, match="another chain"):
        explain(blocked(Violation(code=V.AMBIGUOUS_SWAP)), THREE, SPENT, other,
                tx_hash=TX_HASH, mandate_id=MID)  # fmt: skip


def test_spent_must_match_the_intents() -> None:
    with pytest.raises(ValueError, match="one entry per intent"):
        explain(blocked(Violation(code=V.AMBIGUOUS_SWAP)), THREE, (0,), REGISTRY,
                tx_hash=TX_HASH, mandate_id=MID)  # fmt: skip
