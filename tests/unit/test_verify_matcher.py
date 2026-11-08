"""The matcher: rules 2.1-2.6 of docs/m4-plan.md, and the attacks they stop.

Effects here are hand-built in the shape the simulator produces (checked
against real anvil in test_simulator.py's flow tests): the principal's ETH
balance reconciles with the trace and every token it moves has a consistent
balance check, so no anomaly appears unless a test adds one."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mandate_firewall.mandate.models import (
    AssetRef,
    Budget,
    Limits,
    Mandate,
    MandateKind,
    Ratio,
    SwapIntent,
    TransferIntent,
)
from mandate_firewall.models import (
    UINT256_MAX,
    CallFrame,
    CallType,
    Decision,
    DecodedTransaction,
    Effects,
    NativeBalanceChange,
    OperatorApproval,
    TokenApproval,
    TokenStandard,
    TokenStateCheck,
    TokenTransfer,
    TxType,
)
from mandate_firewall.verify.matcher import match
from mandate_firewall.verify.models import (
    NATIVE,
    Anomaly,
    AnomalyCode,
    ApprovalLimit,
    Asset,
    Charge,
    Verdict,
    Violation,
    ViolationCode,
)

CHAIN = 84532
ALICE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # the principal
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
CAROL = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
THIEF = "0x000000000000000000000000000000000000dEaD"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
WETH = "0x4200000000000000000000000000000000000006"
DAI = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ROUTER = "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"
ROUTER2 = "0x492E6456D9528771018DeB9E87ef7750EF184104"
POOL = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
NFT = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
ZERO = "0x0000000000000000000000000000000000000000"
TX_HASH = "0x" + "11" * 32
GAS = 21_000 * 10**9
ETH = 10**18
USD = 10**6  # one USDC in base units

V = ViolationCode

# --- builders -----------------------------------------------------------------------


def asset(token: str | None, decimals: int = 18) -> AssetRef:
    return AssetRef(chain_id=CHAIN, address=token, decimals=decimals)


def send(budget: int, to: str = BOB, token: str | None = None) -> TransferIntent:
    return TransferIntent(
        kind="transfer", asset=asset(token), budget=Budget(max=budget, period=None), recipient=to
    )


def swap(
    budget: int,
    sell: str | None = USDC,
    buy: str | None = WETH,
    venues: tuple[str, ...] = (ROUTER,),
    ratio: tuple[int, int] | None = None,
) -> SwapIntent:
    return SwapIntent(
        kind="swap",
        sell=asset(sell),
        sell_budget=Budget(max=budget, period=None),
        buy=asset(buy),
        min_buy_per_sell=Ratio(numerator=ratio[0], denominator=ratio[1]) if ratio else None,
        venues=venues,
    )


def mandate(*intents: TransferIntent | SwapIntent) -> Mandate:
    created = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
    return Mandate(
        schema_version=1,
        kind=MandateKind.ONE_SHOT,
        chain_id=CHAIN,
        principal=ALICE,
        intents=intents,
        limits=Limits(max_transactions=5, period=None),
        created_at=created,
        expires_at=created + timedelta(minutes=30),
        instruction="test",
        nonce="0x" + "33" * 32,
    )


def tx(to: str | None, value: int = 0, data: str = "0x") -> DecodedTransaction:
    return DecodedTransaction(
        tx_type=TxType.DYNAMIC_FEE,
        hash=TX_HASH,
        chain_id=CHAIN,
        nonce=0,
        sender=ALICE,
        to=to,
        value=value,
        data=data,
        gas_limit=100_000,
        max_fee_per_gas=10**9,
        max_priority_fee_per_gas=0,
        raw="0x02",
    )


def erc20(token: str, sender: str, recipient: str, amount: int) -> dict[str, Any]:
    return {"token": token, "sender": sender, "recipient": recipient, "amount": amount}


def approve(token: str, spender: str, amount: int) -> dict[str, Any]:
    return {"token": token, "spender": spender, "amount": amount}


def effects(
    t: DecodedTransaction,
    *,
    transfers: tuple[dict[str, Any], ...] = (),
    approvals: tuple[dict[str, Any], ...] = (),
    nft_approvals: tuple[tuple[str, str], ...] = (),
    operators: tuple[tuple[str, str, bool], ...] = (),
    eth_back: int = 0,
    **overrides: Any,
) -> Effects:
    """Effects of `t`: its own top frame, optional ETH paid back to ALICE by
    the target, token transfers and approvals in that order of log index."""
    top_type = CallType.CREATE if t.to is None else CallType.CALL
    target = t.to or NFT
    calls = [CallFrame(depth=0, call_type=top_type, caller=ALICE, target=target, value=t.value)]
    if eth_back:
        calls.append(
            CallFrame(depth=1, call_type=CallType.CALL, caller=target, target=ALICE, value=eth_back)
        )
    log = iter(range(100))
    token_transfers = tuple(
        TokenTransfer(standard=TokenStandard.ERC20, log_index=next(log), **x) for x in transfers
    )
    token_approvals = tuple(
        TokenApproval(standard=TokenStandard.ERC20, owner=ALICE, log_index=next(log), **x)
        for x in approvals
    ) + tuple(
        TokenApproval(
            token=token,
            standard=TokenStandard.ERC721,
            owner=ALICE,
            spender=spender,
            token_id=7,
            log_index=next(log),
        )
        for token, spender in nft_approvals
    )
    operator_approvals = tuple(
        OperatorApproval(token=token, owner=ALICE, operator=op, approved=on, log_index=next(log))
        for token, op, on in operators
    )
    net: dict[str, int] = {}  # token -> ALICE's net change
    for x in transfers:
        if ALICE in (x["sender"], x["recipient"]):
            sign = -1 if x["sender"] == ALICE else 1
            net[x["token"]] = net.get(x["token"], 0) + sign * x["amount"]
    checks = tuple(
        TokenStateCheck(
            token=token,
            kind="balance",
            owner=ALICE,
            before=10**30,
            after=10**30 + change,
            claimed=change,
            consistent=True,
        )
        for token, change in net.items()
    )
    delta = eth_back - t.value - GAS
    fields: dict[str, Any] = {
        "tx_hash": TX_HASH,
        "sender": ALICE,
        "chain_id": CHAIN,
        "fork_block_number": 1,
        "fork_block_hash": "0x" + "22" * 32,
        "status": "success",
        "gas_used": 21_000,
        "effective_gas_price": 10**9,
        "gas_cost": GAS,
        "native_balance_changes": (NativeBalanceChange(address=ALICE, delta=delta),),
        "calls": tuple(calls),
        "token_transfers": token_transfers,
        "token_approvals": token_approvals,
        "operator_approvals": operator_approvals,
        "contracts_created": (target,) if t.to is None else (),
        "token_state_checks": checks,
    }
    return Effects(**(fields | overrides))


def verdict(
    m: Mandate, t: DecodedTransaction, spent: tuple[int, ...] | None = None, **effect_kw: Any
) -> Verdict:
    return match(m, spent or (0,) * len(m.intents), t, effects(t, **effect_kw))


def codes(v: Verdict) -> list[ViolationCode]:
    return [x.code for x in v.violations]


def allowed(v: Verdict, *charges: tuple[int, int]) -> None:
    assert (v.decision, v.violations, v.anomalies) == (Decision.ALLOW, (), ())
    assert v.charges == tuple(Charge(intent_index=i, amount=a) for i, a in charges)


# A swap of 100 USDC for at least 0.03 WETH: Ratio(0.03 WETH, 100 USDC) in base units.
MIN_RATIO = (3 * 10**16, 100 * USD)


def swap_tx(sold: int = 100 * USD, bought: int = 3 * 10**16, to_whom: str = ALICE, **kw: Any):
    """The principal calls the router; the pool takes its USDC and sends WETH
    to `to_whom`, as SwapRouter02's exactInputSingle does."""
    transfers = (erc20(USDC, ALICE, POOL, sold), erc20(WETH, POOL, to_whom, bought))
    return tx(ROUTER, data="0x04e45aaf"), {"transfers": transfers, **kw}


# --- rule 2.1: allowed top-level targets ----------------------------------------------


def test_unnamed_target() -> None:
    v = verdict(mandate(send(ETH)), tx(THIEF))
    assert v.decision is Decision.BLOCK
    assert v.violations == (Violation(code=V.UNNAMED_TARGET, counterparty=THIEF),)


def test_contract_creation() -> None:
    v = verdict(mandate(send(ETH)), tx(None, data="0x6080"))
    assert V.CONTRACT_CREATION in codes(v)
    # Also an anomaly (a contract was created), so it escalates.
    assert v.decision is Decision.ESCALATE


def test_calling_oneself_is_never_allowed() -> None:
    assert codes(verdict(mandate(send(ETH)), tx(ALICE))) == [V.UNNAMED_TARGET]
    # Not even when a mandate names the principal as a recipient (the
    # compiler refuses that, the model doesn't): calling yourself runs
    # whatever code the account has.
    assert codes(verdict(mandate(send(ETH, to=ALICE)), tx(ALICE))) == [V.UNNAMED_TARGET]


@pytest.mark.parametrize(
    ("intent", "target"),
    [
        (send(ETH), BOB),  # the ETH recipient
        (send(100 * USD, token=USDC), USDC),  # the token of a token transfer
        (swap(100 * USD), ROUTER),  # a venue
        (swap(100 * USD), USDC),  # the sell token, to approve
    ],
)
def test_named_targets(intent: TransferIntent | SwapIntent, target: str) -> None:
    v = verdict(mandate(intent), tx(target, data="0x" if target == BOB else "0x12345678"))
    assert codes(v) == []


def test_a_token_recipient_is_not_a_target() -> None:
    # "Send 100 USDC to Bob" lets the agent call USDC, not Bob.
    assert codes(verdict(mandate(send(100 * USD, token=USDC)), tx(BOB))) == [V.UNNAMED_TARGET]


# --- rule 2.2: ETH to a recipient carries no calldata ----------------------------------


def test_eth_with_calldata() -> None:
    v = verdict(mandate(send(ETH)), tx(BOB, value=ETH // 2, data="0xa9059cbb"))
    assert v.violations == (
        Violation(code=V.CALLDATA_TO_RECIPIENT, intent_index=0, counterparty=BOB),
    )


# --- rule 2.3: transfers --------------------------------------------------------------


def test_eth_transfer_within_budget() -> None:
    allowed(verdict(mandate(send(ETH)), tx(BOB, value=4 * ETH // 10)), (0, 4 * ETH // 10))


def test_wrong_recipient() -> None:
    # Demo step 6: the mandate says Bob, the agent pays the thief.
    v = verdict(mandate(send(ETH)), tx(THIEF, value=ETH // 1000))
    assert v.decision is Decision.BLOCK
    assert v.violations == (
        Violation(code=V.UNNAMED_TARGET, counterparty=THIEF),
        Violation(
            code=V.WRONG_RECIPIENT,
            intent_index=0,
            asset=NATIVE,
            counterparty=THIEF,
            amount=ETH // 1000,
        ),
    )
    assert v.charges == ()


def test_wrong_token_recipient() -> None:
    t = tx(USDC, data="0xa9059cbb")
    v = verdict(
        mandate(send(100 * USD, token=USDC)),
        t,
        transfers=(erc20(USDC, ALICE, THIEF, 5 * USD),),
    )
    assert v.violations == (
        Violation(
            code=V.WRONG_RECIPIENT,
            intent_index=0,
            asset=Asset(token=USDC),
            counterparty=THIEF,
            amount=5 * USD,
        ),
    )


def test_exact_budget_after_partial_use() -> None:
    # 0.01 ETH budget, 0.004 spent: 0.006 is exactly what's left.
    m = mandate(send(10**16))
    allowed(verdict(m, tx(BOB, value=6 * 10**15), spent=(4 * 10**15,)), (0, 6 * 10**15))


def test_over_budget() -> None:
    m = mandate(send(10**16))
    v = verdict(m, tx(BOB, value=7 * 10**15), spent=(4 * 10**15,))
    assert v.violations == (
        Violation(
            code=V.OVER_BUDGET, intent_index=0, asset=NATIVE, amount=7 * 10**15, limit=6 * 10**15
        ),
    )
    assert v.charges == ()


def test_token_transfers_are_charged_gross() -> None:
    # Money coming back doesn't make room for more to leave.
    t = tx(USDC, data="0xa9059cbb")
    v = verdict(
        mandate(send(10 * USD, token=USDC)),
        t,
        transfers=(erc20(USDC, ALICE, BOB, 10 * USD), erc20(USDC, BOB, ALICE, 10 * USD)),
    )
    allowed(v, (0, 10 * USD))
    over = verdict(
        mandate(send(10 * USD, token=USDC)),
        t,
        transfers=(erc20(USDC, ALICE, BOB, 11 * USD), erc20(USDC, BOB, ALICE, 5 * USD)),
    )
    assert codes(over) == [V.OVER_BUDGET]


def test_two_recipients_of_one_asset_have_separate_budgets() -> None:
    m = mandate(send(10 * USD, BOB, USDC), send(3 * USD, CAROL, USDC))
    t = tx(USDC, data="0xa9059cbb")
    ok = verdict(
        m, t, transfers=(erc20(USDC, ALICE, BOB, 10 * USD), erc20(USDC, ALICE, CAROL, 3 * USD))
    )
    allowed(ok, (0, 10 * USD), (1, 3 * USD))
    over = verdict(m, t, transfers=(erc20(USDC, ALICE, CAROL, 4 * USD),))
    assert [(x.code, x.intent_index) for x in over.violations] == [(V.OVER_BUDGET, 1)]


# --- rule 2.4: swaps ------------------------------------------------------------------


def test_honest_swap() -> None:
    t, kw = swap_tx()
    allowed(verdict(mandate(swap(100 * USD, ratio=MIN_RATIO)), t, **kw), (0, 100 * USD))


def test_swap_to_the_attacker() -> None:
    # The headline attack: right router, right token, right amount, and the
    # WETH goes to the thief. A spend limit and a router allowlist pass it.
    t, kw = swap_tx(to_whom=THIEF)
    v = verdict(mandate(swap(100 * USD)), t, **kw)
    assert v.decision is Decision.BLOCK
    assert v.violations == (
        Violation(
            code=V.NOTHING_RECEIVED, intent_index=0, asset=Asset(token=USDC), amount=100 * USD
        ),
    )


def test_ratio_boundary() -> None:
    m = mandate(swap(100 * USD, ratio=MIN_RATIO))
    t, kw = swap_tx(bought=3 * 10**16)  # exactly the minimum: allowed
    allowed(verdict(m, t, **kw), (0, 100 * USD))
    t, kw = swap_tx(bought=3 * 10**16 - 1)  # one wei short
    v = verdict(m, t, **kw)
    assert v.violations == (
        Violation(
            code=V.BELOW_MINIMUM,
            intent_index=0,
            asset=Asset(token=WETH),
            amount=3 * 10**16 - 1,
            limit=3 * 10**16,
        ),
    )


def test_minimum_is_rounded_up_in_the_report() -> None:
    # 1/3 WETH-wei per USDC-unit: selling 10 units needs 3.33 -> at least 4.
    m = mandate(swap(100, ratio=(1, 3)))
    t, kw = swap_tx(sold=10, bought=3)
    (violation,) = verdict(m, t, **kw).violations
    assert (violation.code, violation.limit) == (V.BELOW_MINIMUM, 4)
    t, kw = swap_tx(sold=9, bought=3)
    allowed(verdict(m, t, **kw), (0, 9))


def test_pull_and_sweep_without_a_minimum_passes() -> None:
    # SwapRouter02 multicall: pull 100 USDC, swap 1 wei of it, sweep the rest
    # to the thief. Every rule without a minimum passes. This is why capture
    # requires a minimum (Decision 5); stored mandates without one only get
    # "bought > 0". Documented in THREAT_MODEL.md.
    t = tx(ROUTER, data="0xac9650d8")
    transfers = (
        erc20(USDC, ALICE, ROUTER, 100 * USD),  # pull
        erc20(USDC, ROUTER, POOL, 1),
        erc20(WETH, POOL, ALICE, 1),  # 1 wei of WETH
        erc20(USDC, ROUTER, THIEF, 100 * USD - 1),  # sweep
    )
    allowed(verdict(mandate(swap(100 * USD)), t, transfers=transfers), (0, 100 * USD))
    blocked = verdict(mandate(swap(100 * USD, ratio=MIN_RATIO)), t, transfers=transfers)
    assert codes(blocked) == [V.BELOW_MINIMUM]


def test_direct_transfer_to_the_router() -> None:
    # Tokens sent to the router outside a swap can be swept by anyone.
    t = tx(USDC, data="0xa9059cbb")
    v = verdict(mandate(swap(100 * USD)), t, transfers=(erc20(USDC, ALICE, ROUTER, 50 * USD),))
    assert v.violations == (
        Violation(
            code=V.SELL_OUTSIDE_VENUE, intent_index=0, asset=Asset(token=USDC), amount=50 * USD
        ),
    )


def test_swap_through_a_router_the_mandate_does_not_name() -> None:
    t = tx(ROUTER2, data="0x04e45aaf")
    transfers = (erc20(USDC, ALICE, POOL, 100 * USD), erc20(WETH, POOL, ALICE, 3 * 10**16))
    v = verdict(mandate(swap(100 * USD)), t, transfers=transfers)
    assert codes(v) == [V.UNNAMED_TARGET, V.SELL_OUTSIDE_VENUE]


def test_swap_over_budget() -> None:
    t, kw = swap_tx(sold=60 * USD, bought=2 * 10**16)
    v = verdict(mandate(swap(100 * USD)), t, spent=(50 * USD,), **kw)
    assert v.violations == (
        Violation(
            code=V.OVER_BUDGET,
            intent_index=0,
            asset=Asset(token=USDC),
            amount=60 * USD,
            limit=50 * USD,
        ),
    )


def test_refunds_count_back() -> None:
    # exactOutput: 100 USDC pulled, 20 refunded, 80 sold.
    t, kw = swap_tx(sold=100 * USD, bought=3 * 10**16)
    kw["transfers"] += (erc20(USDC, ROUTER, ALICE, 20 * USD),)
    allowed(verdict(mandate(swap(80 * USD, ratio=MIN_RATIO)), t, **kw), (0, 80 * USD))


def test_swap_selling_eth() -> None:
    t = tx(ROUTER, value=ETH, data="0x04e45aaf")
    v = verdict(
        mandate(swap(ETH, sell=None, buy=USDC)),
        t,
        transfers=(erc20(USDC, POOL, ALICE, 3000 * USD),),
    )
    allowed(v, (0, ETH))


def test_swap_buying_eth() -> None:
    # The router unwraps WETH and pays the principal in ETH.
    t, kw = swap_tx(bought=0)
    kw["transfers"] = kw["transfers"][:1]  # no WETH arrives; ETH does
    v = verdict(mandate(swap(100 * USD, buy=None, ratio=MIN_RATIO)), t, eth_back=3 * 10**16, **kw)
    allowed(v, (0, 100 * USD))


def test_two_sell_assets_in_one_transaction() -> None:
    m = mandate(swap(100 * USD), swap(ETH, sell=None, buy=USDC))
    t = tx(ROUTER, value=ETH, data="0xac9650d8")
    transfers = (erc20(USDC, ALICE, POOL, 100 * USD), erc20(WETH, POOL, ALICE, 3 * 10**16))
    v = verdict(m, t, transfers=transfers)
    assert V.AMBIGUOUS_SWAP in codes(v)
    assert v.decision is Decision.BLOCK


def test_two_swaps_selling_the_same_asset_are_told_apart_by_what_arrived() -> None:
    m = mandate(swap(100 * USD), swap(50 * USD, buy=DAI))
    t = tx(ROUTER, data="0x04e45aaf")
    to_dai = verdict(
        m, t, transfers=(erc20(USDC, ALICE, POOL, 40 * USD), erc20(DAI, POOL, ALICE, 40 * ETH))
    )
    allowed(to_dai, (1, 40 * USD))
    both = verdict(
        m,
        t,
        transfers=(
            erc20(USDC, ALICE, POOL, 40 * USD),
            erc20(DAI, POOL, ALICE, 20 * ETH),
            erc20(WETH, POOL, ALICE, 10**16),
        ),
    )
    assert codes(both) == [V.AMBIGUOUS_SWAP]
    # Reported once, however many outflows were ambiguous.
    twice = verdict(
        m,
        t,
        transfers=(
            erc20(USDC, ALICE, POOL, 20 * USD),
            erc20(USDC, ALICE, ROUTER, 20 * USD),
            erc20(DAI, POOL, ALICE, 20 * ETH),
            erc20(WETH, POOL, ALICE, 10**16),
        ),
    )
    assert codes(twice) == [V.AMBIGUOUS_SWAP]


def test_bought_asset_passed_on_under_another_intent() -> None:
    # "Swap 100 USDC for WETH, and send up to 0.03 WETH to Bob", done in one
    # transaction: the WETH arrived, then left under the transfer intent and
    # its budget. It counts as received; the transfer is charged on its own.
    m = mandate(swap(100 * USD, ratio=MIN_RATIO), send(3 * 10**16, BOB, WETH))
    t, kw = swap_tx()
    kw["transfers"] += (erc20(WETH, ALICE, BOB, 3 * 10**16),)
    allowed(verdict(m, t, **kw), (0, 100 * USD), (1, 3 * 10**16))


# --- rule 2.5: approvals --------------------------------------------------------------


def test_approval_within_the_remaining_budget() -> None:
    t = tx(USDC, data="0x095ea7b3")
    v = verdict(
        mandate(swap(100 * USD)), t, spent=(40 * USD,), approvals=(approve(USDC, ROUTER, 60 * USD),)
    )
    allowed(v)
    assert v.approval_limits == (ApprovalLimit(intent_index=0, amount=60 * USD),)


def test_approval_over_the_remaining_budget() -> None:
    t = tx(USDC, data="0x095ea7b3")
    v = verdict(
        mandate(swap(100 * USD)), t, spent=(40 * USD,), approvals=(approve(USDC, ROUTER, 61 * USD),)
    )
    assert v.violations == (
        Violation(
            code=V.APPROVAL_OVER_BUDGET,
            intent_index=0,
            asset=Asset(token=USDC),
            counterparty=ROUTER,
            amount=61 * USD,
            limit=60 * USD,
        ),
    )
    assert v.approval_limits == ()


def test_an_approval_counts_this_transactions_charges() -> None:
    # A router that calls permit() during a swap: the allowance it sets is
    # checked against what is left after the swap, not before.
    m = mandate(swap(100 * USD))
    t, kw = swap_tx(sold=60 * USD, bought=2 * 10**16)
    ok = verdict(m, t, approvals=(approve(USDC, ROUTER, 40 * USD),), **kw)
    allowed(ok, (0, 60 * USD))
    over = verdict(m, t, approvals=(approve(USDC, ROUTER, 41 * USD),), **kw)
    (violation,) = over.violations
    assert (violation.code, violation.limit) == (V.APPROVAL_OVER_BUDGET, 40 * USD)


def test_unlimited_approval() -> None:
    t = tx(USDC, data="0x095ea7b3")
    v = verdict(mandate(swap(100 * USD)), t, approvals=(approve(USDC, ROUTER, UINT256_MAX),))
    assert v.violations == (
        Violation(code=V.UNLIMITED_APPROVAL, asset=Asset(token=USDC), counterparty=ROUTER),
    )


@pytest.mark.parametrize(
    ("token", "spender"),
    [(USDC, THIEF), (WETH, ROUTER)],  # not a venue; not the sell token
)
def test_approval_not_allowed(token: str, spender: str) -> None:
    m = mandate(swap(100 * USD))
    t = tx(token, data="0x095ea7b3")
    v = verdict(m, t, approvals=(approve(token, spender, USD),))
    assert (
        Violation(code=V.APPROVAL_NOT_ALLOWED, asset=Asset(token=token), counterparty=spender)
        in v.violations
    )


def test_approvals_to_several_venues_add_up() -> None:
    m = mandate(swap(100 * USD, venues=(ROUTER, ROUTER2)))
    t = tx(USDC, data="0x095ea7b3")
    ok = verdict(
        m, t, approvals=(approve(USDC, ROUTER, 60 * USD), approve(USDC, ROUTER2, 40 * USD))
    )
    assert ok.approval_limits == (ApprovalLimit(intent_index=0, amount=100 * USD),)
    over = verdict(
        m, t, approvals=(approve(USDC, ROUTER, 60 * USD), approve(USDC, ROUTER2, 41 * USD))
    )
    assert codes(over) == [V.APPROVAL_OVER_BUDGET]


def test_a_later_approval_replaces_an_earlier_one() -> None:
    m = mandate(swap(100 * USD))
    t = tx(USDC, data="0x095ea7b3")
    v = verdict(m, t, approvals=(approve(USDC, ROUTER, UINT256_MAX), approve(USDC, ROUTER, USD)))
    assert v.approval_limits == (ApprovalLimit(intent_index=0, amount=USD),)


def test_revoking_is_always_allowed() -> None:
    m = mandate(swap(100 * USD))
    allowed(verdict(m, tx(USDC, data="0x095ea7b3"), approvals=(approve(USDC, ROUTER, 0),)))
    # Even a token or spender the mandate doesn't name: it only lowers exposure.
    v = verdict(m, tx(USDC, data="0x095ea7b3"), approvals=(approve(USDC, THIEF, 0),))
    allowed(v)


def test_approve_then_swap_spends_the_budget() -> None:
    m = mandate(swap(100 * USD, ratio=MIN_RATIO))
    t, kw = swap_tx()
    allowed(verdict(m, t, **kw), (0, 100 * USD))
    # Budget spent: a second approval of anything is over what's left.
    v = verdict(
        m, tx(USDC, data="0x095ea7b3"), spent=(100 * USD,), approvals=(approve(USDC, ROUTER, 1),)
    )
    assert codes(v) == [V.APPROVAL_OVER_BUDGET]


def test_nft_approval() -> None:
    m = mandate(send(ETH))
    v = verdict(m, tx(BOB), nft_approvals=((NFT, THIEF),))
    assert (
        Violation(code=V.NFT_APPROVAL, asset=Asset(token=NFT), counterparty=THIEF, log_index=0)
        in v.violations
    )
    cleared = verdict(m, tx(BOB), nft_approvals=((NFT, ZERO),))
    assert codes(cleared) == []


def test_approval_for_all() -> None:
    m = mandate(send(ETH))
    v = verdict(m, tx(BOB), operators=((NFT, THIEF, True),))
    assert v.violations == (
        Violation(
            code=V.OPERATOR_APPROVAL, asset=Asset(token=NFT), counterparty=THIEF, log_index=0
        ),
    )
    assert codes(verdict(m, tx(BOB), operators=((NFT, THIEF, False),))) == []


def test_other_owners_approvals_are_not_the_principals() -> None:
    m = mandate(swap(100 * USD))
    t, kw = swap_tx()
    e = effects(t, **kw)
    others = (
        TokenApproval(
            token=USDC,
            standard=TokenStandard.ERC20,
            owner=POOL,
            spender=THIEF,
            amount=UINT256_MAX,
            log_index=50,
        ),
    )
    allowed(match(m, (0,), t, e.model_copy(update={"token_approvals": others})), (0, 100 * USD))


# --- rule 2.6: nothing else may leave -------------------------------------------------


def test_uncovered_token_outflow() -> None:
    # The mandate pays Bob in ETH; the transaction also moves DAI.
    m = mandate(send(ETH))
    t = tx(BOB, value=ETH // 10)
    v = verdict(m, t, transfers=(erc20(DAI, ALICE, THIEF, 5 * ETH),))
    assert v.violations == (
        Violation(
            code=V.UNCOVERED_OUTFLOW, asset=Asset(token=DAI), counterparty=THIEF, amount=5 * ETH
        ),
    )


def test_eth_under_a_token_only_mandate() -> None:
    t, kw = swap_tx()
    t = tx(ROUTER, value=ETH, data=t.data)
    v = verdict(mandate(swap(100 * USD)), t, **kw)
    assert codes(v) == [V.UNCOVERED_OUTFLOW]


def test_the_bought_asset_may_not_leave() -> None:
    t, kw = swap_tx()
    kw["transfers"] += (erc20(WETH, ALICE, THIEF, 10**16),)
    v = verdict(mandate(swap(100 * USD)), t, **kw)
    assert codes(v) == [V.UNCOVERED_OUTFLOW]


def test_inflows_are_fine() -> None:
    t = tx(BOB)
    allowed(verdict(mandate(send(ETH)), t, transfers=(erc20(DAI, THIEF, ALICE, 10**18),)))


def test_gas_alone_is_not_charged() -> None:
    allowed(verdict(mandate(send(ETH)), tx(BOB)))


# --- decisions, anomalies, inputs -------------------------------------------------------


def test_every_violation_is_listed() -> None:
    m = mandate(send(10**16))
    v = verdict(
        m,
        tx(THIEF, value=10**17),
        transfers=(erc20(DAI, ALICE, THIEF, 1),),
        operators=((NFT, THIEF, True),),
    )
    assert codes(v) == [
        V.UNNAMED_TARGET,
        V.WRONG_RECIPIENT,
        V.UNCOVERED_OUTFLOW,
        V.OPERATOR_APPROVAL,
    ]


def test_an_anomaly_escalates_and_nothing_is_charged() -> None:
    t = tx(BOB, value=ETH // 10)
    e = effects(t)
    lying = e.model_copy(
        update={"native_balance_changes": (NativeBalanceChange(address=ALICE, delta=-ETH),)}
    )
    v = match(mandate(send(ETH)), (0,), t, lying)
    assert v.decision is Decision.ESCALATE
    assert v.anomalies == (Anomaly(code=AnomalyCode.NATIVE_BALANCE_UNRECONCILED),)
    assert v.charges == v.approval_limits == ()


def test_the_verdict_carries_the_flows() -> None:
    v = verdict(mandate(send(ETH)), tx(BOB, value=5))
    assert [(f.counterparty, f.amount) for f in v.flows] == [(BOB, 5)]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"spent": (0, 0)}, "one entry per intent"),
        ({"spent": (ETH + 1,)}, "outside its budget"),
        ({"spent": (-1,)}, "outside its budget"),
        ({"spent": (True,)}, "integers"),
        ({"tx_sender": BOB}, "principal"),
        ({"effects_hash": "0x" + "99" * 32}, "this transaction"),
        ({"effects_chain": 1}, "chain"),
    ],
)
def test_inputs_that_do_not_belong_together_are_refused(
    change: dict[str, Any], message: str
) -> None:
    m = mandate(send(ETH))
    t = tx(BOB, value=1)
    e = effects(t)
    if "tx_sender" in change:
        t = t.model_copy(update={"sender": change["tx_sender"]})
    if "effects_hash" in change:
        e = e.model_copy(update={"tx_hash": change["effects_hash"]})
    if "effects_chain" in change:
        e = e.model_copy(update={"chain_id": change["effects_chain"]})
    with pytest.raises(ValueError, match=message):
        match(m, change.get("spent", (0,)), t, e)
