"""The matcher: compare one transaction's effects with its mandate.

This is where the firewall decides (docs/m4-plan.md §2, Decision 1). It is
pure: the mandate (trusted), how much of each intent's budget earlier
transactions spent, the decoded transaction and its simulated effects go in,
and a Verdict comes out. No I/O, no clock, no registry, no LLM.

The rules, in the plan's numbering:

2.1 Allowed top-level targets. `tx.to` must be something the mandate names:
    the token of a token transfer intent, the recipient of an ETH transfer
    intent, a venue of a swap intent, or a swap intent's sell token (to
    approve the venue). Never the principal itself. Creating a contract is
    never allowed. Many harmful state changes move no tokens (a governance
    delegate, a contract's owner), so the entry point is bounded too.
2.2 ETH sent to a recipient carries no calldata: "send ETH to X" is not
    "call X".
2.3 Transfers. Each outflow of asset A to account R is matched to the
    transfer intent for exactly (A, R). The charge is the gross outflow,
    and spent + charge must stay within the budget.
2.4 Swaps. An outflow of a swap's sell asset counts toward the swap only if
    the transaction called one of its venues. The recipient of that outflow
    is NOT checked: with Uniswap the principal pays the pool, not the
    router. What protects the user is what comes back:
      - something of the buy asset must arrive (bought > 0), and
      - with a minimum: bought * denominator >= sold * numerator,
        per transaction, integers only.
    `sold` is the net outflow of the sell asset (refunds count back),
    `bought` everything of the buy asset that arrived. Not net: if some of
    it leaves again in the same transaction, that outflow is matched (and
    charged, or refused) on its own, like any other. The charge is `sold`.
    When two swap intents sell the same asset through the same venue, the
    one whose buy asset arrived is used. If that doesn't settle it, or two
    swap intents' sell assets leave in one transaction: ambiguous_swap.
2.5 Approvals. An ERC-20 approval by the principal must be for a swap's
    sell token, to one of its venues, not unlimited, and (summed over the
    venues of that swap) at most what is left of its budget after this
    transaction's charges. Approving 0 (revoking) is always allowed.
    ERC-721 approvals of a single token and ApprovalForAll(true) are never
    allowed; clearing them is. If a venue serves several swap intents that
    sell the same token, the approval is checked against the one with the
    most budget left.
2.6 Nothing else may leave: any outflow no intent covers is a violation.
    Inflows are always fine.

Every rule runs, so the audit record lists everything wrong with a
transaction, not just the first thing. Anomalies come from flows.py. The
decision follows from the findings (verify/models.py): any anomaly
escalates, otherwise any violation blocks, otherwise the transaction is
allowed with its charges.

The charges and approval limits returned here are checked against `spent`
as it was read before simulation. The store re-checks them atomically when
it charges (commit 4), so a transaction racing for the same budget can't
both pass.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from mandate_firewall.mandate.models import Mandate, SwapIntent, TransferIntent
from mandate_firewall.models import UINT256_MAX, DecodedTransaction, Effects, TokenStandard
from mandate_firewall.verify.flows import analyze
from mandate_firewall.verify.models import (
    Anomaly,
    ApprovalLimit,
    Asset,
    Charge,
    Flow,
    FlowDirection,
    Verdict,
    Violation,
    ViolationCode,
    decide,
)

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
EMPTY_CALLDATA = "0x"


@dataclass
class _Totals:
    """The principal's flows of one asset: outflows per counterparty, in
    first-seen order, and the total inflow."""

    out: dict[str, int] = field(default_factory=dict)
    inflow: int = 0

    @property
    def outflow(self) -> int:
        return sum(self.out.values())


def match(
    mandate: Mandate, spent: Sequence[int], tx: DecodedTransaction, effects: Effects
) -> Verdict:
    """The verdict for `tx` under `mandate`. `spent[i]` is how much of intent
    i's budget earlier transactions used. Raises ValueError if the inputs
    don't belong together: that's a bug in the caller, which must block."""
    _check_inputs(mandate, spent, tx, effects)
    analysis = analyze(effects, mandate.principal)
    m = _Matcher(mandate, spent, tx)
    m.targets()
    totals = _totals(analysis.flows)
    m.outflows(totals)
    m.approvals(effects)
    return m.verdict(analysis.flows, analysis.anomalies)


def _check_inputs(
    mandate: Mandate, spent: Sequence[int], tx: DecodedTransaction, effects: Effects
) -> None:
    if tx.sender != mandate.principal:
        raise ValueError("the transaction is not from the mandate's principal")
    if tx.hash != effects.tx_hash or tx.sender != effects.sender:
        raise ValueError("the effects are not of this transaction")
    if effects.chain_id != mandate.chain_id:
        raise ValueError("the effects are not on the mandate's chain")
    if len(spent) != len(mandate.intents):
        raise ValueError("spent must have one entry per intent")
    for amount, intent in zip(spent, mandate.intents, strict=True):
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError("spent amounts are integers")
        if not 0 <= amount <= _budget(intent):
            raise ValueError("a spent amount is outside its budget")


def _budget(intent: TransferIntent | SwapIntent) -> int:
    return intent.budget.max if isinstance(intent, TransferIntent) else intent.sell_budget.max


def _totals(flows: Sequence[Flow]) -> dict[Asset, _Totals]:
    totals: dict[Asset, _Totals] = {}
    for flow in flows:
        t = totals.setdefault(flow.asset, _Totals())
        if flow.direction is FlowDirection.OUT:
            t.out[flow.counterparty] = t.out.get(flow.counterparty, 0) + flow.amount
        else:
            t.inflow += flow.amount
    return totals


class _Matcher:
    def __init__(self, mandate: Mandate, spent: Sequence[int], tx: DecodedTransaction) -> None:
        self.mandate = mandate
        self.spent = list(spent)
        self.tx = tx
        self.violations: list[Violation] = []
        self.charges: dict[int, int] = {}  # intent index -> amount
        self.approval_limits: dict[int, int] = {}
        self.transfers = [
            (i, intent)
            for i, intent in enumerate(mandate.intents)
            if isinstance(intent, TransferIntent)
        ]
        self.swaps = [
            (i, intent)
            for i, intent in enumerate(mandate.intents)
            if isinstance(intent, SwapIntent)
        ]

    def remaining(self, index: int) -> int:
        """Budget left for an intent after earlier transactions and this one."""
        intent = self.mandate.intents[index]
        return _budget(intent) - self.spent[index] - self.charges.get(index, 0)

    def violate(self, code: ViolationCode, **fields: object) -> None:
        violation = Violation(code=code, **fields)  # type: ignore[arg-type]
        if violation not in self.violations:
            self.violations.append(violation)

    # --- 2.1, 2.2 ------------------------------------------------------------------

    def targets(self) -> None:
        to = self.tx.to
        if to is None:
            self.violate(ViolationCode.CONTRACT_CREATION)
            return
        allowed: set[str] = set()
        for _, t in self.transfers:
            allowed.add(t.asset.address if t.asset.address is not None else t.recipient)
        for _, s in self.swaps:
            allowed.update(s.venues)
            if s.sell.address is not None:
                allowed.add(s.sell.address)
        allowed.discard(self.mandate.principal)
        if to not in allowed:
            self.violate(ViolationCode.UNNAMED_TARGET, counterparty=to)

        if self.tx.data != EMPTY_CALLDATA:
            for i, t in self.transfers:
                if t.asset.address is None and t.recipient == to:
                    self.violate(
                        ViolationCode.CALLDATA_TO_RECIPIENT, intent_index=i, counterparty=to
                    )
                    break

    # --- 2.3, 2.4, 2.6 --------------------------------------------------------------

    def outflows(self, totals: dict[Asset, _Totals]) -> None:
        swap_charged: dict[int, int] = {}  # swap intent -> gross outflow attributed
        for asset, t in totals.items():
            for counterparty, amount in t.out.items():
                transfer = self._transfer_for(asset, counterparty)
                if transfer is not None:
                    self.charges[transfer] = self.charges.get(transfer, 0) + amount
                    continue
                swap = self._swap_for(asset, totals)
                if swap is not None:
                    swap_charged[swap] = swap_charged.get(swap, 0) + amount
                else:
                    self._uncovered(asset, counterparty, amount)

        if len(swap_charged) > 1:
            self.violate(ViolationCode.AMBIGUOUS_SWAP)
        for index, gross in swap_charged.items():
            self._swap(index, gross, totals)

        for index, amount in list(self.charges.items()):
            if amount > _budget(self.mandate.intents[index]) - self.spent[index]:
                intent = self.mandate.intents[index]
                asset = intent.asset if isinstance(intent, TransferIntent) else intent.sell
                self.violate(
                    ViolationCode.OVER_BUDGET,
                    intent_index=index,
                    asset=Asset(token=asset.address),
                    amount=amount,
                    limit=_budget(intent) - self.spent[index],
                )

    def _transfer_for(self, asset: Asset, counterparty: str) -> int | None:
        for i, t in self.transfers:
            if t.asset.address == asset.token and t.recipient == counterparty:
                return i
        return None

    def _swap_for(self, asset: Asset, totals: dict[Asset, _Totals]) -> int | None:
        """The swap intent an outflow of `asset` counts toward: it sells
        `asset` and the transaction called one of its venues. With several,
        the one whose buy asset arrived. None if there is none."""
        candidates = [
            (i, s)
            for i, s in self.swaps
            if s.sell.address == asset.token and self.tx.to in s.venues
        ]
        if len(candidates) <= 1:
            return candidates[0][0] if candidates else None
        arrived = [i for i, s in candidates if _arrived(totals.get(Asset(token=s.buy.address))) > 0]
        if len(arrived) == 1:
            return arrived[0]
        if len(arrived) > 1:
            self.violate(ViolationCode.AMBIGUOUS_SWAP)
        return candidates[0][0]  # nothing arrived: it fails "nothing received" below

    def _uncovered(self, asset: Asset, counterparty: str, amount: int) -> None:
        for i, t in self.transfers:
            if t.asset.address == asset.token:
                self.violate(
                    ViolationCode.WRONG_RECIPIENT,
                    intent_index=i,
                    asset=asset,
                    counterparty=counterparty,
                    amount=amount,
                )
                return
        for i, s in self.swaps:
            if s.sell.address == asset.token:
                # The sell asset left, but not through a call to a venue: for
                # example, tokens sent straight to the router, where anyone
                # can sweep them.
                self.violate(
                    ViolationCode.SELL_OUTSIDE_VENUE, intent_index=i, asset=asset, amount=amount
                )
                return
        self.violate(
            ViolationCode.UNCOVERED_OUTFLOW, asset=asset, counterparty=counterparty, amount=amount
        )

    def _swap(self, index: int, gross: int, totals: dict[Asset, _Totals]) -> None:
        intent = dict(self.swaps)[index]
        sell = Asset(token=intent.sell.address)
        buy = Asset(token=intent.buy.address)
        sold = max(gross - totals[sell].inflow, 0)  # refunds count back
        if sold == 0:
            return
        bought = _arrived(totals.get(buy))
        self.charges[index] = sold
        if bought == 0:
            self.violate(
                ViolationCode.NOTHING_RECEIVED, intent_index=index, asset=sell, amount=sold
            )
            return
        ratio = intent.min_buy_per_sell
        if ratio is not None and bought * ratio.denominator < sold * ratio.numerator:
            required = -(-sold * ratio.numerator // ratio.denominator)  # rounded up
            self.violate(
                ViolationCode.BELOW_MINIMUM,
                intent_index=index,
                asset=buy,
                amount=bought,
                limit=min(required, UINT256_MAX),
            )

    # --- 2.5 -------------------------------------------------------------------------

    def approvals(self, effects: Effects) -> None:
        principal = self.mandate.principal
        latest: dict[tuple[str, str], int] = {}  # (token, spender) -> last ERC-20 amount
        for approval in effects.token_approvals:
            if approval.owner != principal:
                continue
            if approval.standard is TokenStandard.ERC721:
                if approval.spender != ZERO_ADDRESS:  # clearing an approval is fine
                    self.violate(
                        ViolationCode.NFT_APPROVAL,
                        asset=Asset(token=approval.token),
                        counterparty=approval.spender,
                        log_index=approval.log_index,
                    )
                continue
            latest[(approval.token, approval.spender)] = approval.amount or 0

        for operator in effects.operator_approvals:
            if operator.owner == principal and operator.approved:
                self.violate(
                    ViolationCode.OPERATOR_APPROVAL,
                    asset=Asset(token=operator.token),
                    counterparty=operator.operator,
                    log_index=operator.log_index,
                )

        exposure: dict[int, int] = {}  # swap intent -> allowance granted to its venues
        for (token, spender), amount in latest.items():
            if amount == 0:
                continue  # a revoke
            asset = Asset(token=token)
            if amount == UINT256_MAX:
                self.violate(ViolationCode.UNLIMITED_APPROVAL, asset=asset, counterparty=spender)
                continue
            candidates = [
                i for i, s in self.swaps if s.sell.address == token and spender in s.venues
            ]
            if not candidates:
                self.violate(ViolationCode.APPROVAL_NOT_ALLOWED, asset=asset, counterparty=spender)
                continue
            index = max(candidates, key=self.remaining)
            exposure[index] = exposure.get(index, 0) + amount
            if exposure[index] > self.remaining(index):
                self.violate(
                    ViolationCode.APPROVAL_OVER_BUDGET,
                    intent_index=index,
                    asset=asset,
                    counterparty=spender,
                    amount=exposure[index],
                    limit=max(self.remaining(index), 0),
                )
        self.approval_limits = exposure

    # --- verdict -----------------------------------------------------------------------

    def verdict(self, flows: Sequence[Flow], anomalies: Sequence[Anomaly]) -> Verdict:
        violations = tuple(self.violations)
        decision = decide(violations, tuple(anomalies))
        allowed = not violations and not anomalies
        return Verdict(
            decision=decision,
            flows=tuple(flows),
            violations=violations,
            anomalies=tuple(anomalies),
            charges=tuple(
                Charge(intent_index=i, amount=a)
                for i, a in sorted(self.charges.items())
                if allowed and a
            ),
            approval_limits=tuple(
                ApprovalLimit(intent_index=i, amount=a)
                for i, a in sorted(self.approval_limits.items())
                if allowed and a
            ),
        )


def _arrived(totals: _Totals | None) -> int:
    """How much of an asset arrived at the principal."""
    return 0 if totals is None else totals.inflow
