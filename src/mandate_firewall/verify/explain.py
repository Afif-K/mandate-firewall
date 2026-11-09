"""Explanations: a verdict as text, from fixed templates only.

The matcher's Verdict is structured (codes, addresses, amounts). This module
turns it into words, two ways (docs/m4-plan.md §5, Decisions 4 and 6):

- `explain`: the full "You asked: X. This transaction does: Y." diff, for
  the operator log, the audit record and `mandate-firewall alerts`. It
  carries everything the matcher knows, mandate values included (budgets,
  what is left, the swap minimum).
- `agent_reason`: what the agent is told when its transaction is refused.
  The agent is untrusted, possibly injected, so it gets one fixed phrase per
  code and nothing else: no amounts, no addresses, and above all no
  mandate values. An injected agent that learns the swap minimum can set
  the price to exactly that floor; one that learns the remaining budget
  knows how much to ask for.

Why templates and no LLM: the template already says everything the matcher
knows. An LLM could only rephrase it or get it wrong, and a wrong "this looks
like a legitimate swap" could talk the human into widening the mandate, the
one decision they still make. It would also put an API key and a network
call on the transaction path.

The same rules as the capture summary (mandate/render.py), whose code this
reuses:
- Names come only from the trusted registry, never from a token's own
  name(), symbol() or decimals(). An address the registry doesn't know is
  shown as UNREGISTERED TOKEN with the full address, and its amounts in
  base units, because without trusted decimals any scaling would be a guess.
- Addresses are printed in full, never shortened (address poisoning).
- Amounts are exact: integer arithmetic, no rounding.

Pure: no I/O, no clock. Inputs that don't belong together (a violation that
points past the mandate's intents, a registry for another chain) raise
ValueError. That's a bug in the caller, and the transaction stays blocked:
an explanation never decides anything.
"""

from collections.abc import Iterable, Sequence

from mandate_firewall.mandate.models import AssetRef, Mandate, SwapIntent, TransferIntent
from mandate_firewall.mandate.registry import Registry
from mandate_firewall.mandate.render import (
    amount_text,
    asset_text,
    intent_lines,
    safe_text,
    venue_text,
)
from mandate_firewall.models import Decision
from mandate_firewall.verify.models import (
    Anomaly,
    AnomalyCode,
    Asset,
    FlowDirection,
    Verdict,
    Violation,
    ViolationCode,
)

# --- what the agent is told --------------------------------------------------------
#
# One fixed phrase per code. They describe the agent's own transaction in
# general terms only; tests check that every code has one and that no
# phrase contains a digit or an address.

AGENT_VIOLATION: dict[ViolationCode, str] = {
    ViolationCode.UNNAMED_TARGET: "target contract not in mandate",
    ViolationCode.CONTRACT_CREATION: "contract creation not allowed",
    ViolationCode.CALLDATA_TO_RECIPIENT: "ETH transfer to a recipient must carry no calldata",
    ViolationCode.WRONG_RECIPIENT: "recipient not in mandate",
    ViolationCode.OVER_BUDGET: "over budget",
    ViolationCode.SELL_OUTSIDE_VENUE: "sell asset sent outside a swap on a mandate venue",
    ViolationCode.NOTHING_RECEIVED: "swap output did not arrive at the sender",
    ViolationCode.BELOW_MINIMUM: "swap output below the mandate minimum",
    ViolationCode.AMBIGUOUS_SWAP: "sells the assets of more than one swap at once",
    ViolationCode.APPROVAL_NOT_ALLOWED: "approval not allowed by mandate",
    ViolationCode.UNLIMITED_APPROVAL: "unlimited approval not allowed",
    ViolationCode.APPROVAL_OVER_BUDGET: "approval over budget",
    ViolationCode.NFT_APPROVAL: "NFT approval not allowed",
    ViolationCode.OPERATOR_APPROVAL: "operator approval (approval for all) not allowed",
    ViolationCode.UNCOVERED_OUTFLOW: "asset not covered by mandate",
}

AGENT_ANOMALY: dict[AnomalyCode, str] = {
    AnomalyCode.INCONSISTENT_TOKEN_STATE: "token events disagree with token balances",
    AnomalyCode.UNRECOGNIZED_EVENT: "unrecognized event mentions the sender",
    AnomalyCode.NATIVE_BALANCE_UNRECONCILED: "sender ETH balance change not explained by the trace",
    AnomalyCode.PRINCIPAL_RUNS_CODE: "sender account executes code",
    AnomalyCode.CONTRACT_CREATED: "contract created during the transaction",
}


def agent_reason(verdict: Verdict) -> str:
    """The reason in the agent's error message, for a refused transaction:
    "off-mandate: recipient not in mandate; over budget", or for an
    escalation "escalated: <anomalies>", followed by any violations. Each
    phrase appears once, in the order the verifier found them."""
    if verdict.decision is Decision.ALLOW:
        raise ValueError("an allowed transaction has no rejection reason")
    parts = []
    if verdict.anomalies:
        parts.append("escalated: " + _join(AGENT_ANOMALY[a.code] for a in verdict.anomalies))
    if verdict.violations:
        parts.append("off-mandate: " + _join(AGENT_VIOLATION[v.code] for v in verdict.violations))
    return "; ".join(parts)


def _join(phrases: Iterable[str]) -> str:
    return "; ".join(dict.fromkeys(phrases))  # each phrase once, first-seen order


# --- what the operator is told -----------------------------------------------------

_HEADER = {
    Decision.ALLOW: "ALLOWED",
    Decision.BLOCK: "BLOCKED",
    Decision.ESCALATE: "ESCALATED (blocked, needs your attention)",
}

_ESCALATE_ADVICE = (
    "The transaction stays blocked; it can't be approved after the fact. If you\n"
    "expected it, lock a new mandate that covers it. If you didn't, revoke this one."
)


def explain(
    verdict: Verdict,
    mandate: Mandate,
    spent: Sequence[int],
    registry: Registry,
    *,
    tx_hash: str,
    mandate_id: str,
) -> str:
    """The full explanation of `verdict` for the operator. `spent[i]` is how
    much of intent i's budget earlier transactions used, the same input the
    matcher got."""
    return _Explainer(mandate, spent, registry).text(verdict, tx_hash, mandate_id)


class _Explainer:
    def __init__(self, mandate: Mandate, spent: Sequence[int], registry: Registry) -> None:
        if registry.chain_id != mandate.chain_id:
            raise ValueError("the registry is for another chain than the mandate")
        if len(spent) != len(mandate.intents):
            raise ValueError("spent must have one entry per intent")
        self.mandate = mandate
        self.spent = list(spent)
        self.registry = registry

    def text(self, verdict: Verdict, tx_hash: str, mandate_id: str) -> str:
        lines = [
            f"{_HEADER[verdict.decision]}  tx {tx_hash}",
            f"  under mandate {mandate_id}",
            "You asked:",
            f'  you said: "{safe_text(self.mandate.instruction)}"',
        ]
        for i, intent in enumerate(self.mandate.intents):
            lines += intent_lines(i + 1, intent, self.registry)
            left = self.left(i)
            lines.append(
                f"       left before this transaction: "
                f"{self.amount(left, self.asset(i), with_address=False)}"
            )
        lines.append("This transaction:")
        lines += [f"  {line}" for line in self.does(verdict)]

        if verdict.decision is Decision.ALLOW:
            lines += self.charged(verdict)
            return "\n".join(lines)

        lines.append("Why:")
        lines += [f"  - {self.anomaly(a)}" for a in verdict.anomalies]
        lines += [f"  - {self.violation(v)}" for v in verdict.violations]
        lines.append("Nothing was charged.")
        if verdict.decision is Decision.ESCALATE:
            lines.append(_ESCALATE_ADVICE)
        return "\n".join(lines)

    # --- the parts ---------------------------------------------------------------------

    def does(self, verdict: Verdict) -> list[str]:
        if not verdict.flows:
            return ["moves no assets into or out of your account (apart from gas)"]
        out = []
        for flow in verdict.flows:
            amount = self.amount(flow.amount, flow.asset)
            party = self.party(flow.counterparty)
            if flow.direction is FlowDirection.OUT:
                out.append(f"sends {amount} to {party}")
            else:
                out.append(f"receives {amount} from {party}")
        return out

    def charged(self, verdict: Verdict) -> list[str]:
        if not verdict.charges and not verdict.approval_limits:
            return ["Charged: nothing."]
        lines = ["Charged:"]
        for charge in verdict.charges:
            i = self.intent_index(charge.intent_index)
            asset = self.asset(i)
            left = self.left(i) - charge.amount
            lines.append(
                f"  intent {i + 1}: {self.amount(charge.amount, asset)}, "
                f"{self.amount(left, asset, with_address=False)} left"
            )
        for approval in verdict.approval_limits:
            i = self.intent_index(approval.intent_index)
            lines.append(
                f"  intent {i + 1}: approves its venues to spend up to "
                f"{self.amount(approval.amount, self.asset(i))} (not charged; the swap that "
                "uses it is)"
            )
        return lines

    def violation(self, v: Violation) -> str:
        # Every code's required fields are present (verify/models.py checks),
        # so each template below only uses fields its code carries.
        amount = self.amount(v.amount, v.asset) if v.amount is not None and v.asset else ""
        limit = self.amount(v.limit, v.asset) if v.limit is not None and v.asset else ""
        party = self.party(v.counterparty) if v.counterparty else ""
        n = self.intent_index(v.intent_index) + 1 if v.intent_index is not None else 0
        match v.code:
            case ViolationCode.UNNAMED_TARGET:
                return f"it calls {party}, which your mandate doesn't name"
            case ViolationCode.CONTRACT_CREATION:
                return "it deploys a contract, which no mandate allows"
            case ViolationCode.CALLDATA_TO_RECIPIENT:
                return (
                    f"it calls {party} with data; intent {n} allows sending ETH to it, "
                    "not calling it"
                )
            case ViolationCode.WRONG_RECIPIENT:
                return f"it sends {amount} to {party}, a recipient your mandate doesn't name"
            case ViolationCode.OVER_BUDGET:
                return f"it spends {amount} under intent {n}, but only {limit} is left"
            case ViolationCode.SELL_OUTSIDE_VENUE:
                return (
                    f"it sends {amount} without calling a venue of intent {n}; what a swap "
                    "sells may leave only in a call to one of its venues"
                )
            case ViolationCode.NOTHING_RECEIVED:
                buy = self.swap(n - 1).buy
                return (
                    f"it sells {amount} under intent {n}, but no "
                    f"{asset_text(buy, self.registry)} arrived at your account"
                )
            case ViolationCode.BELOW_MINIMUM:
                return (
                    f"it receives {amount} under intent {n}, below the {limit} "
                    "your minimum requires for what it sells"
                )
            case ViolationCode.AMBIGUOUS_SWAP:
                return (
                    "it sells the assets of more than one swap at once, so it's unclear "
                    "which budget it spends"
                )
            case ViolationCode.APPROVAL_NOT_ALLOWED:
                return (
                    f"it approves {party} to spend {self.token(v.asset)}; your mandate allows "
                    "approvals only of a swap's sell token, to that swap's venues"
                )
            case ViolationCode.UNLIMITED_APPROVAL:
                return f"it approves {party} to spend an unlimited amount of {self.token(v.asset)}"
            case ViolationCode.APPROVAL_OVER_BUDGET:
                return (
                    f"it approves {party} to spend {amount} (in total, to the venues of "
                    f"intent {n}), but only {limit} is left"
                )
            case ViolationCode.NFT_APPROVAL:
                return f"it approves {party} to transfer an NFT of {self.token(v.asset)}"
            case ViolationCode.OPERATOR_APPROVAL:
                return f"it lets {party} transfer every token you hold of {self.token(v.asset)}"
            case ViolationCode.UNCOVERED_OUTFLOW:
                return f"it sends {amount} to {party}; no intent in your mandate covers that asset"

    def anomaly(self, a: Anomaly) -> str:
        contract = self.party(a.contract) if a.contract else ""
        account = self.party(a.account) if a.account else ""
        match a.code:
            case AnomalyCode.INCONSISTENT_TOKEN_STATE:
                return (
                    f"{contract}: its events disagree with its balances for "
                    f"{account}, so the flows above can't be trusted"
                )
            case AnomalyCode.UNRECOGNIZED_EVENT:
                return (
                    f"{contract} emitted an event (log {a.log_index}) that mentions your "
                    "account and that the firewall can't decode"
                )
            case AnomalyCode.NATIVE_BALANCE_UNRECONCILED:
                return "your account's ETH balance changed in a way the call trace doesn't show"
            case AnomalyCode.PRINCIPAL_RUNS_CODE:
                return (
                    "your account ran code during the transaction (for example an EIP-7702 "
                    "delegation); the firewall expects a plain key-controlled account"
                )
            case AnomalyCode.CONTRACT_CREATED:
                return f"a contract was created at {a.contract} during the transaction"

    # --- formatting --------------------------------------------------------------------

    def intent_index(self, index: int) -> int:
        if not 0 <= index < len(self.mandate.intents):
            raise ValueError("the verdict names an intent the mandate doesn't have")
        return index

    def asset(self, index: int) -> Asset:
        intent = self.mandate.intents[index]
        ref = intent.asset if isinstance(intent, TransferIntent) else intent.sell
        return Asset(token=ref.address)

    def swap(self, index: int) -> SwapIntent:
        intent = self.mandate.intents[index]
        if not isinstance(intent, SwapIntent):
            raise ValueError("the verdict names a transfer intent where a swap was expected")
        return intent

    def left(self, index: int) -> int:
        intent = self.mandate.intents[index]
        budget = intent.budget.max if isinstance(intent, TransferIntent) else intent.sell_budget.max
        return budget - self.spent[index]

    def decimals(self, token: str | None) -> int | None:
        """The mandate's own decimals first (locked at capture from the
        registry), then the registry's. None: nobody trusted knows."""
        for intent in self.mandate.intents:
            refs = (
                (intent.asset,) if isinstance(intent, TransferIntent) else (intent.sell, intent.buy)
            )
            for ref in refs:
                if ref.address == token:
                    return ref.decimals
        return self.registry.decimals_for(token)

    def amount(self, value: int, asset: Asset, *, with_address: bool = True) -> str:
        decimals = self.decimals(asset.token)
        if decimals is None:
            # Unregistered, so no trusted decimals: exact base units.
            return f"{value} base units of {self.token(asset)}"
        ref = AssetRef(chain_id=self.mandate.chain_id, address=asset.token, decimals=decimals)
        return amount_text(value, ref, self.registry, with_address=with_address)

    def token(self, asset: Asset | None) -> str:
        if asset is None:
            raise ValueError("this code requires an asset")
        symbol = self.registry.symbol_for(asset.token) or "UNREGISTERED TOKEN"
        return f"{symbol} (native)" if asset.token is None else f"{symbol} (token {asset.token})"

    def party(self, address: str) -> str:
        """An account on the other side, with a trusted name if it has one."""
        if address == self.mandate.principal:
            return f"your account ({address})"
        if any(c.address == address for v in self.registry.venues for c in v.contracts):
            return venue_text(address, self.registry)
        symbol = self.registry.symbol_for(address)
        if symbol is not None:
            return f"the {symbol} token contract ({address})"
        return address
