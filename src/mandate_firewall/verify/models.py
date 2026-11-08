"""Verdict models: what the verifier concluded about one transaction.

The matcher (M4, docs/m4-plan.md §2) compares a transaction's simulated
effects with its mandate and returns a Verdict. These models are the shape of
that answer, and they follow the same rules as Effects (models.py):

- No free text. Every string is an address, hex or an enum code. A verdict
  is built from effects (attacker-influenced, but hex only) and the mandate
  (trusted), and it goes into the audit record and, in part, back to the
  agent. Human-readable explanations are rendered from these codes by a
  fixed template (verify/explain.py, commit 5), never stored as prose here.
- The decision follows from the findings and can't contradict them: any
  anomaly means escalate, otherwise any violation means block, otherwise
  allow. A verdict that blocks carries no charges, because blocked
  transactions never spend a mandate's budget.
- Each code says which fields it must carry, so an explanation never has to
  guess at a missing amount or counterparty.
"""

from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, Strict, model_validator

from mandate_firewall.models import Address, Decision, Uint256

# Positions in a mandate's `intents` and receipt log indexes: small integers.
# Strict, so True and 1.0 aren't accepted as 1.
Index = Annotated[int, Strict(), Field(ge=0, le=2**53 - 1)]
Positive = Annotated[Uint256, Field(gt=0)]


class _Verdict(BaseModel):
    # extra="forbid": an audit record with fields we don't know about is not
    # one we wrote, so reading it back must fail.
    model_config = ConfigDict(frozen=True, extra="forbid")


class Asset(_Verdict):
    """An asset as effects see it: a token contract, or native ETH (None).
    A model rather than a bare `Address | None`, so "native ETH" and "no
    asset involved" have different spellings (`{"token": null}` vs `null`)."""

    token: Address | None


NATIVE = Asset(token=None)


class FlowDirection(StrEnum):
    OUT = "out"  # left the principal
    IN = "in"  # arrived at the principal


class Flow(_Verdict):
    """One movement of an asset out of or into the principal in this
    transaction, with the account on the other side. For ETH the gas fee is
    not a flow: Effects.gas_cost reports it separately."""

    asset: Asset
    direction: FlowDirection
    counterparty: Address
    amount: Positive


class ViolationCode(StrEnum):
    """The transaction clearly does something the mandate doesn't allow."""

    # Where the transaction goes
    UNNAMED_TARGET = "unnamed_target"  # calls a contract the mandate doesn't name
    CONTRACT_CREATION = "contract_creation"  # deploys a contract
    CALLDATA_TO_RECIPIENT = "calldata_to_recipient"  # "send ETH to X" is not "call X"
    # Transfers
    WRONG_RECIPIENT = "wrong_recipient"
    OVER_BUDGET = "over_budget"
    # Swaps
    SELL_OUTSIDE_VENUE = "sell_outside_venue"  # sell asset left without calling a venue
    NOTHING_RECEIVED = "nothing_received"  # sold, but nothing bought arrived
    BELOW_MINIMUM = "below_minimum"  # bought * denominator < sold * numerator
    AMBIGUOUS_SWAP = "ambiguous_swap"  # two swap intents' sell assets left at once
    # Approvals
    APPROVAL_NOT_ALLOWED = "approval_not_allowed"  # not a sell asset, or not to a venue
    UNLIMITED_APPROVAL = "unlimited_approval"
    APPROVAL_OVER_BUDGET = "approval_over_budget"  # more than the remaining sell budget
    NFT_APPROVAL = "nft_approval"  # ERC-721 approve() of a single token
    OPERATOR_APPROVAL = "operator_approval"  # ApprovalForAll(approved=true)
    # Everything else
    UNCOVERED_OUTFLOW = "uncovered_outflow"  # an asset no intent covers left


class AnomalyCode(StrEnum):
    """The firewall can't fully interpret what the transaction did. These
    escalate: blocked now, with a louder alert (docs/m4-plan.md §3)."""

    # Events disagree with storage. (S105: "TOKEN" in the name, not a secret.)
    INCONSISTENT_TOKEN_STATE = "inconsistent_token_state"  # noqa: S105
    UNRECOGNIZED_EVENT = "unrecognized_event"  # an event we can't decode mentions the principal
    NATIVE_BALANCE_UNRECONCILED = "native_balance_unreconciled"  # ETH moved outside the trace
    PRINCIPAL_RUNS_CODE = "principal_runs_code"  # the "EOA" executes code (e.g. EIP-7702)
    CONTRACT_CREATED = "contract_created"  # a contract was created somewhere in the call tree


# Which fields each code must carry. Fields not listed may still be set.
_VIOLATION_FIELDS: dict[ViolationCode, frozenset[str]] = {
    ViolationCode.UNNAMED_TARGET: frozenset({"counterparty"}),
    ViolationCode.CONTRACT_CREATION: frozenset(),
    ViolationCode.CALLDATA_TO_RECIPIENT: frozenset({"intent_index", "counterparty"}),
    ViolationCode.WRONG_RECIPIENT: frozenset({"intent_index", "asset", "counterparty", "amount"}),
    ViolationCode.OVER_BUDGET: frozenset({"intent_index", "asset", "amount", "limit"}),
    ViolationCode.SELL_OUTSIDE_VENUE: frozenset({"intent_index", "asset", "amount"}),
    ViolationCode.NOTHING_RECEIVED: frozenset({"intent_index", "asset", "amount"}),
    ViolationCode.BELOW_MINIMUM: frozenset({"intent_index", "asset", "amount", "limit"}),
    ViolationCode.AMBIGUOUS_SWAP: frozenset(),
    ViolationCode.APPROVAL_NOT_ALLOWED: frozenset({"asset", "counterparty"}),
    ViolationCode.UNLIMITED_APPROVAL: frozenset({"asset", "counterparty"}),
    ViolationCode.APPROVAL_OVER_BUDGET: frozenset(
        {"intent_index", "asset", "counterparty", "amount", "limit"}
    ),
    ViolationCode.NFT_APPROVAL: frozenset({"asset", "counterparty"}),
    ViolationCode.OPERATOR_APPROVAL: frozenset({"asset", "counterparty"}),
    ViolationCode.UNCOVERED_OUTFLOW: frozenset({"asset", "counterparty", "amount"}),
}

_ANOMALY_FIELDS: dict[AnomalyCode, frozenset[str]] = {
    AnomalyCode.INCONSISTENT_TOKEN_STATE: frozenset({"contract", "account"}),
    AnomalyCode.UNRECOGNIZED_EVENT: frozenset({"contract", "log_index"}),
    AnomalyCode.NATIVE_BALANCE_UNRECONCILED: frozenset(),
    AnomalyCode.PRINCIPAL_RUNS_CODE: frozenset(),
    AnomalyCode.CONTRACT_CREATED: frozenset({"contract"}),
}


def _require(model: BaseModel, code: StrEnum, required: frozenset[str]) -> None:
    missing = sorted(name for name in required if getattr(model, name) is None)
    if missing:
        raise ValueError(f"{code} requires {', '.join(missing)}")


class Violation(_Verdict):
    """One way the transaction breaks the mandate.

    `amount` is about this transaction (what it sends, sells, approves).
    `limit` is the mandate's side (the remaining budget, the minimum it had
    to receive). The agent may be told the code and the amount, never the
    limit: an injected agent that learns the swap minimum can set the price
    to exactly that floor (docs/m4-plan.md, Decision 6)."""

    code: ViolationCode
    intent_index: Index | None = None  # which of the mandate's intents
    asset: Asset | None = None
    counterparty: Address | None = None  # recipient, target or spender
    amount: Uint256 | None = None
    limit: Uint256 | None = None
    log_index: Index | None = None  # the event it comes from, if any

    @model_validator(mode="after")
    def _fields_for_code(self) -> Self:
        _require(self, self.code, _VIOLATION_FIELDS[self.code])
        return self


class Anomaly(_Verdict):
    """Something in the effects the verifier can't vouch for."""

    code: AnomalyCode
    contract: Address | None = None  # the token, emitter or created contract
    account: Address | None = None  # whose balance or allowance disagreed
    log_index: Index | None = None

    @model_validator(mode="after")
    def _fields_for_code(self) -> Self:
        _require(self, self.code, _ANOMALY_FIELDS[self.code])
        return self


class Charge(_Verdict):
    """What an allowed transaction spends from one intent's budget."""

    intent_index: Index
    amount: Positive


class ApprovalLimit(_Verdict):
    """An approval the transaction grants is only allowed if the intent has
    at least `amount` left *after* this transaction's charges. The matcher
    checks this against what it read before simulation; the store checks it
    again, atomically, when it charges (another transaction may have spent
    budget in between)."""

    intent_index: Index
    amount: Positive


def decide(violations: tuple[Violation, ...], anomalies: tuple[Anomaly, ...]) -> Decision:
    """The decision the findings imply. An anomaly outranks a violation: both
    block, but an anomaly also asks a human to look."""
    if anomalies:
        return Decision.ESCALATE
    if violations:
        return Decision.BLOCK
    return Decision.ALLOW


class Verdict(_Verdict):
    """The verifier's answer for one transaction under one mandate."""

    decision: Decision
    flows: tuple[Flow, ...] = ()
    violations: tuple[Violation, ...] = ()
    anomalies: tuple[Anomaly, ...] = ()
    charges: tuple[Charge, ...] = ()
    approval_limits: tuple[ApprovalLimit, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.decision is not decide(self.violations, self.anomalies):
            raise ValueError("the decision must follow from the violations and anomalies")
        if self.decision is not Decision.ALLOW and (self.charges or self.approval_limits):
            raise ValueError("only an allowed transaction is charged")
        for group in (self.charges, self.approval_limits):
            indexes = [item.intent_index for item in group]
            if len(indexes) != len(set(indexes)):
                raise ValueError("at most one charge and one approval limit per intent")
        return self
