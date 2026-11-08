"""Verdict models: no free text, decisions that follow from findings, required fields."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from mandate_firewall.audit import AuditRecord
from mandate_firewall.models import UINT256_MAX, Decision
from mandate_firewall.verify.models import (
    _ANOMALY_FIELDS,
    _VIOLATION_FIELDS,
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
    decide,
)
from tests.schema import free_string_paths

BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
THIEF = "0x000000000000000000000000000000000000dEaD"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

WRONG_RECIPIENT = Violation(
    code=ViolationCode.WRONG_RECIPIENT,
    intent_index=0,
    asset=NATIVE,
    counterparty=THIEF,
    amount=10**15,
)
INCONSISTENT = Anomaly(code=AnomalyCode.INCONSISTENT_TOKEN_STATE, contract=USDC, account=BOB)
TO_BOB = Flow(asset=NATIVE, direction=FlowDirection.OUT, counterparty=BOB, amount=4 * 10**15)


def allowed(**overrides: Any) -> Verdict:
    fields: dict[str, Any] = {
        "decision": Decision.ALLOW,
        "flows": (TO_BOB,),
        "charges": (Charge(intent_index=0, amount=4 * 10**15),),
    }
    return Verdict(**(fields | overrides))


# --- shape ----------------------------------------------------------------------


def test_no_field_can_hold_free_text() -> None:
    """A verdict goes into the audit record and, in part, back to the agent.
    Like effects, it carries only addresses, hex, numbers and enum codes.
    Explanations are rendered from these by a template, not stored as prose."""
    schema = Verdict.model_json_schema()
    assert free_string_paths(schema) == []
    assert '"pattern"' in json.dumps(schema)  # the walk does see strings


def test_json_round_trip_keeps_big_numbers_as_strings() -> None:
    verdict = Verdict(
        decision=Decision.ESCALATE,
        flows=(
            Flow(asset=Asset(token=USDC), direction=FlowDirection.IN, counterparty=BOB, amount=1),
        ),
        violations=(
            Violation(
                code=ViolationCode.APPROVAL_OVER_BUDGET,
                intent_index=1,
                asset=Asset(token=USDC),
                counterparty=BOB,
                amount=UINT256_MAX,
                limit=100_000_000,
                log_index=3,
            ),
        ),
        anomalies=(INCONSISTENT,),
    )
    text = verdict.model_dump_json()
    assert Verdict.model_validate_json(text) == verdict
    data = json.loads(text)
    assert data["violations"][0]["amount"] == str(UINT256_MAX)
    assert data["flows"][0]["amount"] == "1"


def test_native_and_no_asset_are_spelled_differently() -> None:
    data = json.loads(
        Violation(code=ViolationCode.UNNAMED_TARGET, counterparty=THIEF).model_dump_json()
    )
    assert data["asset"] is None  # not about an asset
    assert json.loads(WRONG_RECIPIENT.model_dump_json())["asset"] == {"token": None}  # ETH


def test_models_are_frozen_and_reject_unknown_fields() -> None:
    verdict = allowed()
    with pytest.raises(ValidationError):
        verdict.decision = Decision.BLOCK  # type: ignore[misc]
    data = json.loads(verdict.model_dump_json())
    data["explanation"] = "looks fine to me"
    with pytest.raises(ValidationError):
        Verdict.model_validate(data)


@pytest.mark.parametrize("value", [True, 1.0, "1", -1])
def test_indexes_are_strict_small_integers(value: Any) -> None:
    with pytest.raises(ValidationError):
        Charge(intent_index=value, amount=1)


@pytest.mark.parametrize("amount", [0, -1, UINT256_MAX + 1, True, 1.5])
def test_flows_and_charges_move_a_positive_uint256(amount: Any) -> None:
    with pytest.raises(ValidationError):
        Charge(intent_index=0, amount=amount)
    with pytest.raises(ValidationError):
        Flow(asset=NATIVE, direction=FlowDirection.OUT, counterparty=BOB, amount=amount)
    with pytest.raises(ValidationError):
        ApprovalLimit(intent_index=0, amount=amount)


# --- the decision follows from the findings -----------------------------------


@pytest.mark.parametrize(
    ("violations", "anomalies", "expected"),
    [
        ((), (), Decision.ALLOW),
        ((WRONG_RECIPIENT,), (), Decision.BLOCK),
        ((), (INCONSISTENT,), Decision.ESCALATE),
        # Both block; the anomaly also asks a human to look.
        ((WRONG_RECIPIENT,), (INCONSISTENT,), Decision.ESCALATE),
    ],
)
def test_decide(
    violations: tuple[Violation, ...], anomalies: tuple[Anomaly, ...], expected: Decision
) -> None:
    assert decide(violations, anomalies) is expected
    assert Verdict(decision=expected, violations=violations, anomalies=anomalies)


@pytest.mark.parametrize(
    ("decision", "violations", "anomalies"),
    [
        (Decision.ALLOW, (WRONG_RECIPIENT,), ()),  # a violation can't be allowed
        (Decision.ALLOW, (), (INCONSISTENT,)),  # nor an anomaly
        (Decision.BLOCK, (), (INCONSISTENT,)),  # an anomaly escalates
        (Decision.BLOCK, (), ()),  # nothing found: no reason to block
        (Decision.ESCALATE, (WRONG_RECIPIENT,), ()),  # a plain violation blocks
    ],
)
def test_a_decision_that_contradicts_the_findings_is_rejected(
    decision: Decision, violations: tuple[Violation, ...], anomalies: tuple[Anomaly, ...]
) -> None:
    with pytest.raises(ValidationError, match="must follow"):
        Verdict(decision=decision, violations=violations, anomalies=anomalies)


@pytest.mark.parametrize("field", ["charges", "approval_limits"])
@pytest.mark.parametrize(
    ("decision", "findings"),
    [
        (Decision.BLOCK, {"violations": (WRONG_RECIPIENT,)}),
        (Decision.ESCALATE, {"anomalies": (INCONSISTENT,)}),
    ],
)
def test_only_an_allowed_transaction_is_charged(
    field: str, decision: Decision, findings: dict[str, Any]
) -> None:
    item = (Charge if field == "charges" else ApprovalLimit)(intent_index=0, amount=1)
    with pytest.raises(ValidationError, match="only an allowed"):
        Verdict(decision=decision, **findings, **{field: (item,)})


@pytest.mark.parametrize("model", [Charge, ApprovalLimit])
def test_one_charge_and_one_approval_limit_per_intent(model: type[Charge | ApprovalLimit]) -> None:
    field = "charges" if model is Charge else "approval_limits"
    twice = (model(intent_index=0, amount=1), model(intent_index=0, amount=2))
    with pytest.raises(ValidationError, match="at most one"):
        allowed(**{field: twice})
    assert allowed(**{field: (model(intent_index=0, amount=1), model(intent_index=1, amount=1))})


# --- each code carries the fields its explanation needs -------------------------


def test_every_code_declares_its_fields() -> None:
    assert set(_VIOLATION_FIELDS) == set(ViolationCode)
    assert set(_ANOMALY_FIELDS) == set(AnomalyCode)


@pytest.mark.parametrize("code", list(ViolationCode))
def test_violation_requires_its_fields(code: ViolationCode) -> None:
    complete: dict[str, Any] = {
        "intent_index": 0,
        "asset": NATIVE,
        "counterparty": BOB,
        "amount": 1,
        "limit": 1,
    }
    required = _VIOLATION_FIELDS[code]
    assert Violation(code=code, **{k: v for k, v in complete.items() if k in required})
    for missing in required:
        fields = {k: v for k, v in complete.items() if k in required and k != missing}
        with pytest.raises(ValidationError, match=f"requires {missing}"):
            Violation(code=code, **fields)


@pytest.mark.parametrize("code", list(AnomalyCode))
def test_anomaly_requires_its_fields(code: AnomalyCode) -> None:
    complete: dict[str, Any] = {"contract": USDC, "account": BOB, "log_index": 0}
    required = _ANOMALY_FIELDS[code]
    assert Anomaly(code=code, **{k: v for k, v in complete.items() if k in required})
    for missing in required:
        fields = {k: v for k, v in complete.items() if k in required and k != missing}
        with pytest.raises(ValidationError, match=f"requires {missing}"):
            Anomaly(code=code, **fields)


def test_codes_are_stable_strings() -> None:
    # Codes are written to audit logs and returned to agents: renaming one
    # breaks every reader. This pins the spelling of a few on purpose.
    assert ViolationCode.WRONG_RECIPIENT == "wrong_recipient"
    assert ViolationCode.BELOW_MINIMUM == "below_minimum"
    assert AnomalyCode.INCONSISTENT_TOKEN_STATE == "inconsistent_token_state"
    assert Decision.ESCALATE == "escalate"


# --- audit record -----------------------------------------------------------------


def test_audit_record_carries_the_verdict() -> None:
    verdict = Verdict(decision=Decision.BLOCK, violations=(WRONG_RECIPIENT,))
    record = AuditRecord(decision=Decision.BLOCK, verdict=verdict, raw="0x")
    data = json.loads(record.to_json_line())
    assert data["verdict"]["violations"][0]["code"] == "wrong_recipient"
    assert data["verdict"]["violations"][0]["amount"] == str(10**15)
    assert AuditRecord.model_validate(data).verdict == verdict


def test_audit_record_without_a_verdict() -> None:
    data = json.loads(AuditRecord.undecodable("0x01", "bad").to_json_line())
    assert data["verdict"] is None


def test_escalate_is_a_valid_audit_decision() -> None:
    record = AuditRecord(
        decision=Decision.ESCALATE,
        verdict=Verdict(decision=Decision.ESCALATE, anomalies=(INCONSISTENT,)),
        raw="0x",
    )
    assert json.loads(record.to_json_line())["decision"] == "escalate"
