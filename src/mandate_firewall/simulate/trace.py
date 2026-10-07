"""Parse a callTracer trace into call frames, touched addresses and created
contracts.

callTracer returns the call tree as nested JSON. Each frame looks like
    {"type": "CALL", "from": ..., "to": ..., "value": "0x1", "input": "0x...",
     "error": "execution reverted", "revertReason": "...", "calls": [...]}
and we flatten it depth-first (parent before children, children in order).

What we take from each frame, and what we deliberately don't (all of this
was checked against traces from anvil 1.8.3 in tests/fixtures/traces):
- `reverted` means the frame's effects were rolled back: it failed itself, or
  an ancestor did. A call inside a reverting call has no `error` of its own,
  but nothing it did survives.
- `value` is ETH that this frame moves from caller to target. DELEGATECALL
  frames report the *inherited* msg.value (the caller's caller sent it, and
  nothing moves), and CALLCODE keeps the value with the caller. Both get 0.
- A CREATE whose init code fails has no `to`: target None, nothing created.
- `revertReason` is the contract's own revert message, decoded to text by the
  node. It is attacker-chosen text, so it is never read. Neither are `error`,
  `output` or the gas fields. Revert data, if needed, comes from the receipt
  as hex.
- The walk is iterative. The EVM allows call depth 1024, deeper than
  Python's default recursion limit.

A trace that isn't a well-formed call tree raises TraceParseError. That
includes unknown frame types: a new tracer feature must fail loudly, not be
misread.
"""

import re
from typing import Any

from eth_utils import to_checksum_address
from pydantic import BaseModel, ConfigDict

from mandate_firewall.models import Address, CallFrame, CallType

MAX_CALL_DEPTH = 1024  # the EVM's limit; depth 0 is the transaction itself
SELECTOR_LEN = 4

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_DATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")

_CALLS_WITH_INPUT = {CallType.CALL, CallType.STATICCALL, CallType.DELEGATECALL, CallType.CALLCODE}
_CREATES = {CallType.CREATE, CallType.CREATE2}
# Frame types that move no ETH from caller to target, whatever `value` says.
_NO_TRANSFER = {CallType.DELEGATECALL, CallType.CALLCODE}


class TraceParseError(ValueError):
    """The node returned something that isn't a well-formed call trace."""


class ParsedTrace(BaseModel):
    model_config = ConfigDict(frozen=True)

    calls: tuple[CallFrame, ...]
    # Every address that appears as a caller or target, in first-seen order,
    # including in reverted frames. Their ETH balances before and after are
    # what measures native transfers.
    touched: tuple[Address, ...]
    # Contracts that exist after the transaction: CREATE/CREATE2 frames that
    # weren't rolled back.
    created: tuple[Address, ...]


def parse_call_trace(trace: Any) -> ParsedTrace:
    calls: list[CallFrame] = []
    touched: dict[str, None] = {}  # an ordered set
    created: list[str] = []

    # (frame, depth, rolled back by an ancestor). Children are pushed in
    # reverse so they pop in order.
    stack: list[tuple[Any, int, bool]] = [(trace, 0, False)]
    while stack:
        obj, depth, ancestor_reverted = stack.pop()
        if depth > MAX_CALL_DEPTH:
            raise TraceParseError(f"call depth exceeds the EVM limit of {MAX_CALL_DEPTH}")
        frame, children = _parse_frame(obj, depth, ancestor_reverted)
        if depth == 0 and frame.call_type not in (CallType.CALL, CallType.CREATE):
            raise TraceParseError(f"a transaction can't be a {frame.call_type} frame")

        calls.append(frame)
        touched[frame.caller] = None
        if frame.target is not None:
            touched[frame.target] = None
            if frame.call_type in _CREATES and not frame.reverted:
                created.append(frame.target)
        stack.extend((child, depth + 1, frame.reverted) for child in reversed(children))

    return ParsedTrace(calls=tuple(calls), touched=tuple(touched), created=tuple(created))


def _parse_frame(obj: Any, depth: int, ancestor_reverted: bool) -> tuple[CallFrame, list[Any]]:
    if not isinstance(obj, dict):
        raise TraceParseError("a trace frame must be an object")

    try:
        call_type = CallType(obj.get("type"))
    except (ValueError, TypeError) as exc:
        raise TraceParseError("trace frame has an unknown type") from exc

    caller = _address(obj.get("from"), "from")
    failed = "error" in obj  # its text is never read: see the module docstring
    reverted = failed or ancestor_reverted

    raw_target = obj.get("to")
    target: str | None
    if call_type in _CREATES and failed:
        target = None  # init code failed: no contract exists at any address
    else:
        target = _address(raw_target, "to")

    raw_value = obj.get("value")
    value = 0 if raw_value is None else _quantity(raw_value, "value")
    if call_type is CallType.STATICCALL and value != 0:
        raise TraceParseError("a STATICCALL frame can't carry value")
    if call_type in _NO_TRANSFER:
        value = 0

    raw_input = obj.get("input", "0x")
    if not isinstance(raw_input, str) or not _DATA.fullmatch(raw_input):
        raise TraceParseError("trace frame has invalid input")
    selector = None
    if call_type in _CALLS_WITH_INPUT and len(raw_input) >= 2 + 2 * SELECTOR_LEN:
        selector = raw_input[: 2 + 2 * SELECTOR_LEN]

    children = obj.get("calls", [])
    if not isinstance(children, list):
        raise TraceParseError("trace frame calls must be a list")
    if call_type is CallType.SELFDESTRUCT and children:
        raise TraceParseError("a SELFDESTRUCT frame can't have subcalls")

    frame = CallFrame(
        depth=depth,
        call_type=call_type,
        caller=caller,
        target=target,
        value=value,
        selector=selector,
        reverted=reverted,
    )
    return frame, children


def _address(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise TraceParseError(f"trace frame has an invalid {field!r} address")
    return to_checksum_address(value)


def _quantity(value: Any, field: str) -> int:
    if not isinstance(value, str) or not _QUANTITY.fullmatch(value):
        raise TraceParseError(f"trace frame has an invalid {field!r}")
    return int(value, 16)
