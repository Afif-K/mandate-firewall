"""Canonical JSON for mandates, and the mandate id (its sha256).

One mandate has exactly one byte string. That's what makes the id a lock: the
store keeps the bytes, recomputes the id on every load, and refuses bytes
that aren't exactly what `canonical_json` would write. A second accepted
spelling (reordered keys, "max": 5 vs "max": "5", an extra space) would let
two different byte strings, with two different ids, mean the same mandate,
or let a parser differential make one byte string mean two things.

The encoding: keys sorted, no whitespace, UTF-8 without escaping non-ASCII,
every field present (nulls included), uint256 values as decimal strings,
small integers (chain id, counts) as JSON numbers below 2**53, times as
"YYYY-MM-DDTHH:MM:SSZ". For the values a Mandate can hold (ASCII keys,
integers below 2**53, no floats), Python's json.dumps with these settings
produces the same bytes as RFC 8785 (JSON Canonicalization Scheme).
"""

import hashlib
import json

from pydantic import ValidationError

from mandate_firewall.mandate.models import Mandate


class CanonicalFormError(ValueError):
    """Bytes that aren't the canonical encoding of a valid mandate."""


def canonical_json(mandate: Mandate) -> bytes:
    return _encode(mandate.model_dump(mode="json"))


def mandate_id(mandate: Mandate) -> str:
    """0x-prefixed sha256 of the canonical JSON."""
    return "0x" + hashlib.sha256(canonical_json(mandate)).hexdigest()


def parse_canonical(data: bytes) -> Mandate:
    """Read a mandate back, accepting only its canonical bytes."""
    try:
        mandate = Mandate.model_validate(json.loads(data.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        # The message names the problem without echoing field values.
        raise CanonicalFormError(f"not a valid mandate ({type(exc).__name__})") from None
    if canonical_json(mandate) != data:
        raise CanonicalFormError("mandate bytes are not in canonical form")
    return mandate


def _encode(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
