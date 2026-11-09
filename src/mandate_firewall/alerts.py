"""`mandate-firewall alerts`: the blocked and escalated transactions in the audit log.

Escalation in M4 is "blocked now, plus a louder alert" (docs/m4-plan.md §3).
This command is where the operator reads those alerts. It shows the
explanation exactly as it was written when the firewall decided, not
re-rendered from today's store or registry, so it says what the firewall saw
and said at the time. Blocks from before verification (no mandate, a revert,
the wrong chain) have no explanation and show their reason instead.

Reads the audit log only: no mandate store, no registry, no upstream. It is
a viewer, so it exits 0 whatever it finds. Every line it prints goes through
safe_text, because anyone who can write the file can put terminal escapes in
it; a line that isn't a valid audit record is reported on stderr and skipped.
"""

import json
from collections import deque
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from mandate_firewall.audit import AuditRecord
from mandate_firewall.mandate.render import safe_text
from mandate_firewall.models import Decision

DEFAULT_LAST = 20
ALERT_DECISIONS = frozenset({Decision.BLOCK, Decision.ESCALATE})
_LABEL = {Decision.BLOCK: "BLOCKED", Decision.ESCALATE: "ESCALATED"}
_MAX_LINE = 2000  # characters per printed line


def run(
    path: Path,
    out: TextIO,
    err: TextIO,
    *,
    escalations_only: bool = False,
    last: int = DEFAULT_LAST,
) -> int:
    """Print the last `last` alerts, oldest first. Returns the exit status."""
    wanted = {Decision.ESCALATE} if escalations_only else ALERT_DECISIONS
    alerts: deque[AuditRecord] = deque(maxlen=last)
    total = 0
    try:
        with open(path, encoding="ascii", errors="replace") as lines:
            for number, line in enumerate(lines, start=1):
                record = _parse(line, number, err)
                if record is not None and record.decision in wanted:
                    total += 1
                    alerts.append(record)
    except FileNotFoundError:
        print(f"mandate-firewall: no audit log at {safe_text(str(path))}", file=err)
        return 1
    except OSError as exc:
        print(f"mandate-firewall: cannot read the audit log: {safe_text(str(exc))}", file=err)
        return 1

    kind = "escalation" if escalations_only else "alert"
    if not alerts:
        print(f"no {kind}s in {safe_text(str(path))}", file=out)
        return 0
    for record in alerts:
        print(format_alert(record), file=out)
        print(file=out)
    shown = f"last {len(alerts)} of {total}" if total > len(alerts) else f"{total}"
    plural = "" if total == 1 else "s"
    print(f"{shown} {kind}{plural} in {safe_text(str(path))}", file=out)
    return 0


def format_alert(record: AuditRecord) -> str:
    lines = [record.ts.strftime("%Y-%m-%d %H:%M:%S UTC")]
    if record.explanation is not None:
        lines += [f"  {line}" for line in record.explanation.splitlines()]
    else:
        lines.append(
            f"  {_LABEL[record.decision]}  tx {record.hash or '<undecodable>'}"
            f"  from {record.sender or '?'}"
        )
        if record.mandate_id is not None:
            lines.append(f"    under mandate {record.mandate_id}")
        lines.append(f"  reason: {record.reason or '?'}")
    return "\n".join(safe_text(line, _MAX_LINE) for line in lines)


def _parse(line: str, number: int, err: TextIO) -> AuditRecord | None:
    if not line.strip():
        return None
    try:
        # A cheap look at the decision first: most lines are allows.
        raw = json.loads(line)
        if not isinstance(raw, dict) or raw.get("decision") not in ALERT_DECISIONS:
            return None
        return AuditRecord.model_validate(raw)
    except (ValueError, ValidationError):  # json.JSONDecodeError is a ValueError
        print(f"mandate-firewall: skipping audit log line {number}: not a valid record", file=err)
        return None
