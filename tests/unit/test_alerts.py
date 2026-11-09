"""`mandate-firewall alerts`: blocks and escalations from the audit log, as written."""

import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from mandate_firewall.alerts import run
from mandate_firewall.audit import AuditRecord
from mandate_firewall.cli import main
from mandate_firewall.models import Decision

HASH = "0x" + "ab" * 32
SENDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
MID = "0x" + "3f" * 32


def record(decision: Decision, n: int = 0, **fields: Any) -> AuditRecord:
    return AuditRecord(
        ts=datetime(2026, 11, 8, 14, 0, n, tzinfo=UTC),
        decision=decision,
        hash=HASH,
        sender=SENDER,
        raw="0x02",
        **fields,
    )


def write(path: Path, *records: AuditRecord | str) -> Path:
    lines = [r if isinstance(r, str) else r.to_json_line() for r in records]
    path.write_text("".join(line + "\n" for line in lines))
    return path


def alerts(path: Path, **kw: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    status = run(path, out, err, **kw)
    return status, out.getvalue(), err.getvalue()


EXPLAINED = (
    "BLOCKED  tx 0xab\n  under mandate 0x3f\nWhy:\n  - it calls 0xdead\nNothing was charged."
)
ESCALATED = "ESCALATED (blocked, ...)  tx 0xab"


def test_blocks_and_escalations_with_their_explanations(tmp_path: Path) -> None:
    log = write(
        tmp_path / "audit.jsonl",
        record(Decision.ALLOW, 0, explanation="ALLOWED  tx ..."),
        record(Decision.BLOCK, 1, reason="off-mandate: wrong recipient", explanation=EXPLAINED),
        record(Decision.BLOCK, 2, reason="no active mandate", mandate_id=None),
        record(Decision.ESCALATE, 3, reason="escalated: x", explanation=ESCALATED),
    )
    status, out, err = alerts(log)
    assert (status, err) == (0, "")
    assert out == (
        "2026-11-08 14:00:01 UTC\n"
        "  BLOCKED  tx 0xab\n"
        "    under mandate 0x3f\n"
        "  Why:\n"
        "    - it calls 0xdead\n"
        "  Nothing was charged.\n"
        "\n"
        "2026-11-08 14:00:02 UTC\n"
        f"  BLOCKED  tx {HASH}  from {SENDER}\n"
        "  reason: no active mandate\n"
        "\n"
        "2026-11-08 14:00:03 UTC\n"
        "  ESCALATED (blocked, ...)  tx 0xab\n"
        "\n"
        f"3 alerts in {log}\n"
    )
    assert "ALLOWED" not in out


def test_a_block_before_verification_names_its_mandate(tmp_path: Path) -> None:
    log = write(tmp_path / "a.jsonl", record(Decision.BLOCK, reason="reverts", mandate_id=MID))
    assert f"    under mandate {MID}\n  reason: reverts\n" in alerts(log)[1]


def test_escalations_only(tmp_path: Path) -> None:
    log = write(
        tmp_path / "a.jsonl",
        record(Decision.BLOCK, 1, reason="b"),
        record(Decision.ESCALATE, 2, reason="e"),
    )
    _, out, _ = alerts(log, escalations_only=True)
    assert "reason: e" in out and "reason: b" not in out
    assert out.endswith(f"1 escalation in {log}\n")


def test_last_n_oldest_first(tmp_path: Path) -> None:
    log = write(
        tmp_path / "a.jsonl", *(record(Decision.BLOCK, n, reason=f"r{n}") for n in range(5))
    )
    _, out, _ = alerts(log, last=2)
    assert [line for line in out.splitlines() if "reason" in line] == [
        "  reason: r3",
        "  reason: r4",
    ]
    assert out.endswith(f"last 2 of 5 alerts in {log}\n")


def test_no_alerts(tmp_path: Path) -> None:
    log = write(tmp_path / "a.jsonl", record(Decision.ALLOW))
    assert alerts(log) == (0, f"no alerts in {log}\n", "")


def test_missing_log(tmp_path: Path) -> None:
    status, out, err = alerts(tmp_path / "nope.jsonl")
    assert (status, out) == (1, "")
    assert "no audit log at" in err


def test_bad_lines_are_reported_and_skipped(tmp_path: Path) -> None:
    log = write(
        tmp_path / "a.jsonl",
        "not json",
        json.dumps({"decision": "block", "raw": 7}),  # a block, but not a valid record
        "[1, 2]",
        record(Decision.BLOCK, reason="kept"),
    )
    status, out, err = alerts(log)
    assert status == 0
    assert "reason: kept" in out
    assert err.splitlines() == [
        "mandate-firewall: skipping audit log line 1: not a valid record",
        "mandate-firewall: skipping audit log line 2: not a valid record",
    ]


def test_terminal_escapes_in_the_file_are_neutralized(tmp_path: Path) -> None:
    """Anyone who can write the audit log can write anything into it."""
    log = write(
        tmp_path / "a.jsonl",
        record(Decision.BLOCK, reason="x\x1b[2J‮y", explanation="BLOCKED\x1b]0;pwned\x07"),
        record(Decision.BLOCK, reason="z\x1b[31m"),
    )
    _, out, _ = alerts(log)
    assert "\x1b" not in out and "‮" not in out and "\x07" not in out
    assert "  BLOCKED?]0;pwned?\n" in out
    assert "  reason: z?[31m\n" in out


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = write(tmp_path / "a.jsonl", record(Decision.ESCALATE, reason="e"))
    with pytest.raises(SystemExit) as exit_:
        main(["alerts", "--audit-log", str(log), "--escalations", "--last", "1"])
    assert exit_.value.code == 0
    assert "reason: e" in capsys.readouterr().out


def test_cli_reads_audit_log_path_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    log = write(tmp_path / "env.jsonl", record(Decision.BLOCK, reason="from env"))
    monkeypatch.chdir(tmp_path)  # no .env here
    monkeypatch.setenv("AUDIT_LOG_PATH", str(log))
    with pytest.raises(SystemExit):
        main(["alerts"])
    assert "reason: from env" in capsys.readouterr().out
