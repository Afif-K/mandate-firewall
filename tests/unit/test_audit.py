import json
import logging
import os
import stat
from pathlib import Path

import pytest

from mandate_firewall.audit import MAX_RAW_CHARS, AuditLog, AuditLogError, AuditRecord
from mandate_firewall.models import Decision


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="ascii").splitlines()


def test_writes_one_json_line_per_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.write(AuditRecord.undecodable("0x01", "first"))
    log.write(AuditRecord.undecodable("0x02", "second"))
    log.close()
    lines = read_lines(path)
    assert [json.loads(line)["reason"] for line in lines] == ["first", "second"]


def test_appends_across_restarts(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    for reason in ("before", "after"):
        log = AuditLog(path)
        log.write(AuditRecord.undecodable("0x", reason))
        log.close()
    assert len(read_lines(path)) == 2


def test_creates_parent_dirs_and_owner_only_file(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "audit.jsonl"
    AuditLog(path).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_warns_about_existing_world_readable_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "audit.jsonl"
    path.touch()
    os.chmod(path, 0o644)
    with caplog.at_level(logging.WARNING, logger="mandate_firewall"):
        AuditLog(path).close()
    assert "accessible to other users" in caplog.text


def test_unopenable_path_raises(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("")
    with pytest.raises(AuditLogError):
        AuditLog(tmp_path / "file" / "audit.jsonl")


def test_write_after_close_raises(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.close()
    with pytest.raises(AuditLogError):
        log.write(AuditRecord.undecodable("0x", "late"))


@pytest.mark.parametrize("raw", ['0x\n{"decision":"allow"}', "0x\ud800", "0x\u2028\x00\u00e9"])
def test_hostile_raw_stays_on_one_ascii_line(tmp_path: Path, raw: str) -> None:
    # An agent controls the raw string of an undecodable transaction. It must
    # not be able to forge a second record or break the encoder.
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.write(AuditRecord.undecodable(raw, "bad"))
    log.close()
    (line,) = read_lines(path)
    assert json.loads(line)["raw"] == raw


def test_undecodable_raw_is_truncated() -> None:
    record = AuditRecord.undecodable("0x" + "ab" * MAX_RAW_CHARS, "too big")
    assert len(record.raw) == MAX_RAW_CHARS
    assert record.raw_truncated
    assert record.decision is Decision.BLOCK
    assert not AuditRecord.undecodable("0xab", "short").raw_truncated


def test_big_integers_serialize_as_strings() -> None:
    record = AuditRecord(decision=Decision.ALLOW, value=2**256 - 1, chain_id=1, raw="0x")
    data = json.loads(record.to_json_line())
    assert data["value"] == str(2**256 - 1)
    assert data["chain_id"] == "1"
    assert data["gas_price"] is None
    assert data["ts"].startswith("20")
