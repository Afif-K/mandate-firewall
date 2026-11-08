"""Append-only audit log: one JSON line per intercepted transaction.

The record is written *before* the transaction is forwarded, and if it can't
be written the transaction is blocked. So every transaction that reached the
node has an audit line, even if the process dies right after forwarding.
What the node then did with it (accepted, "nonce too low", ...) goes to the
normal log; the audit line records what the firewall decided and why.

Why not the logging module: logging handlers swallow write errors (they call
handleError and carry on), so a full disk would silently turn the audit log
off while transactions kept flowing. Here a failed write raises.

The file holds signed transactions, including blocked ones that never reached
the chain. Anyone who can read it could broadcast those, so it is created
owner-read/write only (0600).
"""

import json
import logging
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from pydantic import BaseModel, ConfigDict, Field

from mandate_firewall.decode.transaction import MAX_RAW_TX_BYTES
from mandate_firewall.models import BigInt, Decision, DecodedCall, DecodedTransaction, Effects
from mandate_firewall.verify.models import Verdict

logger = logging.getLogger(__name__)

# Longest raw hex worth keeping: anything longer was rejected for size anyway.
MAX_RAW_CHARS = 2 + 2 * MAX_RAW_TX_BYTES


class AuditLogError(Exception):
    """The audit log could not be opened or written."""


class AuditRecord(BaseModel):
    """One intercepted eth_sendRawTransaction call.

    Transaction fields are None when the raw bytes couldn't be decoded; `raw`
    then holds what the agent sent, truncated to MAX_RAW_CHARS.
    """

    model_config = ConfigDict(frozen=True)

    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decision: Decision
    reason: str | None = None
    # The confirmed mandate this transaction was checked against, if one was
    # found, and for allowed transactions which of its transactions this is
    # (1 = the first). Blocked transactions are never charged, so None.
    mandate_id: str | None = None
    mandate_transaction: int | None = None
    hash: str | None = None
    tx_type: int | None = None
    chain_id: BigInt | None = None
    nonce: BigInt | None = None
    sender: str | None = None
    to: str | None = None
    value: BigInt | None = None
    gas_limit: BigInt | None = None
    gas_price: BigInt | None = None
    max_fee_per_gas: BigInt | None = None
    max_priority_fee_per_gas: BigInt | None = None
    selector: str | None = None
    call: DecodedCall | None = None
    # What the transaction did on the simulated fork. None if it was blocked
    # before simulation, or if simulation failed (then see simulation_error).
    effects: Effects | None = None
    simulation_error: str | None = None
    # How the effects compare with the mandate (M4). None if the transaction
    # was blocked before it could be verified (no mandate, no effects).
    verdict: Verdict | None = None
    raw: str
    raw_truncated: bool = False

    @classmethod
    def for_transaction(
        cls,
        tx: DecodedTransaction,
        call: DecodedCall,
        decision: Decision,
        reason: str | None = None,
        *,
        effects: Effects | None = None,
        simulation_error: str | None = None,
        verdict: Verdict | None = None,
        mandate_id: str | None = None,
        mandate_transaction: int | None = None,
    ) -> "AuditRecord":
        return cls(
            decision=decision,
            reason=reason,
            mandate_id=mandate_id,
            mandate_transaction=mandate_transaction,
            effects=effects,
            simulation_error=simulation_error,
            verdict=verdict,
            hash=tx.hash,
            tx_type=int(tx.tx_type),
            chain_id=tx.chain_id,
            nonce=tx.nonce,
            sender=tx.sender,
            to=tx.to,
            value=tx.value,
            gas_limit=tx.gas_limit,
            gas_price=tx.gas_price,
            max_fee_per_gas=tx.max_fee_per_gas,
            max_priority_fee_per_gas=tx.max_priority_fee_per_gas,
            selector=call.selector,
            call=call,
            raw=tx.raw,
        )

    @classmethod
    def undecodable(cls, raw: str, reason: str) -> "AuditRecord":
        return cls(
            decision=Decision.BLOCK,
            reason=reason,
            raw=raw[:MAX_RAW_CHARS],
            raw_truncated=len(raw) > MAX_RAW_CHARS,
        )

    def to_json_line(self) -> str:
        # Not model_dump_json(): undecodable input can contain lone UTF-16
        # surrogates (JSON "\ud800" parses to one), which can't be encoded as
        # UTF-8 and make it raise. ensure_ascii escapes them, and escaping
        # newlines keeps one record per line whatever the agent sent.
        return json.dumps(self.model_dump(mode="json"), ensure_ascii=True, separators=(",", ":"))


class AuditLog:
    """Appends AuditRecords to a JSONL file, one fsynced line each.

    Writes are synchronous: a few hundred bytes plus an fsync per transaction
    is fine at agent rates, and it means a write is done before we forward.
    Assumes a single proxy process owns the file.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._file: TextIO = os.fdopen(fd, "a", encoding="ascii")
            mode = os.fstat(fd).st_mode
        except OSError as exc:
            raise AuditLogError(f"cannot open audit log {path}: {exc}") from exc
        # The 0600 above only applies when we create the file.
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            logger.warning(
                "audit log %s is accessible to other users (mode %o)", path, mode & 0o777
            )

    def write(self, record: AuditRecord) -> None:
        try:
            self._file.write(record.to_json_line() + "\n")
            self._file.flush()
            os.fsync(self._file.fileno())
        except (OSError, ValueError) as exc:  # ValueError: write to a closed file
            raise AuditLogError(f"cannot write audit log {self.path}: {exc}") from exc

    def close(self) -> None:
        self._file.close()
