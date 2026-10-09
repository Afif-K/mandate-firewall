"""The mandate store: locked mandates on disk, in SQLite.

The capture CLI writes mandates here, running as the firewall's OS user. The
proxy reads them, and its only write is counting transactions. The agent runs
as another user and can't open the file, so file permissions are the boundary
(docs/m3-plan.md §3). The file is created 0600; a store that other users can
reach is warned about, like the audit log.

Three tables:
- mandates: the canonical JSON of each mandate, keyed by its sha256 id.
  Append-only: SQLite triggers refuse UPDATE and DELETE. Every read re-checks
  that the bytes are canonical and hash to the id, and that the lookup columns
  (chain, principal, times) agree with the bytes.
- events: status changes ("revoked", "exhausted"), also append-only.
  "Expired" isn't stored; it follows from the clock.
- counters: transactions charged per (mandate, period start). One-shot
  mandates have one period, starting at created_at. Standing mandates (M5)
  will add more rows, not columns.

Not tamper-evident against the firewall's own OS user: whoever can write the
file can drop the triggers and delete a "revoked" event or a counter row.
Content can't be changed undetected (the hash), status and counts can.
"""

import logging
import os
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from mandate_firewall.mandate.canonical import (
    CanonicalFormError,
    canonical_json,
    mandate_id,
    parse_canonical,
)
from mandate_firewall.mandate.models import Mandate

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
# A mandate created this far in the future means the capture machine's clock
# and ours disagree; refuse rather than guess which one is right.
MAX_CLOCK_SKEW = timedelta(minutes=1)

_SCHEMA = """
CREATE TABLE mandates (
    id         TEXT PRIMARY KEY,
    body       BLOB NOT NULL,
    chain_id   INTEGER NOT NULL,
    principal  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;
CREATE INDEX mandates_by_principal ON mandates (chain_id, principal);

CREATE TABLE events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    mandate_id TEXT NOT NULL REFERENCES mandates (id),
    event      TEXT NOT NULL CHECK (event IN ('revoked', 'exhausted')),
    at         TEXT NOT NULL,
    UNIQUE (mandate_id, event)
) STRICT;

CREATE TABLE counters (
    mandate_id   TEXT NOT NULL REFERENCES mandates (id),
    period_start TEXT NOT NULL,
    transactions INTEGER NOT NULL CHECK (transactions >= 0),
    PRIMARY KEY (mandate_id, period_start)
) STRICT;

CREATE TRIGGER mandates_no_update BEFORE UPDATE ON mandates
BEGIN SELECT RAISE(ABORT, 'mandates are append-only'); END;
CREATE TRIGGER mandates_no_delete BEFORE DELETE ON mandates
BEGIN SELECT RAISE(ABORT, 'mandates are append-only'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER counters_no_delete BEFORE DELETE ON counters
BEGIN SELECT RAISE(ABORT, 'counters are never deleted'); END;
CREATE TRIGGER counters_only_up BEFORE UPDATE ON counters
WHEN NEW.transactions < OLD.transactions
  OR NEW.mandate_id IS NOT OLD.mandate_id
  OR NEW.period_start IS NOT OLD.period_start
BEGIN SELECT RAISE(ABORT, 'counters only go up'); END;
"""


class MandateStoreError(Exception):
    """The store can't be opened, read or written."""


class MandateIntegrityError(MandateStoreError):
    """A stored mandate doesn't match its id or its lookup columns."""


class MandateConflictError(MandateStoreError):
    """The principal already has an active mandate (and replace wasn't asked)."""


class MandateNotActiveError(MandateStoreError):
    """The mandate is expired, revoked or exhausted, or doesn't exist."""


class MandateStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EXHAUSTED = "exhausted"


class StoredMandate(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    mandate: Mandate
    status: MandateStatus
    transactions: int  # charged so far, in the current period


class MandateStore:
    """One SQLite connection, used under a lock. Each write is one
    transaction that SQLite fsyncs before it returns (synchronous=FULL)."""

    def __init__(
        self,
        path: Path,
        *,
        create: bool = False,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        busy_timeout: float = 5.0,
    ) -> None:
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()
        try:
            if create:
                _create_file(path)
            elif not path.is_file():
                raise MandateStoreError(f"mandate store {path} does not exist")
            _warn_if_reachable(path)
            # isolation_level=None: we issue BEGIN/COMMIT ourselves, so a
            # check and the write that depends on it share one transaction.
            self._db = sqlite3.connect(
                path, timeout=busy_timeout, isolation_level=None, check_same_thread=False
            )
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = FULL")
            self._init_schema()
        except (sqlite3.Error, OSError) as exc:
            raise MandateStoreError(f"cannot open mandate store {path}: {exc}") from None

    def close(self) -> None:
        self._db.close()

    # --- writes ---------------------------------------------------------------

    def add(self, mandate: Mandate, *, replace: bool = False) -> str:
        """Store a confirmed mandate and return its id. If the principal
        already has an active mandate on this chain, refuse, or with
        replace=True revoke it in the same transaction."""
        now = self._now()
        if mandate.expires_at <= now:
            raise MandateStoreError("the mandate has already expired")
        if mandate.created_at > now + MAX_CLOCK_SKEW:
            raise MandateStoreError("the mandate is created in the future (clock skew?)")
        mid = mandate_id(mandate)
        with self._write() as db:
            for current in self._active(db, mandate.chain_id, mandate.principal, now):
                if not replace:
                    raise MandateConflictError(
                        f"principal already has an active mandate ({current.id})"
                    )
                self._event(db, current.id, MandateStatus.REVOKED, now)
            try:
                db.execute(
                    "INSERT INTO mandates VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        mid,
                        canonical_json(mandate),
                        mandate.chain_id,
                        mandate.principal,
                        _ts(mandate.created_at),
                        _ts(mandate.expires_at),
                    ),
                )
            except sqlite3.IntegrityError:
                raise MandateStoreError(f"mandate {mid} is already stored") from None
        return mid

    def revoke(self, mid: str) -> bool:
        """Revoke a mandate. False if it had already stopped being active."""
        now = self._now()
        with self._write() as db:
            stored = self._load(db, mid, now)
            if stored.status is not MandateStatus.ACTIVE:
                return False
            self._event(db, mid, MandateStatus.REVOKED, now)
        return True

    def record_transaction(self, mid: str) -> StoredMandate:
        """Charge one transaction to an active mandate, and mark it exhausted
        when that reaches max_transactions. The check and the increment are
        one transaction, so two callers can't both take the last slot.
        Raises MandateNotActiveError if the mandate can't take it."""
        now = self._now()
        with self._write() as db:
            stored = self._load(db, mid, now)
            if stored.status is not MandateStatus.ACTIVE:
                raise MandateNotActiveError(f"mandate {mid} is {stored.status}")
            period = _ts(stored.mandate.created_at)  # one period until M5
            db.execute(
                "INSERT INTO counters VALUES (?, ?, 1) ON CONFLICT (mandate_id, period_start)"
                " DO UPDATE SET transactions = transactions + 1",
                (mid, period),
            )
            used = stored.transactions + 1
            if used >= stored.mandate.limits.max_transactions:
                self._event(db, mid, MandateStatus.EXHAUSTED, now)
            return self._load(db, mid, now)

    # --- reads ----------------------------------------------------------------

    def get(self, mid: str) -> StoredMandate:
        with self._lock:
            return self._load(self._db, mid, self._now())

    def active_for(self, chain_id: int, principal: str) -> StoredMandate | None:
        """The principal's active mandate on this chain, or None. Raises
        MandateIntegrityError if any of the principal's rows fails its checks:
        a tampered store is an error to report, not a mandate to skip."""
        with self._lock:
            active = self._active(self._db, chain_id, principal, self._now())
        if len(active) > 1:  # add() prevents this; a store that has it was edited
            raise MandateIntegrityError("more than one active mandate for one principal")
        return active[0] if active else None

    def all(self) -> list[StoredMandate]:
        """Every stored mandate, oldest first."""
        with self._lock:
            now = self._now()
            ids = [row[0] for row in self._db.execute("SELECT id FROM mandates ORDER BY rowid")]
            return [self._load(self._db, mid, now) for mid in ids]

    # --- internals ------------------------------------------------------------

    def _now(self) -> datetime:
        return self._clock().replace(microsecond=0)

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE takes the write lock up front, so nothing can
        change between our checks and our writes, even from another process.
        A plain BEGIN would only lock at the first write, after the checks."""
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise MandateStoreError(f"mandate store is unavailable: {exc}") from None
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException as exc:
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass  # the failed statement may already have rolled back
                if isinstance(exc, sqlite3.Error):
                    raise MandateStoreError(f"mandate store write failed: {exc}") from None
                raise

    def _active(
        self, db: sqlite3.Connection, chain_id: int, principal: str, now: datetime
    ) -> list[StoredMandate]:
        ids = [
            row[0]
            for row in db.execute(
                "SELECT id FROM mandates WHERE chain_id = ? AND principal = ? ORDER BY rowid",
                (chain_id, principal),
            )
        ]
        loaded = [self._load(db, mid, now) for mid in ids]
        return [s for s in loaded if s.status is MandateStatus.ACTIVE]

    def _load(self, db: sqlite3.Connection, mid: str, now: datetime) -> StoredMandate:
        try:
            row = db.execute(
                "SELECT body, chain_id, principal, created_at, expires_at"
                " FROM mandates WHERE id = ?",
                (mid,),
            ).fetchone()
            if row is None:
                raise MandateNotActiveError(f"no mandate {mid}")
            events = {
                r[0] for r in db.execute("SELECT event FROM events WHERE mandate_id = ?", (mid,))
            }
            counter = db.execute(
                "SELECT transactions FROM counters WHERE mandate_id = ? AND period_start = ?",
                (mid, row[3]),
            ).fetchone()
        except sqlite3.Error as exc:
            raise MandateStoreError(f"cannot read mandate store: {exc}") from None

        body, chain_id, principal, created_at, expires_at = row
        try:
            if not isinstance(body, bytes):
                raise CanonicalFormError("mandate body is not bytes")
            mandate = parse_canonical(body)
        except CanonicalFormError as exc:
            raise MandateIntegrityError(f"mandate {mid}: {exc}") from None
        if mandate_id(mandate) != mid:
            raise MandateIntegrityError(f"mandate {mid}: content does not match its id")
        if (chain_id, principal, created_at, expires_at) != (
            mandate.chain_id,
            mandate.principal,
            _ts(mandate.created_at),
            _ts(mandate.expires_at),
        ):
            raise MandateIntegrityError(f"mandate {mid}: lookup columns do not match content")

        transactions = counter[0] if counter else 0
        if MandateStatus.REVOKED in events:
            status = MandateStatus.REVOKED
        elif MandateStatus.EXHAUSTED in events or transactions >= mandate.limits.max_transactions:
            status = MandateStatus.EXHAUSTED
        elif now >= mandate.expires_at:
            status = MandateStatus.EXPIRED
        else:
            status = MandateStatus.ACTIVE
        return StoredMandate(id=mid, mandate=mandate, status=status, transactions=transactions)

    def _event(self, db: sqlite3.Connection, mid: str, event: MandateStatus, now: datetime) -> None:
        db.execute(
            "INSERT INTO events (mandate_id, event, at) VALUES (?, ?, ?)",
            (mid, str(event), _ts(now)),
        )

    def _init_schema(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return
        if version != 0:
            raise MandateStoreError(f"unknown mandate store schema version {version}")
        tables = self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        if tables:
            raise MandateStoreError("file has tables but no mandate store schema version")
        self._db.executescript(f"BEGIN; {_SCHEMA} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;")


def _ts(value: datetime) -> str:
    """The same spelling as canonical JSON, which also sorts by time."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _create_file(path: Path) -> None:
    """Create the directory (0700) and the file (0600) if they don't exist.
    SQLite gives its -wal and -shm files the same mode as the database."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)


def _warn_if_reachable(path: Path) -> None:
    # The modes above only apply when we create the file and directory.
    for target, kind in ((path, "mandate store"), (path.parent, "mandate store directory")):
        mode = target.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            logger.warning(
                "%s %s is accessible to other users (mode %o); the agent must not be able "
                "to write mandates",
                kind,
                target,
                mode & 0o777,
            )
