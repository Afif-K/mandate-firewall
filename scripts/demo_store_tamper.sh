#!/usr/bin/env bash
# Mandate store tamper demo (M3 commit 3): what the store's defenses catch,
# and what they don't.
#
# Run from the repo root:
#   scripts/demo_store_tamper.sh
#
# Needs uv and the sqlite3 command-line tool. Everything happens in a fresh
# temporary directory that is deleted at the end (also on Ctrl-C or error).
# No chain, no keys, no network.

set -euo pipefail

CHAIN=84532
AGENT=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  # anvil dev account 0 (public)
BOB=0x70997970C51812dc3A010C7d01b50e0d17dc79C8    # anvil dev account 1 (public)
THIEF=0x000000000000000000000000000000000000dEaD

step() {
  echo
  echo "============================================================"
  echo "Step $1: $2"
  echo "============================================================"
}

explain() { echo "  $*"; }

pause() {
  echo
  read -r -p "press Enter to continue " _
}

# Run a Python snippet against the store, with the demo's values as env vars.
store_py() {
  DB="$DB" CHAIN="$CHAIN" AGENT="$AGENT" BOB="$BOB" THIEF="$THIEF" uv run --quiet python -
}

# --- preflight -------------------------------------------------------------------

for tool in uv sqlite3; do
  command -v "$tool" >/dev/null || { echo "error: $tool not found on PATH" >&2; exit 1; }
done
[ -f src/mandate_firewall/mandate/store.py ] || { echo "error: run this from the repo root" >&2; exit 1; }

WORK=$(mktemp -d)
cleanup() {
  rm -rf "$WORK"
  echo
  echo "cleaned up: removed $WORK"
}
trap cleanup EXIT

DB="$WORK/state/mandates.db"

echo "Mandate store tamper demo. Working in $WORK"

# --- 1 ---------------------------------------------------------------------------

step 1 "create a store, lock a mandate, charge one transaction"
explain "Tests: the normal path. The capture CLI (commit 6) will do this; here we"
explain "call the store directly. The mandate: send at most 50 USDC to Bob, 30 min,"
explain "at most 3 transactions. Its id is sha256 of its canonical JSON."
echo
store_py <<'PY'
import os, secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mandate_firewall.mandate.models import (
    AssetRef, Budget, Limits, Mandate, MandateKind, TransferIntent,
)
from mandate_firewall.mandate.store import MandateStore

chain = int(os.environ["CHAIN"])
now = datetime.now(UTC).replace(microsecond=0)
usdc = AssetRef(chain_id=chain, address="0x036CbD53842c5426634e7929541eC2318f3dCF7e", decimals=6)
mandate = Mandate(
    schema_version=1,
    kind=MandateKind.ONE_SHOT,
    chain_id=chain,
    principal=os.environ["AGENT"],
    intents=(
        TransferIntent(
            kind="transfer",
            asset=usdc,
            budget=Budget(max=50_000_000, period=None),
            recipient=os.environ["BOB"],
        ),
    ),
    limits=Limits(max_transactions=3, period=None),
    created_at=now,
    expires_at=now + timedelta(minutes=30),
    instruction="send 50 USDC to " + os.environ["BOB"],
    nonce="0x" + secrets.token_hex(32),
)
store = MandateStore(Path(os.environ["DB"]), create=True)
mid = store.add(mandate)
stored = store.record_transaction(mid)
print(f"  mandate id:   {mid}")
print(f"  principal:    {stored.mandate.principal}")
print(f"  status:       {stored.status}")
print(f"  transactions: {stored.transactions} of {stored.mandate.limits.max_transactions}")
store.close()
PY
explain ""
explain "Expect: status active, transactions 1 of 3."
pause

# --- 2 ---------------------------------------------------------------------------

step 2 "file permissions"
explain "Tests: the real boundary in M3. The agent runs as another OS user, so it"
explain "must not be able to open the store at all. Expect the directory drwx------"
explain "(0700) and the file -rw------- (0600). SQLite's -wal and -shm files get the"
explain "same mode while the store is open; it deletes them when the last connection"
explain "closes, so they may not be listed here."
echo
ls -ld "$WORK/state"
ls -l "$WORK/state"
pause

# --- 3 ---------------------------------------------------------------------------

step 3 "the triggers refuse edits"
explain "Tests: append-only is enforced by SQLite itself, not only by our code."
explain "Anyone opening the file with plain sqlite3 still hits the triggers."
echo
explain "\$ UPDATE mandates SET principal = '$THIEF'"
sqlite3 "$DB" "UPDATE mandates SET principal = '$THIEF';" 2>&1 | sed 's/^/  /' || true
explain "\$ DELETE FROM mandates"
sqlite3 "$DB" "DELETE FROM mandates;" 2>&1 | sed 's/^/  /' || true
explain "\$ DELETE FROM counters  (would reset the transaction count)"
sqlite3 "$DB" "DELETE FROM counters;" 2>&1 | sed 's/^/  /' || true
explain "\$ UPDATE counters SET transactions = 0  (would hand back used transactions)"
sqlite3 "$DB" "UPDATE counters SET transactions = 0;" 2>&1 | sed 's/^/  /' || true
echo
explain "Expect four 'Error: stepping, ...' lines, one per statement, and nothing"
explain "changed. (These are row triggers: they fire once per affected row. That's"
explain "why we target tables with rows; DELETE on the still-empty events table"
explain "would succeed, because it deletes nothing.)"
echo
sqlite3 -header -column "$DB" "SELECT substr(m.id, 1, 12) || '...' AS id, m.principal,
  c.transactions FROM mandates m JOIN counters c ON c.mandate_id = m.id;" | sed 's/^/  /'
pause

# --- 4 ---------------------------------------------------------------------------

step 4 "an attacker drops the trigger and repoints the mandate"
explain "Tests nothing yet; this sets up the attack. Someone who can write the file"
explain "(the firewall's own OS user, or root) can drop a trigger. They leave the"
explain "mandate's JSON alone, because changing it would change its sha256 id. They"
explain "edit only the 'principal' lookup column, so the proxy's lookup by sender"
explain "finds this mandate for the thief's account instead of the agent's."
echo
explain "\$ DROP TRIGGER mandates_no_update; UPDATE mandates SET principal = '$THIEF'"
sqlite3 "$DB" "DROP TRIGGER mandates_no_update; UPDATE mandates SET principal = '$THIEF';"
echo
explain "The column now says:"
sqlite3 -header -column "$DB" \
  "SELECT substr(id, 1, 12) || '...' AS id, principal FROM mandates;" | sed 's/^/  /'
pause

# --- 5 ---------------------------------------------------------------------------

step 5 "the store refuses to read the tampered row"
explain "Tests: every read re-checks the row. The bytes must be canonical, hash to"
explain "the id, and agree with the lookup columns. The JSON still says the agent's"
explain "address, the column says the thief's, so the read raises"
explain "MandateIntegrityError. It never returns the mandate and never skips the row."
echo
store_py <<'PY'
import os
from pathlib import Path

from mandate_firewall.mandate.store import MandateIntegrityError, MandateStore

store = MandateStore(Path(os.environ["DB"]))
chain = int(os.environ["CHAIN"])

for who in ("THIEF", "AGENT"):
    print(f"  active_for({who.lower()}):")
    try:
        found = store.active_for(chain, os.environ[who])
    except MandateIntegrityError as exc:
        print(f"    raised MandateIntegrityError: {exc}")
    else:
        print(f"    returned {found}")
store.close()
PY
explain ""
explain "Expect: the thief's lookup raises (in commit 7 the proxy turns that into a"
explain "block plus a 'store integrity failure' log). The agent's lookup returns None:"
explain "its mandate is gone, so its transactions are blocked too. Fail closed."
explain ""
explain "Known limit (THREAT_MODEL.md, commit 8): the same attacker could instead"
explain "drop the other triggers and delete a 'revoked' event or a counter row."
explain "Content can't change undetected; status and counts can."
pause

# --- 6 ---------------------------------------------------------------------------

step 6 "clean up"
explain "Tests: nothing. The temporary directory is removed on exit."
