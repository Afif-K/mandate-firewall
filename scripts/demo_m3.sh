#!/usr/bin/env bash
# M3 demo: mandates. No confirmed mandate, no transaction.
#
# Run from the repo root, in a terminal (you confirm mandates by typing yes):
#   scripts/demo_m3.sh
#
# Self-contained: it starts its own anvil (chain id 84532, Base Sepolia's) and
# its own firewall on spare ports, with the mandate store and audit log in a
# fresh temporary directory. Everything is stopped and deleted at the end
# (also on Ctrl-C or error). No LLM is used: mandates are created with the
# structured flags, so no API key is needed and nothing leaves your machine.
#
# Override the ports if they are taken:
#   UP_PORT=18545  FW_PORT=18546
#
# Uses anvil's public dev accounts. Local testing only: never real funds.

set -euo pipefail

UP_PORT=${UP_PORT:-18545}
FW_PORT=${FW_PORT:-18546}
UP=http://127.0.0.1:$UP_PORT  # the chain itself (anvil)
FW=http://127.0.0.1:$FW_PORT  # the firewall, which the agent talks to

# anvil's dev accounts (public "test test ... junk" mnemonic): local only.
ALICE=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  # the agent's wallet
ALICE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
CAROL=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC  # a second agent account
CAROL_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
BOB=0x70997970C51812dc3A010C7d01b50e0d17dc79C8    # whom the user wants to pay
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

last_audit() { tail -n 1 "$AUDIT_LOG" | jq -c "$1"; }

# Send 0.001 ETH (or $3) from a dev account through the firewall; print the
# status line, or the firewall's error.
send() {
  cast send --rpc-url "$FW" --private-key "$1" "$2" --value "${3:-0.001ether}" 2>&1 \
    | grep -E '^status|error code' | sed 's/^Error: server returned an error response: //' || true
}

# The mandate CLI, with the demo's store and accounts. Environment variables
# take precedence over a .env file, so your own settings don't interfere.
mandate() {
  MANDATE_DB_PATH="$DB" MANDATE_PRINCIPALS="$ALICE,$CAROL" MANDATE_CHAIN_ID=84532 \
    uv run --quiet mandate-firewall mandate "$@"
}

newest_mandate_id() {
  DB="$DB" uv run --quiet python -c '
import os, sqlite3
db = sqlite3.connect(os.environ["DB"])
print(db.execute("SELECT id FROM mandates ORDER BY rowid DESC LIMIT 1").fetchone()[0])'
}

start_firewall() {
  uv run --quiet mandate-firewall serve --upstream "$UP" --port "$FW_PORT" \
    --audit-log "$AUDIT_LOG" --mandate-db "$DB" >"$DIR/firewall.log" 2>&1 &
  FW_PID=$!
  for _ in $(seq 100); do
    cast chain-id --rpc-url "$FW" >/dev/null 2>&1 && return 0
    kill -0 "$FW_PID" 2>/dev/null || { cat "$DIR/firewall.log" >&2; exit 1; }
    sleep 0.2
  done
  echo "error: firewall did not start; see $DIR/firewall.log" >&2
  exit 1
}

cleanup() {
  # TERM lets the firewall stop its own simulation anvil. `wait` returns the
  # killed process's status (143), so each step ignores failures: under
  # set -e a failing step would end the trap before the directory is deleted.
  set +e
  for pid in ${FW_PID:-} ${UP_PID:-}; do
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  done
  [ -n "${DIR:-}" ] && rm -rf "$DIR"
  return 0
}

# --- preflight -------------------------------------------------------------------

for tool in uv anvil cast jq; do
  command -v "$tool" >/dev/null || { echo "error: $tool not found on PATH" >&2; exit 1; }
done
[ -f scripts/demo_m3.sh ] || { echo "error: run this from the repo root" >&2; exit 1; }
[ -t 0 ] && [ -t 1 ] || { echo "error: run this in a terminal (you confirm mandates)" >&2; exit 1; }
for url in "$UP" "$FW"; do
  if cast chain-id --rpc-url "$url" >/dev/null 2>&1; then
    echo "error: something already answers at $url (set UP_PORT / FW_PORT)" >&2
    exit 1
  fi
done

DIR=$(mktemp -d)
trap cleanup EXIT
DB=$DIR/state/mandates.db
AUDIT_LOG=$DIR/audit.jsonl

anvil --chain-id 84532 --port "$UP_PORT" --quiet >"$DIR/anvil.log" 2>&1 &
UP_PID=$!
for _ in $(seq 50); do cast chain-id --rpc-url "$UP" >/dev/null 2>&1 && break; sleep 0.1; done

echo "Chain (anvil) at $UP, chain id 84532. Demo files in $DIR."
echo "The agent's wallets are Alice ($ALICE) and Carol ($CAROL)."
echo "You are the user. You want the agent to pay Bob ($BOB) 0.01 ETH."
pause

# --- 1 ---------------------------------------------------------------------------

step 1 "no mandate store, no firewall"
explain "The firewall needs the store that holds confirmed mandates. There is none yet."
explain "Expect: it refuses to start (exit code 3) and says the store does not exist."
explain "It never creates the store itself: only the capture CLI does."
echo
set +e
uv run --quiet mandate-firewall serve --upstream "$UP" --port "$FW_PORT" \
  --audit-log "$AUDIT_LOG" --mandate-db "$DB" >"$DIR/refused.log" 2>&1
code=$?
set -e
echo "  exit code: $code"
grep -o 'MandateStoreError: .*' "$DIR/refused.log" | sed 's/^/  /'
pause

# --- 2 ---------------------------------------------------------------------------

step 2 "you lock a mandate, before the agent reads anything"
explain "You give your instruction to the firewall directly, not to the agent: an"
explain "agent that has read a poisoned web page could rewrite it. Here we use the"
explain "structured flags (no LLM). With LLM_API_KEY set you could also write"
explain "  mandate new \"send 0.01 ETH to $BOB\""
explain "The summary shows full addresses (look-alike addresses match the first and"
explain "last characters) and registry names for tokens. It allows 2 transactions."
explain "Type yes to lock it."
echo
mandate new --principal "$ALICE" --send 0.01 ETH --to "$BOB" --max-transactions 2
MANDATE=$(newest_mandate_id)
pause

# --- 3 ---------------------------------------------------------------------------

step 3 "the firewall starts with the store"
explain "It opens the store counters-only: it can count transactions against a"
explain "mandate, but SQLite itself refuses any statement that would create, edit or"
explain "revoke one. It checks every stored mandate's hash before it starts."
echo
start_firewall
grep -o 'mandate store .*' "$DIR/firewall.log" | sed "s|$DIR|<demo dir>|; s/^/  /"
pause

# --- 4 ---------------------------------------------------------------------------

step 4 "an account without a mandate can't send anything"
explain "Carol is a configured agent account, but you never confirmed a mandate for"
explain "her. The key is (chain, sender), and the sender comes from the signature,"
explain "so the agent can't pretend to be Alice."
explain "Expect: error -32003 'no mandate for sender ...'. Never simulated, never mined."
echo
send "$CAROL_KEY" "$BOB"
last_audit '{decision, reason, mandate_id, effects}'
pause

# --- 5 ---------------------------------------------------------------------------

step 5 "the transaction you asked for goes through"
explain "Alice pays Bob 0.01 ETH."
explain "Expect: status 1. The audit record names the mandate and says this is its"
explain "transaction 1."
echo
send "$ALICE_KEY" "$BOB" 0.01ether
last_audit '{decision, mandate_id, mandate_transaction, to}'
pause

# --- 6 ---------------------------------------------------------------------------

step 6 "THE GAP: an off-mandate transaction also goes through (until M4)"
explain "An injected agent sends 0.001 ETH to $THIEF instead."
explain "The mandate only allows paying Bob, but M3 doesn't compare what a"
explain "transaction does with what the mandate allows yet; that's M4. M3 only"
explain "checks that a confirmed, unexpired mandate exists and has transactions left."
explain "Expect: status 1, charged as the mandate's transaction 2. The simulated"
explain "effects on record show exactly where the ETH went."
echo
send "$ALICE_KEY" "$THIEF"
last_audit '{decision, mandate_transaction, to, moved: [.effects.native_balance_changes[] | select(.address != "'"$ALICE"'")]}'
pause

# --- 7 ---------------------------------------------------------------------------

step 7 "the transaction cap holds"
explain "Two transactions used, two allowed. A third one, even to Bob, is blocked."
explain "Expect: error -32003 'mandate ... is exhausted (2 of 2 transactions used)'."
echo
send "$ALICE_KEY" "$BOB"
last_audit '{decision, reason, mandate_id, mandate_transaction}'
echo
mandate list
pause

# --- 8 ---------------------------------------------------------------------------

step 8 "you revoke a mandate, and it stops at once"
explain "You lock a second mandate (type yes again), then change your mind and revoke"
explain "it while the firewall is running. Revoking needs no confirmation: it can"
explain "only make the agent do less."
explain "Expect: error -32003 'mandate ... is revoked'."
echo
mandate new --principal "$ALICE" --send 0.01 ETH --to "$BOB" --max-transactions 2
SECOND=$(newest_mandate_id)
mandate revoke "$SECOND"
send "$ALICE_KEY" "$BOB"
pause

# --- 9 ---------------------------------------------------------------------------

step 9 "the agent can't reach mandates through its RPC"
explain "There are no mandate methods on the firewall, under any name. The agent's"
explain "RPC is default-deny, so it can't create, change, pick or even list mandates."
explain "Expect: error -32601 for each."
echo
for method in mandate_new firewall_createMandate firewall_approve; do
  printf '  %-24s ' "$method"
  cast rpc --rpc-url "$FW" "$method" '{}' 2>&1 | grep -o 'error code.*' || true
done
pause

# --- 10 --------------------------------------------------------------------------

step 10 "a tampered store blocks"
explain "Someone with write access to the store file (not the agent: it must run as"
explain "another OS user) tries to point your mandate at Carol's account by editing"
explain "the lookup column. Each stored mandate is checked against its own hash."
explain "Expect: Carol's transaction is blocked with 'mandate store integrity failure';"
explain "the details (which row, which check) go only to the firewall's log."
echo
DB="$DB" MANDATE="$MANDATE" CAROL="$CAROL" uv run --quiet python -c '
import os, sqlite3
db = sqlite3.connect(os.environ["DB"], isolation_level=None)
db.execute("DROP TRIGGER mandates_no_update")  # the store refuses UPDATEs otherwise
db.execute("UPDATE mandates SET principal = ? WHERE id = ?", (os.environ["CAROL"], os.environ["MANDATE"]))
print("  edited: mandate", os.environ["MANDATE"][:12] + "... now filed under Carol")'
send "$CAROL_KEY" "$BOB"
grep -o 'integrity failure on tx .*' "$DIR/firewall.log" | tail -n 1 | sed 's/^/  log: /'
explain ""
explain "Not caught, by contrast: deleting a 'revoked' event or a counter row. The"
explain "content is hashed, its status and counts aren't. See THREAT_MODEL.md."

echo
echo "Done. Press Enter to stop the firewall and anvil and delete $DIR."
read -r _
