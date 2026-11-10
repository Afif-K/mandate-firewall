#!/usr/bin/env bash
# M4 demo: verification. A transaction must do what the mandate says.
#
# Run from the repo root, in a terminal (you confirm mandates by typing yes):
#   scripts/demo_m4.sh
#
# Self-contained, like demo_m3.sh: its own anvil (chain id 84532, Base
# Sepolia's) and its own firewall on spare ports, with the mandate store,
# audit log and a demo token registry in a fresh temporary directory.
# Everything is stopped and deleted at the end (also on Ctrl-C or error). No
# LLM is used: mandates are created with the structured flags, so no API key
# is needed and nothing leaves your machine.
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
BOB=0x70997970C51812dc3A010C7d01b50e0d17dc79C8    # whom the user wants to pay
MARKET_KEY=0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6  # account 9
THIEF=0x000000000000000000000000000000000000dEaD
MAX_UINT=115792089237316195423570985008687907853269984665640564039457584007913129639935
ARTIFACTS=tests/fixtures/contracts/artifacts
SWAP_SIG="exactInputSingle(address,address,address,uint256,uint256)"
USD=1000000  # the mock tokens have 6 decimals

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

# The last audit record's explanation, indented. Allowed records end with
# what was charged; blocked ones carry the "You asked / This transaction" diff.
last_explanation() { tail -n 1 "$AUDIT_LOG" | jq -r '.explanation // "(none)"' | sed 's/^/    /'; }

# Print the status line of a transaction the agent sends through the
# firewall, or the firewall's error. Callers end with `|| true`: cast exits
# non-zero on a blocked transaction, and with pipefail that ends the script.
show() { grep -E '^status|error code' | sed 's/^Error: server returned an error response: //'; }

# Alice (the agent) sends $2 (e.g. 0.004ether) to $1 through the firewall.
pay() { cast send --rpc-url "$FW" --private-key "$ALICE_KEY" "$1" --value "$2" 2>&1 | show || true; }

# Alice (the agent) calls a contract through the firewall: agent_call TO SIG ARGS...
agent_call() { cast send --rpc-url "$FW" --private-key "$ALICE_KEY" "$@" 2>&1 | show || true; }

# The market (not the agent) acts on the chain directly, not through the firewall.
market() { cast send --rpc-url "$UP" --private-key "$MARKET_KEY" "$@" >/dev/null; }

deploy() {
  local address
  address=$(cast send --rpc-url "$UP" --private-key "$MARKET_KEY" --json \
    --create "$(jq -r .bytecode "$ARTIFACTS/$1.json")" | jq -r .contractAddress)
  cast to-check-sum-address "$address"
}

# In base units: the mock tokens have 6 decimals, so 30000 is 0.03.
token_balance() { cast call --rpc-url "$UP" "$1" "balanceOf(address)(uint256)" "$2" | cut -d" " -f1; }

# The mandate CLI, with the demo's store, account and registry. Environment
# variables take precedence over a .env file, so your own settings don't interfere.
mandate() {
  MANDATE_DB_PATH="$DB" MANDATE_PRINCIPALS="$ALICE" MANDATE_CHAIN_ID=84532 \
    REGISTRY_PATH="$DIR/registry" uv run --quiet mandate-firewall mandate "$@"
}

start_firewall() {
  uv run --quiet mandate-firewall serve --upstream "$UP" --port "$FW_PORT" \
    --audit-log "$AUDIT_LOG" --mandate-db "$DB" --registry "$DIR/registry" \
    >"$DIR/firewall.log" 2>&1 &
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
[ -f scripts/demo_m4.sh ] || { echo "error: run this from the repo root" >&2; exit 1; }
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

# A small market for step 7, set up by "the market" (anvil account 9) on the
# chain directly: two test tokens and a router shaped like Uniswap's
# SwapRouter02 (tests/fixtures/contracts/src/MockRouter.sol). The router pays
# 0.03 mETH per 100 mUSD out of its own 1 mETH, and Alice holds 100 mUSD.
MUSD=$(deploy MockERC20)
METH=$(deploy MockERC20)
ROUTER=$(deploy MockRouter)
market "$MUSD" "mint(address,uint256)" "$ALICE" $((100 * USD))
market "$METH" "mint(address,uint256)" "$ROUTER" $((1 * USD))
market "$ROUTER" "setRate(address,address,uint256,uint256)" "$MUSD" "$METH" 3 10000

# The firewall and the capture CLI resolve names only through a registry,
# and the shipped Base Sepolia one doesn't know these local contracts. This
# one (REGISTRY_PATH / --registry) replaces it for the demo.
mkdir -p "$DIR/registry"
cat >"$DIR/registry/84532.json" <<EOF
{
  "schema_version": 1,
  "chain_id": 84532,
  "chain_name": "demo chain (local anvil, Base Sepolia's chain id)",
  "native": {"symbol": "ETH", "decimals": 18},
  "tokens": [
    {"symbol": "mUSD", "address": "$MUSD", "decimals": 6,
     "source": "https://localhost/demo (deployed by scripts/demo_m4.sh; not a real token)"},
    {"symbol": "mETH", "address": "$METH", "decimals": 6,
     "source": "https://localhost/demo (deployed by scripts/demo_m4.sh; not a real token)"}
  ],
  "venues": [
    {"name": "mockswap", "contracts": [
      {"label": "MockRouter (SwapRouter02-shaped test router)", "address": "$ROUTER",
       "source": "https://localhost/demo (deployed by scripts/demo_m4.sh)"}
    ]}
  ]
}
EOF

echo "Chain (anvil) at $UP, chain id 84532. Demo files in $DIR."
echo "The agent's wallet is Alice ($ALICE)."
echo "You are the user. First you want the agent to pay Bob ($BOB), at most 0.01 ETH."
pause

# --- 1 ---------------------------------------------------------------------------

step 1 "you lock a mandate: at most 0.01 ETH to Bob"
explain "As in M3, you give your instruction to the firewall, not to the agent. Since"
explain "M4 the amount is a budget, not just a description: every transaction is"
explain "checked against it. 4 transactions are allowed. Type yes to lock it."
echo
mandate new --send 0.01 ETH --to "$BOB" --max-transactions 4
pause

# --- 2 ---------------------------------------------------------------------------

step 2 "the firewall starts"
explain "It loads the registry (it refuses to start without a valid one for the"
explain "chain, since verification resolves names through it), checks every stored"
explain "mandate's hash, and starts its own simulation fork."
echo
start_firewall
grep -oE 'registry: .*|mandate store .*' "$DIR/firewall.log" | sed "s|$DIR|<demo dir>|; s/^/  /"
pause

# --- 3 ---------------------------------------------------------------------------

step 3 "the payment you asked for: allowed and charged"
explain "Alice pays Bob 0.004 ETH. The firewall simulates it, sees 0.004 ETH leave"
explain "for Bob, matches that against the mandate, and charges the budget."
explain "Expect: status 1. The audit record shows the charge and 0.006 ETH left."
echo
pay "$BOB" 0.004ether
last_audit '{decision, mandate_transaction}'
last_explanation
pause

# --- 4 ---------------------------------------------------------------------------

step 4 "M3's gap is closed: an off-mandate transfer is blocked"
explain "An injected agent sends 0.001 ETH to $THIEF."
explain "In demo_m3.sh this went through. It is within every limit: a small amount,"
explain "an account with an active mandate and transactions left. But the mandate"
explain "says the ETH goes to Bob."
explain "Expect: error -32003 'off-mandate: ... recipient not in mandate'. The agent"
explain "gets the reason as a code, never your budget or what is left. The audit"
explain "record has the full 'You asked / This transaction' diff. Nothing charged."
echo
pay "$THIEF" 0.001ether
last_audit '{decision, violations: [.verdict.violations[].code]}'
last_explanation
echo "  $THIEF balance on chain: $(cast balance --rpc-url "$UP" "$THIEF") wei"
pause

# --- 5 ---------------------------------------------------------------------------

step 5 "over budget: blocked"
explain "Alice tries to pay Bob 0.007 ETH. The recipient is right, but only 0.006"
explain "ETH of the budget is left."
explain "Expect: error -32003 'off-mandate: over budget'. Nothing charged."
echo
pay "$BOB" 0.007ether
last_explanation
pause

# --- 6 ---------------------------------------------------------------------------

step 6 "exactly the rest of the budget: allowed, and the mandate is used up"
explain "Alice pays Bob 0.006 ETH. That spends the budget exactly (the limit is"
explain "inclusive). The mandate is now exhausted, although only 2 of its 4"
explain "transactions were used: a spent budget ends it too."
echo
pay "$BOB" 0.006ether
last_explanation
echo
mandate list
pause

# --- 7 ---------------------------------------------------------------------------

step 7 "swaps: the within-policy, off-mandate attack"
explain "A market was set up when the demo started (by another account, directly on"
explain "the chain): two test tokens, mUSD and mETH, and 'mockswap', a router shaped"
explain "like Uniswap's SwapRouter02: a recipient parameter, plus pull, sweepToken and"
explain "multicall. It pays 0.03 mETH per 100 mUSD. Alice holds 100 mUSD."
explain "  mUSD     $MUSD"
explain "  mETH     $METH"
explain "  mockswap $ROUTER"
explain "You lock: swap at most 100 mUSD for mETH via mockswap, at least 0.03 mETH."
explain "Since M4 a swap needs a minimum; without --min-out the CLI refuses."
explain "Type yes to lock it."
echo
mandate new --swap 100 mUSD --for mETH --via mockswap --min-out 0.03 --max-transactions 3
pause

echo
echo "(a) An unlimited approval for the router."
explain "Expect: blocked, unlimited_approval. An approval may cover the swap"
explain "budget, never more: an unlimited one outlives the mandate."
agent_call "$MUSD" "approve(address,uint256)" "$ROUTER" "$MAX_UINT"
pause

echo
echo "(b) An approval of exactly the 100 mUSD budget."
explain "Expect: status 1. Approvals spend no budget; the swap that uses one does."
agent_call "$MUSD" "approve(address,uint256)" "$ROUTER" $((100 * USD))
pause

echo
echo "(c) THE ATTACK: the right router, the right token, the right amount, but"
echo "    recipient = $THIEF."
explain "A spend limit passes it (100 mUSD is within budget). An allowlist passes"
explain "it (mockswap is an allowed contract). Only what it does gives it away: 100"
explain "mUSD leave Alice and nothing comes back to her."
explain "Expect: blocked, nothing_received."
agent_call "$ROUTER" "$SWAP_SIG" "$MUSD" "$METH" "$THIEF" $((100 * USD)) 0
last_explanation
pause

echo
echo "(d) A manipulated price."
explain "Someone moves the router's price to a third of the honest rate (anyone can"
explain "call setRate on this test router). The swap itself is honest: Alice's"
explain "address, the full 100 mUSD."
explain "Expect: blocked, below_minimum: 0.01 mETH comes back, the minimum is 0.03."
market "$ROUTER" "setRate(address,address,uint256,uint256)" "$MUSD" "$METH" 1 10000
agent_call "$ROUTER" "$SWAP_SIG" "$MUSD" "$METH" "$ALICE" $((100 * USD)) 0
last_explanation
market "$ROUTER" "setRate(address,address,uint256,uint256)" "$MUSD" "$METH" 3 10000
explain "(The price is set back to the honest rate.)"
pause

echo
echo "(e) The pull + sweep drain, in one multicall."
explain "Swap 1 mUSD honestly (to Alice), pull the other 99 mUSD into the router,"
explain "and sweep them to $THIEF. Alice 'sold 100 mUSD through"
explain "the right venue and received mETH'. Without a minimum every rule would pass;"
explain "this is why capture now requires one."
explain "Expect: blocked, below_minimum: 0.0003 mETH back for 100 mUSD sold."
SWAP1=$(cast calldata "$SWAP_SIG" "$MUSD" "$METH" "$ALICE" $((1 * USD)) 0)
PULL=$(cast calldata "pull(address,uint256)" "$MUSD" $((99 * USD)))
SWEEP=$(cast calldata "sweepToken(address,uint256,address)" "$MUSD" 0 "$THIEF")
agent_call "$ROUTER" "multicall(bytes[])" "[$SWAP1,$PULL,$SWEEP]"
last_audit '{decision, violations: [.verdict.violations[].code]}'
pause

echo
echo "(f) The honest swap."
explain "100 mUSD for 0.03 mETH, to Alice: exactly the minimum, which is allowed."
explain "Expect: status 1. The budget is spent, so this mandate is exhausted too."
agent_call "$ROUTER" "$SWAP_SIG" "$MUSD" "$METH" "$ALICE" $((100 * USD)) 0
last_explanation
echo "  on chain, in base units (6 decimals):"
echo "    mETH: Alice $(token_balance "$METH" "$ALICE"), thief $(token_balance "$METH" "$THIEF")"
echo "    mUSD: Alice $(token_balance "$MUSD" "$ALICE"), thief $(token_balance "$MUSD" "$THIEF")"
pause

# --- 8 ---------------------------------------------------------------------------

step 8 "the alerts"
explain "Blocked and escalated transactions are never held for approval: a person"
explain "acts on the mandate (revoke it, or lock a new one), never on a single"
explain "transaction. 'alerts' lists them from the audit log with their explanations."
explain "Here the last 3 of the 6 blocks (drop --last to see all; --escalations for"
explain "anomalies only, of which this demo has none)."
echo
uv run --quiet mandate-firewall alerts --audit-log "$AUDIT_LOG" --last 3

echo
echo "Done. Press Enter to stop the firewall and anvil and delete $DIR."
read -r _
