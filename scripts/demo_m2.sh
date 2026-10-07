#!/usr/bin/env bash
# M2 demo: what the firewall does with transactions once it simulates them.
#
# Start these first, each in its own terminal, from the repo root:
#   anvil --chain-id 84532
#   uv run mandate-firewall serve --upstream http://127.0.0.1:8545
# Then, from the repo root:
#   scripts/demo_m2.sh
#
# Override the defaults with env vars if you started things differently:
#   UP=http://127.0.0.1:8545  FW=http://127.0.0.1:8546  AUDIT_LOG=logs/audit.jsonl
#
# Uses anvil's public dev accounts. Local testing only: never real funds.

set -euo pipefail

UP=${UP:-http://127.0.0.1:8545}          # the chain itself (anvil)
FW=${FW:-http://127.0.0.1:8546}          # the firewall, which the agent talks to
AUDIT_LOG=${AUDIT_LOG:-logs/audit.jsonl}  # relative to where the firewall was started

# anvil's dev account 0 (the agent's wallet) and dev account 1. Public keys
# from the "test test ... junk" mnemonic: local only.
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ALICE=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
BOB=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
THIEF=0x000000000000000000000000000000000000dEaD
ARTIFACTS=tests/fixtures/contracts/artifacts

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

# --- preflight -------------------------------------------------------------------

for tool in cast jq; do
  command -v "$tool" >/dev/null || { echo "error: $tool not found on PATH" >&2; exit 1; }
done
[ -f "$ARTIFACTS/MockERC20.json" ] || { echo "error: run this from the repo root" >&2; exit 1; }
chain_up=$(cast chain-id --rpc-url "$UP" 2>/dev/null) \
  || { echo "error: no chain at $UP (start: anvil --chain-id 84532)" >&2; exit 1; }
chain_fw=$(cast chain-id --rpc-url "$FW" 2>/dev/null) \
  || { echo "error: no firewall at $FW (start: uv run mandate-firewall serve --upstream $UP)" >&2; exit 1; }
if [ "$chain_up" != 84532 ] || [ "$chain_fw" != 84532 ]; then
  echo "error: expected chain id 84532 on both, got chain=$chain_up firewall=$chain_fw" >&2
  exit 1
fi
[ -r "$AUDIT_LOG" ] || { echo "error: audit log $AUDIT_LOG not found (set AUDIT_LOG)" >&2; exit 1; }

echo "Chain at $UP, firewall at $FW, both on chain 84532 (Base Sepolia's id)."
echo "Audit log: $AUDIT_LOG"
echo "The agent is Alice ($ALICE). Every transaction it sends goes to the"
echo "firewall, which runs it on a private fork first and records the effects."
pause

# --- 1 ---------------------------------------------------------------------------

step 1 "a plain ETH transfer is simulated, recorded and forwarded"
explain "Alice sends 0.01 ETH to Bob through the firewall."
explain "Expect: status 1 (success). The audit record says decision=allow, and its"
explain "effects show Bob +10000000000000000 wei and Alice -0.01 ETH minus gas."
explain "The gas fee is split out (effects.gas_cost), so it can't hide a transfer."
echo
cast send --rpc-url "$FW" --private-key "$KEY" "$BOB" --value 0.01ether | grep -E '^(status|transactionHash)'
echo
last_audit '{decision, gas_cost: .effects.gas_cost, changes: .effects.native_balance_changes}'
pause

# --- 2 ---------------------------------------------------------------------------

step 2 "setup: deploy a token directly on the chain (not through the firewall)"
explain "This is us setting up the world, not the agent: a plain ERC-20 (MockERC20),"
explain "with 100 tokens (6 decimals) minted to Alice. Sent straight to $UP."
explain "Expect: a contract address."
echo
TOKEN=$(cast send --rpc-url "$UP" --private-key "$KEY" --json \
  --create "$(jq -r .bytecode "$ARTIFACTS/MockERC20.json")" | jq -r .contractAddress)
cast send --rpc-url "$UP" --private-key "$KEY" "$TOKEN" "mint(address,uint256)" "$ALICE" 100000000 >/dev/null
echo "  token: $TOKEN"
pause

# --- 3 ---------------------------------------------------------------------------

step 3 "an ERC-20 transfer: events checked against the token's storage"
explain "Alice sends 25 tokens to Bob through the firewall."
explain "Expect: success. The record has one token transfer (Alice -> Bob, 25000000)"
explain "and two state checks, Alice claimed -25000000 and Bob +25000000, both"
explain "consistent: balanceOf before/after matches what the Transfer event says."
echo
cast send --rpc-url "$FW" --private-key "$KEY" "$TOKEN" "transfer(address,uint256)" "$BOB" 25000000 | grep -E '^status'
echo
last_audit '{decision, transfers: [.effects.token_transfers[] | {sender, recipient, amount}]}'
last_audit '[.effects.token_state_checks[] | {owner, claimed, consistent}]'
pause

# --- 4 ---------------------------------------------------------------------------

step 4 "a transaction that reverts is blocked and never reaches the chain"
explain "Alice tries to send 1,000,000 tokens; she has 75."
explain "(--gas-limit stops cast from estimating gas first, which would hit the"
explain "revert itself and never send the transaction to the firewall.)"
explain "Expect: error -32003 'transaction reverts in simulation'. The record says"
explain "decision=block and keeps the raw revert data 0x4e487b71...11: Solidity's"
explain "Panic(0x11), arithmetic underflow. Stored as hex, never decoded to text."
echo
cast send --rpc-url "$FW" --private-key "$KEY" --gas-limit 100000 \
  "$TOKEN" "transfer(address,uint256)" "$BOB" 1000000000000 2>&1 | tail -n 1 || true
echo
last_audit '{decision, reason, status: .effects.status, revert_data: .effects.revert_data}'
pause

# --- 5 ---------------------------------------------------------------------------

step 5 "a lying token: its event says Bob, its storage says the thief"
explain "Setup (direct to the chain): deploy LyingToken and mint Alice 100. Its"
explain "transfer() debits Alice correctly but credits a hard-coded thief, while"
explain "emitting Transfer(Alice -> Bob)."
explain "Then Alice sends Bob 10 through the firewall."
explain "Expect: success. M2 records effects but makes no intent decisions yet"
explain "(that's M4). The record shows the lie: Alice claimed -10, measured -10,"
explain "consistent; Bob claimed +10, measured 0, consistent=false."
echo
LYING=$(cast send --rpc-url "$UP" --private-key "$KEY" --json \
  --create "$(jq -r .bytecode "$ARTIFACTS/LyingToken.json")" "constructor(address)" "$THIEF" \
  | jq -r .contractAddress)
cast send --rpc-url "$UP" --private-key "$KEY" "$LYING" "mint(address,uint256)" "$ALICE" 100 >/dev/null
echo "  lying token: $LYING"
cast send --rpc-url "$FW" --private-key "$KEY" "$LYING" "transfer(address,uint256)" "$BOB" 10 | grep -E '^status'
echo
last_audit '[.effects.token_state_checks[] | {owner, claimed, measured: ((.after|tonumber) - (.before|tonumber)), consistent}]'
pause

# --- 6 ---------------------------------------------------------------------------

step 6 "the agent can't reach the simulator's cheat methods"
explain "The firewall talks to its fork with anvil_*/evm_*/debug_* methods. An agent"
explain "that could call them could, say, give itself a fake balance in simulation."
explain "Alice tries anvil_setBalance through the firewall."
explain "Expect: error -32601 'method ... is not allowed by the firewall'."
echo
cast rpc --rpc-url "$FW" anvil_setBalance "$BOB" 0x1 2>&1 | tail -n 1 || true
pause

# --- 7 ---------------------------------------------------------------------------

step 7 "the simulator dies; the next transaction restarts it"
explain "The firewall's private fork is an anvil child process. We kill it with -9."
explain "Its command line shows how it's run, and that the upstream URL (which can"
explain "hold an API key) isn't in it: the fork is told the URL over RPC instead."
explain "Expect: success for the next transfer. The firewall's terminal logs"
explain "'restarting the simulation node' and 'ready' with a new pid."
echo
pids=$(pgrep -f "no-mining --accounts 0" || true)
if [ "$(echo "$pids" | grep -c .)" != 1 ]; then
  echo "error: expected one simulator process, found: ${pids:-none}" >&2
  exit 1
fi
echo "  simulator before: $(ps -o pid=,args= -p "$pids")"
kill -9 "$pids"
sleep 0.5
cast send --rpc-url "$FW" --private-key "$KEY" "$BOB" --value 0.001ether | grep -E '^status'
echo "  simulator after:  $(ps -o pid=,args= -p "$(pgrep -f 'no-mining --accounts 0')")"

echo
echo "Done. Stop the firewall with Ctrl-C (it stops its simulator too), then anvil."
