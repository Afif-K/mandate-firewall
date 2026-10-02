"""Classify JSON-RPC methods: intercept, forward, or deny.

Default deny: a method is forwarded only if it is on the read-only allowlist
below. Anything we haven't reviewed is rejected, including methods that
don't exist yet. A denylist would fail open: every new node method (or an
anvil_/debug_ method we forgot) would pass through by default.

What "read-only" means here: the method cannot change chain state, cannot
make the node sign anything, and cannot change the node's own state. That
excludes, for example:
- eth_sendTransaction / eth_sign* / personal_*: the node signs with keys it
  holds. We only accept transactions the agent signed itself.
- anvil_* / hardhat_* / evm_*: dev-node cheatcodes (set balances, impersonate
  accounts, mine blocks).
- eth_newFilter and friends: create state on the node. Not needed yet.
- eth_accounts: lists node-held keys, which are useful only for
  eth_sendTransaction.
"""

from enum import StrEnum


class MethodClass(StrEnum):
    INTERCEPT = "intercept"  # decode and check before forwarding
    FORWARD = "forward"  # read-only: pass through unchanged
    DENY = "deny"  # everything else


INTERCEPTED_METHODS: frozenset[str] = frozenset({"eth_sendRawTransaction"})

READ_ONLY_METHODS: frozenset[str] = frozenset(
    {
        # chain and node info
        "eth_chainId",
        "net_version",
        "web3_clientVersion",
        "eth_syncing",
        "eth_blockNumber",
        # fees
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_feeHistory",
        "eth_blobBaseFee",
        # account state
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getProof",
        # execution against current state, never committed
        "eth_call",
        "eth_estimateGas",
        "eth_createAccessList",
        # blocks, transactions, receipts, logs
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getBlockReceipts",
        "eth_getBlockTransactionCountByNumber",
        "eth_getBlockTransactionCountByHash",
        "eth_getTransactionByHash",
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getTransactionByBlockHashAndIndex",
        "eth_getTransactionReceipt",
        "eth_getLogs",
    }
)

if INTERCEPTED_METHODS & READ_ONLY_METHODS:
    raise RuntimeError("a method cannot be both intercepted and forwarded")


def classify(method: str) -> MethodClass:
    # Exact, case-sensitive match. Nodes treat method names case-sensitively,
    # so "ETH_sendRawTransaction" is just an unknown method and is denied.
    if method in INTERCEPTED_METHODS:
        return MethodClass.INTERCEPT
    if method in READ_ONLY_METHODS:
        return MethodClass.FORWARD
    return MethodClass.DENY
