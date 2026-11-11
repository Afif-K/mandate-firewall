"""M4 end to end: a real `mandate-firewall serve` verifies what each
transaction does on its anvil fork against the sender's mandate, then
forwards, blocks or escalates (docs/m4-plan.md §7).

Every test locks its own mandate for ALICE (replacing the last one), the way
`mandate new --replace` would, next to the running proxy."""

import io
import time
from typing import Any

import pytest
from eth_utils import keccak

from mandate_firewall.alerts import run as show_alerts
from mandate_firewall.mandate.models import AssetRef, Budget, Ratio, SwapIntent
from mandate_firewall.mandate.store import MandateStore
from mandate_firewall.models import UINT256_MAX
from mandate_firewall.proxy.jsonrpc import TRANSACTION_REJECTED
from tests.contracts import load
from tests.integration.chain import ALICE, BOB, THIEF, balance, call, deploy, sign, transact
from tests.integration.services import Proxy, Service, rpc_call, rpc_result
from tests.mandates import mandate_with, native_transfer_mandate, replace_mandate

pytestmark = pytest.mark.anvil

MILLI = 10**15  # 0.001 ETH
USD = 10**6  # MockERC20 has 6 decimals, so both mUSD and mETH do
ERC20, ROUTER = load("MockERC20"), load("MockRouter")


def chain_id(anvil: Service) -> int:
    return int(rpc_result(anvil.url, "eth_chainId"), 16)


def via_proxy(proxy: Proxy, to: str, data: str = "0x", value: int = 0) -> tuple[str, Any]:
    raw = sign(proxy.url, to, data, value)
    return "0x" + keccak(hexstr=raw).hex(), rpc_call(proxy.url, "eth_sendRawTransaction", [raw])


def mined(anvil: Service, tx_hash: str) -> bool:
    """Mined successfully. Waits for the receipt: anvil knows a transaction
    (eth_getTransactionByHash) a moment before its block exists."""
    for _ in range(100):
        receipt = rpc_result(anvil.url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt["status"] == "0x1"
        time.sleep(0.05)
    pytest.fail(f"{tx_hash} not mined")


def never_seen(anvil: Service, tx_hash: str) -> bool:
    """The node never received it (blocked transactions aren't forwarded)."""
    return rpc_result(anvil.url, "eth_getTransactionByHash", [tx_hash]) is None


def record_for(proxy: Proxy, tx_hash: str) -> dict[str, Any]:
    return [r for r in proxy.audit_records() if r["hash"] == tx_hash][-1]


def stored(proxy: Proxy, mid: str) -> Any:
    store = MandateStore(proxy.mandate_db)
    try:
        return store.get(mid)
    finally:
        store.close()


def eth_mandate(anvil: Service, proxy: Proxy, budget: int, txs: int = 4) -> str:
    """send at most `budget` wei to Bob, `txs` transactions."""
    m = native_transfer_mandate(chain_id(anvil), ALICE, budget=budget, max_transactions=txs)
    return replace_mandate(proxy.mandate_db, m)


# --- ETH: the old demo step 6, and budgets ------------------------------------------


def test_off_mandate_eth_is_blocked_never_mined_and_not_charged(
    anvil: Service, proxy: Proxy
) -> None:
    mid = eth_mandate(anvil, proxy, 10 * MILLI)
    thief_before = balance(anvil.url, THIEF)
    tx_hash, response = via_proxy(proxy, THIEF, value=MILLI)

    assert response["error"]["code"] == TRANSACTION_REJECTED
    assert response["error"]["message"] == (
        "transaction rejected: off-mandate: target contract not in mandate; "
        "recipient not in mandate"
    )
    assert response["error"]["data"]["violations"] == ["unnamed_target", "wrong_recipient"]
    assert never_seen(anvil, tx_hash)
    assert balance(anvil.url, THIEF) == thief_before
    record = record_for(proxy, tx_hash)
    assert record["decision"] == "block"
    assert f"sends 0.001 ETH (native) to {THIEF}" in record["explanation"]
    assert (stored(proxy, mid).transactions, stored(proxy, mid).spent) == (0, (0,))
    assert f"BLOCKED  tx {tx_hash}" in proxy.log.read_text()  # the operator log


def test_budget_exact_and_over(anvil: Service, proxy: Proxy) -> None:
    """Demo steps 3, 5 and 6: 0.004 allowed, 0.007 over the 0.006 left,
    0.006 allowed, and then the budget is spent: exhausted."""
    mid = eth_mandate(anvil, proxy, 10 * MILLI)
    first, response = via_proxy(proxy, BOB, value=4 * MILLI)
    assert response["result"] == first and mined(anvil, first)
    assert record_for(proxy, first)["explanation"].endswith(
        "intent 1: 0.004 ETH (native), 0.006 ETH left"
    )

    over, response = via_proxy(proxy, BOB, value=7 * MILLI)
    assert response["error"]["data"]["violations"] == ["over_budget"]
    assert "but only 0.006 ETH (native) is left" in record_for(proxy, over)["explanation"]
    assert never_seen(anvil, over)

    last, response = via_proxy(proxy, BOB, value=6 * MILLI)
    assert response["result"] == last
    after = stored(proxy, mid)
    assert (after.spent, after.transactions, after.status) == ((10 * MILLI,), 2, "exhausted")


def test_a_resend_is_not_charged_twice(anvil: Service, proxy: Proxy) -> None:
    mid = eth_mandate(anvil, proxy, 10 * MILLI)
    raw = sign(proxy.url, BOB, value=MILLI)
    first = rpc_call(proxy.url, "eth_sendRawTransaction", [raw])
    again = rpc_call(proxy.url, "eth_sendRawTransaction", [raw])
    tx_hash = "0x" + keccak(hexstr=raw).hex()
    assert first["result"] == tx_hash
    # The node has it already; what it answers is passed through unchanged.
    assert again.get("result") == tx_hash or "error" in again
    assert [r["resend"] for r in proxy.audit_records() if r["hash"] == tx_hash] == [False, True]
    assert (stored(proxy, mid).transactions, stored(proxy, mid).spent) == (1, (MILLI,))


# --- swaps through MockRouter (demo step 7) -----------------------------------------


@pytest.fixture
def market(anvil: Service, proxy: Proxy) -> dict[str, str]:
    """mUSD, mETH and a MockRouter with 1 mETH of liquidity at 0.03 mETH per
    100 mUSD, deployed on the upstream directly (the market, not the agent),
    and a mandate: swap at most 100 mUSD for mETH via the router, at least
    0.03 mETH for 100 mUSD."""
    musd, meth = deploy(anvil.url, ERC20), deploy(anvil.url, ERC20)
    router = deploy(anvil.url, ROUTER)
    transact(anvil.url, ERC20, musd, "mint", ALICE, 100 * USD)
    transact(anvil.url, ERC20, meth, "mint", router, USD)
    transact(anvil.url, ROUTER, router, "setRate", musd, meth, 3, 10_000)
    cid = chain_id(anvil)
    swap = SwapIntent(
        kind="swap",
        sell=AssetRef(chain_id=cid, address=musd, decimals=6),
        sell_budget=Budget(max=100 * USD, period=None),
        buy=AssetRef(chain_id=cid, address=meth, decimals=6),
        min_buy_per_sell=Ratio(numerator=30_000, denominator=100 * USD),
        venues=(router,),
    )
    mid = replace_mandate(proxy.mandate_db, mandate_with(cid, ALICE, swap, max_transactions=5))
    return {"musd": musd, "meth": meth, "router": router, "mid": mid}


def swap_data(m: dict[str, str], recipient: str, amount: int = 100 * USD) -> str:
    return ROUTER.call_data("exactInputSingle", m["musd"], m["meth"], recipient, amount, 0)


def refused(response: dict[str, Any], *violations: str) -> None:
    assert response["error"]["code"] == TRANSACTION_REJECTED, response
    assert response["error"]["data"]["violations"] == list(violations)


def meth_of(anvil: Service, m: dict[str, str], who: str) -> int:
    return call(anvil.url, ERC20, m["meth"], "balanceOf", who)


def test_swap_scenarios(anvil: Service, proxy: Proxy, market: dict[str, str]) -> None:
    m = market
    # (a) an unlimited approval
    _, response = via_proxy(proxy, m["musd"], ERC20.call_data("approve", m["router"], UINT256_MAX))
    refused(response, "unlimited_approval")

    # (b) an approval of exactly the budget
    approve, response = via_proxy(
        proxy, m["musd"], ERC20.call_data("approve", m["router"], 100 * USD)
    )
    assert response["result"] == approve and mined(anvil, approve)

    # (c) the within-policy, off-mandate attack: right router, right token,
    # right amount, the output to the thief
    tx_hash, response = via_proxy(proxy, m["router"], swap_data(m, THIEF))
    refused(response, "nothing_received")
    assert never_seen(anvil, tx_hash) and meth_of(anvil, m, THIEF) == 0

    # (d) a manipulated price: a third of the minimum
    transact(anvil.url, ROUTER, m["router"], "setRate", m["musd"], m["meth"], 1, 10_000)
    _, response = via_proxy(proxy, m["router"], swap_data(m, ALICE))
    refused(response, "below_minimum")
    transact(anvil.url, ROUTER, m["router"], "setRate", m["musd"], m["meth"], 3, 10_000)

    # (f) pull + sweep (plan §6): 1 mUSD swapped honestly, 99 swept to the
    # thief. With a minimum, what arrived is far too little for what left.
    drain = ROUTER.call_data(
        "multicall",
        [
            bytes.fromhex(c[2:])
            for c in (
                swap_data(m, ALICE, USD),
                ROUTER.call_data("pull", m["musd"], 99 * USD),
                ROUTER.call_data("sweepToken", m["musd"], 0, THIEF),
            )
        ],
    )
    tx_hash, response = via_proxy(proxy, m["router"], drain)
    refused(response, "below_minimum")
    assert never_seen(anvil, tx_hash)

    # (e) the honest swap, exactly at the minimum
    tx_hash, response = via_proxy(proxy, m["router"], swap_data(m, ALICE))
    assert response["result"] == tx_hash and mined(anvil, tx_hash)
    assert meth_of(anvil, m, ALICE) == 30_000
    after = stored(proxy, m["mid"])
    assert (after.transactions, after.spent, after.status) == (2, (100 * USD,), "exhausted")


def test_alerts_lists_what_the_proxy_blocked(anvil: Service, proxy: Proxy) -> None:
    eth_mandate(anvil, proxy, 10 * MILLI)
    tx_hash, _ = via_proxy(proxy, THIEF, value=MILLI)
    out, err = io.StringIO(), io.StringIO()
    assert show_alerts(proxy.audit_log, out, err) == 0
    assert f"  BLOCKED  tx {tx_hash}\n" in out.getvalue()
    assert f"    sends 0.001 ETH (native) to {THIEF}\n" in out.getvalue()
    assert err.getvalue() == ""
