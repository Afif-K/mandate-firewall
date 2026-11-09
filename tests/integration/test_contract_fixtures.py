"""Smoke tests: each compiled test contract deploys on a real anvil and does
what it exists to do. They also run real receipts and traces through the log
decoder and trace parser."""

import pytest
from eth_utils import to_checksum_address

from mandate_firewall.models import TokenStandard
from mandate_firewall.simulate.logs import decode_logs
from mandate_firewall.simulate.trace import parse_call_trace
from tests.contracts import NAMES, load
from tests.integration.chain import ALICE, BOB, THIEF, balance, call, deploy, send, transact
from tests.integration.conftest import Service, rpc_call, rpc_result

pytestmark = pytest.mark.anvil


@pytest.mark.parametrize("name", NAMES)
def test_every_contract_deploys(anvil: Service, name: str) -> None:
    args = {
        "LyingToken": (THIEF,),
        "TimeBomb": (2**40, THIEF),
        "SimDetector": (THIEF, THIEF),
    }.get(name, ())
    address = deploy(anvil.url, load(name), *args)
    assert rpc_result(anvil.url, "eth_getCode", [address, "latest"]) != "0x"


def test_mock_erc20(anvil: Service) -> None:
    token = load("MockERC20")
    address = deploy(anvil.url, token)
    transact(anvil.url, token, address, "mint", ALICE, 100_000_000)
    receipt = transact(anvil.url, token, address, "transfer", BOB, 50_000_000)

    assert call(anvil.url, token, address, "balanceOf", ALICE) == 50_000_000
    assert call(anvil.url, token, address, "balanceOf", BOB) == 50_000_000
    (transfer,) = decode_logs(receipt["logs"], receipt["transactionHash"]).transfers
    assert (transfer.standard, transfer.token, transfer.sender, transfer.recipient) == (
        TokenStandard.ERC20,
        address,
        ALICE,
        BOB,
    )
    assert transfer.amount == 50_000_000

    receipt = transact(anvil.url, token, address, "approve", BOB, 2**256 - 1)
    (approval,) = decode_logs(receipt["logs"], receipt["transactionHash"]).approvals
    assert (approval.spender, approval.amount) == (BOB, 2**256 - 1)


def test_mock_erc721(anvil: Service) -> None:
    nft = load("MockERC721")
    address = deploy(anvil.url, nft)
    transact(anvil.url, nft, address, "mint", ALICE, 7)

    receipt = transact(anvil.url, nft, address, "setApprovalForAll", BOB, True)
    (operator,) = decode_logs(receipt["logs"], receipt["transactionHash"]).operator_approvals
    assert (operator.owner, operator.operator, operator.approved) == (ALICE, BOB, True)

    receipt = transact(anvil.url, nft, address, "transferFrom", ALICE, BOB, 7)
    (transfer,) = decode_logs(receipt["logs"], receipt["transactionHash"]).transfers
    assert (transfer.standard, transfer.token_id, transfer.recipient) == (
        TokenStandard.ERC721,
        7,
        BOB,
    )
    assert to_checksum_address(hex(call(anvil.url, nft, address, "ownerOf", 7))) == BOB


def test_lying_token_events_disagree_with_storage(anvil: Service) -> None:
    token = load("LyingToken")
    address = deploy(anvil.url, token, THIEF)
    transact(anvil.url, token, address, "mint", ALICE, 100)

    # transfer: the event says Bob got 10; storage says the thief did.
    receipt = transact(anvil.url, token, address, "transfer", BOB, 10)
    (claim,) = decode_logs(receipt["logs"], receipt["transactionHash"]).transfers
    assert (claim.recipient, claim.amount) == (BOB, 10)
    assert call(anvil.url, token, address, "balanceOf", BOB) == 0
    assert call(anvil.url, token, address, "balanceOf", THIEF) == 10
    # Alice's balance did drop by 10, so checking only the sender's balance
    # would call this event consistent. See the note in docs/m2-plan.md.
    assert call(anvil.url, token, address, "balanceOf", ALICE) == 90

    # fakeTransfer: the event says Bob got 5; nothing moved.
    receipt = transact(anvil.url, token, address, "fakeTransfer", BOB, 5)
    (claim,) = decode_logs(receipt["logs"], receipt["transactionHash"]).transfers
    assert (claim.recipient, claim.amount) == (BOB, 5)
    assert call(anvil.url, token, address, "balanceOf", ALICE) == 90
    assert call(anvil.url, token, address, "balanceOf", BOB) == 0


def test_eth_forwarder_moves_eth_only_the_trace_shows(anvil: Service) -> None:
    forwarder = load("EthForwarder")
    address = deploy(anvil.url, forwarder)
    before = balance(anvil.url, BOB)
    receipt = transact(anvil.url, forwarder, address, "forward", BOB, value=10**18)

    assert balance(anvil.url, BOB) - before == 10**18
    assert receipt["logs"] == []  # no event says anything
    trace = rpc_result(
        anvil.url, "debug_traceTransaction", [receipt["transactionHash"], {"tracer": "callTracer"}]
    )
    top, inner = parse_call_trace(trace).calls
    assert (top.target, top.value) == (address, 10**18)
    assert (inner.caller, inner.target, inner.value) == (address, BOB, 10**18)


def test_time_bomb_depends_on_block_timestamp(anvil: Service) -> None:
    bomb = load("TimeBomb")
    now = int(rpc_result(anvil.url, "eth_getBlockByNumber", ["latest", False])["timestamp"], 16)
    armed_at = now + 1000
    address = deploy(anvil.url, bomb, armed_at, THIEF)

    rpc_result(anvil.url, "evm_setNextBlockTimestamp", [armed_at - 1])
    bob_before = balance(anvil.url, BOB)
    transact(anvil.url, bomb, address, "forward", BOB, value=1)
    assert balance(anvil.url, BOB) - bob_before == 1  # honest one second early

    rpc_result(anvil.url, "evm_setNextBlockTimestamp", [armed_at])
    thief_before = balance(anvil.url, THIEF)
    transact(anvil.url, bomb, address, "forward", BOB, value=1)
    assert balance(anvil.url, THIEF) - thief_before == 1  # a thief from armedAt on


def test_sim_detector_depends_on_coinbase(anvil: Service) -> None:
    detector = load("SimDetector")
    anvil_coinbase = rpc_result(anvil.url, "eth_getBlockByNumber", ["latest", False])["miner"]
    address = deploy(anvil.url, detector, to_checksum_address(anvil_coinbase), THIEF)

    bob_before = balance(anvil.url, BOB)
    transact(anvil.url, detector, address, "forward", BOB, value=1)
    assert balance(anvil.url, BOB) - bob_before == 1  # anvil's coinbase: looks honest

    real_coinbase = "0x4200000000000000000000000000000000000011"  # OP-stack fee vault
    rpc_result(anvil.url, "anvil_setCoinbase", [real_coinbase])
    try:
        thief_before = balance(anvil.url, THIEF)
        transact(anvil.url, detector, address, "forward", BOB, value=1)
        assert balance(anvil.url, THIEF) - thief_before == 1
    finally:
        rpc_result(anvil.url, "anvil_setCoinbase", [anvil_coinbase])


# --- MockRouter (docs/m4-plan.md §7) ------------------------------------------------

USD = 10**6  # MockERC20 has 6 decimals
# 0.03 mETH per 100 mUSD, the demo's minimum: 100 * 10**6 * 3 // 10_000 == 30_000.
RATE = (3, 10_000)


@pytest.fixture
def market(anvil: Service) -> dict[str, str]:
    """A fresh router (so no test sees another's leftovers) with 1 mETH of
    liquidity, a mUSD -> mETH rate, and 100 mUSD for ALICE."""
    token, router = load("MockERC20"), load("MockRouter")
    musd, meth = deploy(anvil.url, token), deploy(anvil.url, token)
    address = deploy(anvil.url, router)
    transact(anvil.url, token, musd, "mint", ALICE, 100 * USD)
    transact(anvil.url, token, meth, "mint", address, 1 * USD)
    transact(anvil.url, router, address, "setRate", musd, meth, *RATE)
    return {"musd": musd, "meth": meth, "router": address}


def balances(url: str, token: str, *who: str) -> list[int]:
    return [call(url, load("MockERC20"), token, "balanceOf", w) for w in who]


def swap_data(m: dict[str, str], recipient: str, amount_in: int, minimum: int = 0) -> str:
    return load("MockRouter").call_data(
        "exactInputSingle", m["musd"], m["meth"], recipient, amount_in, minimum
    )


def test_mock_router_swaps_at_its_rate(anvil: Service, market: dict[str, str]) -> None:
    m, token = market, load("MockERC20")
    transact(anvil.url, token, m["musd"], "approve", m["router"], 100 * USD)
    receipt = send(anvil.url, m["router"], swap_data(m, ALICE, 100 * USD, minimum=30_000))
    assert receipt["status"] == "0x1"

    assert balances(anvil.url, m["musd"], ALICE, m["router"]) == [0, 100 * USD]
    assert balances(anvil.url, m["meth"], ALICE, m["router"]) == [30_000, USD - 30_000]
    decoded = decode_logs(receipt["logs"], receipt["transactionHash"])
    assert [(t.token, t.sender, t.recipient, t.amount) for t in decoded.transfers] == [
        (m["musd"], ALICE, m["router"], 100 * USD),
        (m["meth"], m["router"], ALICE, 30_000),
    ]
    # No events of its own: only the tokens log, so nothing for the verifier
    # to escalate as an unrecognized event mentioning the principal.
    assert decoded.unrecognized == ()
    assert {to_checksum_address(log["address"]) for log in receipt["logs"]} <= {
        m["musd"],
        m["meth"],
    }


def test_mock_router_pays_any_recipient(anvil: Service, market: dict[str, str]) -> None:
    """The within-policy, off-mandate attack: right router, right token,
    right amount, output to the thief."""
    m = market
    transact(anvil.url, load("MockERC20"), m["musd"], "approve", m["router"], 100 * USD)
    send(anvil.url, m["router"], swap_data(m, THIEF, 100 * USD))
    assert balances(anvil.url, m["meth"], ALICE, THIEF) == [0, 30_000]
    assert balances(anvil.url, m["musd"], ALICE) == [0]


def test_mock_router_minimum_and_a_manipulated_rate(anvil: Service, market: dict[str, str]) -> None:
    m, router = market, load("MockRouter")
    transact(anvil.url, load("MockERC20"), m["musd"], "approve", m["router"], 100 * USD)
    # Its own minimum check: one unit above the quote reverts.
    reply = rpc_call(
        anvil.url,
        "eth_call",
        [{"from": ALICE, "to": m["router"], "data": swap_data(m, ALICE, 100 * USD, 30_001)}],
    )
    assert "too little received" in reply["error"]["message"]

    # Anyone can move the price; without a minimum the swap still goes through.
    transact(anvil.url, router, m["router"], "setRate", m["musd"], m["meth"], 1, 10_000)
    assert call(anvil.url, router, m["router"], "quote", m["musd"], m["meth"], 100 * USD) == 10_000
    send(anvil.url, m["router"], swap_data(m, ALICE, 100 * USD))
    assert balances(anvil.url, m["meth"], ALICE) == [10_000]


def test_mock_router_pull_and_sweep_drain(anvil: Service, market: dict[str, str]) -> None:
    """docs/m4-plan.md §6: in one multicall, swap 1 mUSD honestly, pull the
    other 99 into the router and sweep them to the thief. The principal
    "sold 100 mUSD through the right venue and received mETH"."""
    m, router = market, load("MockRouter")
    transact(anvil.url, load("MockERC20"), m["musd"], "approve", m["router"], 100 * USD)
    calls = [
        swap_data(m, ALICE, 1 * USD),
        router.call_data("pull", m["musd"], 99 * USD),
        router.call_data("sweepToken", m["musd"], 0, THIEF),
    ]
    receipt = transact(
        anvil.url, router, m["router"], "multicall", [bytes.fromhex(c[2:]) for c in calls]
    )

    assert balances(anvil.url, m["musd"], ALICE, m["router"], THIEF) == [0, 0, 100 * USD]
    assert balances(anvil.url, m["meth"], ALICE) == [300]  # something arrived: bought > 0
    decoded = decode_logs(receipt["logs"], receipt["transactionHash"])
    assert decoded.unrecognized == ()
    # multicall kept msg.sender: both pulls are transferFrom(ALICE -> router).
    assert [(t.sender, t.amount) for t in decoded.transfers if t.token == m["musd"]] == [
        (ALICE, 1 * USD),
        (ALICE, 99 * USD),
        (m["router"], 100 * USD),
    ]


def test_mock_router_multicall_bubbles_up_the_reason(
    anvil: Service, market: dict[str, str]
) -> None:
    m, router = market, load("MockRouter")
    data = router.call_data("multicall", [bytes.fromhex(swap_data(m, ALICE, USD, 10**9)[2:])])
    reply = rpc_call(anvil.url, "eth_call", [{"from": ALICE, "to": m["router"], "data": data}])
    assert "too little received" in reply["error"]["message"]
