"""Smoke tests: each compiled test contract deploys on a real anvil and does
what it exists to do. They also run real receipts and traces through the log
decoder and trace parser."""

import pytest
from eth_utils import to_checksum_address

from mandate_firewall.models import TokenStandard
from mandate_firewall.simulate.logs import decode_logs
from mandate_firewall.simulate.trace import parse_call_trace
from tests.contracts import NAMES, load
from tests.integration.chain import ALICE, BOB, THIEF, balance, call, deploy, transact
from tests.integration.conftest import Service, rpc_result

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
