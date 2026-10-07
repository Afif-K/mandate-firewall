"""Which token state checks a transaction's events call for, and what they claim."""

from mandate_firewall.models import (
    OperatorApproval,
    TokenApproval,
    TokenStandard,
    TokenTransfer,
)
from mandate_firewall.simulate.claims import ZERO_ADDRESS, StateCheckPlan, plan_state_checks
from mandate_firewall.simulate.logs import DecodedLogs

TOKEN = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
OTHER = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
CAROL = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"


def erc20(sender: str, recipient: str, amount: int, token: str = TOKEN, i: int = 0):
    return TokenTransfer(
        token=token,
        standard=TokenStandard.ERC20,
        sender=sender,
        recipient=recipient,
        amount=amount,
        log_index=i,
    )


def plans(**groups) -> dict[tuple, int]:  # type: ignore[no-untyped-def]
    """{(token, kind, owner, spender): claimed}"""
    return {
        (p.token, p.kind, p.owner, p.spender): p.claimed
        for p in plan_state_checks(DecodedLogs(**groups))
    }


def test_no_events_no_checks() -> None:
    assert plan_state_checks(DecodedLogs()) == ()


def test_sender_and_recipient_are_both_checked() -> None:
    assert plans(transfers=(erc20(ALICE, BOB, 50),)) == {
        (TOKEN, "balance", ALICE, None): -50,
        (TOKEN, "balance", BOB, None): 50,
    }


def test_claims_are_netted_per_token_and_address() -> None:
    transfers = (
        erc20(ALICE, BOB, 50, i=0),
        erc20(BOB, CAROL, 20, i=1),
        erc20(ALICE, BOB, 5, i=2),
        erc20(ALICE, BOB, 7, token=OTHER, i=3),
        erc20(BOB, BOB, 9, i=4),  # to self: claims no change
    )
    assert plans(transfers=transfers) == {
        (TOKEN, "balance", ALICE, None): -55,
        (TOKEN, "balance", BOB, None): 35,
        (TOKEN, "balance", CAROL, None): 20,
        (OTHER, "balance", ALICE, None): -7,
        (OTHER, "balance", BOB, None): 7,
    }


def test_a_round_trip_still_gets_checked() -> None:
    # Net zero is a claim too: "your balance ends where it started".
    transfers = (erc20(ALICE, BOB, 10, i=0), erc20(BOB, ALICE, 10, i=1))
    assert set(plans(transfers=transfers).values()) == {0}


def test_mint_and_burn_skip_the_zero_address() -> None:
    transfers = (erc20(ZERO_ADDRESS, ALICE, 100, i=0), erc20(BOB, ZERO_ADDRESS, 3, i=1))
    assert plans(transfers=transfers) == {
        (TOKEN, "balance", ALICE, None): 100,
        (TOKEN, "balance", BOB, None): -3,
    }


def test_erc721_transfers_count_one_token_each() -> None:
    nft = [
        TokenTransfer(
            token=OTHER,
            standard=TokenStandard.ERC721,
            sender=ALICE,
            recipient=BOB,
            token_id=token_id,
            log_index=i,
        )
        for i, token_id in enumerate((7, 10**30))  # the id is not an amount
    ]
    assert plans(transfers=tuple(nft)) == {
        (OTHER, "balance", ALICE, None): -2,
        (OTHER, "balance", BOB, None): 2,
    }


def test_last_erc20_approval_per_pair_is_the_claim() -> None:
    def approval(spender: str, amount: int, i: int) -> TokenApproval:
        return TokenApproval(
            token=TOKEN,
            standard=TokenStandard.ERC20,
            owner=ALICE,
            spender=spender,
            amount=amount,
            log_index=i,
        )

    approvals = (approval(BOB, 100, 0), approval(CAROL, 1, 1), approval(BOB, 0, 2))
    assert plans(approvals=approvals) == {
        (TOKEN, "allowance", ALICE, BOB): 0,
        (TOKEN, "allowance", ALICE, CAROL): 1,
    }


def test_nft_approvals_are_not_state_checked() -> None:
    nft_approval = TokenApproval(
        token=OTHER,
        standard=TokenStandard.ERC721,
        owner=ALICE,
        spender=BOB,
        token_id=7,
        log_index=0,
    )
    operator = OperatorApproval(token=OTHER, owner=ALICE, operator=BOB, approved=True, log_index=1)
    assert plans(approvals=(nft_approval,), operator_approvals=(operator,)) == {}


def test_balance_checks_come_before_allowance_checks_in_first_seen_order() -> None:
    approval = TokenApproval(
        token=TOKEN, standard=TokenStandard.ERC20, owner=BOB, spender=CAROL, amount=1, log_index=0
    )
    result = plan_state_checks(
        DecodedLogs(transfers=(erc20(BOB, ALICE, 1, i=1),), approvals=(approval,))
    )
    assert [(p.kind, p.owner) for p in result] == [
        ("balance", BOB),
        ("balance", ALICE),
        ("allowance", BOB),
    ]
    assert all(isinstance(p, StateCheckPlan) for p in result)
