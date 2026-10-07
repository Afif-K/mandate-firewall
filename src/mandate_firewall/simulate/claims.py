"""What a transaction's token events claim, as checks the simulator can run.

Events are claims made by the token contract (see logs.py). Storage is
closer to the truth: if a token's balanceOf and allowance are honest, reading
them before and after shows whether the events told the truth. This module
turns decoded events into the list of reads to make, and what each read
should show. It is pure; simulator.py does the reads.

- Balances: every address named in a token's Transfer events, sender *and*
  recipient. Checking only the sender misses a token that debits you
  correctly but credits someone other than the named recipient (see
  tests/fixtures/contracts/src/LyingToken.sol). The claim is the net change
  across all of that token's transfers: an ERC-20 transfer counts its
  amount, an ERC-721 transfer counts 1 (balanceOf counts tokens).
- The zero address is skipped: it stands for mint/burn, not an account, and
  ERC-721 balanceOf(0) reverts.
- Allowances: for each ERC-20 Approval, the allowance afterwards should be
  what the last Approval for that (owner, spender) said. A token that spends
  an allowance in the same transaction without emitting a new Approval will
  show as inconsistent. That is the safe direction to be wrong in.
- Not checked: ERC-721 single-token approvals and ApprovalForAll. Their
  getters (getApproved, isApprovedForAll) don't fit a before/after number,
  and M4 treats those approvals as high-risk on their own.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from mandate_firewall.models import Address, TokenStandard
from mandate_firewall.simulate.logs import DecodedLogs

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class StateCheckPlan(BaseModel):
    """One read to make before and after, and what the events claim it shows."""

    model_config = ConfigDict(frozen=True)

    token: Address
    kind: Literal["balance", "allowance"]
    owner: Address
    spender: Address | None = None
    claimed: int  # balance: net change; allowance: final value


def plan_state_checks(decoded: DecodedLogs) -> tuple[StateCheckPlan, ...]:
    """The checks for a transaction's logs, in first-seen order."""
    net: dict[tuple[str, str], int] = {}  # (token, owner) -> claimed net change
    for transfer in decoded.transfers:
        # The model guarantees an ERC-20 transfer has an amount.
        units = 1 if transfer.standard is TokenStandard.ERC721 else (transfer.amount or 0)
        if transfer.sender != ZERO_ADDRESS:
            key = (transfer.token, transfer.sender)
            net[key] = net.get(key, 0) - units
        if transfer.recipient != ZERO_ADDRESS:
            key = (transfer.token, transfer.recipient)
            net[key] = net.get(key, 0) + units

    allowances: dict[tuple[str, str, str], int] = {}  # (token, owner, spender) -> last value
    for approval in decoded.approvals:
        if approval.standard is TokenStandard.ERC20 and approval.owner != ZERO_ADDRESS:
            key = (approval.token, approval.owner, approval.spender)
            allowances[key] = approval.amount or 0

    balance_checks = [
        StateCheckPlan(token=token, kind="balance", owner=owner, claimed=claimed)
        for (token, owner), claimed in net.items()
    ]
    allowance_checks = [
        StateCheckPlan(token=token, kind="allowance", owner=owner, spender=spender, claimed=value)
        for (token, owner, spender), value in allowances.items()
    ]
    return tuple(balance_checks + allowance_checks)
