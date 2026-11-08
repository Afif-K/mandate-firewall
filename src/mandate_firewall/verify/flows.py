"""Turn a transaction's Effects into the principal's flows and anomalies.

A mandate bounds what may leave one account, the principal (the agent's
wallet). So before matching anything, the verifier needs that account's own
movements of money: what left it, what arrived, and from or to whom. Those
are *flows*. Anything in the effects the verifier can't vouch for is an
*anomaly*, which escalates (docs/m4-plan.md §1, §3).

Pure: no I/O, no clock, no registry, no mandate. Input is Effects (hex and
addresses only, see models.py) and the principal.

ETH flows come from the call trace. Every frame that wasn't rolled back and
carries value moves ETH from its caller to its target (the trace parser
already gives DELEGATECALL and CALLCODE frames value 0, because nothing
moves). The gas fee isn't a flow: Effects.gas_cost reports it. Then the
flows are checked against the balance M2 *measured* for the principal:

    measured_delta == ETH in - ETH out - gas_cost

If that fails, ETH moved in a way the trace doesn't show, and nothing built
on the trace can be trusted. anvil doesn't charge the OP-stack L1 data fee
(THREAT_MODEL.md), so the fee is gas_cost alone on Base too. If a future
anvil starts charging it, every transaction escalates: fail closed, and the
integration tests show it.

Token flows come from Transfer events. Events are claims by the token
contract, so each token the principal sends or receives must also have a
consistent balance check for the principal (M2 plans one for every address
an event names). An ERC-721 transfer counts as an amount of 1, like
balanceOf counts tokens.

Flows are summed per (asset, direction, counterparty), in first-seen order.
A movement between the principal and itself isn't a flow: nothing leaves.

Anomalies (each escalates):
- inconsistent_token_state: a token's events disagree with its storage, or
  a token the principal sent or received has no consistent balance check
  for the principal.
- unrecognized_event: a log we can't decode mentions the principal (its
  address as a 32-byte word in any topic or in the data, at a 32-byte
  boundary), unless its signature is on the informational list below. It
  says something about this account that we can't interpret: an ERC-1155
  transfer, a Permit2 approval, a WETH Withdrawal (an outflow with no
  Transfer event).
- native_balance_unreconciled: the arithmetic above fails.
- principal_runs_code: a frame below the top has the principal as caller.
  A plain EOA never calls anything except as the transaction itself, so
  the account is running code (an EIP-7702 delegation, for instance).
- contract_created: anywhere in the call tree. No supported intent
  creates contracts.

Not seen here, by design or as a known limit (docs/m4-plan.md §8): events
that mention the principal only in packed or unaligned data, and tokens
that move the principal's balance without emitting any event.
"""

from collections.abc import Iterable

from eth_utils import keccak
from pydantic import BaseModel, ConfigDict

from mandate_firewall.models import (
    Effects,
    RawLog,
    SimulationStatus,
    TokenStandard,
)
from mandate_firewall.verify.models import (
    NATIVE,
    Anomaly,
    AnomalyCode,
    Asset,
    Flow,
    FlowDirection,
)

WORD = 32

# Events we can't decode but know to be informational. A log with one of
# these signatures never escalates, even when it names the principal. The
# list only ever *suppresses* an anomaly. It never makes an outflow allowed:
# that's decided from flows and state checks alone. So a contract that fakes
# one of these events gains nothing. Signatures checked against the source:
INFORMATIONAL_EVENTS: dict[str, str] = {
    # Uniswap v3 pool. Its `recipient` topic is the principal on every honest
    # swap, so without this entry every swap would escalate.
    # https://github.com/Uniswap/v3-core/blob/main/contracts/interfaces/pool/IUniswapV3PoolEvents.sol
    "0x" + keccak(text="Swap(address,address,int256,int256,uint160,uint128,int24)").hex(): (
        "Uniswap v3 Swap"
    ),
    # WETH9 deposit(): ETH in, WETH credited to `dst`, with no Transfer
    # event. The ETH side is a flow; the missed WETH inflow can only make a
    # swap look worse than it was. Withdrawal is deliberately NOT listed: it
    # debits WETH without a Transfer event, an outflow we must not miss.
    # https://github.com/gnosis/canonical-weth/blob/master/contracts/WETH9.sol
    "0x" + keccak(text="Deposit(address,uint256)").hex(): "WETH9 Deposit",
}


class FlowAnalysis(BaseModel):
    """The principal's flows in one transaction, and the anomalies found."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    flows: tuple[Flow, ...]
    anomalies: tuple[Anomaly, ...]


def analyze(effects: Effects, principal: str) -> FlowAnalysis:
    """Flows and anomalies of a successfully simulated transaction sent by
    `principal`. Raises ValueError otherwise: the proxy blocks reverted
    transactions before verifying, so getting one here is a bug."""
    if effects.status is not SimulationStatus.SUCCESS:
        raise ValueError("only a successful transaction has flows to verify")
    if effects.sender != principal:
        raise ValueError("the effects are not of a transaction sent by the principal")

    totals: dict[tuple[Asset, FlowDirection, str], int] = {}
    anomalies: list[Anomaly] = []

    def add(asset: Asset, direction: FlowDirection, counterparty: str, amount: int) -> None:
        key = (asset, direction, counterparty)
        totals[key] = totals.get(key, 0) + amount

    # --- ETH, from the call trace -------------------------------------------------
    eth_in = eth_out = 0
    for frame in effects.calls:
        if frame.depth > 0 and frame.caller == principal:
            # Reverted or not: either way the account ran code.
            _once(anomalies, Anomaly(code=AnomalyCode.PRINCIPAL_RUNS_CODE))
        if frame.reverted or frame.value == 0 or frame.target is None:
            continue
        if frame.caller == principal and frame.target != principal:
            eth_out += frame.value
            add(NATIVE, FlowDirection.OUT, frame.target, frame.value)
        elif frame.target == principal and frame.caller != principal:
            eth_in += frame.value
            add(NATIVE, FlowDirection.IN, frame.caller, frame.value)

    measured = sum(c.delta for c in effects.native_balance_changes if c.address == principal)
    if measured != eth_in - eth_out - effects.gas_cost:
        anomalies.append(Anomaly(code=AnomalyCode.NATIVE_BALANCE_UNRECONCILED))

    # --- tokens, from Transfer events, backed by state checks ----------------------
    moved_tokens: dict[str, None] = {}  # tokens the principal sent or received, ordered
    for transfer in effects.token_transfers:
        if transfer.sender == transfer.recipient:
            continue  # a transfer to oneself moves nothing
        amount = 1 if transfer.standard is TokenStandard.ERC721 else (transfer.amount or 0)
        if amount == 0:
            continue
        asset = Asset(token=transfer.token)
        if transfer.sender == principal:
            add(asset, FlowDirection.OUT, transfer.recipient, amount)
            moved_tokens[transfer.token] = None
        elif transfer.recipient == principal:
            add(asset, FlowDirection.IN, transfer.sender, amount)
            moved_tokens[transfer.token] = None

    for check in effects.token_state_checks:
        if not check.consistent:
            _once(anomalies, _inconsistent(check.token, check.owner))
    # A token the principal moved must have been checked for the principal.
    # (Whether that check passed is covered by the loop above.)
    checked = {
        c.token for c in effects.token_state_checks if c.kind == "balance" and c.owner == principal
    }
    for token in moved_tokens:
        if token not in checked:
            _once(anomalies, _inconsistent(token, principal))

    # --- logs we can't decode --------------------------------------------------------
    for log in effects.unrecognized_logs:
        if _mentions(log, principal) and not _informational(log):
            anomalies.append(
                Anomaly(
                    code=AnomalyCode.UNRECOGNIZED_EVENT,
                    contract=log.address,
                    log_index=log.log_index,
                )
            )

    # --- contracts created ---------------------------------------------------------
    for created in effects.contracts_created:
        _once(anomalies, Anomaly(code=AnomalyCode.CONTRACT_CREATED, contract=created))

    flows = tuple(
        Flow(asset=asset, direction=direction, counterparty=counterparty, amount=amount)
        for (asset, direction, counterparty), amount in totals.items()
    )
    return FlowAnalysis(flows=flows, anomalies=tuple(anomalies))


def _inconsistent(token: str, account: str) -> Anomaly:
    return Anomaly(code=AnomalyCode.INCONSISTENT_TOKEN_STATE, contract=token, account=account)


def _once(anomalies: list[Anomaly], anomaly: Anomaly) -> None:
    if anomaly not in anomalies:
        anomalies.append(anomaly)


def _informational(log: RawLog) -> bool:
    return bool(log.topics) and log.topics[0] in INFORMATIONAL_EVENTS


def _mentions(log: RawLog, principal: str) -> bool:
    """Whether the principal's address appears as a 32-byte word (left-padded
    with zeros, as the ABI encodes addresses) in any topic, or in the data
    at a 32-byte boundary. Topic 0 is included: an anonymous event's first
    topic is an argument, not a signature."""
    word = "0x" + "00" * 12 + principal[2:].lower()
    return word in log.topics or word in _words(log.data)


def _words(data: str) -> Iterable[str]:
    body = data[2:]
    size = 2 * WORD
    return ("0x" + body[i : i + size] for i in range(0, len(body) - size + 1, size))
