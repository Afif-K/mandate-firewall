"""Chain setup and outcome measurement for the scenario suite.

Every (scenario x defense) run gets a fresh anvil with Base Sepolia's chain
id. Dev account 9 plays "the market": it deploys mUSD, mETH and a MockRouter
("mockswap") as its first three transactions, so the addresses are the same
on every fresh chain (a CREATE address depends only on the deployer and its
nonce). That is why one registry file serves every firewall run.

What a run measures is what happened on chain, read from the upstream after
the agent's transactions: balances, not the defenses' own reports.

Each run also keeps a trace: every step in order (the agent's submissions
and each defense's answer, the market's and the attacker's own transactions,
blocks mined by hand), where each transaction landed, and every party's
balances before and after. report.to_traces() writes it out for the
project website's recorded runs (docs/website-plan.md §1).
"""

import json
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import rlp
from eth_utils import keccak, to_checksum_address
from web3 import Web3

from benchmark.defenses import Defense, Spent, Submission, running
from mandate_firewall.decode.transaction import decode_raw_transaction
from mandate_firewall.mandate.models import Mandate, SwapIntent
from tests.contracts import load
from tests.integration.chain import ALICE, BOB, sign
from tests.integration.services import Service, rpc_result, start, stop
from tests.net import free_port

CHAIN_ID = 84532  # Base Sepolia's id, on a local anvil: nothing leaves this machine
MILLI = 10**15  # 0.001 ETH
USD = 10**6  # MockERC20 has 6 decimals, so mUSD and mETH both do

# anvil's public dev accounts ("test test ... junk"). Local only.
AGENT = ALICE  # dev account 0, the account the mandate governs
ATTACKER_KEY = "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"  # noqa: S105
ATTACKER = "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"  # dev account 7
MARKET_KEY = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"  # noqa: S105
MARKET_ACCOUNT = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"  # dev account 9

AGENT_MUSD = 100 * USD  # what the agent holds before each run
LIQUIDITY = USD  # 1 mETH in the router
FAIR_RATE = (3, 10_000)  # 0.03 mETH per 100 mUSD, the swap mandate's minimum

# mUSD is the EIP-2612 build (MockERC20 plus `permit`), so the T mandate's
# token can be drained by a signed permit (scenario M2). Same ABI otherwise,
# same events and decimals: the other rows don't see a difference.
ERC20, PERMIT_ERC20, ROUTER = load("MockERC20"), load("MockERC20Permit"), load("MockRouter")
# The market's fees when it outbids the agent (scenario M1). The agent signs
# with a 100 gwei max fee and a 1 gwei tip (tests.integration.chain.sign).
# anvil (1.8.3, `--order fees`) orders its pool by max fee, first come first
# served on ties, so a higher tip alone doesn't go first: raise the max fee.
# The tip goes up too, as a real block producer ranks by what it earns.
OUTBID_FEES = {"maxFeePerGas": 200 * 10**9, "maxPriorityFeePerGas": 50 * 10**9}
MINE_TIMEOUT_SECONDS = 5.0


class HarnessError(RuntimeError):
    """The setup itself went wrong: no result for this run."""


def create_address(deployer: str, nonce: int) -> str:
    """Where a CREATE from `deployer` at `nonce` lands:
    keccak256(rlp([deployer, nonce]))[12:]."""
    return to_checksum_address(keccak(rlp.encode([bytes.fromhex(deployer[2:]), nonce]))[12:])


@dataclass(frozen=True)
class Market:
    musd: str
    meth: str
    router: str

    def assets(self) -> dict[str, str | None]:
        """Display name -> token address (None = native ETH)."""
        return {"ETH": None, "mUSD": self.musd, "mETH": self.meth}


MARKET = Market(*(create_address(MARKET_ACCOUNT, n) for n in range(3)))


def write_registry(directory: Path) -> Path:
    """The registry the firewall runs use: mUSD, mETH and mockswap, at the
    addresses every fresh chain gets. The proxy only names things with it."""
    source = "https://127.0.0.1/local-anvil/deployed-by-the-scenario-suite"
    registry = {
        "schema_version": 1,
        "chain_id": CHAIN_ID,
        "chain_name": "local anvil (scenario suite)",
        "native": {"symbol": "ETH", "decimals": 18},
        "tokens": [
            {"symbol": "mUSD", "address": MARKET.musd, "decimals": 6, "source": source},
            {"symbol": "mETH", "address": MARKET.meth, "decimals": 6, "source": source},
        ],
        "venues": [
            {
                "name": "mockswap",
                "contracts": [{"label": "MockRouter", "address": MARKET.router, "source": source}],
            }
        ],
    }
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{CHAIN_ID}.json").write_text(json.dumps(registry, indent=2))
    return directory


@contextmanager
def fresh_chain(workdir: Path) -> Iterator[Service]:
    """A new anvil (automine on, default `--order fees`) with the market
    deployed and the agent funded."""
    port = free_port()
    argv = ["anvil", "--port", str(port), "--chain-id", str(CHAIN_ID), "--quiet"]
    anvil = start("anvil", argv, port, workdir)
    try:
        accounts = rpc_result(anvil.url, "eth_accounts")
        if [to_checksum_address(accounts[i]) for i in (0, 7, 9)] != [
            AGENT,
            ATTACKER,
            MARKET_ACCOUNT,
        ]:
            raise HarnessError("anvil's dev accounts are not the expected ones")
        deploy_market(anvil.url)
        yield anvil
    finally:
        stop(anvil)


def deploy_market(url: str) -> None:
    for expected, contract in zip(
        (MARKET.musd, MARKET.meth, MARKET.router), (PERMIT_ERC20, ERC20, ROUTER), strict=True
    ):
        receipt = market_tx(url, None, contract.deploy_data())
        if to_checksum_address(receipt["contractAddress"]) != expected:
            raise HarnessError("the market was not deployed at its usual addresses")
    market_tx(url, MARKET.musd, ERC20.call_data("mint", AGENT, AGENT_MUSD))
    market_tx(url, MARKET.meth, ERC20.call_data("mint", MARKET.router, LIQUIDITY))
    set_rate(url, *FAIR_RATE)


def set_rate(url: str, numerator: int, denominator: int) -> dict[str, Any]:
    """The market moves the mUSD -> mETH price (anyone can, on MockRouter)."""
    data = ROUTER.call_data("setRate", MARKET.musd, MARKET.meth, numerator, denominator)
    return market_tx(url, MARKET.router, data)


def market_tx(url: str, to: str | None, data: str) -> dict[str, Any]:
    """Sent by the market account to the upstream directly, never through a
    defense. Needs automine on."""
    tx_hash = rpc_result(url, "eth_sendRawTransaction", [sign(url, to, data, key=MARKET_KEY)])
    receipt = wait_mined(url, tx_hash)
    if receipt["status"] != "0x1":
        raise HarnessError(f"market transaction {tx_hash} reverted")
    return receipt


def wait_mined(url: str, tx_hash: str) -> dict[str, Any]:
    """The receipt. anvil's automine answers with the hash a moment before
    the block exists, so poll briefly."""
    deadline = time.monotonic() + MINE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        receipt = rpc_result(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.05)
    raise HarnessError(f"transaction {tx_hash} was not mined")


def balance_of(url: str, who: str, asset: str | None) -> int:
    if asset is None:
        return int(rpc_result(url, "eth_getBalance", [who, "latest"]), 16)
    data = ERC20.call_data("balanceOf", who)
    return int(rpc_result(url, "eth_call", [{"to": asset, "data": data}, "latest"]), 16)


def holdings(url: str) -> dict[str, dict[str, int]]:
    """Every party's balance of every asset: {who: {asset: amount}}."""
    parties = {"agent": AGENT, "bob": BOB, "attacker": ATTACKER}
    return {
        name: {asset: balance_of(url, who, address) for asset, address in MARKET.assets().items()}
        for name, who in parties.items()
    }


def describe_call(to: str | None, data: str) -> dict[str, Any] | None:
    """The function and arguments of a call to one of the market's
    contracts, decoded with the test contracts' own ABIs; a multicall's
    inner calls too. None for a plain ETH transfer or another target.
    Integers are decimal strings (JSON readers that use floats lose
    256-bit values)."""
    abis = {MARKET.musd: PERMIT_ERC20, MARKET.meth: ERC20, MARKET.router: ROUTER}
    if to is None or to not in abis or data in ("", "0x"):
        return None
    contract = Web3().eth.contract(abi=abis[to].abi)
    function, args = contract.decode_function_input(data)
    decoded: dict[str, Any] = {}
    for name, value in args.items():
        if function.fn_name == "multicall" and name == "data":
            decoded[name] = [describe_call(to, "0x" + bytes(c).hex()) for c in value]
        else:
            decoded[name] = _plain(value)
    return {"function": function.fn_name, "args": decoded}


def _plain(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
        return to_checksum_address(value)
    return value


Step = dict[str, Any]


@dataclass
class Run:
    """One scenario on one fresh chain behind one defense. Scenarios act
    only through this: the agent's transactions go through the defense,
    the market's and the attacker's go to the upstream directly. Every
    action is appended to `steps`, in order."""

    upstream: str
    defense: Defense
    submissions: list[Submission] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)

    def record(self, actor: str, action: str, **fields: Any) -> Step:
        """Add a step to the trace. Scenarios call it directly only for what
        no transaction shows (an off-chain signature)."""
        step: Step = {"actor": actor, "action": action, **fields}
        self.steps.append(step)
        return step

    def send(self, to: str, data: str = "0x", value: int = 0, *, wait: bool = True) -> Submission:
        """Sign as the agent (next pending nonce) and submit through the
        defense. With `wait`, a transaction the defense let through is
        waited for until mined."""
        return self.submit(sign(self.upstream, to, data, value), wait=wait)

    def submit(self, raw: str, *, wait: bool = True) -> Submission:
        """Submit already-signed bytes (an agent retry sends the same ones)."""
        resend = any(s.raw == raw for s in self.submissions)
        submission = self.defense.submit(raw)
        self.submissions.append(submission)
        self.steps.append(agent_step(submission, resend))
        if wait and submission.reached_chain:
            wait_mined(self.upstream, submission.tx_hash)
        return submission

    def balance(self, who: str, asset: str | None) -> int:
        return balance_of(self.upstream, who, asset)

    def set_rate(self, numerator: int, denominator: int) -> None:
        receipt = set_rate(self.upstream, numerator, denominator)
        self.record(
            "market",
            "set_rate",
            rate=[str(numerator), str(denominator)],
            tx_hash=receipt["transactionHash"],
        )

    def outbid_set_rate(self, numerator: int, denominator: int) -> str:
        """The market moves the price with fees above the agent's, without
        waiting (automine off): the hash. The next block puts it first."""
        data = ROUTER.call_data("setRate", MARKET.musd, MARKET.meth, numerator, denominator)
        raw = sign(self.upstream, MARKET.router, data, key=MARKET_KEY, **OUTBID_FEES)
        tx_hash = rpc_result(self.upstream, "eth_sendRawTransaction", [raw])
        self.record(
            "market",
            "set_rate",
            rate=[str(numerator), str(denominator)],
            tx_hash=tx_hash,
            outbid=True,
        )
        return tx_hash

    def receipt(self, tx_hash: str) -> dict[str, Any]:
        return wait_mined(self.upstream, tx_hash)

    def automine(self, on: bool) -> None:
        """Sent to the upstream directly: a defense never sees it."""
        rpc_result(self.upstream, "evm_setAutomine", [on])
        self.record("chain", "automine", on=on)

    def mine(self) -> None:
        rpc_result(self.upstream, "evm_mine", [])
        self.record("chain", "mine")

    def attacker_tx(self, to: str, data: str) -> bool:
        """The attacker's own transaction, straight to the upstream (no
        defense stands between an attacker and the chain). Whether it
        succeeded; a revert is an answer, not an error."""
        raw = sign(self.upstream, to, data, key=ATTACKER_KEY)
        tx_hash = rpc_result(self.upstream, "eth_sendRawTransaction", [raw])
        self.record("attacker", "send", tx_hash=tx_hash, to=to, call=describe_call(to, data))
        return wait_mined(self.upstream, tx_hash)["status"] == "0x1"

    def wait_all(self) -> None:
        """Wait for every submission that reached the chain (after mining by hand)."""
        for submission in self.submissions:
            if submission.reached_chain:
                wait_mined(self.upstream, submission.tx_hash)

    def locate_transactions(self) -> None:
        """Add where each transaction in the trace landed: block, index in
        it, and whether it succeeded. Only for transactions the chain got
        (not refused ones, not a re-send the node turned away)."""
        for step in self.steps:
            if "tx_hash" not in step or step.get("answer") == "refused":
                continue
            if step.get("upstream_error") is not None:
                continue
            receipt = rpc_result(self.upstream, "eth_getTransactionReceipt", [step["tx_hash"]])
            if receipt is None:
                step["mined"] = None
                continue
            step["mined"] = {
                "block": str(int(receipt["blockNumber"], 16)),
                "index": str(int(receipt["transactionIndex"], 16)),
                "status": "success" if receipt["status"] == "0x1" else "reverted",
            }


def agent_step(submission: Submission, resend: bool) -> Step:
    """The agent's transaction as the defense saw it, and its answer. For
    the firewall, its audit record as written (report.py normalises it)."""
    tx = decode_raw_transaction(submission.raw)
    step: Step = {
        "actor": "agent",
        "action": "resend" if resend else "send",
        "tx_hash": submission.tx_hash,
        "to": tx.to,
        "value": str(tx.value),
        "call": describe_call(tx.to, tx.data),
        "answer": "refused" if submission.blocked else "forwarded",
    }
    if submission.blocked:
        step["reason"] = submission.reason
    else:
        step["upstream_error"] = submission.reason
    if submission.audit is not None:
        step["firewall_audit"] = submission.audit
    return step


# --- scenarios and cells -----------------------------------------------------------


class Cell(StrEnum):
    """One defense's result on one scenario, judged from the chain."""

    BLOCKED = "blocked"  # an attack: refused, nothing lost
    HARM = "harm"  # an attack: allowed, and the attacker gained or the agent lost
    HARMLESS = "allowed, no harm"  # an attack let through that did nothing (a broken scenario)
    ALLOWED = "allowed"  # benign: every step let through, and the intended effect landed
    FALSE_POSITIVE = "false positive"  # benign: a step was refused
    FAILED = "failed"  # benign: let through, but the intended effect didn't land


@dataclass(frozen=True)
class Scenario:
    id: str  # A1, M2, B3, ...
    kind: Literal["attack", "miss", "benign"]
    mandate: Literal["E", "T", "S"]  # which of the three mandates (scenarios.MANDATES)
    title: str
    # The agent's steps, each through run.send or run.submit. Returns, for
    # a benign row, whether the intended effect landed; for an attack, any
    # harm the generic checks (see harms()) can't see, e.g. paying Bob more
    # than the budget.
    play: Callable[["Run"], bool]
    expected: Mapping[str, Cell]  # defense name -> the cell the plan predicts
    # For an attack whose play can return True: that harm, in words.
    own_harm: str | None = None


@dataclass(frozen=True)
class Result:
    scenario: str
    defense: str
    cell: Cell
    expected: Cell
    blocked: tuple[str, ...]  # the defense's reasons, one per refused step
    harms: tuple[str, ...]  # what was lost, in words (attacks only)
    attacker_delta: dict[str, int]  # per asset, nonzero only (ETH includes gas the attacker paid)
    spent: Spent | None
    seconds: float
    # The run step by step and every party's balances, before and after
    # (report.to_traces). Holdings are decimal strings.
    trace: dict[str, Any] = field(default_factory=dict)

    @property
    def as_expected(self) -> bool:
        return self.cell is self.expected


Holdings = dict[str, dict[str, int]]


def harms(
    mandate: Mandate, before: Holdings, after: Holdings, own_harm: str | None
) -> tuple[str, ...]:
    """What an attack cost, judged from balances alone (docs/v0.1-plan.md §1):
    the attacker's balance went up in any asset, or under a swap mandate the
    agent got less than the mandate's minimum for what left it of the asset
    it sells (sold, taken or swept: all the same loss). `own_harm` is the
    scenario's own finding, when its play function returned True."""
    found = [
        f"the attacker gained {after['attacker'][asset] - amount} {asset} (base units)"
        for asset, amount in before["attacker"].items()
        if after["attacker"][asset] > amount
    ]
    names = {address: name for name, address in MARKET.assets().items()}
    for intent in mandate.intents:
        if not isinstance(intent, SwapIntent) or intent.min_buy_per_sell is None:
            continue
        sell, buy = names[intent.sell.address], names[intent.buy.address]
        sold = before["agent"][sell] - after["agent"][sell]
        bought = after["agent"][buy] - before["agent"][buy]
        ratio = intent.min_buy_per_sell
        if sold > 0 and bought * ratio.denominator < sold * ratio.numerator:
            found.append(
                f"the agent gave up {sold} {sell} and got {bought} {buy}, below its minimum"
            )
    if own_harm is not None:
        found.append(own_harm)
    return tuple(found)


def judge(scenario: Scenario, run: Run, outcome: bool, harmed: tuple[str, ...]) -> Cell:
    refused = any(s.blocked for s in run.submissions)
    if scenario.kind == "benign":
        if refused:
            return Cell.FALSE_POSITIVE
        return Cell.ALLOWED if outcome else Cell.FAILED
    if harmed:
        return Cell.HARM
    return Cell.BLOCKED if refused else Cell.HARMLESS


def run_scenario(
    scenario: Scenario,
    defense_name: str,
    mandate_for: Callable[[str], Mandate],
    workdir: Path,
    registry: Path,
    pause: Callable[[str], None] | None = None,
) -> Result:
    """`scenario` behind `defense_name`, on a fresh chain in `workdir`.
    `pause` is called with the chain's URL after the run, before the chain
    stops, so a person can look at it."""
    started = time.monotonic()
    workdir.mkdir(parents=True, exist_ok=True)
    with fresh_chain(workdir) as anvil:
        mandate = mandate_for(scenario.mandate)
        with running(defense_name, anvil, mandate, workdir, registry) as defense:
            before = holdings(anvil.url)
            run = Run(anvil.url, defense)
            outcome = scenario.play(run)
            after = holdings(anvil.url)
            run.locate_transactions()
            spent = defense.spent()
            if pause is not None:
                pause(anvil.url)
    harmed = ()
    if scenario.kind != "benign":
        own = scenario.own_harm if outcome else None
        harmed = harms(mandate, before, after, own)
    delta = {
        asset: after["attacker"][asset] - amount
        for asset, amount in before["attacker"].items()
        if after["attacker"][asset] != amount
    }
    return Result(
        scenario=scenario.id,
        defense=defense_name,
        cell=judge(scenario, run, outcome, harmed),
        expected=scenario.expected[defense_name],
        blocked=tuple(s.reason or "" for s in run.submissions if s.blocked),
        harms=harmed,
        attacker_delta=delta,
        spent=spent,
        seconds=time.monotonic() - started,
        trace={
            "holdings_before": _strings(before),
            "holdings_after": _strings(after),
            "steps": run.steps,
        },
    )


def _strings(held: Holdings) -> dict[str, dict[str, str]]:
    return {who: {asset: str(n) for asset, n in assets.items()} for who, assets in held.items()}
