"""The three defenses the scenario suite compares. Each takes the agent's
signed bytes and either forwards them to the upstream or refuses.

- none: forward everything.
- rules: a rule-based guard, the kind wallet guardrails offer, derived
  mechanically from the same mandate the firewall gets (docs/v0.1-plan.md
  §1, pushback 2). Benchmark only: CLAUDE.md keeps a policy engine out of
  the product.
- firewall: the real `mandate-firewall serve`, with the mandate seeded.
"""

from collections import defaultdict
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from eth_utils import keccak, to_checksum_address

from mandate_firewall.decode.calldata import decode_calldata
from mandate_firewall.decode.transaction import TransactionDecodeError, decode_raw_transaction
from mandate_firewall.mandate.models import Mandate, SwapIntent, TransferIntent
from mandate_firewall.mandate.store import MandateStore
from mandate_firewall.models import CallKind, DecodedTransaction
from mandate_firewall.proxy.jsonrpc import TRANSACTION_REJECTED
from tests.integration.services import Proxy, Service, rpc_call, start_proxy, stop
from tests.mandates import seed_store

DEFENSES = ("none", "rules", "firewall")

Asset = str | None  # a token address, or None for native ETH
Spent = dict[Asset, int]


@dataclass(frozen=True)
class Submission:
    raw: str
    tx_hash: str
    blocked: bool  # the defense refused it (the upstream never saw it)
    reason: str | None  # the defense's reason, or the upstream's error
    response: dict[str, Any]

    @property
    def reached_chain(self) -> bool:
        """Forwarded and accepted by the upstream's pool."""
        return not self.blocked and "result" in self.response


class Defense(Protocol):
    name: str

    def submit(self, raw: str) -> Submission: ...

    def spent(self) -> Spent | None:
        """What the defense has charged so far, per asset (None: it doesn't count)."""
        ...


def tx_hash_of(raw: str) -> str:
    return "0x" + keccak(hexstr=raw).hex()


def forward(upstream: str, raw: str) -> Submission:
    response = rpc_call(upstream, "eth_sendRawTransaction", [raw])
    reason = response["error"]["message"] if "error" in response else None
    return Submission(raw, tx_hash_of(raw), False, reason, response)


# --- (a) no defense --------------------------------------------------------------


@dataclass
class NoDefense:
    upstream: str
    name: str = "none"

    def submit(self, raw: str) -> Submission:
        return forward(self.upstream, raw)

    def spent(self) -> Spent | None:
        return None


# --- (b) the rule-based guard ----------------------------------------------------


@dataclass(frozen=True)
class RuleConfig:
    """What a rule-based guard would be configured with for this mandate.

    allowlist: the only addresses a transaction may call, and the only ERC-20
        recipients and spenders: the mandate's recipients, its tokens and its
        venue contracts.
    limits: cumulative spend per asset, the mandate's budget for it. ETH
        `value` counts, and so do decoded transfer and transferFrom amounts.
        An approval may not exceed the limit either. No limit means zero.
    """

    allowlist: frozenset[str]
    limits: Mapping[Asset, int]

    @classmethod
    def from_mandate(cls, mandate: Mandate) -> "RuleConfig":
        allowlist: set[str] = set()
        limits: dict[Asset, int] = defaultdict(int)
        for intent in mandate.intents:
            if isinstance(intent, TransferIntent):
                allowlist.add(intent.recipient)
                if intent.asset.address is not None:
                    allowlist.add(intent.asset.address)
                limits[intent.asset.address] += intent.budget.max
            elif isinstance(intent, SwapIntent):
                allowlist.update(intent.venues)
                allowlist.update(a.address for a in (intent.sell, intent.buy) if a.address)
                limits[intent.sell.address] += intent.sell_budget.max
        return cls(frozenset(allowlist), dict(limits))


def decide(config: RuleConfig, spent: Mapping[Asset, int], tx: DecodedTransaction) -> tuple[
    str | None, Spent
]:  # fmt: skip
    """(reason to block, or None to allow; what it charges per asset).

    Sees only the transaction itself: who it calls, the ETH it sends, and
    the ERC-20 calls it can decode. A call it can't decode (a router's
    swap) passes if its target is allowlisted: that's what an allowlist is.
    """
    if tx.to is None:
        return "contract creation", {}
    if tx.to not in config.allowlist:
        return "target not allowlisted", {}
    charges: Spent = defaultdict(int)
    if tx.value:
        charges[None] += tx.value
    call = decode_calldata(bytes.fromhex(tx.data[2:]))
    if call.kind is CallKind.MALFORMED:
        return "malformed calldata", {}
    if call.kind is CallKind.KNOWN:
        args = {arg.name: arg.value for arg in call.args}
        party = args.get("to", args.get("spender"))
        if to_checksum_address(str(party)) not in config.allowlist:
            return "recipient or spender not allowlisted", {}
        amount = int(args["amount"])
        if call.signature == "approve(address,uint256)":
            if amount > config.limits.get(tx.to, 0):
                return "approval over the spend limit", {}
        else:  # transfer, transferFrom
            charges[tx.to] += amount
    for asset, amount in charges.items():
        if spent.get(asset, 0) + amount > config.limits.get(asset, 0):
            return "over the spend limit", {}
    return None, dict(charges)


@dataclass
class RuleGuard:
    upstream: str
    config: RuleConfig
    name: str = "rules"
    _spent: Spent = field(default_factory=lambda: defaultdict(int))
    _charged: set[str] = field(default_factory=set)

    def submit(self, raw: str) -> Submission:
        try:
            tx = decode_raw_transaction(raw)
        except TransactionDecodeError:
            return Submission(raw, tx_hash_of(raw), True, "undecodable", {})
        if tx.hash in self._charged:  # a retry of the same bytes: forward, don't charge
            return forward(self.upstream, raw)
        reason, charges = decide(self.config, self._spent, tx)
        if reason is not None:
            return Submission(raw, tx.hash, True, reason, {})
        for asset, amount in charges.items():
            self._spent[asset] += amount
        self._charged.add(tx.hash)
        return forward(self.upstream, raw)

    def spent(self) -> Spent | None:
        return {asset: amount for asset, amount in self._spent.items() if amount}


# --- (c) the mandate firewall ----------------------------------------------------


@dataclass
class Firewall:
    proxy: Proxy
    mandate_id: str
    mandate: Mandate
    name: str = "firewall"

    def submit(self, raw: str) -> Submission:
        """Blocked or not is the firewall's own decision, read from its audit
        record for this submission (written before anything is forwarded).
        Not from the error code: anvil refuses with -32003 too (a re-send
        of a mined transaction: "nonce too low"), which the firewall
        forwarded and the node then refused."""
        seen = len(self.proxy.audit_records())
        response = rpc_call(self.proxy.url, "eth_sendRawTransaction", [raw])
        error = response.get("error")
        tx_hash = tx_hash_of(raw)
        records = [r for r in self.proxy.audit_records()[seen:] if r["hash"] == tx_hash]
        if records:
            blocked = records[-1]["decision"] != "allow"
        else:  # refused before an audit record could be written
            blocked = error is not None and error["code"] == TRANSACTION_REJECTED
        return Submission(raw, tx_hash, blocked, error and error["message"], response)

    def spent(self) -> Spent | None:
        """What the store charged, per asset of each intent."""
        store = MandateStore(self.proxy.mandate_db)
        try:
            per_intent = store.get(self.mandate_id).spent
        finally:
            store.close()
        spent: Spent = defaultdict(int)
        for intent, amount in zip(self.mandate.intents, per_intent, strict=True):
            asset = intent.asset if isinstance(intent, TransferIntent) else intent.sell
            spent[asset.address] += amount
        return {asset: amount for asset, amount in spent.items() if amount}


@contextmanager
def running(
    name: str, upstream: Service, mandate: Mandate, workdir: Path, registry: Path
) -> Iterator[Defense]:
    """The defense called `name`, in front of `upstream`, for `mandate`."""
    if name == "none":
        yield NoDefense(upstream.url)
    elif name == "rules":
        yield RuleGuard(upstream.url, RuleConfig.from_mandate(mandate))
    elif name == "firewall":
        db = workdir / "state" / "mandates.db"
        (mandate_id,) = seed_store(db, mandate)
        proxy = start_proxy(upstream, workdir, mandate_db=db, registry=registry)
        try:
            yield Firewall(proxy, mandate_id, mandate)
        finally:
            stop(proxy)
    else:
        raise ValueError(f"unknown defense {name!r}")
