"""Token and venue registry: the shipped Base Sepolia file and strict loading."""

import copy
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from mandate_firewall.mandate.registry import (
    MAX_REGISTRY_BYTES,
    RegistryError,
    UnknownSymbolError,
    UnknownVenueError,
    load_registry,
    parse_registry,
)

BASE_SEPOLIA = 84532
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
WETH = "0x4200000000000000000000000000000000000006"
SWAP_ROUTER_02 = "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"

# Test-only chain and addresses (anvil's default deployer's first contracts).
CHAIN = 31337
TOKEN_A = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
TOKEN_B = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
ROUTER = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
SOURCE = "https://example.org/addresses"

VALID: dict[str, Any] = {
    "schema_version": 1,
    "chain_id": CHAIN,
    "chain_name": "Local test chain",
    "native": {"symbol": "ETH", "decimals": 18},
    "tokens": [
        {"symbol": "AAA", "address": TOKEN_A, "decimals": 6, "source": SOURCE},
        {"symbol": "BBB", "address": TOKEN_B, "decimals": 18, "source": SOURCE},
    ],
    "venues": [
        {
            "name": "testswap",
            "contracts": [{"label": "Router", "address": ROUTER, "source": SOURCE}],
        }
    ],
}


def encode(data: dict[str, Any]) -> bytes:
    return json.dumps(data).encode()


def changed(path: tuple[Any, ...], value: Any) -> bytes:
    """VALID with the value at `path` replaced."""
    data = copy.deepcopy(VALID)
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return encode(data)


# --- the shipped Base Sepolia registry ----------------------------------------------


def test_shipped_registry_contents() -> None:
    """Pinned here so a change to the file shows up in review twice."""
    registry = load_registry(BASE_SEPOLIA)
    assert registry.chain_name == "Base Sepolia"
    assert registry.asset("USDC").address == USDC
    assert registry.asset("USDC").decimals == 6
    assert registry.asset("WETH").address == WETH
    assert registry.asset("WETH").decimals == 18
    assert registry.asset("ETH").address is None
    assert registry.venue("uniswap") == (SWAP_ROUTER_02,)
    assert len(registry.tokens) == 2
    assert len(registry.venues) == 1


def test_shipped_sources_are_issuer_docs() -> None:
    """Every address names where it was checked: the issuer's own docs."""
    issuers = {
        USDC: "developers.circle.com",  # Circle issues USDC
        WETH: "docs.base.org",  # an OP Stack predeploy on Base
        SWAP_ROUTER_02: "docs.uniswap.org",
    }
    registry = load_registry(BASE_SEPOLIA)
    entries = list(registry.tokens) + [c for v in registry.venues for c in v.contracts]
    assert {e.address for e in entries} == set(issuers)
    for entry in entries:
        assert urlsplit(entry.source.split()[0]).hostname == issuers[entry.address]
        assert "checked 2026-10-09" in entry.source


def test_universal_router_and_permit2_are_not_venues() -> None:
    """Their approvals go through Permit2, which effects can't follow yet."""
    registry = load_registry(BASE_SEPOLIA)
    venue_addresses = {c.address for v in registry.venues for c in v.contracts}
    assert "0x492E6456D9528771018DeB9E87ef7750EF184104" not in venue_addresses
    assert "0x000000000022D473030F116dDEE9F6B43aC78BA3" not in venue_addresses


# --- lookups --------------------------------------------------------------------------


def test_lookups() -> None:
    registry = parse_registry(encode(VALID), CHAIN)
    assert registry.asset("aaa") == registry.asset("AAA")
    assert registry.asset("AAA").chain_id == CHAIN
    assert registry.asset("eth") == registry.native_asset()
    assert registry.venue("TestSwap") == (ROUTER,)
    assert registry.symbol_for(TOKEN_B.lower()) == "BBB"
    assert registry.symbol_for(None) == "ETH"
    assert registry.symbol_for(ROUTER) is None  # a venue isn't a token


@pytest.mark.parametrize("symbol", ["CCC", "", "AAA ", "ААА"])  # the last is Cyrillic
def test_unknown_symbol(symbol: str) -> None:
    with pytest.raises(UnknownSymbolError):
        parse_registry(encode(VALID), CHAIN).asset(symbol)


def test_unknown_venue() -> None:
    with pytest.raises(UnknownVenueError):
        parse_registry(encode(VALID), CHAIN).venue("sushiswap")


# --- loading ---------------------------------------------------------------------------


def test_unknown_chain() -> None:
    with pytest.raises(RegistryError, match="no registry for chain 1"):
        load_registry(1)


def test_operator_directory_replaces_the_shipped_file(tmp_path: Path) -> None:
    (tmp_path / f"{CHAIN}.json").write_bytes(encode(VALID))
    assert load_registry(CHAIN, tmp_path).venue("testswap") == (ROUTER,)
    # No file for Base Sepolia in the operator's directory: an error, not a
    # silent fallback to the shipped file.
    with pytest.raises(RegistryError, match="no registry"):
        load_registry(BASE_SEPOLIA, tmp_path)


def test_file_must_match_its_chain(tmp_path: Path) -> None:
    (tmp_path / "1.json").write_bytes(encode(VALID))
    with pytest.raises(RegistryError, match="says chain 31337"):
        load_registry(1, tmp_path)


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        (("tokens", 1, "symbol"), "aaa", "symbol may appear only once"),  # ignoring case
        (("tokens", 1, "symbol"), "eth", "symbol may appear only once"),  # the native symbol
        (("tokens", 1, "address"), TOKEN_A, "address may appear only once"),  # two tokens
        (("tokens", 1, "address"), ROUTER, "address may appear only once"),  # token and venue
        (("tokens", 0, "address"), TOKEN_A.lower(), "EIP-55"),  # no checksum
        (("tokens", 0, "address"), "0x5fbDB2315678afecb367f032d93F642f64180aa3", "EIP-55"),
        (("tokens", 0, "address"), "0x" + "00" * 20, "zero address"),
        (("tokens", 0, "address"), "0x1234", "tokens.0.address"),
        (("tokens", 0, "symbol"), "ААА", "tokens.0.symbol"),  # Cyrillic lookalike
        (("tokens", 0, "symbol"), "A A", "tokens.0.symbol"),
        (("tokens", 0, "symbol"), "TOOLONGSYMBOL", "tokens.0.symbol"),
        (("tokens", 0, "decimals"), True, "tokens.0.decimals"),
        (("tokens", 0, "decimals"), 78, "tokens.0.decimals"),
        (("tokens", 0, "source"), "http://example.org", "tokens.0.source"),  # not https
        (("tokens", 0, "source"), "", "tokens.0.source"),
        (("tokens", 0, "name"), "Token A", "tokens.0.name"),  # unknown field
        (("venues", 0, "name"), "Test Swap", "venues.0.name"),
        (("venues", 0, "contracts"), [], "venues.0.contracts"),
        (("venues", 0, "contracts", 0, "address"), ROUTER.lower(), "EIP-55"),
        (("schema_version",), 2, "schema_version"),
        (("chain_id",), "31337", "chain_id"),
    ],
)
def test_invalid_entries_are_rejected(path: tuple[Any, ...], value: Any, reason: str) -> None:
    with pytest.raises(RegistryError, match=re.escape(reason)):
        parse_registry(changed(path, value), CHAIN)


def test_missing_source_is_rejected() -> None:
    data = copy.deepcopy(VALID)
    del data["tokens"][0]["source"]
    with pytest.raises(RegistryError, match="source"):
        parse_registry(encode(data), CHAIN)


def test_duplicate_venue_names_are_rejected() -> None:
    data = copy.deepcopy(VALID)
    second = copy.deepcopy(data["venues"][0])
    second["contracts"][0]["address"] = TOKEN_B
    data["tokens"].pop()
    data["venues"].append(second)
    with pytest.raises(RegistryError, match="venue name"):
        parse_registry(encode(data), CHAIN)


def test_duplicate_json_keys_are_rejected() -> None:
    text = encode(VALID).replace(
        f'"address": "{TOKEN_A}"'.encode(),
        f'"address": "{TOKEN_B}", "address": "{TOKEN_A}"'.encode(),
    )
    with pytest.raises(RegistryError, match="duplicate key"):
        parse_registry(text, CHAIN)


@pytest.mark.parametrize("data", [b"", b"not json", b"\xff\xfe", b"[]", b"{}"])
def test_malformed_files_are_rejected(data: bytes) -> None:
    with pytest.raises(RegistryError):
        parse_registry(data, CHAIN)


def test_oversized_file_is_rejected() -> None:
    with pytest.raises(RegistryError, match="too large"):
        parse_registry(b" " * (MAX_REGISTRY_BYTES + 1), CHAIN)
