"""The trusted token and venue registry: the only way names become addresses.

When the user says "USDC" or "on Uniswap", the address comes from here, never
from the LLM and never from a token contract's own name() or symbol(), which
its deployer chooses. M4 uses the same file the other way round, to show
canonical names for addresses in effects. See docs/m3-plan.md §2b.

One JSON file per chain. The firewall ships one for Base Sepolia
(registry_data/<chain_id>.json). An operator can point to a directory of their
own files instead; such a file replaces the shipped one for its chain
entirely, because merging two lists would make it unclear which entry wins.

Loading is strict, and a file that fails any check isn't used at all: it is
curated by hand, and a typo in it becomes a wrong mandate.
"""

import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any, Self

from eth_utils import to_checksum_address
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    Strict,
    ValidationError,
    model_validator,
)

from mandate_firewall.mandate.models import AssetRef, ChainId
from mandate_firewall.models import Address

MAX_REGISTRY_BYTES = 1_000_000
ZERO_ADDRESS = "0x" + "00" * 20


class RegistryError(Exception):
    """The registry file is missing or invalid."""


class UnknownSymbolError(LookupError):
    """No token with this symbol on this chain."""


class UnknownVenueError(LookupError):
    """No venue with this name on this chain."""


def _exact_checksum(value: Any) -> Any:
    """The file must spell every address with its EIP-55 checksum. A lowercase
    address carries no checksum, so a typo in it would go unnoticed. Runs on
    the raw input: Address itself checksums lowercase input, which would hide
    exactly the spelling we want to refuse."""
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        if value != to_checksum_address(value):
            raise ValueError("registry addresses must be written with their EIP-55 checksum")
        if value == ZERO_ADDRESS:
            raise ValueError("the zero address is not a token or a venue")
    return value  # anything else is left for Address to reject


RegistryAddress = Annotated[Address, BeforeValidator(_exact_checksum)]
# ASCII only: a Cyrillic "С" in "USDС" looks like USDC and is a different string.
Symbol = Annotated[str, Field(pattern=r"^[A-Za-z0-9.]{1,11}$")]
VenueName = Annotated[str, Field(pattern=r"^[a-z0-9-]{1,32}$")]
Decimals = Annotated[int, Strict(), Field(ge=0, le=77)]
# Where the address was checked: the issuer's own documentation, as a URL.
Source = Annotated[str, Field(pattern=r"^https://\S+", max_length=500)]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class NativeEntry(_Strict):
    symbol: Symbol
    decimals: Decimals


class TokenEntry(_Strict):
    symbol: Symbol
    address: RegistryAddress
    decimals: Decimals
    source: Source


class VenueContract(_Strict):
    label: str = Field(min_length=1, max_length=100)
    address: RegistryAddress
    source: Source


class VenueEntry(_Strict):
    name: VenueName
    contracts: tuple[VenueContract, ...] = Field(min_length=1)


class Registry(_Strict):
    schema_version: Annotated[int, Strict(), Field(ge=1, le=1)]
    chain_id: ChainId
    chain_name: str = Field(min_length=1, max_length=100)
    native: NativeEntry
    tokens: tuple[TokenEntry, ...]
    venues: tuple[VenueEntry, ...]
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _unique(self) -> Self:
        # Symbols are matched without case, so they must be unique without
        # case: "USDC" and "usdc" can't be two tokens. One symbol, one address
        # means the compiler never has to choose.
        symbols = [self.native.symbol.upper()] + [t.symbol.upper() for t in self.tokens]
        if len(set(symbols)) != len(symbols):
            raise ValueError("each symbol may appear only once (ignoring case)")
        names = [v.name for v in self.venues]
        if len(set(names)) != len(names):
            raise ValueError("each venue name may appear only once")
        # An address is one thing: a token, or one venue's contract.
        addresses = [t.address for t in self.tokens] + [
            c.address for v in self.venues for c in v.contracts
        ]
        if len(set(addresses)) != len(addresses):
            raise ValueError("each address may appear only once")
        return self

    def native_asset(self) -> AssetRef:
        return AssetRef(chain_id=self.chain_id, address=None, decimals=self.native.decimals)

    def asset(self, symbol: str) -> AssetRef:
        """The asset for a symbol, ignoring case. The native symbol ("ETH")
        means native ETH, not a wrapped token."""
        key = symbol.upper()
        if key == self.native.symbol.upper():
            return self.native_asset()
        for token in self.tokens:
            if token.symbol.upper() == key:
                return AssetRef(
                    chain_id=self.chain_id, address=token.address, decimals=token.decimals
                )
        raise UnknownSymbolError(f"no token with that symbol on chain {self.chain_id}")

    def venue(self, name: str) -> tuple[str, ...]:
        """The contract addresses of a venue, by its lowercase name."""
        for venue in self.venues:
            if venue.name == name.lower():
                return tuple(c.address for c in venue.contracts)
        raise UnknownVenueError(f"no venue with that name on chain {self.chain_id}")

    def symbol_for(self, address: str | None) -> str | None:
        """The canonical symbol for an asset address (None = native), or None
        if the address isn't a registered token."""
        if address is None:
            return self.native.symbol
        checksummed = to_checksum_address(address)
        for token in self.tokens:
            if token.address == checksummed:
                return token.symbol
        return None

    def decimals_for(self, address: str | None) -> int | None:
        """The decimals for an asset address (None = native), or None if the
        address isn't a registered token. Never a token's own decimals():
        its deployer chooses that too, and a wrong one misstates amounts."""
        if address is None:
            return self.native.decimals
        checksummed = to_checksum_address(address)
        for token in self.tokens:
            if token.address == checksummed:
                return token.decimals
        return None


def load_registry(chain_id: int, directory: Path | None = None) -> Registry:
    """The registry for a chain: from `directory` if given, else the shipped
    one. Raises RegistryError if there's no file for the chain or it's invalid.
    An operator directory without a file for the chain is an error, not a
    reason to fall back to the shipped file."""
    name = f"{chain_id}.json"
    try:
        if directory is not None:
            data = (directory / name).read_bytes()
        else:
            data = files("mandate_firewall.mandate").joinpath("registry_data", name).read_bytes()
    except FileNotFoundError:
        raise RegistryError(f"no registry for chain {chain_id}") from None
    except OSError as exc:
        raise RegistryError(f"can't read the registry for chain {chain_id}: {exc}") from None
    return parse_registry(data, chain_id)


def parse_registry(data: bytes, chain_id: int) -> Registry:
    if len(data) > MAX_REGISTRY_BYTES:
        raise RegistryError("registry file is too large")
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        registry = Registry.model_validate(raw)
    except ValueError as exc:  # also UnicodeDecodeError, JSONDecodeError, ValidationError
        raise RegistryError(f"invalid registry for chain {chain_id}: {_describe(exc)}") from None
    if registry.chain_id != chain_id:
        raise RegistryError(f"the file for chain {chain_id} says chain {registry.chain_id}")
    return registry


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """json.loads keeps the last of two equal keys, so a file with two
    "address" entries would silently use the second."""
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key in registry JSON")
    return dict(pairs)


def _describe(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        # Where and what, so the operator can fix the file. The file is
        # theirs and holds no secrets, so the location is safe to show.
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"])
        return f"{location}: {first['msg']}" if location else first["msg"]
    return str(exc) if isinstance(exc, ValueError) else type(exc).__name__
