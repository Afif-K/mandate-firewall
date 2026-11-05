"""Capture settings: the mandate store, who mandates are for, and the LLM.

Separate from config.Settings on purpose: the proxy reads that class and
must never hold the key. The key comes from the environment or .env, never
from a command-line flag (command lines are visible to other users in `ps`).
"""

import ipaddress
import re
from pathlib import Path
from typing import Self
from urllib.parse import urlsplit

from eth_utils import to_checksum_address
from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_MODEL = "claude-opus-5-5"

# Printable ASCII, no spaces: what an API key looks like. Anything else (a
# pasted newline, say) would end up in an HTTP header.
_KEY = re.compile(r"[\x21-\x7e]{1,500}")
_MODEL = re.compile(r"[a-z0-9][a-z0-9.\-]{0,99}")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


class CaptureSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", frozen=True)

    # None means the LLM path is unavailable; the structured path still works.
    llm_api_key: SecretStr | None = None
    llm_model: str = DEFAULT_MODEL
    llm_base_url: AnyHttpUrl = AnyHttpUrl("https://api.anthropic.com")
    llm_timeout_seconds: float = Field(default=120.0, gt=0, le=600)

    # The SQLite mandate store. The proxy will read the same file (commit 7).
    mandate_db_path: Path = Path("state/mandates.db")
    # The agent accounts mandates may be created for, comma-separated, each
    # written with its EIP-55 checksum. Nothing else can be a principal.
    mandate_principals: str = ""
    # The chain mandates are for; picks the registry file.
    mandate_chain_id: int = Field(default=84532, gt=0)
    # A directory with your own <chain_id>.json registry, replacing the shipped one.
    registry_path: Path | None = None
    # A JSON object of name -> checksummed address, for recipients you pay
    # often ("send 50 USDC to Bob"). Must not be writable by other users.
    address_book_path: Path | None = None
    mandate_lifetime_minutes: int = Field(default=30, ge=1, le=24 * 60)
    mandate_max_transactions: int = Field(default=3, ge=1, le=1000)

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.llm_api_key is not None and not _KEY.fullmatch(self.llm_api_key.get_secret_value()):
            # Never echo the value, not even part of it.
            raise ValueError("LLM_API_KEY must be printable ASCII without spaces")
        if not _MODEL.fullmatch(self.llm_model):
            raise ValueError("LLM_MODEL must be a model id like claude-opus-5-5")
        url = urlsplit(str(self.llm_base_url))
        if url.username or url.password or url.query or url.fragment:
            raise ValueError("LLM_BASE_URL must be scheme://host[:port][/path] only")
        if url.scheme != "https" and not _is_loopback(url.hostname or ""):
            # The key travels in a header: plain HTTP only to this machine.
            raise ValueError("LLM_BASE_URL must use https (http only for loopback)")
        self.principals()  # validate now, not at first use
        return self

    def principals(self) -> tuple[str, ...]:
        """The configured principals, in order. Each must be written with its
        exact checksum, like registry addresses: this is trusted config, and
        a typo in it would lock mandates to the wrong account."""
        found: list[str] = []
        for raw in self.mandate_principals.split(","):
            value = raw.strip()
            if not value:
                continue
            if not _ADDRESS.fullmatch(value) or value != to_checksum_address(value):
                raise ValueError("MANDATE_PRINCIPALS entries must be EIP-55 checksummed addresses")
            if value in found:
                raise ValueError("MANDATE_PRINCIPALS lists an address twice")
            found.append(value)
        return tuple(found)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
