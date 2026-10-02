"""Runtime configuration, read from environment variables (and .env if present)."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", frozen=True)

    upstream_rpc_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8545")
    proxy_host: str = "127.0.0.1"
    proxy_port: int = Field(default=8546, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # Pre-EIP-155 legacy transactions carry no chain id, so a signature is valid
    # on every chain and anyone can replay it elsewhere. Off unless opted in.
    allow_legacy_unprotected: bool = False


def redact_url(url: AnyHttpUrl | str) -> str:
    """scheme://host[:port] only. Hosted RPC URLs often embed an API key in the
    path or query (e.g. .../v2/<key>), and we never log secrets."""
    parts = urlsplit(str(url))
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}"
