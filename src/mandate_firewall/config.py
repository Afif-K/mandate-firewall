"""Runtime configuration, read from environment variables (and .env if present)."""

from pathlib import Path
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
    # One JSON line per intercepted transaction. Relative to the working directory.
    audit_log_path: Path = Path("logs/audit.jsonl")
    # Pre-EIP-155 legacy transactions carry no chain id, so a signature is valid
    # on every chain and anyone can replay it elsewhere. Off unless opted in.
    allow_legacy_unprotected: bool = False
    # The anvil binary that runs the private simulation fork: a name on PATH or a path.
    anvil_path: str = "anvil"
    # Upper bound on simulating one transaction, including waiting for the
    # simulator. A transaction that runs out of time is blocked.
    simulation_timeout_seconds: float = Field(default=10.0, gt=0)
    # Token balance/allowance checks per transaction (two reads each). A
    # transaction that needs more is blocked rather than left to time out.
    max_token_state_checks: int = Field(default=50, ge=1)


def redact_url(url: AnyHttpUrl | str) -> str:
    """scheme://host[:port] only. Hosted RPC URLs often embed an API key in the
    path or query (e.g. .../v2/<key>), and we never log secrets."""
    parts = urlsplit(str(url))
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}"
