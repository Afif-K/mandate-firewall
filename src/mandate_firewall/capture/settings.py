"""Capture settings: the LLM endpoint and its API key.

Separate from config.Settings on purpose: the proxy reads that class and
must never hold the key. The key comes from the environment or .env, never
from a command-line flag (command lines are visible to other users in `ps`).
"""

import ipaddress
import re
from typing import Self
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_MODEL = "claude-opus-5-5"

# Printable ASCII, no spaces: what an API key looks like. Anything else (a
# pasted newline, say) would end up in an HTTP header.
_KEY = re.compile(r"[\x21-\x7e]{1,500}")
_MODEL = re.compile(r"[a-z0-9][a-z0-9.\-]{0,99}")


class CaptureSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", frozen=True)

    # None means the LLM path is unavailable; the structured path still works.
    llm_api_key: SecretStr | None = None
    llm_model: str = DEFAULT_MODEL
    llm_base_url: AnyHttpUrl = AnyHttpUrl("https://api.anthropic.com")
    llm_timeout_seconds: float = Field(default=120.0, gt=0, le=600)

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
        return self


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
