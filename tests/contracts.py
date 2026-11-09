"""The compiled test contracts in tests/fixtures/contracts/artifacts.

Encoding is done offline with web3's ABI tools; nothing here talks to a node.
"""

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from web3 import Web3

CONTRACTS_DIR = Path(__file__).parent / "fixtures" / "contracts"
ARTIFACTS_DIR = CONTRACTS_DIR / "artifacts"
NAMES = (
    "EthForwarder",
    "LyingToken",
    "MockERC20",
    "MockERC721",
    "MockRouter",
    "SimDetector",
    "TimeBomb",
)


@dataclass(frozen=True)
class Contract:
    name: str
    abi: list[dict[str, Any]]
    bytecode: str  # creation code, 0x-prefixed
    source_sha256: str

    def deploy_data(self, *args: Any) -> str:
        """Creation code followed by the ABI-encoded constructor arguments."""
        return self._web3().constructor(*args).data_in_transaction

    def call_data(self, function: str, *args: Any) -> str:
        return self._web3().encode_abi(function, args=list(args))

    def _web3(self) -> Any:
        return Web3().eth.contract(abi=self.abi, bytecode=self.bytecode)


@cache
def load(name: str) -> Contract:
    artifact = json.loads((ARTIFACTS_DIR / f"{name}.json").read_text())
    return Contract(
        name=artifact["contract"],
        abi=artifact["abi"],
        bytecode=artifact["bytecode"],
        source_sha256=artifact["source_sha256"],
    )
