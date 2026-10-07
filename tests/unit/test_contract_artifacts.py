"""The committed contract artifacts match their sources (no tools needed),
and forge rebuilds them byte for byte (needs forge and the pinned solc)."""

import hashlib
import json
import re
import subprocess
import sys
import tomllib

import pytest

from tests.contracts import ARTIFACTS_DIR, CONTRACTS_DIR, NAMES, load


def test_every_source_has_an_artifact_and_nothing_else_does() -> None:
    sources = {p.stem for p in (CONTRACTS_DIR / "src").glob("*.sol")}
    artifacts = {p.stem for p in ARTIFACTS_DIR.glob("*.json")}
    assert sources == artifacts == set(NAMES)


@pytest.mark.parametrize("name", NAMES)
def test_artifact_was_built_from_the_current_source(name: str) -> None:
    source = CONTRACTS_DIR / "src" / f"{name}.sol"
    assert load(name).source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest(), (
        f"{source.name} changed; run: uv run python tests/fixtures/contracts/build.py"
    )


@pytest.mark.parametrize("name", NAMES)
def test_artifact_settings_match_foundry_toml(name: str) -> None:
    settings = tomllib.loads((CONTRACTS_DIR / "foundry.toml").read_text())["profile"]["default"]
    artifact = json.loads((ARTIFACTS_DIR / f"{name}.json").read_text())
    assert (artifact["solc"], artifact["evm_version"]) == (
        settings["solc_version"],
        settings["evm_version"],
    )
    assert re.fullmatch(r"0x(?:[0-9a-f]{2})+", artifact["bytecode"])
    # No CBOR metadata: solc would end the code with a2 64 'ipfs' ... or a1 64 'solc'.
    assert "64697066735822" not in artifact["bytecode"]  # "ipfsX" + length


@pytest.mark.forge
def test_build_reproduces_committed_artifacts() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(CONTRACTS_DIR / "build.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
