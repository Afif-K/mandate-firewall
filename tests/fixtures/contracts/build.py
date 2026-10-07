"""Compile the test contracts and write their committed artifacts.

    uv run python tests/fixtures/contracts/build.py            # rebuild artifacts/
    uv run python tests/fixtures/contracts/build.py --check    # verify, change nothing

Needs Foundry's forge, plus solc at the version pinned in foundry.toml. forge
keeps compilers under ~/Library/Application Support/svm (macOS) or ~/.svm.
The build runs offline. If that solc isn't installed yet, add
--allow-download once and forge fetches it (checking its sha256 against
binaries.soliditylang.org).

The tests use only the committed artifacts, so they need neither forge nor
solc. Each artifact records its source's sha256, so a test can tell when a
.sol file changed without a rebuild.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
SOURCES = HERE / "src"
ARTIFACTS = HERE / "artifacts"


def source_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(allow_download: bool) -> dict[str, str]:
    """Compile every contract; return {file name: artifact JSON text}."""
    settings = tomllib.loads((HERE / "foundry.toml").read_text())["profile"]["default"]
    with tempfile.TemporaryDirectory() as tmp:
        out, cache = Path(tmp) / "out", Path(tmp) / "cache"
        argv = [
            "forge",
            "build",
            "--root",
            str(HERE),
            "--out",
            str(out),
            "--cache-path",
            str(cache),
        ]
        if not allow_download:
            argv.append("--offline")
        subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)  # noqa: S603

        artifacts = {}
        for source in sorted(SOURCES.glob("*.sol")):
            name = source.stem  # one contract per file, named after it
            compiled = json.loads((out / source.name / f"{name}.json").read_text())
            artifact: dict[str, Any] = {
                "contract": name,
                "source": f"src/{source.name}",
                "source_sha256": source_sha256(source),
                "solc": settings["solc_version"],
                "evm_version": settings["evm_version"],
                "abi": compiled["abi"],
                "bytecode": compiled["bytecode"]["object"],  # creation code
            }
            artifacts[f"{name}.json"] = json.dumps(artifact, indent=2) + "\n"
        return artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare, don't write")
    parser.add_argument(
        "--allow-download", action="store_true", help="let forge fetch the pinned solc"
    )
    args = parser.parse_args()

    built = build(args.allow_download)
    committed = {p.name: p.read_text() for p in ARTIFACTS.glob("*.json")}
    if args.check:
        if built == committed:
            print(f"ok: {len(built)} artifacts match their sources")
            return 0
        for name in sorted(built.keys() | committed.keys()):
            if built.get(name) != committed.get(name):
                print(f"differs: artifacts/{name}", file=sys.stderr)
        return 1

    ARTIFACTS.mkdir(exist_ok=True)
    for stale in committed.keys() - built.keys():
        (ARTIFACTS / stale).unlink()
    for name, text in built.items():
        (ARTIFACTS / name).write_text(text)
    print(f"wrote {len(built)} artifacts to {ARTIFACTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
