"""scripts/audit_history.py: run on throwaway git repos built in tmp_path."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
from eth_account import Account

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "audit_history.py"
NOREPLY = "1+dev@users.noreply.github.com"
PERSONAL = "dev@example.com"
# Not an anvil key: a fixed value that must never be printed in full.
UNKNOWN_HEX = "1f" * 32
# Built at runtime so this file, once committed, doesn't trip the audit itself:
# the script scans its own test file like any other, with no exceptions.
HOME_PATH = "/" + "Users/someone"
CREDENTIAL_URL = "https://bob:" + "hunter2" + "@rpc.example:8545/x"
REDACTED_URL = "https://" + "***@rpc.example:8545"
ANVIL_KEY_0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def load_script():
    spec = importlib.util.spec_from_file_location("audit_history", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # @dataclass looks its module up in sys.modules while the class is built.
    sys.modules.setdefault("audit_history", module)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str, email: str = NOREPLY) -> None:
    env = {
        **os.environ,
        # Ignore the developer's own git config (signing, hooks, identity).
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "dev",
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": "dev",
        "GIT_COMMITTER_EMAIL": email,
    }
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), *args],  # noqa: S607
        check=True,
        env=env,
        capture_output=True,
    )


def commit(repo: Path, files: dict[str, str | None], message: str, email: str = NOREPLY) -> None:
    for name, text in files.items():
        path = repo / name
        if text is None:
            git(repo, "rm", "-q", name)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        git(repo, "add", name)
    git(repo, "commit", "-q", "-m", message, email=email)


def audit(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(SCRIPT), "--repo", str(repo)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    return path


def test_allowlisted_keys_are_exactly_anvils_dev_keys() -> None:
    Account.enable_unaudited_hdwallet_features()
    mnemonic = "test test test test test test test test test test test junk"
    derived = {
        Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/{i}").key.hex()
        for i in range(10)
    }
    assert {k.removeprefix("0x") for k in derived} == load_script().ANVIL_DEV_KEYS


def test_clean_history_exits_zero(repo: Path) -> None:
    commit(
        repo,
        {"src/app.py": f'KEY = "0x{ANVIL_KEY_0}"  # anvil account 0\n', ".env.example": "X=1\n"},
        "add app",
    )
    result = audit(repo)
    assert result.returncode == 0, result.stdout
    assert "1 anvil dev keys allowlisted, 0 others" in result.stdout
    assert ANVIL_KEY_0 not in result.stdout


def test_flags_personal_email_deleted_secrets_and_home_paths(repo: Path) -> None:
    commit(repo, {".env": "LLM_API_KEY=x\n", "a.txt": f"see {HOME_PATH}/x\n"}, "one", PERSONAL)
    commit(repo, {".env": None, "a.txt": "clean\n"}, "remove them")
    result = audit(repo)
    out = result.stdout
    assert result.returncode == 1
    assert f"FLAG  dev <{PERSONAL}>  (author 1, committer 1)" in out
    assert f"ok    dev <{NOREPLY}>" in out
    assert "FLAG  .env\n" in out  # deleted later, still in history
    assert f"FLAG  {HOME_PATH}" in out
    assert "3 flagged" in out


def test_unknown_hex_is_listed_but_never_printed_in_full(repo: Path) -> None:
    commit(repo, {"k.py": f'A = "0x{UNKNOWN_HEX}"\nB = "{UNKNOWN_HEX.upper()}"\n'}, "add")
    result = audit(repo)
    assert result.returncode == 0  # review section, not a flag
    assert "1 others to read by hand" in result.stdout
    assert "0x1f1f1f…1f1f  (2 places)" in result.stdout
    assert "k.py:1 @ " in result.stdout and '| A = "<HEX64>"' in result.stdout
    assert UNKNOWN_HEX not in result.stdout.lower()


def test_hex_found_in_commit_messages(repo: Path) -> None:
    commit(repo, {"a.txt": "x\n"}, f"oops {UNKNOWN_HEX}")
    out = audit(repo).stdout
    assert "commit message @ " in out
    assert UNKNOWN_HEX not in out


def test_sha256_lines_and_longer_hex_are_skipped(repo: Path) -> None:
    lock = f'hash = "sha256:{UNKNOWN_HEX}"\nbytecode = "0x{UNKNOWN_HEX}60"\n'
    commit(repo, {"uv.lock": lock}, "lock")
    assert "0 others to read by hand" in audit(repo).stdout


def test_url_credentials_flagged_and_redacted_placeholders_ok(repo: Path) -> None:
    text = f"a = '{CREDENTIAL_URL}'\nb = 'https://user:pw@api.test?q=1'\n"
    commit(repo, {"cfg.py": text}, "urls")
    result = audit(repo)
    out = result.stdout
    assert result.returncode == 1
    assert "FLAG  credentials in a URL to rpc.example" in out
    assert "ok    placeholder credentials in a URL to api.test" in out
    assert "hunter2" not in out
    assert REDACTED_URL in out


@pytest.mark.parametrize(
    ("path", "sensitive"),
    [
        (".env", True),
        ("deploy/.env.local", True),
        (".env.example", False),
        ("state/mandates.db", True),
        ("logs/audit.jsonl", True),
        ("graphify-out/graph.json", True),
        ("keys/id_ed25519", True),
        ("certs/server.pem", True),
        ("src/logs.py", False),
        ("docs/state-machine.md", False),
    ],
)
def test_sensitive_paths(path: str, sensitive: bool) -> None:
    assert load_script().path_is_sensitive(path) is sensitive


def test_not_a_repo_exits_two(tmp_path: Path) -> None:
    result = audit(tmp_path)
    assert result.returncode == 2
    assert result.stderr.startswith("error: git")
