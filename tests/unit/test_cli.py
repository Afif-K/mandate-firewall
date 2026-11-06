import os
import subprocess
import sys
from pathlib import Path

import pytest

from mandate_firewall.cli import build_parser, build_settings, is_loopback, main
from mandate_firewall.config import Settings
from tests.mandates import native_transfer_mandate, seed_store
from tests.net import free_port

ALICE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # anvil dev account 0 (public)


def settings_for(*argv: str) -> Settings:
    return build_settings(build_parser().parse_args(["serve", *argv]))


@pytest.fixture(autouse=True)
def _clean_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Settings reads .env from the working directory and the process env.
    monkeypatch.chdir(tmp_path)
    for name in (
        "UPSTREAM_RPC_URL",
        "PROXY_HOST",
        "PROXY_PORT",
        "LOG_LEVEL",
        "AUDIT_LOG_PATH",
        "MANDATE_DB_PATH",
    ):
        monkeypatch.delenv(name, raising=False)


def test_defaults_come_from_settings() -> None:
    settings = settings_for()
    assert str(settings.upstream_rpc_url) == "http://127.0.0.1:8545/"
    assert settings.proxy_port == 8546
    assert settings.audit_log_path == Path("logs/audit.jsonl")
    assert settings.mandate_db_path == Path("state/mandates.db")


def test_mandate_db_flag_and_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANDATE_DB_PATH", "env/m.db")
    assert settings_for().mandate_db_path == Path("env/m.db")
    assert settings_for("--mandate-db", "flag/m.db").mandate_db_path == Path("flag/m.db")


def test_flags_override_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROXY_PORT", "9000")
    monkeypatch.setenv("LOG_LEVEL", "ERROR")
    assert settings_for().proxy_port == 9000
    settings = settings_for("--port", "9001", "--log-level", "debug", "--audit-log", "a.jsonl")
    assert settings.proxy_port == 9001
    assert settings.log_level == "DEBUG"
    assert settings.audit_log_path == Path("a.jsonl")


def test_invalid_setting_exits_2_without_echoing_value(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["serve", "--upstream", "ftp://host/SECRET-KEY"])
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "upstream_rpc_url" in err
    assert "SECRET-KEY" not in err


def test_command_is_required() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.0.0.2", True),
        ("::1", True),
        ("localhost", True),
        ("0.0.0.0", False),  # noqa: S104
        ("192.168.1.10", False),
        ("example.com", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert is_loopback(host) is expected


def run_serve(cwd: Path) -> subprocess.CompletedProcess[str]:
    """A real `serve` process: checks the exit code uvicorn gives a failed
    startup. Port 9 (discard) has no JSON-RPC node on it."""
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mandate_firewall",
            "serve",
            "--upstream",
            "http://127.0.0.1:9/v2/SECRET-API-KEY",
            "--port",
            str(free_port()),
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=30,
        env={k: v for k, v in os.environ.items() if k != "MANDATE_DB_PATH"},
    )


def test_serve_refuses_to_start_without_mandate_store(tmp_path: Path) -> None:
    result = run_serve(tmp_path)
    assert result.returncode == 3
    assert "mandate store state/mandates.db does not exist" in result.stderr
    assert not (tmp_path / "state").exists()


def test_serve_refuses_to_start_without_upstream(tmp_path: Path) -> None:
    seed_store(tmp_path / "state" / "mandates.db", native_transfer_mandate(84532, ALICE))
    result = run_serve(tmp_path)
    assert result.returncode == 3
    assert "cannot fetch chain id from upstream http://127.0.0.1:9" in result.stderr
    assert "SECRET-API-KEY" not in result.stderr + result.stdout
