"""`mandate new | show | list | revoke`, driven through the real parser."""

import io
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from mandate_firewall.capture.commands import MAX_ROUNDS, Console, run
from mandate_firewall.capture.extractor import ExtractionError, FakeExtractor
from mandate_firewall.capture.settings import CaptureSettings
from mandate_firewall.cli import build_parser
from mandate_firewall.mandate.draft import Draft, DraftIntent
from mandate_firewall.mandate.store import MandateStatus, MandateStore

PRINCIPAL = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
OTHER_AGENT = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
SENTINEL = "sk-ant-SENTINEL-never-printed-0123456789"


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class NoExtractor:
    """Fails the test if the LLM path is used."""

    def extract(self, instruction: str) -> Draft:
        raise AssertionError("the LLM must not be called here")


def transfer_draft(**fields: Any) -> Draft:
    values: dict[str, Any] = {
        "kind": "transfer",
        "asset_symbol": "USDC",
        "amount_text": "50",
        "recipient_text": BOB,
    } | fields
    return Draft(intents=(DraftIntent(**values),))


@pytest.fixture
def settings(tmp_path: Path) -> CaptureSettings:
    return make_settings(tmp_path)


def make_settings(tmp_path: Path, **overrides: Any) -> CaptureSettings:
    values: dict[str, Any] = {
        "mandate_db_path": tmp_path / "state" / "mandates.db",
        "mandate_principals": PRINCIPAL,
        "llm_api_key": SENTINEL,
    } | overrides
    return CaptureSettings(_env_file=None, **values)  # type: ignore[call-arg]


class Result:
    def __init__(self, code: int, out: str, err: str) -> None:
        self.code, self.out, self.err = code, out, err


def cli(
    settings: CaptureSettings,
    *argv: str,
    stdin: str = "",
    extractor: Any = None,
    tty: bool = True,
) -> Result:
    args = build_parser().parse_args(["mandate", *argv])
    out = TTY() if tty else io.StringIO()
    err = io.StringIO()
    console = Console(stdin=TTY(stdin) if tty else io.StringIO(stdin), stdout=out, stderr=err)
    code = run(args, settings=settings, console=console, extractor=extractor or NoExtractor())
    return Result(code, out.getvalue(), err.getvalue())


def stored(settings: CaptureSettings) -> list[Any]:
    if not settings.mandate_db_path.exists():
        return []
    store = MandateStore(settings.mandate_db_path)
    try:
        return store.all()
    finally:
        store.close()


# --- new, LLM path ---------------------------------------------------------------


def test_llm_path_locks_after_yes(settings: CaptureSettings) -> None:
    fake = FakeExtractor([transfer_draft()])
    r = cli(settings, "new", f"send 50 USDC to {BOB}", stdin="yes\n", extractor=fake)
    assert r.code == 0, r.err
    assert fake.instructions == [f"send 50 USDC to {BOB}"]
    assert "1. SEND at most 50 USDC" in r.out and f"to {BOB}" in r.out
    assert 'Type "yes" to lock this mandate' in r.out
    (s,) = stored(settings)
    assert s.status is MandateStatus.ACTIVE
    assert f"Locked mandate {s.id}" in r.out
    assert "is sent to api.anthropic.com" in r.out  # the privacy line


def test_instruction_is_asked_for_when_not_given(settings: CaptureSettings) -> None:
    fake = FakeExtractor([transfer_draft()])
    r = cli(settings, "new", stdin=f"send 50 USDC to {BOB}\nyes\n", extractor=fake)
    assert r.code == 0, r.err
    assert fake.instructions == [f"send 50 USDC to {BOB}"]


@pytest.mark.parametrize("answer", ["y", "YES", "yes please", "", "no"])
def test_anything_but_yes_stores_nothing(settings: CaptureSettings, answer: str) -> None:
    fake = FakeExtractor([transfer_draft()])
    r = cli(settings, "new", f"send 50 USDC to {BOB}", stdin=answer + "\n", extractor=fake)
    assert r.code == 1
    assert "Nothing stored" in r.out
    assert stored(settings) == []


def test_end_of_input_at_confirmation_stores_nothing(settings: CaptureSettings) -> None:
    fake = FakeExtractor([transfer_draft()])
    r = cli(settings, "new", f"send 50 USDC to {BOB}", stdin="", extractor=fake)
    assert r.code == 1
    assert stored(settings) == []


@pytest.mark.parametrize("which", ["stdin", "stdout"])
def test_needs_a_terminal_before_calling_the_llm(settings: CaptureSettings, which: str) -> None:
    fake = FakeExtractor([transfer_draft()])
    args = build_parser().parse_args(["mandate", "new", f"send 50 USDC to {BOB}"])
    stdin = io.StringIO("yes\n") if which == "stdin" else TTY("yes\n")
    stdout = io.StringIO() if which == "stdout" else TTY()
    err = io.StringIO()
    code = run(args, settings=settings, console=Console(stdin, stdout, err), extractor=fake)
    assert code == 2
    assert "interactive terminal" in err.getvalue()
    assert fake.instructions == []  # no API call, no cost
    assert stored(settings) == []


def test_clarification_appends_the_answer(settings: CaptureSettings) -> None:
    fake = FakeExtractor([transfer_draft(amount_text=None), transfer_draft()])
    r = cli(settings, "new", f"send some USDC to {BOB}", stdin="50 USDC\nyes\n", extractor=fake)
    assert r.code == 0, r.err
    assert "how much should be sent?" in r.out
    assert fake.instructions == [f"send some USDC to {BOB}", f"send some USDC to {BOB}\n50 USDC"]
    (s,) = stored(settings)
    assert s.mandate.instruction == f"send some USDC to {BOB}\n50 USDC"


def test_gives_up_after_max_rounds(settings: CaptureSettings) -> None:
    fake = FakeExtractor([transfer_draft(amount_text=None)] * (MAX_ROUNDS + 1))
    r = cli(settings, "new", "send USDC", stdin="more\n" * MAX_ROUNDS, extractor=fake)
    assert r.code == 1
    assert len(fake.instructions) == MAX_ROUNDS + 1
    assert f"still unclear after {MAX_ROUNDS} rounds" in r.err
    assert "--send 50 USDC" in r.err  # points to the structured form
    assert stored(settings) == []


def test_empty_answer_stops(settings: CaptureSettings) -> None:
    fake = FakeExtractor([transfer_draft(amount_text=None)])
    r = cli(settings, "new", "send USDC", stdin="\n", extractor=fake)
    assert r.code == 1
    assert "stopped; nothing stored" in r.err


def test_unsupported(settings: CaptureSettings) -> None:
    fake = FakeExtractor([Draft(intents=(), unsupported="bridging")])
    r = cli(settings, "new", "bridge my USDC", extractor=fake)
    assert r.code == 1
    assert "not supported: bridging" in r.err


def test_extraction_error_offers_the_structured_path(settings: CaptureSettings) -> None:
    fake = FakeExtractor([ExtractionError("timeout")])
    r = cli(settings, "new", "send 50 USDC", extractor=fake)
    assert r.code == 1
    assert "LLM extraction failed: timeout" in r.err
    assert "structured form" in r.err
    assert stored(settings) == []


def test_no_key_points_to_the_structured_path(tmp_path: Path) -> None:
    s = make_settings(tmp_path, llm_api_key=None)
    args = build_parser().parse_args(["mandate", "new", "send 50 USDC"])
    err = io.StringIO()
    code = run(args, settings=s, console=Console(TTY(), TTY(), err))  # real extractor path
    assert code == 2
    assert "LLM_API_KEY is not set" in err.getvalue()
    assert "--send" in err.getvalue()


def test_notes_are_shown(settings: CaptureSettings) -> None:
    swap = Draft(
        intents=(
            DraftIntent(
                kind="swap",
                asset_symbol="USDC",
                amount_text="100",
                buy_symbol="WETH",
                venue_name="uniswap",
            ),
        )
    )
    r = cli(
        settings,
        "new",
        "swap 100 USDC for WETH on uniswap",
        stdin="yes\n",
        extractor=FakeExtractor([swap]),
    )
    assert r.code == 0, r.err
    assert "minimum: NONE ⚠" in r.out
    assert "  ⚠ For swap: no minimum amount to receive" in r.out


# --- new, structured path --------------------------------------------------------


def test_structured_send(settings: CaptureSettings) -> None:
    r = cli(settings, "new", "--send", "50", "USDC", "--to", BOB, stdin="yes\n")
    assert r.code == 0, r.err
    (s,) = stored(settings)
    assert s.mandate.instruction == f"send 50 USDC to {BOB}"
    assert s.mandate.intents[0].budget.max == 50_000_000
    assert "is sent to" not in r.out  # nothing went to the LLM


def test_structured_swap_with_minimum(settings: CaptureSettings) -> None:
    argv = (
        "new",
        "--swap",
        "100",
        "USDC",
        "--for",
        "WETH",
        "--via",
        "uniswap",
        "--min-out",
        "0.03",
    )
    r = cli(settings, *argv, stdin="yes\n")
    assert r.code == 0, r.err
    (s,) = stored(settings)
    assert s.mandate.instruction == "swap 100 USDC for at least 0.03 WETH on uniswap"
    assert s.mandate.intents[0].min_buy_per_sell is not None
    assert "minimum: at least 0.03 WETH per 100 USDC sold" in r.out


def test_structured_questions_stop_instead_of_asking(settings: CaptureSettings) -> None:
    r = cli(settings, "new", "--send", "50", "USDC", "--to", BOB.lower(), stdin="yes\n")
    assert r.code == 1
    assert "has no checksum" in r.out
    assert "fix them and run again" in r.err
    assert stored(settings) == []


@pytest.mark.parametrize(
    "argv",
    [
        ("new", "--send", "50", "USDC"),  # no --to
        ("new", "--swap", "100", "USDC", "--via", "uniswap"),  # no --for
        ("new", "--send", "50", "USDC", "--to", BOB, "--via", "uniswap"),
        ("new", "--swap", "100", "USDC", "--for", "WETH", "--via", "uniswap", "--to", BOB),
        ("new", "send 50 USDC", "--send", "50", "USDC", "--to", BOB),
    ],
)
def test_structured_flag_mistakes(settings: CaptureSettings, argv: tuple[str, ...]) -> None:
    r = cli(settings, *argv, stdin="yes\n")
    assert r.code == 2
    assert stored(settings) == []


def test_lifetime_and_cap_flags(settings: CaptureSettings) -> None:
    argv = ("new", "--send", "5", "USDC", "--to", BOB, "--minutes", "90", "--max-transactions", "1")
    r = cli(settings, *argv, stdin="yes\n")
    assert r.code == 0, r.err
    (s,) = stored(settings)
    assert (s.mandate.expires_at - s.mandate.created_at).total_seconds() == 90 * 60
    assert s.mandate.limits.max_transactions == 1


# --- principals and replacing ----------------------------------------------------


def test_no_principals_configured(tmp_path: Path) -> None:
    r = cli(
        make_settings(tmp_path, mandate_principals=""), "new", "--send", "5", "USDC", "--to", BOB
    )
    assert r.code == 2
    assert "MANDATE_PRINCIPALS is not set" in r.err


def test_several_principals_need_a_choice(tmp_path: Path) -> None:
    s = make_settings(tmp_path, mandate_principals=f"{PRINCIPAL}, {OTHER_AGENT}")
    assert cli(s, "new", "--send", "5", "USDC", "--to", BOB).code == 2
    r = cli(s, "new", "--send", "5", "USDC", "--to", BOB, "--principal", OTHER_AGENT, stdin="yes\n")
    assert r.code == 0, r.err
    assert stored(s)[0].mandate.principal == OTHER_AGENT


def test_principal_must_be_configured(settings: CaptureSettings) -> None:
    r = cli(settings, "new", "--send", "5", "USDC", "--to", BOB, "--principal", OTHER_AGENT)
    assert r.code == 2
    assert "must be one of MANDATE_PRINCIPALS" in r.err


def test_principals_setting_needs_checksums(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="EIP-55"):
        make_settings(tmp_path, mandate_principals=PRINCIPAL.lower())


def test_active_mandate_blocks_a_new_one_before_the_llm(settings: CaptureSettings) -> None:
    assert cli(settings, "new", "--send", "5", "USDC", "--to", BOB, stdin="yes\n").code == 0
    fake = FakeExtractor([transfer_draft()])
    r = cli(settings, "new", f"send 50 USDC to {BOB}", stdin="yes\n", extractor=fake)
    assert r.code == 1
    assert "already has active mandate" in r.err and "--replace" in r.err
    assert fake.instructions == []
    assert len(stored(settings)) == 1


def test_replace_revokes_the_old_one(settings: CaptureSettings) -> None:
    assert cli(settings, "new", "--send", "5", "USDC", "--to", BOB, stdin="yes\n").code == 0
    old_id = stored(settings)[0].id
    r = cli(settings, "new", "--send", "7", "USDC", "--to", BOB, "--replace", stdin="yes\n")
    assert r.code == 0, r.err
    assert f"This REPLACES active mandate {old_id}" in r.out
    statuses = [s.status for s in stored(settings)]
    assert statuses == [MandateStatus.REVOKED, MandateStatus.ACTIVE]


# --- address book ----------------------------------------------------------------


def write_book(tmp_path: Path, content: str, mode: int = 0o600) -> Path:
    path = tmp_path / "book.json"
    path.write_text(content)
    os.chmod(path, mode)
    return path


def test_address_book_name(tmp_path: Path) -> None:
    book = write_book(tmp_path, json.dumps({"Bob": BOB}))
    s = make_settings(tmp_path, address_book_path=book)
    r = cli(s, "new", "--send", "5", "USDC", "--to", "Bob", stdin="yes\n")
    assert r.code == 0, r.err
    assert f'"Bob" is {BOB}, from the address book' in r.out
    assert stored(s)[0].mandate.intents[0].recipient == BOB


@pytest.mark.parametrize(
    ("content", "mode", "message"),
    [
        (json.dumps({"Bob": BOB}), 0o620, "writable by other users"),
        (json.dumps({"Bob": BOB}), 0o602, "writable by other users"),
        ("{not json", 0o600, "not valid JSON"),
        (f'{{"Bob": "{BOB}", "Bob": "{OTHER_AGENT}"}}', 0o600, "not valid JSON"),
        (json.dumps(["Bob", BOB]), 0o600, "JSON object"),
        (json.dumps({"Bob": BOB.lower()}), 0o600, "configuration problem"),
    ],
)
def test_bad_address_books_are_refused(
    tmp_path: Path, content: str, mode: int, message: str
) -> None:
    s = make_settings(tmp_path, address_book_path=write_book(tmp_path, content, mode))
    r = cli(s, "new", "--send", "5", "USDC", "--to", "Bob", stdin="yes\n")
    assert r.code == 2
    assert message in r.err
    assert stored(s) == []


# --- show / list / revoke --------------------------------------------------------


def lock_one(settings: CaptureSettings, amount: str = "5") -> str:
    r = cli(settings, "new", "--send", amount, "USDC", "--to", BOB, "--replace", stdin="yes\n")
    assert r.code == 0, r.err
    return stored(settings)[-1].id


def test_show_by_prefix(settings: CaptureSettings) -> None:
    mid = lock_one(settings)
    for key in (mid, mid[:10], mid[2:12].upper()):
        r = cli(settings, "show", key)
        assert r.code == 0, r.err
        assert f"id: {mid}" in r.out
        assert "status: active, 0 of 3 transactions used" in r.out
        assert "SEND at most 5 USDC" in r.out


@pytest.mark.parametrize("key", ["0x1234", "zzzzzzzzzz", "0x" + "0" * 64])
def test_show_bad_or_unknown_id(settings: CaptureSettings, key: str) -> None:
    lock_one(settings)
    assert cli(settings, "show", key).code in (1, 2)


def test_list_newest_first(settings: CaptureSettings) -> None:
    first = lock_one(settings, "5")
    second = lock_one(settings, "7")
    r = cli(settings, "list")
    assert r.code == 0
    assert r.out.index(second[:18]) < r.out.index(first[:18])
    assert "revoked" in r.out and "active" in r.out
    assert f"send ≤7 USDC to {BOB}" in r.out


def test_list_empty_and_missing_store(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    r = cli(s, "list")
    assert r.code == 1
    assert "does not exist" in r.err
    assert not s.mandate_db_path.exists()  # show/list/revoke never create it
    MandateStore(s.mandate_db_path, create=True).close()
    assert cli(s, "list").out == "No mandates.\n"


def test_revoke(settings: CaptureSettings) -> None:
    mid = lock_one(settings)
    r = cli(settings, "revoke", mid[:12])
    assert r.code == 0 and f"Revoked mandate {mid}" in r.out
    assert stored(settings)[0].status is MandateStatus.REVOKED
    r = cli(settings, "revoke", mid)
    assert r.code == 0 and "was already revoked" in r.out


def test_integrity_failure_is_reported(settings: CaptureSettings) -> None:
    lock_one(settings)
    db = sqlite3.connect(settings.mandate_db_path, isolation_level=None)
    db.execute("DROP TRIGGER mandates_no_update")
    db.execute("UPDATE mandates SET principal = ?", (OTHER_AGENT,))
    db.close()
    for argv in (("list",), ("new", "--send", "5", "USDC", "--to", BOB)):
        r = cli(settings, *argv, stdin="yes\n")
        assert r.code == 1
        assert "integrity failure" in r.err


# --- settings errors never print the key -----------------------------------------


def test_settings_error_names_the_field_not_the_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)  # no .env here
    monkeypatch.setenv("LLM_API_KEY", SENTINEL + "\nX")
    monkeypatch.setenv("MANDATE_MAX_TRANSACTIONS", "zero")
    args = build_parser().parse_args(["mandate", "list"])
    err = io.StringIO()
    code = run(args, console=Console(TTY(), TTY(), err))
    assert code == 2
    assert "invalid configuration" in err.getvalue()
    assert "MANDATE_MAX_TRANSACTIONS" in err.getvalue()
    assert SENTINEL not in err.getvalue()


def test_main_dispatches_to_mandate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from mandate_firewall import cli as cli_module

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MANDATE_DB_PATH", str(tmp_path / "m.db"))
    MandateStore(tmp_path / "m.db", create=True).close()
    with pytest.raises(SystemExit) as info:
        cli_module.main(["mandate", "list"])
    assert info.value.code == 0
