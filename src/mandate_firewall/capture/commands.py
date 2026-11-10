"""The `mandate` commands: new, show, list, revoke.

`mandate new` is where a human locks what the agent may do:

    instruction ──► Draft ──► compiler ──► rendered summary ──► "yes" ──► store
       (LLM extractor, or the structured flags)

- The LLM path asks up to MAX_ROUNDS rounds of questions. Each answer is
  appended to the instruction as more of the user's own text, and
  extraction runs again.
- The structured path (--send / --swap) builds the Draft from flags, with no
  LLM and no API key. Questions there mean the flags are incomplete; the
  command stops and says what to fix.
- Confirmation needs an interactive terminal on both stdin and stdout, and
  the exact word "yes". That's defense in depth against a scripted "yes",
  not a boundary: whoever runs commands as the firewall's user can create
  mandates (docs/m3-plan.md §3).

cli.py imports this module only inside the `mandate` command, so the proxy
never loads it.
"""

import argparse
import json
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, TextIO

from pydantic import ValidationError

from mandate_firewall.capture.extractor import AnthropicExtractor, ExtractionError, MandateExtractor
from mandate_firewall.capture.settings import CaptureSettings
from mandate_firewall.mandate.compile import (
    Compiled,
    CompileError,
    NeedsClarification,
    Unsupported,
    compile_draft,
)
from mandate_firewall.mandate.draft import Draft, DraftIntent
from mandate_firewall.mandate.registry import Registry, RegistryError, load_registry
from mandate_firewall.mandate.render import render, safe_text, summary_line
from mandate_firewall.mandate.store import (
    MandateConflictError,
    MandateIntegrityError,
    MandateStore,
    MandateStoreError,
    StoredMandate,
)

MAX_ROUNDS = 3  # rounds of clarifying questions on the LLM path
MAX_ADDRESS_BOOK_BYTES = 100_000

EXIT_OK = 0
EXIT_REFUSED = 1  # nothing stored: declined, unsupported, failed, or not found
EXIT_USAGE = 2  # bad configuration or arguments

STRUCTURED_HINT = (
    "Without the LLM, use the structured form:\n"
    "  mandate-firewall mandate new --send 50 USDC --to 0x<checksummed address>\n"
    "  mandate-firewall mandate new --swap 100 USDC --for WETH --via uniswap --min-out 0.03"
)


@dataclass
class Console:
    stdin: TextIO = field(default_factory=lambda: sys.stdin)
    stdout: TextIO = field(default_factory=lambda: sys.stdout)
    stderr: TextIO = field(default_factory=lambda: sys.stderr)

    def say(self, text: str = "") -> None:
        print(text, file=self.stdout, flush=True)

    def error(self, text: str) -> None:
        print(f"mandate-firewall: {text}", file=self.stderr, flush=True)

    def ask(self, prompt: str) -> str | None:
        """One line from stdin, or None on end of input."""
        self.stdout.write(prompt)
        self.stdout.flush()
        line = self.stdin.readline()
        return line.rstrip("\n") if line else None

    def interactive(self) -> bool:
        return self.stdin.isatty() and self.stdout.isatty()


class _Exit(Exception):
    def __init__(self, code: int, message: str | None = None) -> None:
        self.code = code
        self.message = message


def _fail(code: int, message: str) -> NoReturn:
    raise _Exit(code, message)


def run(
    args: argparse.Namespace,
    *,
    settings: CaptureSettings | None = None,
    console: Console | None = None,
    extractor: MandateExtractor | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    """Run one `mandate` subcommand and return the exit code."""
    console = console or Console()
    try:
        if settings is None:
            settings = _load_settings()
        handler = {"new": _new, "show": _show, "list": _list, "revoke": _revoke}
        return handler[args.mandate_command](args, settings, console, extractor, clock)
    except _Exit as exc:
        if exc.message:
            console.error(exc.message)
        return exc.code
    except KeyboardInterrupt:
        console.error("interrupted; nothing stored")
        return EXIT_REFUSED


def _load_settings() -> CaptureSettings:
    try:
        return CaptureSettings()
    except ValidationError as exc:
        # Locations and our own messages only. Pydantic keeps the rejected
        # input in a separate field that we never print: it could be the key.
        problems = []
        for err in exc.errors():
            where = ".".join(str(part) for part in err["loc"]).upper() or "settings"
            problems.append(f"{where}: {err['msg']}")
        _fail(EXIT_USAGE, "invalid configuration: " + "; ".join(problems))


# --- new -------------------------------------------------------------------------


def _new(
    args: argparse.Namespace,
    settings: CaptureSettings,
    console: Console,
    extractor: MandateExtractor | None,
    clock: Callable[[], datetime],
) -> int:
    structured = args.send is not None or args.swap is not None
    if structured and args.instruction is not None:
        _fail(EXIT_USAGE, "give either an instruction or --send/--swap, not both")
    if not console.interactive():
        # Checked first, before any LLM call: confirming needs a person at
        # a terminal, reading the summary.
        _fail(EXIT_USAGE, "mandate new needs an interactive terminal (stdin and stdout)")

    principal = _principal(args, settings)
    registry = _registry(settings, settings.mandate_chain_id)
    book = _address_book(settings.address_book_path)
    lifetime = timedelta(minutes=args.minutes or settings.mandate_lifetime_minutes)
    max_transactions = args.max_transactions or settings.mandate_max_transactions

    store = _open_store(settings, create=True)
    try:
        replaces = _check_active(store, registry.chain_id, principal, replace=args.replace)

        def compile_(draft: Draft, instruction: str) -> object:
            try:
                return compile_draft(
                    draft,
                    instruction=instruction,
                    registry=registry,
                    principal=principal,
                    now=clock(),
                    lifetime=lifetime,
                    max_transactions=max_transactions,
                    address_book=book,
                )
            except CompileError as exc:
                _fail(EXIT_USAGE, f"configuration problem: {exc}")

        if structured:
            draft, instruction = _structured_draft(args)
            result = compile_(draft, instruction)
            if isinstance(result, NeedsClarification):
                _print_questions(console, result)
                _fail(EXIT_REFUSED, "the flags are incomplete; fix them and run again")
        else:
            result = _llm_rounds(args, settings, console, extractor, compile_)

        if isinstance(result, Unsupported):
            _fail(EXIT_REFUSED, f"not supported: {safe_text(result.reason)}")
        if not isinstance(result, Compiled):  # not an assert: -O would remove it
            _fail(EXIT_REFUSED, "no mandate was compiled; nothing stored")

        console.say()
        console.say(render(result.mandate, registry, now=clock(), replaces=replaces))
        for note in result.notes:
            console.say(f"  ⚠ {safe_text(note)}")
        console.say()
        answer = console.ask('Type "yes" to lock this mandate: ')
        if answer is None or answer.strip() != "yes":
            console.say("Not confirmed. Nothing stored.")
            return EXIT_REFUSED
        try:
            mid = store.add(result.mandate, replace=args.replace)
        except MandateConflictError:
            _fail(EXIT_REFUSED, "the agent got another active mandate meanwhile; nothing stored")
        except MandateStoreError as exc:
            _fail(EXIT_REFUSED, f"not stored: {exc}")
        console.say(f"Locked mandate {mid}")
        console.say("Now give the agent its task.")
        return EXIT_OK
    finally:
        store.close()


def _llm_rounds(
    args: argparse.Namespace,
    settings: CaptureSettings,
    console: Console,
    extractor: MandateExtractor | None,
    compile_: Callable[[Draft, str], object],
) -> object:
    if extractor is None:
        if settings.llm_api_key is None:
            _fail(EXIT_USAGE, "LLM_API_KEY is not set.\n" + STRUCTURED_HINT)
        extractor = AnthropicExtractor(settings)

    instruction = args.instruction
    if instruction is None:
        instruction = console.ask("What may the agent do? ")
        if instruction is None or not instruction.strip():
            _fail(EXIT_REFUSED, "no instruction; nothing stored")
    console.say(
        f"Reading your instruction with {settings.llm_model} "
        f"(it is sent to {settings.llm_base_url.host})..."
    )

    for round_ in range(MAX_ROUNDS + 1):
        try:
            draft = extractor.extract(instruction)
        except ExtractionError as exc:
            _fail(EXIT_REFUSED, f"{exc}. Nothing stored.\n{STRUCTURED_HINT}")
        result = compile_(draft, instruction)
        if not isinstance(result, NeedsClarification):
            return result
        _print_questions(console, result)
        if round_ == MAX_ROUNDS:
            break
        answer = console.ask("Your answer (empty to stop): ")
        if answer is None or not answer.strip():
            _fail(EXIT_REFUSED, "stopped; nothing stored")
        # The answer is more of the user's own words, so values in it are
        # grounded exactly like the first line.
        instruction = f"{instruction}\n{answer.strip()}"
    _fail(
        EXIT_REFUSED, f"still unclear after {MAX_ROUNDS} rounds; nothing stored.\n{STRUCTURED_HINT}"
    )


def _print_questions(console: Console, result: NeedsClarification) -> None:
    console.say("Before this can become a mandate:")
    for number, question in enumerate(result.questions, start=1):
        console.say(f"  {number}. {safe_text(question)}")


def _structured_draft(args: argparse.Namespace) -> tuple[Draft, str]:
    """The flags as a Draft, plus the instruction they spell, which the
    compiler grounds values in and the mandate records."""
    if args.send is not None:
        if args.swap is not None or args.buy or args.via or args.min_out:
            _fail(EXIT_USAGE, "--send can't be combined with --swap, --for, --via or --min-out")
        if args.to is None:
            _fail(EXIT_USAGE, "--send needs --to ADDRESS_OR_NAME")
        amount, symbol = args.send
        intent = DraftIntent(
            kind="transfer", asset_symbol=symbol, amount_text=amount, recipient_text=args.to
        )
        return Draft(intents=(intent,)), f"send {amount} {symbol} to {args.to}"

    if args.to is not None:
        _fail(EXIT_USAGE, "--to belongs to --send; a swap's tokens always come back to the agent")
    if args.buy is None or args.via is None:
        _fail(EXIT_USAGE, "--swap needs --for SYMBOL and --via VENUE")
    amount, symbol = args.swap
    if args.min_out is None:
        # Required (docs/m4-plan.md §6). The compiler would ask too; a flag
        # error says what to type.
        _fail(
            EXIT_USAGE,
            f"--swap needs --min-out AMOUNT: the least {safe_text(args.buy, 20)} to receive "
            f"for {safe_text(amount, 40)} {safe_text(symbol, 20)}",
        )
    intent = DraftIntent(
        kind="swap",
        asset_symbol=symbol,
        amount_text=amount,
        buy_symbol=args.buy,
        min_out_text=args.min_out,
        venue_name=args.via,
    )
    instruction = f"swap {amount} {symbol} for at least {args.min_out} {args.buy} on {args.via}"
    return Draft(intents=(intent,)), instruction


# --- show / list / revoke --------------------------------------------------------


def _show(
    args: argparse.Namespace,
    settings: CaptureSettings,
    console: Console,
    extractor: MandateExtractor | None,
    clock: Callable[[], datetime],
) -> int:
    store = _open_store(settings, create=False)
    try:
        stored = _find(store, args.id)
        registry = _registry(settings, stored.mandate.chain_id)
        console.say(render(stored.mandate, registry, now=clock()))
        console.say()
        console.say(f"  id: {stored.id}")
        console.say(
            f"  status: {stored.status}, {stored.transactions} of "
            f"{stored.mandate.limits.max_transactions} transactions used"
        )
        return EXIT_OK
    finally:
        store.close()


def _list(
    args: argparse.Namespace,
    settings: CaptureSettings,
    console: Console,
    extractor: MandateExtractor | None,
    clock: Callable[[], datetime],
) -> int:
    store = _open_store(settings, create=False)
    try:
        try:
            mandates = store.all()
        except MandateIntegrityError as exc:
            _fail(EXIT_REFUSED, f"mandate store integrity failure: {exc}")
        if not mandates:
            console.say("No mandates.")
            return EXIT_OK
        registries: dict[int, Registry] = {}
        for stored in reversed(mandates):  # newest first
            m = stored.mandate
            if m.chain_id not in registries:
                registries[m.chain_id] = _registry(settings, m.chain_id)
            console.say(
                f"{stored.id[:18]}  {stored.status:<9}  "
                f"{stored.transactions}/{m.limits.max_transactions} tx  "
                f"until {m.expires_at:%Y-%m-%d %H:%M} UTC  {m.principal}"
            )
            console.say(f"    {summary_line(m, registries[m.chain_id])}")
        return EXIT_OK
    finally:
        store.close()


def _revoke(
    args: argparse.Namespace,
    settings: CaptureSettings,
    console: Console,
    extractor: MandateExtractor | None,
    clock: Callable[[], datetime],
) -> int:
    # No confirmation: revoking only ever makes the agent able to do less.
    store = _open_store(settings, create=False)
    try:
        stored = _find(store, args.id)
        if store.revoke(stored.id):
            console.say(f"Revoked mandate {stored.id}")
            return EXIT_OK
        console.say(f"Mandate {stored.id} was already {stored.status}; nothing changed.")
        return EXIT_OK
    except MandateStoreError as exc:
        _fail(EXIT_REFUSED, str(exc))
    finally:
        store.close()


# --- shared ----------------------------------------------------------------------


_ID_PREFIX = re.compile(r"(?:0x)?[0-9a-f]{8,64}")


def _find(store: MandateStore, text: str) -> StoredMandate:
    """A mandate by its id or a unique prefix of at least 8 hex digits."""
    key = text.strip().lower()
    if not _ID_PREFIX.fullmatch(key):
        _fail(EXIT_USAGE, "give a mandate id, or at least its first 8 hex digits")
    key = key if key.startswith("0x") else "0x" + key
    try:
        matches = [s for s in store.all() if s.id.startswith(key)]
    except MandateIntegrityError as exc:
        _fail(EXIT_REFUSED, f"mandate store integrity failure: {exc}")
    if not matches:
        _fail(EXIT_REFUSED, f"no mandate {key}")
    if len(matches) > 1:
        _fail(EXIT_USAGE, f"{key} matches {len(matches)} mandates; give more digits")
    return matches[0]


def _principal(args: argparse.Namespace, settings: CaptureSettings) -> str:
    principals = settings.principals()
    if not principals:
        _fail(EXIT_USAGE, "MANDATE_PRINCIPALS is not set: list the agent accounts mandates are for")
    if args.principal is None:
        if len(principals) > 1:
            _fail(EXIT_USAGE, "several principals are configured; choose one with --principal")
        return principals[0]
    if args.principal not in principals:
        # Only configured accounts: a typo here must not lock a mandate to
        # an account nobody controls.
        _fail(EXIT_USAGE, "--principal must be one of MANDATE_PRINCIPALS, written the same way")
    return str(args.principal)


def _registry(settings: CaptureSettings, chain_id: int) -> Registry:
    try:
        return load_registry(chain_id, settings.registry_path)
    except RegistryError as exc:
        _fail(EXIT_USAGE, str(exc))


def _open_store(settings: CaptureSettings, *, create: bool) -> MandateStore:
    try:
        return MandateStore(settings.mandate_db_path, create=create)
    except MandateStoreError as exc:
        _fail(EXIT_REFUSED, str(exc))


def _check_active(
    store: MandateStore, chain_id: int, principal: str, *, replace: bool
) -> str | None:
    """Checked before any LLM call, so a conflict costs nothing. store.add
    checks again, atomically. Every row is verified first, not just this
    principal's: a tampered row filed under another account would otherwise
    go unnoticed, and this is the moment a person is here to see it."""
    try:
        store.all()
        active = store.active_for(chain_id, principal)
    except MandateIntegrityError as exc:
        _fail(EXIT_REFUSED, f"mandate store integrity failure: {exc}")
    if active is None:
        return None
    if not replace:
        _fail(
            EXIT_REFUSED,
            f"{principal} already has active mandate {active.id}. "
            "Use --replace to revoke it and lock a new one, or revoke it first.",
        )
    return active.id


def _address_book(path: Path | None) -> dict[str, str]:
    """Name -> address. Whoever can write this file can redirect "send to
    Bob", so a file other users can write is refused, not just warned about."""
    if path is None:
        return {}
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            _fail(EXIT_USAGE, f"address book {path} is writable by other users; chmod go-w it")
        data = path.read_bytes()
    except OSError as exc:
        _fail(EXIT_USAGE, f"can't read address book {path}: {exc.strerror}")
    if len(data) > MAX_ADDRESS_BOOK_BYTES:
        _fail(EXIT_USAGE, "address book is too large")
    try:
        book = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except ValueError as exc:
        _fail(EXIT_USAGE, f"address book is not valid JSON: {exc}")
    if not isinstance(book, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in book.items()
    ):
        _fail(EXIT_USAGE, 'address book must be a JSON object of "name": "0x..." entries')
    return book


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate name")
    return dict(pairs)
