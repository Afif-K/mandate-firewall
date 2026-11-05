"""Command-line entry point.

    mandate-firewall serve [--upstream URL] [--host H] [--port P]
                           [--audit-log PATH] [--log-level LEVEL]
    mandate-firewall mandate new ["instruction"] | --send AMOUNT SYMBOL --to WHO
                                 | --swap AMOUNT SYMBOL --for SYMBOL --via VENUE
    mandate-firewall mandate show ID | list | revoke ID

Every flag overrides the matching environment variable (see .env.example),
which overrides the default in config.Settings.
"""

import argparse
import ipaddress
import logging
import sys
from typing import Any

import uvicorn
from pydantic import ValidationError

from mandate_firewall import __version__
from mandate_firewall.config import Settings
from mandate_firewall.proxy.app import create_app

logger = logging.getLogger("mandate_firewall.cli")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        serve(args)
    elif args.command == "mandate":
        # Imported here, never at module level: building the proxy for
        # `serve` must not load capture/ (docs/m3-plan.md, decision 5).
        from mandate_firewall.capture.commands import run

        sys.exit(run(args))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mandate-firewall",
        description="Firewall for AI agents that transact onchain (beta).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    serve_parser = commands.add_parser("serve", help="run the JSON-RPC proxy")
    # Defaults are None so we can tell "not given" from "given", and only pass
    # given flags to Settings; the rest come from the environment.
    serve_parser.add_argument(
        "--upstream",
        dest="upstream_rpc_url",
        metavar="URL",
        help="upstream JSON-RPC node (env UPSTREAM_RPC_URL). Command lines are visible "
        "to other local users; put URLs that contain an API key in the environment.",
    )
    serve_parser.add_argument("--host", dest="proxy_host", help="listen address (env PROXY_HOST)")
    serve_parser.add_argument(
        "--port", dest="proxy_port", type=int, help="listen port (env PROXY_PORT)"
    )
    serve_parser.add_argument(
        "--audit-log",
        dest="audit_log_path",
        metavar="PATH",
        help="JSONL audit log (env AUDIT_LOG_PATH)",
    )
    serve_parser.add_argument(
        "--log-level",
        dest="log_level",
        type=str.upper,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="(env LOG_LEVEL)",
    )
    _add_mandate_parser(commands)
    return parser


def _add_mandate_parser(commands: Any) -> None:
    mandate = commands.add_parser(
        "mandate",
        help="create and manage mandates (settings: see .env.example)",
    )
    actions = mandate.add_subparsers(dest="mandate_command", required=True)

    new = actions.add_parser(
        "new",
        help="lock a new mandate after you confirm it",
        description="Describe what the agent may do, in words (read by the LLM) or with "
        "--send/--swap (no LLM). You confirm a summary before anything is stored.",
    )
    new.add_argument(
        "instruction",
        nargs="?",
        help='e.g. "send 50 USDC to 0x..."; asked for interactively if left out',
    )
    new.add_argument("--send", nargs=2, metavar=("AMOUNT", "SYMBOL"), help="transfer, no LLM")
    new.add_argument("--to", metavar="ADDRESS_OR_NAME", help="recipient for --send")
    new.add_argument("--swap", nargs=2, metavar=("AMOUNT", "SYMBOL"), help="swap, no LLM")
    new.add_argument("--for", dest="buy", metavar="SYMBOL", help="token to buy with --swap")
    new.add_argument("--via", metavar="VENUE", help="venue for --swap, e.g. uniswap")
    new.add_argument("--min-out", metavar="AMOUNT", help="least amount to receive with --swap")
    new.add_argument("--principal", metavar="ADDRESS", help="which of MANDATE_PRINCIPALS")
    new.add_argument("--replace", action="store_true", help="revoke the account's active mandate")
    new.add_argument(
        "--minutes",
        type=int,
        choices=range(1, 24 * 60 + 1),
        metavar="1-1440",
        help="lifetime (env MANDATE_LIFETIME_MINUTES, default 30)",
    )
    new.add_argument(
        "--max-transactions",
        type=int,
        choices=range(1, 1001),
        metavar="1-1000",
        help="transaction cap (env MANDATE_MAX_TRANSACTIONS, default 3)",
    )

    show = actions.add_parser("show", help="show one mandate and its status")
    show.add_argument("id", help="mandate id, or its first 8+ hex digits")
    actions.add_parser("list", help="list all mandates, newest first")
    revoke = actions.add_parser("revoke", help="revoke a mandate")
    revoke.add_argument("id", help="mandate id, or its first 8+ hex digits")


def build_settings(args: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {
        name: value for name, value in vars(args).items() if name != "command" and value is not None
    }
    return Settings(**overrides)


def serve(args: argparse.Namespace) -> None:
    try:
        settings = build_settings(args)
    except ValidationError as exc:
        # Show which settings are wrong, not their values: one could be a keyed URL.
        bad = ", ".join(sorted({str(err["loc"][0]) for err in exc.errors() if err["loc"]}))
        print(f"mandate-firewall: invalid configuration: {bad}", file=sys.stderr)
        sys.exit(2)

    configure_logging(settings.log_level)
    if not is_loopback(settings.proxy_host):
        # The proxy has no authentication. Anyone who can reach it can send
        # transactions and read calls through it, using your upstream (and
        # its API key) and writing to your audit log.
        logger.warning(
            "listening on %s, which is not a loopback address; the proxy has no authentication",
            settings.proxy_host,
        )

    # lifespan="on": if startup fails (upstream unreachable, audit log not
    # writable), uvicorn exits with code 3 instead of serving. With "auto" it
    # may treat a lifespan error as "lifespan unsupported" and serve anyway.
    uvicorn.run(
        create_app(settings),
        host=settings.proxy_host,
        port=settings.proxy_port,
        log_level=settings.log_level.lower(),
        lifespan="on",
        server_header=False,
        # Every JSON-RPC reply is "POST / 200", so access lines say nothing; the
        # proxy logs each method itself (forwarded ones at DEBUG).
        access_log=False,
    )


def configure_logging(level: str) -> None:
    package_logger = logging.getLogger("mandate_firewall")
    package_logger.setLevel(level)
    if not package_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        package_logger.addHandler(handler)


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # a hostname we can't judge without resolving it
