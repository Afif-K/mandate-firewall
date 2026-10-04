"""Command-line entry point.

    mandate-firewall serve [--upstream URL] [--host H] [--port P]
                           [--audit-log PATH] [--log-level LEVEL]

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
    return parser


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
