#!/usr/bin/env python3
"""Audit the whole git history before the repo goes public (v0.1 plan, section 3).

Run from the repo root:

    uv run python scripts/audit_history.py [--repo PATH]

It reads every commit reachable from any ref (``git rev-list --all``): every blob
ever committed, every commit message, every author, committer and tagger. It
reports six sections:

1. Identities: every name and email that authored, committed or tagged.
   Any email that isn't a GitHub noreply address is flagged.
2. Paths: every path ever committed, even if later deleted. Paths that look
   like secrets or runtime state (.env, *.db, logs/, keys, ...) are flagged.
3. 64-hex values (private keys look like this, and so do hashes): every
   distinct value, with or without 0x. The only allowlist is anvil's ten
   public dev keys. A bare value on a line that mentions sha256 is skipped
   (lockfile and checksum hashes). Everything else is listed for review by hand.
4. URL hosts. A URL with credentials in it (user:pass@host) is flagged.
5. Email addresses in file contents and commit messages, for review by hand.
6. Home-directory paths (/Users/<name>, /home/<name>): flagged.

Nothing secret is printed in full: hex values are shortened to 0xabcdef…1234 and
blanked out of the context lines, URL credentials are replaced by ***, and
context lines are cut to 120 characters.

Exit status: 0 if nothing is flagged, 1 if anything is (sections 1, 2, 4, 6),
2 if git fails. Sections 3 and 5 never change the exit status: someone has to
read them.

Standard library only, so it runs on a fresh clone without installing anything.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # noqa: S404 (runs git with fixed arguments, no shell)
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# anvil's dev keys, accounts 0-9, from the public mnemonic
# "test test test test test test test test test test test junk".
# tests/unit/test_audit_history.py re-derives them, so a typo here fails a test.
ANVIL_DEV_KEYS = frozenset(
    {
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
        "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
        "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
        "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
    }
)

NOREPLY_SUFFIX = "users.noreply.github.com"

# Exactly 64 hex digits, optionally 0x-prefixed, not part of a longer hex run
# (so contract bytecode and 40-hex git hashes don't match).
HEX64 = re.compile(r"(?<![0-9A-Za-z])(0[xX])?([0-9a-fA-F]{64})(?![0-9A-Za-z])")
URL = re.compile(r"\b(?:https?|wss?)://([^\s/?#'\"<>()\[\]`]+)")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
HOME_PATH = re.compile(r"(?:/Users|/home)/[A-Za-z0-9._-]+")

# Path patterns that should never be in a public repo (matched per path segment
# or on the file name). .env.example is the one allowed .env file.
SENSITIVE_DIRS = {"logs", "state", "graphify-out", ".claude", ".venv", "__pycache__"}
SENSITIVE_NAME = re.compile(
    r"""^(
        \.env(\..+)? | .*\.(db|sqlite3?|jsonl|pem|key|p12|pfx|keystore) |
        id_(rsa|dsa|ecdsa|ed25519)(\.pub)? | \.DS_Store | \.netrc | \.pypirc
    )$""",
    re.VERBOSE,
)
ALLOWED_NAMES = {".env.example"}

# Credentials in URLs that are known placeholders, not secrets. "user:pw" is in
# tests/unit/test_capture_extractor.py, which checks that such a URL is rejected.
PLACEHOLDER_USERINFO = frozenset({"user:pw"})

CONTEXT_WIDTH = 120
MAX_PLACES = 3


@dataclass
class Place:
    """Where something was seen: a file at the commit that added it, or a message."""

    where: str  # "path:line" or "commit message"
    commit: str  # short hash
    context: str = ""

    def __str__(self) -> str:
        return f"{self.where} @ {self.commit}"


@dataclass
class Findings:
    places: dict[str, list[Place]] = field(default_factory=lambda: defaultdict(list))

    def add(self, key: str, place: Place) -> None:
        self.places[key].append(place)


# --- git ------------------------------------------------------------------------


class GitError(RuntimeError):
    pass


def git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    proc = subprocess.run(  # noqa: S603 (fixed git argv, no shell)
        ["git", "-C", str(repo), *args],  # noqa: S607 (git from PATH, like every git tool)
        input=stdin,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def blob_locations(repo: Path) -> tuple[dict[str, tuple[str, str]], set[str]]:
    """Map each blob to (path, short commit) where it was first added; also all paths.

    ``git log --raw`` lists, per commit, every file whose blob changed. Walking
    oldest-first, the first time a blob appears is where it was introduced.
    ``-m`` includes merge commits' diffs against each parent.
    """
    out = git(
        repo,
        "log",
        "--all",
        "--reverse",
        "--raw",
        "--no-abbrev",
        "--no-renames",
        "-m",
        "--format=commit %H",
    ).decode(errors="replace")
    locations: dict[str, tuple[str, str]] = {}
    paths: set[str] = set()
    commit = "?"
    for line in out.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:7]
        elif line.startswith(":"):
            meta, _, path = line.partition("\t")
            new_blob = meta.split()[3]
            paths.add(path)
            if set(new_blob) != {"0"}:  # all zeros = the file was deleted
                locations.setdefault(new_blob, (path, commit))
    return locations, paths


def all_blobs(repo: Path) -> dict[str, str]:
    """Every blob reachable from any ref, with the path rev-list found it at."""
    listing = git(repo, "rev-list", "--all", "--objects").decode(errors="replace")
    named: dict[str, str] = {}
    for line in listing.splitlines():
        sha, _, path = line.partition(" ")
        named[sha] = path
    if not named:
        return {}
    types = git(repo, "cat-file", "--batch-check", stdin="\n".join(named).encode() + b"\n")
    blobs: dict[str, str] = {}
    for line in types.decode().splitlines():
        sha, kind, _size = line.split()
        if kind == "blob":
            blobs[sha] = named[sha]
    return blobs


def read_blobs(repo: Path, shas: list[str]) -> dict[str, str]:
    if not shas:
        return {}
    raw = git(repo, "cat-file", "--batch", stdin="\n".join(shas).encode() + b"\n")
    contents: dict[str, str] = {}
    pos = 0
    for _ in shas:
        header_end = raw.index(b"\n", pos)
        sha, _kind, size = raw[pos:header_end].decode().split()
        start = header_end + 1
        contents[sha] = raw[start : start + int(size)].decode("utf-8", errors="replace")
        pos = start + int(size) + 1  # skip the trailing newline
    return contents


def messages(repo: Path) -> list[tuple[str, str]]:
    out = git(repo, "log", "--all", "--format=%H%x00%B%x1e").decode(errors="replace")
    result = []
    for record in out.split("\x1e"):
        record = record.lstrip("\n")
        if record:
            full, _, body = record.partition("\x00")
            result.append((full[:7], body))
    return result


def identities(repo: Path) -> dict[tuple[str, str], dict[str, int]]:
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    out = git(repo, "log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce").decode(errors="replace")
    for line in out.splitlines():
        an, ae, cn, ce = line.split("\x00")
        counts[(an, ae)]["author"] += 1
        counts[(cn, ce)]["committer"] += 1
    tags = git(repo, "for-each-ref", "refs/tags", "--format=%(taggername)%00%(taggeremail)").decode(
        errors="replace"
    )
    for line in tags.splitlines():
        name, _, email = line.partition("\x00")
        if email:  # lightweight tags have no tagger
            counts[(name, email.strip("<>"))]["tagger"] += 1
    return counts


# --- redaction ------------------------------------------------------------------


def short_hex(value: str) -> str:
    return f"0x{value[:6]}…{value[-4:]}"


def redact_line(line: str) -> str:
    line = HEX64.sub("<HEX64>", line)
    line = URL.sub(lambda m: m.group(0).replace(m.group(1), strip_userinfo(m.group(1))), line)
    line = line.strip()
    if len(line) > CONTEXT_WIDTH:
        line = line[: CONTEXT_WIDTH - 1] + "…"
    return line


def strip_userinfo(authority: str) -> str:
    if "@" in authority:
        return "***@" + authority.rsplit("@", 1)[1]
    return authority


def host_of(authority: str) -> str:
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):  # IPv6 literal
        return host.split("]")[0] + "]"
    return host.split(":")[0].rstrip(".,;").lower()


# --- scanning -------------------------------------------------------------------


@dataclass
class Report:
    hex_values: Findings = field(default_factory=Findings)
    anvil_keys_seen: set[str] = field(default_factory=set)
    hosts: Findings = field(default_factory=Findings)
    credential_urls: Findings = field(default_factory=Findings)
    placeholder_urls: Findings = field(default_factory=Findings)
    emails: Findings = field(default_factory=Findings)
    home_paths: Findings = field(default_factory=Findings)


def scan_text(text: str, where: str, commit: str, report: Report, *, numbered: bool) -> None:
    for number, line in enumerate(text.splitlines(), start=1):
        loc = f"{where}:{number}" if numbered else where

        def place(loc: str = loc, line: str = line) -> Place:
            return Place(loc, commit, redact_line(line))

        for match in HEX64.finditer(line):
            value = match.group(2).lower()
            if value in ANVIL_DEV_KEYS:
                report.anvil_keys_seen.add(value)
            elif match.group(1) is None and "sha256" in line.lower():
                continue  # lockfile/checksum hash
            else:
                report.hex_values.add(value, place())
        authorities = [m.span(1) for m in URL.finditer(line)]
        for match in URL.finditer(line):
            authority = match.group(1)
            report.hosts.add(host_of(authority), place())
            if "@" in authority:
                userinfo = authority.rsplit("@", 1)[0]
                found = (
                    report.placeholder_urls
                    if userinfo in PLACEHOLDER_USERINFO
                    else report.credential_urls
                )
                found.add(host_of(authority), place())
        for match in EMAIL.finditer(line):
            # "pass@host" inside a URL is a credential, already reported (redacted)
            # in the URL section; printing it here would leak the password.
            if any(start <= match.start() < end for start, end in authorities):
                continue
            report.emails.add(match.group(0).lower(), place())
        for match in HOME_PATH.finditer(line):
            report.home_paths.add(match.group(0), place())


def path_is_sensitive(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    if name in ALLOWED_NAMES:
        return False
    return bool(SENSITIVE_DIRS.intersection(parts[:-1])) or bool(SENSITIVE_NAME.match(name))


# --- output ---------------------------------------------------------------------


def print_places(places: list[Place], *, context: bool) -> None:
    for place in places[:MAX_PLACES]:
        print(f"        {place}")
        if context and place.context:
            print(f"          | {place.context}")
    if len(places) > MAX_PLACES:
        print(f"        … and {len(places) - MAX_PLACES} more")


def audit(repo: Path) -> int:
    commit_count = len(git(repo, "rev-list", "--all").splitlines())
    locations, paths = blob_locations(repo)
    blobs = all_blobs(repo)
    contents = read_blobs(repo, sorted(blobs))

    report = Report()
    for sha in sorted(blobs, key=lambda s: locations.get(s, (blobs[s], ""))):
        path, commit = locations.get(sha, (blobs[sha], "?"))
        scan_text(contents[sha], path, commit, report, numbered=True)
    for short, body in messages(repo):
        scan_text(body, "commit message", short, report, numbered=False)

    flags = 0
    print(f"History audit of {repo.resolve()}")
    print(f"{commit_count} commits, {len(blobs)} blobs, {len(paths)} paths (all refs)\n")

    print("[1] Identities (author, committer, tagger)")
    for (name, email), roles in sorted(identities(repo).items()):
        ok = email.lower().endswith("@" + NOREPLY_SUFFIX)
        flags += not ok
        role_text = ", ".join(f"{role} {n}" for role, n in sorted(roles.items()))
        print(f"  {'ok  ' if ok else 'FLAG'}  {name} <{email}>  ({role_text})")

    print(f"\n[2] Paths ever committed ({len(paths)})")
    sensitive = sorted(p for p in paths if path_is_sensitive(p))
    flags += len(sensitive)
    for path in sensitive:
        print(f"  FLAG  {path}")
    for path in sorted(paths):
        if path not in sensitive:
            print(f"        {path}")

    hex_places = report.hex_values.places
    print(
        f"\n[3] 64-hex values: {len(report.anvil_keys_seen)} anvil dev keys allowlisted, "
        f"{len(hex_places)} others to read by hand"
    )
    for value, places in sorted(hex_places.items(), key=lambda kv: str(kv[1][0])):
        print(f"  {short_hex(value)}  ({len(places)} place{'s' * (len(places) != 1)})")
        print_places(places, context=True)

    print(f"\n[4] URL hosts ({len(report.hosts.places)})")
    for host, places in sorted(report.credential_urls.places.items()):
        flags += 1
        print(f"  FLAG  credentials in a URL to {host}")
        print_places(places, context=True)
    for host, places in sorted(report.placeholder_urls.places.items()):
        print(f"  ok    placeholder credentials in a URL to {host}")
        print_places(places, context=True)
    for host, places in sorted(report.hosts.places.items()):
        print(f"        {host}  ({len(places)}; first: {places[0]})")

    print(f"\n[5] Email addresses in contents and messages ({len(report.emails.places)})")
    for email, places in sorted(report.emails.places.items()):
        print(f"        {email}  ({len(places)})")
        print_places(places, context=False)

    print(f"\n[6] Home-directory paths ({len(report.home_paths.places)})")
    for home, places in sorted(report.home_paths.places.items()):
        flags += 1
        print(f"  FLAG  {home}")
        print_places(places, context=True)

    print(f"\n{flags} flagged; sections 3 and 5 still need reading by hand.")
    return 1 if flags else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=Path("."), help="repository to audit")
    args = parser.parse_args(argv)
    try:
        return audit(args.repo)
    except GitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
