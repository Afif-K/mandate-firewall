"""Only capture/ talks to the LLM. The proxy never loads it or holds the key.

docs/m3-plan.md, decision 5. Two checks: a static one over every module's
imports and text, and a runtime one that builds the proxy app in a fresh
interpreter and looks at what got imported.
"""

import ast
import subprocess
import sys
from pathlib import Path

import mandate_firewall

PACKAGE = Path(mandate_firewall.__file__).parent
CAPTURE = PACKAGE / "capture"


def _modules() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def _outside_capture() -> list[Path]:
    return [p for p in _modules() if CAPTURE not in p.parents]


def _imports(path: Path) -> set[str]:
    """Absolute module names a file imports, relative imports resolved."""
    package = ".".join(path.relative_to(PACKAGE.parent).with_suffix("").parts[:-1])
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")[: len(package.split(".")) - node.level + 1]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            found.add(module)
            found.update(f"{module}.{alias.name}" for alias in node.names)
    return found


def test_the_walk_sees_the_package() -> None:
    names = {p.name for p in _outside_capture()}
    assert {"cli.py", "app.py", "compile.py", "store.py"} <= names
    assert any(p.name == "extractor.py" for p in _modules())


def test_nothing_outside_capture_imports_it() -> None:
    for path in _outside_capture():
        bad = {m for m in _imports(path) if m.startswith("mandate_firewall.capture")}
        assert not bad, f"{path.relative_to(PACKAGE)} imports {bad}"


def test_no_llm_sdk_anywhere() -> None:
    # We call the API over httpx; the SDK and its HTTP stack carry no
    # provenance attestations (decision 5).
    for path in _modules():
        roots = {m.split(".")[0] for m in _imports(path)}
        assert not roots & {"anthropic", "httpx2", "httpcore2"}, path


def test_endpoint_and_key_names_only_in_capture() -> None:
    for path in _outside_capture():
        source = path.read_text().lower()
        for needle in ("api.anthropic.com", "llm_api_key", "/v1/messages"):
            assert needle not in source, f"{path.relative_to(PACKAGE)} mentions {needle}"


def test_building_the_proxy_does_not_load_capture() -> None:
    code = (
        "import sys\n"
        "from mandate_firewall.cli import build_parser, build_settings\n"
        "from mandate_firewall.proxy.app import create_app\n"
        "args = build_parser().parse_args(['serve'])\n"
        "create_app(build_settings(args))\n"
        "loaded = sorted(m for m in sys.modules if m.startswith('mandate_firewall.capture')"
        " or m.split('.')[0] in ('anthropic', 'httpx2', 'httpcore2'))\n"
        "print('LOADED', loaded)\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "LOADED []" in result.stdout
