import os
import shutil

import pytest

# Marker -> the binary it needs. Tests are skipped, not failed, when it's missing,
# unless REQUIRE_FOUNDRY=1 (CI sets it): then a missing binary fails the run, so a
# broken Foundry install can't turn CI green by skipping every integration test.
REQUIRED_BINARIES = {"anvil": "anvil", "forge": "forge"}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for marker, binary in REQUIRED_BINARIES.items():
        if shutil.which(binary) is not None:
            continue
        if os.environ.get("REQUIRE_FOUNDRY") == "1":
            raise pytest.UsageError(f"REQUIRE_FOUNDRY=1 but {binary} is not on PATH")
        skip = pytest.mark.skip(reason=f"{binary} not found on PATH (install Foundry)")
        for item in items:
            if marker in item.keywords:
                item.add_marker(skip)
