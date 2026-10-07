import shutil

import pytest

# Marker -> the binary it needs. Tests are skipped, not failed, when it's missing.
REQUIRED_BINARIES = {"anvil": "anvil", "forge": "forge"}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for marker, binary in REQUIRED_BINARIES.items():
        if shutil.which(binary) is not None:
            continue
        skip = pytest.mark.skip(reason=f"{binary} not found on PATH (install Foundry)")
        for item in items:
            if marker in item.keywords:
                item.add_marker(skip)
