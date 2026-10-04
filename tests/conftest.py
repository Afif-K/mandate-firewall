import shutil

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if shutil.which("anvil") is not None:
        return
    skip = pytest.mark.skip(reason="anvil not found on PATH (install Foundry)")
    for item in items:
        if "anvil" in item.keywords:
            item.add_marker(skip)
