"""Fixtures that run a real anvil node and a real `mandate-firewall serve`
process in front of it. Both start once per module (a second or two).
The helpers behind them are in services.py."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.integration.services import Proxy, Service, start, start_proxy, stop
from tests.net import free_port


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("anvil")


@pytest.fixture(scope="module")
def anvil(workdir: Path) -> Iterator[Service]:
    port = free_port()
    # Automine (the default): each accepted transaction is mined at once.
    service = start("anvil", ["anvil", "--port", str(port), "--quiet"], port, workdir)
    yield service
    stop(service)


@pytest.fixture(scope="module")
def proxy(anvil: Service, workdir: Path) -> Iterator[Proxy]:
    service = start_proxy(anvil, workdir)
    yield service
    stop(service)
