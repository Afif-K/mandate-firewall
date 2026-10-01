import mandate_firewall


def test_package_imports() -> None:
    assert mandate_firewall.__version__ == "0.0.1"
