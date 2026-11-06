import pytest

from mandate_firewall.proxy.methods import (
    INTERCEPTED_METHODS,
    READ_ONLY_METHODS,
    MethodClass,
    classify,
)


def test_send_raw_transaction_is_intercepted() -> None:
    assert classify("eth_sendRawTransaction") is MethodClass.INTERCEPT


@pytest.mark.parametrize("method", sorted(READ_ONLY_METHODS))
def test_read_only_methods_are_forwarded(method: str) -> None:
    assert classify(method) is MethodClass.FORWARD


@pytest.mark.parametrize(
    "method",
    [
        # the node would sign with its own keys
        "eth_sendTransaction",
        "eth_signTransaction",
        "eth_sign",
        "personal_sign",
        "personal_sendTransaction",
        "personal_unlockAccount",
        "eth_signTypedData_v4",
        "eth_accounts",
        # dev-node cheatcodes and debug/admin namespaces
        "anvil_setBalance",
        "anvil_impersonateAccount",
        "hardhat_setBalance",
        "evm_mine",
        "debug_traceTransaction",
        "admin_addPeer",
        "txpool_content",
        # stateful filters and subscriptions
        "eth_newFilter",
        "eth_subscribe",
        # near-misses must not match the intercepted or allowed names
        "ETH_SENDRAWTRANSACTION",
        "eth_sendRawTransaction ",
        "eth_getbalance",
        "",
        "some_future_method",
    ],
)
def test_everything_else_is_denied(method: str) -> None:
    assert classify(method) is MethodClass.DENY


def test_no_method_is_both_intercepted_and_forwarded() -> None:
    assert not INTERCEPTED_METHODS & READ_ONLY_METHODS


def test_no_signing_or_sending_method_is_forwarded() -> None:
    for method in READ_ONLY_METHODS:
        assert "send" not in method.lower()
        assert "sign" not in method.lower()


def test_no_mandate_or_firewall_methods_are_exposed() -> None:
    # Decision 2 (docs/m3-plan.md): mandates come only from the user, through
    # the capture CLI. The agent's RPC must have no way to create, change,
    # select or even list them.
    for method in INTERCEPTED_METHODS | READ_ONLY_METHODS:
        assert not method.lower().startswith(("mandate", "firewall")), method
        assert classify("mandate_" + method) is MethodClass.DENY
        assert classify("firewall_" + method) is MethodClass.DENY
