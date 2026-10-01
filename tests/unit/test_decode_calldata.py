import pytest
from eth_abi import encode
from eth_utils import keccak, to_checksum_address

from mandate_firewall.decode.calldata import KNOWN_FUNCTIONS, FunctionSpec, decode_calldata
from mandate_firewall.models import CallKind

SPENDER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BEEF = to_checksum_address("0x" + "beef" * 10)
ONE_TOKEN = 10**18
MAX_UINT256 = 2**256 - 1


def calldata(signature: str, types: list[str], values: list[object]) -> bytes:
    """Encode with eth_abi, independently of the decoder under test."""
    return keccak(text=signature)[:4] + encode(types, values)


def args_of(data: bytes) -> dict[str, int | str]:
    return {arg.name: arg.value for arg in decode_calldata(data).args}


# --- registry -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("selector", "signature"),
    [
        ("a9059cbb", "transfer(address,uint256)"),
        ("095ea7b3", "approve(address,uint256)"),
        ("23b872dd", "transferFrom(address,address,uint256)"),
    ],
)
def test_registry_selectors_match_well_known_values(selector: str, signature: str) -> None:
    assert KNOWN_FUNCTIONS[bytes.fromhex(selector)].signature == signature


def test_function_spec_rejects_dynamic_types() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        FunctionSpec("swap(bytes)", (("path", "bytes"),))


# --- known functions ------------------------------------------------------------


def test_decodes_transfer() -> None:
    data = calldata("transfer(address,uint256)", ["address", "uint256"], [BEEF, ONE_TOKEN])
    decoded = decode_calldata(data)

    assert decoded.kind is CallKind.KNOWN
    assert decoded.selector == "0xa9059cbb"
    assert decoded.signature == "transfer(address,uint256)"
    assert args_of(data) == {"to": BEEF, "amount": ONE_TOKEN}
    assert decoded.trailing_bytes == 0


def test_decodes_unlimited_approve() -> None:
    # The classic drainer pattern: approve(attacker, 2**256 - 1).
    data = calldata("approve(address,uint256)", ["address", "uint256"], [SPENDER, MAX_UINT256])
    assert decode_calldata(data).kind is CallKind.KNOWN
    assert args_of(data) == {"spender": SPENDER, "amount": MAX_UINT256}


def test_decodes_transfer_from() -> None:
    data = calldata(
        "transferFrom(address,address,uint256)",
        ["address", "address", "uint256"],
        [SPENDER, BEEF, 5],
    )
    assert args_of(data) == {"from": SPENDER, "to": BEEF, "amount": 5}


def test_records_trailing_bytes_instead_of_rejecting() -> None:
    # Solidity ignores extra calldata, so the call still executes as a transfer.
    # Some tooling appends attribution suffixes; we record them rather than fail.
    base = calldata("transfer(address,uint256)", ["address", "uint256"], [BEEF, 1])
    decoded = decode_calldata(base + b"\xde\xad\xbe\xef")
    assert decoded.kind is CallKind.KNOWN
    assert decoded.trailing_bytes == 4


# --- everything else ------------------------------------------------------------


def test_empty_calldata() -> None:
    assert decode_calldata(b"").kind is CallKind.EMPTY


def test_unknown_selector_is_not_guessed() -> None:
    data = calldata("mint(address,uint256)", ["address", "uint256"], [BEEF, 1])
    decoded = decode_calldata(data)
    assert decoded.kind is CallKind.UNKNOWN_SELECTOR
    assert decoded.selector == "0x" + data[:4].hex()
    assert decoded.signature is None
    assert decoded.args == ()


@pytest.mark.parametrize("data", [b"\xa9", b"\xa9\x05\x9c"])
def test_shorter_than_selector_is_malformed(data: bytes) -> None:
    assert decode_calldata(data).kind is CallKind.MALFORMED


def test_truncated_arguments_are_malformed() -> None:
    data = calldata("transfer(address,uint256)", ["address", "uint256"], [BEEF, 1])[:-1]
    decoded = decode_calldata(data)
    assert decoded.kind is CallKind.MALFORMED
    assert decoded.signature == "transfer(address,uint256)"
    assert "expected 64" in (decoded.error or "")


def test_dirty_address_padding_is_malformed() -> None:
    """Old compilers drop the high 12 bytes, new ones revert; two readings of the
    same bytes means we refuse to give either one."""
    selector = keccak(text="transfer(address,uint256)")[:4]
    dirty_address_word = b"\xff" * 12 + bytes.fromhex(BEEF[2:])
    data = selector + dirty_address_word + (1).to_bytes(32, "big")
    decoded = decode_calldata(data)
    assert decoded.kind is CallKind.MALFORMED
    assert "padding" in (decoded.error or "")
