"""Decode calldata against a small, fixed registry of function signatures.

Calldata layout (Solidity ABI):
    selector (4 bytes) = keccak256("transfer(address,uint256)")[:4]
    then one 32-byte word per static argument (address and uint256 here).

Two deliberate choices:
- Only selectors we register are decoded. Public selector databases accept any
  name, and selectors are only 4 bytes, so an attacker can find an innocent-looking
  signature that collides with a dangerous one. Unknown means unknown.
- A matching selector says nothing about the target contract. Any contract can
  implement transfer(address,uint256) to do anything. Decoding is for logging and
  explanation; the verifier will trust simulated effects instead.
"""

from dataclasses import dataclass

from eth_utils import keccak, to_checksum_address

from mandate_firewall.models import CallKind, DecodedArg, DecodedCall

WORD = 32
SELECTOR_LEN = 4
_SUPPORTED_TYPES = {"address", "uint256"}


@dataclass(frozen=True)
class FunctionSpec:
    signature: str
    params: tuple[tuple[str, str], ...]  # (name, abi_type); static types only

    def __post_init__(self) -> None:
        # The decoder below only handles fixed-size 32-byte arguments.
        unsupported = [t for _, t in self.params if t not in _SUPPORTED_TYPES]
        if unsupported:
            raise ValueError(f"{self.signature}: unsupported argument types {unsupported}")

    @property
    def selector(self) -> bytes:
        return keccak(text=self.signature)[:SELECTOR_LEN]


ERC20_FUNCTIONS = (
    FunctionSpec("transfer(address,uint256)", (("to", "address"), ("amount", "uint256"))),
    FunctionSpec("approve(address,uint256)", (("spender", "address"), ("amount", "uint256"))),
    FunctionSpec(
        "transferFrom(address,address,uint256)",
        (("from", "address"), ("to", "address"), ("amount", "uint256")),
    ),
)

KNOWN_FUNCTIONS: dict[bytes, FunctionSpec] = {spec.selector: spec for spec in ERC20_FUNCTIONS}


class CalldataDecodeError(ValueError):
    pass


def decode_calldata(data: bytes) -> DecodedCall:
    """Classify and, if the selector is registered, decode a call's arguments.

    Never raises: malformed input is reported as CallKind.MALFORMED so the
    caller can log it and decide (the verifier will fail closed on it).
    """
    if not data:
        return DecodedCall(kind=CallKind.EMPTY)
    if len(data) < SELECTOR_LEN:
        # Solidity routes this to the fallback function; there is no selector.
        return DecodedCall(
            kind=CallKind.MALFORMED, error=f"calldata shorter than a selector ({len(data)} bytes)"
        )

    selector, body = data[:SELECTOR_LEN], data[SELECTOR_LEN:]
    selector_hex = "0x" + selector.hex()
    spec = KNOWN_FUNCTIONS.get(selector)
    if spec is None:
        return DecodedCall(kind=CallKind.UNKNOWN_SELECTOR, selector=selector_hex)

    try:
        args = _decode_static_args(spec, body)
    except CalldataDecodeError as exc:
        return DecodedCall(
            kind=CallKind.MALFORMED,
            selector=selector_hex,
            signature=spec.signature,
            error=str(exc),
        )

    return DecodedCall(
        kind=CallKind.KNOWN,
        selector=selector_hex,
        signature=spec.signature,
        args=args,
        trailing_bytes=len(body) - WORD * len(spec.params),
    )


def _decode_static_args(spec: FunctionSpec, body: bytes) -> tuple[DecodedArg, ...]:
    needed = WORD * len(spec.params)
    if len(body) < needed:
        raise CalldataDecodeError(f"expected {needed} argument bytes, got {len(body)}")
    # Extra bytes after the arguments are ignored by Solidity, so the call still
    # executes; the caller records them as trailing_bytes rather than rejecting.

    args = []
    for i, (name, abi_type) in enumerate(spec.params):
        word = body[i * WORD : (i + 1) * WORD]
        value: int | str
        if abi_type == "address":
            # Addresses are 20 bytes left-padded with 12 zero bytes. Modern Solidity
            # reverts on dirty padding; old compilers silently drop it. Either way the
            # meaning is ambiguous, so we refuse to decode it.
            if word[:12] != b"\x00" * 12:
                raise CalldataDecodeError(f"argument {name!r} has non-zero address padding")
            value = to_checksum_address(word[12:])
        else:
            value = int.from_bytes(word, "big")
        args.append(DecodedArg(name=name, abi_type=abi_type, value=value))
    return tuple(args)
