// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// MockERC20 plus EIP-2612 `permit`: an approval made by an off-chain
/// signature instead of a transaction from the owner.
///
/// It exists for the v0.1 scenario suite's off-chain signature row
/// (docs/v0.1-plan.md, scenario M2; THREAT_MODEL.md "Off-chain signatures").
/// The agent only signs a typed-data message. The attacker submits `permit`
/// and then `transferFrom` from its own account, so the agent never sends a
/// transaction and the firewall's proxy never sees one.
///
/// Like a real EIP-2612 token: the domain is (name, version "1", chain id,
/// this contract), a nonce per owner makes each signature usable once, a
/// deadline bounds it in time, and high-s signatures are refused (each
/// signature has a single valid form). The domain separator is computed on
/// every call, so it stays right on a fork with a different chain id.
contract MockERC20Permit {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    string public constant name = "Mock Permit Token";
    string public constant version = "1";
    uint8 public constant decimals = 6;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    // secp256k1 order / 2: an s above this has a twin (n - s) that verifies too.
    uint256 private constant HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    /// Sets allowance[owner][spender] = value if `owner` signed exactly this
    /// permit with its current nonce. Anyone may submit it.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "permit expired");
        require(uint256(s) <= HALF_ORDER, "invalid signature s");
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == owner, "invalid signature");
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
