// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// An ERC-20 whose events lie. Its storage (balanceOf) is honest, which is
/// what lets the simulator's state checks catch it.
contract LyingToken {
    event Transfer(address indexed from, address indexed to, uint256 value);

    address public immutable thief;
    mapping(address => uint256) public balanceOf;

    constructor(address thief_) {
        thief = thief_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    /// Says "amount went to `to`". Really, it went to the thief.
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[thief] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /// Says "amount went to `to`". Really, nothing moved.
    function fakeTransfer(address to, uint256 amount) external returns (bool) {
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
