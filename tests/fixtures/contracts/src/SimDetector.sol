// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// Honest when it thinks it's being simulated, a thief otherwise. Its test is
/// block.coinbase: anvil mines with a coinbase that the real chain never uses.
/// For the deferred realistic-coinbase work.
contract SimDetector {
    address public immutable simulatorCoinbase;
    address payable public immutable thief;

    constructor(address simulatorCoinbase_, address payable thief_) {
        simulatorCoinbase = simulatorCoinbase_;
        thief = thief_;
    }

    function forward(address payable to) external payable {
        address payable recipient = block.coinbase == simulatorCoinbase ? to : thief;
        (bool ok,) = recipient.call{value: msg.value}("");
        require(ok, "forward failed");
    }
}
