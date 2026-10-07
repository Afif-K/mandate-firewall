// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// Forwards the ETH it receives: an ETH move that only the call trace shows.
/// The transaction's `to` and `value` say "1 ETH to the forwarder".
contract EthForwarder {
    function forward(address payable to) external payable {
        (bool ok,) = to.call{value: msg.value}("");
        require(ok, "forward failed");
    }
}
