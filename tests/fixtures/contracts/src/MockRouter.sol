// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// A swap router for tests, shaped like Uniswap's SwapRouter02 where it
/// matters to the firewall (docs/m4-plan.md §6, §7):
///
/// - exactInputSingle takes a `recipient`, so the output can go anywhere.
///   recipient = attacker is the within-policy, off-mandate attack: right
///   router, right token, right amount, wrong destination.
/// - pull and sweepToken work like SwapRouter02's PeripheryPaymentsExtended:
///   pull moves the caller's approved tokens into the router; sweepToken
///   sends the router's whole balance of a token to anyone. With multicall
///   they make the pull + sweep drain: sell 100, swap 1 unit, sweep the rest.
/// - multicall runs several of these in one transaction, with msg.sender
///   kept (delegatecall to itself).
///
/// Unlike SwapRouter02 it is its own liquidity: it pays out of its own
/// balance of tokenOut (mint some to it first) at a fixed rate per pair,
/// amountOut = amountIn * numerator / denominator, rounded down. Anyone can
/// set the rate, so a test can play a manipulated price.
///
/// It emits no events. The firewall escalates unrecognized events that
/// mention the principal (verify/flows.py), so a "Swapped(sender, ...)" event
/// would make every honest swap escalate. The only logs are the tokens' own
/// Transfer and Approval events.
contract MockRouter {
    struct Rate {
        uint256 numerator;
        uint256 denominator;
    }

    mapping(address => mapping(address => Rate)) public rates; // tokenIn => tokenOut => rate

    function setRate(address tokenIn, address tokenOut, uint256 numerator, uint256 denominator)
        external
    {
        require(denominator != 0, "zero denominator");
        rates[tokenIn][tokenOut] = Rate(numerator, denominator);
    }

    function quote(address tokenIn, address tokenOut, uint256 amountIn)
        public
        view
        returns (uint256)
    {
        Rate memory rate = rates[tokenIn][tokenOut];
        require(rate.denominator != 0, "no rate");
        return amountIn * rate.numerator / rate.denominator;
    }

    /// Takes amountIn of tokenIn from the caller and sends the output to
    /// `recipient`. Reverts below amountOutMinimum, like SwapRouter02.
    function exactInputSingle(
        address tokenIn,
        address tokenOut,
        address recipient,
        uint256 amountIn,
        uint256 amountOutMinimum
    ) external returns (uint256 amountOut) {
        amountOut = quote(tokenIn, tokenOut, amountIn);
        require(amountOut >= amountOutMinimum, "too little received");
        require(IERC20Like(tokenIn).transferFrom(msg.sender, address(this), amountIn), "pay");
        require(IERC20Like(tokenOut).transfer(recipient, amountOut), "payout");
    }

    /// Moves `value` of the caller's tokens into the router (needs an approval).
    function pull(address token, uint256 value) external {
        require(IERC20Like(token).transferFrom(msg.sender, address(this), value), "pull");
    }

    /// Sends the router's whole balance of `token` to `recipient`. Anyone may
    /// call it: tokens sitting in the router belong to whoever sweeps first.
    function sweepToken(address token, uint256 amountMinimum, address recipient) external {
        uint256 balance = IERC20Like(token).balanceOf(address(this));
        require(balance >= amountMinimum, "insufficient token");
        if (balance > 0) {
            require(IERC20Like(token).transfer(recipient, balance), "sweep");
        }
    }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory result) = address(this).delegatecall(data[i]);
            if (!ok) {
                assembly {
                    revert(add(result, 32), mload(result)) // bubble up the reason
                }
            }
            results[i] = result;
        }
    }
}
