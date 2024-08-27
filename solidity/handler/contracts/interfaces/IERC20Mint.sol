// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @dev Extension of {ERC20} that allows token holders to destroy both their own
 * tokens and those that they have an allowance for, in a way that can be
 * recognized off-chain (via event analysis).
 */
interface IERC20Mint {
    /**
     * @dev Mint a `value` amount of tokens from the caller.
     *
     * See {ERC20-_mint}.
     */
    function mint(uint256 value) external;

    /**
     * @dev Mint a `value` amount of tokens from `account`, deducting from
     * the caller's allowance.
     *
     * See {ERC20-_mint} and {ERC20-allowance}.
     *
     * Requirements:
     *
     * - the caller must have allowance for ``accounts``'s tokens of at least
     * `value`.
     */
    function mint_to(address account, uint256 value) external;
}
