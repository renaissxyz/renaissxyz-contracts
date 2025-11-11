// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock ERC20 token for testing with EIP-2612 permit support and EIP-3009 meta-transactions
// Based on Circle's USDC implementation
contract MockERC20 is ERC20 {
    uint8 private _decimals;

    constructor(string memory name, string memory symbol, uint8 decimals_, uint256 _initialSupply)
        ERC20(name, symbol)
    {
        _mint(msg.sender, _initialSupply);
        _decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }
}
