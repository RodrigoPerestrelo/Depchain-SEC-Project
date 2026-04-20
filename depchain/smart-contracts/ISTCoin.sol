// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ISTCoin is ERC20 {

    // Set token name, symbol and initial supply
    constructor(address[] memory initialOwners) ERC20("IST Coin", "IST") {
        require(initialOwners.length > 0, "At least one owner required");
        uint256 total = 100000000 * 10 ** 2; // 100M tokens considering 2 decimals (100,000,000 * 10^2)
        uint256 share = total / initialOwners.length;
        
        for(uint i=0; i < initialOwners.length; i++) {
            _mint(initialOwners[i], share);
        }
    }

    // Override default decimals (default is 18)
    function decimals() public view virtual override returns (uint8) {
        return 2;
    }

    // Mitigate frontrunning by forcing allowance to 0 first
    function approve(address spender, uint256 value) public override returns (bool) {
        require(value == 0 || allowance(msg.sender, spender) == 0, "ISTCoin: reset allowance to 0 first");
        return super.approve(spender, value);
    }

    // Safe alternative to increase allowance
    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        address owner = msg.sender;
        _approve(owner, spender, allowance(owner, spender) + addedValue);
        return true;
    }

    // Safe alternative to decrease allowance
    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
        address owner = msg.sender;
        uint256 currentAllowance = allowance(owner, spender);
        require(currentAllowance >= subtractedValue, "ISTCoin: decreased allowance below zero");

        _approve(owner, spender, currentAllowance - subtractedValue);
        return true;
    }
}