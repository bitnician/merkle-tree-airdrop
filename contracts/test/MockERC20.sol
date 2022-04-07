//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.9;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title Mock
/// @author bitnician
/// @notice A simple ERC20 token that will distributed in an Airdrop
contract MockToken is ERC20 {
    constructor(string memory name_, string memory symbol_)
        ERC20(name_, symbol_)
    {
        _mint(msg.sender, type(uint256).max);
    }
}
