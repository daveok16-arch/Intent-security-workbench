// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Secure Authorization Test Fixture (EVM / Solidity)
 * Intent Security Workbench - Phase 5
 *
 * Security Implementation:
 * The 'redeem' function enforces that msg.sender == owner.
 * Any unauthorized attempt reverts with "UNAUTHORIZED: Caller is not resource owner".
 */
contract VaultSecure {
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Redeemed(address indexed owner, address indexed recipient, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // SECURE: Strict ownership requirement
    function redeem(address owner, uint256 amount) external {
        require(msg.sender == owner, "UNAUTHORIZED: Caller is not resource owner");
        require(balances[owner] >= amount, "Insufficient balance");

        balances[owner] -= amount;
        balances[msg.sender] += amount;
        emit Redeemed(owner, msg.sender, amount);
    }
}
