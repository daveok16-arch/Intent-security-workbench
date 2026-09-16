// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Vulnerable BOLA Test Fixture (EVM / Solidity)
 * Intent Security Workbench - Phase 5
 *
 * Vulnerability:
 * The 'redeem' function accepts an arbitrary 'owner' parameter and transfers funds
 * from that owner's balance to the caller without verifying that msg.sender == owner
 * or that msg.sender has an operator allowance.
 */
contract VaultVulnerable {
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Redeemed(address indexed owner, address indexed recipient, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // VULNERABLE BOLA: Missing authorization check between msg.sender and owner
    function redeem(address owner, uint256 amount) external {
        require(balances[owner] >= amount, "Insufficient balance");
        balances[owner] -= amount;
        balances[msg.sender] += amount;
        emit Redeemed(owner, msg.sender, amount);
    }
}
