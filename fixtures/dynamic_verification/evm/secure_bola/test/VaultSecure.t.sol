// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/VaultSecure.sol";

contract VaultSecureTest is Test {
    VaultSecure internal vault;
    address internal victim = address(0xAAAA1111);
    address internal attacker = address(0xBBBB2222);

    function setUp() public {
        vault = new VaultSecure();

        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);

        vm.prank(victim);
        vault.deposit{value: 5 ether}();
    }

    /**
     * Secure Negative Test:
     * - Attacker attempts unauthorized redeem
     * - Call is rejected / reverted with UNAUTHORIZED
     * - Protected state remains completely unchanged!
     */
    function test_unauthorized_redeem_reverts_and_protects_state() public {
        uint256 victimBefore = vault.balances(victim);
        uint256 attackerBefore = vault.balances(attacker);

        assertEq(victimBefore, 5 ether);
        assertEq(attackerBefore, 0);

        // Attempt unauthorized redeem
        vm.prank(attacker);
        vm.expectRevert(bytes("UNAUTHORIZED: Caller is not resource owner"));
        vault.redeem(victim, 2 ether);

        // Confirm protected state is untouched
        uint256 victimAfter = vault.balances(victim);
        uint256 attackerAfter = vault.balances(attacker);

        assertEq(victimAfter, victimBefore, "Victim balance must remain unchanged");
        assertEq(attackerAfter, attackerBefore, "Attacker balance must remain unchanged");
    }

    /**
     * Secure Positive Baseline:
     * - Legitimate owner redeems own funds
     * - Operation succeeds
     */
    function test_authorized_owner_redeem_succeeds() public {
        uint256 victimBefore = vault.balances(victim);

        vm.prank(victim);
        vault.redeem(victim, 1 ether);

        uint256 victimAfter = vault.balances(victim);
        assertEq(victimAfter, 5 ether, "Balance unchanged after self-redemption");
    }

    function testUnauthorizedWithdrawReverts() public {
        test_unauthorized_redeem_reverts_and_protects_state();
    }
}
