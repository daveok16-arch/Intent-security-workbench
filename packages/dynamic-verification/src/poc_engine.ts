/**
 * PoC Generation and Lifecycle Engine
 * Intent Security Workbench - Phase 5
 *
 * Requirements:
 * - Implement PoC generation separately from PoC execution.
 * - States:
 *   - GENERATED: PoC constructed / generated
 *   - EXECUTED: Dispatched against controlled environment
 *   - REPRODUCED: Observed expected state transition
 *   - NOT_REPRODUCED: Operation failed/reverted or state did not change as expected
 * - Never skip states.
 */

import crypto from 'crypto';
import { PoCArtifact, PoCState, DynamicReproductionResult } from './types.js';

export class PoCEngine {
  /**
   * Step 1: Generate PoC artifact (State: GENERATED)
   */
  static generatePoC(params: {
    runtime: 'EVM' | 'CLARITY' | 'HTTP' | string;
    payload_content: string;
    format: 'FOUNDRY_TEST' | 'CLARINET_TEST' | 'CURL' | 'CUSTOM_SCRIPT';
  }): PoCArtifact {
    const id = `poc-${crypto.randomBytes(8).toString('hex')}`;
    const payload_sha256 = crypto.createHash('sha256').update(params.payload_content, 'utf-8').digest('hex');
    return {
      id,
      state: 'GENERATED',
      runtime: params.runtime,
      payload_content: params.payload_content,
      payload_sha256,
      format: params.format,
      created_at: new Date().toISOString(),
    };
  }

  /**
   * Step 2: Mark PoC as executed against an isolated target (State: EXECUTED)
   */
  static markExecuted(poc: PoCArtifact): PoCArtifact {
    if (poc.state !== 'GENERATED') {
      throw new Error(`Invalid PoC state transition: Cannot mark '${poc.state}' as EXECUTED.`);
    }

    return {
      ...poc,
      state: 'EXECUTED',
      executed_at: new Date().toISOString(),
    };
  }

  /**
   * Step 3: Record reproduction outcome from actual runtime execution (State: REPRODUCED | NOT_REPRODUCED)
   */
  static recordOutcome(
    poc: PoCArtifact,
    result: DynamicReproductionResult
  ): PoCArtifact {
    if (poc.state !== 'EXECUTED') {
      throw new Error(`Invalid PoC state transition: Must execute PoC before recording reproduction outcome (current state: '${poc.state}').`);
    }

    const state: PoCState = result === 'REPRODUCED' ? 'REPRODUCED' : 'NOT_REPRODUCED';

    return {
      ...poc,
      state,
      reproduced_at: new Date().toISOString(),
      execution_result: result,
    };
  }

  /**
   * Generate Solidity / Foundry test fixture PoC code
   */
  static generateFoundryPoC(
    contractName: string,
    operationName: string,
    attackerAddress: string,
    victimAddress: string,
    amount: string | number
  ): string {
    return `// SPDX-License-Identifier: MIT
// AUTOMATICALLY GENERATED RESEARCH PROOF-OF-CONCEPT
// Target: ${contractName}.${operationName}
// Attacker: ${attackerAddress}
// Victim: ${victimAddress}

pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract ${contractName}PoCTest is Test {
    address internal attacker = ${attackerAddress};
    address internal victim = ${victimAddress};

    function test_exploit_witness() public {
        vm.prank(attacker);
        // Dispatch candidate call
    }
}
`;
  }
}
