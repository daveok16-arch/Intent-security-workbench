#!/usr/bin/env tsx
/**
 * Intent Security Workbench CLI
 * Phase 0 & Phase 1 Scope & Target Authorization CLI
 *
 * Usage:
 *   intent programs list
 *   intent programs show <program_id>
 *   intent targets list [program_id]
 *   intent targets show <target_id>
 *   intent scope list [program_id]
 *   intent scope evaluate <target_id>
 *   intent source acquire <target_id>
 *   intent source verify <target_id>
 *   intent gate check <investigation_id>
 *   intent analyze static <investigation_id>
 *   intent analyze treesitter <investigation_id>
 *   intent analyze semgrep <investigation_id>
 *   intent candidates list [investigation_id]
 *   intent candidates show <candidate_id>
 *   intent rules list
 *   intent rules show <rule_id>
 *   intent engines list
 *   intent engines check [engine_id]
 *   intent evidence list [investigation_id]
 *   intent evidence show <artifact_id>
 *   intent evidence verify <artifact_id>
 *   intent provenance <investigation_id>
 *   intent events list [investigation_id]
 */

import { globalEngineRegistry } from './engines/engine_registry.js';
import { EngineAvailabilityStatus } from './engines/types.js';
import { globalDB } from './apps/api/db_store.js';
import { globalJobOrchestrator } from './packages/orchestrator/src/index.js';
import {
  globalTreeSitterService,
  globalSemgrepService,
  globalCandidateStore,
  globalSecurityRuleRegistry,
  executeStaticAnalysisPipeline,
} from './packages/static-analysis/src/index.js';
import { globalAPIAnalysisOrchestrator } from './packages/api-analysis/src/index.js';
import {
  globalFormalVerificationService,
  FormalModelBuilder,
  STANDARD_PROPERTIES,
  getStandardProperty,
  Z3Detector,
  VerificationStatus,
} from './packages/formal-verification/src/index.js';
import {
  globalDynamicVerificationService,
  ToolDetector,
  TargetValidator,
  FoundryAdapter,
  ClarinetAdapter,
  APIAdapter,
  StateDiffer,
} from './packages/dynamic-verification/src/index.js';

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const subcommand = args[1];
  const param = args[2];

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    process.exit(0);
  }

  if (command === 'programs') {
    if (!subcommand || subcommand === 'list') {
      handleProgramsList();
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: program_id required. Usage: intent programs show <program_id>');
        process.exit(1);
      }
      handleProgramShow(param);
    } else {
      console.error(`Unknown programs subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'targets') {
    if (!subcommand || subcommand === 'list') {
      handleTargetsList(param);
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent targets show <target_id>');
        process.exit(1);
      }
      handleTargetShow(param);
    } else {
      console.error(`Unknown targets subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'scope') {
    if (!subcommand || subcommand === 'list') {
      handleScopeList(param);
    } else if (subcommand === 'evaluate') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent scope evaluate <target_id>');
        process.exit(1);
      }
      handleScopeEvaluate(param);
    } else {
      console.error(`Unknown scope subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'source') {
    if (subcommand === 'acquire') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent source acquire <target_id>');
        process.exit(1);
      }
      await handleSourceAcquire(param);
    } else if (subcommand === 'status') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent source status <target_id>');
        process.exit(1);
      }
      handleSourceStatus(param);
    } else if (subcommand === 'verify') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent source verify <target_id>');
        process.exit(1);
      }
      await handleSourceVerify(param);
    } else {
      console.error(`Unknown source subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'gate') {
    if (subcommand === 'check' || subcommand === 'evaluate') {
      if (!param) {
        console.error('Error: investigation_id required. Usage: intent gate check <investigation_id>');
        process.exit(1);
      }
      handleGateCheck(param);
    } else {
      console.error(`Unknown gate subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'engines') {
    if (!subcommand || subcommand === 'list') {
      await handleEnginesList();
    } else if (subcommand === 'check') {
      if (param) {
        await handleEngineCheck(param);
      } else {
        await handleEnginesCheckAll();
      }
    } else {
      console.error(`Unknown engines subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'evidence') {
    if (!subcommand || subcommand === 'list') {
      await handleEvidenceList(param);
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: artifact_id is required. Usage: intent evidence show <artifact_id>');
        process.exit(1);
      }
      await handleEvidenceShow(param);
    } else if (subcommand === 'verify') {
      if (!param) {
        console.error('Error: artifact_id is required. Usage: intent evidence verify <artifact_id>');
        process.exit(1);
      }
      await handleEvidenceVerify(param);
    } else {
      console.error(`Unknown evidence subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'provenance') {
    const invId = subcommand;
    if (!invId) {
      console.error('Error: investigation_id is required. Usage: intent provenance <investigation_id>');
      process.exit(1);
    }
    await handleProvenance(invId);
  } else if (command === 'events') {
    await handleEventsList(subcommand);
  } else if (command === 'analyze') {
    if (!subcommand) {
      console.error('Error: analysis type required. Usage: intent analyze <static|treesitter|semgrep> <investigation_id>');
      process.exit(1);
    }
    await handleAnalyze(subcommand, param);
  } else if (command === 'candidates') {
    if (!subcommand || subcommand === 'list') {
      handleCandidatesList(param);
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: candidate_id is required. Usage: intent candidates show <candidate_id>');
        process.exit(1);
      }
      handleCandidateShow(param);
    } else if (subcommand === 'verify') {
      if (!param) {
        console.error('Error: candidate_id is required. Usage: intent candidates verify <candidate_id>');
        process.exit(1);
      }
      await handleCandidateVerify(param, args[3]);
    } else {
      console.error(`Unknown candidates subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'rules') {
    if (!subcommand || subcommand === 'list') {
      handleRulesList();
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: rule_id is required. Usage: intent rules show <rule_id>');
        process.exit(1);
      }
      handleRuleShow(param);
    } else {
      console.error(`Unknown rules subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'api') {
    if (subcommand === 'contracts') {
      if (!param) {
        console.error('Error: investigation_id required. Usage: intent api contracts <investigation_id>');
        process.exit(1);
      }
      handleApiContracts(param);
    } else if (subcommand === 'endpoints') {
      if (!param) {
        console.error('Error: contract_id required. Usage: intent api endpoints <contract_id>');
        process.exit(1);
      }
      handleApiEndpoints(param);
    } else if (subcommand === 'auth') {
      if (!param) {
        console.error('Error: investigation_id required. Usage: intent api auth <investigation_id>');
        process.exit(1);
      }
      handleApiAuth(param);
    } else if (subcommand === 'diff') {
      if (!param) {
        console.error('Error: investigation_id required. Usage: intent api diff <investigation_id>');
        process.exit(1);
      }
      handleApiDiff(param);
    } else {
      console.error(`Unknown api subcommand: '${subcommand}'. Valid: contracts, endpoints, auth, diff`);
      process.exit(1);
    }
  } else if (command === 'verify') {
    if (subcommand === 'formal') {
      const action = param;
      const extraArg = args[3];
      await handleVerifyFormal(action, extraArg, args.slice(2));
    } else if (subcommand === 'dynamic') {
      const action = param;
      const extraArg = args[3];
      await handleVerifyDynamic(action, extraArg, args.slice(2));
    } else {
      console.error(`Unknown verify subcommand: '${subcommand}'. Valid: formal, dynamic`);
      process.exit(1);
    }
  } else if (command === 'tools') {
    if (!subcommand || subcommand === 'dynamic' || subcommand === 'list') {
      handleToolsDynamic();
    } else {
      console.error(`Unknown tools subcommand: '${subcommand}'. Valid: dynamic, list`);
      process.exit(1);
    }
  } else {
    console.error(`Unknown command: '${command}'`);
    printHelp();
    process.exit(1);
  }
}

function printHelp() {
  console.log(`
INTENT SECURITY WORKBENCH CLI (Phase 4 Formal Verification)

Program & Scope Commands:
  intent programs list                  List registered security programs
  intent programs show <program_id>     Show program policy, status, and scope entries
  intent targets list [program_id]      List targets
  intent targets show <target_id>       Show target details, scope status, and snapshots
  intent scope list [program_id]        List normalized scope entries
  intent scope evaluate <target_id>     Execute deterministic scope evaluation with provenance
  intent source acquire <target_id>     Execute sandboxed Git clone/checkout & SHA-256 tree hashing
  intent source status <target_id>      Display source acquisition status and snapshot metadata
  intent source verify <target_id>      Verify local snapshot tree hash against stored digest
  intent gate check <investigation_id>  Pre-flight gate check (Authorization, Scope, Source, Policy)

Static & Structural Analysis Commands:
  intent analyze static <inv_id>        Execute unified Tree-sitter + Semgrep static analysis
  intent analyze treesitter <inv_id>    Execute Tree-sitter concrete syntax tree queries
  intent analyze semgrep <inv_id>       Execute Semgrep rule-based taint and pattern scan
  intent candidates list [inv_id]       List all candidate findings and verification states
  intent candidates show <cand_id>      Display detailed candidate finding, evidence & provenance
  intent rules list                     List data-driven static analysis security rules
  intent rules show <rule_id>           Show rule definition, pattern, CWE, and OWASP mapping

API & BOLA Analysis Commands:
  intent api contracts <inv_id>         List OpenAPI contracts parsed for investigation
  intent api endpoints <contract_id>    Display normalized endpoints, auth status & object params
  intent api auth <inv_id>              List BOLA authorization candidate findings
  intent api diff <inv_id>              Compare documented OpenAPI contract vs source code

Formal Verification Commands (Phase 4 - Real Z3):
  intent verify formal <inv_id>             Execute Z3 formal verification on security properties
  intent verify formal list <inv_id>        List formal verification results for an investigation
  intent verify formal show <result_id>     Display formal verification result, solver, and status
  intent verify formal model <result_id>    Display formal model variables, assumptions, and SMT-LIB2 input
  intent verify formal counterexample <id>  Display formal counterexample variable assignments

Dynamic Verification & Exploit-Witness Commands (Phase 5 - Real Foundry/Clarinet):
  intent verify dynamic <inv_id> [runtime]  Execute dynamic reproduction attempt
  intent verify dynamic list <inv_id>       List dynamic verification jobs
  intent verify dynamic show <job_id>       Display job details, reproduction verdict, and metrics
  intent verify dynamic trace <job_id>      Display execution trace and call sequence
  intent verify dynamic state <job_id>      Display before/after state diff and mutated fields
  intent verify dynamic evidence <job_id>   Display immutable evidence artifacts (stdout, stderr, trace)
  intent candidates verify <cand_id>        Verify an authorization candidate finding dynamically
  intent tools dynamic                      Display status of dynamic execution binaries (forge, anvil, clarinet)

Engine Commands:
  intent engines list                   List registered engines and verified host availability
  intent engines check                  Execute real-time availability check across all engines
  intent engines check <engine_id>      Verify binary availability for a specific engine

Evidence & Provenance Commands:
  intent evidence list [inv_id]         List evidence artifacts
  intent evidence show <artifact_id>    Display detailed metadata and raw preview of an artifact
  intent evidence verify <artifact_id>  Compute actual SHA-256 and cryptographically verify integrity
  intent provenance <inv_id>            Traverse and display the complete investigation provenance graph
  intent events list [inv_id]           List immutable audit event trail
`);
}

function handleProgramsList() {
  const programs = globalDB.listPrograms();
  console.log('\nINTENT SECURITY WORKBENCH — SECURITY PROGRAMS');
  console.log('='.repeat(95));
  console.log(
    rpad('Program ID', 22) +
    rpad('Platform', 16) +
    rpad('Status', 12) +
    rpad('Scope Count', 14) +
    rpad('Name', 30)
  );
  console.log('-'.repeat(95));
  if (programs.length === 0) {
    console.log('(No programs registered)');
  } else {
    for (const prog of programs) {
      const scopeCount = globalDB.listScopeEntries(prog.id).length;
      console.log(
        rpad(prog.id, 22) +
        rpad(prog.platform, 16) +
        rpad(prog.status || 'ACTIVE', 12) +
        rpad(String(scopeCount), 14) +
        rpad(prog.name, 30)
      );
    }
  }
  console.log('-'.repeat(95));
  console.log(`Total Programs: ${programs.length}\n`);
}

function handleProgramShow(programId: string) {
  const prog = globalDB.getProgram(programId);
  if (!prog) {
    console.error(`Error: Program '${programId}' not found.`);
    process.exit(1);
  }
  const scope = globalDB.listScopeEntries(programId);

  console.log('\nPROGRAM RECORD');
  console.log('----------------------------------------------------');
  console.log(`ID:               ${prog.id}`);
  console.log(`Name:             ${prog.name}`);
  console.log(`Platform:         ${prog.platform}`);
  console.log(`Status:           ${prog.status}`);
  console.log(`Policy Version:   ${prog.policy_version}`);
  console.log(`Freshness:        ${prog.freshness_status}`);
  console.log(`Program URL:      ${prog.program_url || '(none)'}`);
  console.log(`Source Reference: ${prog.source_reference || '(none)'}`);
  console.log(`Retrieved At:     ${prog.retrieved_at}`);
  console.log(`Scope Entries:    ${scope.length}`);
  console.log('----------------------------------------------------');
  console.log('Scope Entries:\n');
  for (const s of scope) {
    console.log(`  [${s.inclusion_status}] (${s.asset_type}) ${s.asset_identifier}`);
  }
  console.log('\n');
}

function handleTargetsList(programId?: string) {
  const targets = globalDB.listTargets(programId);
  console.log(`\nINTENT SECURITY WORKBENCH — TARGETS${programId ? ` (Program: ${programId})` : ''}`);
  console.log('='.repeat(105));
  console.log(
    rpad('Target ID', 22) +
    rpad('Type', 16) +
    rpad('Scope Status', 16) +
    rpad('Auth Status', 16) +
    rpad('Source Status', 18) +
    rpad('Name', 17)
  );
  console.log('-'.repeat(105));
  if (targets.length === 0) {
    console.log('(No targets registered)');
  } else {
    for (const t of targets) {
      console.log(
        rpad(t.id, 22) +
        rpad(t.target_type, 16) +
        rpad(t.scope_status || 'NOT_EVALUATED', 16) +
        rpad(t.authorization_status || 'NOT_EVALUATED', 16) +
        rpad(t.source_acquisition_status || 'SOURCE_NOT_ACQUIRED', 18) +
        rpad(t.name, 17)
      );
    }
  }
  console.log('-'.repeat(105));
  console.log(`Total Targets: ${targets.length}\n`);
}

function handleTargetShow(targetId: string) {
  const target = globalDB.getTarget(targetId);
  if (!target) {
    console.error(`Error: Target '${targetId}' not found.`);
    process.exit(1);
  }
  const snapshots = globalDB.listSourceSnapshots(targetId);

  console.log('\nTARGET RECORD');
  console.log('----------------------------------------------------');
  console.log(`ID:                   ${target.id}`);
  console.log(`Program ID:           ${target.program_id}`);
  console.log(`Name:                 ${target.name}`);
  console.log(`Type:                 ${target.target_type}`);
  console.log(`Ecosystem:            ${target.ecosystem}`);
  console.log(`Identifier:           ${target.identifier || target.name}`);
  console.log(`Repo URL:             ${target.repository_url || '(none)'}`);
  console.log(`Commit Hash:          ${target.commit_hash || '(none)'}`);
  console.log(`Branch:               ${target.branch || '(none)'}`);
  console.log(`Scope Status:         ${target.scope_status}`);
  console.log(`Auth Status:          ${target.authorization_status}`);
  console.log(`Source Status:        ${target.source_acquisition_status}`);
  console.log(`Source Hash:          ${target.source_hash || '(none)'}`);
  console.log(`Source Snapshots:     ${snapshots.length}`);
  console.log('----------------------------------------------------\n');
}

function handleScopeList(programId?: string) {
  const entries = globalDB.listScopeEntries(programId);
  console.log(`\nINTENT SECURITY WORKBENCH — SCOPE ENTRIES${programId ? ` (Program: ${programId})` : ''}`);
  console.log('='.repeat(100));
  console.log(
    rpad('Entry ID', 22) +
    rpad('Inclusion', 16) +
    rpad('Asset Type', 18) +
    rpad('Asset Identifier', 44)
  );
  console.log('-'.repeat(100));
  if (entries.length === 0) {
    console.log('(No scope entries defined)');
  } else {
    for (const e of entries) {
      console.log(
        rpad(e.id, 22) +
        rpad(e.inclusion_status, 16) +
        rpad(e.asset_type, 18) +
        rpad(e.asset_identifier, 44)
      );
    }
  }
  console.log('-'.repeat(100));
  console.log(`Total Scope Entries: ${entries.length}\n`);
}

function handleScopeEvaluate(targetId: string) {
  console.log(`\n[!] Running deterministic scope evaluation for target '${targetId}'...`);
  try {
    const result = globalDB.evaluateTargetScope(targetId);
    console.log('\nSCOPE DECISION RESULT');
    console.log('----------------------------------------------------');
    console.log(`Decision:          ${result.decision}`);
    console.log(`Reason:            ${result.reason}`);
    console.log(`Evaluator Version: ${result.evaluator_version}`);
    console.log(`Policy Version:    ${result.policy_version}`);
    console.log(`Evaluated At:      ${result.evaluated_at}`);
    if (result.matched_scope_entry) {
      console.log(`Matched Entry:     ${result.matched_scope_entry.id} (${result.matched_scope_entry.asset_identifier})`);
    }
    console.log('----------------------------------------------------\n');
  } catch (err: any) {
    console.error('Evaluation failed:', err.message);
    process.exit(1);
  }
}

async function handleSourceAcquire(targetId: string) {
  console.log(`\n[!] Executing sandboxed Git source acquisition for target '${targetId}'...`);
  try {
    const result = await globalDB.acquireTargetSource(targetId);
    console.log('\nSOURCE ACQUISITION RESULT');
    console.log('----------------------------------------------------');
    console.log(`Success:           ${result.success ? '✔ SUCCESS' : '✖ FAILED'}`);
    console.log(`Resolved Commit:   ${result.resolved_commit_sha || '(none)'}`);
    console.log(`Deterministic Hash:${result.source_hash || '(none)'}`);
    console.log(`File Count:        ${result.file_count ?? 0}`);
    console.log(`Total Bytes:       ${result.total_bytes ?? 0}`);
    console.log(`Execution Time:    ${result.execution_time_ms} ms`);
    if (result.error) {
      console.log(`Error:             ${result.error}`);
    }
    console.log('----------------------------------------------------\n');
  } catch (err: any) {
    console.error('Acquisition failed:', err.message);
    process.exit(1);
  }
}

async function handleSourceVerify(targetId: string) {
  console.log(`\n[!] Verifying source integrity for target '${targetId}'...`);
  try {
    const result = await globalDB.verifyTargetSourceIntegrity(targetId);
    console.log('\nSOURCE INTEGRITY VERIFICATION');
    console.log('----------------------------------------------------');
    console.log(`Verified:          ${result.verified ? '✔ MATCH' : '✖ MISMATCH'}`);
    console.log(`Expected Hash:     ${result.expected_hash || '(none)'}`);
    console.log(`Calculated Hash:   ${result.actual_hash || '(none)'}`);
    if (result.error) {
      console.log(`Error:             ${result.error}`);
    }
    console.log('----------------------------------------------------\n');
  } catch (err: any) {
    console.error('Verification failed:', err.message);
    process.exit(1);
  }
}

function handleSourceStatus(targetId: string) {
  const target = globalDB.getTarget(targetId);
  if (!target) {
    console.error(`Error: Target '${targetId}' not found.`);
    process.exit(1);
  }
  const snapshots = globalDB.listSourceSnapshots(targetId);
  const latestSnapshot = snapshots[0];

  console.log('\nTARGET SOURCE ACQUISITION STATUS');
  console.log('----------------------------------------------------');
  console.log(`Target ID:            ${target.id}`);
  console.log(`Target Name:          ${target.name}`);
  console.log(`Source Status:        ${target.source_acquisition_status}`);
  console.log(`Source Hash:          ${target.source_hash || '(none)'}`);
  console.log(`Commit SHA:           ${target.commit_hash || '(none)'}`);
  console.log(`Branch:               ${target.branch || '(none)'}`);
  console.log(`Repository URL:       ${target.repository_url || '(none)'}`);
  console.log(`Snapshots Count:      ${snapshots.length}`);
  if (latestSnapshot) {
    console.log(`Latest Snapshot ID:   ${latestSnapshot.id}`);
    console.log(`Acquired At:          ${latestSnapshot.acquired_at || latestSnapshot.retrieval_timestamp || '(none)'}`);
    console.log(`Storage Path:         ${latestSnapshot.storage_path || '(none)'}`);
    console.log(`Provider:             ${latestSnapshot.provider} (v${latestSnapshot.provider_version})`);
  }
  console.log('----------------------------------------------------\n');
}

function handleGateCheck(investigationId: string) {
  console.log(`\n[!] Evaluating pre-flight investigation gate for '${investigationId}'...`);
  try {
    const gate = globalDB.evaluateInvestigationGate(investigationId);
    console.log('\nINVESTIGATION PRE-FLIGHT GATE RESULT');
    console.log('====================================================');
    console.log(`Overall Gate Status: ${gate.passed ? '✔ PASSED' : '✖ BLOCKED'}`);
    console.log(`Target Authorization: ${gate.target_authorization}`);
    console.log(`Scope Status:        ${gate.scope_status}`);
    console.log(`Source Status:       ${gate.source_status}`);
    console.log(`Policy Status:       ${gate.policy_status}`);
    console.log('----------------------------------------------------');
    console.log('Checks:');
    for (const check of gate.checks) {
      console.log(`  [${check.passed ? '✔ PASS' : '✖ FAIL'}] ${rpad(check.name, 28)} : ${check.message}`);
    }
    console.log('====================================================\n');
  } catch (err: any) {
    console.error('Gate check failed:', err.message);
    process.exit(1);
  }
}

async function handleEnginesList() {
  const engines = globalEngineRegistry.list();
  const availability = await globalEngineRegistry.check_all();

  console.log('\nINTENT SECURITY WORKBENCH — ENGINE REGISTRY');
  console.log('='.repeat(70));
  console.log(
    rpad('Engine', 24) +
    rpad('Status', 18) +
    rpad('Version', 24)
  );
  console.log('-'.repeat(70));

  for (const eng of engines) {
    const avail = availability.find(a => a.engine_id === eng.engine_id);
    const rawStatus = avail ? avail.status : EngineAvailabilityStatus.NOT_INSTALLED;
    const status = rawStatus === EngineAvailabilityStatus.NOT_INSTALLED ? 'NOT INSTALLED' : rawStatus;
    const version = (avail && avail.version) ? avail.version : '-';
    
    console.log(
      rpad(eng.engine_id, 24) +
      rpad(status, 18) +
      rpad(version, 24)
    );
  }
  console.log('-'.repeat(70));
  console.log(`Total Engines: ${engines.length} | Real binary verification verified at runtime.\n`);
}

async function handleEnginesCheckAll() {
  console.log('\n[!] Executing real host availability check across all registered engines...\n');
  const availability = await globalEngineRegistry.check_all();

  console.log(
    rpad('Engine ID', 22) +
    rpad('Status', 16) +
    rpad('Path', 20) +
    rpad('Version', 20)
  );
  console.log('-'.repeat(80));

  for (const item of availability) {
    const status = item.status === EngineAvailabilityStatus.NOT_INSTALLED ? 'NOT INSTALLED' : item.status;
    console.log(
      rpad(item.engine_id, 22) +
      rpad(status, 16) +
      rpad(item.detected_path || '(none)', 20) +
      rpad(item.version || '-', 20)
    );
  }
  console.log('-'.repeat(80));
  console.log(`Checked ${availability.length} engines at ${new Date().toISOString()}\n`);
}

async function handleEngineCheck(engineId: string) {
  console.log(`\n[!] Checking engine binary for: '${engineId}'...`);
  const engine = globalEngineRegistry.get(engineId);
  if (!engine) {
    console.error(`Error: Engine '${engineId}' is not registered in EngineRegistry.`);
    process.exit(1);
  }

  const avail = await engine.check_availability();
  console.log('\nENGINE VERIFICATION RESULT');
  console.log('-------------------------------------------');
  console.log(`Engine ID:     ${avail.engine_id}`);
  console.log(`Name:          ${avail.name}`);
  console.log(`Executable:    ${avail.executable}`);
  console.log(`Status:        ${avail.status}`);
  console.log(`Detected Path: ${avail.detected_path || '(none)'}`);
  console.log(`Version:       ${avail.version || '-'}`);
  console.log(`Error/Reason:  ${avail.error || '(none)'}`);
  console.log(`Capabilities:  ${avail.capabilities.join(', ')}`);
  console.log(`Checked At:    ${avail.checked_at}\n`);

  if (avail.status === EngineAvailabilityStatus.AVAILABLE) {
    console.log(`✔ Engine executable detected and verified on host PATH.\n`);
  } else {
    console.log(`✖ Engine executable is unavailable (${avail.status}). Never simulated.\n`);
  }
}

async function queryApi<T>(endpoint: string): Promise<T | null> {
  const apiUrl = process.env.API_URL || 'http://127.0.0.1:3000';
  try {
    const res = await fetch(`${apiUrl}${endpoint}`, { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      return await res.json() as T;
    }
  } catch {
    // API not reachable, fallback to direct in-memory / storage
  }
  return null;
}

async function handleEvidenceList(investigationId?: string) {
  let artifacts = await queryApi<any[]>(investigationId ? `/api/v1/investigations/${investigationId}/evidence` : '/api/v1/evidence');
  if (!artifacts) {
    artifacts = globalDB.listEvidence(investigationId);
  }
  console.log(`\nINTENT SECURITY WORKBENCH — EVIDENCE LOCKER${investigationId ? ` (Investigation: ${investigationId})` : ''}`);
  console.log('='.repeat(95));
  console.log(
    rpad('Artifact ID', 24) +
    rpad('Type', 18) +
    rpad('Producer', 20) +
    rpad('Size', 10) +
    rpad('SHA-256 Prefix', 20)
  );
  console.log('-'.repeat(95));

  if (artifacts.length === 0) {
    console.log('(No evidence artifacts recorded)');
  } else {
    for (const art of artifacts) {
      console.log(
        rpad(art.id, 24) +
        rpad(String(art.artifact_type), 18) +
        rpad(`${art.producer} (v${art.producer_version})`, 20) +
        rpad(`${art.size_bytes || art.byte_size || 0} B`, 10) +
        rpad(`${art.sha256.substring(0, 16)}...`, 20)
      );
    }
  }
  console.log('-'.repeat(95));
  console.log(`Total Artifacts: ${artifacts.length}\n`);
}

async function handleEvidenceShow(artifactId: string) {
  let art = await queryApi<any>(`/api/v1/evidence/${artifactId}`);
  if (!art) {
    art = globalDB.getEvidenceArtifact(artifactId);
  }
  if (!art) {
    console.error(`Error: Evidence artifact '${artifactId}' not found.`);
    process.exit(1);
  }

  console.log('\nEVIDENCE ARTIFACT RECORD');
  console.log('----------------------------------------------------');
  console.log(`ID:               ${art.id}`);
  console.log(`Investigation ID: ${art.investigation_id}`);
  console.log(`Artifact Type:    ${art.artifact_type}`);
  console.log(`Producer:         ${art.producer} (v${art.producer_version})`);
  console.log(`Command Executed: ${art.command || '(none)'}`);
  console.log(`Storage Path:     ${art.path || art.path_or_reference}`);
  console.log(`Size in Bytes:    ${art.size_bytes || art.byte_size} bytes`);
  console.log(`SHA-256 Digest:   ${art.sha256}`);
  console.log(`MIME Type:        ${art.mime_type || 'text/plain'}`);
  console.log(`Created At:       ${art.created_at}`);
  console.log('----------------------------------------------------');
  console.log('Content Preview:\n');
  console.log(art.content_preview || '(No preview available)');
  console.log('\n');
}

async function handleEvidenceVerify(artifactId: string) {
  console.log(`\n[!] Calculating actual SHA-256 byte digest for: '${artifactId}'...`);
  let integrity = await queryApi<any>(`/api/v1/evidence/${artifactId}/integrity`);
  if (!integrity) {
    integrity = await globalDB.verifyArtifactIntegrity(artifactId);
  }

  console.log('\nCRYPTOGRAPHIC INTEGRITY REPORT');
  console.log('----------------------------------------------------');
  console.log(`Artifact ID:     ${artifactId}`);
  console.log(`Expected SHA:    ${integrity.expected_sha256}`);
  console.log(`Actual SHA:      ${integrity.actual_sha256 || '(unreadable)'}`);
  console.log(`Size Checked:    ${integrity.size_bytes} bytes`);
  console.log(`Integrity State: ${integrity.status}`);
  if (integrity.error) {
    console.log(`Error:           ${integrity.error}`);
  }
  console.log('----------------------------------------------------');

  if (integrity.valid) {
    console.log('✔ PASS: Stored bytes match exact cryptographic digest.\n');
  } else {
    console.log('✖ FAIL: Cryptographic signature mismatch or artifact missing.\n');
  }
}

async function handleProvenance(investigationId: string) {
  let graph = await queryApi<any>(`/api/v1/investigations/${investigationId}/provenance`);
  let invTitle = investigationId;
  if (!graph) {
    const inv = globalDB.getInvestigation(investigationId);
    if (!inv) {
      console.error(`Error: Investigation '${investigationId}' not found.`);
      process.exit(1);
    }
    invTitle = inv.title;
    const jobs = globalJobOrchestrator.listJobs({ investigation_id: investigationId });
    graph = globalDB.getInvestigationProvenance(investigationId, jobs);
  }

  console.log(`\nPROVENANCE GRAPH — INVESTIGATION: '${invTitle}' (${investigationId})`);
  console.log('='.repeat(80));
  console.log(`Generated At: ${graph.generated_at}`);
  console.log(`Total Nodes:  ${graph.nodes.length}`);
  console.log(`Total Edges:  ${graph.edges.length}\n`);

  console.log('GRAPH NODES:');
  console.log('-'.repeat(80));
  for (const node of graph.nodes) {
    console.log(`  [${rpad(node.type, 16)}] ${rpad(node.id, 24)} -> ${node.label}`);
  }

  console.log('\nGRAPH RELATIONSHIPS (EDGES):');
  console.log('-'.repeat(80));
  for (const edge of graph.edges) {
    console.log(`  ${rpad(edge.source, 24)} --[ ${rpad(edge.relationship, 20)} ]--> ${edge.target}`);
  }
  console.log('='.repeat(80) + '\n');
}

async function handleEventsList(investigationId?: string) {
  const events = globalDB.listEvidenceEvents(investigationId);
  console.log(`\nIMMUTABLE EVIDENCE EVENT LOG${investigationId ? ` (Investigation: ${investigationId})` : ''}`);
  console.log('='.repeat(95));
  console.log(
    rpad('Event ID', 22) +
    rpad('Event Type', 22) +
    rpad('Actor', 18) +
    rpad('Producer', 18) +
    rpad('Timestamp', 15)
  );
  console.log('-'.repeat(95));

  if (events.length === 0) {
    console.log('(No events recorded)');
  } else {
    for (const ev of events) {
      console.log(
        rpad(ev.id, 22) +
        rpad(String(ev.event_type), 22) +
        rpad(ev.actor, 18) +
        rpad(ev.producer, 18) +
        rpad(new Date(ev.timestamp).toLocaleTimeString(), 15)
      );
    }
  }
  console.log('-'.repeat(95) + '\n');
}

async function handleAnalyze(type: string, investigationId?: string) {
  if (!investigationId) {
    console.error(`Error: investigation_id is required. Usage: intent analyze ${type} <investigation_id>`);
    process.exit(1);
  }

  const inv = globalDB.getInvestigation(investigationId);
  if (!inv) {
    console.error(`Error: Investigation '${investigationId}' not found.`);
    process.exit(1);
  }

  const target = globalDB.getTarget(inv.target_id);
  const snapshots = globalDB.listSourceSnapshots(inv.target_id);
  const snapshotId = snapshots.length > 0 ? snapshots[0].id : `snap-${inv.target_id}-default`;
  const sourceDir = process.cwd();

  console.log(`\n========================================================================`);
  console.log(`INTENT WORKBENCH — STATIC & STRUCTURAL SECURITY ANALYSIS`);
  console.log(`========================================================================`);
  console.log(`Investigation:   ${inv.id} (${inv.title})`);
  console.log(`Target:          ${target ? target.name : inv.target_id}`);
  console.log(`Analysis Mode:   ${type.toUpperCase()}`);
  console.log(`Source Snapshot: ${snapshotId}`);
  console.log(`Working Dir:     ${sourceDir}`);
  console.log(`Started At:      ${new Date().toISOString()}\n`);

  if (type === 'static' || type === 'all') {
    console.log(`[*] Executing multi-engine static analysis pipeline (Tree-sitter + Semgrep)...`);
    const result = await executeStaticAnalysisPipeline(
      inv.id,
      inv.target_id,
      snapshotId,
      sourceDir
    );

    console.log(`\nEXECUTION BREAKDOWN:`);
    console.log(`------------------------------------------------------------------------`);
    console.log(`Tree-sitter:     Status: ${result.treesitter.status} | Files: ${result.treesitter.files_scanned} | Errors: ${result.treesitter.parse_errors} | Duration: ${result.treesitter.duration_ms}ms`);
    console.log(`Semgrep:         Status: ${result.semgrep.status} | Exit Code: ${result.semgrep.exit_code} | Duration: ${result.semgrep.duration_ms}ms`);
    console.log(`Correlation:     Candidates: ${result.correlation.candidates_created} | Corroborated: ${result.correlation.corroborated_candidates}`);
    console.log(`Total Duration:  ${result.total_duration_ms}ms\n`);

    console.log(`CANDIDATE VULNERABILITY FINDINGS (INITIAL STATE: CANDIDATE):`);
    console.log(`========================================================================`);
    console.log(
      rpad('Candidate ID', 22) +
      rpad('Rule ID', 18) +
      rpad('Severity', 10) +
      rpad('Conf', 8) +
      rpad('Engine', 24) +
      rpad('Location', 18)
    );
    console.log(`-`.repeat(100));

    if (result.candidates.length === 0) {
      console.log(`(No candidate findings detected in target source)`);
    } else {
      for (const c of result.candidates) {
        console.log(
          rpad(c.id, 22) +
          rpad(c.rule_id, 18) +
          rpad(c.severity, 10) +
          rpad(c.confidence, 8) +
          rpad(c.engine, 24) +
          rpad(`${c.file_path}:${c.line_start}`, 18)
        );
      }
    }
    console.log(`========================================================================\n`);

  } else if (type === 'treesitter') {
    console.log(`[*] Executing Tree-sitter concrete syntax tree analysis...`);
    const scan = await globalTreeSitterService.scanDirectory(
      sourceDir,
      snapshotId,
      inv.id,
      inv.target_id
    );

    console.log(`Files scanned: ${scan.results.length}`);
    console.log(`AST Artifacts created: ${scan.artifactIds.length}`);
    console.log(`Candidates identified: ${scan.candidates.length}\n`);

    for (const c of scan.candidates) {
      globalCandidateStore.addCandidate(c);
      console.log(`  -> [CANDIDATE] ${c.rule_id} (${c.severity}) at ${c.file_path}:${c.line_start} [${c.confidence}]`);
    }
  } else if (type === 'semgrep') {
    console.log(`[*] Executing Semgrep CLI scan...`);
    const scan = await globalSemgrepService.executeScan(
      sourceDir,
      snapshotId,
      inv.id,
      inv.target_id
    );

    console.log(`Exit code: ${scan.execution.exit_code}`);
    console.log(`Raw matches: ${scan.execution.raw_findings_count}`);
    console.log(`Duration: ${scan.execution.duration_ms}ms\n`);

    for (const c of scan.candidates) {
      globalCandidateStore.addCandidate(c);
      console.log(`  -> [CANDIDATE] ${c.rule_id} (${c.severity}) at ${c.file_path}:${c.line_start} [${c.confidence}]`);
    }
  } else if (type === 'api') {
    console.log(`[*] Executing API Contract & Authorization Analysis pipeline...`);
    const result = await globalAPIAnalysisOrchestrator.runAnalysis({
      investigationId: inv.id,
      targetId: inv.target_id,
      sourceDir,
      sourceSnapshotId: snapshotId,
    });

    if (result.status === 'API_SPEC_NOT_FOUND') {
      console.log(`\n[!] API_SPEC_NOT_FOUND: ${result.message}`);
      console.log('Zero synthetic contracts or endpoints were fabricated.\n');
      return;
    }

    if (result.contract) {
      globalDB.saveApiContract(result.contract);
      console.log(`\n✔ Documented Contract: ${result.contract.title} (${result.contract.openapi_version})`);
      console.log(`  Path: ${result.contract.specification_path}`);
      console.log(`  Hash: ${result.contract.specification_hash}`);
      console.log(`  Endpoints: ${result.contract.endpoints.length}`);
      console.log(`  Security Schemes: ${result.contract.security_schemes.length}`);
      console.log(`  Validation Issues: ${result.contract.validation_issues.length}`);
    }

    if (result.diff) {
      globalDB.saveContractDiff(result.diff);
      console.log(`\n✔ Contract <-> Source Differential:`);
      console.log(`  Matched: ${result.diff.matched} | Doc Only: ${result.diff.documented_not_found} | Source Only (Shadow): ${result.diff.source_only} | Method Mismatches: ${result.diff.method_mismatches}`);
    }

    if (result.authorizationCandidates.length > 0) {
      console.log(`\n✔ Authorization Candidates (${result.authorizationCandidates.length}):`);
      for (const cand of result.authorizationCandidates) {
        globalDB.saveAuthorizationCandidate(cand);
        console.log(`  -> [${cand.status}] ${cand.method} ${cand.path} [Priority: ${cand.priority_score}] (Boundaries: ${cand.identified_boundaries.length})`);
      }
    } else {
      console.log('\n✔ Zero authorization candidates identified (all endpoints enforce ownership boundaries or no object parameters).');
    }
    console.log('');
  } else {
    console.error(`Unknown analysis type: '${type}'. Options: static, treesitter, semgrep, api`);
    process.exit(1);
  }
}

function handleCandidatesList(investigationId?: string) {
  const candidates = globalCandidateStore.listCandidates(investigationId);
  console.log(`\nCANDIDATE FINDINGS LEDGER${investigationId ? ` (Investigation: ${investigationId})` : ''}`);
  console.log('='.repeat(105));
  console.log(
    rpad('Candidate ID', 22) +
    rpad('Status', 14) +
    rpad('Rule ID', 18) +
    rpad('Severity', 10) +
    rpad('Confidence', 12) +
    rpad('Corroborated', 14) +
    rpad('File:Line', 15)
  );
  console.log('-'.repeat(105));

  if (candidates.length === 0) {
    console.log('(No candidates in store)');
  } else {
    for (const c of candidates) {
      console.log(
        rpad(c.id, 22) +
        rpad(c.status, 14) +
        rpad(c.rule_id, 18) +
        rpad(c.severity, 10) +
        rpad(c.confidence, 12) +
        rpad(c.corroborated ? 'YES' : 'NO', 14) +
        rpad(`${c.file_path}:${c.line_start}`, 15)
      );
    }
  }
  console.log('-'.repeat(105));
  console.log(`Total Candidates: ${candidates.length}\n`);
}

function handleCandidateShow(candidateId: string) {
  const c = globalCandidateStore.getCandidate(candidateId);
  if (!c) {
    console.error(`Error: Candidate '${candidateId}' not found.`);
    process.exit(1);
  }

  const evidence = globalCandidateStore.getEvidenceForCandidate(candidateId);

  console.log('\n========================================================================');
  console.log(`CANDIDATE FINDING: ${c.id}`);
  console.log('========================================================================');
  console.log(`Title:             ${c.title}`);
  console.log(`Rule ID:           ${c.rule_id}`);
  console.log(`Status:            ${c.status} (Verified entry state)`);
  console.log(`Category:          ${c.category}`);
  console.log(`Severity:          ${c.severity}`);
  console.log(`Confidence:        ${c.confidence}`);
  console.log(`Confidence Basis:  ${c.confidence_basis}`);
  console.log(`Corroborated:      ${c.corroborated ? 'TRUE (Multiple engines concurred)' : 'FALSE'}`);
  console.log(`Engine:            ${c.engine}`);
  console.log(`File:              ${c.file_path}:${c.line_start}-${c.line_end}`);
  console.log(`Investigation ID:  ${c.investigation_id}`);
  console.log(`Target ID:         ${c.target_id}`);
  console.log(`Source Snapshot:   ${c.source_snapshot_id}`);
  console.log(`Created At:        ${c.created_at}`);

  if (c.cwe_ids?.length) {
    console.log(`CWE:               ${c.cwe_ids.join(', ')}`);
  }
  if (c.owasp_categories?.length) {
    console.log(`OWASP:             ${c.owasp_categories.join(', ')}`);
  }

  console.log('\nMATCHED CODE EVIDENCE:');
  console.log('------------------------------------------------------------------------');
  console.log(c.matched_code);
  console.log('------------------------------------------------------------------------');

  console.log(`\nEVIDENCE ARTIFACTS (${c.evidence_artifact_ids.length}):`);
  for (const art of evidence.artifacts) {
    console.log(`  - [${art.artifact_type}] ${art.id} | SHA-256: ${art.sha256}`);
  }

  console.log(`\nPROVENANCE EVENTS (${evidence.provenance_events.length}):`);
  for (const ev of evidence.provenance_events) {
    console.log(`  - [${ev.event_type}] by ${ev.actor} at ${new Date(ev.timestamp).toLocaleTimeString()}`);
  }

  console.log('\nSTATUS HISTORY:');
  for (const h of c.status_history) {
    console.log(`  - ${h.from_status} -> ${h.to_status} by ${h.actor} (${new Date(h.timestamp).toLocaleTimeString()}): ${h.reason}`);
  }
  console.log('========================================================================\n');
}

function handleRulesList() {
  const rules = globalSecurityRuleRegistry.list();
  console.log('\nINTENT SECURITY WORKBENCH — SECURITY RULE REGISTRY');
  console.log('='.repeat(95));
  console.log(
    rpad('Rule ID', 20) +
    rpad('Category', 18) +
    rpad('Severity', 10) +
    rpad('Languages', 18) +
    rpad('Title', 29)
  );
  console.log('-'.repeat(95));

  for (const r of rules) {
    console.log(
      rpad(r.id, 20) +
      rpad(r.category, 18) +
      rpad(r.severity, 10) +
      rpad(r.languages.join(','), 18) +
      rpad(r.title, 29)
    );
  }
  console.log('-'.repeat(95));
  console.log(`Total Registered Rules: ${rules.length}\n`);
}

function handleRuleShow(ruleId: string) {
  const r = globalSecurityRuleRegistry.get(ruleId);
  if (!r) {
    console.error(`Error: Rule '${ruleId}' not found.`);
    process.exit(1);
  }

  console.log('\n========================================================================');
  console.log(`RULE: ${r.id} - ${r.title}`);
  console.log('========================================================================');
  console.log(`Description:  ${r.description}`);
  console.log(`Category:     ${r.category}`);
  console.log(`Severity:     ${r.severity}`);
  console.log(`Languages:    ${r.languages.join(', ')}`);
  console.log(`CWE IDs:      ${r.cwe_ids.join(', ')}`);
  console.log(`OWASP:        ${r.owasp_categories.join(', ')}`);
  console.log(`Engine:       ${r.engine_support.join(', ')}`);
  console.log(`Version:      ${r.version}`);
  console.log('\nRULE PATTERNS:');
  console.log(JSON.stringify(r.patterns, null, 2));
  console.log('========================================================================\n');
}

function handleApiContracts(investigationId: string) {
  const contracts = globalDB.getApiContractsByInvestigation(investigationId);
  console.log(`\nAPI CONTRACTS LEDGER (Investigation: ${investigationId})`);
  console.log('='.repeat(95));
  console.log(
    rpad('Contract ID', 20) +
    rpad('Version', 12) +
    rpad('Endpoints', 12) +
    rpad('Schemes', 10) +
    rpad('Title', 25) +
    rpad('Specification Hash', 16)
  );
  console.log('-'.repeat(95));

  if (contracts.length === 0) {
    console.log('(No API contracts recorded for this investigation)');
  } else {
    for (const c of contracts) {
      console.log(
        rpad(c.id, 20) +
        rpad(c.openapi_version, 12) +
        rpad(String(c.endpoints.length), 12) +
        rpad(String(c.security_schemes.length), 10) +
        rpad(c.title, 25) +
        rpad(c.specification_hash.substring(0, 12) + '...', 16)
      );
    }
  }
  console.log('-'.repeat(95));
  console.log(`Total Contracts: ${contracts.length}\n`);
}

function handleApiEndpoints(contractId: string) {
  const contract = globalDB.getApiContract(contractId);
  if (!contract) {
    console.error(`Error: API Contract '${contractId}' not found.`);
    process.exit(1);
  }

  console.log(`\nAPI CONTRACT ENDPOINTS: ${contract.title} (${contractId})`);
  console.log('='.repeat(105));
  console.log(
    rpad('Method', 9) +
    rpad('Path', 35) +
    rpad('Auth Status', 24) +
    rpad('Object ID Params', 22) +
    rpad('Mutation', 12)
  );
  console.log('-'.repeat(105));

  for (const ep of contract.endpoints) {
    const objParams = ep.parameters
      .filter((p) => p.identifier_role !== 'UNKNOWN')
      .map((p) => p.name)
      .join(', ');

    console.log(
      rpad(ep.method, 9) +
      rpad(ep.path, 35) +
      rpad(ep.auth_status, 24) +
      rpad(objParams || '(none)', 22) +
      rpad(ep.is_state_mutation ? 'YES' : 'NO', 12)
    );
  }
  console.log('-'.repeat(105));
  console.log(`Total Endpoints: ${contract.endpoints.length}\n`);
}

function handleApiAuth(investigationId: string) {
  const candidates = globalDB.getAuthorizationCandidatesByInvestigation(investigationId);
  console.log(`\nAUTHORIZATION CANDIDATE FINDINGS (Investigation: ${investigationId})`);
  console.log('='.repeat(110));
  console.log(
    rpad('Candidate ID', 24) +
    rpad('Method', 8) +
    rpad('Endpoint Path', 32) +
    rpad('Priority', 10) +
    rpad('Status', 14) +
    rpad('Boundaries Found', 18)
  );
  console.log('-'.repeat(110));

  if (candidates.length === 0) {
    console.log('(No authorization candidate findings recorded for this investigation)');
  } else {
    for (const c of candidates) {
      console.log(
        rpad(c.id, 24) +
        rpad(c.method, 8) +
        rpad(c.path, 32) +
        rpad(String(c.priority_score), 10) +
        rpad(c.status, 14) +
        rpad(String(c.identified_boundaries.length), 18)
      );
    }
  }
  console.log('-'.repeat(110));
  console.log(`Total Authorization Candidates: ${candidates.length}\n`);
}

function handleApiDiff(investigationId: string) {
  const diff = globalDB.getContractDiffByInvestigation(investigationId);
  if (!diff) {
    console.error(`Error: No contract differential found for investigation '${investigationId}'. Run 'intent analyze api <inv_id>' first.`);
    process.exit(1);
  }

  console.log(`\nSOURCE <-> CONTRACT DIFFERENTIAL (Investigation: ${investigationId})`);
  console.log('='.repeat(100));
  console.log(`Total Documented in OpenAPI: ${diff.total_documented}`);
  console.log(`Total Source-Discovered:     ${diff.total_source_discovered}`);
  console.log(`Documented & Implemented:   ${diff.matched}`);
  console.log(`Documented But Not Found:   ${diff.documented_not_found}`);
  console.log(`Source Only (Shadow APIs):  ${diff.source_only}`);
  console.log(`Method Mismatches:          ${diff.method_mismatches}`);
  console.log('-'.repeat(100));

  for (const item of diff.items) {
    console.log(`  [${rpad(item.status, 28)}] ${item.method} ${item.path} - ${item.details}`);
  }
  console.log('-'.repeat(100) + '\n');
}

async function handleVerifyFormal(action?: string, extraArg?: string, allArgs: string[] = []) {
  if (!action) {
    console.error('Error: Action or investigation_id required. Usage: intent verify formal <inv_id> | list <inv_id> | show <result_id> | model <result_id> | counterexample <result_id>');
    process.exit(1);
  }

  // 1. Sub-action: list
  if (action === 'list') {
    if (!extraArg) {
      console.error('Error: investigation_id required. Usage: intent verify formal list <investigation_id>');
      process.exit(1);
    }
    const results = globalDB.getVerificationResultsByInvestigation(extraArg);
    console.log(`\nFORMAL VERIFICATION RESULTS (Investigation: ${extraArg})`);
    console.log('='.repeat(110));
    console.log(
      rpad('Result ID', 24) +
      rpad('Property', 28) +
      rpad('Status', 26) +
      rpad('Solver', 12) +
      rpad('Time (ms)', 12) +
      rpad('Assumptions', 12)
    );
    console.log('-'.repeat(110));
    if (results.length === 0) {
      console.log('(No formal verification results found for this investigation)');
    } else {
      for (const r of results) {
        console.log(
          rpad(r.id, 24) +
          rpad(r.property.name, 28) +
          rpad(r.status, 26) +
          rpad(`${r.solver} ${r.solver_version}`, 12) +
          rpad(String(r.execution_time_ms), 12) +
          rpad(String(r.assumptions.length), 12)
        );
      }
    }
    console.log('-'.repeat(110));
    console.log(`Total Verification Results: ${results.length}\n`);
    return;
  }

  // 2. Sub-action: show
  if (action === 'show') {
    if (!extraArg) {
      console.error('Error: verification_id required. Usage: intent verify formal show <verification_id>');
      process.exit(1);
    }
    const res = globalDB.getVerificationResult(extraArg);
    if (!res) {
      console.error(`Error: Formal verification result '${extraArg}' not found.`);
      process.exit(1);
    }

    console.log('\nFORMAL VERIFICATION RESULT RECORD');
    console.log('='.repeat(80));
    console.log(`Result ID:         ${res.id}`);
    console.log(`Investigation ID:  ${res.investigation_id}`);
    console.log(`Candidate ID:      ${res.candidate_id || '(none)'}`);
    console.log(`Property:          ${res.property.name} (${res.property.id})`);
    console.log(`Property Desc:     ${res.property.description}`);
    console.log(`Status:            ${res.status}`);
    console.log(`Solver:            ${res.solver} (${res.solver_version})`);
    console.log(`Command:           ${res.command_executed}`);
    console.log(`Execution Time:    ${res.execution_time_ms} ms`);
    console.log(`Exit Code:         ${res.exit_code}`);
    console.log(`Model Hash:        ${res.model_hash}`);
    console.log(`SMT-LIB2 SHA-256:  ${res.smt_lib_sha256}`);
    console.log(`Created At:        ${res.created_at}`);
    console.log('-'.repeat(80));
    console.log(`Assumptions (${res.assumptions.length}):`);
    for (const a of res.assumptions) {
      console.log(`  - [${a.id}] ${a.assumption_text}`);
      console.log(`    Rationale: ${a.rationale}`);
    }
    console.log(`Source Facts (${res.source_facts.length}):`);
    for (const f of res.source_facts) {
      console.log(`  - [${f.observed_via}] ${f.description} (${f.file}:${f.line || 1})`);
    }
    console.log(`Constraints (${res.constraints.length}):`);
    for (const c of res.constraints) {
      const typeStr = c.is_assumption ? 'MODEL_ASSUMPTION' : 'SOURCE_FACT';
      console.log(`  - [${typeStr}] ${c.name}: ${c.smt_representation}`);
    }
    if (res.counterexample) {
      console.log('\nFORMAL COUNTEREXAMPLE:');
      console.log(`  Assignments: ${JSON.stringify(res.counterexample.assignments, null, 2)}`);
    }
    console.log('\nBOUNDARY CLARIFICATION:');
    console.log(`  ${res.boundary_clarification}\n`);
    return;
  }

  // 3. Sub-action: model
  if (action === 'model') {
    if (!extraArg) {
      console.error('Error: verification_id required. Usage: intent verify formal model <verification_id>');
      process.exit(1);
    }
    const res = globalDB.getVerificationResult(extraArg);
    if (!res) {
      console.error(`Error: Formal verification result '${extraArg}' not found.`);
      process.exit(1);
    }

    console.log(`\nFORMAL SMT-LIB2 MODEL (ID: ${res.id})`);
    console.log('='.repeat(80));
    console.log(`SHA-256 Digest: ${res.smt_lib_sha256}`);
    console.log('-'.repeat(80));
    console.log(res.smt_lib_input);
    console.log('='.repeat(80) + '\n');
    return;
  }

  // 4. Sub-action: counterexample
  if (action === 'counterexample') {
    if (!extraArg) {
      console.error('Error: verification_id required. Usage: intent verify formal counterexample <verification_id>');
      process.exit(1);
    }
    const res = globalDB.getVerificationResult(extraArg);
    if (!res) {
      console.error(`Error: Formal verification result '${extraArg}' not found.`);
      process.exit(1);
    }
    if (!res.counterexample) {
      console.log(`\nResult ${res.id} has status ${res.status}. No counterexample was generated.\n`);
      return;
    }

    console.log(`\nFORMAL MODEL COUNTEREXAMPLE (ID: ${res.id})`);
    console.log('='.repeat(80));
    console.log('WARNING / BOUNDARY CLARIFICATION:');
    console.log(res.boundary_clarification);
    console.log('-'.repeat(80));
    console.log('Counterexample Variable Assignments:');
    for (const [k, v] of Object.entries(res.counterexample.assignments)) {
      console.log(`  ${rpad(k, 25)} = ${v}`);
    }
    console.log('\nRaw Solver Output:');
    console.log(res.counterexample.raw_model_string);
    console.log('='.repeat(80) + '\n');
    return;
  }

  // 5. Default execution: intent verify formal <investigation_id>
  const investigationId = action;
  const investigation = globalDB.getInvestigation(investigationId);
  if (!investigation) {
    console.error(`Error: Investigation '${investigationId}' not found.`);
    process.exit(1);
  }

  const target = globalDB.getTarget(investigation.target_id);
  console.log(`\nINITIATING FORMAL VERIFICATION PIPELINE`);
  console.log('='.repeat(80));
  console.log(`Investigation: ${investigation.id} (${investigation.name})`);
  console.log(`Target:        ${target?.name || investigation.target_id}`);

  // Check Z3 availability first
  const hostZ3 = Z3Detector.detect();
  if (!hostZ3.installed) {
    console.error(`\nERROR: Z3 SMT Solver is not available: ${hostZ3.error}`);
    process.exit(1);
  }
  console.log(`Solver Engine: Z3 (${hostZ3.version}) at ${hostZ3.executable_path}`);

  // Check for candidate findings or build default property model
  const candidates = globalDB.getAuthorizationCandidatesByInvestigation(investigationId);
  console.log(`Found ${candidates.length} authorization candidate(s) for formal verification.`);

  const property = STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS;

  let model;
  if (candidates.length > 0) {
    const primaryCandidate = candidates[0];
    console.log(`Modeling candidate finding: ${primaryCandidate.id} (${primaryCandidate.method} ${primaryCandidate.path})`);
    model = FormalModelBuilder.buildFromSource({
      name: `Formal Model: ${property.name} for ${primaryCandidate.path}`,
      investigation_id: investigationId,
      target_id: investigation.target_id,
      source_snapshot_id: investigation.source_snapshot_id || null,
      candidate_id: primaryCandidate.id,
      source_code: primaryCandidate.matched_source_snippet || '',
      source_file: primaryCandidate.file,
      authorization_candidate: primaryCandidate,
      property,
    });
  } else {
    console.log('No prior candidates; generating formal authorization model from investigation target.');
    model = FormalModelBuilder.buildFromSource({
      name: `Formal Model: ${property.name}`,
      investigation_id: investigationId,
      target_id: investigation.target_id,
      source_snapshot_id: investigation.source_snapshot_id || null,
      property,
    });
  }

  console.log(`\nCompiling model to SMT-LIB2...`);
  console.log(`Variables:    ${model.variables.length}`);
  console.log(`Constraints:  ${model.constraints.length}`);
  console.log(`Assumptions:  ${model.assumptions.length}`);
  console.log(`Source Facts: ${model.sourceFacts.length}`);

  const result = await globalFormalVerificationService.verifyModel({
    investigationId,
    targetId: investigation.target_id,
    sourceSnapshotId: investigation.source_snapshot_id || null,
    candidateId: model.candidate_id || null,
    model,
    timeoutMs: 8000,
  });

  console.log('\nVERIFICATION RESULT:');
  console.log('-'.repeat(80));
  console.log(`Result ID:       ${result.id}`);
  console.log(`Status:          ${result.status}`);
  console.log(`Solver Result:   ${result.solver_result_raw.toUpperCase()}`);
  console.log(`Execution Time:  ${result.execution_time_ms} ms`);
  console.log(`Model Hash:      ${result.model_hash}`);
  console.log(`SMT Artifact:    ${result.smt_artifact_id || '(none)'}`);
  console.log(`Result Artifact: ${result.result_artifact_id || '(none)'}`);

  if (result.counterexample) {
    console.log('\nCounterexample Generated:');
    for (const [k, v] of Object.entries(result.counterexample.assignments)) {
      console.log(`  ${rpad(k, 25)} = ${v}`);
    }
  }

  console.log('\nBoundary Clarification:');
  console.log(`  ${result.boundary_clarification}`);
  console.log('='.repeat(80) + '\n');
}

function handleToolsDynamic() {
  const tools = ToolDetector.detectAll();
  console.log('\nDYNAMIC VERIFICATION HOST BINARIES');
  console.log('='.repeat(85));
  console.log(
    rpad('Tool', 14) +
    rpad('Installed', 14) +
    rpad('Version', 24) +
    rpad('Path', 30)
  );
  console.log('-'.repeat(85));
  for (const t of Object.values(tools)) {
    console.log(
      rpad(t.tool, 14) +
      rpad(t.installed ? 'YES' : 'NO', 14) +
      rpad(t.version || 'N/A', 24) +
      rpad(t.executable_path || t.error || 'N/A', 30)
    );
  }
  console.log('='.repeat(85) + '\n');
}

async function handleCandidateVerify(candidateId: string, runtimeArg?: string) {
  const candidate = globalDB.getAuthorizationCandidate(candidateId);
  if (!candidate) {
    console.error(`Error: Authorization candidate '${candidateId}' not found.`);
    process.exit(1);
  }

  console.log(`\nDISPATCHING DYNAMIC VERIFICATION FOR CANDIDATE: ${candidate.id}`);
  console.log('='.repeat(85));
  console.log(`Candidate Path:      ${candidate.method} ${candidate.path}`);
  console.log(`Investigation ID:    ${candidate.investigation_id}`);
  console.log(`Target ID:           ${candidate.target_id}`);

  const runtime = (runtimeArg || 'API').toUpperCase();
  console.log(`Selected Runtime:    ${runtime}`);

  const job = await globalDynamicVerificationService.execute({
    investigation_id: candidate.investigation_id,
    candidate_id: candidate.id,
    target_id: candidate.target_id,
    runtime,
    environment: 'LOCAL_SOURCE',
    timeout_ms: 15000,
    caller: 'attacker',
    owner: 'victim',
    operation: candidate.path,
  });

  console.log('\nDYNAMIC VERIFICATION RESULT:');
  console.log('-'.repeat(85));
  console.log(`Job ID:              ${job.id}`);
  console.log(`Tool:                ${job.tool} (${job.tool_version || 'N/A'})`);
  console.log(`Status:              ${job.status}`);
  console.log(`Reproduction Result: ${job.result}`);
  console.log(`Exit Code:           ${job.exit_code ?? 'N/A'}`);
  console.log(`State Changed:       ${job.state_diff?.has_changes ? 'YES' : 'NO'}`);
  console.log(`Protected Mutated:   ${job.state_diff?.protected_changed ? 'YES' : 'NO'}`);
  console.log(`Stdout Artifact:     ${job.stdout_artifact_id || '(none)'}`);
  console.log(`Trace Artifact:      ${job.execution_trace_artifact_id || '(none)'}`);
  if (job.failure_reason) {
    console.log(`Failure Reason:      ${job.failure_reason}`);
  }
  console.log('='.repeat(85) + '\n');
}

async function handleVerifyDynamic(action?: string, extraArg?: string, fullArgs: string[] = []) {
  // 1. intent verify dynamic (without args) or --help
  if (!action || action === 'help' || action === '--help') {
    console.log(`
Usage:
  intent verify dynamic <investigation_id> [runtime] [fixture_dir]  Execute dynamic verification
  intent verify dynamic list <investigation_id>                     List verification jobs
  intent verify dynamic show <job_id>                              Display verification job details
  intent verify dynamic trace <job_id>                             Display execution trace
  intent verify dynamic state <job_id>                             Display state diff
  intent verify dynamic evidence <job_id>                          Display verification evidence
`);
    return;
  }

  // 2. intent verify dynamic list <investigation_id>
  if (action === 'list') {
    if (!extraArg) {
      console.error('Error: investigation_id required. Usage: intent verify dynamic list <investigation_id>');
      process.exit(1);
    }
    const jobs = globalDB.listDynamicVerificationJobs(extraArg);
    console.log(`\nDYNAMIC VERIFICATION JOBS FOR INVESTIGATION: ${extraArg}`);
    console.log('='.repeat(95));
    console.log(
      rpad('Job ID', 22) +
      rpad('Runtime', 12) +
      rpad('Tool', 12) +
      rpad('Status', 16) +
      rpad('Result', 18) +
      rpad('Created At', 15)
    );
    console.log('-'.repeat(95));
    if (jobs.length === 0) {
      console.log('(No dynamic verification jobs found)');
    } else {
      for (const j of jobs) {
        console.log(
          rpad(j.id, 22) +
          rpad(j.runtime, 12) +
          rpad(j.tool, 12) +
          rpad(j.status, 16) +
          rpad(j.result, 18) +
          rpad(j.created_at.substring(0, 19), 15)
        );
      }
    }
    console.log('='.repeat(95) + '\n');
    return;
  }

  // 3. intent verify dynamic show <job_id>
  if (action === 'show') {
    if (!extraArg) {
      console.error('Error: job_id required. Usage: intent verify dynamic show <job_id>');
      process.exit(1);
    }
    const job = globalDB.getDynamicVerificationJob(extraArg);
    if (!job) {
      console.error(`Error: Dynamic verification job '${extraArg}' not found.`);
      process.exit(1);
    }
    console.log(`\nDYNAMIC VERIFICATION JOB: ${job.id}`);
    console.log('='.repeat(85));
    console.log(`Investigation ID:    ${job.investigation_id}`);
    console.log(`Target ID:           ${job.target_id}`);
    console.log(`Candidate ID:        ${job.candidate_id || '(none)'}`);
    console.log(`Runtime:             ${job.runtime}`);
    console.log(`Environment:         ${job.environment}`);
    console.log(`Tool:                ${job.tool} (${job.tool_version || 'N/A'})`);
    console.log(`Command:             ${job.command}`);
    console.log(`Status:              ${job.status}`);
    console.log(`Reproduction Result: ${job.result}`);
    console.log(`Exit Code:           ${job.exit_code ?? 'N/A'}`);
    console.log(`Started At:          ${job.started_at}`);
    console.log(`Completed At:        ${job.completed_at || 'In Progress'}`);
    console.log(`State Changed:       ${job.state_diff?.has_changes ? 'YES' : 'NO'}`);
    console.log(`Protected Changed:   ${job.state_diff?.protected_changed ? 'YES' : 'NO'}`);
    console.log(`Stdout Artifact:     ${job.stdout_artifact_id || '(none)'}`);
    console.log(`Stderr Artifact:     ${job.stderr_artifact_id || '(none)'}`);
    console.log(`Trace Artifact:      ${job.execution_trace_artifact_id || '(none)'}`);
    console.log(`State Before Art:    ${job.state_before_artifact_id || '(none)'}`);
    console.log(`State After Art:     ${job.state_after_artifact_id || '(none)'}`);
    if (job.failure_reason) {
      console.log(`Failure Reason:      ${job.failure_reason}`);
    }
    console.log('='.repeat(85) + '\n');
    return;
  }

  // 4. intent verify dynamic trace <job_id>
  if (action === 'trace') {
    if (!extraArg) {
      console.error('Error: job_id required. Usage: intent verify dynamic trace <job_id>');
      process.exit(1);
    }
    const job = globalDB.getDynamicVerificationJob(extraArg);
    if (!job) {
      console.error(`Error: Dynamic verification job '${extraArg}' not found.`);
      process.exit(1);
    }
    console.log(`\nEXECUTION TRACE FOR JOB: ${job.id}`);
    console.log('='.repeat(85));
    console.log(`Command:   ${job.command}`);
    console.log(`Exit Code: ${job.exit_code ?? 'N/A'}`);
    console.log('-'.repeat(85));
    if (job.trace?.traces && job.trace.traces.length > 0) {
      for (const t of job.trace.traces) {
        console.log(`[${t.call_type || 'CALL'}] ${t.from || 'Caller'} -> ${t.to || 'Target'}::${t.function_name || 'execute'}`);
        if (t.gas_used) console.log(`  Gas Used: ${t.gas_used}`);
        if (t.output) console.log(`  Output:   ${t.output}`);
        if (t.error) console.log(`  Error:    ${t.error}`);
      }
    } else {
      console.log('Raw Stdout:');
      console.log(job.stdout || '(no output)');
    }
    console.log('='.repeat(85) + '\n');
    return;
  }

  // 5. intent verify dynamic state <job_id>
  if (action === 'state') {
    if (!extraArg) {
      console.error('Error: job_id required. Usage: intent verify dynamic state <job_id>');
      process.exit(1);
    }
    const job = globalDB.getDynamicVerificationJob(extraArg);
    if (!job) {
      console.error(`Error: Dynamic verification job '${extraArg}' not found.`);
      process.exit(1);
    }
    console.log(`\nSTATE DIFFERENTIAL FOR JOB: ${job.id}`);
    console.log('='.repeat(85));
    console.log(`Has Changes:       ${job.state_diff?.has_changes ? 'YES' : 'NO'}`);
    console.log(`Protected Changed: ${job.state_diff?.protected_changed ? 'YES' : 'NO'}`);
    console.log('-'.repeat(85));
    console.log('State Before:');
    console.log(JSON.stringify(job.state_before, null, 2) || '(none)');
    console.log('\nState After:');
    console.log(JSON.stringify(job.state_after, null, 2) || '(none)');
    console.log('\nDiff Entries:');
    if (job.state_diff?.diffs && job.state_diff.diffs.length > 0) {
      for (const d of job.state_diff.diffs) {
        const typeStr = d.type || (d.before === null ? 'ADDED' : d.after === null ? 'REMOVED' : 'MODIFIED');
        const oldVal = d.old_value !== undefined ? d.old_value : d.before;
        const newVal = d.new_value !== undefined ? d.new_value : d.after;
        const isProt = d.is_protected ?? d.protected ?? false;
        console.log(`  [${typeStr}] ${d.path}: ${JSON.stringify(oldVal)} -> ${JSON.stringify(newVal)} (Protected: ${isProt})`);
      }
    } else {
      console.log('  (No state changes detected)');
    }
    console.log('='.repeat(85) + '\n');
    return;
  }

  // 6. intent verify dynamic evidence <job_id>
  if (action === 'evidence') {
    if (!extraArg) {
      console.error('Error: job_id required. Usage: intent verify dynamic evidence <job_id>');
      process.exit(1);
    }
    const job = globalDB.getDynamicVerificationJob(extraArg);
    if (!job) {
      console.error(`Error: Dynamic verification job '${extraArg}' not found.`);
      process.exit(1);
    }
    console.log(`\nEVIDENCE ARTIFACTS FOR DYNAMIC JOB: ${job.id}`);
    console.log('='.repeat(85));
    const artIds = [
      { name: 'STDOUT', id: job.stdout_artifact_id },
      { name: 'STDERR', id: job.stderr_artifact_id },
      { name: 'EXECUTION TRACE', id: job.execution_trace_artifact_id },
      { name: 'STATE BEFORE', id: job.state_before_artifact_id },
      { name: 'STATE AFTER', id: job.state_after_artifact_id },
    ];
    for (const a of artIds) {
      if (a.id) {
        const art = globalDB.getEvidence(a.id);
        console.log(`Artifact [${a.name}]: ${a.id}`);
        console.log(`  Type:   ${art?.type}`);
        console.log(`  SHA256: ${art?.sha256}`);
        console.log(`  Bytes:  ${art?.size_bytes}`);
      } else {
        console.log(`Artifact [${a.name}]: (none)`);
      }
    }
    console.log('='.repeat(85) + '\n');
    return;
  }

  // 7. Default execution: intent verify dynamic <investigation_id> [runtime] [fixture_dir]
  const investigationId = action;
  const investigation = globalDB.getInvestigation(investigationId);
  if (!investigation) {
    console.error(`Error: Investigation '${investigationId}' not found.`);
    process.exit(1);
  }

  const runtime = (extraArg || 'EVM').toUpperCase();
  const customFixture = fullArgs[1] || undefined;

  console.log(`\nINITIATING REAL DYNAMIC VERIFICATION`);
  console.log('='.repeat(85));
  console.log(`Investigation: ${investigation.id} (${investigation.name})`);
  console.log(`Target ID:     ${investigation.target_id}`);
  console.log(`Runtime:       ${runtime}`);
  if (customFixture) {
    console.log(`Custom Dir:    ${customFixture}`);
  }

  const job = await globalDynamicVerificationService.execute({
    investigation_id: investigationId,
    candidate_id: '',
    target_id: investigation.target_id,
    runtime,
    environment: 'LOCAL_SOURCE',
    timeout_ms: 20000,
    custom_fixture_dir: customFixture,
  });

  console.log('\nDYNAMIC VERIFICATION COMPLETED');
  console.log('-'.repeat(85));
  console.log(`Job ID:              ${job.id}`);
  console.log(`Tool:                ${job.tool} (${job.tool_version || 'N/A'})`);
  console.log(`Status:              ${job.status}`);
  console.log(`Reproduction Result: ${job.result}`);
  console.log(`Exit Code:           ${job.exit_code ?? 'N/A'}`);
  console.log(`State Changed:       ${job.state_diff?.has_changes ? 'YES' : 'NO'}`);
  console.log(`Protected Mutated:   ${job.state_diff?.protected_changed ? 'YES' : 'NO'}`);
  console.log(`Stdout Artifact:     ${job.stdout_artifact_id || '(none)'}`);
  console.log(`Trace Artifact:      ${job.execution_trace_artifact_id || '(none)'}`);
  if (job.failure_reason) {
    console.log(`Failure Reason:      ${job.failure_reason}`);
  }
  console.log('='.repeat(85) + '\n');
}

function rpad(str: string, length: number): string {
  if (str.length >= length) {
    return str.substring(0, length - 1) + ' ';
  }
  return str + ' '.repeat(length - str.length);
}

main().catch(err => {
  console.error('CLI Error:', err);
  process.exit(1);
});
