/**
 * TargetValidator tests.
 *
 * The validator is the control that stops dynamic verification from being
 * pointed at a third-party production system. It previously had three gaps:
 * a substring `testnet` check, no scheme validation at all (so `file://` and
 * `ws://` bypassed it), and no handling of schemeless hostnames.
 */

import { describe, it, expect } from 'vitest';
import { TargetValidator } from '../../packages/dynamic-verification/src/target_validator.js';

const LOCAL_OK = [
  'http://127.0.0.1:8545',
  'http://localhost:8545',
  'http://anvil.localhost:8545',
  'http://[::1]:8545',
  'http://10.0.0.5:8545',
  'http://192.168.1.20:8545',
  'http://172.16.4.4:8545',
  '/workspace/fixtures/dynamic_verification/evm/vulnerable_bola',
  './fixtures/dynamic_verification/evm/secure_bola',
];

const MUST_REJECT = [
  ['production https host', 'https://api.acme-production.com/v1/orders'],
  ['corporate internal host', 'http://internal-corp.enterprise.com'],
  ['mainnet RPC', 'https://mainnet.infura.io/v3/key'],
  ['alchemy mainnet', 'https://eth-mainnet.g.alchemy.com/v2/key'],
  ['substring testnet spoof', 'https://mytestnet.attacker.example.com'],
  ['testnet as a label', 'http://testnet.evil.example.com'],
  ['localhost as a suffix label', 'http://not-localhost.attacker.example.com'],
  ['schemeless production host', 'api.production.example.com'],
  ['schemeless host with port', 'mainnet.rpc.example.com:8545'],
  ['public IP', 'http://8.8.8.8:80'],
  ['public IP schemeless', '203.0.113.9'],
  ['file scheme', 'file:///etc/passwd'],
  ['websocket scheme', 'ws://attacker.example:9001'],
  ['ftp scheme', 'ftp://attacker.example/x'],
];

describe('TargetValidator rejects production and non-local targets', () => {
  it.each(LOCAL_OK)('approves the isolated local target %s', (target) => {
    const result = TargetValidator.validateTarget('LOCAL_SOURCE', target);
    expect(result.approved).toBe(true);
  });

  it.each(MUST_REJECT)('rejects %s', (_label, target) => {
    const result = TargetValidator.validateTarget('LOCAL_SOURCE', target);
    expect(result.approved).toBe(false);
    expect(result.error).toContain('UNAUTHORIZED_PRODUCTION_TARGET');
  });

  it('rejects unapproved environment strings', () => {
    const result = TargetValidator.validateTarget('PUBLIC_PRODUCTION' as any);
    expect(result.approved).toBe(false);
    expect(result.error).toContain('ENVIRONMENT_INVALID');
  });

  it('does not treat a hostname merely containing testnet as isolated', () => {
    // The old implementation used `hostname.includes('testnet')`.
    expect(TargetValidator.validateTarget('LOCAL_SOURCE', 'https://attacker-testnet.example.com').approved)
      .toBe(false);
    expect(TargetValidator.validateTarget('LOCAL_SOURCE', 'https://testnet.example.com').approved)
      .toBe(false);
  });
});