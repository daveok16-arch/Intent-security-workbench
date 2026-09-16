import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { globalTreeSitterService } from '../../packages/static-analysis/src/treesitter_service.js';
import { globalSecurityRuleRegistry } from '../../packages/static-analysis/src/rule_registry.js';
import { globalSemgrepService } from '../../packages/static-analysis/src/semgrep_service.js';

/**
 * Precision regression tests for the structural BOLA / access-control rules.
 *
 * The engine previously flagged any function with a parameter and a
 * `get(`/`delete(` call, which produced 45 HIGH findings across the project's
 * own library code with zero true positives. These tests pin both directions:
 * genuine route-handler BOLA must still be found, and ordinary library code must
 * stay clean.
 */
describe('Structural Rule Precision (BOLA / Access Control)', () => {
  const scan = async (file: string, source: string) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prec-'));
    const p = path.join(dir, file);
    fs.writeFileSync(p, source);
    return globalTreeSitterService.analyzeFileForVulnerabilities(p, 'snap-p', 'inv-p', 'tgt-p');
  };

  describe('1. Must detect genuine BOLA in route handlers', () => {
    it('flags a route reading req.params into a db lookup with no auth check', async () => {
      const c = await scan('a.js', `
const router = require('express').Router();
router.get('/documents/:id', async (req, res) => {
  const doc = await db.documents.findOne({ _id: req.params.id });
  return res.json(doc);
});
`);
      expect(c.length).toBeGreaterThan(0);
      expect(c[0].rule_id).toBe('INTENT-BOLA-001');
      expect(c[0].category).toBe('BOLA');
    });

    it('flags a delete route reading req.params into a destructive query', async () => {
      const c = await scan('b.js', `
const router = require('express').Router();
router.delete('/orders/:id', async (req, res) => {
  await db.orders.deleteOne({ id: req.params.id });
  return res.json({ ok: true });
});
`);
      expect(c.some((x) => x.rule_id === 'INTENT-BOLA-001')).toBe(true);
    });
  });

  describe('2. Must NOT flag ordinary library code', () => {
    it('ignores an in-memory collection with .get()/.add()/.delete()', async () => {
      const c = await scan('lib.ts', `
export class EventBus {
  private listeners = new Set<() => void>();
  public addEventListener(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
`);
      expect(c).toEqual([]);
    });

    it('ignores a pure helper taking a parameter and calling Map.get()', async () => {
      const c = await scan('util.ts', `
export function loadFixture(name: string, registry: Map<string, string>): string {
  const value = registry.get(name);
  if (!value) throw new Error('missing ' + name);
  return value;
}
`);
      expect(c).toEqual([]);
    });

    it('ignores a function whose name merely contains "admin" but only reads', async () => {
      const c = await scan('cfg.ts', `
export function getAdminConfig(admin: { id: string }, config: Map<string, string>): string | undefined {
  return config.get(admin.id);
}
`);
      expect(c).toEqual([]);
    });
  });

  describe('3. Must NOT flag secured route handlers', () => {
    it('ignores a route with an ownership comparison', async () => {
      const c = await scan('secure.js', `
router.get('/documents/:id', async (req, res) => {
  const doc = await db.documents.findOne({ _id: req.params.id });
  if (doc.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json(doc);
});
`);
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });

    it('ignores a route that never reads an attacker-controlled id', async () => {
      const c = await scan('static.js', `
router.get('/health', async (req, res) => {
  const status = await db.status.findOne({ name: 'health' });
  return res.json(status);
});
`);
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });
  });

  describe('4. Repository fixtures behave as labelled', () => {
    it('finds BOLA in the vulnerable fixture', async () => {
      const c = await globalTreeSitterService.analyzeFileForVulnerabilities(
        path.resolve('fixtures/static_analysis/bola_vulnerable/api.js'),
        'snap-v', 'inv-v', 'tgt-v'
      );
      expect(c.some((x) => x.rule_id === 'INTENT-BOLA-001')).toBe(true);
    });

    it('finds nothing in the secure fixture', async () => {
      const c = await globalTreeSitterService.analyzeFileForVulnerabilities(
        path.resolve('fixtures/static_analysis/bola_secure/api.js'),
        'snap-s', 'inv-s', 'tgt-s'
      );
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });
  });

  /**
   * Shapes taken from real applications (OWASP NodeGoat, OWASP Juice Shop) that
   * the engine previously mishandled. Each case was observed in the wild.
   */
  describe('5. Real-world shapes (NodeGoat / Juice Shop)', () => {
    it('detects a destructured route param reaching a DAO lookup (NodeGoat allocations.js)', async () => {
      const c = await scan('allocations.js', `
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
function AllocationsHandler(db) {
    "use strict";
    const allocationsDAO = new AllocationsDAO(db);
    this.displayAllocations = (req, res, next) => {
        const { userId } = req.params;
        const { threshold } = req.query;
        allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) => {
            if (err) return next(err);
            return res.render("allocations", { userId, allocations });
        });
    };
}
module.exports = AllocationsHandler;
`);
      const bola = c.filter((x) => x.rule_id === 'INTENT-BOLA-001');
      expect(bola.length).toBeGreaterThan(0);
      // The real handler must be identified, and reported once (no nested duplicate).
      expect(bola).toHaveLength(1);
      // The narrower arrow handler is kept, not the enclosing constructor.
      expect(bola[0].line_start).toBeGreaterThan(1);
      expect(bola[0].structural_evidence?.function_name).toBe('anonymous');
    });

    it('reports the real request value and lookup call, not a fabricated one', async () => {
      const c = await scan('allocations.js', `
function AllocationsHandler(db) {
    const allocationsDAO = new AllocationsDAO(db);
    this.displayAllocations = (req, res, next) => {
        const { userId } = req.params;
        allocationsDAO.getByUserIdAndThreshold(userId, 10, cb);
    };
}
`);
      const bola = c.find((x) => x.rule_id === 'INTENT-BOLA-001');
      expect(bola).toBeDefined();
      // Previously hardcoded to 'req.params.id' / 'db.getAccount(...)' for every
      // finding, which asserted evidence the code did not contain.
      expect(bola!.data_flow?.source).toBe('userId');
      expect(bola!.data_flow?.object).toContain('allocationsDAO.getByUserIdAndThreshold');
      expect(JSON.stringify(bola!.data_flow)).not.toContain('db.getAccount');
    });

    it('ignores a handler that reads the user id from the session (NodeGoat profile.js)', async () => {
      // Reading the authenticated user's id from the session is the *correct*
      // pattern, not an attacker-controlled identifier.
      const c = await scan('profile.js', `
function ProfileHandler(db) {
    const profile = new ProfileDAO(db);
    this.displayProfile = (req, res, next) => {
        const { userId } = req.session;
        profile.getByUserId(parseInt(userId), (err, doc) => {
            if (err) return next(err);
            return res.render("profile", { user: doc });
        });
    };
}
`);
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });

    it('ignores create-only data calls (NodeGoat memos.js insert)', async () => {
      // Creating a record is not object-level authorization failure: there is no
      // pre-existing object reached by an attacker-supplied identifier.
      const c = await scan('memos.js', `
function MemosHandler(db) {
    const memosDAO = new MemosDAO(db);
    this.addMemos = (req, res, next) => {
        memosDAO.insert(req.body.memo, (err, docs) => {
            if (err) return next(err);
            return res.render("memos", { memosList: docs });
        });
    };
}
`);
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });

    it('ignores a login handler passing a username to the data layer', async () => {
      // username/password are credentials or content, not object identifiers.
      const c = await scan('session.js', `
function SessionHandler(db) {
    const userDAO = new UserDAO(db);
    this.login = (req, res, next) => {
        const { userName, password } = req.body;
        userDAO.validateLogin(userName, password, (err, user) => {
            if (err) return next(err);
            return res.redirect("/");
        });
    };
}
`);
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });
  });

  /**
   * Rule-pack sanity. A malformed generated rule makes Semgrep emit an empty
   * results array with an error envelope, which is indistinguishable from a
   * clean scan — silently disabling a rule class while reporting success.
   */
  describe('6. Generated Semgrep rule pack', () => {
    it('contains every registered rule and is syntactically usable', () => {
      const yaml = globalSecurityRuleRegistry.generateSemgrepConfig();
      const ids = ['INTENT-BOLA-001', 'RULE-BOLA-001', 'RULE-AUTH-002', 'RULE-CONTRACT-001', 'RULE-REENT-001'];
      for (const id of ids) {
        expect(yaml).toContain(`- id: ${id}`);
      }
      // Unquoted flow-style braces break YAML parsing.
      expect(yaml).not.toMatch(/pattern: \$[A-Z_]+\.[A-Za-z]+\{[^']/);
      // Every rule needs a languages list and a severity.
      const ruleBlocks = yaml.split(/\n(?=- id: )/).filter((b) => b.startsWith('- id: '));
      for (const b of ruleBlocks) {
        expect(b).toMatch(/languages:/);
        expect(b).toMatch(/severity:/);
      }
    });

    it('has a Solidity rule for the major vulnerability classes', () => {
      const rules = globalSecurityRuleRegistry.list();
      const solidityIds = rules.filter((r) => r.languages.includes('solidity')).map((r) => r.id);
      // Reentrancy is the most common Solidity defect class; its absence would
      // leave a large blind spot (only one Solidity rule existed originally).
      expect(solidityIds).toContain('RULE-REENT-001');
      expect(solidityIds).toContain('RULE-CONTRACT-001');
      expect(solidityIds).toContain('RULE-ACCESS-001');
    });
  });

  /**
   * The reentrancy guard suppression operates on source text, so it is tested
   * directly: a genuine reentrancy must survive, and a mutex-protected variant
   * must not be reported.
   */
  describe('7. Reentrancy guard suppression', () => {
    it('keeps a canonical reentrancy and drops the mutex-protected variant', async () => {
      const source = `
contract Guard {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public userWithdrawing;

    function donate(address _to) public payable {
        balances[_to] = balances[_to] + msg.value;
    }

    function vulnerable(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            (bool result,) = msg.sender.call{value: _amount}("");
            if (result) { _amount; }
            balances[msg.sender] -= _amount;
        }
    }

    function mutexed(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        if (userWithdrawing[msg.sender] <= 1) {
            userWithdrawing[msg.sender] = userWithdrawing[msg.sender] + 1;
        } else {
            userWithdrawing[msg.sender] = 0;
            return;
        }
        balances[msg.sender] -= _amount;
        (bool ok,) = msg.sender.call{value: _amount}("");
        require(ok, "failed");
        userWithdrawing[msg.sender] = 0;
    }
}`;
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reent-'));
      fs.writeFileSync(path.join(dir, 'Guard.sol'), source);
      const scanRes = await globalSemgrepService.executeScan(dir, 'snap-r', 'inv-r', 'tgt-r');
      const reent = scanRes.candidates.filter((x) => x.rule_id === 'RULE-REENT-001');
      // The genuine reentrancy must survive: the preceding donate() writes the
      // same state variable and must not be mistaken for a guard.
      // Exactly one finding, and it must be in the vulnerable function.
      expect(reent).toHaveLength(1);
      const vulnerableLine = source.split('\n').findIndex((l) => l.includes('function vulnerable'));
      const mutexedLine = source.split('\n').findIndex((l) => l.includes('function mutexed'));
      const reported = (reent[0].line_start ?? 0) - 1;
      expect(reported).toBeGreaterThan(vulnerableLine);
      expect(reported).toBeLessThan(mutexedLine);
    });
  });
});