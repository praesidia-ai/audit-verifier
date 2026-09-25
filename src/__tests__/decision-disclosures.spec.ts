/**
 * AV-0009 — `decisionReceipt` / `policyReference` over be BE-1585's
 * `evidence/decision-receipts.ndjson`, bound to commitment-signed rows.
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { verifyBundle, type VerifyOptions } from '../verify.js';
import { verifyAuditPackage } from '../package.js';
import { findVerifiedDecision, formatDecision } from '../decision-disclosures.js';
import { canonicalJson, signEd25519, sha256, merkleBuild, merkleProof, GENESIS_PREV_ROW_HASH } from '../crypto.js';
import { writeZip, gzipDeterministic } from '../zip.js';

const V = 'praesidia.decision-disclosure.v1';
const ORG = '00000000-0000-0000-0000-000000000009';

/**
 * Pinned from be's REAL `canonicalJson` (`be/src/common/security/utils/
 * canonical-json.ts`, run unmodified) through the exact
 * `AuditCanonicalHelper.computeDetailsCommitment` formula — so producer and
 * verifier agreement is proven, not assumed from this package's canonicaliser.
 */
const BE_DETAILS = {
  schemaVersion: 1,
  decisionId: 'dec-1',
  decision: 'ALLOW',
  policyId: 'pol-1',
  policyVersion: '3',
  note: 'café ✓',
  n: 1.5,
  nested: { b: [1, null, true], a: 'x' },
};
const BE_SALT = 'CQkJCQkJCQkJCQkJCQkJCQ==';
const BE_COMMITMENT = 'YBbshE0YskMfBHyoZG2D9lgBixn7OohtM78PlevhqZ0=';

const commit = (details: unknown, salt: string) =>
  sha256(Buffer.concat([Buffer.from(salt, 'base64'), canonicalJson({ details })])).toString('base64');

interface DecisionRowSpec {
  id: string;
  action: string;
  detailsCommitment: string;
}

/** A signed v1 bundle: one plain row, then commitment-signed decision rows. */
function buildBundle(decisionRows: DecisionRowSpec[]): Buffer {
  const seed = Buffer.alloc(32, 9);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const jwk = crypto.createPublicKey(crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' }))
    .export({ format: 'jwk' }) as { x: string };
  const publicKeyB64 = Buffer.from(jwk.x, 'base64url').toString('base64');
  const privateKey = new Uint8Array(seed);
  const base = Date.UTC(2026, 8, 1);
  const iso = (s: number) => new Date(base + s * 1000).toISOString();

  const specs: Array<{ id: string; signable: Record<string, unknown> }> = [
    {
      id: 'row-plain',
      signable: {
        organizationId: ORG, action: 'agent.created', actorId: null, actorType: 'system', resourceType: 'agent',
        resourceId: null, teamId: null, agentId: null, summary: 'Created agent', details: { a: 1 }, createdAt: iso(0),
      },
    },
    ...decisionRows.map((r, i) => ({
      id: r.id,
      signable: {
        organizationId: ORG, action: r.action, actorId: null, actorType: 'agent', resourceType: 'policy',
        resourceId: null, teamId: null, agentId: 'agent-1', createdAt: iso(60 * (i + 1)),
        detailsCommitment: r.detailsCommitment,
      },
    })),
  ];
  const rows: Record<string, unknown>[] = [];
  const leaves: Uint8Array[] = [];
  let prevRowHash = GENESIS_PREV_ROW_HASH;
  for (const s of specs) {
    const canonical = canonicalJson(s.signable);
    const signature = signEd25519(Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]), privateKey);
    rows.push({ id: s.id, ...s.signable, signature, keyVersion: 1, signedAt: s.signable.createdAt, prevRowHash });
    const leaf = Buffer.concat([canonical, Buffer.from(signature, 'base64')]);
    leaves.push(new Uint8Array(leaf));
    prevRowHash = sha256(leaf).toString('base64');
  }
  const tree = merkleBuild(leaves);
  const rootHash = Buffer.from(tree.root).toString('base64');
  const periodStart = iso(0);
  const periodEnd = iso(3600);
  const rootSignature = signEd25519(canonicalJson({ rootHash, periodStart, periodEnd, rowCount: rows.length }), privateKey);
  const root = {
    id: 'root-0', organizationId: ORG, periodStart, periodEnd, rowCount: rows.length, rootHash,
    signature: rootSignature, keyVersion: 1, signedAt: iso(3605), anchoredAt: null, anchorReceipt: null,
  };
  const proofs = rows.map((r, i) => {
    const p = merkleProof(leaves, i);
    return { rowId: r.id, index: p.index, proof: p.siblings.map((x) => Buffer.from(x).toString('base64')), rootHash };
  });
  const manifestSans = {
    version: 1, orgId: ORG, from: periodStart, to: periodEnd, rowCount: rows.length, rootCount: 1,
    keyVersions: [{ keyVersion: 1, publicKey: publicKeyB64 }], generatedAt: iso(3606), signatureAlgorithm: 'Ed25519' as const,
  };
  const manifest = { ...manifestSans, signature: signEd25519(canonicalJson(manifestSans), privateKey), signatureKeyVersion: 1 };
  const ndjsonGz = (xs: unknown[]) => gzipDeterministic(Buffer.from(xs.map((x) => JSON.stringify(x) + '\n').join(''), 'utf8'));
  return writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest), 'utf8') },
    { name: 'rows.ndjson.gz', data: ndjsonGz(rows) },
    { name: 'roots.ndjson.gz', data: ndjsonGz([root]) },
    { name: 'proofs.ndjson.gz', data: ndjsonGz(proofs) },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify({ '1': publicKeyB64 }), 'utf8') },
    { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
  ]);
}

const STEP_UP = { schemaVersion: 1, decisionId: 'dec-2', decision: 'STEP_UP', canonicalDecision: 'REQUIRE_APPROVAL', policyId: 'pol-1', policyVersion: '3', approvalId: 'appr-1', fnName: 'send_email' };
const STEP_UP_SALT = Buffer.alloc(16, 2).toString('base64');
const bundle = buildBundle([
  { id: 'row-d1', action: 'POLICY_DECISION', detailsCommitment: BE_COMMITMENT },
  { id: 'row-d2', action: 'POLICY_DECISION', detailsCommitment: commit(STEP_UP, STEP_UP_SALT) },
]);
const line = (rowId: string, details: Record<string, unknown>, detailsSalt: string, over: Record<string, unknown> = {}) =>
  ({ version: V, rowId, decisionId: typeof details.decisionId === 'string' ? details.decisionId : null, details, detailsSalt, ...over });
const ndjson = (lines: unknown[], withheld = 0) =>
  Buffer.from([...lines, { version: V, withheld }].map((l) => JSON.stringify(l) + '\n').join(''), 'utf8');
const genuine = [line('row-d1', BE_DETAILS, BE_SALT), line('row-d2', STEP_UP, STEP_UP_SALT)];
const opts = (decisionDisclosures?: Buffer): VerifyOptions => ({
  noRekor: true, allowLegacyUnattested: true, ...(decisionDisclosures ? { decisionDisclosures } : {}),
});

describe('AV-0009 decision disclosures', () => {
  it('pins be\'s commitment for the reference vector', () => {
    expect(commit(BE_DETAILS, BE_SALT)).toBe(BE_COMMITMENT);
  });

  it('genuine disclosures: decisionReceipt + policyReference valid, bundle valid, pairs reported', async () => {
    const r = await verifyBundle(bundle, opts(ndjson(genuine)));
    expect(r.decisionReceipt).toMatchObject({ status: 'valid', checked: 2, failed: 0 });
    expect(r.policyReference).toMatchObject({ status: 'valid', checked: 2, failed: 0 });
    expect(r.policyReference.reason).toMatch(/policy text is not in the package and is NOT verified/);
    expect(r.status).toBe('valid');
    expect(r.decisionDisclosures?.policyReferences).toEqual([{ policyId: 'pol-1', policyVersion: '3' }]);
    expect(r.decisionDisclosures?.decisions.map((d) => d.decisionId)).toEqual(['dec-1', 'dec-2']);
  });

  it('a flipped byte in details → invalid', async () => {
    const tampered = [line('row-d1', { ...BE_DETAILS, note: 'cafe ✓' }, BE_SALT), genuine[1]];
    const r = await verifyBundle(bundle, opts(ndjson(tampered)));
    expect(r.decisionReceipt).toMatchObject({ status: 'invalid', failed: 1, firstFailure: 'row-d1' });
    expect(r.decisionReceipt.reason).toMatch(/does not match the signed detailsCommitment/);
    expect(r.status).toBe('invalid');
    expect(r.decisionDisclosures).toBeUndefined();
  });

  it('a wrong salt → invalid', async () => {
    const r = await verifyBundle(bundle, opts(ndjson([line('row-d1', BE_DETAILS, STEP_UP_SALT), genuine[1]])));
    expect(r.decisionReceipt).toMatchObject({ status: 'invalid', firstFailure: 'row-d1' });
  });

  it('a disclosure for a row not in the bundle, or not a decision row → invalid', async () => {
    const foreign = await verifyBundle(bundle, opts(ndjson([...genuine, line('row-elsewhere', BE_DETAILS, BE_SALT)])));
    expect(foreign.decisionReceipt).toMatchObject({ status: 'invalid', firstFailure: 'row-elsewhere' });
    expect(foreign.decisionReceipt.reason).toMatch(/not in the bundle/);
    const plain = await verifyBundle(bundle, opts(ndjson([line('row-plain', { a: 1 }, BE_SALT)])));
    expect(plain.decisionReceipt).toMatchObject({ status: 'invalid', firstFailure: 'row-plain' });
  });

  it('decisionId must equal details.decisionId', async () => {
    const r = await verifyBundle(bundle, opts(ndjson([line('row-d1', BE_DETAILS, BE_SALT, { decisionId: 'dec-9' })])));
    expect(r.decisionReceipt.reason).toMatch(/decisionId does not match/);
  });

  it('withheld rows are counted and reported, not failed', async () => {
    const r = await verifyBundle(bundle, opts(ndjson([genuine[0]], 1)));
    expect(r.decisionReceipt).toMatchObject({ status: 'valid', checked: 1 });
    expect(r.decisionReceipt.reason).toMatch(/1 withheld .*1 commitment-signed decision rows in the bundle not opened/);
    expect(r.decisionDisclosures).toMatchObject({ withheld: 1, undisclosed: 1 });
  });

  it('no file → not_present for both components; bundle verdict unchanged', async () => {
    const r = await verifyBundle(bundle, opts());
    expect(r.decisionReceipt.status).toBe('not_present');
    expect(r.policyReference.status).toBe('not_present');
    expect(r.status).toBe('valid');
    expect(r.decisionDisclosures).toBeUndefined();
  });

  it('fails closed on a missing trailer, an unknown version, a duplicate and an unparseable line', async () => {
    const noTrailer = Buffer.from(genuine.map((l) => JSON.stringify(l) + '\n').join(''), 'utf8');
    const cases = [
      noTrailer,
      ndjson([{ ...genuine[0], version: 'praesidia.decision-disclosure.v2' }]),
      ndjson([genuine[0], genuine[0]]),
      Buffer.from('{not json}\n' + ndjson([]).toString(), 'utf8'),
      Buffer.from(
        `{"version":"${V}","rowId":"row-d1","decisionId":null,"details":{"x":1e400},"detailsSalt":"${BE_SALT}"}\n` + ndjson([]).toString(),
        'utf8',
      ),
    ];
    for (const c of cases) {
      expect((await verifyBundle(bundle, opts(c))).decisionReceipt.status).toBe('invalid');
    }
  });

  it('policyReference: malformed or contradictory references are invalid', async () => {
    const bad = [
      { ...BE_DETAILS, policyVersion: 3 },
      { ...BE_DETAILS, decision: 'MAYBE' },
      { ...BE_DETAILS, decision: 'DENY' }, // a DENY must be a POLICY_VIOLATION row
      { ...BE_DETAILS, reasonCode: 'approval_consumed' }, // ALLOW after step-up with no approvalId
      { ...BE_DETAILS, schemaVersion: 2 },
    ];
    for (const details of bad) {
      const salt = Buffer.alloc(16, 5).toString('base64');
      const b = buildBundle([{ id: 'row-x', action: 'POLICY_DECISION', detailsCommitment: commit(details, salt) }]);
      const r = await verifyBundle(b, opts(ndjson([line('row-x', details, salt)])));
      expect(r.decisionReceipt.status).toBe('valid');
      expect(r.policyReference.status).toBe('invalid');
    }
  });

  it('audit package: the entry is verified, not listed as an unverified side artifact', async () => {
    const receipt = Buffer.from(
      `Evidence archive SHA-256: ${crypto.createHash('sha256').update(bundle).digest('hex')}\nEvidence archive bytes: ${bundle.length}\n`,
    );
    const pkg = (entries: Array<{ name: string; data: Buffer }>) =>
      writeZip([{ name: 'evidence/audit-bundle.zip', data: bundle }, { name: 'verification.txt', data: receipt }, ...entries]);
    const withFile = await verifyAuditPackage(
      pkg([{ name: 'evidence/decision-receipts.ndjson', data: ndjson(genuine) }, { name: 'evaluations/summary.json', data: Buffer.from('{}') }]),
      opts(),
    );
    expect(withFile.decisionReceipt.status).toBe('valid');
    expect(withFile.package.sideArtifacts).toEqual(['evaluations/summary.json']);
    const without = await verifyAuditPackage(pkg([]), opts());
    expect(without.decisionReceipt.status).toBe('not_present');
    const entry = { name: 'evidence/decision-receipts.ndjson', data: ndjson(genuine) };
    await expect(verifyAuditPackage(pkg([entry]), opts(ndjson(genuine)))).rejects.toThrow(/--disclosures/);
  });

  it('--decision lookup: found + verified, not found, and not verified', async () => {
    const report = await verifyBundle(bundle, opts(ndjson(genuine)));
    const found = findVerifiedDecision(report, 'dec-2');
    expect(found).not.toBeNull();
    expect(formatDecision(found!).join('\n')).toMatch(/decision: +STEP_UP[\s\S]*policy: +pol-1@3[\s\S]*approvalId: +appr-1[\s\S]*tool: +send_email/);
    expect(findVerifiedDecision(report, 'dec-404')).toBeNull();
    expect(findVerifiedDecision({ ...report, status: 'incomplete' }, 'dec-2')).toBeNull();
  });

  describe('CLI (dist/cli.js)', () => {
    const cli = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js');
    it.runIf(fs.existsSync(cli))('--disclosures + --decision: exit 0 when verified, 1 when not found', () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-0009-'));
      try {
        const b = path.join(tmp, 'bundle.zip');
        const d = path.join(tmp, 'd.ndjson');
        fs.writeFileSync(b, bundle);
        fs.writeFileSync(d, ndjson(genuine));
        const run = (...args: string[]) =>
          spawnSync(process.execPath, [cli, b, '--no-rekor', '--allow-legacy-unattested', '--disclosures', d, ...args], { encoding: 'utf8' });
        const ok = run('--decision', 'dec-1');
        expect(ok.status).toBe(0);
        expect(ok.stdout).toMatch(/policy: +pol-1@3/);
        expect(run('--decision', 'dec-404').status).toBe(1);
        expect(run().stdout).toMatch(/decision receipts .*VALID|\[VALID +\] decision receipts/);
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });
  });
});
