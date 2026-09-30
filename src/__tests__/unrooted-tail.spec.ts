/**
 * AV-0032 — a bundle exported with `includeUnrooted=true` carries a
 * `{ rowId, status: 'not_yet_rooted' }` stub for each row the exporter could
 * not prove yet (bundle-exporter.service.ts `streamProofsGzipped`). Rows after
 * the latest root in the bundle are an honest, unrooted TAIL: `incomplete`
 * (exit 3), never `valid` and never `invalid`. Every other stub stays
 * `invalid`: one on a row inside a published root's period, one on a row
 * before the end of the latest root (a rooting gap), a malformed stub, any
 * other status, a stub for an absent row. The rows themselves stay fully
 * checked (signatures, chain).
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { verifyBundle } from '../verify.js';
import { canonicalJson, signEd25519, sha256, merkleBuild, merkleProof, GENESIS_PREV_ROW_HASH } from '../crypto.js';
import { writeZip, gzipDeterministic } from '../zip.js';

const ORG = '00000000-0000-0000-0000-000000000001';
const BASE = Date.UTC(2026, 4, 1);
const HOUR = 3600;
const iso = (sec: number) => new Date(BASE + sec * 1000).toISOString();

const SEED = Buffer.alloc(32, 7);
const PRIV = new Uint8Array(SEED);
const PUB = (() => {
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]),
    format: 'der',
    type: 'pkcs8',
  });
  const x = (crypto.createPublicKey(priv).export({ format: 'jwk' }) as { x: string }).x;
  return Buffer.from(x, 'base64url').toString('base64');
})();

type Row = Record<string, unknown> & { id: string; prevRowHash: string; summary: string };
type Proof = { rowId: string; status?: string; index?: number; proof?: string[]; rootHash?: string };
interface RootSpec { id: string; rows: number[]; hour: number }
interface Spec {
  /** createdAt second offsets, one chained row each (signedAt = createdAt + 1s). */
  rowSecs: number[];
  roots: RootSpec[];
  /** manifest `to`, in seconds from BASE. */
  toSec: number;
  mutate?: (rows: Row[], proofs: Proof[]) => void;
}

/** Rows chained and signed as the be writer does; rooted rows get real proofs, the rest `not_yet_rooted` stubs. */
function build(spec: Spec): Buffer {
  const rows: Row[] = [];
  const leaves: Buffer[] = [];
  let prevRowHash = GENESIS_PREV_ROW_HASH;
  spec.rowSecs.forEach((sec, i) => {
    const signable = {
      organizationId: ORG, action: 'gateway.degraded_window', actorId: null, actorType: 'system',
      resourceType: null, resourceId: null, teamId: null, agentId: null,
      summary: `row ${i}`, details: null, createdAt: iso(sec),
    };
    const canonical = canonicalJson(signable);
    const signature = signEd25519(Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]), PRIV);
    rows.push({ id: `row-${i}`, ...signable, signature, keyVersion: 1, signedAt: iso(sec + 1), prevRowHash });
    const leaf = Buffer.concat([canonical, Buffer.from(signature, 'base64')]);
    leaves.push(leaf);
    prevRowHash = sha256(leaf).toString('base64');
  });

  const roots: Record<string, unknown>[] = [];
  const proofs: Proof[] = rows.map((r) => ({ rowId: r.id, status: 'not_yet_rooted' }));
  for (const s of spec.roots) {
    const ls = s.rows.map((i) => new Uint8Array(leaves[i]!));
    const rootHash = Buffer.from(merkleBuild(ls).root).toString('base64');
    const periodStart = iso(s.hour * HOUR);
    const periodEnd = iso((s.hour + 1) * HOUR);
    const signature = signEd25519(canonicalJson({ rootHash, periodStart, periodEnd, rowCount: s.rows.length }), PRIV);
    roots.push({
      id: s.id, organizationId: ORG, periodStart, periodEnd, rowCount: s.rows.length, rootHash, signature,
      keyVersion: 1, signedAt: iso((s.hour + 1) * HOUR + 5), anchoredAt: null, anchorReceipt: null,
    });
    s.rows.forEach((rowIdx, i) => {
      const p = merkleProof(ls, i);
      proofs[rowIdx] = { rowId: `row-${rowIdx}`, index: p.index, proof: p.siblings.map((x) => Buffer.from(x).toString('base64')), rootHash };
    });
  }
  spec.mutate?.(rows, proofs);

  const to = iso(spec.toSec);
  const manifestSans = {
    version: 1, orgId: ORG, from: iso(0), to, rowCount: rows.length, rootCount: roots.length,
    keyVersions: [{ keyVersion: 1, publicKey: PUB }], generatedAt: to, signatureAlgorithm: 'Ed25519' as const,
  };
  const manifest = { ...manifestSans, signature: signEd25519(canonicalJson(manifestSans), PRIV), signatureKeyVersion: 1 };
  const nd = (xs: unknown[]) => gzipDeterministic(Buffer.from(xs.map((x) => JSON.stringify(x)).join('\n') + (xs.length ? '\n' : '')));
  return writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest)) },
    { name: 'rows.ndjson.gz', data: nd(rows) },
    { name: 'roots.ndjson.gz', data: nd(roots) },
    { name: 'proofs.ndjson.gz', data: nd(proofs) },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify({ 1: PUB })) },
    { name: 'README.md', data: Buffer.from('# t\n') },
  ]);
}

const verify = (zip: Buffer) => verifyBundle(zip, { allowLegacyUnattested: true, noRekor: true });

/** Hour 0 rooted (rows 0, 1); rows 2, 3 in the still-open hour 1 — the includeUnrooted=true shape. */
const TAIL: Spec = { rowSecs: [60, 120, HOUR + 60, HOUR + 120], roots: [{ id: 'root-1', rows: [0, 1], hour: 0 }], toSec: 2 * HOUR };
const withMutate = (mutate: Spec['mutate']): Spec => ({ ...TAIL, mutate });

describe('AV-0032 — not_yet_rooted stubs in an unrooted tail', () => {
  it('rooted head + stub-only unrooted tail → incomplete, rows counted, every row still checked', async () => {
    const r = await verify(build(TAIL));
    expect(r.status).toBe('incomplete');
    expect(r.ok).toBe(false);
    expect(r.inclusionProofs).toMatchObject({ status: 'incomplete', ok: false, checked: 4, failed: 0, firstFailure: 'row-2' });
    expect(r.inclusionProofs.reason).toMatch(/^not_yet_rooted: 2 of 4 row\(s\) have no inclusion proof yet/);
    expect(r.inclusionProofs.reason).toContain(iso(HOUR));
    expect(r.rowSignatures.status).toBe('valid');
    expect(r.chain.status).toBe('valid');
    expect(r.rootSignatures.status).toBe('valid');
    expect(r.rootCoverage.status).toBe('valid');
  });

  it('no root at all (fresh org, open hour only) → incomplete, never invalid', async () => {
    const r = await verify(build({ rowSecs: [60, 120], roots: [], toSec: HOUR }));
    expect(r.status).toBe('incomplete');
    expect(r.inclusionProofs).toMatchObject({ status: 'incomplete', checked: 2, failed: 0 });
    expect(r.inclusionProofs.reason).toContain('2 of 2 row(s)');
    expect(r.rowSignatures.status).toBe('valid');
  });

  it('a stub claimed for a row inside a published root → invalid', async () => {
    const r = await verify(build(withMutate((_, proofs) => {
      proofs[1] = { rowId: 'row-1', status: 'not_yet_rooted' };
    })));
    expect(r.status).toBe('invalid');
    expect(r.inclusionProofs).toMatchObject({ status: 'invalid', firstFailure: 'row-1' });
    expect(r.inclusionProofs.reason).toContain('inside the period of published root root-1');
  });

  it('a stub in a rooting gap (before the latest root) → invalid', async () => {
    const r = await verify(build({
      rowSecs: [60, HOUR + 60, 2 * HOUR + 60],
      roots: [{ id: 'root-1', rows: [0], hour: 0 }, { id: 'root-3', rows: [2], hour: 2 }],
      toSec: 3 * HOUR,
    }));
    expect(r.status).toBe('invalid');
    expect(r.inclusionProofs).toMatchObject({ status: 'invalid', firstFailure: 'row-1' });
    expect(r.inclusionProofs.reason).toContain('before the end of the latest published root');
  });

  it('a tampered row in the unrooted tail → invalid', async () => {
    const r = await verify(build(withMutate((rows) => {
      rows[3]!.summary = 'rewritten after signing';
    })));
    expect(r.status).toBe('invalid');
    expect(r.rowSignatures).toMatchObject({ status: 'invalid', firstFailure: 'row-3' });
  });

  it('a chain break in the unrooted tail → invalid', async () => {
    const r = await verify(build(withMutate((rows) => {
      rows[2]!.prevRowHash = Buffer.alloc(32, 1).toString('base64');
    })));
    expect(r.status).toBe('invalid');
    expect(r.chain.status).toBe('invalid');
  });

  it.each<[string, (proofs: Proof[]) => void, string]>([
    ['a stub that also carries proof fields', (p) => { p[3] = { ...p[3]!, rootHash: p[0]!.rootHash, index: 0, proof: [] }; }, 'malformed not_yet_rooted stub'],
    ['any other stub status in the tail', (p) => { p[3] = { rowId: 'row-3', status: 'error' }; }, 'status=error'],
    ['a stub for a row absent from rows.ndjson.gz', (p) => { p.push({ rowId: 'row-99', status: 'not_yet_rooted' }); }, 'not present in rows.ndjson.gz'],
    ['a duplicate stub', (p) => { p.push({ rowId: 'row-3', status: 'not_yet_rooted' }); }, 'duplicate proof entry'],
  ])('%s → invalid', async (_, mutate, reason) => {
    const r = await verify(build(withMutate((_rows, proofs) => mutate(proofs))));
    expect(r.status).toBe('invalid');
    expect(r.inclusionProofs.status).toBe('invalid');
    expect(r.inclusionProofs.reason).toContain(reason);
  });

  it('CLI: unrooted tail exits 3 (INCOMPLETE); a stub on a rooted row exits 1', () => {
    const cliPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js');
    expect(fs.existsSync(cliPath), 'npm run build must run before npm test').toBe(true);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-0032-'));
    const run = (zip: Buffer, extra: string[] = []) => {
      const file = path.join(tmp, `${crypto.randomUUID()}.zip`);
      fs.writeFileSync(file, zip);
      try {
        return { code: 0, stdout: execFileSync(process.execPath, [cliPath, file, '--no-rekor', '--allow-legacy-unattested', ...extra], { encoding: 'utf8', stdio: 'pipe' }) };
      } catch (e) {
        const err = e as { status: number; stdout: string };
        return { code: err.status, stdout: err.stdout };
      }
    };
    try {
      const tail = run(build(TAIL));
      expect(tail.code).toBe(3);
      expect(tail.stdout).toMatch(/\[INCOMPLETE {1,}\] inclusion proofs .*not_yet_rooted: 2 of 4 row\(s\)/);
      expect(run(build(TAIL), ['--quiet'])).toEqual({ code: 3, stdout: 'INCOMPLETE\n' });
      const json = run(build(TAIL), ['--json']);
      expect(json.code).toBe(3);
      expect(JSON.parse(json.stdout)).toMatchObject({ status: 'incomplete', inclusionProofs: { status: 'incomplete', failed: 0 } });
      const rootedStub = run(build(withMutate((_, proofs) => { proofs[0] = { rowId: 'row-0', status: 'not_yet_rooted' }; })));
      expect(rootedStub.code).toBe(1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
