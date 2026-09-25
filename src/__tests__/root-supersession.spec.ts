/**
 * AV-0016 — a superseding Merkle root repairs an hour whose first root was
 * partial. Both roots ship; the new one names the old one (`supersedesRootId`)
 * and signs the link (`supersessionSignature`). Every attack here must fail.
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';

import { verifyBundle, ROOT_SUPERSESSION_VERSION } from '../verify.js';
import { canonicalJson, signEd25519, sha256, merkleBuild, merkleProof, GENESIS_PREV_ROW_HASH } from '../crypto.js';
import { writeZip, gzipDeterministic } from '../zip.js';

const ORG = '00000000-0000-0000-0000-000000000001';
const BASE = Date.UTC(2026, 4, 1);
const iso = (sec: number) => new Date(BASE + sec * 1000).toISOString();

function keypair(fill: number) {
  const seed = Buffer.alloc(32, fill);
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const x = (crypto.createPublicKey(priv).export({ format: 'jwk' }) as { x: string }).x;
  return { pub: Buffer.from(x, 'base64url').toString('base64'), priv: new Uint8Array(seed) };
}
const KEY = keypair(7);
const OTHER = keypair(9);

type Root = Record<string, unknown> & { id: string; rootHash: string; periodStart: string; periodEnd: string; rowCount: number };
type Proof = { rowId: string; index: number; proof: string[]; rootHash: string };
interface Spec { id: string; rows: number[]; supersedes?: string; periodEndSec?: number }

function supersessionEnvelope(root: Root, supersededHash: string): Buffer {
  return canonicalJson({
    version: ROOT_SUPERSESSION_VERSION,
    supersedes: supersededHash,
    rootHash: root.rootHash,
    periodStart: root.periodStart,
    periodEnd: root.periodEnd,
    rowCount: root.rowCount,
  });
}

/** 4 chained rows in hour [0, 3600); one root per spec, proofs for every (row, root) pair. */
function build(specs: Spec[], mutate?: (roots: Root[], proofs: Proof[]) => void): Buffer {
  const rows: Record<string, unknown>[] = [];
  const leaves: Buffer[] = [];
  let prevRowHash = GENESIS_PREV_ROW_HASH;
  for (let i = 0; i < 4; i++) {
    const signable = {
      organizationId: ORG, action: 'agent.created', actorId: null, actorType: 'user',
      resourceType: 'agent', resourceId: `agent-${i}`, teamId: null, agentId: null,
      summary: null, details: null, createdAt: iso(i * 60),
    };
    const canonical = canonicalJson(signable);
    const signature = signEd25519(Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]), KEY.priv);
    rows.push({ id: `row-${i}`, ...signable, signature, keyVersion: 1, signedAt: iso(i * 60 + 1), prevRowHash });
    const leaf = Buffer.concat([canonical, Buffer.from(signature, 'base64')]);
    leaves.push(leaf);
    prevRowHash = sha256(leaf).toString('base64');
  }
  const roots: Root[] = [];
  const proofs: Proof[] = [];
  for (const s of specs) {
    const ls = s.rows.map((i) => new Uint8Array(leaves[i]!));
    const rootHash = Buffer.from(merkleBuild(ls).root).toString('base64');
    const root: Root = {
      id: s.id, organizationId: ORG, periodStart: iso(0), periodEnd: iso(s.periodEndSec ?? 3600),
      rowCount: s.rows.length, rootHash, signature: '', keyVersion: 1,
      signedAt: iso(3605), anchoredAt: null, anchorReceipt: null,
    };
    root.signature = signEd25519(
      canonicalJson({ rootHash, periodStart: root.periodStart, periodEnd: root.periodEnd, rowCount: root.rowCount }),
      KEY.priv,
    );
    roots.push(root);
    s.rows.forEach((rowIdx, i) => {
      const p = merkleProof(ls, i);
      proofs.push({ rowId: `row-${rowIdx}`, index: p.index, proof: p.siblings.map((x) => Buffer.from(x).toString('base64')), rootHash });
    });
  }
  for (const s of specs) {
    if (!s.supersedes) continue;
    const root = roots.find((r) => r.id === s.id)!;
    const old = roots.find((r) => r.id === s.supersedes)!;
    root.supersedesRootId = old.id;
    root.supersessionSignature = signEd25519(supersessionEnvelope(root, old.rootHash), KEY.priv);
  }
  mutate?.(roots, proofs);
  const to = iso(Math.max(3600, ...specs.map((s) => s.periodEndSec ?? 3600)));
  const manifestSans = {
    version: 1, orgId: ORG, from: iso(0), to, rowCount: rows.length, rootCount: roots.length,
    keyVersions: [{ keyVersion: 1, publicKey: KEY.pub }], generatedAt: to, signatureAlgorithm: 'Ed25519' as const,
  };
  const manifest = { ...manifestSans, signature: signEd25519(canonicalJson(manifestSans), KEY.priv), signatureKeyVersion: 1 };
  const nd = (xs: unknown[]) => gzipDeterministic(Buffer.from(xs.map((x) => JSON.stringify(x)).join('\n') + '\n'));
  return writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest)) },
    { name: 'rows.ndjson.gz', data: nd(rows) },
    { name: 'roots.ndjson.gz', data: nd(roots) },
    { name: 'proofs.ndjson.gz', data: nd(proofs) },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify({ 1: KEY.pub })) },
    { name: 'README.md', data: Buffer.from('# t\n') },
  ]);
}

const verify = (zip: Buffer, noRekor = true) => verifyBundle(zip, { allowLegacyUnattested: true, noRekor });
const PARTIAL: Spec = { id: 'root-1', rows: [0, 1] };
const FULL: Spec = { id: 'root-2', rows: [0, 1, 2, 3], supersedes: 'root-1' };

describe('AV-0016 — superseding Merkle root', () => {
  it('partial root + signed superseding root verify, and both roots are reported', async () => {
    const r = await verify(build([PARTIAL, FULL]));
    expect(r.status).toBe('valid');
    expect(r.rootSignatures.checked).toBe(3); // 2 root signatures + 1 supersession signature
    expect(r.rootCoverage.supersessions).toHaveLength(1);
    const line = r.rootCoverage.supersessions![0]!;
    expect(line).toContain('root root-1');
    expect(line).toContain('rowCount 2');
    expect(line).toContain('superseded by root root-2');
    expect(line).toContain('rowCount 4');
  });

  it('a linear chain of two supersessions verifies', async () => {
    const r = await verify(build([
      { id: 'root-1', rows: [0] },
      { id: 'root-2', rows: [0, 1], supersedes: 'root-1' },
      { id: 'root-3', rows: [0, 1, 2, 3], supersedes: 'root-2' },
    ]));
    expect(r.status).toBe('valid');
    expect(r.rootCoverage.supersessions).toHaveLength(2);
  });

  it('a bundle with no supersession is unchanged (no supersessions field, same counts)', async () => {
    const r = await verify(build([{ id: 'root-1', rows: [0, 1, 2, 3] }]));
    expect(r.status).toBe('valid');
    expect(r.rootSignatures.checked).toBe(1);
    expect(r.rootCoverage).not.toHaveProperty('supersessions');
  });

  it('the same bundle with the link removed fails', async () => {
    const r = await verify(build([PARTIAL, FULL], (roots) => {
      delete roots[1]!.supersedesRootId;
      delete roots[1]!.supersessionSignature;
    }));
    expect(r.status).toBe('invalid');
    expect(r.rootCoverage.status).toBe('invalid');
    expect(r.rootCoverage.firstFailure).toBe('root-1');
  });

  it('a link with no supersession signature fails', async () => {
    const r = await verify(build([PARTIAL, FULL], (roots) => { delete roots[1]!.supersessionSignature; }));
    expect(r.rootSignatures.status).toBe('invalid');
    expect(r.rootSignatures.reason).toMatch(/supersession signature/);
  });

  it('a forged supersession not bound to the old root hash fails', async () => {
    const r = await verify(build([PARTIAL, FULL], (roots) => {
      // The root's own signature (no `supersedes`), then a signature over another hash.
      roots[1]!.supersessionSignature = roots[1]!.signature;
    }));
    expect(r.rootSignatures.status).toBe('invalid');
    const r2 = await verify(build([PARTIAL, FULL], (roots) => {
      roots[1]!.supersessionSignature = signEd25519(supersessionEnvelope(roots[1]!, Buffer.alloc(32, 1).toString('base64')), KEY.priv);
    }));
    expect(r2.rootSignatures.status).toBe('invalid');
  });

  it('re-pointing a signed link at another root fails', async () => {
    const r = await verify(build([{ id: 'root-0', rows: [1, 0] }, PARTIAL, { ...FULL }], (roots) => {
      roots[2]!.supersedesRootId = 'root-0';
    }));
    expect(r.status).toBe('invalid');
    expect(r.rootSignatures.status).toBe('invalid');
  });

  it('a supersession signed by a different key fails', async () => {
    const r = await verify(build([PARTIAL, FULL], (roots) => {
      roots[1]!.supersessionSignature = signEd25519(supersessionEnvelope(roots[1]!, roots[0]!.rootHash), OTHER.priv);
    }));
    expect(r.rootSignatures.status).toBe('invalid');
    expect(r.status).toBe('invalid');
  });

  it('a superseding root with a lower rowCount fails', async () => {
    const r = await verify(build([{ id: 'root-1', rows: [0, 1, 2, 3] }, { id: 'root-2', rows: [0, 1], supersedes: 'root-1' }]));
    expect(r.rootCoverage.status).toBe('invalid');
    expect(r.rootCoverage.reason).toMatch(/rowCount/);
  });

  it('a superseding root with an equal rowCount fails', async () => {
    const r = await verify(build([{ id: 'root-1', rows: [0, 1, 2, 3] }, { id: 'root-2', rows: [3, 2, 1, 0], supersedes: 'root-1' }]));
    expect(r.rootCoverage.status).toBe('invalid');
    expect(r.rootCoverage.reason).toMatch(/rowCount/);
  });

  it('a period mismatch fails', async () => {
    const r = await verify(build([PARTIAL, { ...FULL, periodEndSec: 7200 }]));
    expect(r.rootCoverage.status).toBe('invalid');
    expect(r.rootCoverage.reason).toMatch(/period/);
  });

  it('a cycle fails', async () => {
    const r = await verify(build([{ ...PARTIAL, supersedes: 'root-2' }, FULL]));
    expect(r.status).toBe('invalid');
    expect(r.rootCoverage.status).toBe('invalid');
  });

  it('two roots superseding the same root fail', async () => {
    const r = await verify(build([PARTIAL, FULL, { id: 'root-3', rows: [3, 2, 1, 0], supersedes: 'root-1' }]));
    expect(r.rootCoverage.status).toBe('invalid');
    expect(r.rootCoverage.reason).toMatch(/already superseded/);
  });

  it('a link to a root absent from the bundle fails', async () => {
    const r = await verify(build([{ id: 'root-2', rows: [0, 1, 2, 3] }], (roots) => {
      roots[0]!.supersedesRootId = 'root-gone';
      roots[0]!.supersessionSignature = roots[0]!.signature;
    }));
    expect(r.status).toBe('invalid');
    expect(r.rootCoverage.reason).toMatch(/not in this bundle/);
  });

  it('a superseding root that drops a row of the old root fails', async () => {
    const r = await verify(build([PARTIAL, { id: 'root-2', rows: [1, 2, 3], supersedes: 'root-1' }]));
    expect(r.status).toBe('invalid');
    expect(r.inclusionProofs.status).toBe('invalid');
    expect(r.rootCoverage.status).toBe('invalid');
  });

  it('removing the proofs of the superseded root fails', async () => {
    const r = await verify(build([PARTIAL, FULL], (roots, proofs) => {
      const h = roots[0]!.rootHash;
      proofs.splice(0, proofs.length, ...proofs.filter((p) => p.rootHash !== h));
    }));
    expect(r.rootCoverage.status).toBe('invalid');
    expect(r.rootCoverage.firstFailure).toBe('root-1');
  });

  it('a row with two proofs into current roots still fails', async () => {
    const r = await verify(build([PARTIAL, FULL], (_roots, proofs) => { proofs.push({ ...proofs[2]! }); }));
    expect(r.inclusionProofs.status).toBe('invalid');
  });

  it("the superseded root's anchor receipt is still checked", async () => {
    const r = await verify(build([PARTIAL, FULL], (roots) => {
      roots[0]!.anchorReceipts = [{ provider: 'rekor', receipt: 'not-a-receipt', anchoredAt: iso(3700) }];
    }), false);
    expect(r.rekor.status).toBe('invalid');
    expect(r.rekor.firstFailure).toBe('root-1');
  });

  it('a malformed supersedesRootId is a format error', async () => {
    await expect(verify(build([PARTIAL, FULL], (roots) => { roots[1]!.supersedesRootId = 42; }))).rejects.toThrow(/invalid\/duplicate root/);
  });
});
