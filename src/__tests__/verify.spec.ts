/**
 * AGV-040 — Verifier acceptance tests.
 *
 * Builds a deterministic in-memory compliance bundle, then runs the
 * verifier against:
 *   - The pristine bundle (happy path).
 *   - Five distinct tampers, each isolated to one bundle component.
 *
 * The fixture builder uses the same vendored crypto / zip primitives
 * the verifier itself relies on; that's safe because the test
 * assertions check *behavior* (ok vs. failed, which component flagged
 * the offender), not byte-level equality with be-core fixtures. The
 * cross-implementation byte-compatibility claim is documented in the
 * package README and is the responsibility of the integration tests
 * against the live exporter (which live in be-core's test suite).
 */

import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';

import { verifyBundle } from '../verify.js';
import {
  canonicalJson,
  signEd25519,
  sha256,
  merkleBuild,
  merkleProof,
  GENESIS_PREV_ROW_HASH,
} from '../crypto.js';
import { writeZip, gzipDeterministic, readZip } from '../zip.js';

// ────────────────────────────────────────────────────────────────────────
// Fixture types — minimal shapes for the bundle wire format.
// ────────────────────────────────────────────────────────────────────────

interface FixtureRow {
  id: string;
  organizationId: string;
  action: string;
  actorId: string | null;
  actorType: string;
  resourceType: string | null;
  resourceId: string | null;
  teamId: string | null;
  agentId: string | null;
  summary: string | null;
  details: Record<string, unknown> | null;
  createdAt: string;
  signature: string;
  keyVersion: number;
  signedAt: string;
  prevRowHash: string;
}

interface FixtureRoot {
  id: string;
  organizationId: string;
  periodStart: string;
  periodEnd: string;
  rowCount: number;
  rootHash: string;
  signature: string;
  keyVersion: number;
  signedAt: string;
  anchoredAt: string | null;
  anchorReceipt: string | null;
}

interface FixtureProof {
  rowId: string;
  proof?: string[];
  index?: number;
  rootHash?: string;
  status?: string;
}

interface FixtureBundle {
  zip: Buffer;
  manifestPublicKey: Uint8Array;
  rows: FixtureRow[];
  roots: FixtureRoot[];
  proofs: FixtureProof[];
}

// ────────────────────────────────────────────────────────────────────────
// Deterministic Ed25519 keypair from a seed — used by the fixture so
// the bundle bytes are reproducible across runs.
// ────────────────────────────────────────────────────────────────────────

function keypairFromSeed(seed: Buffer): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  // PKCS#8 prefix for Ed25519 raw 32-byte private seed.
  const PKCS8_PREFIX = Buffer.from(
    '302e020100300506032b657004220420',
    'hex',
  );
  const der = Buffer.concat([PKCS8_PREFIX, seed]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const jwk = pub.export({ format: 'jwk' }) as { x?: string };
  if (!jwk.x) throw new Error('failed to derive Ed25519 public key');
  // base64url -> bytes
  const padded = jwk.x + '='.repeat((4 - (jwk.x.length % 4)) % 4);
  const pubBytes = Buffer.from(
    padded.replace(/-/g, '+').replace(/_/g, '/'),
    'base64',
  );
  return {
    publicKey: new Uint8Array(pubBytes),
    privateKey: new Uint8Array(seed),
  };
}

function isoSecond(base: number, offset: number): string {
  // base is in milliseconds; offset adds seconds.
  return new Date(base + offset * 1000).toISOString();
}

function signableRow(r: {
  organizationId: string;
  action: string;
  actorId: string | null;
  actorType: string;
  resourceType: string | null;
  resourceId: string | null;
  teamId: string | null;
  agentId: string | null;
  summary: string | null;
  details: Record<string, unknown> | null;
  createdAt: string;
}): Record<string, unknown> {
  return {
    organizationId: r.organizationId,
    action: r.action,
    actorId: r.actorId,
    actorType: r.actorType,
    resourceType: r.resourceType,
    resourceId: r.resourceId,
    teamId: r.teamId,
    agentId: r.agentId,
    summary: r.summary,
    details: r.details,
    createdAt: r.createdAt,
  };
}

/** Build a fully-signed, fully-verifiable compliance bundle in memory. */
function buildFixtureBundle(): FixtureBundle {
  const seed = Buffer.alloc(32, 7); // deterministic seed
  const { publicKey, privateKey } = keypairFromSeed(seed);
  const keyVersion = 1;
  const orgId = '00000000-0000-0000-0000-000000000001';

  // ── 1) Build four rows, chained ─────────────────────────────────────
  const baseTs = Date.UTC(2026, 4, 1, 0, 0, 0); // 2026-05-01T00:00:00Z
  const rows: FixtureRow[] = [];
  const rowSignablePayloads: Array<{
    signable: Record<string, unknown>;
    canonical: Buffer;
    signatureBase64: string;
  }> = [];

  for (let i = 0; i < 4; i++) {
    const createdAt = isoSecond(baseTs, i * 60);
    const signedAt = isoSecond(baseTs, i * 60 + 1);
    const partial = {
      organizationId: orgId,
      action: `agent.created`,
      actorId: '00000000-0000-0000-0000-00000000aa01',
      actorType: 'user',
      resourceType: 'agent',
      resourceId: `agent-${i}`,
      teamId: null,
      agentId: `agent-${i}`,
      summary: `Created agent: Agent ${i}`,
      details: { agentId: `agent-${i}`, name: `Agent ${i}` },
      createdAt,
    };
    const signable = signableRow(partial);
    const canonical = canonicalJson(signable);
    const signatureBase64 = signEd25519(canonical, privateKey);

    // prev_row_hash chains from the previous row's (canonical || sig).
    let prevRowHash: string;
    if (i === 0) {
      prevRowHash = GENESIS_PREV_ROW_HASH;
    } else {
      const prev = rowSignablePayloads[i - 1]!;
      const prevSigBytes = Buffer.from(prev.signatureBase64, 'base64');
      prevRowHash = sha256(
        Buffer.concat([prev.canonical, prevSigBytes]),
      ).toString('base64');
    }
    rows.push({
      id: `row-${i}`,
      ...partial,
      signature: signatureBase64,
      keyVersion,
      signedAt,
      prevRowHash,
    });
    rowSignablePayloads.push({ signable, canonical, signatureBase64 });
  }

  // ── 2) Build the Merkle tree over leaf = canonical || sig_bytes ─────
  const leaves = rowSignablePayloads.map((p) =>
    new Uint8Array(
      Buffer.concat([p.canonical, Buffer.from(p.signatureBase64, 'base64')]),
    ),
  );
  const tree = merkleBuild(leaves);
  const rootHashB64 = Buffer.from(tree.root).toString('base64');

  // ── 3) Sign the root envelope ───────────────────────────────────────
  const periodStart = isoSecond(baseTs, 0);
  const periodEnd = isoSecond(baseTs, 60 * 60);
  const rootMessage = canonicalJson({
    rootHash: rootHashB64,
    periodStart,
    periodEnd,
    rowCount: rows.length,
  });
  const rootSignature = signEd25519(rootMessage, privateKey);

  const roots: FixtureRoot[] = [
    {
      id: 'root-1',
      organizationId: orgId,
      periodStart,
      periodEnd,
      rowCount: rows.length,
      rootHash: rootHashB64,
      signature: rootSignature,
      keyVersion,
      signedAt: isoSecond(baseTs, 60 * 60 + 5),
      anchoredAt: null,
      anchorReceipt: null,
    },
  ];

  // ── 4) Build inclusion proofs (one per row) ─────────────────────────
  const proofs: FixtureProof[] = rows.map((row, i) => {
    const p = merkleProof(leaves, i);
    return {
      rowId: row.id,
      index: p.index,
      proof: p.siblings.map((s) => Buffer.from(s).toString('base64')),
      rootHash: rootHashB64,
    };
  });

  // ── 5) Build + sign the manifest ────────────────────────────────────
  const publicKeyB64 = Buffer.from(publicKey).toString('base64');
  const generatedAt = isoSecond(baseTs, 60 * 60 + 30);
  const manifestSans = {
    version: 1,
    orgId,
    from: periodStart,
    to: periodEnd,
    rowCount: rows.length,
    rootCount: roots.length,
    keyVersions: [{ keyVersion, publicKey: publicKeyB64 }],
    generatedAt,
    signatureAlgorithm: 'Ed25519' as const,
  };
  const manifestBytes = canonicalJson(manifestSans);
  const manifestSignature = signEd25519(manifestBytes, privateKey);
  const manifest = {
    ...manifestSans,
    signature: manifestSignature,
    signatureKeyVersion: keyVersion,
  };

  // ── 6) Pack the zip ─────────────────────────────────────────────────
  const publicKeys: Record<string, string> = {
    [String(keyVersion)]: publicKeyB64,
  };
  const rowsNdjson = Buffer.from(
    rows.map((r) => JSON.stringify(r)).join('\n') + '\n',
    'utf8',
  );
  const rootsNdjson = Buffer.from(
    roots.map((r) => JSON.stringify(r)).join('\n') + '\n',
    'utf8',
  );
  const proofsNdjson = Buffer.from(
    proofs.map((p) => JSON.stringify(p)).join('\n') + '\n',
    'utf8',
  );

  const zip = writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8') },
    { name: 'rows.ndjson.gz', data: gzipDeterministic(rowsNdjson) },
    { name: 'roots.ndjson.gz', data: gzipDeterministic(rootsNdjson) },
    { name: 'proofs.ndjson.gz', data: gzipDeterministic(proofsNdjson) },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8') },
    { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
  ]);

  return { zip, manifestPublicKey: publicKey, rows, roots, proofs };
}

/**
 * Build a fresh bundle but allow each tamper to mutate the rows /
 * roots / proofs / manifest / publicKeys *before* the zip is sealed.
 * This is the cleanest tamper surface: every signature is recomputed
 * against the tampered data so the *only* failure surface is the
 * specific cryptographic invariant the tamper targets.
 *
 * For tampers that should defeat the signature (e.g. flipping a byte
 * in a row payload AFTER signing), set the `postSign*` hook.
 */
function buildBundleWithTamper(opts: {
  postSignRowByte?: (rows: FixtureRow[]) => void;
  postSignPrevRowHash?: (rows: FixtureRow[]) => void;
  postSignRootSignature?: (roots: FixtureRoot[]) => void;
  postSignProofSibling?: (proofs: FixtureProof[]) => void;
  postSignManifestSignature?: (manifest: {
    signature: string;
  }) => void;
}): { zip: Buffer; rows: FixtureRow[]; roots: FixtureRoot[]; proofs: FixtureProof[] } {
  const base = buildFixtureBundle();

  // Apply tampers to the in-memory structs *after* signing.
  if (opts.postSignRowByte) opts.postSignRowByte(base.rows);
  if (opts.postSignPrevRowHash) opts.postSignPrevRowHash(base.rows);
  if (opts.postSignRootSignature) opts.postSignRootSignature(base.roots);
  if (opts.postSignProofSibling) opts.postSignProofSibling(base.proofs);

  // Rebuild manifest from scratch by re-parsing the original entry from
  // the freshly-built fixture zip, then optionally tamper its signature.
  const originalEntries = readBundleEntries(base.zip);
  const manifest = JSON.parse(
    originalEntries.get('manifest.json')!.toString('utf8'),
  ) as { signature: string };
  if (opts.postSignManifestSignature) opts.postSignManifestSignature(manifest);

  // Re-pack with the tampered structures.
  const publicKeys = JSON.parse(
    originalEntries.get('public-keys.json')!.toString('utf8'),
  ) as Record<string, string>;
  const rowsNdjson = Buffer.from(
    base.rows.map((r) => JSON.stringify(r)).join('\n') + '\n',
    'utf8',
  );
  const rootsNdjson = Buffer.from(
    base.roots.map((r) => JSON.stringify(r)).join('\n') + '\n',
    'utf8',
  );
  const proofsNdjson = Buffer.from(
    base.proofs.map((p) => JSON.stringify(p)).join('\n') + '\n',
    'utf8',
  );

  const zip = writeZip([
    {
      name: 'manifest.json',
      data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
    },
    { name: 'rows.ndjson.gz', data: gzipDeterministic(rowsNdjson) },
    { name: 'roots.ndjson.gz', data: gzipDeterministic(rootsNdjson) },
    { name: 'proofs.ndjson.gz', data: gzipDeterministic(proofsNdjson) },
    {
      name: 'public-keys.json',
      data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
    },
    { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
  ]);
  return { zip, rows: base.rows, roots: base.roots, proofs: base.proofs };
}

/** Helper — parse a zip into a name→data map without verifying anything. */
function readBundleEntries(zip: Buffer): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (const e of readZip(zip)) out.set(e.name, e.data);
  return out;
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

describe('verifyBundle', () => {
  it('verifies a pristine bundle (happy path)', async () => {
    const { zip } = buildBundleWithTamper({});
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.ok).toBe(true);
    expect(report.manifest.ok).toBe(true);
    expect(report.rowSignatures.ok).toBe(true);
    expect(report.chain.ok).toBe(true);
    expect(report.rootSignatures.ok).toBe(true);
    expect(report.inclusionProofs.ok).toBe(true);
    expect(report.bundle.rowsSeen).toBe(4);
    expect(report.bundle.rootsSeen).toBe(1);
    expect(report.bundle.proofsSeen).toBe(4);
  });

  it('detects a tampered row payload byte (row signature mismatch)', async () => {
    const { zip } = buildBundleWithTamper({
      postSignRowByte: (rows) => {
        // Flip one character of the `action` field on row 2 — leaves
        // the signature intact so the verifier surfaces a row-signature
        // failure rather than a parse error.
        rows[2]!.action = 'agent.deleted';
      },
    });
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.ok).toBe(false);
    expect(report.rowSignatures.ok).toBe(false);
    expect(report.rowSignatures.failed).toBeGreaterThan(0);
    expect(report.rowSignatures.firstFailure).toBe('row-2');
  });

  it('detects a tampered prev_row_hash (chain break)', async () => {
    const { zip } = buildBundleWithTamper({
      postSignPrevRowHash: (rows) => {
        // Replace prevRowHash on row 1 with the genesis hash so it
        // doesn't chain to row 0.
        rows[1]!.prevRowHash = GENESIS_PREV_ROW_HASH;
      },
    });
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.ok).toBe(false);
    expect(report.chain.ok).toBe(false);
    expect(report.chain.failed).toBeGreaterThan(0);
    expect(report.chain.firstFailure).toBe('row-1');
  });

  it('detects a tampered root signature', async () => {
    const { zip } = buildBundleWithTamper({
      postSignRootSignature: (roots) => {
        const buf = Buffer.from(roots[0]!.signature, 'base64');
        buf[0] = buf[0]! ^ 0xff;
        roots[0]!.signature = buf.toString('base64');
      },
    });
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.ok).toBe(false);
    expect(report.rootSignatures.ok).toBe(false);
    expect(report.rootSignatures.firstFailure).toBe('root-1');
  });

  it('detects a tampered inclusion proof sibling', async () => {
    const { zip } = buildBundleWithTamper({
      postSignProofSibling: (proofs) => {
        // Flip one byte of the first sibling hash of row-0's proof.
        // (Row 0 has >=1 sibling since the tree has 4 leaves.)
        const target = proofs[0]!;
        const sib0 = Buffer.from(target.proof![0]!, 'base64');
        sib0[0] = sib0[0]! ^ 0xff;
        target.proof![0] = sib0.toString('base64');
      },
    });
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.ok).toBe(false);
    expect(report.inclusionProofs.ok).toBe(false);
    expect(report.inclusionProofs.failed).toBeGreaterThan(0);
    expect(report.inclusionProofs.firstFailure).toBe('row-0');
  });

  it('detects a tampered manifest signature', async () => {
    const { zip } = buildBundleWithTamper({
      postSignManifestSignature: (manifest) => {
        const buf = Buffer.from(manifest.signature, 'base64');
        buf[0] = buf[0]! ^ 0xff;
        manifest.signature = buf.toString('base64');
      },
    });
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.ok).toBe(false);
    expect(report.manifest.ok).toBe(false);
    expect(report.manifest.failed).toBe(1);
  });
});
