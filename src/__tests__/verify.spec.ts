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
import * as zlib from 'node:zlib';

import { verifyBundle } from '../verify.js';
import {
  canonicalJson,
  signEd25519,
  sha256,
  merkleBuild,
  merkleProof,
  isLowSP256,
  extractEcdsaSFromSignature,
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
  // AUDIT-2026-05-09 — multi-anchor receipts array. Optional so the
  // legacy single-slot fixture still compiles without changes.
  anchorReceipts?: Array<{
    provider: string;
    receipt: string;
    anchoredAt: string;
  }>;
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
  const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
  const der = Buffer.concat([PKCS8_PREFIX, seed]);
  const priv = crypto.createPrivateKey({
    key: der,
    format: 'der',
    type: 'pkcs8',
  });
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

    // prev_row_hash chains from the previous row's (canonical || sig).
    // AUDIT-SDK-01 — compute it BEFORE signing so the row signature can
    // bind it (the backend writer signs `canonical || prev_row_hash`).
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

    // AUDIT-SDK-01 — sign `canonical || prev_row_hash_bytes`, byte-for-byte
    // as `audit-writer.service.ts` persistSignedLog does. The prior fixture
    // signed canonical-ONLY, which mirrored the verifier defect and hid it.
    const rowMessage = Buffer.concat([
      canonical,
      Buffer.from(prevRowHash, 'base64'),
    ]);
    const signatureBase64 = signEd25519(rowMessage, privateKey);

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
  const leaves = rowSignablePayloads.map(
    (p) =>
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
  postSignManifestSignature?: (manifest: { signature: string }) => void;
}): {
  zip: Buffer;
  rows: FixtureRow[];
  roots: FixtureRoot[];
  proofs: FixtureProof[];
} {
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

  /**
   * BUG-AUDIT-01 — Trailing-truncation bypass.
   *
   * `manifest.rowCount` / `manifest.rootCount` are covered by the
   * manifest signature. An attacker who deletes the trailing rows (and
   * their proofs) leaves a shorter prefix that still chains from genesis
   * and whose surviving proofs still verify — so before this fix the
   * bundle returned `ok: true`. The `completeness` component must now
   * catch the count mismatch and fail the bundle (CLI exit 1).
   */
  describe('AUDIT-SDK-01 — row signature binds prev_row_hash', () => {
    // The backend signs each row over `canonical(row) || prev_row_hash_bytes`
    // (audit-writer.service.ts persistSignedLog). The pristine fixture now
    // mirrors that preimage byte-for-byte; these tests pin the binding and
    // prove a canonical-ONLY signature (the historical verifier defect AND
    // the old self-consistent fixture bug) now FAILS.
    const SEED = Buffer.alloc(32, 7); // identical seed to buildFixtureBundle()

    it('verifies rows signed over canonical || prev_row_hash (backend-writer preimage)', async () => {
      const { zip } = buildFixtureBundle();
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(true);
      expect(report.rowSignatures.checked).toBe(4);
      expect(report.rowSignatures.failed).toBe(0);
      expect(report.ok).toBe(true);
    });

    it('FAILS a row signed over canonical-ONLY (the omitted prev_row_hash regression)', async () => {
      const { privateKey } = keypairFromSeed(SEED);
      const entries = readBundleEntries(buildFixtureBundle().zip);

      // Re-sign row-0 the OLD (buggy) way — over canonical bytes only, with
      // NO prev_row_hash bound. A verifier that omitted prev_row_hash would
      // (wrongly) accept this; the fixed verifier must reject it.
      const rows = zlib
        .gunzipSync(entries.get('rows.ndjson.gz')!)
        .toString('utf8')
        .split('\n')
        .filter((l) => l.length > 0)
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      const canonicalOnly = canonicalJson(
        signableRow(rows[0] as unknown as Parameters<typeof signableRow>[0]),
      );
      rows[0]!.signature = signEd25519(canonicalOnly, privateKey);

      const tamperedRows = Buffer.from(
        rows.map((r) => JSON.stringify(r)).join('\n') + '\n',
        'utf8',
      );
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: gzipDeterministic(tamperedRows) },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        { name: 'public-keys.json', data: entries.get('public-keys.json')! },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.rowSignatures.firstFailure).toBe('row-0');
      expect(report.rowSignatures.reason).toBe('row signature does not verify');
      expect(report.ok).toBe(false);
    });

    it('FAILS closed when a row prev_row_hash is missing (cannot reconstruct preimage)', async () => {
      const entries = readBundleEntries(buildFixtureBundle().zip);
      const rows = zlib
        .gunzipSync(entries.get('rows.ndjson.gz')!)
        .toString('utf8')
        .split('\n')
        .filter((l) => l.length > 0)
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      delete rows[0]!.prevRowHash;

      const tamperedRows = Buffer.from(
        rows.map((r) => JSON.stringify(r)).join('\n') + '\n',
        'utf8',
      );
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: gzipDeterministic(tamperedRows) },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        { name: 'public-keys.json', data: entries.get('public-keys.json')! },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.rowSignatures.firstFailure).toBe('row-0');
      expect(report.rowSignatures.reason).toMatch(/prev_row_hash/);
    });
  });

  describe('BUG-AUDIT-01 — completeness / truncation', () => {
    /**
     * Re-pack the pristine fixture keeping the ORIGINAL signed manifest
     * (which declares rowCount=4) but dropping the trailing `dropRows`
     * rows and their proofs from the ndjson members.
     */
    function rebuildTruncated(dropRows: number): Buffer {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const keptRows = base.rows.slice(0, base.rows.length - dropRows);
      const keptRowIds = new Set(keptRows.map((r) => r.id));
      const keptProofs = base.proofs.filter((p) => keptRowIds.has(p.rowId));
      const rowsNdjson = Buffer.from(
        keptRows.map((r) => JSON.stringify(r)).join('\n') + '\n',
        'utf8',
      );
      const proofsNdjson = Buffer.from(
        keptProofs.map((p) => JSON.stringify(p)).join('\n') + '\n',
        'utf8',
      );
      return writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: gzipDeterministic(rowsNdjson) },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: gzipDeterministic(proofsNdjson) },
        { name: 'public-keys.json', data: entries.get('public-keys.json')! },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
    }

    it('fails a bundle with trailing rows + proofs truncated (was OK before the fix)', async () => {
      const zip = rebuildTruncated(1); // drop the last row + its proof
      const report = await verifyBundle(zip, { noRekor: true });

      // The surviving prefix still chains + proves — every crypto
      // component is individually happy…
      expect(report.chain.ok).toBe(true);
      expect(report.inclusionProofs.ok).toBe(true);
      expect(report.rowSignatures.ok).toBe(true);
      // …but completeness catches the signed-vs-present count mismatch.
      expect(report.completeness.ok).toBe(false);
      expect(report.completeness.failed).toBeGreaterThan(0);
      expect(report.completeness.reason).toMatch(/row count mismatch/);
      expect(report.bundle.rowsSeen).toBe(3);
      expect(report.bundle.declaredRowCount).toBe(4);
      // Overall bundle FAILS → CLI exit 1.
      expect(report.ok).toBe(false);
    });

    it('passes completeness for a pristine (untruncated) bundle', async () => {
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.completeness.ok).toBe(true);
      expect(report.completeness.checked).toBe(2);
      expect(report.completeness.failed).toBe(0);
    });
  });

  /**
   * BUG-AUDIT-03 — Verification keys cross-checked against the signed
   * manifest.keyVersions set.
   *
   * public-keys.json is unsigned; manifest.keyVersions is covered by the
   * manifest signature. A swapped public-keys.json (a key not byte-present
   * in the signed set) must fail the `keyBinding` component.
   */
  describe('BUG-AUDIT-03 — key binding cross-check', () => {
    it('fails when public-keys.json is swapped for a key not in the signed manifest', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      // A completely different keypair, NOT the one in manifest.keyVersions.
      const attacker = keypairFromSeed(Buffer.alloc(32, 9));
      const attackerB64 = Buffer.from(attacker.publicKey).toString('base64');
      const swappedKeys: Record<string, string> = { '1': attackerB64 };
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(swappedKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.keyBinding.ok).toBe(false);
      expect(report.keyBinding.failed).toBe(1);
      expect(report.keyBinding.firstFailure).toBe('1');
      expect(report.keyBinding.reason).toMatch(/key_bytes_mismatch/);
    });

    it('fails when public-keys.json declares a keyVersion absent from the signed set', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, string>;
      // Add an extra, unsigned key version.
      const extra = keypairFromSeed(Buffer.alloc(32, 11));
      publicKeys['2'] = Buffer.from(extra.publicKey).toString('base64');
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.keyBinding.ok).toBe(false);
      expect(report.keyBinding.reason).toMatch(/key_not_in_signed_manifest/);
    });

    it('passes key binding for a pristine bundle', async () => {
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.keyBinding.ok).toBe(true);
      expect(report.keyBinding.checked).toBe(1);
      expect(report.keyBinding.failed).toBe(0);
    });
  });

  /**
   * AUDIT-2026-05-14 — Revoked-key acceptance window.
   *
   * The exporter now emits each key in `public-keys.json` as
   * `{ publicKey, status, revokedAt }`. The verifier MUST accept rows
   * signed BEFORE `revokedAt` (otherwise revoking a key would orphan
   * the entire pre-revocation history) and reject rows signed AFTER
   * it (otherwise revocation has no forward-looking force).
   */
  describe('BUG-AUDIT-02 — REVOKED key fails closed (no signedAt grace)', () => {
    /**
     * Re-pack the pristine fixture's `public-keys.json` to declare the
     * (single) signing key as REVOKED at `revokedAt`. Re-signing isn't
     * needed because every row + manifest signature was minted with
     * THAT key; the test only flips the lifecycle metadata.
     */
    function rebuildWithRevokedKey(revokedAt: string | null): Buffer {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const publicKeyB64 = Buffer.from(base.manifestPublicKey).toString(
        'base64',
      );
      const publicKeys: Record<
        string,
        { publicKey: string; status: string; revokedAt: string | null }
      > = {
        '1': {
          publicKey: publicKeyB64,
          status: 'REVOKED',
          revokedAt,
        },
      };
      return writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
    }

    it('row signedAt BEFORE revokedAt + REVOKED status → still FAILS (grace removed)', async () => {
      // Every fixture row signs at baseTs + i*60 + 1s. Revoke at +05:00,
      // comfortably AFTER every row's signedAt — under the old grace this
      // verified OK. `signedAt` is not signed, so a revoked-key holder
      // could forge exactly this shape; the verifier now fails closed.
      const revokedAt = new Date(Date.UTC(2026, 4, 1, 0, 5, 0)).toISOString();
      const zip = rebuildWithRevokedKey(revokedAt);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.rowSignatures.failed).toBe(4);
      expect(report.rowSignatures.firstFailure).toBe('row-0');
      expect(report.rowSignatures.reason).toBe('key_revoked');
      // The root is signed by the same (now REVOKED) key → also fails.
      expect(report.rootSignatures.ok).toBe(false);
      expect(report.rootSignatures.reason).toBe('key_revoked');
    });

    it('row signedAt AFTER revokedAt + REVOKED status → FAILS with key_revoked', async () => {
      // Revoke BEFORE the first row signs (at baseTs - 1h).
      const revokedAt = new Date(Date.UTC(2026, 3, 30, 23, 0, 0)).toISOString();
      const zip = rebuildWithRevokedKey(revokedAt);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.rowSignatures.failed).toBe(4);
      expect(report.rowSignatures.firstFailure).toBe('row-0');
      expect(report.rowSignatures.reason).toBe('key_revoked');
    });

    it('REVOKED entry with no revokedAt → FAILS with key_revoked', async () => {
      const zip = rebuildWithRevokedKey(null);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.rowSignatures.reason).toBe('key_revoked');
    });

    it('legacy v1 public-keys.json (bare base64 string) still verifies', async () => {
      // Pre-AUDIT-14 bundles wrote `{ "1": "<base64>" }`. The verifier
      // must keep reading those without forcing operators to rebuild
      // their archive.
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const publicKeyB64 = Buffer.from(base.manifestPublicKey).toString(
        'base64',
      );
      const legacyShape: Record<string, string> = { '1': publicKeyB64 };
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(legacyShape, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(true);
      expect(report.rowSignatures.ok).toBe(true);
    });
  });

  /**
   * AUDIT-2026-05-09 — Multi-anchor receipt verification.
   *
   * The exporter now emits `anchorReceipts: [{provider, receipt,
   * anchoredAt}, ...]` per root so dual-anchored roots (e.g. Rekor +
   * S3) preserve BOTH receipts. The verifier dispatches on
   * `provider` and verifies each entry independently; the report's
   * `rekor` component aggregates the per-entry results.
   */
  describe('AUDIT-2026-05-09 — multi-anchor receipts', () => {
    /**
     * Rebuild the pristine fixture's `roots.ndjson.gz` to attach an
     * `anchorReceipts` array. Re-signing isn't needed because the
     * receipts are not part of the root's signed envelope (which is
     * `{rootHash, periodStart, periodEnd, rowCount}` — see
     * `verifyRootSignatures`).
     */
    function rebuildWithReceipts(
      receipts: Array<{
        provider: string;
        receipt: string;
        anchoredAt: string;
      }>,
      legacyAnchorReceipt: string | null = null,
    ): Buffer {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const root = base.roots[0]!;
      const patched: FixtureRoot = {
        ...root,
        anchoredAt: receipts[0]?.anchoredAt ?? null,
        anchorReceipt: legacyAnchorReceipt,
        anchorReceipts: receipts,
      };
      const rootsNdjson = Buffer.from(JSON.stringify(patched) + '\n', 'utf8');
      return writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: gzipDeterministic(rootsNdjson) },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        { name: 'public-keys.json', data: entries.get('public-keys.json')! },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
    }

    it('verifies a dual-anchor root (rekor + s3) — both providers checked independently', async () => {
      const zip = rebuildWithReceipts([
        {
          provider: 'rekor',
          receipt: '{"logIndex":9001}',
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
        {
          provider: 's3',
          receipt: 's3:my-bucket:audit-roots/org/period.json:v123',
          anchoredAt: '2026-05-01T01:00:05.000Z',
        },
      ]);

      const report = await verifyBundle(zip, {
        // Default rekor fetcher just parses JSON — our '{"logIndex":9001}'
        // receipt is parseable so it passes.
      });
      expect(report.ok).toBe(true);
      expect(report.rekor.ok).toBe(true);
      // Two entries on one root → checked = 2.
      expect(report.rekor.checked).toBe(2);
      expect(report.rekor.failed).toBe(0);
    });

    it('synthesizes a rekor entry from the legacy anchorReceipt scalar when anchorReceipts is empty', async () => {
      // Empty multi-anchor array but legacy slot populated. The
      // verifier must still verify the legacy receipt (the migration
      // backfill writes this synthesis into the array, but bundles
      // captured from older snapshots may not have run the backfill).
      const zip = rebuildWithReceipts([], '{"logIndex":9001}');

      const report = await verifyBundle(zip, {});
      expect(report.ok).toBe(true);
      expect(report.rekor.ok).toBe(true);
      expect(report.rekor.checked).toBe(1);
      expect(report.rekor.failed).toBe(0);
    });

    it('flags an unknown provider as failed with reason=unknown_provider but still reports per-entry', async () => {
      const zip = rebuildWithReceipts([
        {
          provider: 'rekor',
          receipt: '{"logIndex":9001}',
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
        {
          provider: 'mystery-notary',
          receipt: 'notary:abc123',
          anchoredAt: '2026-05-01T01:00:05.000Z',
        },
      ]);

      const report = await verifyBundle(zip, {});
      expect(report.ok).toBe(false);
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.checked).toBe(2);
      expect(report.rekor.failed).toBe(1);
      expect(report.rekor.reason).toContain('mystery-notary');
      expect(report.rekor.reason).toContain('unknown_provider');
    });

    it('rejects a malformed s3 receipt shape (offline check)', async () => {
      const zip = rebuildWithReceipts([
        {
          provider: 's3',
          // Missing versionId segment.
          receipt: 's3:my-bucket:audit-roots/period.json',
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
      ]);

      const report = await verifyBundle(zip, {});
      expect(report.ok).toBe(false);
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.failed).toBe(1);
      expect(report.rekor.reason).toContain('s3');
      expect(report.rekor.reason).toContain('malformed');
    });

    it('honours a caller-supplied anchorReceiptVerifier for ALL providers (overrides defaults)', async () => {
      const calls: Array<{ provider: string; receipt: string }> = [];
      const zip = rebuildWithReceipts([
        {
          provider: 'rekor',
          receipt: 'rekor:9001',
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
        {
          provider: 's3',
          receipt: 's3:b:k:v',
          anchoredAt: '2026-05-01T01:00:05.000Z',
        },
      ]);

      const report = await verifyBundle(zip, {
        anchorReceiptVerifier: async (entry) => {
          calls.push({ provider: entry.provider, receipt: entry.receipt });
          return { ok: true };
        },
      });

      expect(report.ok).toBe(true);
      expect(report.rekor.ok).toBe(true);
      expect(calls).toEqual([
        { provider: 'rekor', receipt: 'rekor:9001' },
        { provider: 's3', receipt: 's3:b:k:v' },
      ]);
    });
  });

  /**
   * AUDIT-2026-05-01 — Algorithm-aware verifier.
   *
   * Bundles produced under the `aws-kms` substrate carry
   * `signatureAlgorithm: 'ECDSA_P256_SHA256'`. The verifier now
   * dispatches per-envelope (manifest, row, root) on the declared
   * algorithm so KMS-substrate bundles round-trip cleanly. The
   * downgrade defence relies on the natural key-type mismatch inside
   * `crypto.verify` — `signatureAlgorithm` is intentionally NOT part
   * of the canonical signing bytes, but a forged downgrade ends up
   * feeding (e.g.) an Ed25519 SPKI to `crypto.verify('sha256', ...)`,
   * which returns `false`.
   */
  describe('AUDIT-2026-05-01 — algorithm-aware envelope dispatch', () => {
    /**
     * Helper — sign `message` with `privateKey` using ECDSA-P256-SHA256
     * and re-sign until the result satisfies the canonical low-s rule
     * (AUDIT-21). Mirrors the substrate's sign-side flip so the
     * fixture bundles always carry signatures the verifier will accept.
     */
    function signLowSP256(
      message: Buffer,
      privateKey: crypto.KeyObject,
    ): Buffer {
      for (let i = 0; i < 64; i++) {
        const candidate = crypto.sign('sha256', message, privateKey);
        if (isLowSP256(candidate)) {
          return candidate;
        }
        // Flip s to n - s and rebuild a canonical DER. Reuses the
        // helper signature `(r, s) → (r, n - s)`; cheaper than
        // rolling fresh randomness.
        const s = extractEcdsaSFromSignature(candidate)!;
        const P256_N = BigInt(
          '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
        );
        return reencodeDerWithS(candidate, P256_N - s);
      }
      throw new Error('unreachable');
    }

    /** DER re-encode with a new s value — same helper as the low-s spec. */
    function reencodeDerWithS(sig: Buffer, newS: bigint): Buffer {
      if (sig[0] !== 0x30) {
        throw new Error('not DER');
      }
      let off = 2;
      const firstLen = sig[1]!;
      if (firstLen & 0x80) {
        off += firstLen & 0x7f;
      }
      if (sig[off] !== 0x02) {
        throw new Error('expected INTEGER r');
      }
      const rLen = sig[off + 1]!;
      const rBytes = sig.subarray(off + 2, off + 2 + rLen);
      let sHex = newS.toString(16);
      if (sHex.length % 2 === 1) {
        sHex = '0' + sHex;
      }
      let sBytes = Buffer.from(sHex, 'hex');
      while (sBytes.length > 1 && sBytes[0] === 0x00) {
        sBytes = sBytes.subarray(1);
      }
      if (sBytes[0]! & 0x80) {
        sBytes = Buffer.concat([Buffer.from([0x00]), sBytes]);
      }
      const rField = Buffer.concat([
        Buffer.from([0x02, rBytes.length]),
        rBytes,
      ]);
      const sField = Buffer.concat([
        Buffer.from([0x02, sBytes.length]),
        sBytes,
      ]);
      const inner = Buffer.concat([rField, sField]);
      return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
    }

    /**
     * Build a single-row ECDSA-P256 signed bundle. Mirrors the
     * Ed25519 `buildFixtureBundle` but routes every signature through
     * `crypto.sign('sha256', ...)` against a P-256 keypair. The
     * resulting bundle declares `signatureAlgorithm: 'ECDSA_P256_SHA256'`
     * on the manifest, the root, and every row.
     */
    function buildEcdsaFixtureBundle(): { zip: Buffer } {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });
      const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' });
      const publicKeyDerB64 = Buffer.from(publicKeyDer).toString('base64');
      const keyVersion = 1;
      const orgId = '00000000-0000-0000-0000-000000000abc';
      const baseTs = Date.UTC(2026, 4, 1, 0, 0, 0);

      // ── Single row, deterministic shape ─────────────────────────────
      const partial = {
        organizationId: orgId,
        action: 'agent.created',
        actorId: '00000000-0000-0000-0000-00000000aa01',
        actorType: 'user',
        resourceType: 'agent',
        resourceId: 'agent-0',
        teamId: null,
        agentId: 'agent-0',
        summary: 'Created agent: Agent 0',
        details: { agentId: 'agent-0', name: 'Agent 0' },
        createdAt: isoSecond(baseTs, 0),
      };
      const signable = signableRow(partial);
      const canonical = canonicalJson(signable);
      // AUDIT-SDK-01 — single row → prev_row_hash is genesis; sign
      // `canonical || prev_row_hash_bytes` exactly as the backend writer.
      const prevRowHash = GENESIS_PREV_ROW_HASH;
      const rowMessage = Buffer.concat([
        canonical,
        Buffer.from(prevRowHash, 'base64'),
      ]);
      const rowSig = signLowSP256(rowMessage, privateKey);
      const rowSignatureB64 = rowSig.toString('base64');

      const row: FixtureRow & { signatureAlgorithm: string } = {
        id: 'row-0',
        ...partial,
        signature: rowSignatureB64,
        keyVersion,
        signedAt: isoSecond(baseTs, 1),
        prevRowHash,
        signatureAlgorithm: 'ECDSA_P256_SHA256',
      };

      // ── Merkle root over the single leaf ────────────────────────────
      const leaf = new Uint8Array(Buffer.concat([canonical, rowSig]));
      const tree = merkleBuild([leaf]);
      const rootHashB64 = Buffer.from(tree.root).toString('base64');
      const periodStart = isoSecond(baseTs, 0);
      const periodEnd = isoSecond(baseTs, 60 * 60);
      const rootMessage = canonicalJson({
        rootHash: rootHashB64,
        periodStart,
        periodEnd,
        rowCount: 1,
      });
      const rootSigBytes = signLowSP256(rootMessage, privateKey);
      const root: FixtureRoot & { signatureAlgorithm: string } = {
        id: 'root-1',
        organizationId: orgId,
        periodStart,
        periodEnd,
        rowCount: 1,
        rootHash: rootHashB64,
        signature: rootSigBytes.toString('base64'),
        keyVersion,
        signedAt: isoSecond(baseTs, 60 * 60 + 5),
        anchoredAt: null,
        anchorReceipt: null,
        signatureAlgorithm: 'ECDSA_P256_SHA256',
      };

      // ── Single inclusion proof ──────────────────────────────────────
      const proof = merkleProof([leaf], 0);
      const proofs: FixtureProof[] = [
        {
          rowId: row.id,
          index: proof.index,
          proof: proof.siblings.map((s) => Buffer.from(s).toString('base64')),
          rootHash: rootHashB64,
        },
      ];

      // ── Manifest signed under ECDSA-P256 ────────────────────────────
      const generatedAt = isoSecond(baseTs, 60 * 60 + 30);
      const manifestSans = {
        version: 1,
        orgId,
        from: periodStart,
        to: periodEnd,
        rowCount: 1,
        rootCount: 1,
        keyVersions: [{ keyVersion, publicKey: publicKeyDerB64 }],
        generatedAt,
        signatureAlgorithm: 'ECDSA_P256_SHA256' as const,
      };
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSigBytes = signLowSP256(manifestBytes, privateKey);
      const manifest = {
        ...manifestSans,
        signature: manifestSigBytes.toString('base64'),
        signatureKeyVersion: keyVersion,
      };

      const publicKeys: Record<string, string> = {
        [String(keyVersion)]: publicKeyDerB64,
      };
      const rowsNdjson = Buffer.from(JSON.stringify(row) + '\n', 'utf8');
      const rootsNdjson = Buffer.from(JSON.stringify(root) + '\n', 'utf8');
      const proofsNdjson = Buffer.from(
        proofs.map((p) => JSON.stringify(p)).join('\n') + '\n',
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

      return { zip };
    }

    it('round-trips an ECDSA-P256-SHA256 signed bundle', async () => {
      const { zip } = buildEcdsaFixtureBundle();
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(true);
      expect(report.manifest.ok).toBe(true);
      expect(report.rowSignatures.ok).toBe(true);
      expect(report.rowSignatures.checked).toBe(1);
      expect(report.rowSignatures.failed).toBe(0);
      expect(report.rootSignatures.ok).toBe(true);
      expect(report.inclusionProofs.ok).toBe(true);
    });

    it('round-trips an Ed25519-signed bundle (unchanged behavior)', async () => {
      // The existing pristine-fixture happy-path covers this, but we
      // re-assert here so the AUDIT-01 acceptance bullet is explicit.
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(true);
      expect(report.rowSignatures.ok).toBe(true);
      expect(report.rootSignatures.ok).toBe(true);
    });

    it("rejects a bundle whose row signatureAlgorithm is downgraded to a primitive the key can't satisfy", async () => {
      // Build an ECDSA bundle, then re-pack with the row's
      // signatureAlgorithm flipped to 'Ed25519'. The bundle's
      // public-keys.json still carries the ECDSA SPKI, so
      // `crypto.verify(null, msg, ecdsaKey, sig)` fails — the verifier
      // surfaces the row as a signature failure.
      const base = buildEcdsaFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const rowsText = zlib
        .gunzipSync(entries.get('rows.ndjson.gz')!)
        .toString('utf8')
        .trim();
      const tamperedRow = JSON.parse(rowsText);
      tamperedRow.signatureAlgorithm = 'Ed25519';
      const tamperedRowsNdjson = Buffer.from(
        JSON.stringify(tamperedRow) + '\n',
        'utf8',
      );
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        {
          name: 'rows.ndjson.gz',
          data: gzipDeterministic(tamperedRowsNdjson),
        },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        { name: 'public-keys.json', data: entries.get('public-keys.json')! },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.rowSignatures.failed).toBe(1);
      expect(report.rowSignatures.firstFailure).toBe('row-0');
    });

    it('historical bundles without per-row signatureAlgorithm fall back to manifest algorithm', async () => {
      // The pristine Ed25519 fixture (`buildFixtureBundle`) does NOT
      // emit `signatureAlgorithm` on rows — it represents a pre-AUDIT-01
      // bundle that only tagged the manifest. The verifier must still
      // verify, falling back through (row → manifest → 'Ed25519'). The
      // existing happy-path test covers the success direction; this
      // test asserts the fallback is what is actually being exercised
      // by inspecting the row payload before re-verifying.
      const { zip } = buildBundleWithTamper({});
      const entries = readBundleEntries(zip);
      const rowsText = zlib
        .gunzipSync(entries.get('rows.ndjson.gz')!)
        .toString('utf8');
      const firstRow = JSON.parse(
        rowsText.split('\n').filter((l) => l.length > 0)[0]!,
      ) as Record<string, unknown>;
      expect(firstRow.signatureAlgorithm).toBeUndefined();

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(true);
      expect(report.rowSignatures.ok).toBe(true);
    });
  });

  /**
   * AUDIT-2026-05-30 — Platform key-binding attestation.
   *
   * A bundle now ships `platform-attestation.json`: an ECDSA-P256
   * signature minted by a platform-wide key (NOT a tenant key) over
   * `{orgId, [keyVersion, fingerprint, status, revokedAt, issuedAt]}`.
   * The verifier accepts a caller-supplied platform pubkey via
   * `options.platformPublicKeyDerB64` so tests can pin a fresh key
   * without rebuilding the CLI's bundled pin.
   *
   * Cases covered:
   *   - Pristine bundle with a valid platform attestation → ok.
   *   - Tampered attestation signature → fails with `signature:` reason.
   *   - Tampered attestation orgId → fails with `org_mismatch`.
   *   - Mismatched per-key fingerprint → fails.
   *   - Missing attestation entry (pre-AUDIT-30 bundle) → warn but
   *     proceed (`missing_legacy`); overall bundle.ok stays true.
   */
  describe('AUDIT-2026-05-30 — platform attestation', () => {
    /** Helper — sign with ECDSA-P256 and ensure low-s canonical form. */
    function platformSign(
      message: Buffer,
      privateKey: crypto.KeyObject,
    ): Buffer {
      for (let i = 0; i < 64; i++) {
        const candidate = crypto.sign('sha256', message, privateKey);
        if (isLowSP256(candidate)) {
          return candidate;
        }
        const s = extractEcdsaSFromSignature(candidate)!;
        const P256_N = BigInt(
          '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
        );
        return reencodeDerWithS(candidate, P256_N - s);
      }
      throw new Error('unreachable');
    }
    /** Re-encode DER with a new s value (mirrors the AUDIT-01 helper). */
    function reencodeDerWithS(sig: Buffer, newS: bigint): Buffer {
      if (sig[0] !== 0x30) throw new Error('not DER');
      let off = 2;
      const firstLen = sig[1]!;
      if (firstLen & 0x80) off += firstLen & 0x7f;
      if (sig[off] !== 0x02) throw new Error('expected INTEGER r');
      const rLen = sig[off + 1]!;
      const rBytes = sig.subarray(off + 2, off + 2 + rLen);
      let sHex = newS.toString(16);
      if (sHex.length % 2 === 1) sHex = '0' + sHex;
      let sBytes = Buffer.from(sHex, 'hex');
      while (sBytes.length > 1 && sBytes[0] === 0x00) {
        sBytes = sBytes.subarray(1);
      }
      if (sBytes[0]! & 0x80) {
        sBytes = Buffer.concat([Buffer.from([0x00]), sBytes]);
      }
      const rField = Buffer.concat([
        Buffer.from([0x02, rBytes.length]),
        rBytes,
      ]);
      const sField = Buffer.concat([
        Buffer.from([0x02, sBytes.length]),
        sBytes,
      ]);
      const inner = Buffer.concat([rField, sField]);
      return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
    }

    /** Sha256-hex of a base64-encoded public key blob. */
    function fingerprintB64(b64: string): string {
      return crypto
        .createHash('sha256')
        .update(Buffer.from(b64, 'base64'))
        .digest('hex');
    }

    /**
     * Build a complete bundle whose `platform-attestation.json` is
     * minted by a fresh ECDSA-P256 keypair. Returns the bundle bytes
     * + the platform pubkey (base64-DER) so the verifier can pin it.
     */
    function buildBundleWithPlatformAttestation(opts: {
      tamperOrgId?: boolean;
      tamperSignature?: boolean;
      tamperFingerprint?: boolean;
      omitEntry?: boolean;
    }): { zip: Buffer; platformPublicKeyDerB64: string } {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, string>;
      const manifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string };

      // Fresh platform keypair for THIS bundle. Pin it via options.
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });
      const platformPublicKeyDer = publicKey.export({
        format: 'der',
        type: 'spki',
      }) as Buffer;
      const platformPublicKeyDerB64 = platformPublicKeyDer.toString('base64');
      const platformFingerprint = crypto
        .createHash('sha256')
        .update(platformPublicKeyDer)
        .digest('hex');

      const keyVersions = Object.keys(publicKeys)
        .map((v) => ({
          keyVersion: Number(v),
          fingerprint: opts.tamperFingerprint
            ? '0'.repeat(64)
            : fingerprintB64(publicKeys[v]!),
          status: 'ACTIVE',
          revokedAt: null as string | null,
          issuedAt: '2026-05-01T00:00:00.000Z',
        }))
        .sort((a, b) => a.keyVersion - b.keyVersion);

      const attestation = {
        orgId: opts.tamperOrgId
          ? '00000000-0000-0000-0000-0000DEADBEEF'
          : manifest.orgId,
        keyVersions,
        issuedAt: '2026-05-01T01:00:00.000Z',
        platformSigningKeyFingerprint: platformFingerprint,
        signatureAlgorithm: 'ECDSA_P256_SHA256' as const,
      };
      const canonical = canonicalJson(attestation);
      const sigBytes = platformSign(canonical, privateKey);
      let signatureB64 = sigBytes.toString('base64');
      if (opts.tamperSignature) {
        const buf = Buffer.from(signatureB64, 'base64');
        buf[buf.length - 1] = buf[buf.length - 1]! ^ 0xff;
        signatureB64 = buf.toString('base64');
      }
      const envelope = { attestation, signature: signatureB64 };

      const zipEntries = [
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: entries.get('public-keys.json')!,
        },
      ];
      if (!opts.omitEntry) {
        zipEntries.push({
          name: 'platform-attestation.json',
          data: Buffer.from(JSON.stringify(envelope, null, 2), 'utf8'),
        });
      }
      zipEntries.push({
        name: 'README.md',
        data: entries.get('README.md')!,
      });

      return {
        zip: writeZip(zipEntries),
        platformPublicKeyDerB64,
      };
    }

    it('verifies a pristine platform-attested bundle', async () => {
      const { zip, platformPublicKeyDerB64 } =
        buildBundleWithPlatformAttestation({});
      const report = await verifyBundle(zip, {
        noRekor: true,
        platformPublicKeyDerB64,
      });
      expect(report.ok).toBe(true);
      expect(report.platformAttestation.ok).toBe(true);
      expect(report.platformAttestation.checked).toBe(1);
      expect(report.platformAttestation.failed).toBe(0);
    });

    it('rejects a tampered attestation signature', async () => {
      const { zip, platformPublicKeyDerB64 } =
        buildBundleWithPlatformAttestation({ tamperSignature: true });
      const report = await verifyBundle(zip, {
        noRekor: true,
        platformPublicKeyDerB64,
      });
      expect(report.ok).toBe(false);
      expect(report.platformAttestation.ok).toBe(false);
      expect(report.platformAttestation.failed).toBe(1);
      expect(report.platformAttestation.reason).toMatch(/signature/);
    });

    it('rejects an attestation whose orgId does not match the manifest', async () => {
      const { zip, platformPublicKeyDerB64 } =
        buildBundleWithPlatformAttestation({ tamperOrgId: true });
      const report = await verifyBundle(zip, {
        noRekor: true,
        platformPublicKeyDerB64,
      });
      expect(report.ok).toBe(false);
      expect(report.platformAttestation.ok).toBe(false);
      expect(report.platformAttestation.reason).toMatch(/org_mismatch/);
    });

    it('rejects an attestation whose per-key fingerprint disagrees with public-keys.json', async () => {
      const { zip, platformPublicKeyDerB64 } =
        buildBundleWithPlatformAttestation({ tamperFingerprint: true });
      const report = await verifyBundle(zip, {
        noRekor: true,
        platformPublicKeyDerB64,
      });
      expect(report.ok).toBe(false);
      expect(report.platformAttestation.ok).toBe(false);
      // Signature is still valid (we re-sign the tampered body); the
      // failure surface is the keyversion fingerprint mismatch.
      expect(report.platformAttestation.reason).toMatch(
        /keyversion_fingerprint_mismatch/,
      );
    });

    it('treats a missing platform-attestation.json as legacy → warn but proceed', async () => {
      const { zip, platformPublicKeyDerB64 } =
        buildBundleWithPlatformAttestation({ omitEntry: true });
      const report = await verifyBundle(zip, {
        noRekor: true,
        platformPublicKeyDerB64,
      });
      // Overall bundle still verifies (legacy bundles predate AUDIT-30).
      expect(report.ok).toBe(true);
      expect(report.platformAttestation.ok).toBe(true);
      expect(report.platformAttestation.checked).toBe(0);
      expect(report.platformAttestation.reason).toBe('missing_legacy');
    });

    it('treats an unpinned platform pubkey (placeholder mode) as warn-but-proceed', async () => {
      // No `platformPublicKeyDerB64` override AND the bundled pin is
      // still the empty placeholder — the verifier reports
      // `placeholder_platform_key` and does NOT fail the bundle.
      // We use the pristine fixture (no attestation entry) so the
      // verifier short-circuits in placeholder mode before parsing
      // anything.
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(true);
      expect(report.platformAttestation.ok).toBe(true);
      expect(report.platformAttestation.reason).toBe(
        'placeholder_platform_key',
      );
    });
  });
});
