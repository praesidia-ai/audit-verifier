import { httpRequestCommitment, httpTargetKeyFingerprint } from '../http-receipt.js';
import { jcsCanonicalize, jcsCommitment } from '../jcs-canonical.js';
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

import { describe, expect, it, vi } from 'vitest';
import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  verifyBundle as verifyBundleStrict,
  retentionSealLinkMessage,
  type VerifyOptions,
  type VerifyReport,
} from '../verify.js';
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
import * as cryptoPrimitives from '../crypto.js';
import {
  MAX_ZIP_ARCHIVE_BYTES,
  writeZip,
  gzipDeterministic,
  readZip,
} from '../zip.js';
import { verifyRekorReceipt } from '../rekor.js';
import { formatEvidencePrivacyLines } from '../evidence-privacy.js';
import { aibomTrustFromBundle, verifyAibomAttestation } from '../aibom.js';

// Most fixtures intentionally model pre-attestation legacy bundles. Their
// crypto assertions opt in explicitly; dedicated trust-boundary tests below
// exercise the production default, which fails closed.
function verifyBundle(
  bundle: Buffer,
  options: VerifyOptions = {},
): Promise<VerifyReport> {
  return verifyBundleStrict(bundle, {
    allowLegacyUnattested: true,
    ...options,
  });
}

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

/**
 * Build a fully-signed, fully-verifiable compliance bundle in memory.
 *
 * @param opts.firstRowPrevRowHash — BUGHUNT-SDK-02: override row-0's
 *   `prevRowHash` (default genesis) to model a MID-CHAIN ranged export whose
 *   first row links to an out-of-bundle predecessor. Row-0's signature is
 *   minted over `canonical || thisPrevRowHash`, exactly as the backend writer
 *   does, so the bundle stays internally valid under the anchor semantics.
 */
function buildFixtureBundle(opts?: {
  firstRowPrevRowHash?: string;
}): FixtureBundle {
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
      prevRowHash = opts?.firstRowPrevRowHash ?? GENESIS_PREV_ROW_HASH;
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
  firstRowPrevRowHash?: string;
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
  const base = buildFixtureBundle(
    opts.firstRowPrevRowHash !== undefined
      ? { firstRowPrevRowHash: opts.firstRowPrevRowHash }
      : undefined,
  );

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

/** Repack a fixture while replacing exactly one named entry. */
function replaceBundleEntry(zip: Buffer, name: string, data: Buffer): Buffer {
  return writeZip(
    readZip(zip).map((entry) => ({
      name: entry.name,
      data: entry.name === name ? data : entry.data,
    })),
  );
}

function rebuildWithProofs(proofs: FixtureProof[]): Buffer {
  const base = buildFixtureBundle();
  const entries = readBundleEntries(base.zip);
  const ndjson = Buffer.from(
    proofs.map((proof) => JSON.stringify(proof)).join('\n') +
      (proofs.length > 0 ? '\n' : ''),
    'utf8',
  );
  return writeZip([
    { name: 'manifest.json', data: entries.get('manifest.json')! },
    { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
    { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
    { name: 'proofs.ndjson.gz', data: gzipDeterministic(ndjson) },
    { name: 'public-keys.json', data: entries.get('public-keys.json')! },
    { name: 'README.md', data: entries.get('README.md')! },
  ]);
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

  /**
   * PA-0009 (`PA01-DECISIONS.md` D15) — `status` is now the authoritative
   * per-component and top-level verdict; `ok` is derived from it
   * (`status === 'valid'`). Every one of today's 11 components can only
   * ever produce `valid`/`invalid` — `incomplete`/`unsupported` are
   * reserved for the action-proof components landing in PA-0010 — so this
   * asserts the derivation is exact, not that new states appear yet.
   */
  it('reports status: valid on every component of a pristine bundle, and top-level status valid', async () => {
    const { zip } = buildBundleWithTamper({});
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.status).toBe('valid');
    expect(report.ok).toBe(true);
    for (const component of [
      report.manifest,
      report.rowSignatures,
      report.chain,
      report.rootSignatures,
      report.inclusionProofs,
      report.completeness,
      report.keyBinding,
      report.rootCoverage,
    ]) {
      expect(component.status).toBe('valid');
      expect(component.ok).toBe(true);
    }
    // AV-0008 — 0-checked components are not_present, never valid: a v1
    // bundle carries no integrity checkpoints, and the fixture root has no
    // anchor receipt (skipped under --no-rekor).
    expect(report.integrityCheckpoints.status).toBe('not_present');
    expect(report.rekor.status).toBe('not_present');
  });

  it('reports status: invalid at both component and top level when a component fails, never incomplete/unsupported', async () => {
    const { zip } = buildBundleWithTamper({
      postSignRowByte: (rows) => {
        rows[2]!.action = 'agent.deleted';
      },
    });
    const report = await verifyBundle(zip, { noRekor: true });
    expect(report.status).toBe('invalid');
    expect(report.ok).toBe(false);
    expect(report.rowSignatures.status).toBe('invalid');
    expect(report.rowSignatures.ok).toBe(false);
    // The reduction is real, not "any failed" — an untouched component
    // stays `valid`, it is not dragged to `invalid` by a sibling failure.
    // (`chain` is deliberately NOT asserted here: a tampered row payload
    // also breaks the next row's prev-row-hash link, so `chain` legitimately
    // fails too — `manifest`, whose signature covers none of the row
    // content, is the clean independent witness.)
    expect(report.manifest.status).toBe('valid');
  });

  describe('bundle resource boundaries', () => {
    it('rejects an archive larger than the configured raw-byte ceiling', async () => {
      const { zip } = buildFixtureBundle();
      await expect(
        verifyBundle(zip, {
          noRekor: true,
          resourceLimits: { maxBundleBytes: zip.length - 1 },
        }),
      ).rejects.toThrow(/zip archive size .* exceeds limit/);
    });

    it('rejects unknown archive members before processing their payload', async () => {
      const { zip } = buildFixtureBundle();
      const withUnexpectedMember = writeZip([
        ...readZip(zip),
        { name: '../ignored.bin', data: Buffer.from('ignored') },
      ]);
      await expect(
        verifyBundle(withUnexpectedMember, { noRekor: true }),
      ).rejects.toThrow(/unexpected zip entry name/);
    });

    it('rejects an oversized static member before JSON parsing', async () => {
      const { zip } = buildFixtureBundle();
      const oversizedManifest = replaceBundleEntry(
        zip,
        'manifest.json',
        Buffer.alloc(4 * 1024 * 1024 + 1, 0x20),
      );
      await expect(
        verifyBundle(oversizedManifest, { noRekor: true }),
      ).rejects.toThrow(/manifest\.json uncompressed size .* exceeds limit/);
    });

    it('rejects signed manifest counts above the configured record ceiling', async () => {
      const { zip } = buildFixtureBundle();
      await expect(
        verifyBundle(zip, {
          noRekor: true,
          resourceLimits: { maxRows: 3 },
        }),
      ).rejects.toThrow(
        /manifest rowCount 4 exceeds verifier resource limit 3/,
      );
    });

    it('rejects an NDJSON member with too many records', async () => {
      const { zip } = buildFixtureBundle();
      await expect(
        verifyBundle(zip, {
          noRekor: true,
          resourceLimits: { maxProofs: 3 },
        }),
      ).rejects.toThrow(/proofs\.ndjson\.gz record count exceeds.*3/);
    });

    it('rejects aggregate anchor-receipt fanout above its configured ceiling', async () => {
      const base = buildFixtureBundle();
      const root = {
        ...base.roots[0]!,
        anchorReceipts: [
          {
            provider: 's3',
            receipt: 's3:bucket:key:version-1',
            anchoredAt: '2026-05-01T01:00:00.000Z',
          },
          {
            provider: 's3',
            receipt: 's3:bucket:key:version-2',
            anchoredAt: '2026-05-01T01:00:01.000Z',
          },
        ],
      };
      const zip = replaceBundleEntry(
        base.zip,
        'roots.ndjson.gz',
        gzipDeterministic(Buffer.from(`${JSON.stringify(root)}\n`, 'utf8')),
      );
      // Keep this assertion before provider verification: no external hook
      // should be invoked for a bundle that exceeds the aggregate ceiling.
      await expect(
        verifyBundle(zip, {
          noRekor: true,
          resourceLimits: { maxAnchorReceipts: 1 },
        }),
      ).rejects.toThrow(/anchor receipt count exceeds.*1/);
    });

    it('rejects an oversized NDJSON line without splitting the whole stream', async () => {
      const { zip } = buildFixtureBundle();
      await expect(
        verifyBundle(zip, {
          noRekor: true,
          resourceLimits: { maxNdjsonLineBytes: 64 },
        }),
      ).rejects.toThrow(/rows\.ndjson\.gz line 1 exceeds.*64 bytes/);
    });

    it('rejects blank NDJSON lines instead of letting them bypass record caps', async () => {
      const { zip } = buildFixtureBundle();
      const blankRows = replaceBundleEntry(
        zip,
        'rows.ndjson.gz',
        gzipDeterministic(Buffer.from('\n\n', 'utf8')),
      );
      await expect(verifyBundle(blankRows, { noRekor: true })).rejects.toThrow(
        /rows\.ndjson\.gz line 1 is empty/,
      );
    });

    it('stops a high-ratio nested gzip at the per-entry decoded-byte ceiling', async () => {
      const { zip } = buildFixtureBundle();
      const compressedBomb = replaceBundleEntry(
        zip,
        'rows.ndjson.gz',
        gzipDeterministic(Buffer.alloc(256 * 1024, 0x20)),
      );
      await expect(
        verifyBundle(compressedBomb, {
          noRekor: true,
          resourceLimits: { maxGzipOutputBytes: 32 * 1024 },
        }),
      ).rejects.toThrow(
        /rows\.ndjson\.gz expanded output exceeds per-entry limit 32768/,
      );
    });

    it('shares one decoded-byte budget across every nested gzip member', async () => {
      const { zip } = buildFixtureBundle();
      const totalDecodedBytes = readZip(zip)
        .filter((entry) => entry.name.endsWith('.ndjson.gz'))
        .reduce(
          (total, entry) => total + zlib.gunzipSync(entry.data).length,
          0,
        );
      expect(totalDecodedBytes).toBeGreaterThan(1);

      await expect(
        verifyBundle(zip, {
          noRekor: true,
          resourceLimits: {
            maxTotalGzipOutputBytes: totalDecodedBytes - 1,
          },
        }),
      ).rejects.toThrow(/bundle gzip output exceeds total resource limit/);
    });

    it('rejects signed scopes that cannot fit the shared NDJSON record budget', async () => {
      const { zip } = buildFixtureBundle();
      await expect(
        verifyBundle(zip, {
          noRekor: true,
          // Four rows imply four proof records, plus the declared root.
          resourceLimits: { maxTotalNdjsonRecords: 5 },
        }),
      ).rejects.toThrow(
        /manifest requires at least 9 NDJSON records, exceeding verifier total resource limit 5/,
      );
    });

    it('charges optional NDJSON members to the same aggregate record budget', async () => {
      const { zip } = buildFixtureBundle();
      const withOptionalSeal = writeZip([
        ...readZip(zip),
        {
          name: 'sealed-purges.ndjson.gz',
          data: gzipDeterministic(Buffer.from('{}\n')),
        },
      ]);
      await expect(
        verifyBundle(withOptionalSeal, {
          noRekor: true,
          // Exactly enough for 4 rows + 1 root + 4 proofs; the optional
          // seal must not receive a fresh independent allowance.
          resourceLimits: { maxTotalNdjsonRecords: 9 },
        }),
      ).rejects.toThrow(
        /bundle NDJSON record count exceeds total resource limit while reading sealed-purges\.ndjson\.gz/,
      );
    });
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

  it('rejects a vacuous empty proofs file', async () => {
    const report = await verifyBundle(rebuildWithProofs([]), {
      noRekor: true,
    });
    expect(report.ok).toBe(false);
    expect(report.inclusionProofs.failed).toBe(4);
    expect(report.inclusionProofs.reason).toContain('no entry');
  });

  it('rejects a diagnostic status marker in place of a proof', async () => {
    const base = buildFixtureBundle();
    const proofs = base.proofs.map((proof) => ({ ...proof }));
    proofs[0] = { rowId: 'row-0', status: 'not_yet_rooted' };
    const report = await verifyBundle(rebuildWithProofs(proofs), {
      noRekor: true,
    });
    expect(report.ok).toBe(false);
    expect(report.inclusionProofs.reason).toContain('not_yet_rooted');
  });

  it('rejects duplicate proof entries for a row', async () => {
    const base = buildFixtureBundle();
    const report = await verifyBundle(
      rebuildWithProofs([...base.proofs, { ...base.proofs[0]! }]),
      { noRekor: true },
    );
    expect(report.ok).toBe(false);
    expect(report.inclusionProofs.reason).toContain('duplicate proof');
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
   * BUGHUNT-SDK-02 — Partial-range (non-genesis) bundles verify.
   *
   * Bundles are date-ranged and hard-capped at 90 days, so a bundle for
   * any org older than 90 days CANNOT begin at the genesis row: its first
   * row's `prevRowHash` links to a predecessor whose `signedAt < from` and
   * is therefore not in the bundle. The verifier now treats the first
   * row's `prevRowHash` as an opaque anchor and only enforces internal
   * linkage for rows [1..]. Leading truncation is still caught by
   * `completeness`; middle-row tamper still breaks an internal link.
   */
  describe('BUGHUNT-SDK-02 — partial-range chain anchor', () => {
    it('verifies a mid-chain ranged bundle whose first row prevRowHash is NOT genesis', async () => {
      // Anchor into the org's pre-range history (an out-of-bundle
      // predecessor). Row-0's signature binds this value (canonical ||
      // prevRowHash), exactly as the backend writer produces it.
      const anchor = sha256(
        Buffer.from('out-of-range predecessor row'),
      ).toString('base64');
      expect(anchor).not.toBe(GENESIS_PREV_ROW_HASH);

      const { zip } = buildFixtureBundle({ firstRowPrevRowHash: anchor });
      const report = await verifyBundle(zip, { noRekor: true });

      // The whole bundle verifies — the non-genesis first row is accepted
      // as an anchor and rows [1..] still chain internally.
      expect(report.ok).toBe(true);
      expect(report.chain.ok).toBe(true);
      expect(report.chain.failed).toBe(0);
      // 4 rows → 3 inter-row link assertions (the anchor is not asserted).
      expect(report.chain.checked).toBe(3);
      expect(report.rowSignatures.ok).toBe(true);
    });

    it('still catches a MIDDLE-row chain break in a ranged bundle', async () => {
      const anchor = sha256(Buffer.from('anchor')).toString('base64');
      const { zip } = buildBundleWithTamper({
        firstRowPrevRowHash: anchor,
        postSignPrevRowHash: (rows) => {
          // Break row-2's link to row-1 (a NON-leading row).
          rows[2]!.prevRowHash = GENESIS_PREV_ROW_HASH;
        },
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.chain.ok).toBe(false);
      expect(report.chain.firstFailure).toBe('row-2');
    });

    it('leading-truncated ranged bundle STILL FAILS via completeness (dropped first row)', async () => {
      // Genesis-rooted fixture, rowCount=4 in the signed manifest. Drop the
      // FIRST row + its proof. The surviving rows [1..3] still internally
      // chain (row-1 becomes the first row → its prevRowHash accepted as an
      // anchor), so `chain` is happy — but `completeness` catches 3 != 4.
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const keptRows = base.rows.slice(1);
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
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: gzipDeterministic(rowsNdjson) },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: gzipDeterministic(proofsNdjson) },
        { name: 'public-keys.json', data: entries.get('public-keys.json')! },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);

      const report = await verifyBundle(zip, { noRekor: true });
      // Internal linkage of the surviving prefix is intact + first row
      // anchored…
      expect(report.chain.ok).toBe(true);
      // …but the signed count no longer matches → completeness fails.
      expect(report.completeness.ok).toBe(false);
      expect(report.completeness.reason).toMatch(/row count mismatch/);
      expect(report.bundle.rowsSeen).toBe(3);
      expect(report.bundle.declaredRowCount).toBe(4);
      expect(report.ok).toBe(false);
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
    it('rejects non-canonical public-key version names before verification', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const key = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const zip = replaceBundleEntry(
        base.zip,
        'public-keys.json',
        Buffer.from(JSON.stringify({ '01': key['1'] }), 'utf8'),
      );

      await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
        /non-canonical positive key version: 01/,
      );
    });

    it('rejects identical key material reused under multiple versions', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const keys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const zip = replaceBundleEntry(
        base.zip,
        'public-keys.json',
        Buffer.from(JSON.stringify({ '1': keys['1'], '2': keys['1'] }), 'utf8'),
      );

      await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
        /reuses identical key material for key versions 1 and 2/,
      );
    });

    it('fails when a signed manifest key is suppressed from public-keys.json', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const manifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as {
        keyVersions: Array<{ keyVersion: number; publicKey: string }>;
        signature: string;
        signatureKeyVersion: number;
        [key: string]: unknown;
      };
      const extraKey = keypairFromSeed(Buffer.alloc(32, 8));
      manifest.keyVersions.push({
        keyVersion: 2,
        publicKey: Buffer.from(extraKey.publicKey).toString('base64'),
      });
      const {
        signature: _oldSignature,
        signatureKeyVersion: _signatureKeyVersion,
        ...signable
      } = manifest;
      manifest.signature = signEd25519(
        canonicalJson(signable),
        Buffer.alloc(32, 7),
      );
      const zip = replaceBundleEntry(
        base.zip,
        'manifest.json',
        Buffer.from(JSON.stringify(manifest), 'utf8'),
      );

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(true);
      expect(report.keyBinding.ok).toBe(false);
      expect(report.keyBinding.reason).toContain(
        'signed_key_missing_from_public_keys',
      );
    });

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
   * PROD15 — `manifest.keyVersions[].status`/`revokedAt` is part of the
   * SIGNED manifest (see the `ManifestKeyVersionEntry` docblock) but was
   * never cross-checked against `public-keys.json`. An attacker who edits
   * only the UNSIGNED `public-keys.json` — downgrading a REVOKED key back
   * to ACTIVE, leaving `manifest.json` and every row/root signature
   * untouched — must not be able to resurrect a revoked key's signatures
   * just because platform attestation (which independently catches this)
   * is skipped via `allowLegacyUnattested`.
   */
  describe('PROD15 — signed keyVersions lifecycle bound to public-keys.json', () => {
    it('fails when public-keys.json downgrades a signed-REVOKED keyVersion to ACTIVE', async () => {
      const seed = Buffer.alloc(32, 7); // identical seed to buildFixtureBundle()
      const { privateKey, publicKey } = keypairFromSeed(seed);
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const publicKeyB64 = Buffer.from(publicKey).toString('base64');

      // Re-sign the manifest so it legitimately declares keyVersion 1 as
      // REVOKED — this is the SIGNED source of truth.
      const manifestSans = {
        version: originalManifest.version,
        orgId: originalManifest.orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        keyVersions: [
          {
            keyVersion: 1,
            publicKey: publicKeyB64,
            status: 'REVOKED',
            revokedAt: '2026-05-01T00:10:00.000Z',
          },
        ],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: originalManifest.signatureAlgorithm,
      };
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(manifestBytes, privateKey);
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };

      // The UNSIGNED public-keys.json is the only thing tampered: same key
      // bytes, but status downgraded to ACTIVE and revokedAt cleared.
      const publicKeys = {
        '1': { publicKey: publicKeyB64, status: 'ACTIVE', revokedAt: null },
      };

      const zip = writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);

      const report = await verifyBundle(zip, {
        noRekor: true,
        allowLegacyUnattested: true,
      });
      expect(report.keyBinding.ok).toBe(false);
      expect(report.keyBinding.reason).toMatch(/key_status_mismatch/);
      expect(report.ok).toBe(false);
    });
  });

  /**
   * RA-05 (PROD15 adversarial re-attack) — residual HIGH found in
   * `verifyManifest` and `verifyKeyBinding` after the PROD15 lifecycle-
   * binding fix above.
   *
   * Gap 1: `verifyManifest` never checked the signing key's revocation
   * status at all, unlike its `verifyRowSignatures` / `verifyRootSignatures`
   * siblings. A holder of a compromised (honestly-revoked) key could sign a
   * brand-new manifest — asserting any `orgId`/`from`/`to`/`rowCount`/
   * `rootCount`/`keyVersions` they like — while leaving `public-keys.json`
   * completely honest, and it would verify.
   *
   * Gap 2: the PROD15 lifecycle cross-check itself only ran
   * `if (signedEntry.status !== undefined)`. A v2 manifest can legally omit
   * `status` on one entry (the parser does not require it), which silently
   * fell back to trusting the UNSIGNED `public-keys.json` alone for that
   * entry — exactly the case PROD15 exists to close.
   */
  describe('RA-05 — verifyManifest must fail closed on a REVOKED signing key', () => {
    function buildGap1ForgedBundle(): Buffer {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const activeKeyB64 = Buffer.from(base.manifestPublicKey).toString(
        'base64',
      );
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;

      // A SEPARATE key the attacker holds, honestly REVOKED in both files.
      const revokedKeypair = keypairFromSeed(Buffer.alloc(32, 42));
      const revokedKeyB64 = Buffer.from(revokedKeypair.publicKey).toString(
        'base64',
      );

      // Relabel the fixture's rows/roots onto keyVersion 2 (the ACTIVE key)
      // — buildFixtureBundle hardcodes keyVersion 1, so free it up for the
      // attacker's revoked key.
      const rows = zlib
        .gunzipSync(entries.get('rows.ndjson.gz')!)
        .toString('utf8')
        .split('\n')
        .filter((l) => l.length > 0)
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      rows.forEach((r) => {
        r.keyVersion = 2;
      });
      const roots = zlib
        .gunzipSync(entries.get('roots.ndjson.gz')!)
        .toString('utf8')
        .split('\n')
        .filter((l) => l.length > 0)
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      roots.forEach((r) => {
        r.keyVersion = 2;
      });

      // Forge a fresh manifest signed under the REVOKED key (v1), while
      // BOTH the signed manifest AND public-keys.json honestly agree v1 is
      // REVOKED and v2 is ACTIVE — so `verifyKeyBinding`'s cross-check has
      // nothing to catch. Only a direct revocation check on the manifest's
      // OWN signing key can reject this.
      const manifestSans = {
        version: 2,
        orgId: originalManifest.orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        keyVersions: [
          {
            keyVersion: 1,
            publicKey: revokedKeyB64,
            status: 'REVOKED',
            revokedAt: '2026-01-01T00:00:00.000Z',
          },
          {
            keyVersion: 2,
            publicKey: activeKeyB64,
            status: 'ACTIVE',
            revokedAt: null,
          },
        ],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: 'Ed25519' as const,
      };
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(
        manifestBytes,
        revokedKeypair.privateKey,
      );
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };

      const publicKeys = {
        '1': {
          publicKey: revokedKeyB64,
          status: 'REVOKED',
          revokedAt: '2026-01-01T00:00:00.000Z',
        },
        '2': { publicKey: activeKeyB64, status: 'ACTIVE', revokedAt: null },
      };

      const rowsNdjson = Buffer.from(
        rows.map((r) => JSON.stringify(r)).join('\n') + '\n',
        'utf8',
      );
      const rootsNdjson = Buffer.from(
        roots.map((r) => JSON.stringify(r)).join('\n') + '\n',
        'utf8',
      );

      return writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: gzipDeterministic(rowsNdjson) },
        { name: 'roots.ndjson.gz', data: gzipDeterministic(rootsNdjson) },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
    }

    it('closes RA-05 Gap 1: rejects a manifest signed by a REVOKED key even though rows/roots + keyBinding are all otherwise honest', async () => {
      const zip = buildGap1ForgedBundle();
      const report = await verifyBundle(zip, {
        noRekor: true,
        allowLegacyUnattested: true,
      });

      // Everything else about this forged bundle is genuinely consistent —
      // proving the ONLY thing that can catch it is a direct revocation
      // check on the manifest's own signing key.
      expect(report.keyBinding.ok).toBe(true);
      expect(report.rowSignatures.ok).toBe(true);
      expect(report.rootSignatures.ok).toBe(true);
      // The manifest itself was signed under a REVOKED key → must fail.
      expect(report.manifest.ok).toBe(false);
      expect(report.manifest.reason).toBe('key_revoked');
      expect(report.ok).toBe(false);
    });

    it('closes RA-05 Gap 2: a v2 manifest cannot skip the lifecycle cross-check by omitting `status` on an entry', async () => {
      const seed = Buffer.alloc(32, 7); // identical seed to buildFixtureBundle()
      const { privateKey, publicKey } = keypairFromSeed(seed);
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const publicKeyB64 = Buffer.from(publicKey).toString('base64');

      // A v2 manifest whose sole keyVersions entry OMITS `status` entirely.
      // Structurally legal (`assertManifestStructure` does not require the
      // field) but never genuinely produced — a real v2 exporter always
      // stamps `status` on every entry in the same change that bumped the
      // version to 2.
      const manifestSans = {
        version: 2,
        orgId: originalManifest.orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        keyVersions: [{ keyVersion: 1, publicKey: publicKeyB64 }],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: originalManifest.signatureAlgorithm,
      };
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(manifestBytes, privateKey);
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };

      // public-keys.json says ACTIVE — before this fix, an omitted signed
      // `status` trusted this file alone, so ANY value here would pass.
      const publicKeys = {
        '1': { publicKey: publicKeyB64, status: 'ACTIVE', revokedAt: null },
      };

      const zip = writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);

      const report = await verifyBundle(zip, {
        noRekor: true,
        allowLegacyUnattested: true,
      });
      expect(report.keyBinding.ok).toBe(false);
      expect(report.keyBinding.reason).toMatch(/key_status_mismatch/);
      expect(report.ok).toBe(false);
    });

    it('preserves the v1 fallback for a TRUE legacy manifest (version: 1, no status anywhere)', async () => {
      // Sanity/regression guard: `buildFixtureBundle()` produces a genuine
      // v1 manifest (no status field on its sole keyVersions entry) with a
      // bare-string `public-keys.json`. Neither Gap-1 nor Gap-2 hardening
      // should touch this — it must keep verifying exactly as before.
      const { zip } = buildFixtureBundle();
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(true);
      expect(report.keyBinding.ok).toBe(true);
      expect(report.ok).toBe(true);
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
        // BUGHUNT-SDK-05 — the rekor receipt here is a stub; this test
        // exercises multi-anchor DISPATCH + counting, not Rekor crypto
        // (covered by the dedicated suite below), so pass an explicit
        // rekorFetcher seam rather than a full signed Rekor entry.
        anchorReceiptVerifier: async () => ({ ok: true }),
      });
      expect(report.ok).toBe(true);
      expect(report.rekor.ok).toBe(true);
      // Two entries on one root → checked = 2.
      expect(report.rekor.checked).toBe(2);
      expect(report.rekor.failed).toBe(0);
    });

    it('AV-0019 — verifies an rfc3161 token on the root offline, fails closed without a TSA anchor', async () => {
      const fx = path.resolve(process.cwd(), 'test-fixtures/rfc3161');
      const token = fs.readFileSync(path.join(fx, 'token-bundle-root.b64'), 'utf8').trim();
      const tsaRoot = fs.readFileSync(path.join(fx, 'root-ca.pem'), 'utf8');
      const { verifyRfc3161Receipt } = await import('../rfc3161.js');
      const probe = verifyRfc3161Receipt(token, { rootHashB64: buildFixtureBundle().roots[0]!.rootHash }, [tsaRoot]);
      if (probe.status !== 'verified') throw new Error(`fixture token must verify: ${JSON.stringify(probe)}`);
      const zip = rebuildWithReceipts([{ provider: 'rfc3161', receipt: token, anchoredAt: probe.genTime }]);

      const good = await verifyBundle(zip, { tsaTrustAnchorsPem: [tsaRoot] });
      expect(good.ok).toBe(true);
      expect(good.rekor).toMatchObject({ ok: true, checked: 1, failed: 0 });
      expect(good.rfc3161).toEqual([{ rootId: buildFixtureBundle().roots[0]!.id, ...probe }]);

      const noAnchor = await verifyBundle(zip);
      expect(noAnchor.ok).toBe(false);
      expect(noAnchor.rekor.reason).toMatch(/^rfc3161: no_tsa_trust_anchor/);
      expect(noAnchor.rfc3161[0]!.status).toBe('failed');

      const wrong = await verifyBundle(zip, { tsaTrustAnchorsPem: [fs.readFileSync(path.join(fx, 'other-ca.pem'), 'utf8')] });
      expect(wrong.ok).toBe(false);
      expect(wrong.rekor.reason).toMatch(/^rfc3161: tsa_chain_untrusted/);

      const s3Only = await verifyBundle(
        rebuildWithReceipts([{ provider: 's3', receipt: 's3:b:k:v', anchoredAt: '2026-05-01T01:00:05.000Z' }]),
        { anchorReceiptVerifier: async () => ({ ok: true }) },
      );
      expect(s3Only.rfc3161).toEqual([{ rootId: buildFixtureBundle().roots[0]!.id, status: 'absent' }]);
    });

    it('synthesizes a rekor entry from the legacy anchorReceipt scalar when anchorReceipts is empty', async () => {
      // Empty multi-anchor array but legacy slot populated. The
      // verifier must still verify the legacy receipt (the migration
      // backfill writes this synthesis into the array, but bundles
      // captured from older snapshots may not have run the backfill).
      const zip = rebuildWithReceipts([], '{"logIndex":9001}');

      // BUGHUNT-SDK-05 — dispatch/counting test; stub the rekor crypto.
      const report = await verifyBundle(zip, {
        rekorFetcher: async (_receipt, expectedRoot) => {
          expect(expectedRoot.rootHash).toBe(
            buildFixtureBundle().roots[0]!.rootHash,
          );
          return true;
        },
      });
      expect(report.ok).toBe(true);
      expect(report.rekor.ok).toBe(true);
      expect(report.rekor.checked).toBe(1);
      expect(report.rekor.failed).toBe(0);
    });

    it('fails closed when a root has no anchor receipt', async () => {
      const zip = rebuildWithReceipts([], null);
      const report = await verifyBundle(zip);
      expect(report.ok).toBe(false);
      expect(report.rekor.checked).toBe(1);
      expect(report.rekor.failed).toBe(1);
      // PROD16 F8 — every root in this (single-root) bundle is
      // unanchored, so this is the "no external witness configured at
      // all" case, distinct from a partial-coverage gap.
      expect(report.rekor.reason).toContain('no_external_witness');
    });

    it('PROD16 F8 — distinguishes a partial-coverage gap from "no witness ever configured"', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const anchoredRoot: FixtureRoot = {
        ...base.roots[0]!,
        anchorReceipts: [
          {
            provider: 'rekor',
            receipt: '{"logIndex":1}',
            anchoredAt: '2026-05-01T01:00:00.000Z',
          },
        ],
      };
      const unanchoredRoot: FixtureRoot = {
        ...base.roots[0]!,
        id: 'root-2',
        rootHash: Buffer.alloc(32, 5).toString('base64'),
        anchorReceipts: [],
        anchorReceipt: null,
      };
      const rootsNdjson = Buffer.from(
        [anchoredRoot, unanchoredRoot]
          .map((r) => JSON.stringify(r))
          .join('\n') + '\n',
        'utf8',
      );
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: gzipDeterministic(rootsNdjson) },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: entries.get('public-keys.json')!,
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
      // Only `report.rekor.*` is asserted here — the fabricated second
      // root is not signed/proved and other components are expected to
      // disagree; this test isolates the rekor-message distinction only.
      const report = await verifyBundle(zip, {
        anchorReceiptVerifier: async () => ({ ok: true }),
      });
      expect(report.rekor.failed).toBe(1);
      expect(report.rekor.reason).toContain(
        'anchor_missing_for_partially_anchored_bundle',
      );
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

      // BUGHUNT-SDK-05 — stub the rekor crypto so the ONLY failure is the
      // unknown provider (this test is about provider dispatch, not SET).
      const report = await verifyBundle(zip, {
        rekorFetcher: async () => true,
      });
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

    it('rejects oversized receipt metadata at the streaming line boundary before verification', async () => {
      const zip = rebuildWithReceipts([
        {
          provider: 'rekor',
          receipt: 'x'.repeat(1024 * 1024 + 1),
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
      ]);
      await expect(verifyBundle(zip)).rejects.toThrow(
        /roots\.ndjson\.gz line 1 exceeds verifier resource limit/,
      );
      expect(verifyRekorReceipt('x'.repeat(1024 * 1024 + 1))).toEqual({
        ok: false,
        reason: 'receipt_too_large',
      });
    });

    it('fails closed for a well-formed s3 receipt without an online verifier', async () => {
      const zip = rebuildWithReceipts([
        {
          provider: 's3',
          receipt: 's3:my-bucket:audit-roots/period.json:v123',
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
      ]);
      const report = await verifyBundle(zip);
      expect(report.ok).toBe(false);
      expect(report.rekor.reason).toContain('unverifiable_offline');
    });

    it('--no-rekor does not bypass a present S3 receipt', async () => {
      const zip = rebuildWithReceipts([
        {
          provider: 's3',
          receipt: 's3:my-bucket:audit-roots/period.json:v123',
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
      ]);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.rekor.checked).toBe(1);
      expect(report.rekor.failed).toBe(1);
      expect(report.rekor.reason).toContain('s3');
      expect(report.rekor.reason).toContain('unverifiable_offline');
    });

    it('--no-rekor skips only Rekor while still verifying another provider', async () => {
      const zip = rebuildWithReceipts([
        {
          provider: 'rekor',
          receipt: '{"logIndex":9001}',
          anchoredAt: '2026-05-01T01:00:00.000Z',
        },
        {
          provider: 's3',
          receipt: 's3:my-bucket:audit-roots/period.json:v123',
          anchoredAt: '2026-05-01T01:00:05.000Z',
        },
      ]);
      const calls: string[] = [];

      const report = await verifyBundle(zip, {
        noRekor: true,
        anchorReceiptVerifier: async (entry, expectedRoot) => {
          calls.push(entry.provider);
          expect(expectedRoot.rootHash).toBe(
            buildFixtureBundle().roots[0]!.rootHash,
          );
          return { ok: true };
        },
      });

      expect(report.ok).toBe(true);
      expect(report.rekor.checked).toBe(1);
      expect(report.rekor.failed).toBe(0);
      expect(report.rekor.reason).toContain('rekor_check_skipped_by_caller');
      expect(calls).toEqual(['s3']);
    });

    it('honours a caller-supplied anchorReceiptVerifier for ALL providers (overrides defaults)', async () => {
      const calls: Array<{
        provider: string;
        receipt: string;
        rootHash: string;
        signature: string;
      }> = [];
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
        anchorReceiptVerifier: async (entry, expectedRoot) => {
          calls.push({
            provider: entry.provider,
            receipt: entry.receipt,
            rootHash: expectedRoot.rootHash,
            signature: expectedRoot.signature,
          });
          return { ok: true };
        },
      });

      expect(report.ok).toBe(true);
      expect(report.rekor.ok).toBe(true);
      expect(calls).toEqual(
        [
          { provider: 'rekor', receipt: 'rekor:9001' },
          { provider: 's3', receipt: 's3:b:k:v' },
        ].map((entry) => ({
          ...entry,
          rootHash: buildFixtureBundle().roots[0]!.rootHash,
          signature: buildFixtureBundle().roots[0]!.signature,
        })),
      );
    });
  });

  /**
   * BUGHUNT-SDK-05 — Real offline Rekor receipt verification.
   *
   * The DEFAULT `rekor` check is now cryptographic: the receipt's Signed
   * Entry Timestamp (SET) and signed checkpoint must verify under the pinned
   * Rekor key, and its inclusion proof must reproduce the checkpoint's
   * authenticated root. A forged
   * non-Rekor blob like `"{}"` no longer passes (the old `JSON.parse`
   * default returned `true` for it). Tests pin a fresh Rekor key via
   * `rekorPublicKeyPem` (the sovereign-instance / test seam) and mint a
   * self-consistent single-leaf signed entry, then prove tampers fail.
   */
  describe('BUGHUNT-SDK-05 — real Rekor SET + checkpoint + inclusion verification', () => {
    const LEAF = Buffer.from([0x00]);

    function flipLastByteB64(b64: string): string {
      const buf = Buffer.from(b64, 'base64');
      buf[buf.length - 1] = buf[buf.length - 1]! ^ 0xff;
      return buf.toString('base64');
    }

    /**
     * Mint a self-consistent Rekor receipt (persisted flat shape) whose
     * SET and signed checkpoint verify under the returned P-256 pubkey and
     * whose single-leaf inclusion proof verifies against that checkpoint.
     */
    function buildRekorReceipt(opts?: {
      tamperSet?: boolean;
      tamperProof?: boolean;
      tamperCheckpoint?: boolean;
      tamperTreeSize?: boolean;
      omitCheckpoint?: boolean;
      bundleStyleCheckpoint?: boolean;
      unrelatedRoot?: boolean;
      /**
       * SEC-2026-09-12 (MCPSDK-01) — override the log's signed
       * `integratedTime` (epoch SECONDS) to model a receipt minted outside
       * the root's own claimed time window.
       */
      integratedTime?: number;
    }): { receiptJson: string; publicKeyPem: string } {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });
      const publicKeyPem = publicKey.export({
        type: 'spki',
        format: 'pem',
      }) as string;
      const spkiDer = publicKey.export({
        type: 'spki',
        format: 'der',
      }) as Buffer;
      const logID = crypto.createHash('sha256').update(spkiDer).digest('hex');
      const logIndex = 0;
      const fixtureRoot = buildFixtureBundle().roots[0]!;
      // SEC-2026-09-12 (MCPSDK-01) — a genuine log entry is integrated AFTER
      // the root it witnesses was signed. The previous hard-coded constant
      // (1748131200 = 2025-05-25) predated this fixture's `signedAt`
      // (2026-05-01) by ~11 months, i.e. it modelled exactly the
      // backdated-forgery shape the verifier now rejects; it passed only
      // because nothing compared `integratedTime` to anything.
      const integratedTime =
        opts?.integratedTime ??
        Math.floor(Date.parse(fixtureRoot.signedAt) / 1000) + 30;
      const rootHash = opts?.unrelatedRoot
        ? Buffer.alloc(32, 0xee).toString('base64')
        : fixtureRoot.rootHash;
      const body = Buffer.from(
        JSON.stringify({
          apiVersion: '0.0.1',
          kind: 'hashedrekord',
          spec: {
            data: {
              hash: {
                algorithm: 'sha256',
                value: Buffer.from(rootHash, 'base64').toString('hex'),
              },
            },
            signature: {
              content: fixtureRoot.signature,
              publicKey: { content: 'dGVzdC1rZXk=' },
            },
          },
        }),
        'utf8',
      ).toString('base64');

      // Canonical SET payload — key order body,integratedTime,logID,logIndex.
      const setPayload = Buffer.from(
        '{' +
          `"body":${JSON.stringify(body)},` +
          `"integratedTime":${JSON.stringify(integratedTime)},` +
          `"logID":${JSON.stringify(logID)},` +
          `"logIndex":${JSON.stringify(logIndex)}` +
          '}',
        'utf8',
      );
      const setSig = crypto.sign('sha256', setPayload, privateKey);
      const signedEntryTimestamp = opts?.tamperSet
        ? flipLastByteB64(setSig.toString('base64'))
        : setSig.toString('base64');

      // Single-leaf tree: rootHash = sha256(0x00 || body_bytes).
      const leafHash = crypto
        .createHash('sha256')
        .update(LEAF)
        .update(Buffer.from(body, 'base64'))
        .digest('hex');
      const checkpointNote = `rekor.test\n1\n${Buffer.from(leafHash, 'hex').toString('base64')}\n`;
      const checkpointSignature = crypto.sign(
        'sha256',
        Buffer.from(checkpointNote, 'utf8'),
        privateKey,
      );
      const signedCheckpoint = Buffer.concat([
        Buffer.from(logID, 'hex').subarray(0, 4),
        checkpointSignature,
      ]);
      const checkpointEnvelope = `${checkpointNote}\n— rekor.test ${
        opts?.tamperCheckpoint
          ? flipLastByteB64(signedCheckpoint.toString('base64'))
          : signedCheckpoint.toString('base64')
      }\n`;

      const receipt = {
        uuid: '24296fb24b8ad77a000000000000000000000000000000000000000000000001',
        logIndex,
        inclusionProof: {
          logIndex: 0,
          treeSize: opts?.tamperTreeSize ? 2 : 1,
          rootHash: opts?.tamperProof ? '00'.repeat(32) : leafHash,
          hashes: [] as string[],
          ...(opts?.omitCheckpoint
            ? {}
            : {
                checkpoint: opts?.bundleStyleCheckpoint
                  ? { envelope: checkpointEnvelope }
                  : checkpointEnvelope,
              }),
        },
        signedEntryTimestamp,
        logId: logID,
        integratedTime,
        body,
      };
      return { receiptJson: JSON.stringify(receipt), publicKeyPem };
    }

    /** Attach a rekor receipt to the pristine fixture's single root. */
    function bundleWithRekorReceipt(
      receiptJson: string,
      anchoredAt = '2026-05-01T01:05:00.000Z',
    ): Buffer {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const root = base.roots[0]!;
      const patched: FixtureRoot = {
        ...root,
        anchoredAt,
        anchorReceipt: null,
        anchorReceipts: [
          {
            provider: 'rekor',
            receipt: receiptJson,
            anchoredAt,
          },
        ],
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

    it('verifies a genuine signed Rekor receipt (SET + checkpoint + inclusion) by default', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt();
      const zip = bundleWithRekorReceipt(receiptJson);
      // Default rekor path (no rekorFetcher/anchorReceiptVerifier); pin the
      // fresh signing key as a sovereign Rekor instance would.
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.rekor.ok).toBe(true);
      expect(report.rekor.checked).toBe(1);
      expect(report.rekor.failed).toBe(0);
      expect(report.ok).toBe(true);
    });

    describe('SEC-2026-09-12 (MCPSDK-01) — integratedTime bound to the root window', () => {
      /**
       * The revoked-key replay: a holder of a compromised (since-REVOKED)
       * tenant key forges a bundle claiming an old period, re-anchors the
       * forged root in public Rekor TODAY (anyone may submit a
       * hashedrekord), and ships it. Every signature, the chain, the proofs
       * and the Rekor receipt itself are internally consistent — the only
       * artefact the forger cannot backdate is the log's own signed
       * `integratedTime`, so that is what must be compared to the bundle's
       * self-asserted window.
       */
      it('FAILS a receipt integrated months AFTER the root claims it was anchored', async () => {
        const anchoredAt = '2026-05-01T01:05:00.000Z';
        const { receiptJson, publicKeyPem } = buildRekorReceipt({
          // ~3 months after `anchoredAt` — far outside the 24h skew.
          integratedTime: Math.floor(
            Date.parse('2026-08-01T01:05:00.000Z') / 1000,
          ),
        });
        const zip = bundleWithRekorReceipt(receiptJson, anchoredAt);
        const report = await verifyBundle(zip, {
          rekorPublicKeyPem: publicKeyPem,
        });
        expect(report.rekor.ok).toBe(false);
        expect(report.rekor.failed).toBe(1);
        expect(report.rekor.reason).toMatch(
          /rekor_integrated_time_out_of_window/,
        );
        expect(report.ok).toBe(false);
        expect(report.status).toBe('invalid');
      });

      it('FAILS a receipt integrated BEFORE the root was signed', async () => {
        const { receiptJson, publicKeyPem } = buildRekorReceipt({
          integratedTime: Math.floor(
            Date.parse('2026-04-01T00:00:00.000Z') / 1000,
          ),
        });
        const zip = bundleWithRekorReceipt(receiptJson);
        const report = await verifyBundle(zip, {
          rekorPublicKeyPem: publicKeyPem,
        });
        expect(report.rekor.ok).toBe(false);
        expect(report.rekor.reason).toMatch(
          /rekor_integrated_time_out_of_window/,
        );
        expect(report.ok).toBe(false);
      });

      it('ACCEPTS a legacy single-slot receipt anchored later than signedAt (no anchoredAt recorded)', async () => {
        // Back-compat: pre-multi-anchor bundles carry `anchorReceipt` with
        // NO `anchoredAt`. A backfill run that anchored an old root months
        // after it was signed is legitimate and must keep verifying — the
        // upper bound only exists where the producer recorded a real anchor
        // time.
        const { receiptJson, publicKeyPem } = buildRekorReceipt({
          integratedTime: Math.floor(
            Date.parse('2026-09-01T00:00:00.000Z') / 1000,
          ),
        });
        const base = buildFixtureBundle();
        const entries = readBundleEntries(base.zip);
        const patched: FixtureRoot = {
          ...base.roots[0]!,
          anchoredAt: null,
          anchorReceipt: receiptJson,
        };
        const zip = writeZip([
          { name: 'manifest.json', data: entries.get('manifest.json')! },
          { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
          {
            name: 'roots.ndjson.gz',
            data: gzipDeterministic(
              Buffer.from(JSON.stringify(patched) + '\n', 'utf8'),
            ),
          },
          { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
          { name: 'public-keys.json', data: entries.get('public-keys.json')! },
          { name: 'README.md', data: entries.get('README.md')! },
        ]);
        const report = await verifyBundle(zip, {
          rekorPublicKeyPem: publicKeyPem,
        });
        expect(report.rekor.ok).toBe(true);
        expect(report.rekor.checked).toBe(1);
      });
    });

    it('accepts the Sigstore bundle-style checkpoint envelope object', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt({
        bundleStyleCheckpoint: true,
      });
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.rekor.ok).toBe(true);
      expect(report.ok).toBe(true);
    });

    it('FAILS a forged non-Rekor receipt ("{}") — no false OK', async () => {
      const zip = bundleWithRekorReceipt('{}');
      const report = await verifyBundle(zip, {}); // pure default path
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.failed).toBe(1);
      expect(report.rekor.reason).toContain('not_a_rekor_entry');
      expect(report.ok).toBe(false);
    });

    it('FAILS a tampered SET signature', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt({
        tamperSet: true,
      });
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.reason).toMatch(/set_/);
      expect(report.ok).toBe(false);
    });

    it('FAILS a tampered inclusion proof (rootHash mismatch)', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt({
        tamperProof: true,
      });
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.reason).toContain('checkpoint_root_mismatch');
      expect(report.ok).toBe(false);
    });

    it('FAILS an inclusion proof that omits its signed checkpoint', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt({
        omitCheckpoint: true,
      });
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.reason).toContain('checkpoint_missing');
      expect(report.ok).toBe(false);
    });

    it('FAILS a tampered signed checkpoint', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt({
        tamperCheckpoint: true,
      });
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.reason).toContain('checkpoint_signature_invalid');
      expect(report.ok).toBe(false);
    });

    it('FAILS proof metadata whose tree size disagrees with the signed checkpoint', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt({
        tamperTreeSize: true,
      });
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.reason).toContain('checkpoint_tree_size_mismatch');
      expect(report.ok).toBe(false);
    });

    it('FAILS a genuine receipt whose logID is not the pinned Sigstore key', async () => {
      // No override → the receipt's fresh logID does not match the bundled
      // Sigstore pin, so the verifier fails closed rather than trusting an
      // unpinned key (never silently falls back to a default key).
      const { receiptJson } = buildRekorReceipt();
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {});
      expect(report.rekor.ok).toBe(false);
      expect(report.rekor.reason).toContain('set_logid_unpinned');
    });

    it('FAILS a genuine but unrelated Rekor receipt', async () => {
      const { receiptJson, publicKeyPem } = buildRekorReceipt({
        unrelatedRoot: true,
      });
      const zip = bundleWithRekorReceipt(receiptJson);
      const report = await verifyBundle(zip, {
        rekorPublicKeyPem: publicKeyPem,
      });
      expect(report.ok).toBe(false);
      expect(report.rekor.reason).toContain('body_root_mismatch');
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
   *   - Missing attestation entry fails closed unless legacy semantics are
   *     explicitly requested.
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
      omitKeyVersion?: boolean;
      /**
       * SEC-2026-09-12 (MCPSDK-01) — emit a PRE-binding (legacy)
       * attestation: no `manifestGeneratedAt`/`manifestDigest` at all.
       * Every attestation minted before the binding change looks like this
       * and must keep verifying (customers verify archives).
       */
      legacyUnbound?: boolean;
      /** Bind to a digest that is not this manifest's. */
      tamperManifestDigest?: boolean;
      /** Bind to a `generatedAt` that is not this manifest's. */
      tamperManifestGeneratedAt?: boolean;
      /** Override the attestation's own `issuedAt`. */
      issuedAt?: string;
    }): { zip: Buffer; platformPublicKeyDerB64: string } {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, string>;
      const manifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; generatedAt: string };
      // SEC-2026-09-12 (MCPSDK-01) — sha256 over the manifest's canonical
      // SIGNABLE bytes (everything except the signature envelope fields);
      // this fixture's manifest is v1, whose signable set is exactly that.
      const manifestSignable = { ...(JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>) };
      delete manifestSignable.signature;
      delete manifestSignable.signatureKeyVersion;
      const manifestDigest = crypto
        .createHash('sha256')
        .update(canonicalJson(manifestSignable))
        .digest('hex');

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
        .filter(() => !opts.omitKeyVersion)
        .sort((a, b) => a.keyVersion - b.keyVersion);

      const attestation = {
        orgId: opts.tamperOrgId
          ? '00000000-0000-0000-0000-0000DEADBEEF'
          : manifest.orgId,
        keyVersions,
        issuedAt: opts.issuedAt ?? '2026-05-01T01:00:00.000Z',
        platformSigningKeyFingerprint: platformFingerprint,
        // Default models the CURRENT exporter: bound to this exact manifest.
        // Every tamper below is re-signed, so the failure surface under test
        // is the binding check itself, never the signature.
        ...(opts.legacyUnbound
          ? {}
          : {
              manifestGeneratedAt: opts.tamperManifestGeneratedAt
                ? '2026-04-01T00:00:00.000Z'
                : manifest.generatedAt,
              manifestDigest: opts.tamperManifestDigest
                ? '0'.repeat(64)
                : manifestDigest,
            }),
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

    it('rejects an attestation that omits a bundled key version', async () => {
      const { zip, platformPublicKeyDerB64 } =
        buildBundleWithPlatformAttestation({ omitKeyVersion: true });
      const report = await verifyBundleStrict(zip, {
        noRekor: true,
        platformPublicKeyDerB64,
      });
      expect(report.ok).toBe(false);
      expect(report.platformAttestation.reason).toContain(
        'keyversion_set_mismatch',
      );
    });

    it('fails closed when platform-attestation.json is missing', async () => {
      const { zip, platformPublicKeyDerB64 } =
        buildBundleWithPlatformAttestation({ omitEntry: true });
      const report = await verifyBundleStrict(zip, {
        noRekor: true,
        platformPublicKeyDerB64,
      });
      expect(report.ok).toBe(false);
      expect(report.platformAttestation.ok).toBe(false);
      expect(report.platformAttestation.reason).toBe(
        'platform_attestation_missing',
      );
    });

    describe('SEC-2026-09-12 (MCPSDK-01) — attestation bound to THIS export', () => {
      /**
       * The attestation is the only PLATFORM-signed input in a bundle.
       * Before this binding it named an org and a key set but no particular
       * export and no point in time, so a holder of a compromised
       * (since-REVOKED) tenant key could forge a whole bundle that re-labels
       * the key ACTIVE and staple on any genuine PRE-revocation attestation
       * for that org — every check passed.
       */
      it('rejects an attestation issued BEFORE the manifest it vouches for was generated', async () => {
        const { zip, platformPublicKeyDerB64 } =
          buildBundleWithPlatformAttestation({
            // Manifest generatedAt is 2026-05-01T01:00:30Z; a month earlier
            // is far outside the 24h skew allowance.
            issuedAt: '2026-04-01T00:00:00.000Z',
            legacyUnbound: true,
          });
        const report = await verifyBundleStrict(zip, {
          noRekor: true,
          platformPublicKeyDerB64,
        });
        expect(report.ok).toBe(false);
        expect(report.platformAttestation.ok).toBe(false);
        expect(report.platformAttestation.reason).toMatch(
          /attestation_predates_manifest/,
        );
      });

      it('rejects an attestation bound to a different manifest digest', async () => {
        const { zip, platformPublicKeyDerB64 } =
          buildBundleWithPlatformAttestation({ tamperManifestDigest: true });
        const report = await verifyBundleStrict(zip, {
          noRekor: true,
          platformPublicKeyDerB64,
        });
        expect(report.ok).toBe(false);
        expect(report.platformAttestation.ok).toBe(false);
        expect(report.platformAttestation.reason).toMatch(
          /attestation_manifest_binding_mismatch/,
        );
      });

      it('rejects an attestation bound to a different manifest generatedAt', async () => {
        const { zip, platformPublicKeyDerB64 } =
          buildBundleWithPlatformAttestation({
            tamperManifestGeneratedAt: true,
          });
        const report = await verifyBundleStrict(zip, {
          noRekor: true,
          platformPublicKeyDerB64,
        });
        expect(report.ok).toBe(false);
        expect(report.platformAttestation.reason).toMatch(
          /attestation_manifest_binding_mismatch/,
        );
      });

      it('verifies a bound attestation with no note', async () => {
        const { zip, platformPublicKeyDerB64 } =
          buildBundleWithPlatformAttestation({});
        const report = await verifyBundleStrict(zip, {
          noRekor: true,
          platformPublicKeyDerB64,
        });
        expect(report.ok).toBe(true);
        expect(report.platformAttestation.reason).toBeUndefined();
      });

      it('ACCEPTS a legacy unbound attestation but flags it, and the CLI prints a NOTE', () => {
        const { zip, platformPublicKeyDerB64 } =
          buildBundleWithPlatformAttestation({ legacyUnbound: true });
        const testDir = path.dirname(fileURLToPath(import.meta.url));
        const cliPath = path.resolve(testDir, '../../dist/cli.js');
        if (!fs.existsSync(cliPath)) {
          throw new Error(
            'dist/cli.js not found — `npm run build` must run before `npm test`.',
          );
        }
        const tmpDir = fs.mkdtempSync(
          path.join(os.tmpdir(), 'audit-verifier-attest-note-'),
        );
        try {
          const bundlePath = path.join(tmpDir, 'bundle.zip');
          const keyPath = path.join(tmpDir, 'platform.der');
          fs.writeFileSync(bundlePath, zip);
          fs.writeFileSync(
            keyPath,
            Buffer.from(platformPublicKeyDerB64, 'base64'),
          );
          const stdout = execFileSync(
            process.execPath,
            [cliPath, bundlePath, '--no-rekor', '--platform-key', keyPath],
            { encoding: 'utf8' },
          );
          expect(stdout).toContain('RESULT: OK');
          expect(stdout).toContain(
            'NOTE: this bundle\'s platform attestation is not bound to this manifest',
          );
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });
    });

    it('accepts a missing attestation only with explicit legacy opt-in', async () => {
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundleStrict(zip, {
        noRekor: true,
        allowLegacyUnattested: true,
      });
      expect(report.ok).toBe(true);
      // AV-0008 — opted-out missing attestation is absent evidence.
      expect(report.platformAttestation.status).toBe('not_present');
      expect(report.platformAttestation.reason).toBe(
        'missing_legacy_explicitly_allowed',
      );
    });

    /**
     * AV-0002 — a verified bundle's platform attestation is the customer's
     * verifier-produced source for the AIBOM tenant-key pin. The AIBOM is
     * be's real `verified-ed25519` export, re-homed to an org and re-signed
     * with `buildFixtureBundle`'s tenant key (be's generator discards its
     * private keys, so no be fixture shares a key with a bundle fixture).
     */
    describe('AV-0002 — the verified bundle is the AIBOM tenant-key pin source', () => {
      const bundleKey = keypairFromSeed(Buffer.alloc(32, 7));
      const bundleOrg = '00000000-0000-0000-0000-000000000001';
      const otherOrg = '4b0f5a3e-2c1d-4e8f-9a7b-0c1d2e3f4a5b';
      const fp = sha256(bundleKey.publicKey).toString('hex');
      function aibomFor(orgId: string): Buffer {
        const env = JSON.parse(
          fs.readFileSync(path.resolve(process.cwd(), 'test-fixtures/aibom/verified-ed25519.attested.json'), 'utf8'),
        ) as Record<string, unknown> & { document: Record<string, unknown>; digest: string };
        env.organizationId = orgId;
        env.document = { ...env.document, organizationId: orgId };
        env.digest = sha256(canonicalJson(env.document)).toString('hex');
        env.publicKey = Buffer.from(bundleKey.publicKey).toString('base64');
        env.signature = signEd25519(Buffer.from(`praesidia:aibom-snapshot:v1:${env.digest}`), bundleKey.privateKey);
        return canonicalJson(env);
      }
      async function attested(opts: { tamperSignature?: boolean } = {}) {
        const { zip, platformPublicKeyDerB64 } = buildBundleWithPlatformAttestation(opts);
        const report = await verifyBundleStrict(zip, { noRekor: true, platformPublicKeyDerB64 });
        return { zip, platformPublicKeyDerB64, report };
      }
      async function unattested() {
        return verifyBundleStrict(buildBundleWithTamper({}).zip, { noRekor: true, allowLegacyUnattested: true });
      }

      it('lists keyVersion, status and fingerprint only when the platform attestation verified', async () => {
        expect((await attested()).report.bundle.attestedTenantKeys).toEqual([
          { keyVersion: 1, status: 'ACTIVE', fingerprint: fp, attestedAt: '2026-05-01T01:00:00.000Z' },
        ]);
        expect((await attested({ tamperSignature: true })).report.bundle.attestedTenantKeys).toBeUndefined();
        const legacy = await unattested();
        expect(legacy.ok).toBe(true);
        expect(legacy.bundle.attestedTenantKeys).toBeUndefined();
      });

      it('verifies an AIBOM of the same org; another org fails closed even though the key matches', async () => {
        const trust = aibomTrustFromBundle((await attested()).report);
        expect(trust).toEqual({ trustedKeyFingerprints: [fp], organizationId: bundleOrg });
        expect(verifyAibomAttestation(aibomFor(bundleOrg), trust)).toMatchObject({ valid: true, reason: 'verified' });
        // Same key, other org: the fingerprint alone would accept it.
        expect(verifyAibomAttestation(aibomFor(otherOrg), { trustedKeyFingerprints: [fp] }).valid).toBe(true);
        const cross = verifyAibomAttestation(aibomFor(otherOrg), trust);
        expect(cross).toMatchObject({ valid: false, reason: 'untrusted_key' });
        expect(cross.detail).toContain(`pinned keys belong to org ${bundleOrg}`);
      });

      it('refuses an unattested, invalid or incomplete bundle as a pin source, and never pins a REVOKED key', async () => {
        const legacy = await unattested();
        const broken = (await attested({ tamperSignature: true })).report;
        expect(() => aibomTrustFromBundle(legacy)).toThrow(/no verified platform attestation/);
        expect(() => aibomTrustFromBundle(broken)).toThrow(/status is invalid/);
        const { report } = await attested();
        expect(() => aibomTrustFromBundle({ ...report, status: 'incomplete' })).toThrow(/status is incomplete/);
        const revoked = aibomTrustFromBundle({
          ...report,
          bundle: { ...report.bundle, attestedTenantKeys: [{ ...report.bundle.attestedTenantKeys![0]!, status: 'REVOKED' }] },
        });
        expect(revoked.trustedKeyFingerprints).toEqual([]);
        expect(verifyAibomAttestation(aibomFor(bundleOrg), revoked).reason).toBe('untrusted_key');
      });

      it('CLI: `aibom --audit-bundle` pins from the verified bundle and fails closed otherwise', async () => {
        const cliPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js');
        expect(fs.existsSync(cliPath), 'npm run build must run before npm test').toBe(true);
        const run = (args: string[]) => {
          try {
            return { code: 0, stdout: execFileSync(process.execPath, [cliPath, ...args], { encoding: 'utf8', stdio: 'pipe' }), stderr: '' };
          } catch (e) {
            const err = e as { status: number; stdout: string; stderr: string };
            return { code: err.status, stdout: err.stdout, stderr: err.stderr };
          }
        };
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-0002-'));
        try {
          const { zip, platformPublicKeyDerB64 } = await attested();
          const f = (name: string, data: Buffer) => (fs.writeFileSync(path.join(tmp, name), data), path.join(tmp, name));
          const bundle = f('bundle.zip', zip);
          const legacy = f('legacy.zip', buildBundleWithTamper({}).zip);
          const key = f('platform.der', Buffer.from(platformPublicKeyDerB64, 'base64'));
          const same = f('same.json', aibomFor(bundleOrg));
          const other = f('other.json', aibomFor(otherOrg));
          const trustFlags = ['--no-rekor', '--platform-key', key];

          expect(run([bundle, ...trustFlags]).stdout).toContain(`tenant key v1:  ACTIVE  sha256 ${fp} (platform-attested 2026-05-01T01:00:00.000Z)`);
          expect(run(['aibom', same, '--audit-bundle', bundle, ...trustFlags, '--quiet'])).toMatchObject({ code: 0, stdout: 'OK\n' });
          const human = run(['aibom', same, '--audit-bundle', bundle, ...trustFlags]).stdout;
          expect(human).toContain(`pin source: verified audit bundle for org ${bundleOrg}: 1 non-revoked tenant key(s), status as attested at 2026-05-01T01:00:00.000Z`);
          expect(human).toContain('WARNING: platform key supplied by caller');
          const cross = run(['aibom', other, '--audit-bundle', bundle, ...trustFlags, '--json']);
          expect(cross.code).toBe(1);
          expect(JSON.parse(cross.stdout).reason).toBe('untrusted_key');
          for (const extra of [[], ['--allow-legacy-unattested']]) {
            const res = run(['aibom', same, '--audit-bundle', legacy, '--no-rekor', ...extra]);
            expect(res.code).toBe(1);
            expect(res.stderr).toContain('--audit-bundle is not a pin source');
          }
          expect(run(['aibom', same, '--audit-bundle', bundle, '--tenant-key-fingerprint', fp]).code).toBe(2);
          expect(run(['aibom', same, '--tenant-key-fingerprint', fp, '--no-rekor']).code).toBe(2);
        } finally {
          fs.rmSync(tmp, { recursive: true, force: true });
        }
      });
    });
  });

  /**
   * PROD16 (be-compliance F5(a) / audit-verifier's half of the same
   * finding) — `rootCoverage`.
   *
   * `completeness` (BUG-AUDIT-01, above) only compares the AGGREGATE
   * `rows.length` to the SIGNED `manifest.rowCount` — it says nothing
   * about which PERIOD the surviving rows fall into. A root is signed
   * and Rekor-anchored independently, at anchor time, over its own
   * `rowCount`. If rows are deleted from the underlying table AFTER a
   * period's root was anchored but BEFORE the bundle is (re-)exported,
   * the exporter honestly recomputes a SMALLER `manifest.rowCount` from
   * the live (already-truncated) table — `completeness` passes — while
   * the untouched, already-signed root still claims the ORIGINAL,
   * larger count. Nothing compared the two before this fix.
   */
  describe('rootCoverage — suffix deletion inside an already-anchored period (PROD16)', () => {
    function reSignManifest(opts: {
      orgId: string;
      rowCount: number;
      rootCount: number;
      from: string;
      to: string;
      publicKeyB64: string;
      keyVersion: number;
      privateKey: Uint8Array;
    }): { manifestJson: Record<string, unknown> } {
      const manifestSans = {
        version: 1,
        orgId: opts.orgId,
        from: opts.from,
        to: opts.to,
        rowCount: opts.rowCount,
        rootCount: opts.rootCount,
        keyVersions: [
          { keyVersion: opts.keyVersion, publicKey: opts.publicKeyB64 },
        ],
        generatedAt: opts.to,
        signatureAlgorithm: 'Ed25519' as const,
      };
      const signature = signEd25519(
        canonicalJson(manifestSans),
        opts.privateKey,
      );
      return {
        manifestJson: {
          ...manifestSans,
          signature,
          signatureKeyVersion: opts.keyVersion,
        },
      };
    }

    function packBundle(
      manifestJson: Record<string, unknown>,
      rows: FixtureRow[],
      roots: FixtureRoot[],
      proofs: FixtureProof[],
      publicKeys: Record<string, string>,
    ): Buffer {
      const rowsNdjson = Buffer.from(
        rows.map((r) => JSON.stringify(r)).join('\n') +
          (rows.length > 0 ? '\n' : ''),
        'utf8',
      );
      const rootsNdjson = Buffer.from(
        roots.map((r) => JSON.stringify(r)).join('\n') +
          (roots.length > 0 ? '\n' : ''),
        'utf8',
      );
      const proofsNdjson = Buffer.from(
        proofs.map((p) => JSON.stringify(p)).join('\n') +
          (proofs.length > 0 ? '\n' : ''),
        'utf8',
      );
      return writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifestJson, null, 2), 'utf8'),
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
    }

    it('fails closed when a fully-anchored root outlives a deleted trailing row (forgery that completeness alone cannot see)', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, string>;

      // Delete the trailing row (as if it were removed from the DB after
      // root-1 was already anchored) + its proof. The root — already
      // signed and anchored — is left byte-identical, still claiming
      // rowCount=4.
      const survivingRows = base.rows.slice(0, 3);
      const survivingProofs = base.proofs.filter((p) => p.rowId !== 'row-3');

      // The exporter honestly recomputes rowCount from the (now
      // truncated) live table and mints a fresh, validly-signed
      // manifest — this is NOT a forged signature, it's what a real
      // re-export produces after the deletion.
      const { manifestJson } = reSignManifest({
        orgId: originalManifest.orgId,
        rowCount: survivingRows.length,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1']!,
        keyVersion: 1,
        privateKey,
      });

      const zip = packBundle(
        manifestJson,
        survivingRows,
        base.roots,
        survivingProofs,
        publicKeys,
      );
      const report = await verifyBundle(zip, { noRekor: true });

      // Every other component is individually happy — this is exactly
      // the bypass PROD16 flagged.
      expect(report.completeness.ok).toBe(true);
      expect(report.rowSignatures.ok).toBe(true);
      expect(report.chain.ok).toBe(true);
      expect(report.rootSignatures.ok).toBe(true);
      expect(report.inclusionProofs.ok).toBe(true);
      // rootCoverage is the only component that catches it.
      expect(report.rootCoverage.ok).toBe(false);
      expect(report.rootCoverage.failed).toBeGreaterThan(0);
      expect(report.rootCoverage.firstFailure).toBe('root-1');
      expect(report.rootCoverage.reason).toContain('root-1');
      expect(report.ok).toBe(false);
    });

    it('passes rootCoverage for a pristine (untruncated) bundle', async () => {
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rootCoverage.ok).toBe(true);
      expect(report.rootCoverage.checked).toBe(1);
      expect(report.rootCoverage.failed).toBe(0);
    });

    it('exempts a boundary root that only partially overlaps the bundle range (legitimate ranged export)', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, string>;

      // A genuine ranged export whose declared `to` cuts off BEFORE the
      // root's real periodEnd — rows signed at/after the cutoff are
      // legitimately absent. root-1 (periodEnd = original `to`) now only
      // PARTIALLY overlaps [from, cutoffTo), so it must be exempted.
      const cutoffTo = base.rows[2]!.signedAt;
      const survivingRows = base.rows.filter((r) => r.signedAt < cutoffTo);
      const survivingRowIds = new Set(survivingRows.map((r) => r.id));
      const survivingProofs = base.proofs.filter((p) =>
        survivingRowIds.has(p.rowId),
      );

      const { manifestJson } = reSignManifest({
        orgId: originalManifest.orgId,
        rowCount: survivingRows.length,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: cutoffTo,
        publicKeyB64: publicKeys['1']!,
        keyVersion: 1,
        privateKey,
      });

      const zip = packBundle(
        manifestJson,
        survivingRows,
        base.roots,
        survivingProofs,
        publicKeys,
      );
      const report = await verifyBundle(zip, { noRekor: true });

      expect(report.completeness.ok).toBe(true);
      // Exempted: root-1's periodEnd exceeds the bundle's declared `to`,
      // so it is a boundary/partial root, not fully contained.
      // AV-0008 — no fully-contained root to cover: not_present, not valid.
      expect(report.rootCoverage.status).toBe('not_present');
      expect(report.rootCoverage.checked).toBe(0);
      expect(report.ok).toBe(true);
    });
  });

  /**
   * FIX01 (audit-verifier2) / `BE-0003` — closes the `rootCoverage`
   * false-positive on a bundle spanning a LEGITIMATE, signed, two-person
   * -approval-gated `AuditRetentionSeal` retention purge. See
   * `FIX01-FIXED-be4.md`'s "FOR AUDIT-VERIFIER" spec for the wire shape
   * and algorithm this implements.
   */
  describe('FIX01 (audit-verifier2) / BE-0003 — sealed-purge exemption for rootCoverage', () => {
    function reSignManifestV1(opts: {
      orgId: string;
      rowCount: number;
      rootCount: number;
      from: string;
      to: string;
      publicKeyB64: string;
      keyVersion: number;
      privateKey: Uint8Array;
    }): Record<string, unknown> {
      const manifestSans = {
        version: 1,
        orgId: opts.orgId,
        from: opts.from,
        to: opts.to,
        rowCount: opts.rowCount,
        rootCount: opts.rootCount,
        keyVersions: [
          { keyVersion: opts.keyVersion, publicKey: opts.publicKeyB64 },
        ],
        generatedAt: opts.to,
        signatureAlgorithm: 'Ed25519' as const,
      };
      const signature = signEd25519(
        canonicalJson(manifestSans),
        opts.privateKey,
      );
      return {
        ...manifestSans,
        signature,
        signatureKeyVersion: opts.keyVersion,
      };
    }

    /**
     * Mirrors `AuditRetentionSeal`'s wire shape (`BundleSealedPurge`).
     * Signed preimage: `canonicalJson({organizationId, periodStart,
     * periodEnd, rowCount, rootHash, rekorReceipt})` — the seal's OWN
     * envelope, independent of the manifest signature.
     */
    function signSeal(opts: {
      id: string;
      orgId: string;
      periodStart: string;
      periodEnd: string;
      rowCount: string;
      rootHash: string;
      deletedAt: string;
      approvalId: string;
      deletedBy: string;
      keyVersion: number;
      privateKey: Uint8Array;
      tamperSignature?: boolean;
      /** Models seals emitted before the producer signed bigint rowCount as a string. */
      legacyNumericRowCountPreimage?: boolean;
    }): Record<string, unknown> {
      const rekorReceipt = null;
      const message = canonicalJson({
        organizationId: opts.orgId,
        periodStart: opts.periodStart,
        periodEnd: opts.periodEnd,
        rowCount: opts.legacyNumericRowCountPreimage
          ? Number(opts.rowCount)
          : opts.rowCount,
        rootHash: opts.rootHash,
        rekorReceipt,
      });
      let signature = signEd25519(message, opts.privateKey);
      if (opts.tamperSignature) {
        const bytes = Buffer.from(signature, 'base64');
        bytes[0] = (bytes[0]! + 1) % 256;
        signature = bytes.toString('base64');
      }
      return {
        id: opts.id,
        organizationId: opts.orgId,
        periodStart: opts.periodStart,
        periodEnd: opts.periodEnd,
        rowCount: opts.rowCount,
        rootHash: opts.rootHash,
        rekorReceipt,
        signature,
        signingKeyVersion: opts.keyVersion,
        signatureAlgorithm: 'Ed25519',
        deletedAt: opts.deletedAt,
        deletedBy: opts.deletedBy,
        approvalId: opts.approvalId,
      };
    }

    function packBundleWithSeals(
      manifestJson: Record<string, unknown>,
      rows: FixtureRow[],
      roots: FixtureRoot[],
      proofs: FixtureProof[],
      publicKeys: Record<string, unknown>,
      seals: Array<Record<string, unknown>>,
    ): Buffer {
      const ndjson = (arr: unknown[]): Buffer =>
        Buffer.from(
          arr.map((x) => JSON.stringify(x)).join('\n') +
            (arr.length > 0 ? '\n' : ''),
          'utf8',
        );
      return writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifestJson, null, 2), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: gzipDeterministic(ndjson(rows)) },
        { name: 'roots.ndjson.gz', data: gzipDeterministic(ndjson(roots)) },
        { name: 'proofs.ndjson.gz', data: gzipDeterministic(ndjson(proofs)) },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
        {
          name: 'sealed-purges.ndjson.gz',
          data: gzipDeterministic(ndjson(seals)),
        },
      ]);
    }

    it("downgrades a rootCoverage suffix-deletion failure to a pass when a verified sealed purge exactly matches the root's period+rootHash", async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const root = base.roots[0]!;

      // A real retention seal replaces the entire rooted period, not an
      // arbitrary suffix. The signed seal rowCount must exactly account for
      // the missing rows/proofs.
      const survivingRows: FixtureRow[] = [];
      const survivingProofs: FixtureProof[] = [];
      const manifestJson = reSignManifestV1({
        orgId: originalManifest.orgId,
        rowCount: survivingRows.length,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1'] as string,
        keyVersion: 1,
        privateKey,
      });
      const seal = signSeal({
        id: 'seal-1',
        orgId: originalManifest.orgId,
        periodStart: root.periodStart,
        periodEnd: root.periodEnd,
        rowCount: String(root.rowCount),
        rootHash: root.rootHash,
        deletedAt: '2026-05-01T01:15:00.000Z',
        approvalId: 'approval-42',
        deletedBy: 'user-1',
        keyVersion: 1,
        privateKey,
      });
      const zip = packBundleWithSeals(
        manifestJson,
        survivingRows,
        base.roots,
        survivingProofs,
        publicKeys,
        [seal],
      );
      const report = await verifyBundle(zip, { noRekor: true });

      expect(report.rootCoverage.ok).toBe(true);
      expect(report.rootCoverage.failed).toBe(0);
      expect(report.rootCoverage.sealExemptions).toBeDefined();
      expect(report.rootCoverage.sealExemptions![0]).toContain('seal-1');
      expect(report.rootCoverage.sealExemptions![0]).toContain('approval-42');
      expect(report.bundle.sealedPurgesSeen).toBe(1);
      expect(report.bundle.sealedPurgesVerified).toBe(1);
      expect(report.ok).toBe(true);
    });

    it('keeps failing closed when a validly signed seal does not account for the full missing row count', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const root = base.roots[0]!;
      const manifestJson = reSignManifestV1({
        orgId: originalManifest.orgId,
        rowCount: 0,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1'] as string,
        keyVersion: 1,
        privateKey,
      });
      const undercountingSeal = signSeal({
        id: 'seal-undercounts',
        orgId: originalManifest.orgId,
        periodStart: root.periodStart,
        periodEnd: root.periodEnd,
        rowCount: '1',
        rootHash: root.rootHash,
        deletedAt: '2026-05-01T01:15:00.000Z',
        approvalId: 'approval-42',
        deletedBy: 'user-1',
        keyVersion: 1,
        privateKey,
      });
      const report = await verifyBundle(
        packBundleWithSeals(manifestJson, [], base.roots, [], publicKeys, [
          undercountingSeal,
        ]),
        { noRekor: true },
      );

      expect(report.bundle.sealedPurgesVerified).toBe(1);
      expect(report.rootCoverage.status).toBe('invalid');
      expect(report.rootCoverage.sealExemptions).toBeUndefined();
      expect(report.ok).toBe(false);
    });

    it('accepts the backend legacy numeric rowCount signature while the wire remains a string', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const root = base.roots[0]!;
      const manifestJson = reSignManifestV1({
        orgId: originalManifest.orgId,
        rowCount: 0,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1'] as string,
        keyVersion: 1,
        privateKey,
      });
      const legacySeal = signSeal({
        id: 'seal-legacy-number',
        orgId: originalManifest.orgId,
        periodStart: root.periodStart,
        periodEnd: root.periodEnd,
        rowCount: String(root.rowCount),
        rootHash: root.rootHash,
        deletedAt: '2026-05-01T01:15:00.000Z',
        approvalId: 'approval-legacy',
        deletedBy: 'user-1',
        keyVersion: 1,
        privateKey,
        legacyNumericRowCountPreimage: true,
      });
      const report = await verifyBundle(
        packBundleWithSeals(manifestJson, [], base.roots, [], publicKeys, [
          legacySeal,
        ]),
        { noRekor: true },
      );

      expect(report.bundle.sealedPurgesVerified).toBe(1);
      expect(report.rootCoverage.status).toBe('valid');
      expect(report.ok).toBe(true);
    });

    it('keeps failing closed when the sealed-purge signature is tampered — unverifiable evidence is never used', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const root = base.roots[0]!;

      const survivingRows = base.rows.slice(0, 3);
      const survivingProofs = base.proofs.filter((p) => p.rowId !== 'row-3');
      const manifestJson = reSignManifestV1({
        orgId: originalManifest.orgId,
        rowCount: survivingRows.length,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1'] as string,
        keyVersion: 1,
        privateKey,
      });
      const seal = signSeal({
        id: 'seal-tampered',
        orgId: originalManifest.orgId,
        periodStart: root.periodStart,
        periodEnd: root.periodEnd,
        rowCount: '1',
        rootHash: root.rootHash,
        deletedAt: '2026-05-01T01:15:00.000Z',
        approvalId: 'approval-42',
        deletedBy: 'user-1',
        keyVersion: 1,
        privateKey,
        tamperSignature: true,
      });
      const zip = packBundleWithSeals(
        manifestJson,
        survivingRows,
        base.roots,
        survivingProofs,
        publicKeys,
        [seal],
      );
      const report = await verifyBundle(zip, { noRekor: true });

      expect(report.rootCoverage.ok).toBe(false);
      expect(report.rootCoverage.reason).toContain('root-1');
      expect(report.rootCoverage.sealExemptions).toBeUndefined();
      expect(report.bundle.sealedPurgesSeen).toBe(1);
      expect(report.bundle.sealedPurgesVerified).toBe(0);
      expect(report.ok).toBe(false);
    });

    it('keeps failing closed when the sealed-purge names a different period (a validly-signed but non-matching seal is not evidence)', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const root = base.roots[0]!;

      const survivingRows = base.rows.slice(0, 3);
      const survivingProofs = base.proofs.filter((p) => p.rowId !== 'row-3');
      const manifestJson = reSignManifestV1({
        orgId: originalManifest.orgId,
        rowCount: survivingRows.length,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1'] as string,
        keyVersion: 1,
        privateKey,
      });
      const seal = signSeal({
        id: 'seal-wrong-period',
        orgId: originalManifest.orgId,
        periodStart: '2020-01-01T00:00:00.000Z', // does not match root-1
        periodEnd: '2020-01-02T00:00:00.000Z',
        rowCount: '1',
        rootHash: root.rootHash,
        deletedAt: '2026-05-01T01:15:00.000Z',
        approvalId: 'approval-42',
        deletedBy: 'user-1',
        keyVersion: 1,
        privateKey,
      });
      const zip = packBundleWithSeals(
        manifestJson,
        survivingRows,
        base.roots,
        survivingProofs,
        publicKeys,
        [seal],
      );
      const report = await verifyBundle(zip, { noRekor: true });

      expect(report.rootCoverage.ok).toBe(false);
      expect(report.rootCoverage.reason).toContain('root-1');
      expect(report.bundle.sealedPurgesVerified).toBe(1); // signature IS valid...
      expect(report.rootCoverage.sealExemptions).toBeUndefined(); // ...just doesn't match
      expect(report.ok).toBe(false);
    });

    it('keeps failing closed when the sealed-purge is signed under a REVOKED key', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const { privateKey: revokedPriv, publicKey: revokedPub } =
        keypairFromSeed(Buffer.alloc(32, 9));
      const revokedPubB64 = Buffer.from(revokedPub).toString('base64');
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const root = base.roots[0]!;

      const survivingRows = base.rows.slice(0, 3);
      const survivingProofs = base.proofs.filter((p) => p.rowId !== 'row-3');
      const manifestJson = reSignManifestV1({
        orgId: originalManifest.orgId,
        rowCount: survivingRows.length,
        rootCount: base.roots.length,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1'] as string,
        keyVersion: 1,
        privateKey,
      });
      const seal = signSeal({
        id: 'seal-revoked',
        orgId: originalManifest.orgId,
        periodStart: root.periodStart,
        periodEnd: root.periodEnd,
        rowCount: '1',
        rootHash: root.rootHash,
        deletedAt: '2026-05-01T01:15:00.000Z',
        approvalId: 'approval-42',
        deletedBy: 'user-1',
        keyVersion: 2,
        privateKey: revokedPriv,
      });
      const publicKeysWithRevoked = {
        ...publicKeys,
        '2': {
          publicKey: revokedPubB64,
          status: 'REVOKED',
          revokedAt: '2026-01-01T00:00:00.000Z',
        },
      };
      const zip = packBundleWithSeals(
        manifestJson,
        survivingRows,
        base.roots,
        survivingProofs,
        publicKeysWithRevoked,
        [seal],
      );
      const report = await verifyBundle(zip, { noRekor: true });

      expect(report.rootCoverage.ok).toBe(false);
      expect(report.bundle.sealedPurgesVerified).toBe(0);
      expect(report.ok).toBe(false);
    });

    // AV-0008 — a correctly signed bundle that carries no evidence at all
    // must not read as VALID: every evidence component is `not_present`
    // and the top level is `incomplete` (CLI exit 3), never `valid`.
    it('AV-0008: a zero-row, zero-root bundle is incomplete, never valid; evidence components are not_present', async () => {
      const base = buildFixtureBundle();
      const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as { orgId: string; from: string; to: string };
      const publicKeys = JSON.parse(
        entries.get('public-keys.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const manifestJson = reSignManifestV1({
        orgId: originalManifest.orgId,
        rowCount: 0,
        rootCount: 0,
        from: originalManifest.from,
        to: originalManifest.to,
        publicKeyB64: publicKeys['1'] as string,
        keyVersion: 1,
        privateKey,
      });
      const report = await verifyBundle(
        packBundleWithSeals(manifestJson, [], [], [], publicKeys, []),
        { noRekor: true },
      );

      expect(report.status).toBe('incomplete');
      expect(report.ok).toBe(false);
      for (const c of [
        report.rowSignatures,
        report.chain,
        report.rootSignatures,
        report.inclusionProofs,
        report.rekor,
        report.rootCoverage,
      ]) {
        expect(c.status).toBe('not_present');
        expect(c.ok).toBe(false); // ok is DERIVED: status === 'valid'
        expect(c.checked).toBe(0);
      }
      // Mandatory components are still decided, never not_present.
      expect(report.manifest.status).toBe('valid');
      expect(report.completeness.status).toBe('valid');
      expect(report.keyBinding.status).toBe('valid');
    });
  });

  /**
   * AV-2754 (BE-2979 AV-1) — a sealed purge deletes a contiguous run of chain
   * leaves; the successor S keeps `prevRowHash` = link(last purged leaf). A
   * seal bridges link(P) → S.prevRowHash only when BOTH its 6-field signature
   * (`retention-seal`) and its link signature (`retention-seal-link`, over the
   * `praesidia.retention-seal-link.v1` envelope) verify. Fixtures use the
   * throwaway seed keys of this file; envelopes and the format-2 prefix are
   * written out literally here, never built with the verifier's helpers.
   */
  describe('AV-2754 (BE-2979 AV-1) — a doubly-signed sealed purge bridges the chain gap', () => {
    const ORG = '00000000-0000-0000-0000-000000000001';
    const BASE = Date.UTC(2026, 4, 1);
    const at = (sec: number): string => new Date(BASE + sec * 1000).toISOString();
    const HOUR = 3600;
    /** Hour of each chained row: r0 H0, r1 H1, r2 + r3 H2, r4 H3, r5 H4. */
    const HOUR_OF = [0, 1, 2, 2, 3, 4];
    const KEY1 = keypairFromSeed(Buffer.alloc(32, 7));
    const KEY2 = keypairFromSeed(Buffer.alloc(32, 9));
    const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');
    const ndjson = (xs: unknown[]): Buffer =>
      gzipDeterministic(Buffer.from(xs.map((x) => JSON.stringify(x)).join('\n') + (xs.length > 0 ? '\n' : ''), 'utf8'));

    type Fmt = 1 | 2 | undefined;
    /** be's signed bytes: format 2 prepends the ADR-0004 prefix. */
    const sign = (format: Fmt, purpose: string, payload: Buffer, key: Uint8Array = KEY1.privateKey): string =>
      signEd25519(format === 2 ? Buffer.concat([Buffer.from(`praesidia:${purpose}:v2\n`, 'ascii'), payload]) : payload, key);
    const flip = (sig: string): string => {
      const b = Buffer.from(sig, 'base64');
      b[0] = (b[0]! + 1) % 256;
      return b.toString('base64');
    };

    interface LinkFields {
      organizationId: string;
      periodStart: string;
      periodEnd: string;
      rowCount: string;
      rootHash: string;
      chainLinkIn: string;
      chainLinkOut: string;
    }
    /** The v1 link envelope, written out independently of `retentionSealLinkMessage`. */
    const linkEnvelope = (f: LinkFields): Buffer =>
      canonicalJson({
        version: 'praesidia.retention-seal-link.v1',
        organizationId: f.organizationId,
        periodStart: f.periodStart,
        periodEnd: f.periodEnd,
        rowCount: f.rowCount,
        rootHash: f.rootHash,
        chainLinkIn: f.chainLinkIn,
        chainLinkOut: f.chainLinkOut,
      });

    interface SealOpts {
      id?: string;
      /** The purged hour the seal covers (its 6-field envelope names that hour's root). */
      hour: number;
      /** false = a legacy seal, no link fields. */
      links?: boolean;
      chainLinkIn?: string;
      chainLinkOut?: string;
      /** Links actually signed, when they differ from the wire values (tamper). */
      signedLinks?: { chainLinkIn: string; chainLinkOut: string };
      linkFormat?: Fmt;
      linkPurpose?: string;
      linkKeyVersion?: 1 | 2;
      /** Organization named inside the signed link envelope (the wire keeps ORG). */
      linkEnvelopeOrg?: string;
      unsigned?: boolean;
      tamperSeal?: boolean;
      tamperLink?: boolean;
      /** Hour the purge committed (`deletedAt`); default just after the last hour. */
      deletedHour?: number;
    }

    /**
     * Six chained rows (HOUR_OF), one Merkle root per hour, the rows of
     * `purgedHours` removed. `seals` receives link(i) and prev(i) of the full
     * chain. v7 signs every slot in format 2 with the cutover at `cutover`.
     * `range` [from, to) hours cuts one bundle of a set: rows, roots and
     * proofs of those hours, and the seals be exports for that range (period
     * overlaps it, or `deletedAt` falls inside it). `hourOf` replaces HOUR_OF
     * (an hour with no row has no root: a quiet window). `erasedHours` are
     * deleted outright, rows AND root, with no seal: no bundle shows they existed.
     */
    function build(o: {
      version?: 1 | 7;
      cutover?: string;
      purgedHours: number[];
      seals: (c: { link: (i: number) => string; prev: (i: number) => string }) => SealOpts[];
      /** Adds a validly signed row whose prevRowHash is link(row i). */
      forkAfter?: number;
      key2Status?: 'ACTIVE' | 'REVOKED';
      post?: (seals: Record<string, unknown>[]) => void;
      range?: [number, number];
      hourOf?: readonly number[];
      erasedHours?: number[];
    }): Buffer {
      const [fromHour, toHour] = o.range ?? [0, 5];
      const hourOf = o.hourOf ?? HOUR_OF;
      const gone = [...o.purgedHours, ...(o.erasedHours ?? [])];
      const inRange = (h: number): boolean => h >= fromHour && h < toHour;
      const v7 = o.version === 7;
      const fmt: Fmt = v7 ? 2 : undefined;
      const fmtField = (f: Fmt, key = 'signatureFormat') => (f === 2 ? { [key]: 2 } : {});
      const rows: Record<string, unknown>[] = [];
      const leaves: Buffer[] = [];
      const links: string[] = [];
      const prevs: string[] = [];
      const rowHour = new Map<unknown, number>();
      const addRow = (id: string, hour: number, minute: number, prevRowHash: string): string => {
        rowHour.set(id, hour);
        const signable = {
          organizationId: ORG, action: 'agent.created', actorId: null, actorType: 'user', resourceType: 'agent',
          resourceId: id, teamId: null, agentId: null, summary: null, details: null,
          createdAt: at(hour * HOUR + minute * 60),
        };
        const canonical = canonicalJson(signable);
        const signature = sign(fmt, 'audit-record', Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]));
        rows.push({
          id, ...signable, signature, keyVersion: 1, signedAt: at(hour * HOUR + minute * 60 + 1), prevRowHash,
          ...(v7 ? { signatureAlgorithm: 'Ed25519' } : {}), ...fmtField(fmt),
        });
        const leaf = Buffer.concat([canonical, Buffer.from(signature, 'base64')]);
        leaves.push(leaf);
        return sha256(leaf).toString('base64');
      };
      let prev = GENESIS_PREV_ROW_HASH;
      hourOf.forEach((hour, i) => {
        prevs.push(prev);
        prev = addRow(`row-${i}`, hour, i + 1, prev);
        links.push(prev);
      });
      if (o.forkAfter !== undefined) addRow('row-fork', hourOf[o.forkAfter]!, 30, links[o.forkAfter]!);

      const roots: Record<string, unknown>[] = [];
      const outOfRangeRoots: Record<string, unknown>[] = [];
      const proofs: unknown[] = [];
      for (let h = 0; h <= hourOf[hourOf.length - 1]!; h++) {
        const idx = hourOf.flatMap((hh, i) => (hh === h ? [i] : []));
        if (idx.length === 0 || o.erasedHours?.includes(h)) continue;
        const ls = idx.map((i) => new Uint8Array(leaves[i]!));
        const rootHash = Buffer.from(merkleBuild(ls).root).toString('base64');
        const env = { rootHash, periodStart: at(h * HOUR), periodEnd: at((h + 1) * HOUR), rowCount: idx.length };
        (inRange(h) ? roots : outOfRangeRoots).push({
          id: `root-h${h}`, organizationId: ORG, ...env, signature: sign(fmt, 'merkle-root', canonicalJson(env)),
          keyVersion: 1, signedAt: at((h + 1) * HOUR + 5), anchoredAt: null, anchorReceipt: null,
          ...(v7 ? { signatureAlgorithm: 'Ed25519' } : {}), ...fmtField(fmt),
        });
        if (gone.includes(h) || !inRange(h)) continue;
        idx.forEach((rowIdx, j) => {
          const p = merkleProof(ls, j);
          proofs.push({ rowId: `row-${rowIdx}`, index: p.index, proof: p.siblings.map((s) => b64(s)), rootHash });
        });
      }
      const present = rows.filter((r) => inRange(rowHour.get(r.id)!) && (r.id === 'row-fork' || !gone.includes(rowHour.get(r.id)!)));
      const rootOfHour = (h: number) => [...roots, ...outOfRangeRoots].find((r) => r.id === `root-h${h}`)!;

      const sealOpts = o.seals({ link: (i) => links[i]!, prev: (i) => prevs[i]! });
      const seals = sealOpts.filter((s) => inRange(s.hour) || inRange(s.deletedHour ?? 5)).map((s) => {
        const idx = hourOf.flatMap((hh, i) => (hh === s.hour ? [i] : []));
        const env = {
          organizationId: ORG, periodStart: at(s.hour * HOUR), periodEnd: at((s.hour + 1) * HOUR),
          rowCount: String(idx.length), rootHash: rootOfHour(s.hour).rootHash as string, rekorReceipt: null,
        };
        const signature = sign(fmt, 'retention-seal', canonicalJson(env));
        const wire: Record<string, unknown> = {
          id: s.id ?? `seal-h${s.hour}`, ...env,
          ...(s.unsigned
            ? { signature: null, signingKeyVersion: null, signatureAlgorithm: null }
            : { signature: s.tamperSeal ? flip(signature) : signature, signingKeyVersion: 1, signatureAlgorithm: 'Ed25519', ...fmtField(fmt) }),
          deletedAt: at((s.deletedHour ?? 5) * HOUR + 60), deletedBy: 'user-1', approvalId: `approval-h${s.hour}`,
        };
        if (s.links !== false) {
          const chainLinkIn = s.chainLinkIn ?? prevs[idx[0]!]!;
          const chainLinkOut = s.chainLinkOut ?? links[idx[idx.length - 1]!]!;
          const linkFormat = s.linkFormat ?? fmt;
          const kv = s.linkKeyVersion ?? 1;
          const chainLinkSignature = sign(
            linkFormat,
            s.linkPurpose ?? 'retention-seal-link',
            linkEnvelope({ ...env, organizationId: s.linkEnvelopeOrg ?? ORG, ...(s.signedLinks ?? { chainLinkIn, chainLinkOut }) }),
            kv === 2 ? KEY2.privateKey : KEY1.privateKey,
          );
          Object.assign(wire, {
            chainLinkIn, chainLinkOut,
            chainLinkSignature: s.tamperLink ? flip(chainLinkSignature) : chainLinkSignature,
            chainLinkSigningKeyVersion: kv, chainLinkSignatureAlgorithm: 'Ed25519',
            ...fmtField(linkFormat, 'chainLinkSignatureFormat'),
          });
        }
        return wire;
      });
      o.post?.(seals);

      const key2 = o.key2Status ? { publicKey: b64(KEY2.publicKey), status: o.key2Status, revokedAt: o.key2Status === 'REVOKED' ? at(-HOUR) : null } : null;
      const publicKeys: Record<string, unknown> = {
        1: v7 ? { publicKey: b64(KEY1.publicKey), status: 'ACTIVE', revokedAt: null } : b64(KEY1.publicKey),
        ...(key2 ? { 2: key2 } : {}),
      };
      const keyVersions = [
        { keyVersion: 1, publicKey: b64(KEY1.publicKey), ...(v7 ? { status: 'ACTIVE', revokedAt: null } : {}) },
        ...(key2 ? [{ keyVersion: 2, ...(v7 ? key2 : { publicKey: key2.publicKey }) }] : []),
      ];
      const manifestSans: Record<string, unknown> = {
        version: v7 ? 7 : 1, orgId: ORG, from: at(fromHour * HOUR), to: at(toHour * HOUR), rowCount: present.length, rootCount: roots.length,
        keyVersions, generatedAt: at(5 * HOUR + 30), signatureAlgorithm: 'Ed25519',
      };
      if (v7) {
        Object.assign(manifestSans, {
          chainSeqCeiling: rows.length, chainSeqSnapshotAt: at(5 * HOUR + 30), integrityCheckpointCount: 0,
          actionEventCount: 0, captureScopeDigest: sha256(Buffer.from('scope')).toString('hex'),
          evidenceGradeSummary: { A: 0, B: 0, C: 0, D: 0, enforcementMode: 'observe' },
          evidencePrivacy: { modes: [{ mode: 'FULL', effectiveFrom: at(fromHour * HOUR) }], schemaVersion: 1 },
          signatureFormat: 2, signatureFormatCutoverAt: o.cutover ?? at(0),
        });
      }
      const manifest = { ...manifestSans, signature: sign(fmt, 'bundle-manifest', canonicalJson(manifestSans)), signatureKeyVersion: 1 };
      return writeZip([
        { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest), 'utf8') },
        { name: 'rows.ndjson.gz', data: ndjson(present) },
        { name: 'roots.ndjson.gz', data: ndjson(roots) },
        { name: 'proofs.ndjson.gz', data: ndjson(proofs) },
        { name: 'public-keys.json', data: Buffer.from(JSON.stringify(publicKeys), 'utf8') },
        ...(v7
          ? [
              { name: 'integrity-checkpoints.ndjson.gz', data: ndjson([]) },
              { name: 'action-events.ndjson.gz', data: ndjson([]) },
            ]
          : []),
        { name: 'sealed-purges.ndjson.gz', data: ndjson(seals) },
        { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
      ]);
    }

    const verify = (zip: Buffer): Promise<VerifyReport> => verifyBundle(zip, { noRekor: true });
    /** Hour 2 (row-2, row-3) purged and NOT bridged: exactly today's chain verdict. */
    const GAP = {
      ok: false, checked: 4, failed: 2, firstFailure: 'row-4',
      reason: 'prev_row_hash does not chain to previous row',
    };
    async function expectGap(zip: Buffer, sealsVerified: number): Promise<void> {
      const r = await verify(zip);
      expect(r.bundle.sealedPurgesVerified).toBe(sealsVerified);
      expect(r.chain).toMatchObject(GAP);
      expect(r.ok).toBe(false);
    }

    it('V1: the link envelope v1 equals the golden vector byte-for-byte (BE-2979 BE-1 asserts the same string)', () => {
      const inputs: LinkFields = {
        organizationId: '00000000-0000-0000-0000-000000000001',
        periodStart: '2026-05-01T02:00:00.000Z',
        periodEnd: '2026-05-01T03:00:00.000Z',
        rowCount: '2',
        rootHash: Buffer.alloc(32, 0x33).toString('base64'),
        chainLinkIn: Buffer.alloc(32, 0x11).toString('base64'),
        chainLinkOut: Buffer.alloc(32, 0xfb).toString('base64'),
      };
      const GOLDEN =
        '{"chainLinkIn":"ERERERERERERERERERERERERERERERERERERERERERE=",' +
        '"chainLinkOut":"+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=",' +
        '"organizationId":"00000000-0000-0000-0000-000000000001",' +
        '"periodEnd":"2026-05-01T03:00:00.000Z",' +
        '"periodStart":"2026-05-01T02:00:00.000Z",' +
        '"rootHash":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",' +
        '"rowCount":"2",' +
        '"version":"praesidia.retention-seal-link.v1"}';
      expect(retentionSealLinkMessage(inputs).toString('utf8')).toBe(GOLDEN);
      // The fixtures below sign exactly these bytes.
      expect(linkEnvelope(inputs).toString('utf8')).toBe(GOLDEN);
      expect(cryptoPrimitives.tenantSignedBytes(2, 'retention-seal-link', Buffer.from(GOLDEN, 'utf8')).toString('utf8'))
        .toBe(`praesidia:retention-seal-link:v2\n${GOLDEN}`);
    });

    it('V2: a doubly-signed seal bridges link(P) to S.prevRowHash; the bundle verifies', async () => {
      const r = await verify(build({ purgedHours: [2], seals: () => [{ hour: 2 }] }));
      expect(r.bundle.sealedPurgesVerified).toBe(1);
      expect(r.chain).toMatchObject({ ok: true, checked: 3, failed: 0 });
      expect(r.rootCoverage.ok).toBe(true);
      expect(r.ok).toBe(true);
    });

    it('V3: adjacent seals bridge two purged hours, in either file order', async () => {
      for (const order of [[2, 3], [3, 2]]) {
        const r = await verify(build({ purgedHours: [2, 3], seals: () => order.map((hour) => ({ hour })) }));
        expect(r.bundle.sealedPurgesVerified).toBe(2);
        expect(r.chain).toMatchObject({ ok: true, checked: 2, failed: 0 });
        expect(r.ok).toBe(true);
      }
    });

    it('V3b: a verified bridge leaving the bundle tail (a purge after the range) leaves a passing chain passing', async () => {
      const r = await verify(build({
        purgedHours: [],
        seals: ({ link }) => [{ hour: 2, chainLinkIn: link(5), chainLinkOut: Buffer.alloc(32, 0x44).toString('base64') }],
      }));
      expect(r.bundle.sealedPurgesVerified).toBe(1);
      expect(r.chain).toMatchObject({ ok: true, checked: 5, failed: 0 });
    });

    it('V4: a tampered link (flipped signature, or links edited after signing) does not bridge', async () => {
      await expectGap(build({ purgedHours: [2], seals: () => [{ hour: 2, tamperLink: true }] }), 1);
      await expectGap(build({
        purgedHours: [2],
        seals: ({ link }) => [{ hour: 2, signedLinks: { chainLinkIn: link(0), chainLinkOut: link(3) } }],
      }), 1);
    });

    it('V5: a flipped 6-field seal signature does not bridge, even with a valid link signature', async () => {
      await expectGap(build({ purgedHours: [2], seals: () => [{ hour: 2, tamperSeal: true }] }), 0);
    });

    it('V6: a signed chainLinkIn other than link(P) does not bridge', async () => {
      // link(row-2) is interior to the purged run, not the predecessor's link.
      await expectGap(build({ purgedHours: [2], seals: ({ link }) => [{ hour: 2, chainLinkIn: link(2) }] }), 1);
    });

    it('V7: a row S\' directly after P plus S bridged after P is a fork', async () => {
      const r = await verify(build({ purgedHours: [2], forkAfter: 1, seals: () => [{ hour: 2 }] }));
      expect(r.bundle.sealedPurgesVerified).toBe(1);
      expect(r.chain).toMatchObject({
        ok: false,
        firstFailure: 'row-fork',
        reason: 'chain fork: row row-fork and a sealed-purge bridge both succeed the same link',
      });
      expect(r.ok).toBe(false);
    });

    it('V8: a legacy seal without link fields gives exactly the pre-AV-2754 result', async () => {
      const r = await verify(build({ purgedHours: [2], seals: () => [{ hour: 2, links: false }] }));
      expect(r.bundle.sealedPurgesVerified).toBe(1);
      expect(r.rootCoverage.ok).toBe(true);
      expect(r.chain).toMatchObject(GAP);
      expect(r.ok).toBe(false);
    });

    it('V9: a format-2 link signature under another purpose, or relabelled as format 1, does not bridge', async () => {
      const control = await verify(build({ version: 7, purgedHours: [2], seals: () => [{ hour: 2 }] }));
      expect(control.bundle.sealedPurgesVerified).toBe(1);
      expect(control.chain).toMatchObject({ ok: true, checked: 3 });
      await expectGap(build({ version: 7, purgedHours: [2], seals: () => [{ hour: 2, linkPurpose: 'retention-seal' }] }), 1);
      // Signed with the format-2 prefix, wire claims format 1 (no cutover on a v1 manifest).
      await expectGap(build({
        purgedHours: [2],
        seals: () => [{ hour: 2, linkFormat: 2 }],
        post: (s) => { delete s[0]!.chainLinkSignatureFormat; },
      }), 1);
    });

    it('V10: a format-1 link signature at or after the cutover (periodEnd) does not bridge', async () => {
      const periodEnd = at(3 * HOUR);
      await expectGap(build({ version: 7, cutover: periodEnd, purgedHours: [2], seals: () => [{ hour: 2, linkFormat: 1 }] }), 1);
      const before = await verify(build({
        version: 7, cutover: at(3 * HOUR + 1), purgedHours: [2], seals: () => [{ hour: 2, linkFormat: 1 }],
      }));
      expect(before.chain).toMatchObject({ ok: true, checked: 3 });
    });

    it('V11: a partial or malformed link field set is an invalid entry', async () => {
      const mutations: Array<[string, (s: Record<string, unknown>) => void]> = [
        ...['chainLinkIn', 'chainLinkOut', 'chainLinkSignature', 'chainLinkSigningKeyVersion', 'chainLinkSignatureAlgorithm']
          .map((k): [string, (s: Record<string, unknown>) => void] => [`missing ${k}`, (s) => { delete s[k]; }]),
        ['31-byte chainLinkIn', (s) => { s.chainLinkIn = Buffer.alloc(31, 1).toString('base64'); }],
        ['base64url chainLinkOut', (s) => { s.chainLinkOut = String(s.chainLinkOut).replace(/\+/g, '-').replace(/\//g, '_'); }],
        ['null chainLinkIn', (s) => { s.chainLinkIn = null; }],
        ['non-base64 signature', (s) => { s.chainLinkSignature = 'not base64!'; }],
        ['key version 0', (s) => { s.chainLinkSigningKeyVersion = 0; }],
        ['key version as string', (s) => { s.chainLinkSigningKeyVersion = '1'; }],
        ['unknown algorithm', (s) => { s.chainLinkSignatureAlgorithm = 'RSA_PKCS1_SHA256'; }],
        ['format 3', (s) => { s.chainLinkSignatureFormat = 3; }],
        ['format as string', (s) => { s.chainLinkSignatureFormat = '2'; }],
      ];
      for (const [label, mutate] of mutations) {
        await expect(
          verify(build({ purgedHours: [2], seals: () => [{ hour: 2 }], post: (s) => mutate(s[0]!) })),
          label,
        ).rejects.toThrow(/sealed-purges\.ndjson\.gz has an invalid\/duplicate entry: seal-h2/);
      }
      // A lone link field on an otherwise legacy seal is a partial set too.
      await expect(verify(build({
        purgedHours: [2], seals: () => [{ hour: 2, links: false }], post: (s) => { s[0]!.chainLinkSignatureFormat = 2; },
      }))).rejects.toThrow(/invalid\/duplicate entry: seal-h2/);
      // An explicit format 1 is well-formed.
      const explicit1 = await verify(build({
        purgedHours: [2], seals: () => [{ hour: 2 }], post: (s) => { s[0]!.chainLinkSignatureFormat = 1; },
      }));
      expect(explicit1.chain.ok).toBe(true);
    });

    it('V12: a link signed under a REVOKED or absent key version does not bridge', async () => {
      const active = await verify(build({ purgedHours: [2], key2Status: 'ACTIVE', seals: () => [{ hour: 2, linkKeyVersion: 2 }] }));
      expect(active.chain).toMatchObject({ ok: true, checked: 3 });
      const revoked = await verify(build({ purgedHours: [2], key2Status: 'REVOKED', seals: () => [{ hour: 2, linkKeyVersion: 2 }] }));
      expect(revoked.bundle.sealedPurgesVerified).toBe(1);
      expect(revoked.chain).toMatchObject(GAP);
      // Key version 2 is not in the bundle's key set at all.
      const absent = await verify(build({ purgedHours: [2], seals: () => [{ hour: 2, linkKeyVersion: 2 }] }));
      expect(absent.bundle.sealedPurgesVerified).toBe(1);
      expect(absent.chain).toMatchObject(GAP);
    });

    it('V13: a cycle of signed bridges never bridges the gap and fails closed off the tail', async () => {
      const x = Buffer.alloc(32, 0x55).toString('base64');
      await expectGap(build({
        purgedHours: [2],
        seals: ({ link }) => [{ hour: 2, chainLinkOut: x }, { id: 'seal-back', hour: 3, chainLinkIn: x, chainLinkOut: link(1) }],
      }), 2);
      const tail = await verify(build({
        purgedHours: [2],
        seals: ({ link }) => [
          { hour: 2 },
          { id: 'seal-out', hour: 3, chainLinkIn: link(5), chainLinkOut: x },
          { id: 'seal-back', hour: 4, chainLinkIn: x, chainLinkOut: link(5) },
        ],
      }));
      expect(tail.bundle.sealedPurgesVerified).toBe(3);
      expect(tail.chain.ok).toBe(false);
      expect(tail.chain.reason).toMatch(/cycle/);
    });

    it('V14: a link envelope signed for another organization does not bridge', async () => {
      await expectGap(build({
        purgedHours: [2], seals: () => [{ hour: 2, linkEnvelopeOrg: '00000000-0000-0000-0000-000000000002' }],
      }), 1);
    });

    it('V15: link fields on an unsigned (legacy backfilled) seal do not bridge', async () => {
      await expectGap(build({ purgedHours: [2], seals: () => [{ hour: 2, unsigned: true }] }), 0);
    });

    it('V16: two verified seals claiming the same chainLinkIn or chainLinkOut drop both (fail closed)', async () => {
      await expectGap(build({ purgedHours: [2], seals: () => [{ hour: 2 }, { id: 'seal-h2-dup', hour: 2 }] }), 2);
      await expectGap(build({
        purgedHours: [2],
        seals: ({ link }) => [{ hour: 2 }, { id: 'seal-same-out', hour: 3, chainLinkIn: Buffer.alloc(32, 0x66).toString('base64'), chainLinkOut: link(3) }],
      }), 2);
    });

    type SetFinding = { kind: string; reason: string; leftIndex?: number; rightIndex?: number };
    type SetResult = { code: number | null; status: string; findings: SetFinding[] };
    /** The built CLI's `verify-set --json` over `zips`, written as bundle-<i>.zip in that order. */
    function verifySetOf(zips: Buffer[]): SetResult {
      const cliPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js');
      expect(fs.existsSync(cliPath), 'npm run build must run before npm test').toBe(true);
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-verify-set-'));
      try {
        const files = zips.map((zip, i) => {
          fs.writeFileSync(path.join(tmp, `bundle-${i}.zip`), zip);
          return path.join(tmp, `bundle-${i}.zip`);
        });
        const r = spawnSync(
          process.execPath,
          [cliPath, 'verify-set', ...files, '--no-rekor', '--allow-legacy-unattested', '--json'],
          { encoding: 'utf8' },
        );
        const out = JSON.parse(r.stdout) as Omit<SetResult, 'code'>;
        return { code: r.status, status: out.status, findings: out.findings };
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    }
    const CONTINUOUS: SetResult = { code: 0, status: 'continuous', findings: [] };
    /** Every bundle valid, one boundary not stitched: exit 4, one boundary finding. */
    function expectBoundaryBreak(r: SetResult, reason: RegExp = /adjacent-but-forged boundary/): void {
      expect(r).toMatchObject({ code: 4, status: 'discontinuous' });
      expect(r.findings).toHaveLength(1);
      expect(r.findings[0]!.kind).toBe('boundary_chain_mismatch');
      expect(r.findings[0]!.reason).toMatch(reason);
    }

    /**
     * AV-2755 — `verify-set` stitches two adjacent bundles with the same
     * bridges, so a sealed purge on the boundary is not a forged boundary.
     * `split` is the boundary hour: left [0, split), right [split, 5). With
     * hour 2 purged, split 3 exports its seal in the left bundle only and
     * split 2 in the right bundle only. Driven through the built CLI.
     */
    describe('AV-2755 — verify-set bridges a sealed-purge gap that falls on a bundle boundary', () => {
      function verifySet(split: number, o: Omit<Parameters<typeof build>[0], 'range'>): SetResult {
        return verifySetOf([build({ ...o, range: [0, split] }), build({ ...o, range: [split, 5] })]);
      }
      const x = Buffer.alloc(32, 0x77).toString('base64');

      it('B1: a doubly-signed seal on the boundary stitches the set, exported with either bundle', () => {
        for (const split of [3, 2]) {
          expect(verifySet(split, { purgedHours: [2], seals: () => [{ hour: 2 }] }), `split ${split}`).toEqual(CONTINUOUS);
        }
      });

      it('B2: adjacent seals, one in each bundle, stitch the boundary together', () => {
        expect(verifySet(3, { purgedHours: [2, 3], seals: () => [{ hour: 2 }, { hour: 3 }] })).toEqual(CONTINUOUS);
      });

      it('B3: one seal exported in both bundles (purge committed in the right range) counts once', () => {
        expect(verifySet(3, { purgedHours: [2], seals: () => [{ hour: 2, deletedHour: 3 }] })).toEqual(CONTINUOUS);
      });

      it('C1: the boundary gap with no seal, or with a legacy seal without links, fails', () => {
        for (const split of [3, 2]) {
          // No seal: the purged hour's root is unexplained, so its bundle is itself invalid.
          expect(verifySet(split, { purgedHours: [2], seals: () => [] }), `split ${split}`)
            .toMatchObject({ code: 1, status: 'bundle_invalid' });
          expectBoundaryBreak(verifySet(split, { purgedHours: [2], seals: () => [{ hour: 2, links: false }] }));
        }
      });

      it('C2: a seal whose link signature or 6-field signature is bad does not stitch the boundary', () => {
        for (const split of [3, 2]) {
          expectBoundaryBreak(verifySet(split, { purgedHours: [2], seals: () => [{ hour: 2, tamperLink: true }] }));
          // An unverified seal explains nothing: the purged hour's root fails its bundle outright.
          expect(verifySet(split, { purgedHours: [2], seals: () => [{ hour: 2, tamperSeal: true }] }), `split ${split}`)
            .toMatchObject({ code: 1, status: 'bundle_invalid' });
        }
      });

      it('C3: a seal whose chainLinkIn or chainLinkOut does not match the neighbouring rows does not stitch the boundary', () => {
        for (const split of [3, 2]) {
          expectBoundaryBreak(verifySet(split, { purgedHours: [2], seals: ({ link }) => [{ hour: 2, chainLinkIn: link(2) }] }));
          expectBoundaryBreak(verifySet(split, { purgedHours: [2], seals: () => [{ hour: 2, chainLinkOut: x }] }));
        }
      });

      it('C4: a bridge beside the right bundle\'s directly chained head is a fork', () => {
        // Nothing purged: row-2 (right) declares link(1); the left bundle's verified seal also bridges link(1) away.
        expectBoundaryBreak(
          verifySet(2, { purgedHours: [], seals: ({ link }) => [{ hour: 1, chainLinkIn: link(1), chainLinkOut: x }] }),
          /chain fork/,
        );
      });

      it('C5: bridges across the boundary that lead back to the left tail are a cycle', () => {
        expectBoundaryBreak(
          verifySet(3, {
            purgedHours: [2],
            seals: ({ link }) => [{ hour: 2, chainLinkOut: x }, { id: 'seal-back', hour: 3, chainLinkIn: x, chainLinkOut: link(1) }],
          }),
          /chain cycle/,
        );
      });

      it('C6: two seals with the same links, one in each bundle, bridge nothing', () => {
        expectBoundaryBreak(verifySet(3, {
          purgedHours: [2],
          seals: ({ link }) => [{ hour: 2 }, { id: 'seal-dup', hour: 3, chainLinkIn: link(1), chainLinkOut: link(3) }],
        }));
      });
    });

    /**
     * AV-2756 — an empty bundle (no rows) has no chain link of its own, and
     * it used to switch the chain checks off around it: rows deleted across
     * an empty bundle, or under a leading one, went unreported. It is now
     * transparent: each bundle with rows is stitched to the previous bundle
     * with rows through the bridges of every bundle in between, and the
     * genesis check applies to the earliest bundle with rows. A zero-row,
     * zero-root bundle is itself `incomplete` (README), so a set holding a
     * quiet window is `bundle_incomplete` (exit 3) when nothing else is wrong.
     */
    describe('AV-2756 — verify-set checks chain continuity across empty bundles', () => {
      /** One bundle per window [hours[i], hours[i + 1]), written as bundle-<i>.zip. */
      const setOf = (hours: number[], o: Omit<Parameters<typeof build>[0], 'range'>): SetResult =>
        verifySetOf(hours.slice(1).map((to, i) => build({ ...o, range: [hours[i]!, to] })));
      const QUIET: SetResult = { code: 3, status: 'bundle_incomplete', findings: [] };
      const ACROSS_1 = /bundle-0\.zip's newest-row hash-chain link does not equal \S*bundle-2\.zip's declared chain-head anchor \(across empty bundle\(s\) \S*bundle-1\.zip\)/;

      it('E1: rows deleted without a seal under an empty middle bundle break the boundary between its neighbours', () => {
        // Hour 2 erased (rows and root): bundle-1 [2, 3) is empty, bundle-2 starts at row-4.
        const r = setOf([0, 2, 3, 5], { purgedHours: [], erasedHours: [2], seals: () => [] });
        expectBoundaryBreak(r, ACROSS_1);
        expect(r.findings[0]).toMatchObject({ leftIndex: 0, rightIndex: 2 });
      });

      it('E2: a purge under an empty middle bundle whose seal binds no verified link breaks the boundary', () => {
        for (const seal of [{ hour: 2, links: false }, { hour: 2, tamperLink: true }]) {
          expectBoundaryBreak(setOf([0, 2, 3, 5], { purgedHours: [2], seals: () => [seal] }), ACROSS_1);
        }
      });

      it('E3: with no gap, an empty middle bundle adds no finding', () => {
        // Hour 2 is a quiet window: nothing was ever written in it.
        expect(setOf([0, 2, 3, 6], { hourOf: [0, 1, 3, 3, 4, 5], purgedHours: [], seals: () => [] })).toEqual(QUIET);
      });

      it('E4: a doubly-signed sealed purge that empties the middle bundle bridges its neighbours', () => {
        const sealed = { purgedHours: [2], seals: () => [{ hour: 2 }] };
        expect(setOf([0, 2, 3, 5], sealed)).toEqual(CONTINUOUS);
        // Committed in bundle-2's window: exported by bundle-1 and bundle-2, counted once.
        expect(setOf([0, 2, 3, 5], { ...sealed, seals: () => [{ hour: 2, deletedHour: 3 }] })).toEqual(CONTINUOUS);
        // A bad 6-field signature explains nothing: the empty bundle's root fails it outright.
        expect(setOf([0, 2, 3, 5], { ...sealed, seals: () => [{ hour: 2, tamperSeal: true }] }))
          .toMatchObject({ code: 1, status: 'bundle_invalid' });
      });

      it('E5: several consecutive empty bundles behave as one', () => {
        const erased = setOf([0, 2, 3, 4, 5], { purgedHours: [], erasedHours: [2, 3], seals: () => [] });
        expectBoundaryBreak(erased, /\(across empty bundle\(s\) \S*bundle-1\.zip, \S*bundle-2\.zip\)/);
        expect(erased.findings[0]).toMatchObject({ leftIndex: 0, rightIndex: 3 });
        expect(setOf([0, 2, 3, 4, 7], { hourOf: [0, 1, 4, 4, 5, 6], purgedHours: [], seals: () => [] })).toEqual(QUIET);
        // One bridge exported by each empty bundle: link(1) -> link(3) -> link(4).
        expect(setOf([0, 2, 3, 4, 5], { purgedHours: [2, 3], seals: () => [{ hour: 2 }, { hour: 3 }] })).toEqual(CONTINUOUS);
      });

      it('E6: the genesis check applies to the earliest bundle with rows, after leading empty bundles', () => {
        // Hours 0-1 erased under an empty leading bundle: the history's head is gone.
        const erased = setOf([0, 2, 5], { purgedHours: [], erasedHours: [0, 1], seals: () => [] });
        expect(erased).toMatchObject({ code: 4, status: 'discontinuous' });
        expect(erased.findings).toEqual([{
          kind: 'chain_head_not_genesis',
          rightIndex: 1,
          reason: expect.stringMatching(/^earliest bundle with rows in this set \(\S*bundle-1\.zip, after empty bundle\(s\) \S*bundle-0\.zip\) is not genesis-rooted/),
        }]);
        // A quiet window before the history starts adds no finding.
        expect(setOf([-1, 0, 3, 5], { purgedHours: [], seals: () => [] })).toEqual(QUIET);
        // Hour 0 purged under a legacy seal (no links): the same verdict whether or not an empty bundle
        // holds the purged window. A doubly-signed linked seal bridges the genesis check (AV-2758).
        for (const [hours, firstWithRows] of [[[0, 1, 5], 1], [[0, 3, 5], 0]] as const) {
          const r = setOf([...hours], { purgedHours: [0], seals: () => [{ hour: 0, links: false }] });
          expect(r, `windows ${hours.join(',')}`).toMatchObject({ code: 4, status: 'discontinuous' });
          expect(r.findings.map((f) => [f.kind, f.rightIndex])).toEqual([['chain_head_not_genesis', firstWithRows]]);
        }
      });

      it('E7: trailing empty bundles add no finding', () => {
        expect(setOf([0, 3, 5, 6], { purgedHours: [], seals: () => [] })).toEqual(QUIET);
        expect(setOf([0, 3, 4, 5], { purgedHours: [4], seals: () => [{ hour: 4 }] })).toEqual(CONTINUOUS);
      });
    });

    /**
     * AV-2758 — the genesis check (AUDIT-03) follows sealed-purge bridges by
     * verifyChain's rules: the earliest bundle with rows is genesis-rooted
     * when its head is GENESIS_PREV_ROW_HASH or is reached from it through
     * seals, exported by that bundle or an empty bundle before it, whose
     * seal and link signatures both verify. A purge of the oldest hours is
     * then not a missing head.
     */
    describe('AV-2758 — the genesis check follows doubly-signed sealed-purge bridges', () => {
      const setOf = (hours: number[], o: Omit<Parameters<typeof build>[0], 'range'>): SetResult =>
        verifySetOf(hours.slice(1).map((to, i) => build({ ...o, range: [hours[i]!, to] })));
      /** Windows, and the earliest bundle with rows: the seal is exported by it, or by an empty bundle before it. */
      const PLACEMENTS = [[[0, 3, 5], 0], [[0, 1, 5], 1]] as const;
      const x = Buffer.alloc(32, 0x66).toString('base64');
      function expectNotGenesis(r: SetResult, firstWithRows: number, reason: RegExp): void {
        expect(r).toMatchObject({ code: 4, status: 'discontinuous' });
        expect(r.findings).toHaveLength(1);
        expect(r.findings[0]).toMatchObject({ kind: 'chain_head_not_genesis', rightIndex: firstWithRows });
        expect(r.findings[0]!.reason).toMatch(reason);
      }

      it('G1: the oldest hour purged under a doubly-signed seal is genesis-rooted, wherever the seal is exported', () => {
        for (const [hours] of PLACEMENTS) {
          expect(setOf([...hours], { purgedHours: [0], seals: () => [{ hour: 0 }] }), `windows ${hours.join(',')}`)
            .toEqual(CONTINUOUS);
          // Committed in the last bundle's window: exported there too, counted once.
          expect(setOf([...hours], { purgedHours: [0], seals: () => [{ hour: 0, deletedHour: 4 }] }), `windows ${hours.join(',')}`)
            .toEqual(CONTINUOUS);
        }
        // Format-2 signatures (manifest v7).
        expect(setOf([0, 3, 5], { version: 7, purgedHours: [0], seals: () => [{ hour: 0 }] })).toEqual(CONTINUOUS);
      });

      it('G2: the two oldest hours purged under adjacent seals, one per empty leading bundle or both in the first', () => {
        const two = { purgedHours: [0, 1], seals: () => [{ hour: 0 }, { hour: 1 }] };
        expect(setOf([0, 1, 2, 5], two)).toEqual(CONTINUOUS);
        expect(setOf([0, 3, 5], two)).toEqual(CONTINUOUS);
      });

      it('C1: a legacy seal, a bad link signature, a seal for another org or a chainLinkIn off genesis leaves the head non-genesis', () => {
        const controls: Array<[string, SealOpts]> = [
          ['legacy seal, no links', { hour: 0, links: false }],
          ['bad link signature', { hour: 0, tamperLink: true }],
          ['link envelope for another org', { hour: 0, linkEnvelopeOrg: '00000000-0000-0000-0000-000000000002' }],
          ['chainLinkIn is not the genesis link', { hour: 0, chainLinkIn: x }],
        ];
        for (const [hours, firstWithRows] of PLACEMENTS) {
          for (const [label, seal] of controls) {
            const r = setOf([...hours], { purgedHours: [0], seals: () => [seal] });
            expect(r, `${label}, windows ${hours.join(',')}`).toMatchObject({ code: 4 });
            expectNotGenesis(r, firstWithRows, /is not genesis-rooted — its chain head is an opaque anchor/);
          }
        }
      });

      it('C2: a seal whose own signature is bad explains nothing: the bundle holding the purged root is invalid', () => {
        for (const [hours] of PLACEMENTS) {
          expect(setOf([...hours], { purgedHours: [0], seals: () => [{ hour: 0, tamperSeal: true }] }), `windows ${hours.join(',')}`)
            .toMatchObject({ code: 1, status: 'bundle_invalid' });
        }
      });

      it('C3: only bundles up to the earliest bundle with rows count, so a later export of an old purge is no fork', () => {
        // A pre-purge archive still holds the genesis row; the later export carries the seal of hour 0's purge.
        expect(verifySetOf([
          build({ purgedHours: [], seals: () => [], range: [0, 3] }),
          build({ purgedHours: [0], seals: () => [{ hour: 0, deletedHour: 4 }], range: [3, 5] }),
        ])).toEqual(CONTINUOUS);
      });

      it('C4: a bridge out of the genesis link beside a genesis head is a fork', () => {
        // Nothing purged: row-0 declares genesis; the empty leading bundle's verified seal also bridges genesis away.
        const r = verifySetOf([
          build({ purgedHours: [], seals: () => [{ hour: 0, deletedHour: -1, chainLinkOut: x }], range: [-1, 0] }),
          build({ purgedHours: [], seals: () => [], range: [0, 5] }),
        ]);
        expectNotGenesis(r, 1, /is not genesis-rooted — chain fork/);
      });
    });

    /**
     * AV-2757 — documented limit. At a boundary, fork and cycle checks see
     * only the two end links (left tail, right head), not the rows inside
     * either bundle. A seal exported by one bundle whose links contradict
     * rows inside the other is therefore not reported. Every such vector
     * needs the tenant key to sign contradictory links, and a holder of that
     * key could sign a clean bridge instead. Indexing the rows' links would
     * also fail a legitimate set (A1): be exports a seal with every bundle
     * whose window holds its `deletedAt`, so a pre-purge archive meets the
     * seal of its own later purge, and `deletedAt` is unsigned, so it cannot
     * tell the two apart. These tests pin the current verdicts.
     */
    describe('AV-2757 — boundary fork/cycle checks see only the two end links (documented limit)', () => {
      const x = Buffer.alloc(32, 0x88).toString('base64');
      const pair = (o: Omit<Parameters<typeof build>[0], 'range'>): SetResult =>
        verifySetOf([build({ ...o, range: [0, 3] }), build({ ...o, range: [3, 5] })]);

      it('D1-D3: a seal link into the interior of the other bundle (fork or cycle) is not seen at the boundary', () => {
        const interior: Array<[string, Parameters<typeof build>[0]['seals']]> = [
          ['left seal forks off right-interior link(4)', ({ link }) => [{ hour: 1, chainLinkIn: link(4), chainLinkOut: x }]],
          ['right seal forks off left-interior link(0)', ({ link }) => [{ hour: 4, chainLinkIn: link(0), chainLinkOut: x }]],
          ['left seal from the right tail back to left-interior link(0)', ({ link }) => [{ hour: 1, chainLinkIn: link(5), chainLinkOut: link(0) }]],
        ];
        for (const [label, seals] of interior) {
          expect(pair({ purgedHours: [], seals }), label).toEqual(CONTINUOUS);
        }
      });

      it('A1: a pre-purge archive plus a later export carrying that purge\'s seal is continuous', () => {
        // The seal's chainLinkIn, link(1), is still declared by row-2 in the archive.
        expect(verifySetOf([
          build({ purgedHours: [], seals: () => [], range: [0, 3] }),
          build({ purgedHours: [2], seals: () => [{ hour: 2, deletedHour: 4 }], range: [3, 5] }),
        ])).toEqual(CONTINUOUS);
      });
    });
  });

  /**
   * PROD16 F10 (be-compliance) — `verifyChain` must not depend on the
   * bundle's on-disk row order. `bundle-exporter.service.ts` orders rows
   * by `(signedAt, id)` while the chain is actually built in `chainSeq`
   * order; two rows in the same org sharing a `signedAt` millisecond (the
   * expected shape of `PendingSignatureDrainService`'s same-transaction
   * signing bursts) can then be emitted in the opposite order from the
   * real chain. The fixed `verifyChain` reconstructs the true order from
   * the cryptographic links themselves, so file order is irrelevant.
   */
  describe('PROD16 F10 — chain verification does not depend on file order', () => {
    it('verifies a bundle whose rows.ndjson.gz lines are reversed relative to chain order', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      // Same signatures/links, just written to the wire in the opposite
      // order — simulating a same-millisecond tie landing on the "wrong"
      // side of the (signedAt, id) sort.
      const reorderedRows = [...base.rows].reverse();
      const rowsNdjson = Buffer.from(
        reorderedRows.map((r) => JSON.stringify(r)).join('\n') + '\n',
        'utf8',
      );
      const zip = writeZip([
        { name: 'manifest.json', data: entries.get('manifest.json')! },
        { name: 'rows.ndjson.gz', data: gzipDeterministic(rowsNdjson) },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        { name: 'public-keys.json', data: entries.get('public-keys.json')! },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
      const report = await verifyBundle(zip, { noRekor: true });
      // Before the fix, this reported a false chain break — file order
      // WAS the chain-order assumption.
      expect(report.chain.ok).toBe(true);
      expect(report.chain.failed).toBe(0);
      expect(report.chain.checked).toBe(3);
      expect(report.ok).toBe(true);
    });

    it('still fails closed on a genuine fork (two rows claim the same predecessor) regardless of file order', async () => {
      const { zip } = buildBundleWithTamper({
        postSignPrevRowHash: (rows) => {
          // row-3 now claims to be an immediate successor of row-1 (the
          // same predecessor row-2 already legitimately claims) — a
          // forged sibling, not a legitimate reordering.
          rows[3]!.prevRowHash = rows[2]!.prevRowHash;
        },
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(false);
      expect(report.chain.ok).toBe(false);
      expect(report.chain.reason).toContain('fork');
    });
  });

  /**
   * PROD16 F6 (be-compliance) — `ipAddress` is signed only for rows
   * produced at/after `be`'s `IP_ADDRESS_SIGNABLE_CUTOVER_AT` activation.
   * The verifier must include the key in the canonical preimage IFF the
   * wire row carries it, with no cutover-date knowledge of its own.
   */
  describe('PROD16 F6 — ipAddress signable field (exporter/verifier version skew)', () => {
    function buildIpAddressFixtureBundle(opts: {
      includeIpAddress?: boolean;
      ipAddress?: string | null;
      tamperIpAddressPostSign?: boolean;
    }): Buffer {
      const seed = Buffer.alloc(32, 9);
      const { publicKey, privateKey } = keypairFromSeed(seed);
      const keyVersion = 1;
      const orgId = '00000000-0000-0000-0000-000000000002';
      const createdAt = new Date(Date.UTC(2026, 6, 1, 0, 0, 0)).toISOString();

      const basePartial: Record<string, unknown> = {
        organizationId: orgId,
        action: 'agent.created',
        actorId: null,
        actorType: 'user',
        resourceType: 'agent',
        resourceId: 'agent-0',
        teamId: null,
        agentId: 'agent-0',
        summary: 'Created agent',
        details: null,
        createdAt,
      };
      if (opts.includeIpAddress) {
        basePartial.ipAddress = opts.ipAddress ?? null;
      }
      const canonical = canonicalJson(basePartial);
      const prevRowHash = GENESIS_PREV_ROW_HASH;
      const rowMessage = Buffer.concat([
        canonical,
        Buffer.from(prevRowHash, 'base64'),
      ]);
      const signatureBase64 = signEd25519(rowMessage, privateKey);

      const row: Record<string, unknown> = {
        id: 'row-0',
        ...basePartial,
        signature: signatureBase64,
        keyVersion,
        signedAt: createdAt,
        prevRowHash,
      };
      if (opts.tamperIpAddressPostSign) {
        // Mutate AFTER signing — the signature must no longer verify.
        row.ipAddress = '10.0.0.99';
      }

      const leaf = new Uint8Array(
        Buffer.concat([canonical, Buffer.from(signatureBase64, 'base64')]),
      );
      const tree = merkleBuild([leaf]);
      const rootHashB64 = Buffer.from(tree.root).toString('base64');
      const periodStart = createdAt;
      const periodEnd = new Date(
        Date.parse(createdAt) + 3600_000,
      ).toISOString();
      const rootMessage = canonicalJson({
        rootHash: rootHashB64,
        periodStart,
        periodEnd,
        rowCount: 1,
      });
      const rootSignature = signEd25519(rootMessage, privateKey);
      const rootSignedAt = new Date(Date.parse(periodEnd) + 5000).toISOString();
      const root = {
        id: 'root-0',
        organizationId: orgId,
        periodStart,
        periodEnd,
        rowCount: 1,
        rootHash: rootHashB64,
        signature: rootSignature,
        keyVersion,
        signedAt: rootSignedAt,
        anchoredAt: null,
        anchorReceipt: null,
      };
      const proof = merkleProof([leaf], 0);
      const proofEntry = {
        rowId: 'row-0',
        index: proof.index,
        proof: proof.siblings.map((s) => Buffer.from(s).toString('base64')),
        rootHash: rootHashB64,
      };

      const publicKeyB64 = Buffer.from(publicKey).toString('base64');
      const generatedAt = new Date(
        Date.parse(rootSignedAt) + 1000,
      ).toISOString();
      const manifestSans = {
        version: 1,
        orgId,
        from: periodStart,
        to: periodEnd,
        rowCount: 1,
        rootCount: 1,
        keyVersions: [{ keyVersion, publicKey: publicKeyB64 }],
        generatedAt,
        signatureAlgorithm: 'Ed25519' as const,
      };
      const manifestSignature = signEd25519(
        canonicalJson(manifestSans),
        privateKey,
      );
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: keyVersion,
      };

      const publicKeys = { [String(keyVersion)]: publicKeyB64 };
      return writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        {
          name: 'rows.ndjson.gz',
          data: gzipDeterministic(
            Buffer.from(JSON.stringify(row) + '\n', 'utf8'),
          ),
        },
        {
          name: 'roots.ndjson.gz',
          data: gzipDeterministic(
            Buffer.from(JSON.stringify(root) + '\n', 'utf8'),
          ),
        },
        {
          name: 'proofs.ndjson.gz',
          data: gzipDeterministic(
            Buffer.from(JSON.stringify(proofEntry) + '\n', 'utf8'),
          ),
        },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
      ]);
    }

    it('verifies a row signed with ipAddress present (post-cutover shape)', async () => {
      const zip = buildIpAddressFixtureBundle({
        includeIpAddress: true,
        ipAddress: '203.0.113.5',
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(true);
      // AV-0008 — single-row fixture: no inter-row link to assert (0 checked).
      expect(report.chain.status).toBe('not_present');
      expect(report.inclusionProofs.ok).toBe(true);
      expect(report.ok).toBe(true);
    });

    it('verifies a legacy row that never carries ipAddress (pre-cutover shape unaffected)', async () => {
      const zip = buildIpAddressFixtureBundle({ includeIpAddress: false });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(true);
      expect(report.ok).toBe(true);
    });

    it('rejects a row whose ipAddress is tampered after signing', async () => {
      const zip = buildIpAddressFixtureBundle({
        includeIpAddress: true,
        ipAddress: '203.0.113.5',
        tamperIpAddressPostSign: true,
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.ok).toBe(false);
    });
  });

  /**
   * SCAN-AV-01 (be-audit N1) — `detailsCommitment` REPLACES `summary`/
   * `details` on the signed row (not additive alongside them, unlike
   * `ipAddress`) for rows produced at/after be's own
   * `AUDIT_DETAILS_COMMITMENT_CUTOVER_AT` activation
   * (`be/src/config/audit-details-commitment-cutover.config.ts`). The
   * verifier must include the key in the canonical preimage IFF the wire
   * row carries it, with no cutover-date knowledge of its own — same
   * discipline as PROD16 F6's `ipAddress` immediately above.
   */
  describe('SCAN-AV-01 — detailsCommitment signable field (exporter/verifier version skew)', () => {
    /**
     * Ground truth captured by executing be-core's REAL, unmodified
     * `AuditCanonicalHelper.buildSignableRow` + `canonicalJson`
     * (`be/src/audit/audit-canonical.helper.ts`,
     * `be/src/common/security/utils/canonical-json.ts`) against a
     * representative post-cutover row — NOT re-derived from this package's
     * own `canonicalJson`. Signing over bytes this test computed with the
     * same helper under test would prove nothing about producer/consumer
     * agreement; this is the producer's actual output for:
     *   organizationId=00000000-0000-0000-0000-000000000002,
     *   action=agent.created, agentId=agent-0, createdAt=2026-07-01T00:00:00.000Z,
     *   detailsCommitment=k2j9F3q7ZC1lM8n0pQdR5sTuVwXyZaBcDeFgHiJkLm=
     * — captured once via a one-off script invoking be's plain (non-DI)
     * helper directly, pinned here byte-for-byte.
     */
    const BE_REAL_CANONICAL_UTF8 =
      '{"action":"agent.created","actorId":null,"actorType":"agent","agentId":"agent-0","createdAt":"2026-07-01T00:00:00.000Z","detailsCommitment":"k2j9F3q7ZC1lM8n0pQdR5sTuVwXyZaBcDeFgHiJkLm=","organizationId":"00000000-0000-0000-0000-000000000002","resourceId":null,"resourceType":"agent","teamId":null}';

    function buildDetailsCommitmentFixtureBundle(opts: {
      includeDetailsCommitment?: boolean;
      detailsCommitment?: string | null;
      tamperDetailsCommitmentPostSign?: boolean;
    }): Buffer {
      const seed = Buffer.alloc(32, 11);
      const { publicKey, privateKey } = keypairFromSeed(seed);
      const keyVersion = 1;
      const orgId = '00000000-0000-0000-0000-000000000002';
      const createdAt = '2026-07-01T00:00:00.000Z';

      let basePartial: Record<string, unknown>;
      let canonical: Buffer;
      if (opts.includeDetailsCommitment) {
        // Post-cutover shape: summary/details ABSENT, detailsCommitment
        // present. Sign over be's REAL canonical bytes captured above, not
        // bytes this package's own canonicalJson computes.
        basePartial = {
          organizationId: orgId,
          action: 'agent.created',
          actorId: null,
          actorType: 'agent',
          resourceType: 'agent',
          resourceId: null,
          teamId: null,
          agentId: 'agent-0',
          createdAt,
          detailsCommitment:
            opts.detailsCommitment ??
            'k2j9F3q7ZC1lM8n0pQdR5sTuVwXyZaBcDeFgHiJkLm=',
        };
        canonical = Buffer.from(BE_REAL_CANONICAL_UTF8, 'utf8');
      } else {
        // Legacy/pre-cutover shape (mirrors the PROD16 F6 ipAddress
        // fixture's own legacy base): summary/details present, no
        // detailsCommitment key at all.
        basePartial = {
          organizationId: orgId,
          action: 'agent.created',
          actorId: null,
          actorType: 'agent',
          resourceType: 'agent',
          resourceId: null,
          teamId: null,
          agentId: 'agent-0',
          summary: 'Created agent',
          details: null,
          createdAt,
        };
        canonical = canonicalJson(basePartial);
      }
      const prevRowHash = GENESIS_PREV_ROW_HASH;
      const rowMessage = Buffer.concat([
        canonical,
        Buffer.from(prevRowHash, 'base64'),
      ]);
      const signatureBase64 = signEd25519(rowMessage, privateKey);

      const row: Record<string, unknown> = {
        id: 'row-0',
        ...basePartial,
        signature: signatureBase64,
        keyVersion,
        signedAt: createdAt,
        prevRowHash,
      };
      if (opts.tamperDetailsCommitmentPostSign) {
        // Mutate AFTER signing — the signature must no longer verify.
        row.detailsCommitment = 'tampered-commitment-value-not-signed==';
      }

      const leaf = new Uint8Array(
        Buffer.concat([canonical, Buffer.from(signatureBase64, 'base64')]),
      );
      const tree = merkleBuild([leaf]);
      const rootHashB64 = Buffer.from(tree.root).toString('base64');
      const periodStart = createdAt;
      const periodEnd = new Date(
        Date.parse(createdAt) + 3600_000,
      ).toISOString();
      const rootMessage = canonicalJson({
        rootHash: rootHashB64,
        periodStart,
        periodEnd,
        rowCount: 1,
      });
      const rootSignature = signEd25519(rootMessage, privateKey);
      const rootSignedAt = new Date(Date.parse(periodEnd) + 5000).toISOString();
      const root = {
        id: 'root-0',
        organizationId: orgId,
        periodStart,
        periodEnd,
        rowCount: 1,
        rootHash: rootHashB64,
        signature: rootSignature,
        keyVersion,
        signedAt: rootSignedAt,
        anchoredAt: null,
        anchorReceipt: null,
      };
      const proof = merkleProof([leaf], 0);
      const proofEntry = {
        rowId: 'row-0',
        index: proof.index,
        proof: proof.siblings.map((s) => Buffer.from(s).toString('base64')),
        rootHash: rootHashB64,
      };

      const publicKeyB64 = Buffer.from(publicKey).toString('base64');
      const generatedAt = new Date(
        Date.parse(rootSignedAt) + 1000,
      ).toISOString();
      const manifestSans = {
        version: 1,
        orgId,
        from: periodStart,
        to: periodEnd,
        rowCount: 1,
        rootCount: 1,
        keyVersions: [{ keyVersion, publicKey: publicKeyB64 }],
        generatedAt,
        signatureAlgorithm: 'Ed25519' as const,
      };
      const manifestSignature = signEd25519(
        canonicalJson(manifestSans),
        privateKey,
      );
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: keyVersion,
      };

      const publicKeys = { [String(keyVersion)]: publicKeyB64 };
      return writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        {
          name: 'rows.ndjson.gz',
          data: gzipDeterministic(
            Buffer.from(JSON.stringify(row) + '\n', 'utf8'),
          ),
        },
        {
          name: 'roots.ndjson.gz',
          data: gzipDeterministic(
            Buffer.from(JSON.stringify(root) + '\n', 'utf8'),
          ),
        },
        {
          name: 'proofs.ndjson.gz',
          data: gzipDeterministic(
            Buffer.from(JSON.stringify(proofEntry) + '\n', 'utf8'),
          ),
        },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
      ]);
    }

    it("verifies a row signed with detailsCommitment present, using be-core's REAL captured canonical bytes (post-cutover shape)", async () => {
      const zip = buildDetailsCommitmentFixtureBundle({
        includeDetailsCommitment: true,
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(true);
      // AV-0008 — single-row fixture: no inter-row link to assert (0 checked).
      expect(report.chain.status).toBe('not_present');
      expect(report.inclusionProofs.ok).toBe(true);
      expect(report.ok).toBe(true);
    });

    it('verifies a legacy row that never carries detailsCommitment (pre-cutover shape unaffected)', async () => {
      const zip = buildDetailsCommitmentFixtureBundle({
        includeDetailsCommitment: false,
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(true);
      expect(report.ok).toBe(true);
    });

    it('rejects a row whose detailsCommitment is tampered after signing', async () => {
      const zip = buildDetailsCommitmentFixtureBundle({
        includeDetailsCommitment: true,
        tamperDetailsCommitmentPostSign: true,
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.rowSignatures.ok).toBe(false);
      expect(report.ok).toBe(false);
    });
  });

  /**
   * SCAN-AV-01 — this package's `canonicalJson` claims (crypto.ts docblock)
   * to be "byte-for-byte identical to be-core's `canonicalJson`". Confirmed
   * divergence found while adding `detailsCommitment` support: an object
   * property whose value is `undefined` must be OMITTED entirely (matching
   * be-core's `FT-DEFECT-be-audit-chain-signature-invalid-after-first-row`
   * fix, `be/src/common/security/utils/canonical-json.ts`), not
   * canonicalized as `"key":null`. Ground truth captured by executing
   * be-core's REAL `canonicalJson({ a: undefined, b: 1, z: null })`.
   * Without this fix, `signableRow()`'s unconditional `summary: row.summary,
   * details: row.details` assignment (both `undefined` on a post-cutover
   * wire row that omits those keys) would inject a spurious
   * `"summary":null,"details":null` into the reconstructed preimage even
   * after `detailsCommitment` support is added above, so this fix is
   * necessary — not incidental — to SCAN-AV-01.
   */
  describe("SCAN-AV-01 — canonicalJson matches be-core's undefined-omission rule", () => {
    it('omits an object key whose value is undefined; preserves an explicit null', () => {
      const result = canonicalJson({ a: undefined, b: 1, z: null });
      expect(result.toString('utf8')).toBe('{"b":1,"z":null}');
    });
  });

  /**
   * SCAN-AV-02 — investigated as a suspected `__proto__`-key hazard in
   * `canonicalize`'s object branch (this package indexes the raw parsed
   * object directly; be-core's FROZEN `canonical-json.ts`, TICKET-213,
   * first copies into `Object.assign(Object.create(null), v)` before
   * indexing). Traced against the ECMAScript spec and CONFIRMED by
   * executing both sides for real (be-core via `ts-node`, this package via
   * this test): **neither divergence nor pollution is reachable.**
   * `[[Get]]`/`Object.keys` always resolve an object's OWN enumerable
   * property named `__proto__` (however constructed — `JSON.parse`,
   * `Object.defineProperty`, `Object.fromEntries`, spread — all use
   * `CreateDataProperty`, never the exotic literal-syntax special case)
   * in preference to the inherited `Object.prototype.__proto__` accessor,
   * for BOTH reading and enumeration; own properties always shadow
   * inherited ones. The accessor is reachable only via `[[Set]]`-style
   * assignment onto a target that does not already own that key (e.g.
   * `Object.assign({}, source)`, `target.__proto__ = value`) — a pattern
   * neither this file's cast-only object branch, nor be-core's read half
   * of its own null-prototype copy, ever exercises. be-core's copy is
   * therefore harmless-but-inert for this operation, not load-bearing;
   * mirroring it here would change zero bytes for any reachable input.
   * Ground truth for every case below captured by executing be-core's
   * REAL, unmodified `canonicalJson` via `node -r ts-node/register`
   * against `be/src/common/security/utils/canonical-json.ts` — not
   * re-derived by reading it, not re-derived from this package's own copy.
   * Closed `resolved-no-change` (`.claude/backlog/SCAN-AV-02.md`); this
   * test locks the now-verified-safe behavior in against regression.
   */
  describe('SCAN-AV-02 — __proto__-keyed object is not a canonicalization divergence or a pollution vector', () => {
    it('canonicalizes a __proto__ key created via JSON.parse to its own value (realistic path: jsonb/bundle round-trip)', () => {
      const parsed = JSON.parse('{"__proto__":"legit-value","a":1}') as Record<
        string,
        unknown
      >;
      expect(canonicalJson(parsed).toString('utf8')).toBe(
        '{"__proto__":"legit-value","a":1}',
      );
    });

    it('canonicalizes a __proto__ key forced onto a normal object via Object.defineProperty to its own value, not Object.prototype', () => {
      // Object literal syntax `{ __proto__: 'x' }` is special-cased by the
      // grammar to set [[Prototype]] instead of creating a property (and
      // is a no-op here since 'x' isn't Object|null) — Object.defineProperty
      // is the only way to force a genuine OWN, enumerable, normal-object
      // property literally named "__proto__" for this test to be meaningful.
      const obj: Record<string, unknown> = {};
      Object.defineProperty(obj, '__proto__', {
        value: 'x',
        writable: true,
        enumerable: true,
        configurable: true,
      });
      obj.a = 1;
      expect(canonicalJson(obj).toString('utf8')).toBe(
        '{"__proto__":"x","a":1}',
      );
    });

    it('treats a bare __proto__ object-literal key as prototype syntax (no own key created), matching be-core', () => {
      const lit = { __proto__: 'literal', a: 1 } as Record<string, unknown>;
      expect(canonicalJson(lit).toString('utf8')).toBe('{"a":1}');
    });

    it('preserves an object-valued __proto__ key faithfully, including nested contents', () => {
      const parsed = JSON.parse(
        '{"__proto__":{"nested":true},"a":1}',
      ) as Record<string, unknown>;
      expect(canonicalJson(parsed).toString('utf8')).toBe(
        '{"__proto__":{"nested":true},"a":1}',
      );
    });

    it('omits an undefined-valued __proto__ key, same as any other undefined-valued key', () => {
      const obj: Record<string, unknown> = {};
      Object.defineProperty(obj, '__proto__', {
        value: undefined,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      obj.a = 1;
      expect(canonicalJson(obj).toString('utf8')).toBe('{"a":1}');
    });
  });

  /**
   * PROD16 F6 (be-compliance) — explicit, non-positional manifest version
   * negotiation: a version this build does not implement must fail loudly
   * as a bundle-format error rather than being verified under the wrong
   * (older) field set.
   */
  describe('PROD16 F6 — explicit manifest version negotiation', () => {
    it('rejects a manifest version newer than this build supports', async () => {
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const manifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      manifest.version = 99;
      // Deliberately NOT re-signed — an unsupported version must be
      // rejected before any signature is even inspected.
      const zip = writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: entries.get('public-keys.json')!,
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
      await expect(verifyBundleStrict(zip, { noRekor: true })).rejects.toThrow(
        /newer than/,
      );
    });

    it('accepts the currently-supported manifest versions unchanged', async () => {
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.ok).toBe(true);
    });
  });

  /**
   * PROD16 §1b (`PROD16-REATTACK-3.md`, `PROD16-CONTRACT-manifest-v3.md`) —
   * `be` commit `dc5b8a97` added `chainSeqCeiling`/`chainSeqSnapshotAt`
   * INSIDE the signed manifest preimage and bumped the wire version to 3
   * for bundles that carry them. This is the round-trip test the ticket
   * asked for: a manifest shaped exactly like the real `be` producer's
   * `manifestSansSignature` object (§1b's quoted literal), verified by the
   * shipped verifier end to end — not a unit test of either side alone,
   * which is exactly what let the original skew ship.
   */
  describe('PROD16 §1b — v3 manifest signable set (chainSeqCeiling/chainSeqSnapshotAt)', () => {
    /**
     * Re-signs the fixture's manifest as a v3 manifest, mirroring
     * `bundle-exporter.service.ts:410-462`'s `manifestSansSignature` shape
     * byte-for-byte (same field set, same key order irrelevant since
     * `canonicalJson` sorts). `chainSeqCeiling`/`chainSeqSnapshotAt` are
     * included in — or omitted from — the signed object based on the
     * `omitChainSeqFields` flag, so both a genuine v3 manifest and an
     * attacker-forged one (same version, missing fields) can be built from
     * one helper.
     */
    function buildV3Manifest(opts: { omitChainSeqFields?: boolean } = {}): {
      zip: Buffer;
    } {
      const seed = Buffer.alloc(32, 7); // identical seed to buildFixtureBundle()
      const { privateKey, publicKey } = keypairFromSeed(seed);
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const publicKeyB64 = Buffer.from(publicKey).toString('base64');

      const manifestSans: Record<string, unknown> = {
        version: 3,
        orgId: originalManifest.orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        // v2+ producers always stamp status/revokedAt on every entry
        // (PROD15-FIXED-av2.md) — matched here so `verifyKeyBinding`'s
        // cross-check is a non-factor and this test isolates §1b's own
        // signable-set concern.
        keyVersions: [
          {
            keyVersion: 1,
            publicKey: publicKeyB64,
            status: 'ACTIVE',
            revokedAt: null,
          },
        ],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: originalManifest.signatureAlgorithm,
      };
      if (!opts.omitChainSeqFields) {
        manifestSans.chainSeqCeiling = 4;
        manifestSans.chainSeqSnapshotAt = '2026-05-01T01:00:30.000Z';
      }
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(manifestBytes, privateKey);
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };

      const zip = writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: entries.get('public-keys.json')!,
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);
      return { zip };
    }

    it('round-trips a genuine v3 manifest (be-exported shape) end to end', async () => {
      const { zip } = buildV3Manifest();
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(true);
      expect(report.ok).toBe(true);
    });

    it('rejects a v3 manifest missing chainSeqCeiling/chainSeqSnapshotAt with a distinct reason (not a generic signature failure)', async () => {
      const { zip } = buildV3Manifest({ omitChainSeqFields: true });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(false);
      expect(report.manifest.reason).toMatch(
        /chainseq_fields_missing_on_v3_manifest/,
      );
      expect(report.ok).toBe(false);
    });

    it('rejects a v1/v2 manifest that illegitimately carries chainSeqCeiling/chainSeqSnapshotAt with a distinct reason (attacker-selectable downgrade)', async () => {
      const seed = Buffer.alloc(32, 7); // identical seed to buildFixtureBundle()
      const { privateKey, publicKey } = keypairFromSeed(seed);
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const publicKeyB64 = Buffer.from(publicKey).toString('base64');

      // A v2-declared manifest, honestly re-signed OVER an object that
      // ALSO carries the two v3-only fields — modelling either version-
      // downgrade skew or an attacker bolting extra fields onto a v2
      // envelope. No genuine v2 producer emits these fields at all.
      const manifestSans = {
        version: 2,
        orgId: originalManifest.orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        keyVersions: [{ keyVersion: 1, publicKey: publicKeyB64 }],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: originalManifest.signatureAlgorithm,
        chainSeqCeiling: 4,
        chainSeqSnapshotAt: '2026-05-01T01:00:30.000Z',
      };
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(manifestBytes, privateKey);
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };

      const zip = writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: entries.get('public-keys.json')!,
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ]);

      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(false);
      expect(report.manifest.reason).toMatch(
        /chainseq_fields_present_on_v2_manifest/,
      );
      expect(report.ok).toBe(false);
    });

    it('v1 bundles (predating chainSeqCeiling entirely) keep verifying unchanged', async () => {
      // The existing pristine fixture IS a v1 manifest with neither field —
      // this is the explicit backward-compatibility regression guard.
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(true);
      expect(report.ok).toBe(true);
    });
  });

  describe('FIX01 F5(b) — manifest v4 integrity checkpoints', () => {
    /**
     * Mirrors the REAL `be` producer shape byte-for-byte:
     *  - entity: `audit-integrity-checkpoint.entity.ts`
     *    (`{id, organizationId, chainHeadHash, cumulativeRowCount, asOf,
     *    signature, signatureAlgorithm, keyVersion, createdAt}`).
     *  - signed preimage: `audit-integrity-checkpoint.service.ts`'s
     *    `canonicalJson({organizationId, chainHeadHash, cumulativeRowCount,
     *    asOf: asOf.toISOString()})` — reproduced here exactly, not
     *    reinvented, so this is the round-trip test the ticket asked for
     *    against the producer's actual field set and preimage, not a
     *    hand-built guess of it.
     */
    interface CheckpointDef {
      id: string;
      asOfIso: string;
      chainHeadHash: string;
      cumulativeRowCount: string;
      keyVersion?: number;
      privateKeyOverride?: Uint8Array;
      tamperSignature?: boolean;
    }

    function signCheckpoint(
      def: CheckpointDef,
      orgId: string,
      privateKey: Uint8Array,
    ): Record<string, unknown> {
      const message = canonicalJson({
        organizationId: orgId,
        chainHeadHash: def.chainHeadHash,
        cumulativeRowCount: def.cumulativeRowCount,
        asOf: def.asOfIso,
      });
      let signature = signEd25519(message, privateKey);
      if (def.tamperSignature) {
        const bytes = Buffer.from(signature, 'base64');
        bytes[0] = (bytes[0]! + 1) % 256;
        signature = bytes.toString('base64');
      }
      return {
        id: def.id,
        organizationId: orgId,
        chainHeadHash: def.chainHeadHash,
        cumulativeRowCount: def.cumulativeRowCount,
        asOf: def.asOfIso,
        signature,
        signatureAlgorithm: 'Ed25519',
        keyVersion: def.keyVersion ?? 1,
        createdAt: def.asOfIso,
      };
    }

    /**
     * FIX01 (audit-verifier2) / `FIX01-FIXED-be4.md`'s "FOR AUDIT-VERIFIER"
     * spec — mirrors `AuditRetentionSeal`'s wire shape byte-for-byte
     * (`BundleSealedPurge`). Signed preimage:
     * `canonicalJson({organizationId, periodStart, periodEnd, rowCount,
     * rootHash, rekorReceipt})` — the seal's OWN envelope, independent of
     * the manifest signature.
     */
    interface SealedPurgeDef {
      id: string;
      periodStart: string;
      periodEnd: string;
      /** Bigint-as-string, per the wire contract. */
      rowCount: string;
      rootHash: string;
      rekorReceipt?: Record<string, unknown> | null;
      deletedAt: string;
      deletedBy?: string;
      approvalId?: string;
      keyVersion?: number;
      privateKeyOverride?: Uint8Array;
      tamperSignature?: boolean;
      /** Model a legacy backfilled row with no signature at all. */
      unsigned?: boolean;
    }

    function signSealedPurge(
      def: SealedPurgeDef,
      orgId: string,
      privateKey: Uint8Array,
    ): Record<string, unknown> {
      const rekorReceipt = def.rekorReceipt ?? null;
      if (def.unsigned) {
        return {
          id: def.id,
          organizationId: orgId,
          periodStart: def.periodStart,
          periodEnd: def.periodEnd,
          rowCount: def.rowCount,
          rootHash: def.rootHash,
          rekorReceipt,
          signature: null,
          signingKeyVersion: null,
          signatureAlgorithm: null,
          deletedAt: def.deletedAt,
          deletedBy: def.deletedBy ?? 'user-op-1',
          approvalId: def.approvalId ?? 'approval-1',
        };
      }
      const message = canonicalJson({
        organizationId: orgId,
        periodStart: def.periodStart,
        periodEnd: def.periodEnd,
        rowCount: def.rowCount,
        rootHash: def.rootHash,
        rekorReceipt,
      });
      let signature = signEd25519(message, privateKey);
      if (def.tamperSignature) {
        const bytes = Buffer.from(signature, 'base64');
        bytes[0] = (bytes[0]! + 1) % 256;
        signature = bytes.toString('base64');
      }
      return {
        id: def.id,
        organizationId: orgId,
        periodStart: def.periodStart,
        periodEnd: def.periodEnd,
        rowCount: def.rowCount,
        rootHash: def.rootHash,
        rekorReceipt,
        signature,
        signingKeyVersion: def.keyVersion ?? 1,
        signatureAlgorithm: 'Ed25519',
        deletedAt: def.deletedAt,
        deletedBy: def.deletedBy ?? 'user-op-1',
        approvalId: def.approvalId ?? 'approval-1',
      };
    }

    /**
     * Builds a v4 bundle on top of the standard 4-row fixture
     * (`buildFixtureBundle`). `checkpointDefs` are signed with the
     * fixture's primary key (seed 7) unless a def carries its own
     * `privateKeyOverride`/`keyVersion`. `sealedPurgeDefs`, when provided
     * (even as `[]`), adds a `sealed-purges.ndjson.gz` entry — omitted
     * entirely means "no sealed-purge evidence in this bundle" (the
     * entry is wholly optional/unversioned per the spec).
     */
    function buildV4Bundle(opts: {
      checkpointDefs: CheckpointDef[];
      sealedPurgeDefs?: SealedPurgeDef[];
      integrityCheckpointCountOverride?: number;
      omitCheckpointsFile?: boolean;
      extraPublicKeys?: Record<string, unknown>;
      extraManifestKeyVersions?: Array<Record<string, unknown>>;
      versionOverride?: number;
    }): { zip: Buffer } {
      const seed = Buffer.alloc(32, 7); // identical seed to buildFixtureBundle()
      const { privateKey, publicKey } = keypairFromSeed(seed);
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const orgId = originalManifest.orgId as string;
      const publicKeyB64 = Buffer.from(publicKey).toString('base64');

      const checkpoints = opts.checkpointDefs.map((def) =>
        signCheckpoint(def, orgId, def.privateKeyOverride ?? privateKey),
      );
      const sealedPurges = (opts.sealedPurgeDefs ?? []).map((def) =>
        signSealedPurge(def, orgId, def.privateKeyOverride ?? privateKey),
      );

      const version = opts.versionOverride ?? 4;
      const manifestSans: Record<string, unknown> = {
        version,
        orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        keyVersions: [
          {
            keyVersion: 1,
            publicKey: publicKeyB64,
            status: 'ACTIVE',
            revokedAt: null,
          },
          ...(opts.extraManifestKeyVersions ?? []),
        ],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: originalManifest.signatureAlgorithm,
      };
      if (version >= 3) {
        manifestSans.chainSeqCeiling = 4;
        manifestSans.chainSeqSnapshotAt = '2026-05-01T01:00:30.000Z';
      }
      if (version >= 4 || opts.integrityCheckpointCountOverride !== undefined) {
        manifestSans.integrityCheckpointCount =
          opts.integrityCheckpointCountOverride ?? checkpoints.length;
      }
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(manifestBytes, privateKey);
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };

      const publicKeys: Record<string, unknown> = {
        '1': { publicKey: publicKeyB64, status: 'ACTIVE', revokedAt: null },
        ...(opts.extraPublicKeys ?? {}),
      };

      const checkpointsNdjson = Buffer.from(
        checkpoints.map((c) => JSON.stringify(c)).join('\n') +
          (checkpoints.length > 0 ? '\n' : ''),
        'utf8',
      );

      const zipEntries = [
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
      ];
      if (!opts.omitCheckpointsFile) {
        zipEntries.push({
          name: 'integrity-checkpoints.ndjson.gz',
          data: gzipDeterministic(checkpointsNdjson),
        });
      }
      if (opts.sealedPurgeDefs !== undefined) {
        const sealedPurgesNdjson = Buffer.from(
          sealedPurges.map((p) => JSON.stringify(p)).join('\n') +
            (sealedPurges.length > 0 ? '\n' : ''),
          'utf8',
        );
        zipEntries.push({
          name: 'sealed-purges.ndjson.gz',
          data: gzipDeterministic(sealedPurgesNdjson),
        });
      }
      return { zip: writeZip(zipEntries) };
    }

    // Fixture chain facts (see buildFixtureBundle): 4 rows, org
    // '00000000-0000-0000-0000-000000000001', signedAt at
    // 2026-05-01T00:00:0{1,61→01:01,...} — row 3 (last) is the true chain
    // tip. `tipChainHeadHash` is recomputed independently here (NOT copied
    // from the fixture's internals) via the same `computeChainLink`
    // formula the verifier itself uses, over row 3's signable bytes + its
    // own signature bytes.
    function tipChainHeadHash(base: FixtureBundle): string {
      const row3 = base.rows[3]!;
      const canonical = canonicalJson(signableRow(row3));
      const sigBytes = Buffer.from(row3.signature, 'base64');
      return sha256(Buffer.concat([canonical, sigBytes])).toString('base64');
    }

    it('round-trips a genuine v4 manifest + checkpoints (be-exported shape) end to end', async () => {
      const base = buildFixtureBundle();
      const { zip } = buildV4Bundle({
        checkpointDefs: [
          {
            id: 'cp-0',
            asOfIso: '2026-04-30T23:59:00.000Z', // before any row
            chainHeadHash: GENESIS_PREV_ROW_HASH,
            cumulativeRowCount: '0',
          },
          {
            id: 'cp-1',
            asOfIso: '2026-05-01T01:30:00.000Z', // after all 4 rows
            chainHeadHash: tipChainHeadHash(base),
            cumulativeRowCount: '4',
          },
        ],
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.integrityCheckpoints.ok).toBe(true);
      expect(report.integrityCheckpoints.failed).toBe(0);
      expect(report.completeness.ok).toBe(true);
      expect(report.ok).toBe(true);
    });

    it('computes row chain links once rather than once per checkpoint', async () => {
      const base = buildFixtureBundle();
      const tip = tipChainHeadHash(base);
      const { zip } = buildV4Bundle({
        checkpointDefs: Array.from({ length: 50 }, (_, index) => ({
          id: `cp-linear-${index}`,
          asOfIso: '2026-05-01T01:30:00.000Z',
          chainHeadHash: tip,
          cumulativeRowCount: '4',
        })),
      });
      const hashSpy = vi.spyOn(cryptoPrimitives, 'sha256');
      try {
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.integrityCheckpoints.ok).toBe(true);
        // The fixture has four rows. The chain verifier and checkpoint pass
        // each hash those rows a constant number of times; adding fifty
        // checkpoints must not add 50 x 4 canonical-link recomputations.
        expect(hashSpy.mock.calls.length).toBeGreaterThanOrEqual(4);
        expect(hashSpy.mock.calls.length).toBeLessThan(100);
      } finally {
        hashSpy.mockRestore();
      }
    });

    it('rejects a v4 manifest missing integrityCheckpointCount with a distinct reason', async () => {
      const seed = Buffer.alloc(32, 7);
      const { privateKey, publicKey } = keypairFromSeed(seed);
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const publicKeyB64 = Buffer.from(publicKey).toString('base64');
      const manifestSans: Record<string, unknown> = {
        version: 4,
        orgId: originalManifest.orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        keyVersions: [
          {
            keyVersion: 1,
            publicKey: publicKeyB64,
            status: 'ACTIVE',
            revokedAt: null,
          },
        ],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: originalManifest.signatureAlgorithm,
        chainSeqCeiling: 4,
        chainSeqSnapshotAt: '2026-05-01T01:00:30.000Z',
        // integrityCheckpointCount deliberately omitted.
      };
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(manifestBytes, privateKey);
      const manifest = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };
      const zip = writeZip([
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: entries.get('public-keys.json')!,
        },
        { name: 'README.md', data: entries.get('README.md')! },
        {
          name: 'integrity-checkpoints.ndjson.gz',
          data: gzipDeterministic(Buffer.alloc(0)),
        },
      ]);
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(false);
      expect(report.manifest.reason).toMatch(
        /integrity_checkpoint_count_missing_on_v4_manifest/,
      );
      expect(report.ok).toBe(false);
    });

    it('rejects a v3 manifest that illegitimately carries integrityCheckpointCount', async () => {
      const { zip } = buildV4Bundle({
        checkpointDefs: [],
        versionOverride: 3,
        integrityCheckpointCountOverride: 0,
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.manifest.ok).toBe(false);
      expect(report.manifest.reason).toMatch(
        /integrity_checkpoint_count_present_on_v3_manifest/,
      );
      expect(report.ok).toBe(false);
    });

    it('fails as a bundle-format error when v4 is declared but integrity-checkpoints.ndjson.gz is absent', async () => {
      const { zip } = buildV4Bundle({
        checkpointDefs: [],
        omitCheckpointsFile: true,
      });
      await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
        /missing required entry: integrity-checkpoints\.ndjson\.gz/,
      );
    });

    it('fails closed on a tampered checkpoint signature', async () => {
      const { zip } = buildV4Bundle({
        checkpointDefs: [
          {
            id: 'cp-0',
            asOfIso: '2026-04-30T23:59:00.000Z',
            chainHeadHash: GENESIS_PREV_ROW_HASH,
            cumulativeRowCount: '0',
            tamperSignature: true,
          },
        ],
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.integrityCheckpoints.ok).toBe(false);
      expect(report.integrityCheckpoints.reason).toMatch(
        /checkpoint signature does not verify/,
      );
      expect(report.ok).toBe(false);
    });

    it('fails closed on a checkpoint signed under a REVOKED key', async () => {
      const seed2 = Buffer.alloc(32, 9);
      const { privateKey: revokedPriv, publicKey: revokedPub } =
        keypairFromSeed(seed2);
      const revokedPubB64 = Buffer.from(revokedPub).toString('base64');
      const { zip } = buildV4Bundle({
        checkpointDefs: [
          {
            id: 'cp-revoked',
            asOfIso: '2026-04-30T23:59:00.000Z',
            chainHeadHash: GENESIS_PREV_ROW_HASH,
            cumulativeRowCount: '0',
            keyVersion: 2,
            privateKeyOverride: revokedPriv,
          },
        ],
        extraPublicKeys: {
          '2': {
            publicKey: revokedPubB64,
            status: 'REVOKED',
            revokedAt: '2026-04-15T00:00:00.000Z',
          },
        },
        extraManifestKeyVersions: [
          {
            keyVersion: 2,
            publicKey: revokedPubB64,
            status: 'REVOKED',
            revokedAt: '2026-04-15T00:00:00.000Z',
          },
        ],
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.integrityCheckpoints.ok).toBe(false);
      expect(report.integrityCheckpoints.reason).toMatch(/key_revoked/);
      expect(report.ok).toBe(false);
    });

    it('fails closed when cumulativeRowCount decreases between two checkpoints (suffix-deletion signal)', async () => {
      const { zip } = buildV4Bundle({
        checkpointDefs: [
          {
            id: 'cp-a',
            // Both well before any bundled row so the chain-head-hash
            // check is skipped (ambiguous/dormant) and this test isolates
            // the monotonic-count check alone.
            asOfIso: '2026-04-30T22:00:00.000Z',
            chainHeadHash: sha256(Buffer.from('arbitrary-a')).toString(
              'base64',
            ),
            cumulativeRowCount: '5',
          },
          {
            id: 'cp-b',
            asOfIso: '2026-04-30T23:00:00.000Z',
            chainHeadHash: sha256(Buffer.from('arbitrary-b')).toString(
              'base64',
            ),
            cumulativeRowCount: '3',
          },
        ],
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.integrityCheckpoints.ok).toBe(false);
      expect(report.integrityCheckpoints.reason).toMatch(
        /cumulative_row_count_decreased/,
      );
      expect(report.ok).toBe(false);
    });

    it('fails closed when a checkpoint claims a chainHeadHash the bundle rows do not reach', async () => {
      const { zip } = buildV4Bundle({
        checkpointDefs: [
          {
            id: 'cp-tip',
            asOfIso: '2026-05-01T01:30:00.000Z', // after all 4 rows exist
            chainHeadHash: GENESIS_PREV_ROW_HASH, // wrong: true tip isn't genesis
            cumulativeRowCount: '4',
          },
        ],
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.integrityCheckpoints.ok).toBe(false);
      expect(report.integrityCheckpoints.reason).toMatch(
        /chain_head_hash_mismatch/,
      );
      expect(report.ok).toBe(false);
    });

    it('does NOT flag a checkpoint whose asOf predates every bundled row (dormant-org / boundary export) — avoids a false suffix-deletion report', async () => {
      const { zip } = buildV4Bundle({
        checkpointDefs: [
          {
            id: 'cp-early',
            asOfIso: '2026-04-30T22:00:00.000Z', // before row 0's signedAt
            // A non-genesis, arbitrary claim: if this bundle's rows were
            // wrongly treated as authoritative for this instant, this
            // would look unreachable and fail. It must NOT be asserted.
            chainHeadHash: sha256(Buffer.from('pre-range-head')).toString(
              'base64',
            ),
            cumulativeRowCount: '117',
          },
        ],
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.integrityCheckpoints.ok).toBe(true);
      expect(report.integrityCheckpoints.failed).toBe(0);
      expect(report.ok).toBe(true);
    });

    it('completeness fails closed when checkpoints.length disagrees with the signed integrityCheckpointCount', async () => {
      const { zip } = buildV4Bundle({
        checkpointDefs: [
          {
            id: 'cp-0',
            asOfIso: '2026-04-30T23:59:00.000Z',
            chainHeadHash: GENESIS_PREV_ROW_HASH,
            cumulativeRowCount: '0',
          },
        ],
        integrityCheckpointCountOverride: 2, // signed count says 2, only 1 present
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.completeness.ok).toBe(false);
      expect(report.completeness.reason).toMatch(
        /integrity checkpoint count mismatch/,
      );
      expect(report.ok).toBe(false);
    });

    it('v1-v3 bundles (no checkpoints file at all) report integrityCheckpoints not_present without failing the bundle (AV-0008)', async () => {
      const { zip } = buildBundleWithTamper({});
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.integrityCheckpoints.status).toBe('not_present');
      expect(report.integrityCheckpoints.checked).toBe(0);
      expect(report.ok).toBe(true);
    });

    describe('FIX01 (audit-verifier2) — sealed-purge reconciliation closes the contract residual', () => {
      it('downgrades a cumulativeRowCount decrease to a pass when a verified sealed purge in the checkpoint window reconciles it', async () => {
        const base = buildFixtureBundle();
        const { zip } = buildV4Bundle({
          checkpointDefs: [
            {
              id: 'cp-a',
              asOfIso: '2026-04-30T23:00:00.000Z',
              chainHeadHash: sha256(Buffer.from('arbitrary-a')).toString(
                'base64',
              ),
              cumulativeRowCount: '5',
            },
            {
              id: 'cp-b',
              asOfIso: '2026-05-01T01:30:00.000Z',
              chainHeadHash: tipChainHeadHash(base), // true tip — check 3 passes on its own
              cumulativeRowCount: '3', // decrease of 2
            },
          ],
          sealedPurgeDefs: [
            {
              id: 'seal-cp-1',
              periodStart: '2026-04-30T00:00:00.000Z',
              periodEnd: '2026-05-01T00:00:00.000Z',
              rowCount: '2', // exactly covers the decrease
              rootHash: sha256(Buffer.from('irrelevant-root')).toString(
                'base64',
              ),
              deletedAt: '2026-05-01T00:30:00.000Z', // inside (cp-a.asOf, cp-b.asOf]
              approvalId: 'approval-9',
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.integrityCheckpoints.ok).toBe(true);
        expect(report.integrityCheckpoints.failed).toBe(0);
        expect(report.integrityCheckpoints.sealExemptions).toBeDefined();
        expect(report.integrityCheckpoints.sealExemptions).toHaveLength(1);
        expect(report.integrityCheckpoints.sealExemptions![0]).toContain(
          'seal-cp-1',
        );
        expect(report.integrityCheckpoints.sealExemptions![0]).toContain(
          'approval-9',
        );
        expect(report.bundle.sealedPurgesSeen).toBe(1);
        expect(report.bundle.sealedPurgesVerified).toBe(1);
        expect(report.ok).toBe(true);
      });

      it('keeps failing closed when the reconciling seal rowCount does not cover the full decrease', async () => {
        const base = buildFixtureBundle();
        const { zip } = buildV4Bundle({
          checkpointDefs: [
            {
              id: 'cp-a',
              asOfIso: '2026-04-30T23:00:00.000Z',
              chainHeadHash: sha256(Buffer.from('arbitrary-a')).toString(
                'base64',
              ),
              cumulativeRowCount: '5',
            },
            {
              id: 'cp-b',
              asOfIso: '2026-05-01T01:30:00.000Z',
              chainHeadHash: tipChainHeadHash(base),
              cumulativeRowCount: '3', // decrease of 2
            },
          ],
          sealedPurgeDefs: [
            {
              id: 'seal-cp-short',
              periodStart: '2026-04-30T00:00:00.000Z',
              periodEnd: '2026-05-01T00:00:00.000Z',
              rowCount: '1', // short of the decrease (2) — must NOT exempt
              rootHash: sha256(Buffer.from('irrelevant-root')).toString(
                'base64',
              ),
              deletedAt: '2026-05-01T00:30:00.000Z',
              approvalId: 'approval-9',
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.integrityCheckpoints.ok).toBe(false);
        expect(report.integrityCheckpoints.reason).toMatch(
          /cumulative_row_count_decreased/,
        );
        expect(report.integrityCheckpoints.sealExemptions).toBeUndefined();
        expect(report.ok).toBe(false);
      });

      it('keeps failing closed when no sealed-purge entry falls inside the checkpoint window (evidence elsewhere does not count)', async () => {
        const base = buildFixtureBundle();
        const { zip } = buildV4Bundle({
          checkpointDefs: [
            {
              id: 'cp-a',
              asOfIso: '2026-04-30T23:00:00.000Z',
              chainHeadHash: sha256(Buffer.from('arbitrary-a')).toString(
                'base64',
              ),
              cumulativeRowCount: '5',
            },
            {
              id: 'cp-b',
              asOfIso: '2026-05-01T01:30:00.000Z',
              chainHeadHash: tipChainHeadHash(base),
              cumulativeRowCount: '3',
            },
          ],
          sealedPurgeDefs: [
            {
              id: 'seal-outside-window',
              periodStart: '2026-04-30T00:00:00.000Z',
              periodEnd: '2026-05-01T00:00:00.000Z',
              rowCount: '2',
              rootHash: sha256(Buffer.from('irrelevant-root')).toString(
                'base64',
              ),
              deletedAt: '2026-04-30T20:00:00.000Z', // BEFORE cp-a.asOf — outside (cp-a, cp-b]
              approvalId: 'approval-9',
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.integrityCheckpoints.ok).toBe(false);
        expect(report.integrityCheckpoints.reason).toMatch(
          /cumulative_row_count_decreased/,
        );
        expect(report.ok).toBe(false);
      });

      it('keeps failing closed when the sealed-purge signature is tampered — unverifiable evidence is never used for a downgrade', async () => {
        const base = buildFixtureBundle();
        const { zip } = buildV4Bundle({
          checkpointDefs: [
            {
              id: 'cp-a',
              asOfIso: '2026-04-30T23:00:00.000Z',
              chainHeadHash: sha256(Buffer.from('arbitrary-a')).toString(
                'base64',
              ),
              cumulativeRowCount: '5',
            },
            {
              id: 'cp-b',
              asOfIso: '2026-05-01T01:30:00.000Z',
              chainHeadHash: tipChainHeadHash(base),
              cumulativeRowCount: '3',
            },
          ],
          sealedPurgeDefs: [
            {
              id: 'seal-tampered',
              periodStart: '2026-04-30T00:00:00.000Z',
              periodEnd: '2026-05-01T00:00:00.000Z',
              rowCount: '2',
              rootHash: sha256(Buffer.from('irrelevant-root')).toString(
                'base64',
              ),
              deletedAt: '2026-05-01T00:30:00.000Z',
              approvalId: 'approval-9',
              tamperSignature: true,
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.integrityCheckpoints.ok).toBe(false);
        expect(report.integrityCheckpoints.reason).toMatch(
          /cumulative_row_count_decreased/,
        );
        expect(report.bundle.sealedPurgesSeen).toBe(1);
        expect(report.bundle.sealedPurgesVerified).toBe(0);
        expect(report.ok).toBe(false);
      });

      it('downgrades a chain_head_hash_mismatch to a pass when the same seal window reconciles the cumulativeRowCount decrease (closes the contract residual explicitly)', async () => {
        const { zip } = buildV4Bundle({
          checkpointDefs: [
            {
              id: 'cp-a',
              asOfIso: '2026-04-30T23:00:00.000Z',
              chainHeadHash: sha256(Buffer.from('arbitrary-a')).toString(
                'base64',
              ),
              cumulativeRowCount: '6',
            },
            {
              id: 'cp-b',
              asOfIso: '2026-05-01T01:30:00.000Z',
              // Wrong: true tip after all 4 rows isn't genesis — this
              // would fail chain_head_hash_mismatch WITHOUT the seal.
              chainHeadHash: GENESIS_PREV_ROW_HASH,
              cumulativeRowCount: '4', // decrease of 2
            },
          ],
          sealedPurgeDefs: [
            {
              id: 'seal-cp-2',
              periodStart: '2026-04-30T00:00:00.000Z',
              periodEnd: '2026-05-01T00:00:00.000Z',
              rowCount: '2',
              rootHash: sha256(Buffer.from('irrelevant-root-2')).toString(
                'base64',
              ),
              deletedAt: '2026-05-01T00:45:00.000Z',
              approvalId: 'approval-10',
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.integrityCheckpoints.ok).toBe(true);
        expect(report.integrityCheckpoints.failed).toBe(0);
        expect(report.integrityCheckpoints.sealExemptions).toBeDefined();
        // Both the count-decrease (2) and the hash-mismatch (3) checks
        // reconcile against the SAME window/seal — two distinct exemption
        // entries, one per check.
        expect(report.integrityCheckpoints.sealExemptions).toHaveLength(2);
        expect(
          report.integrityCheckpoints.sealExemptions!.some((s) =>
            s.includes('chainHeadHash mismatch'),
          ),
        ).toBe(true);
        expect(
          report.integrityCheckpoints.sealExemptions!.every((s) =>
            s.includes('seal-cp-2'),
          ),
        ).toBe(true);
        expect(report.ok).toBe(true);
      });

      it('real end-to-end round trip: a be-shaped v4 bundle with a genuine sealed-purge reconciling a checkpoint decrease verifies OK via the shipped CLI subprocess', () => {
        const base = buildFixtureBundle();
        const { zip } = buildV4Bundle({
          checkpointDefs: [
            {
              id: 'cp-a',
              asOfIso: '2026-04-30T23:00:00.000Z',
              chainHeadHash: sha256(Buffer.from('arbitrary-a')).toString(
                'base64',
              ),
              cumulativeRowCount: '5',
            },
            {
              id: 'cp-b',
              asOfIso: '2026-05-01T01:30:00.000Z',
              chainHeadHash: tipChainHeadHash(base),
              cumulativeRowCount: '3',
            },
          ],
          sealedPurgeDefs: [
            {
              id: 'seal-e2e-1',
              periodStart: '2026-04-30T00:00:00.000Z',
              periodEnd: '2026-05-01T00:00:00.000Z',
              rowCount: '2',
              rootHash: sha256(Buffer.from('irrelevant-root-e2e')).toString(
                'base64',
              ),
              deletedAt: '2026-05-01T00:30:00.000Z',
              approvalId: 'approval-e2e',
            },
          ],
        });
        const testDir = path.dirname(fileURLToPath(import.meta.url));
        const cliPath = path.resolve(testDir, '../../dist/cli.js');
        if (!fs.existsSync(cliPath)) {
          throw new Error(
            'dist/cli.js not found — `npm run build` must run before `npm test` ' +
              '(the standard gate order in .claude/bin/verify.sh already does this).',
          );
        }
        const tmpDir = fs.mkdtempSync(
          path.join(os.tmpdir(), 'audit-verifier-e2e-'),
        );
        const bundlePath = path.join(tmpDir, 'bundle.zip');
        try {
          fs.writeFileSync(bundlePath, zip);
          const stdout = execFileSync(
            process.execPath,
            [cliPath, bundlePath, '--no-rekor', '--allow-legacy-unattested'],
            { encoding: 'utf8' },
          );
          expect(stdout).toContain('RESULT: OK');
          expect(stdout).toContain('seal_exempted');
          expect(stdout).toContain('seal-e2e-1');
          expect(stdout).not.toContain('RESULT: FAIL');
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });
    });
  });

  /**
   * PA-0009 — CLI `--json` flag and the `status`-derived exit codes
   * (0 valid / 1 invalid / 3 incomplete; 2 stays reserved for I/O/format
   * errors and is unaffected by this ticket). No component in this build
   * can produce `incomplete`, so exit 3 is not exercisable end-to-end yet
   * — the switch statement's `case 'incomplete': return 3;` branch is
   * exact-mirrored from `reduceStatus`'s own exhaustive union, and will be
   * covered live once PA-0010 lands a component that can return it.
   */
  describe('PA-0009 — CLI --json flag and status exit codes', () => {
    function cliPathOrThrow(): string {
      const testDir = path.dirname(fileURLToPath(import.meta.url));
      const cliPath = path.resolve(testDir, '../../dist/cli.js');
      if (!fs.existsSync(cliPath)) {
        throw new Error(
          'dist/cli.js not found — `npm run build` must run before `npm test` ' +
            '(the standard gate order in .claude/bin/verify.sh already does this).',
        );
      }
      return cliPath;
    }

    function writeTempBundle(zip: Buffer): {
      tmpDir: string;
      bundlePath: string;
    } {
      const tmpDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'audit-verifier-cli-status-'),
      );
      const bundlePath = path.join(tmpDir, 'bundle.zip');
      fs.writeFileSync(bundlePath, zip);
      return { tmpDir, bundlePath };
    }

    describe('SEC-2026-09-12 (MCPSDK-03) — --platform-key provenance', () => {
      function writeP256KeyFile(dir: string): {
        keyPath: string;
        fingerprint: string;
      } {
        const { publicKey } = crypto.generateKeyPairSync('ec', {
          namedCurve: 'P-256',
        });
        const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
        const der = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
        const keyPath = path.join(dir, 'platform.pem');
        fs.writeFileSync(keyPath, pem);
        return {
          keyPath,
          fingerprint: crypto.createHash('sha256').update(der).digest('hex'),
        };
      }

      /**
       * The CLI accepts ANY P-256 key as the platform trust anchor, and with
       * a caller-supplied key the attestation's own
       * `platformSigningKeyFingerprint` check degenerates to hashing the key
       * it was handed. A forger who controls both the bundle and the key file
       * would otherwise get an unqualified `[VALID] platform attest.`
       */
      it('prints a WARNING whenever --platform-key was supplied', () => {
        const { zip } = buildBundleWithTamper({});
        const cliPath = cliPathOrThrow();
        const { tmpDir, bundlePath } = writeTempBundle(zip);
        try {
          const { keyPath } = writeP256KeyFile(tmpDir);
          const stdout = execFileSync(
            process.execPath,
            [
              cliPath,
              bundlePath,
              '--no-rekor',
              '--allow-legacy-unattested',
              '--platform-key',
              keyPath,
            ],
            { encoding: 'utf8' },
          );
          expect(stdout).toContain('RESULT: OK');
          expect(stdout).toContain(
            'WARNING: platform key supplied by caller — result is only as strong as the provenance of that key file',
          );
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });

      it('prints no such WARNING when no --platform-key was supplied', () => {
        const { zip } = buildBundleWithTamper({});
        const cliPath = cliPathOrThrow();
        const { tmpDir, bundlePath } = writeTempBundle(zip);
        try {
          const stdout = execFileSync(
            process.execPath,
            [cliPath, bundlePath, '--no-rekor', '--allow-legacy-unattested'],
            { encoding: 'utf8' },
          );
          expect(stdout).not.toContain('platform key supplied by caller');
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });

      it('accepts --platform-key-fingerprint when it matches the key file', () => {
        const { zip } = buildBundleWithTamper({});
        const cliPath = cliPathOrThrow();
        const { tmpDir, bundlePath } = writeTempBundle(zip);
        try {
          const { keyPath, fingerprint } = writeP256KeyFile(tmpDir);
          const stdout = execFileSync(
            process.execPath,
            [
              cliPath,
              bundlePath,
              '--no-rekor',
              '--allow-legacy-unattested',
              '--platform-key',
              keyPath,
              '--platform-key-fingerprint',
              fingerprint,
            ],
            { encoding: 'utf8' },
          );
          expect(stdout).toContain('RESULT: OK');
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });

      it('exits 2 when --platform-key-fingerprint does not match the key file', () => {
        const { zip } = buildBundleWithTamper({});
        const cliPath = cliPathOrThrow();
        const { tmpDir, bundlePath } = writeTempBundle(zip);
        try {
          const { keyPath } = writeP256KeyFile(tmpDir);
          execFileSync(
            process.execPath,
            [
              cliPath,
              bundlePath,
              '--no-rekor',
              '--allow-legacy-unattested',
              '--platform-key',
              keyPath,
              '--platform-key-fingerprint',
              'a'.repeat(64),
            ],
            { encoding: 'utf8' },
          );
          throw new Error('expected exit code 2, process did not exit non-zero');
        } catch (err) {
          const e = err as { status?: number; stderr?: string };
          expect(e.status).toBe(2);
          expect(e.stderr ?? '').toContain('platform key fingerprint mismatch');
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });

      it('exits 2 when --platform-key-fingerprint is given without --platform-key', () => {
        const { zip } = buildBundleWithTamper({});
        const cliPath = cliPathOrThrow();
        const { tmpDir, bundlePath } = writeTempBundle(zip);
        try {
          execFileSync(
            process.execPath,
            [
              cliPath,
              bundlePath,
              '--no-rekor',
              '--allow-legacy-unattested',
              '--platform-key-fingerprint',
              'a'.repeat(64),
            ],
            { encoding: 'utf8' },
          );
          throw new Error('expected exit code 2, process did not exit non-zero');
        } catch (err) {
          const e = err as { status?: number; stderr?: string };
          expect(e.status).toBe(2);
          expect(e.stderr ?? '').toContain(
            '--platform-key-fingerprint requires --platform-key',
          );
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });
    });

    it('--json emits a stable JSON report with status: valid and exits 0 on a pristine bundle', () => {
      const { zip } = buildBundleWithTamper({});
      const cliPath = cliPathOrThrow();
      const { tmpDir, bundlePath } = writeTempBundle(zip);
      try {
        const stdout = execFileSync(
          process.execPath,
          [
            cliPath,
            bundlePath,
            '--no-rekor',
            '--allow-legacy-unattested',
            '--json',
          ],
          { encoding: 'utf8' },
        );
        const parsed = JSON.parse(stdout) as VerifyReport;
        expect(parsed.status).toBe('valid');
        expect(parsed.ok).toBe(true);
        expect(parsed.manifest.status).toBe('valid');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('--json emits status: invalid and the process exits 1 on a tampered bundle', () => {
      const { zip } = buildBundleWithTamper({
        postSignRowByte: (rows) => {
          rows[2]!.action = 'agent.deleted';
        },
      });
      const cliPath = cliPathOrThrow();
      const { tmpDir, bundlePath } = writeTempBundle(zip);
      try {
        execFileSync(
          process.execPath,
          [
            cliPath,
            bundlePath,
            '--no-rekor',
            '--allow-legacy-unattested',
            '--json',
          ],
          { encoding: 'utf8' },
        );
        throw new Error('expected exit code 1, process did not exit non-zero');
      } catch (err) {
        const e = err as { status?: number; stdout?: string };
        expect(e.status).toBe(1);
        const parsed = JSON.parse(e.stdout ?? '{}') as VerifyReport;
        expect(parsed.status).toBe('invalid');
        expect(parsed.ok).toBe(false);
        expect(parsed.rowSignatures.status).toBe('invalid');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('--quiet prints the status word (OK), not a hardcoded checkmark', () => {
      const { zip } = buildBundleWithTamper({});
      const cliPath = cliPathOrThrow();
      const { tmpDir, bundlePath } = writeTempBundle(zip);
      try {
        const stdout = execFileSync(
          process.execPath,
          [
            cliPath,
            bundlePath,
            '--no-rekor',
            '--allow-legacy-unattested',
            '--quiet',
          ],
          { encoding: 'utf8' },
        );
        expect(stdout).toBe('OK\n');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('rejects an oversized sparse bundle before reading it into memory', () => {
      const cliPath = cliPathOrThrow();
      const tmpDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'audit-verifier-cli-size-'),
      );
      const bundlePath = path.join(tmpDir, 'oversized.zip');
      try {
        fs.writeFileSync(bundlePath, Buffer.alloc(0));
        fs.truncateSync(bundlePath, MAX_ZIP_ARCHIVE_BYTES + 1);
        try {
          execFileSync(process.execPath, [cliPath, bundlePath], {
            encoding: 'utf8',
          });
          throw new Error(
            'expected exit code 2, process did not exit non-zero',
          );
        } catch (err) {
          const e = err as { status?: number; stderr?: string };
          expect(e.status).toBe(2);
          expect(e.stderr).toContain('bundle size');
          expect(e.stderr).toContain('exceeds limit');
        }
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('rejects an oversized platform key before reading it into memory', () => {
      const { zip } = buildBundleWithTamper({});
      const cliPath = cliPathOrThrow();
      const { tmpDir, bundlePath } = writeTempBundle(zip);
      const keyPath = path.join(tmpDir, 'oversized-platform-key.pem');
      try {
        fs.writeFileSync(keyPath, Buffer.alloc(0));
        fs.truncateSync(keyPath, 64 * 1024 + 1);
        try {
          execFileSync(
            process.execPath,
            [
              cliPath,
              bundlePath,
              '--platform-key',
              keyPath,
              '--no-rekor',
              '--allow-legacy-unattested',
            ],
            { encoding: 'utf8' },
          );
          throw new Error(
            'expected exit code 2, process did not exit non-zero',
          );
        } catch (err) {
          const e = err as { status?: number; stderr?: string };
          expect(e.status).toBe(2);
          expect(e.stderr).toContain('platform key size');
          expect(e.stderr).toContain('exceeds limit');
        }
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('rejects a FIFO bundle path without waiting for a writer', () => {
      if (process.platform === 'win32') return;

      const cliPath = cliPathOrThrow();
      const tmpDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'audit-verifier-cli-fifo-'),
      );
      const bundlePath = path.join(tmpDir, 'bundle.fifo');
      try {
        execFileSync('mkfifo', [bundlePath]);
        try {
          execFileSync(process.execPath, [cliPath, bundlePath], {
            encoding: 'utf8',
            timeout: 2_000,
          });
          throw new Error(
            'expected exit code 2, process did not exit non-zero',
          );
        } catch (err) {
          const e = err as {
            status?: number;
            stderr?: string;
            code?: string;
          };
          expect(e.code).not.toBe('ETIMEDOUT');
          expect(e.status).toBe(2);
          expect(e.stderr).toContain('bundle path is not a regular file');
        }
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    // AV-0006 — `verify` is the form be's verification.txt and the ui proof
    // page print. It must be an exact alias of single-bundle mode: same exit
    // code and byte-identical report, for a passing AND a failing bundle.
    describe('AV-0006 — `verify <bundle>` alias of single-bundle mode', () => {
      const run = (args: string[]) =>
        spawnSync(process.execPath, [cliPathOrThrow(), ...args], { encoding: 'utf8' });
      const flags = ['--no-rekor', '--allow-legacy-unattested', '--json'];

      it.each([
        ['pristine', {}, 0],
        ['tampered', { postSignRowByte: (rows: FixtureRow[]) => { rows[2]!.action = 'agent.deleted'; } }, 1],
      ] as const)('%s bundle: same exit code and report with or without `verify`', (_n, tamper, code) => {
        const { zip } = buildBundleWithTamper(tamper);
        const { tmpDir, bundlePath } = writeTempBundle(zip);
        try {
          const bare = run([bundlePath, ...flags]);
          const alias = run(['verify', bundlePath, ...flags]);
          expect(bare.status).toBe(code);
          expect(alias.status).toBe(code);
          expect(alias.stdout).toBe(bare.stdout);
          expect(JSON.parse(alias.stdout).status).toBe(code === 0 ? 'valid' : 'invalid');
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      });

      it('`verify` with no bundle path exits 2 and prints usage', () => {
        const r = run(['verify']);
        expect(r.status).toBe(2);
        expect(r.stdout).toContain('praesidia-verify verify <bundle.zip>');
      });
    });

    // AV-0007 — the audit package (be `audit-package.service.ts`) wraps the
    // signed bundle at evidence/audit-bundle.zip next to an UNSIGNED
    // verification.txt receipt stating its sha256 + byte count.
    describe('AV-0007 — `praesidia-verify audit-package.zip`', () => {
      const run = (args: string[]) =>
        spawnSync(process.execPath, [cliPathOrThrow(), ...args], { encoding: 'utf8' });
      const flags = ['--no-rekor', '--allow-legacy-unattested'];
      const receipt = (inner: Buffer) =>
        Buffer.from(
          [
            'Praesidia Audit Package — Verification Receipt',
            'Evidence archive: evidence/audit-bundle.zip',
            `Evidence archive SHA-256: ${crypto.createHash('sha256').update(inner).digest('hex')}`,
            `Evidence archive bytes: ${inner.length}`,
            '',
          ].join('\n'),
          'utf8',
        );
      const pkg = (inner: Buffer, verificationTxt: Buffer | null) =>
        writeZip([
          { name: 'executive-summary.pdf', data: Buffer.from('%PDF-1.4\n') },
          { name: 'evaluations/summary.json', data: Buffer.from('{}') },
          { name: 'evidence/audit-bundle.zip', data: inner },
          ...(verificationTxt ? [{ name: 'verification.txt', data: verificationTxt }] : []),
        ]);
      const runPkg = (zip: Buffer, extra: string[] = ['--json']) => {
        const { tmpDir, bundlePath } = writeTempBundle(zip);
        try {
          return run([bundlePath, ...flags, ...extra]);
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      };

      it('valid package: exit 0, inner bundle verified, side artifacts listed as unverified', () => {
        const { zip: inner } = buildBundleWithTamper({});
        const r = runPkg(pkg(inner, receipt(inner)));
        expect(r.status).toBe(0);
        const report = JSON.parse(r.stdout);
        expect(report.status).toBe('valid');
        expect(report.package).toEqual({
          status: 'valid',
          sha256Matches: true,
          byteCountMatches: true,
          sideArtifacts: ['executive-summary.pdf', 'evaluations/summary.json'],
        });
        const human = runPkg(pkg(inner, receipt(inner)), []);
        expect(human.status).toBe(0);
        expect(human.stdout).toMatch(/^package: +VALID/m);
        expect(human.stdout).toContain('unsigned side artifacts (not verified): executive-summary.pdf, evaluations/summary.json');
      });

      it('tampered inner bytes: exit 1 with the hash mismatch named, even though the inner bundle verifies', async () => {
        const { zip: inner } = buildBundleWithTamper({});
        const swapped = writeZip(
          readZip(inner).map((e) =>
            e.name === 'README.md' ? { name: e.name, data: Buffer.from('# tampered\n') } : e,
          ),
        );
        expect((await verifyBundle(swapped, { noRekor: true })).status).toBe('valid');
        const r = runPkg(pkg(swapped, receipt(inner)));
        expect(r.status).toBe(1);
        const report = JSON.parse(r.stdout);
        expect(report.status).toBe('invalid');
        expect(report.package.status).toBe('invalid');
        expect(report.package.sha256Matches).toBe(false);
        expect(report.package.reason).toContain('SHA-256');
      });

      it('receipt present but unparseable: invalid (exit 1), never skipped', () => {
        const { zip: inner } = buildBundleWithTamper({});
        const r = runPkg(pkg(inner, Buffer.from('Evidence archive bytes: 12\n')));
        expect(r.status).toBe(1);
        expect(JSON.parse(r.stdout).package.status).toBe('invalid');
      });

      it('verification.txt missing: package integrity incomplete, exit 3', () => {
        const { zip: inner } = buildBundleWithTamper({});
        const r = runPkg(pkg(inner, null));
        expect(r.status).toBe(3);
        const report = JSON.parse(r.stdout);
        expect(report.status).toBe('incomplete');
        expect(report.package).toMatchObject({ status: 'incomplete', sha256Matches: null, byteCountMatches: null });
      });

      it('a plain bundle still verifies unchanged (no `package` key)', () => {
        const { zip } = buildBundleWithTamper({});
        const r = runPkg(zip);
        expect(r.status).toBe(0);
        expect(JSON.parse(r.stdout)).not.toHaveProperty('package');
      });
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // PA-0010 — manifest v5 action-event evidence
  // (`PA01-CONTRACT-manifest-v5-actions.md`, `PA01-DECISIONS.md` D7/D8/D9,
  // corrigendum C4)
  // ──────────────────────────────────────────────────────────────────────
  describe('PA-0010 — manifest v5 action-event evidence', () => {
    interface ActionEventDef {
      actionId: string;
      actionSeq: number;
      eventType: string;
      schemaVersion?: number;
      observedAtIso: string;
      receivedAtIso?: string;
      issuer?: string;
      issuerType?: string;
      trustDomain?: string;
      payload?: Record<string, unknown> | null;
      payloadCommitment?: string | null;
      dispatched?: boolean;
      timeSource?: string;
      permitNonce?: string | null;
      edgeVersion?: string | null;
      adapterVersion?: string | null;
      externalReceiptRef?: string | null;
      artifactStorageRef?: string | null;
      producerVersion?: string;
      keyVersion?: number;
      privateKeyOverride?: Uint8Array;
      organizationIdOverride?: string;
      prevEventCommitmentOverride?: string;
      tamperSignature?: boolean;
    }

    /**
     * Signs a sequence of action-event definitions, computing
     * `prevEventCommitment`/`eventCommitment` sequentially PER `actionId`
     * (each `actionId` starts its own chain from genesis), mirroring
     * `protected-action-canonical.helper.ts` byte-for-byte:
     * `message = canonicalJson(signable) || prevEventCommitmentBytes`,
     * `eventCommitment = sha256(canonical || sigBytes)`.
     */
    function signActionEvents(
      defs: ActionEventDef[],
      orgId: string,
      defaultPrivateKey: Uint8Array,
    ): Array<Record<string, unknown>> {
      const lastCommitment = new Map<string, string>();
      const out: Array<Record<string, unknown>> = [];
      for (const def of defs) {
        const schemaVersion = def.schemaVersion ?? 0.1;
        const receivedAtIso = def.receivedAtIso ?? def.observedAtIso;
        const issuer = def.issuer ?? 'mcp-proof-edge';
        const issuerType = def.issuerType ?? 'system';
        const trustDomain = def.trustDomain ?? 'praesidia';
        const payload = def.payload === undefined ? {} : def.payload;
        const payloadCommitment = def.payloadCommitment ?? null;
        const dispatched = def.dispatched ?? false;
        const timeSource = def.timeSource ?? 'system';
        const permitNonce = def.permitNonce ?? null;
        const edgeVersion = def.edgeVersion ?? null;
        const adapterVersion = def.adapterVersion ?? null;
        const externalReceiptRef = def.externalReceiptRef ?? null;
        const artifactStorageRef = def.artifactStorageRef ?? null;
        const producerVersion = def.producerVersion ?? '1.0.0';
        const keyVersion = def.keyVersion ?? 1;
        const privateKey = def.privateKeyOverride ?? defaultPrivateKey;
        const signingOrgId = def.organizationIdOverride ?? orgId;

        const prevEventCommitment =
          def.prevEventCommitmentOverride ??
          lastCommitment.get(def.actionId) ??
          '0'.repeat(64);

        const signable = {
          organizationId: signingOrgId,
          actionId: def.actionId,
          actionSeq: String(def.actionSeq),
          eventType: def.eventType,
          schemaVersion: String(schemaVersion),
          issuerType,
          issuerId: issuer,
          trustDomain,
          timeSource,
          observedAt: def.observedAtIso,
          receivedAt: receivedAtIso,
          dispatched,
          permitNonce,
          payload,
          payloadCommitment,
          producerVersion,
          edgeVersion,
          adapterVersion,
          externalReceiptRef,
          artifactStorageRef,
          prevEventCommitment,
        };
        const canonical = canonicalJson(signable);
        const message = Buffer.concat([
          canonical,
          Buffer.from(prevEventCommitment, 'hex'),
        ]);
        let signature = signEd25519(message, privateKey);
        if (def.tamperSignature) {
          const bytes = Buffer.from(signature, 'base64');
          bytes[0] = (bytes[0]! + 1) % 256;
          signature = bytes.toString('base64');
        }
        const sigBytes = Buffer.from(signature, 'base64');
        const eventCommitment = sha256(
          Buffer.concat([canonical, sigBytes]),
        ).toString('hex');
        lastCommitment.set(def.actionId, eventCommitment);

        out.push({
          actionId: def.actionId,
          actionSeq: def.actionSeq,
          eventType: def.eventType,
          schemaVersion,
          observedAt: def.observedAtIso,
          receivedAt: receivedAtIso,
          issuer,
          trustDomain,
          payload,
          payloadCommitment,
          prevEventCommitment,
          signature,
          signatureAlgorithm: 'Ed25519',
          keyVersion,
          organizationId: signingOrgId,
          issuerType,
          dispatched,
          eventCommitment,
          producerVersion,
          timeSource,
          permitNonce,
          edgeVersion,
          adapterVersion,
          externalReceiptRef,
          artifactStorageRef,
        });
      }
      return out;
    }

    /**
     * Builds a full v5 bundle on top of the standard fixture rows/roots
     * (`buildFixtureBundle`), with `action-events.ndjson.gz` built from
     * `opts.events`. Mirrors `buildV4Bundle`'s structure.
     */
    function buildV5Bundle(opts: {
      events: ActionEventDef[];
      actionEventCountOverride?: number;
      evidenceGradeSummaryOverride?: Record<string, unknown>;
      captureScopeDigestOverride?: string;
      omitActionEventsFile?: boolean;
      versionOverride?: number;
      /** Force-include the three v5 manifest fields even when `versionOverride` is below 5 (models version-downgrade skew / an attacker bolting v5-only fields onto an older envelope). */
      forceIncludeV5Fields?: boolean;
      extraPublicKeys?: Record<string, unknown>;
      /** Post-signing mutation hook — applied to the wire event array right before serialization. */
      postSignEvents?: (events: Array<Record<string, unknown>>) => void;
      /** AV-0013 — v6 `evidencePrivacy` (given the manifest's `from`); default one FULL window on v6. Forced in on any version when set. */
      evidencePrivacy?: (from: string) => unknown;
      omitEvidencePrivacy?: boolean;
      /** Post-signing mutation of the manifest object (tamper tests). */
      postSignManifest?: (manifest: Record<string, unknown>) => void;
    }): { zip: Buffer; orgId: string } {
      const seed = Buffer.alloc(32, 7); // identical seed to buildFixtureBundle()
      const { privateKey, publicKey } = keypairFromSeed(seed);
      const base = buildFixtureBundle();
      const entries = readBundleEntries(base.zip);
      const originalManifest = JSON.parse(
        entries.get('manifest.json')!.toString('utf8'),
      ) as Record<string, unknown>;
      const orgId = originalManifest.orgId as string;
      const publicKeyB64 = Buffer.from(publicKey).toString('base64');

      const wireEvents = signActionEvents(opts.events, orgId, privateKey).sort(
        (a, b) =>
          a.actionId === b.actionId
            ? (a.actionSeq as number) - (b.actionSeq as number)
            : (a.actionId as string).localeCompare(b.actionId as string),
      );
      if (opts.postSignEvents) opts.postSignEvents(wireEvents);

      const version = opts.versionOverride ?? 5;
      const actionEventCount =
        opts.actionEventCountOverride ?? wireEvents.length;
      const captureScopeDigest =
        opts.captureScopeDigestOverride ??
        sha256(canonicalJson({ fixture: 'capture-scope' })).toString('hex');
      const evidenceGradeSummary = opts.evidenceGradeSummaryOverride ?? {
        A: 0,
        B: 0,
        C: 0,
        D: 0,
        enforcementMode: 'observe',
      };

      const manifestSans: Record<string, unknown> = {
        version,
        orgId,
        from: originalManifest.from,
        to: originalManifest.to,
        rowCount: originalManifest.rowCount,
        rootCount: originalManifest.rootCount,
        keyVersions: [
          {
            keyVersion: 1,
            publicKey: publicKeyB64,
            status: 'ACTIVE',
            revokedAt: null,
          },
        ],
        generatedAt: originalManifest.generatedAt,
        signatureAlgorithm: originalManifest.signatureAlgorithm,
      };
      if (version >= 3) {
        manifestSans.chainSeqCeiling = 4;
        manifestSans.chainSeqSnapshotAt = '2026-05-01T01:00:30.000Z';
      }
      if (version >= 4) {
        manifestSans.integrityCheckpointCount = 0;
      }
      if (version >= 5 || opts.forceIncludeV5Fields) {
        manifestSans.actionEventCount = actionEventCount;
        manifestSans.captureScopeDigest = captureScopeDigest;
        manifestSans.evidenceGradeSummary = evidenceGradeSummary;
      }
      if (opts.evidencePrivacy || (version >= 6 && !opts.omitEvidencePrivacy)) {
        const from = originalManifest.from as string;
        manifestSans.evidencePrivacy = opts.evidencePrivacy
          ? opts.evidencePrivacy(from)
          : { modes: [{ mode: 'FULL', effectiveFrom: from }], schemaVersion: 1 };
      }
      const manifestBytes = canonicalJson(manifestSans);
      const manifestSignature = signEd25519(manifestBytes, privateKey);
      const manifest: Record<string, unknown> = {
        ...manifestSans,
        signature: manifestSignature,
        signatureKeyVersion: 1,
      };
      opts.postSignManifest?.(manifest);

      const publicKeys: Record<string, unknown> = {
        '1': { publicKey: publicKeyB64, status: 'ACTIVE', revokedAt: null },
        ...(opts.extraPublicKeys ?? {}),
      };

      const actionEventsNdjson = Buffer.from(
        wireEvents.map((e) => JSON.stringify(e)).join('\n') +
          (wireEvents.length > 0 ? '\n' : ''),
        'utf8',
      );

      const zipEntries = [
        {
          name: 'manifest.json',
          data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
        },
        { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
        { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
        { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
        {
          name: 'public-keys.json',
          data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
        },
        { name: 'README.md', data: entries.get('README.md')! },
        {
          name: 'integrity-checkpoints.ndjson.gz',
          data: gzipDeterministic(Buffer.alloc(0)),
        },
      ];
      if (!opts.omitActionEventsFile) {
        zipEntries.push({
          name: 'action-events.ndjson.gz',
          data: gzipDeterministic(actionEventsNdjson),
        });
      }
      return { zip: writeZip(zipEntries), orgId };
    }

    const T0 = Date.UTC(2026, 4, 1, 0, 10, 0); // inside buildFixtureBundle()'s [from, to)

    /** A full happy-path action stream: proposed → authority → policy → permit issued → permit consumed → dispatched → caller result → closed SUCCEEDED. */
    function successfulActionEvents(actionId: string): ActionEventDef[] {
      const requestCommitment = 'a'.repeat(64);
      const permitId = 'permit-nonce-' + actionId;
      return [
        {
          actionId,
          actionSeq: 1,
          eventType: 'ACTION_PROPOSED',
          observedAtIso: isoSecond(T0, 0),
          payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
        },
        {
          actionId,
          actionSeq: 2,
          eventType: 'PERMIT_ISSUED',
          observedAtIso: isoSecond(T0, 1),
          issuer: 'permit-service',
          payload: { permitId, requestCommitment, exp: 9999999999 },
        },
        {
          actionId,
          actionSeq: 3,
          eventType: 'PERMIT_CONSUMED',
          observedAtIso: isoSecond(T0, 2),
          permitNonce: permitId,
          payload: {
            permitNonce: permitId,
            requestCommitment,
            destinationIdempotencyCommitment: null,
          },
        },
        {
          actionId,
          actionSeq: 4,
          eventType: 'DISPATCH_ATTEMPTED',
          observedAtIso: isoSecond(T0, 3),
          dispatched: true,
          payload: { requestCommitment, permitId, enforcementMode: 'observe' },
        },
        {
          actionId,
          actionSeq: 5,
          eventType: 'CALLER_RESULT_OBSERVED',
          observedAtIso: isoSecond(T0, 4),
          payload: { success: true, resultCommitment: 'b'.repeat(64) },
        },
        {
          actionId,
          actionSeq: 6,
          eventType: 'ACTION_CLOSED',
          observedAtIso: isoSecond(T0, 5),
          payload: { closure: 'SUCCEEDED', reason: 'EVIDENCED' },
        },
      ];
    }

    it('round-trips a genuine v5 bundle end to end — eight new components valid, targetAck not_present (AV-0008: no TARGET_ACKNOWLEDGED event)', async () => {
      const { zip } = buildV5Bundle({
        events: successfulActionEvents('aaaaaaaa-0000-7000-8000-000000000001'),
        evidenceGradeSummaryOverride: {
          A: 0,
          B: 0,
          C: 1,
          D: 0,
          enforcementMode: 'observe',
        },
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.status).toBe('valid');
      expect(report.actionEventChain.status).toBe('valid');
      expect(report.permitBinding.status).toBe('valid');
      expect(report.requestBinding.status).toBe('valid');
      expect(report.dispatchIntegrity.status).toBe('valid');
      expect(report.targetAck.status).toBe('not_present');
      expect(report.callerResult.status).toBe('valid');
      expect(report.closureLegality.status).toBe('valid');
      expect(report.evidenceGrade.status).toBe('valid');
      expect(report.actionCompleteness.status).toBe('valid');
      expect(report.bundle.actionEventsSeen).toBe(6);
    });

    // AV-0008 — the successful-action fixture carries no TARGET_ACKNOWLEDGED
    // event: targetAck checked 0 and must say so (not_present), while the
    // bundle as a whole, which does carry evidence, stays valid.
    it('AV-0008: a v5 bundle without target receipts reports targetAck not_present and the top level stays valid', async () => {
      const { zip } = buildV5Bundle({
        events: successfulActionEvents('aaaaaaaa-0000-7000-8000-000000000001'),
        evidenceGradeSummaryOverride: {
          A: 0,
          B: 0,
          C: 1,
          D: 0,
          enforcementMode: 'observe',
        },
      });
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.targetAck.status).toBe('not_present');
      expect(report.targetAck.checked).toBe(0);
      expect(report.targetAck.ok).toBe(false);
      expect(report.chain.status).toBe('valid');
      expect(report.status).toBe('valid');
      expect(report.ok).toBe(true);
    });

    it('a v1 bundle (buildFixtureBundle) reports every new component as unsupported, never dragging the verdict down', async () => {
      const { zip } = buildFixtureBundle();
      const report = await verifyBundle(zip, { noRekor: true });
      expect(report.status).toBe('valid');
      for (const c of [
        report.actionEventChain,
        report.permitBinding,
        report.requestBinding,
        report.dispatchIntegrity,
        report.targetAck,
        report.callerResult,
        report.closureLegality,
        report.evidenceGrade,
        report.actionCompleteness,
      ]) {
        expect(c.status).toBe('unsupported');
        expect(c.ok).toBe(false); // ok is DERIVED (status === 'valid'); unsupported !== valid
      }
    });

    describe('version negotiation (both directions)', () => {
      it('rejects a v4 manifest illegitimately carrying actionEventCount', async () => {
        const { zip } = buildV5Bundle({
          events: [],
          versionOverride: 4,
          forceIncludeV5Fields: true,
          omitActionEventsFile: true,
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.manifest.status).toBe('invalid');
        expect(report.manifest.reason).toMatch(
          /action_event_count_present_on_v4_manifest/,
        );
      });

      it('rejects a v5 manifest missing evidenceGradeSummary', async () => {
        const { privateKey } = keypairFromSeed(Buffer.alloc(32, 7));
        void privateKey;
        const base = buildV5Bundle({ events: [] });
        const entries = readBundleEntries(base.zip);
        const manifest = JSON.parse(
          entries.get('manifest.json')!.toString('utf8'),
        ) as Record<string, unknown>;
        delete manifest.evidenceGradeSummary;
        // Re-sign is unnecessary for THIS assertion: the missing-field check
        // in `verifyManifest` fires before signature verification runs.
        const zip = writeZip([
          {
            name: 'manifest.json',
            data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'),
          },
          { name: 'rows.ndjson.gz', data: entries.get('rows.ndjson.gz')! },
          { name: 'roots.ndjson.gz', data: entries.get('roots.ndjson.gz')! },
          { name: 'proofs.ndjson.gz', data: entries.get('proofs.ndjson.gz')! },
          { name: 'public-keys.json', data: entries.get('public-keys.json')! },
          { name: 'README.md', data: entries.get('README.md')! },
          {
            name: 'integrity-checkpoints.ndjson.gz',
            data: entries.get('integrity-checkpoints.ndjson.gz')!,
          },
          {
            name: 'action-events.ndjson.gz',
            data: entries.get('action-events.ndjson.gz')!,
          },
        ]);
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.manifest.status).toBe('invalid');
        expect(report.manifest.reason).toMatch(
          /evidence_grade_summary_missing_on_v5_manifest/,
        );
      });

      it('a v5 manifest declaring version >= 5 with NO action-events.ndjson.gz entry is a bundle-format error', async () => {
        const { zip } = buildV5Bundle({
          events: [],
          omitActionEventsFile: true,
        });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
          /missing required entry: action-events\.ndjson\.gz/,
        );
      });

      it('rejects a v5 manifest whose captureScopeDigest is not a sha256 digest', async () => {
        const { zip } = buildV5Bundle({
          events: [],
          captureScopeDigestOverride: 'not-a-digest',
        });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
          /manifest\.captureScopeDigest must be a lowercase sha256 hex digest/,
        );
      });
    });

    describe('actionEventChain', () => {
      it('rejects an action event signed under a REVOKED key (threat-model row #7, key-rotation-revocation)', async () => {
        const { zip } = buildV5Bundle({
          events: successfulActionEvents(
            'aaaaaaaa-0000-7000-8000-000000000002',
          ).map((e, i) => (i === 0 ? { ...e, keyVersion: 1 } : e)),
          extraPublicKeys: {},
        });
        const entries = readBundleEntries(zip);
        const publicKeys = JSON.parse(
          entries.get('public-keys.json')!.toString('utf8'),
        ) as Record<
          string,
          { publicKey: string; status: string; revokedAt: string | null }
        >;
        publicKeys['1']!.status = 'REVOKED';
        publicKeys['1']!.revokedAt = '2026-04-01T00:00:00.000Z';
        // Also mark REVOKED in the SIGNED manifest.keyVersions — otherwise
        // `keyBinding`'s cross-check (a pre-existing, unrelated component)
        // would fail FIRST and mask the assertion this test targets.
        const manifest = JSON.parse(
          entries.get('manifest.json')!.toString('utf8'),
        ) as Record<string, unknown> & {
          keyVersions: Array<{
            keyVersion: number;
            status?: string;
            revokedAt?: string | null;
          }>;
        };
        // manifest.keyVersions is inside the SIGNED preimage — leaving it
        // ACTIVE here (unsigned public-keys.json alone is REVOKED) is
        // sufficient: `verifyRowSignatures`'s sibling logic for action
        // events reads REVOKED status from `public-keys.json`, exactly
        // mirroring the existing row/root/checkpoint precedent.
        void manifest;
        const rebuilt = writeZip([
          ...[...entries.entries()]
            .filter(([name]) => name !== 'public-keys.json')
            .map(([name, data]) => ({ name, data })),
          {
            name: 'public-keys.json',
            data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8'),
          },
        ]);
        const report = await verifyBundle(rebuilt, {
          noRekor: true,
          allowLegacyUnattested: true,
        });
        expect(report.actionEventChain.status).toBe('invalid');
        expect(report.actionEventChain.reason).toMatch(/key_revoked/);
      });

      it("rejects an actionSeq gap within one actionId's stream (insertion — fabricated row mid-stream)", async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-000000000003',
        );
        // Skip actionSeq 3 entirely, as if an event were deleted/never
        // inserted, or as if a fabricated row were spliced in without
        // renumbering the tail — either way a gap.
        const gapped = events.filter((e) => e.actionSeq !== 3);
        const { zip } = buildV5Bundle({ events: gapped });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionEventChain.status).toBe('invalid');
        expect(report.actionEventChain.reason).toMatch(/action_event_seq_gap/);
      });

      it("rejects a tampered prevEventCommitment — manifests as a signature failure BY CONSTRUCTION, since prevEventCommitment is baked into the signed preimage (mirrors AUDIT-SDK-01's prev_row_hash binding for audit rows — an attacker cannot break the chain link without also invalidating the event's own signature)", async () => {
        const { zip } = buildV5Bundle({
          events: successfulActionEvents(
            'aaaaaaaa-0000-7000-8000-000000000004',
          ),
          postSignEvents: (evs) => {
            const target = evs.find((e) => e.actionSeq === 4)!;
            target.prevEventCommitment = 'f'.repeat(64);
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionEventChain.status).toBe('invalid');
        expect(report.actionEventChain.reason).toMatch(
          /event signature does not verify/,
        );
      });

      it('rejects a wire eventCommitment that does not match the signed event bytes', async () => {
        const { zip } = buildV5Bundle({
          events: successfulActionEvents(
            'aaaaaaaa-0000-7000-8000-00000000004c',
          ),
          postSignEvents: (evs) => {
            evs[evs.length - 1]!.eventCommitment = 'f'.repeat(64);
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionEventChain.status).toBe('invalid');
        expect(report.actionEventChain.reason).toMatch(
          /event_commitment_mismatch/,
        );
      });

      it('rejects an event type outside the closed producer vocabulary', async () => {
        const { zip } = buildV5Bundle({
          events: [
            {
              actionId: 'aaaaaaaa-0000-7000-8000-00000000004d',
              actionSeq: 1,
              eventType: 'FORGED_EVENT',
              observedAtIso: isoSecond(T0, 0),
              payload: {},
            },
          ],
        });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
          /invalid\/incomplete event/,
        );
      });

      it('accepts future subtypes in the producer-defined open COMPENSATION_ family', async () => {
        const { zip } = buildV5Bundle({
          events: [
            {
              actionId: 'aaaaaaaa-0000-7000-8000-00000000004e',
              actionSeq: 1,
              eventType: 'COMPENSATION_manual-repair.v2',
              observedAtIso: isoSecond(T0, 0),
              payload: { reason: 'operator-approved' },
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionEventChain.status).toBe('valid');
      });

      it('rejects a genesis (actionSeq 1) event that does not declare the all-zero prevEventCommitment', async () => {
        const { zip } = buildV5Bundle({
          events: [
            {
              actionId: 'aaaaaaaa-0000-7000-8000-000000000005',
              actionSeq: 1,
              eventType: 'ACTION_PROPOSED',
              observedAtIso: isoSecond(T0, 0),
              payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
              prevEventCommitmentOverride: 'e'.repeat(64),
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionEventChain.status).toBe('invalid');
        expect(report.actionEventChain.reason).toMatch(
          /genesis_prev_event_commitment_mismatch/,
        );
      });

      it('accepts a non-genesis first-seen event as an opaque out-of-range anchor (mid-range export boundary)', async () => {
        // actionSeq 4 as the FIRST event of this actionId present in the
        // bundle models a genuinely ranged export whose earlier events
        // (actionSeq 1-3) fall before [from, to) — mirrors BUGHUNT-SDK-02.
        const { zip } = buildV5Bundle({
          events: [
            {
              actionId: 'aaaaaaaa-0000-7000-8000-000000000006',
              actionSeq: 4,
              eventType: 'DISPATCH_ATTEMPTED',
              observedAtIso: isoSecond(T0, 3),
              dispatched: true,
              payload: {
                requestCommitment: 'a'.repeat(64),
                permitId: 'p1',
                enforcementMode: 'observe',
              },
              prevEventCommitmentOverride: 'deadbeef'.repeat(8),
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionEventChain.status).toBe('valid');
      });

      it('rejects a duplicate (actionId, actionSeq) pair (replay — a genuine signed event resubmitted out of context)', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-000000000007',
        );
        const { zip } = buildV5Bundle({
          events,
          postSignEvents: (evs) => {
            // Replay: append a byte-identical copy of the PERMIT_CONSUMED
            // event (actionSeq 3) — a genuinely valid, signed artifact
            // resubmitted verbatim, distinct from a reorder tamper.
            const consumed = evs.find((e) => e.actionSeq === 3)!;
            evs.push({ ...consumed });
          },
        });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
          /invalid\/duplicate event/,
        );
      });

      it('rejects an action event whose receivedAt precedes observedAt (threat-model row #6, clock-skew)', async () => {
        const { zip } = buildV5Bundle({
          events: [
            {
              actionId: 'aaaaaaaa-0000-7000-8000-000000000008',
              actionSeq: 1,
              eventType: 'ACTION_PROPOSED',
              observedAtIso: isoSecond(T0, 10),
              receivedAtIso: isoSecond(T0, 5), // before observedAt — impossible
              payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
            },
          ],
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionEventChain.status).toBe('invalid');
        expect(report.actionEventChain.reason).toMatch(/clock_skew/);
      });
    });

    describe('permitBinding', () => {
      it('rejects a permitNonce consumed by two distinct actionIds (threat-model row #1, permit-replay)', async () => {
        const sharedNonce = 'shared-permit-nonce';
        const a1 = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000a1',
        ).map((e) =>
          e.eventType === 'PERMIT_CONSUMED' || e.eventType === 'PERMIT_ISSUED'
            ? {
                ...e,
                ...(e.eventType === 'PERMIT_CONSUMED'
                  ? { permitNonce: sharedNonce }
                  : {}),
                payload: {
                  ...e.payload,
                  permitId: sharedNonce,
                  permitNonce: sharedNonce,
                },
              }
            : e,
        );
        const a2 = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000a2',
        ).map((e) =>
          e.eventType === 'PERMIT_CONSUMED' || e.eventType === 'PERMIT_ISSUED'
            ? {
                ...e,
                ...(e.eventType === 'PERMIT_CONSUMED'
                  ? { permitNonce: sharedNonce }
                  : {}),
                payload: {
                  ...e.payload,
                  permitId: sharedNonce,
                  permitNonce: sharedNonce,
                },
              }
            : e,
        );
        const { zip } = buildV5Bundle({ events: [...a1, ...a2] });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.permitBinding.status).toBe('invalid');
        expect(report.permitBinding.reason).toMatch(/permit_nonce_reused/);
      });

      it('rejects PERMIT_ISSUED/PERMIT_CONSUMED disagreeing on requestCommitment (D2 substitution)', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000b1',
        ).map((e) =>
          e.eventType === 'PERMIT_CONSUMED'
            ? {
                ...e,
                payload: { ...e.payload, requestCommitment: 'f'.repeat(64) },
              }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.permitBinding.status).toBe('invalid');
        expect(report.permitBinding.reason).toMatch(
          /permit_request_commitment_mismatch/,
        );
      });

      it('rejects a mismatch between the signed top-level permitNonce and its payload mirror', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000b2',
        ).map((e) =>
          e.eventType === 'PERMIT_CONSUMED'
            ? { ...e, permitNonce: 'different-signed-nonce' }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.permitBinding.status).toBe('invalid');
        expect(report.permitBinding.reason).toMatch(
          /permit_nonce_mirror_mismatch/,
        );
      });

      it('rejects one destination idempotency commitment used by two actionIds', async () => {
        const destinationCommitment = 'd'.repeat(64);
        const withDestinationCommitment = (actionId: string) =>
          successfulActionEvents(actionId).map((e) =>
            e.eventType === 'PERMIT_CONSUMED'
              ? {
                  ...e,
                  payload: {
                    ...e.payload,
                    destinationIdempotencyCommitment: destinationCommitment,
                  },
                }
              : e,
          );
        const { zip } = buildV5Bundle({
          events: [
            ...withDestinationCommitment(
              'aaaaaaaa-0000-7000-8000-0000000000b3',
            ),
            ...withDestinationCommitment(
              'aaaaaaaa-0000-7000-8000-0000000000b4',
            ),
          ],
          evidenceGradeSummaryOverride: {
            A: 0,
            B: 0,
            C: 2,
            D: 0,
            enforcementMode: 'observe',
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.permitBinding.status).toBe('invalid');
        expect(report.permitBinding.reason).toMatch(
          /destination_idempotency_reused/,
        );
      });
    });

    describe('requestBinding — threat-model row #2, commitment-mismatch (request substitution)', () => {
      it('rejects DISPATCH_ATTEMPTED and PERMIT_CONSUMED disagreeing on requestCommitment', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000c1',
        ).map((e) =>
          e.eventType === 'DISPATCH_ATTEMPTED'
            ? {
                ...e,
                payload: { ...e.payload, requestCommitment: 'f'.repeat(64) },
              }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.requestBinding.status).toBe('invalid');
        expect(report.requestBinding.reason).toMatch(/commitment_mismatch/);
      });

      it('rejects a consumed permit whose request commitment is missing', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000c2',
        ).map((e) =>
          e.eventType === 'PERMIT_CONSUMED'
            ? {
                ...e,
                payload: { ...e.payload, requestCommitment: null },
              }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.requestBinding.status).toBe('invalid');
        expect(report.requestBinding.reason).toMatch(
          /requestCommitment is missing/,
        );
      });
    });

    describe('dispatchIntegrity', () => {
      it('rejects a DISPATCH_ATTEMPTED event with dispatched: false', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000d1',
        ).map((e) =>
          e.eventType === 'DISPATCH_ATTEMPTED'
            ? { ...e, dispatched: false }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.dispatchIntegrity.status).toBe('invalid');
        expect(report.dispatchIntegrity.reason).toMatch(/dispatched: true/);
      });

      it('rejects a SUCCEEDED closure with no DISPATCH_ATTEMPTED event at all', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000d2',
        ).filter((e) => e.eventType !== 'DISPATCH_ATTEMPTED');
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.dispatchIntegrity.status).toBe('invalid');
        expect(report.dispatchIntegrity.reason).toMatch(
          /dispatch_evidence_missing/,
        );
      });

      it('rejects a DENIED (pre-dispatch-only) closure alongside a real DISPATCH_ATTEMPTED event', async () => {
        const actionId = 'aaaaaaaa-0000-7000-8000-0000000000d3';
        const events: ActionEventDef[] = [
          {
            actionId,
            actionSeq: 1,
            eventType: 'ACTION_PROPOSED',
            observedAtIso: isoSecond(T0, 0),
            payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
          },
          {
            actionId,
            actionSeq: 2,
            eventType: 'DISPATCH_ATTEMPTED',
            observedAtIso: isoSecond(T0, 1),
            dispatched: true,
            payload: {
              requestCommitment: 'a'.repeat(64),
              permitId: null,
              enforcementMode: 'observe',
            },
          },
          {
            actionId,
            actionSeq: 3,
            eventType: 'ACTION_CLOSED',
            observedAtIso: isoSecond(T0, 2),
            payload: { closure: 'DENIED', reason: 'POLICY' },
          },
        ];
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.dispatchIntegrity.status).toBe('invalid');
        expect(report.dispatchIntegrity.reason).toMatch(
          /dispatch_evidence_contradiction/,
        );
      });
    });

    describe('targetAck — threat-model row #8, target-ack-mismatch', () => {
      function actionWithTargetAck(
        actionId: string,
        ackPayload: Record<string, unknown>,
      ): ActionEventDef[] {
        return [
          ...successfulActionEvents(actionId).filter(
            (e) => e.eventType !== 'CALLER_RESULT_OBSERVED',
          ),
          {
            actionId,
            actionSeq: 5,
            eventType: 'TARGET_ACKNOWLEDGED',
            observedAtIso: isoSecond(T0, 4),
            payload: ackPayload,
          },
        ].map((e) =>
          e.eventType === 'ACTION_CLOSED' ? { ...e, actionSeq: 6 } : e,
        );
      }

      it.each(['valid', 'missing-pin', 'wrong-pin', 'changed-result', 'changed-request', 'changed-signature', 'commitments-only', 'commitments-wrong-key', 'commitments-changed-result', 'legacy-missing-result', 'mixed-content'] as const)('independently verifies HTTP target receipts: %s', async mode => {
        const actionId = 'aaaaaaaa-0000-7000-8000-000000000099';
        const organizationId = '00000000-0000-0000-0000-000000000001';
        const keys = crypto.generateKeyPairSync('ed25519');
        const publicKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
        const request = { version: 'praesidia.http-request.v1' as const, targetId: 'bank', destination: 'https://target.example/credit', targetKeyFingerprint: httpTargetKeyFingerprint(publicKeyPem), method: 'POST' as const, contentType: 'application/json' as const, body: { amount: '5.00' } };
        const requestCommitment = httpRequestCommitment(request);
        const result = { applied: '5.00' };
        const resultCommitment = jcsCommitment(result);
        const statement = { version: 'praesidia.http-receipt.v1', organizationId, actionId, targetId: 'bank', keyId: 'key-1', requestCommitment, resultCommitment, effect: 'succeeded', issuedAt: isoSecond(T0, 4), targetTransactionId: 'credit-1' };
        const signature = crypto.sign(null, jcsCanonicalize(statement), keys.privateKey).toString('base64');
        const events: ActionEventDef[] = successfulActionEvents(actionId).map(event => ({ ...event,
          actionSeq: event.eventType === 'ACTION_CLOSED' ? 7 : event.actionSeq,
          payload: event.eventType === 'ACTION_PROPOSED' ? { protocol: 'http-receipt', actionClass: 'http:POST', request: mode === 'changed-request' ? { ...request, body: { amount: '500.00' } } : request, requestCommitment }
            : event.eventType === 'CALLER_RESULT_OBSERVED' ? { observer: 'praesidia-http-edge', success: true, outcomeClass: 'completed_success', result: mode === 'changed-result' ? { applied: '999.00' } : result, resultCommitment, requestCommitment }
            : { ...event.payload, ...(event.payload?.requestCommitment ? { requestCommitment } : {}) },
        }));
        events.push({ actionId, actionSeq: 6, eventType: 'TARGET_ACKNOWLEDGED', observedAtIso: isoSecond(T0, 4), payload: { grade: 'A', targetSignature: signature, signatureAlgorithm: 'Ed25519', requestCommitment, resultCommitment, receipt: { statement, signature: mode === 'changed-signature' ? 'A'.repeat(86) + '==' : signature } } });
        if (['commitments-only', 'commitments-wrong-key', 'commitments-changed-result', 'mixed-content'].includes(mode)) {
          const proposal = events.find(event => event.eventType === 'ACTION_PROPOSED')!;
          proposal.payload = { protocol: 'http-receipt', actionClass: 'http:POST', evidenceContent: 'commitments-only.v1', targetIdentity: 'bank', targetKeyFingerprint: mode === 'commitments-wrong-key' ? '0'.repeat(64) : request.targetKeyFingerprint, requestCommitment };
          const observed = events.find(event => event.eventType === 'CALLER_RESULT_OBSERVED')!;
          observed.payload = { observer: 'praesidia-http-edge', success: true, outcomeClass: 'completed_success', evidenceContent: 'commitments-only.v1', resultCommitment: mode === 'commitments-changed-result' ? '0'.repeat(64) : resultCommitment, requestCommitment,
            ...(mode === 'mixed-content' ? { result } : {}) };
        }
        if (mode === 'legacy-missing-result') delete events.find(event => event.eventType === 'CALLER_RESULT_OBSERVED')!.payload!.result;
        const { zip } = buildV5Bundle({ events: events.sort((a, b) => a.actionSeq - b.actionSeq), evidenceGradeSummaryOverride: { A: 1, B: 0, C: 0, D: 0, enforcementMode: 'observe' } });
        const report = await verifyBundle(zip, { noRekor: true, ...(mode !== 'missing-pin' ? { targetPublicKeys: { [`${organizationId}:bank:key-1`]: mode === 'wrong-pin' ? crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString() : publicKeyPem } } : {}) });
        expect(report.targetAck.status).toBe(['valid', 'commitments-only'].includes(mode) ? 'valid' : 'invalid');
        expect(report.evidenceGrade.status).toBe(['valid', 'commitments-only'].includes(mode) ? 'valid' : 'invalid');
        expect(report.status, JSON.stringify(report)).toBe(['valid', 'commitments-only'].includes(mode) ? 'valid' : 'invalid');
      });

      it('rejects a grade-A TARGET_ACKNOWLEDGED claim with no targetSignature', async () => {
        const events = actionWithTargetAck(
          'aaaaaaaa-0000-7000-8000-0000000000e1',
          {
            grade: 'A',
            targetId: 't1',
            authoritativeState: 'succeeded',
            observedAt: isoSecond(T0, 4),
            adapterVersion: '1.0.0',
          },
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.targetAck.status).toBe('invalid');
        expect(report.targetAck.reason).toMatch(
          /target_ack_grade_a_missing_signature/,
        );
      });

      describe('late signed HTTP receipt reconciliation', () => {
        function lateReceipt(effect: 'succeeded' | 'partial' | 'failed_no_effect' | 'unknown' = 'succeeded') {
          const actionId = 'aaaaaaaa-0000-7000-8000-00000000009a';
          const organizationId = '00000000-0000-0000-0000-000000000001';
          const keys = crypto.generateKeyPairSync('ed25519');
          const pin = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
          const request = { version: 'praesidia.http-request.v1' as const, targetId: 'bank',
            destination: 'https://target.example/credit', targetKeyFingerprint: httpTargetKeyFingerprint(pin),
            method: 'POST' as const, contentType: 'application/json' as const, body: { amount: '5.00' } };
          const requestCommitment = httpRequestCommitment(request);
          const result = { applied: effect === 'partial' ? '2.00' : '5.00' };
          const resultCommitment = jcsCommitment(result);
          // The receipt is issued during the original attempt, one second after
          // the sweeper closes unknown, and observed immediately. Reconciliation
          // does not extend the producer's five-minute receipt freshness window.
          const statement = { version: 'praesidia.http-receipt.v1', organizationId, actionId,
            targetId: 'bank', keyId: 'key-1', requestCommitment, resultCommitment, effect,
            issuedAt: isoSecond(T0, 11), targetTransactionId: 'credit-late-1' };
          const receipt = { statement, signature: crypto.sign(null, jcsCanonicalize(statement), keys.privateKey).toString('base64') };
          const closure = { succeeded: 'SUCCEEDED', partial: 'PARTIAL', failed_no_effect: 'FAILED_NO_EFFECT', unknown: 'OUTCOME_UNKNOWN' }[effect];
          const events: ActionEventDef[] = successfulActionEvents(actionId).slice(0, 4).map(event => ({ ...event,
            payload: event.eventType === 'ACTION_PROPOSED'
              ? { protocol: 'http-receipt', actionClass: 'http:POST', evidenceContent: 'commitments-only.v1',
                  targetIdentity: request.targetId, targetKeyFingerprint: request.targetKeyFingerprint, requestCommitment }
              : { ...event.payload, requestCommitment },
          }));
          events.push(
            { actionId, actionSeq: 5, eventType: 'ACTION_CLOSED', observedAtIso: isoSecond(T0, 10),
              payload: { closure: 'OUTCOME_UNKNOWN', reason: 'TIMEOUT', evidenceGrade: 'C' } },
            { actionId, actionSeq: 6, eventType: 'TARGET_ACKNOWLEDGED', observedAtIso: isoSecond(T0, 11),
              payload: { grade: 'A', targetSignature: receipt.signature, signatureAlgorithm: 'Ed25519', requestCommitment, resultCommitment, receipt } },
            { actionId, actionSeq: 7, eventType: 'CALLER_RESULT_OBSERVED', observedAtIso: isoSecond(T0, 12),
              payload: { observer: 'praesidia-http-edge', evidenceContent: 'commitments-only.v1',
                success: effect === 'succeeded', outcomeClass: effect === 'succeeded' ? 'completed_success' : 'completed_with_error',
                requestCommitment, resultCommitment } },
            { actionId, actionSeq: 8, eventType: 'OUTCOME_RECONCILED', observedAtIso: isoSecond(T0, 13),
              payload: { toClosure: closure, reason: effect === 'unknown' ? 'TIMEOUT' : 'EVIDENCED', evidenceGrade: 'A', outcomeReason: 'target_signed_assertion' } },
          );
          const verify = async () => {
            const { zip } = buildV5Bundle({ events: events.map((event, index) => ({ ...event, actionSeq: index + 1 })),
              evidenceGradeSummaryOverride: { A: 1, B: 0, C: 0, D: 0, enforcementMode: 'observe' } });
            return verifyBundle(zip, { noRekor: true, targetPublicKeys: { [`${organizationId}:bank:key-1`]: pin } });
          };
          return { events, verify, receipt, keys, request, result, requestCommitment, resultCommitment };
        }

        it.each(['succeeded', 'partial', 'failed_no_effect', 'unknown'] as const)('accepts a signed %s receipt after an honest unknown closure', async effect => {
          const report = await lateReceipt(effect).verify();
          expect(report.status, JSON.stringify(report)).toBe('valid');
          expect(report.actionEventChain.status).toBe('valid');
          expect(report.permitBinding.status).toBe('valid');
          expect(report.requestBinding.status).toBe('valid');
          expect(report.closureLegality.status).toBe('valid');
          expect(report.targetAck.status).toBe('valid');
          expect(report.evidenceGrade.status).toBe('valid');
        });

        it('accepts incomplete → unknown → partial with the legacy body-bearing receipt evidence', async () => {
          const fixture = lateReceipt('partial');
          fixture.events[4]!.payload!.closure = 'EVIDENCE_INCOMPLETE';
          fixture.events.splice(5, 0, { ...fixture.events[4]!, eventType: 'OUTCOME_RECONCILED',
            payload: { toClosure: 'OUTCOME_UNKNOWN', reason: 'TIMEOUT' } });
          fixture.events[0]!.payload = { protocol: 'http-receipt', actionClass: 'http:POST', request: fixture.request, requestCommitment: fixture.requestCommitment };
          const caller = fixture.events.find(event => event.eventType === 'CALLER_RESULT_OBSERVED')!;
          delete caller.payload!.evidenceContent;
          caller.payload!.result = fixture.result;
          const report = await fixture.verify();
          expect(report.status, JSON.stringify(report)).toBe('valid');
          expect(report.targetAck.status).toBe('valid');
          expect(report.evidenceGrade.status).toBe('valid');
        });

        it('matches the late receipt to its result even when a prior timeout observation exists', async () => {
          const fixture = lateReceipt();
          fixture.events.splice(4, 0, { ...fixture.events[6]!, observedAtIso: isoSecond(T0, 9),
            payload: { ...fixture.events[6]!.payload, success: false, outcomeClass: 'no_response_received',
              resultCommitment: jcsCommitment({ error: 'timeout' }) } });
          const report = await fixture.verify();
          expect(report.status, JSON.stringify(report)).toBe('valid');
          expect(report.targetAck.status).toBe('valid');
          expect(report.evidenceGrade.status).toBe('valid');
        });

        it('preserves older reconciliation payloads that omitted the optional reason', async () => {
          const fixture = lateReceipt();
          delete fixture.events[7]!.payload!.reason;
          const report = await fixture.verify();
          expect(report.status, JSON.stringify(report)).toBe('valid');
          expect(report.closureLegality.status).toBe('valid');
          expect(report.targetAck.status).toBe('valid');
        });

        it.each(['determined-overwrite', 'double-initial-close', 'missing-initial-close', 'malformed-target',
          'contradictory-reason', 'malformed-reason', 'unknown-reason', 'illegal-intermediate', 'receipt-after-final-close',
          'caller-after-final-close', 'unknown-receipt-for-success', 'substituted-request',
          'changed-signature', 'invalid-issued-at', 'invalid-event-signature'] as const)('rejects %s despite an otherwise genuine signed target receipt', async mode => {
          const fixture = lateReceipt(mode === 'unknown-receipt-for-success' ? 'unknown' : 'partial');
          const initial = fixture.events[4]!;
          const ack = fixture.events[5]!;
          const caller = fixture.events[6]!;
          const reconciled = fixture.events[7]!;
          if (mode === 'determined-overwrite') {
            // Make the original determined closure independently legal, then
            // attempt to overwrite it with the genuine late partial receipt.
            fixture.events.splice(4, 0, { ...caller, observedAtIso: isoSecond(T0, 9),
              payload: { success: true, outcomeClass: 'completed_success', resultCommitment: fixture.resultCommitment } });
            initial.payload = { closure: 'SUCCEEDED', reason: 'EVIDENCED' };
          } else if (mode === 'double-initial-close') {
            reconciled.eventType = 'ACTION_CLOSED';
            reconciled.payload = { closure: 'PARTIAL', reason: 'EVIDENCED' };
          } else if (mode === 'missing-initial-close') fixture.events.splice(4, 1);
          else if (mode === 'malformed-target') reconciled.payload!.toClosure = 42;
          else if (mode === 'contradictory-reason') reconciled.payload!.reason = 'TIMEOUT';
          else if (mode === 'malformed-reason') reconciled.payload!.reason = { reason: 'EVIDENCED' };
          else if (mode === 'unknown-reason') reconciled.payload!.reason = 'constructor';
          else if (mode === 'illegal-intermediate') fixture.events.splice(5, 0, { ...initial,
            eventType: 'OUTCOME_RECONCILED', payload: { toClosure: 'DENIED', reason: 'POLICY' } });
          else if (mode === 'receipt-after-final-close') {
            fixture.events.splice(5, 1);
            fixture.events.push(ack);
          } else if (mode === 'caller-after-final-close') {
            fixture.events.splice(6, 1);
            fixture.events.push(caller);
          }
          else if (mode === 'unknown-receipt-for-success') reconciled.payload = { toClosure: 'SUCCEEDED', reason: 'EVIDENCED' };
          else if (mode === 'substituted-request') fixture.events[0]!.payload!.requestCommitment = 'f'.repeat(64);
          else if (mode === 'changed-signature') {
            fixture.receipt.signature = 'A'.repeat(86) + '==';
            ack.payload!.targetSignature = fixture.receipt.signature;
          } else if (mode === 'invalid-issued-at') {
            // Even re-signing a noncanonical timestamp must not make it valid.
            fixture.receipt.statement.issuedAt = '2026-05-01';
            fixture.receipt.signature = crypto.sign(null, jcsCanonicalize(fixture.receipt.statement), fixture.keys.privateKey).toString('base64');
            ack.payload!.targetSignature = fixture.receipt.signature;
          } else if (mode === 'invalid-event-signature') reconciled.tamperSignature = true;
          const report = await fixture.verify();
          expect(report.status, JSON.stringify(report)).toBe('invalid');
          if (mode === 'invalid-event-signature') expect(report.actionEventChain.status).toBe('invalid');
          else {
            expect(report.targetAck.status).toBe('invalid');
            expect(report.evidenceGrade.status).toBe('invalid');
          }
          if (mode === 'determined-overwrite') expect(report.closureLegality.reason).toMatch(/illegal_reconciliation/);
          if (mode === 'double-initial-close') expect(report.closureLegality.reason).toMatch(/multiple_action_closed/);
          if (mode.includes('reason')) expect(report.closureLegality.reason).toMatch(/closure_reason_mismatch/);
        });
      });

      it('rejects a grade-B TARGET_ACKNOWLEDGED claim with destinationAuthenticated !== true', async () => {
        const events = actionWithTargetAck(
          'aaaaaaaa-0000-7000-8000-0000000000e2',
          {
            grade: 'B',
            targetId: 't1',
            authoritativeState: 'succeeded',
            observedAt: isoSecond(T0, 4),
            adapterVersion: '1.0.0',
            edgeAttestation: 'attestation-bytes',
            destinationAuthenticated: false,
          },
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.targetAck.status).toBe('invalid');
        expect(report.targetAck.reason).toMatch(
          /target_ack_grade_b_missing_attestation/,
        );
      });

      it('accepts a well-formed grade-C TARGET_ACKNOWLEDGED claim', async () => {
        const events = actionWithTargetAck(
          'aaaaaaaa-0000-7000-8000-0000000000e3',
          {
            grade: 'C',
            targetId: null,
            authoritativeState: 'succeeded',
            observedAt: isoSecond(T0, 4),
            adapterVersion: '1.0.0',
          },
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.targetAck.status).toBe('valid');
      });
    });

    describe('callerResult — threat-model row #9, caller-result-forgery', () => {
      it('rejects a CALLER_RESULT_OBSERVED event whose payload.success is not a boolean', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000f1',
        ).map((e) =>
          e.eventType === 'CALLER_RESULT_OBSERVED'
            ? {
                ...e,
                payload: { success: 'yes', resultCommitment: 'b'.repeat(64) },
              }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.callerResult.status).toBe('invalid');
        expect(report.callerResult.reason).toMatch(
          /payload\.success must be a boolean/,
        );
      });

      it('rejects a CALLER_RESULT_OBSERVED event with a malformed resultCommitment', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000f2',
        ).map((e) =>
          e.eventType === 'CALLER_RESULT_OBSERVED'
            ? { ...e, payload: { success: true, resultCommitment: 'not-hex' } }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.callerResult.status).toBe('invalid');
        expect(report.callerResult.reason).toMatch(/resultCommitment/);
      });
    });

    describe('redaction — threat-model row #10, redaction-completeness', () => {
      it('a legitimately redacted CALLER_RESULT_OBSERVED (payload: null, payloadCommitment present) verifies as incomplete, not invalid — exit code 3', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000g1',
        ).map((e) =>
          e.eventType === 'CALLER_RESULT_OBSERVED'
            ? { ...e, payload: null, payloadCommitment: 'c'.repeat(64) }
            : e,
        );
        const { zip } = buildV5Bundle({
          events,
          evidenceGradeSummaryOverride: {
            A: 0,
            B: 0,
            C: 1,
            D: 0,
            enforcementMode: 'observe',
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.callerResult.status).toBe('incomplete');
        expect(report.callerResult.ok).toBe(false);
        expect(report.status).toBe('incomplete');
      });

      it('an illegitimately stripped event (payload: null AND payloadCommitment: null) is a structural bundle-format error', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000g2',
        ).map((e) =>
          e.eventType === 'CALLER_RESULT_OBSERVED'
            ? { ...e, payload: null, payloadCommitment: null }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
          /invalid\/incomplete event/,
        );
      });
    });

    describe('AV-0013 — manifest v6 evidence privacy mode', () => {
      const BASE = ['chain_integrity', 'signatures', 'ordering', 'commitment_binding'];
      const CONTENT = ['content_equality', 'target_ack_body'];
      const REDUCED_AT = isoSecond(T0, -5 * 60); // 00:05:00, before every successfulActionEvents() event
      const metadataOnly = (from: string) => ({
        modes: [
          { mode: 'FULL', effectiveFrom: from },
          { mode: 'METADATA_ONLY', effectiveFrom: REDUCED_AT },
        ],
        schemaVersion: 1,
      });
      const withNullCallerResult = (id: string) =>
        successfulActionEvents(id).map((e) =>
          e.eventType === 'CALLER_RESULT_OBSERVED'
            ? { ...e, payload: null, payloadCommitment: 'c'.repeat(64) }
            : e,
        );
      const gradeC = { A: 0, B: 0, C: 1, D: 0, enforcementMode: 'observe' };

      it('a v6 METADATA_ONLY bundle keeps the incomplete verdict, annotates the reason, and lists what is and is not provable', async () => {
        const { zip } = buildV5Bundle({
          versionOverride: 6,
          events: withNullCallerResult('aaaaaaaa-0000-7000-8000-0000000000p1'),
          evidenceGradeSummaryOverride: gradeC,
          evidencePrivacy: metadataOnly,
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.manifest.status).toBe('valid');
        expect(report.callerResult.status).toBe('incomplete');
        expect(report.callerResult.reason).toBe('evidence_privacy_mode:METADATA_ONLY');
        expect(report.status).toBe('incomplete');
        expect(report.ok).toBe(false);
        const ep = report.evidencePrivacy;
        expect(ep.declared).toBe(true);
        expect(ep.schemaVersion).toBe(1);
        expect(ep.modes).toEqual([
          { mode: 'FULL', effectiveFrom: report.bundle.from, effectiveTo: REDUCED_AT, proven: [...BASE, ...CONTENT], notProvable: [] },
          { mode: 'METADATA_ONLY', effectiveFrom: REDUCED_AT, effectiveTo: report.bundle.to, proven: BASE, notProvable: CONTENT },
        ]);
        expect(ep.payloadAbsences).toEqual([
          {
            event: 'aaaaaaaa-0000-7000-8000-0000000000p1#5',
            eventType: 'CALLER_RESULT_OBSERVED',
            receivedAt: isoSecond(T0, 4),
            annotation: 'evidence_privacy_mode:METADATA_ONLY',
          },
        ]);
        const text = formatEvidencePrivacyLines(ep).join('\n');
        expect(text).toMatch(/METADATA_ONLY .*not provable: content_equality, target_ack_body/);
        expect(text).toMatch(/#5 CALLER_RESULT_OBSERVED: evidence_privacy_mode:METADATA_ONLY/);
      });

      it('a v6 bundle with full payloads under a declared reduced mode still verifies valid', async () => {
        const { zip } = buildV5Bundle({
          versionOverride: 6,
          events: successfulActionEvents('aaaaaaaa-0000-7000-8000-0000000000p2'),
          evidenceGradeSummaryOverride: gradeC,
          evidencePrivacy: metadataOnly,
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.status).toBe('valid');
        expect(report.evidencePrivacy.payloadAbsences).toEqual([]);
      });

      it('a v5 bundle is unchanged and reads as FULL (undeclared), claiming no content equality', async () => {
        const { zip } = buildV5Bundle({
          events: withNullCallerResult('aaaaaaaa-0000-7000-8000-0000000000p3'),
          evidenceGradeSummaryOverride: gradeC,
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.manifest.status).toBe('valid');
        expect(report.callerResult.status).toBe('incomplete');
        expect(report.callerResult.reason).toBeUndefined();
        expect(report.status).toBe('incomplete');
        expect(report.evidencePrivacy).toEqual({
          declared: false,
          schemaVersion: null,
          modes: [
            { mode: 'FULL', effectiveFrom: report.bundle.from, effectiveTo: report.bundle.to, proven: BASE, notProvable: CONTENT },
          ],
          payloadAbsences: [
            {
              event: 'aaaaaaaa-0000-7000-8000-0000000000p3#5',
              eventType: 'CALLER_RESULT_OBSERVED',
              receivedAt: isoSecond(T0, 4),
              annotation: 'undeclared_payload_absence',
            },
          ],
        });
        expect(formatEvidencePrivacyLines(report.evidencePrivacy).join('\n')).toMatch(/FULL \(undeclared\)/);
      });

      it('a null payload outside any declared reduced window is annotated undeclared_payload_absence, not invalid', async () => {
        const { zip } = buildV5Bundle({
          versionOverride: 6,
          events: withNullCallerResult('aaaaaaaa-0000-7000-8000-0000000000p4'),
          evidenceGradeSummaryOverride: gradeC,
          evidencePrivacy: (from) => ({
            modes: [
              { mode: 'FULL', effectiveFrom: from },
              { mode: 'METADATA_ONLY', effectiveFrom: isoSecond(T0, 30 * 60) },
            ],
            schemaVersion: 1,
          }),
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.callerResult.status).toBe('incomplete');
        expect(report.callerResult.reason).toBeUndefined();
        expect(report.status).toBe('incomplete');
        expect(report.evidencePrivacy.payloadAbsences.map((a) => a.annotation)).toEqual([
          'undeclared_payload_absence',
        ]);
      });

      it('evidencePrivacy is inside the signed preimage: a post-signing mode edit fails the manifest', async () => {
        const { zip } = buildV5Bundle({
          versionOverride: 6,
          events: successfulActionEvents('aaaaaaaa-0000-7000-8000-0000000000p5'),
          postSignManifest: (m) => {
            (m.evidencePrivacy as { modes: Array<{ mode: string }> }).modes[0]!.mode = 'METADATA_ONLY';
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.manifest.status).toBe('invalid');
        expect(report.manifest.reason).toBe('manifest signature does not verify');
        expect(report.status).toBe('invalid');
        expect(report.evidencePrivacy.declared).toBe(false);
      });

      it('rejects evidencePrivacy on a v5 manifest and its absence on a v6 manifest', async () => {
        const onV5 = await verifyBundle(
          buildV5Bundle({ events: [], evidencePrivacy: metadataOnly }).zip,
          { noRekor: true },
        );
        expect(onV5.manifest.reason).toMatch(/^evidence_privacy_present_on_v5_manifest/);
        const missing = await verifyBundle(
          buildV5Bundle({ events: [], versionOverride: 6, omitEvidencePrivacy: true }).zip,
          { noRekor: true },
        );
        expect(missing.manifest.reason).toMatch(/^evidence_privacy_missing_on_v6_manifest/);
      });

      it.each([
        ['an unknown mode', (f: string) => ({ modes: [{ mode: 'PARTIAL', effectiveFrom: f }], schemaVersion: 1 })],
        ['an empty timeline', () => ({ modes: [], schemaVersion: 1 })],
        ['a first window not starting at manifest.from', () => ({ modes: [{ mode: 'FULL', effectiveFrom: REDUCED_AT }], schemaVersion: 1 })],
        ['a descending timeline', (f: string) => ({ modes: [{ mode: 'FULL', effectiveFrom: f }, { mode: 'REDACTED', effectiveFrom: isoSecond(T0, 60) }, { mode: 'FULL', effectiveFrom: REDUCED_AT }], schemaVersion: 1 })],
        ['a change at or after manifest.to', (f: string) => ({ modes: [{ mode: 'FULL', effectiveFrom: f }, { mode: 'REDACTED', effectiveFrom: '2027-01-01T00:00:00.000Z' }], schemaVersion: 1 })],
        ['an unknown key', (f: string) => ({ modes: [{ mode: 'FULL', effectiveFrom: f }], schemaVersion: 1, note: 'x' })],
        ['a non-integer schemaVersion', (f: string) => ({ modes: [{ mode: 'FULL', effectiveFrom: f }], schemaVersion: '1' })],
      ])('rejects %s as a bundle-format error', async (_name, evidencePrivacy) => {
        const { zip } = buildV5Bundle({ events: [], versionOverride: 6, evidencePrivacy });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(/manifest\.evidencePrivacy/);
      });

      it('rejects an evidencePrivacy schemaVersion this build does not know (upgrade the verifier)', async () => {
        const { zip } = buildV5Bundle({
          events: [],
          versionOverride: 6,
          evidencePrivacy: (f) => ({ modes: [{ mode: 'FULL', effectiveFrom: f }], schemaVersion: 2 }),
        });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(/evidencePrivacy schemaVersion 2 .*upgrade the verifier/);
      });
    });

    describe('closureLegality — the centerpiece (D7, threat-model row #5 crash-window-recovery)', () => {
      it("a bundle claiming FAILED_NO_EFFECT with reason TIMEOUT verifies as invalid (D7's hard rule)", async () => {
        const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h1';
        const events: ActionEventDef[] = [
          {
            actionId,
            actionSeq: 1,
            eventType: 'ACTION_PROPOSED',
            observedAtIso: isoSecond(T0, 0),
            payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
          },
          {
            actionId,
            actionSeq: 2,
            eventType: 'DISPATCH_ATTEMPTED',
            observedAtIso: isoSecond(T0, 1),
            dispatched: true,
            payload: {
              requestCommitment: 'a'.repeat(64),
              permitId: null,
              enforcementMode: 'observe',
            },
          },
          {
            actionId,
            actionSeq: 3,
            eventType: 'ACTION_CLOSED',
            observedAtIso: isoSecond(T0, 100),
            // A post-dispatch timeout with NO caller result / target ack —
            // reconciliation would legitimately produce OUTCOME_UNKNOWN,
            // never FAILED_NO_EFFECT (D7's own worker never constructs
            // this transition — this fixture models a forged/buggy
            // producer attempting it anyway).
            payload: {
              closure: 'FAILED_NO_EFFECT',
              reason: 'TIMEOUT',
              attemptCount: 3,
            },
          },
        ];
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.closureLegality.status).toBe('invalid');
        expect(report.closureLegality.reason).toMatch(
          /closure_reason_mismatch/,
        );
        expect(report.status).toBe('invalid');
      });

      it('a bundle claiming FAILED_NO_EFFECT with reason EVIDENCED but NO actual evidencing event verifies as invalid (derive, do not believe)', async () => {
        const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h2';
        const events: ActionEventDef[] = [
          {
            actionId,
            actionSeq: 1,
            eventType: 'ACTION_PROPOSED',
            observedAtIso: isoSecond(T0, 0),
            payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
          },
          {
            actionId,
            actionSeq: 2,
            eventType: 'DISPATCH_ATTEMPTED',
            observedAtIso: isoSecond(T0, 1),
            dispatched: true,
            payload: {
              requestCommitment: 'a'.repeat(64),
              permitId: null,
              enforcementMode: 'observe',
            },
          },
          {
            actionId,
            actionSeq: 3,
            eventType: 'ACTION_CLOSED',
            observedAtIso: isoSecond(T0, 2),
            // Declares EVIDENCED (passes the reason/closure table) but no
            // TARGET_ACKNOWLEDGED/CALLER_RESULT_OBSERVED event exists
            // anywhere in this actionId's stream — the deeper check.
            payload: {
              closure: 'FAILED_NO_EFFECT',
              reason: 'EVIDENCED',
              resultCommitment: null,
            },
          },
        ];
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.closureLegality.status).toBe('invalid');
        expect(report.closureLegality.reason).toMatch(
          /closure_lacks_evidencing_event/,
        );
      });

      it('a genuine OUTCOME_UNKNOWN via reason TIMEOUT verifies as valid (the honest crash-window-recovery outcome)', async () => {
        const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h3';
        const events: ActionEventDef[] = [
          {
            actionId,
            actionSeq: 1,
            eventType: 'ACTION_PROPOSED',
            observedAtIso: isoSecond(T0, 0),
            payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
          },
          {
            actionId,
            actionSeq: 2,
            eventType: 'DISPATCH_ATTEMPTED',
            observedAtIso: isoSecond(T0, 1),
            dispatched: true,
            payload: {
              requestCommitment: 'a'.repeat(64),
              permitId: null,
              enforcementMode: 'observe',
            },
          },
          {
            actionId,
            actionSeq: 3,
            eventType: 'ACTION_CLOSED',
            observedAtIso: isoSecond(T0, 100),
            payload: {
              closure: 'OUTCOME_UNKNOWN',
              reason: 'TIMEOUT',
              attemptCount: 3,
            },
          },
        ];
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.closureLegality.status).toBe('valid');
      });

      it('rejects an illegal reconciliation FROM a terminal (non-reconcilable) closure', async () => {
        const events = [
          ...successfulActionEvents('aaaaaaaa-0000-7000-8000-0000000000h4'),
          {
            actionId: 'aaaaaaaa-0000-7000-8000-0000000000h4',
            actionSeq: 7,
            eventType: 'OUTCOME_RECONCILED',
            observedAtIso: isoSecond(T0, 6),
            payload: { toClosure: 'PARTIAL' },
          },
        ];
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.closureLegality.status).toBe('invalid');
        expect(report.closureLegality.reason).toMatch(/illegal_reconciliation/);
      });

      it('a genuine DUPLICATE_SUPPRESSED via reason REPLAY verifies as valid (threat-model row #1, permit-replay)', async () => {
        const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h5';
        const events: ActionEventDef[] = [
          {
            actionId,
            actionSeq: 1,
            eventType: 'ACTION_PROPOSED',
            observedAtIso: isoSecond(T0, 0),
            payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
          },
          {
            actionId,
            actionSeq: 2,
            eventType: 'ACTION_CLOSED',
            observedAtIso: isoSecond(T0, 1),
            payload: {
              closure: 'DUPLICATE_SUPPRESSED',
              reason: 'REPLAY',
              message: 'replay suppressed',
              errorCode: 'PERMIT_REPLAYED',
              enforcementMode: 'enforce',
            },
          },
        ];
        const { zip } = buildV5Bundle({ events });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.closureLegality.status).toBe('valid');
      });

      describe('PA-0033 (HIGH-1 security re-attack) — presence of an evidencing event is not evidence', () => {
        /** Post-dispatch, evidenced only by a single CALLER_RESULT_OBSERVED — the exact shape the re-attack exploited. */
        function timeoutEvidencedFailure(
          actionId: string,
          callerResultPayload: Record<string, unknown>,
        ): ActionEventDef[] {
          return [
            {
              actionId,
              actionSeq: 1,
              eventType: 'ACTION_PROPOSED',
              observedAtIso: isoSecond(T0, 0),
              payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' },
            },
            {
              actionId,
              actionSeq: 2,
              eventType: 'DISPATCH_ATTEMPTED',
              observedAtIso: isoSecond(T0, 1),
              dispatched: true,
              payload: {
                requestCommitment: 'a'.repeat(64),
                permitId: null,
                enforcementMode: 'observe',
              },
            },
            {
              actionId,
              actionSeq: 3,
              eventType: 'CALLER_RESULT_OBSERVED',
              observedAtIso: isoSecond(T0, 2),
              payload: callerResultPayload,
            },
            {
              actionId,
              actionSeq: 4,
              eventType: 'ACTION_CLOSED',
              observedAtIso: isoSecond(T0, 3),
              payload: { closure: 'FAILED_NO_EFFECT', reason: 'EVIDENCED' },
            },
          ];
        }

        it('HIGH-1 EXACT REPRODUCTION: FAILED_NO_EFFECT/EVIDENCED justified only by a timeout-shaped CALLER_RESULT_OBSERVED (outcomeClass: no_response_received) verifies as invalid, named reason', async () => {
          const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h6';
          const events = timeoutEvidencedFailure(actionId, {
            success: false,
            resultSummary: 'Tool call timed out after 30000ms',
            resultCommitment: 'b'.repeat(64),
            outcomeClass: 'no_response_received',
          });
          const { zip } = buildV5Bundle({ events });
          const report = await verifyBundle(zip, { noRekor: true });
          expect(report.closureLegality.status).toBe('invalid');
          expect(report.closureLegality.reason).toMatch(
            /closure_evidencing_event_not_positive/,
          );
          expect(report.status).toBe('invalid');
        });

        it('a legitimate negative result (outcomeClass: completed_with_error) DOES support FAILED_NO_EFFECT — verifies as valid', async () => {
          const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h7';
          const events = timeoutEvidencedFailure(actionId, {
            success: false,
            resultSummary: 'error',
            resultCommitment: 'b'.repeat(64),
            outcomeClass: 'completed_with_error',
          });
          const { zip } = buildV5Bundle({ events });
          const report = await verifyBundle(zip, { noRekor: true });
          expect(report.closureLegality.status).toBe('valid');
        });

        it('a bundle predating PA-0034 (CALLER_RESULT_OBSERVED{success:false}, no outcomeClass field at all) is neither valid nor invalid — it is incomplete, never a silent pass', async () => {
          const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h8';
          const events = timeoutEvidencedFailure(actionId, {
            success: false,
            resultSummary: 'Tool call timed out after 30000ms',
            resultCommitment: 'b'.repeat(64),
            // no outcomeClass — the pre-PA-0034 wire shape.
          });
          const { zip } = buildV5Bundle({
            events,
            evidenceGradeSummaryOverride: {
              A: 0,
              B: 0,
              C: 1,
              D: 0,
              enforcementMode: 'observe',
            },
          });
          const report = await verifyBundle(zip, { noRekor: true });
          expect(report.closureLegality.status).toBe('incomplete');
          expect(report.closureLegality.ok).toBe(false);
          expect(report.closureLegality.reason).toMatch(
            /closure_evidencing_event_ambiguous/,
          );
          expect(report.status).toBe('incomplete');
        });

        it('rejects a CALLER_RESULT_OBSERVED whose outcomeClass contradicts payload.success', async () => {
          const actionId = 'aaaaaaaa-0000-7000-8000-0000000000h9';
          const events = timeoutEvidencedFailure(actionId, {
            success: false,
            resultCommitment: 'b'.repeat(64),
            outcomeClass: 'completed_success', // says success but success:false — contradiction
          });
          const { zip } = buildV5Bundle({ events });
          const report = await verifyBundle(zip, { noRekor: true });
          expect(report.callerResult.status).toBe('invalid');
          expect(report.callerResult.reason).toMatch(
            /outcomeClass.*inconsistent with payload\.success/,
          );
        });

        it('rejects a CALLER_RESULT_OBSERVED with an unrecognized outcomeClass value', async () => {
          const actionId = 'aaaaaaaa-0000-7000-8000-0000000000ha';
          const events = timeoutEvidencedFailure(actionId, {
            success: false,
            resultCommitment: 'b'.repeat(64),
            outcomeClass: 'partial_response', // not in the recognized set
          });
          const { zip } = buildV5Bundle({ events });
          const report = await verifyBundle(zip, { noRekor: true });
          expect(report.callerResult.status).toBe('invalid');
          expect(report.callerResult.reason).toMatch(/not a recognized value/);
        });
      });
    });

    describe('evidenceGrade — corrigendum C4: derive, do not believe', () => {
      it('rejects a declared grade A when only grade-C evidence is actually present', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000i1',
        );
        const { zip } = buildV5Bundle({
          events,
          evidenceGradeSummaryOverride: {
            A: 1,
            B: 0,
            C: 0,
            D: 0,
            enforcementMode: 'observe',
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.evidenceGrade.status).toBe('invalid');
        expect(report.evidenceGrade.reason).toMatch(
          /declared_grade_exceeds_derived_evidence/,
        );
      });

      it('accepts a declared grade C matching the actually-present evidence', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000i2',
        );
        const { zip } = buildV5Bundle({
          events,
          evidenceGradeSummaryOverride: {
            A: 0,
            B: 0,
            C: 1,
            D: 0,
            enforcementMode: 'observe',
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.evidenceGrade.status).toBe('valid');
      });

      it('rejects an inflated grade-D bucket even when stronger buckets do not exceed derived evidence', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000i4',
        );
        const { zip } = buildV5Bundle({
          events,
          evidenceGradeSummaryOverride: {
            A: 0,
            B: 0,
            C: 1,
            D: 9,
            enforcementMode: 'observe',
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.evidenceGrade.status).toBe('invalid');
        expect(report.evidenceGrade.reason).toMatch(
          /declared_grade_summary_count_mismatch/,
        );
      });

      it('rejects enforcementMode "enforce" when a counted event\'s own payload declares "observe" — an observe-mode action must never be countable as enforced', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000i3',
        );
        // successfulActionEvents' DISPATCH_ATTEMPTED already declares
        // enforcementMode: 'observe' in its payload.
        const { zip } = buildV5Bundle({
          events,
          evidenceGradeSummaryOverride: {
            A: 0,
            B: 0,
            C: 1,
            D: 0,
            enforcementMode: 'enforce',
          },
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.evidenceGrade.status).toBe('invalid');
        expect(report.evidenceGrade.reason).toMatch(
          /observe_mode_action_counted_as_enforced/,
        );
      });
    });

    describe('actionCompleteness — truncation defense', () => {
      it('rejects a signed actionEventCount that disagrees with the rows actually shipped', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000j1',
        );
        const { zip } = buildV5Bundle({
          events,
          actionEventCountOverride: events.length + 1,
        });
        const report = await verifyBundle(zip, { noRekor: true });
        expect(report.actionCompleteness.status).toBe('invalid');
        expect(report.actionCompleteness.reason).toMatch(
          /action event count mismatch/,
        );
      });
    });

    describe('substitution (narrower proxy — see PA01-FIXED-audit-verifier.md for the documented scope limit)', () => {
      it('rejects an action event whose organizationId field was left unedited from a foreign org (structural bundle-format error)', async () => {
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000k1',
        ).map((e, i) =>
          i === 0
            ? {
                ...e,
                organizationIdOverride: '99999999-0000-0000-0000-000000000099',
              }
            : e,
        );
        const { zip } = buildV5Bundle({ events });
        await expect(verifyBundle(zip, { noRekor: true })).rejects.toThrow(
          /invalid\/incomplete event/,
        );
      });

      it('rejects an action event validly signed for a foreign org whose organizationId field was rewritten post-signing to match the target org (signature no longer verifies)', async () => {
        const foreignOrgId = '99999999-0000-0000-0000-000000000099';
        const events = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000k2',
        ).map((e, i) =>
          i === 0 ? { ...e, organizationIdOverride: foreignOrgId } : e,
        );
        const { zip } = buildV5Bundle({
          events,
          postSignEvents: (evs) => {
            // Rewrite the wire organizationId AFTER signing, to the
            // bundle's real org — the signature still covers the
            // ORIGINAL (foreign) organizationId, so it must fail.
            evs[0]!.organizationId = 'placeholder';
          },
        });
        // Patch the wire org back to the bundle's real orgId so the
        // structural check passes and the SIGNATURE check is what fires.
        const entries = readBundleEntries(zip);
        const manifest = JSON.parse(
          entries.get('manifest.json')!.toString('utf8'),
        ) as { orgId: string };
        const lines = zlib
          .gunzipSync(entries.get('action-events.ndjson.gz')!)
          .toString('utf8')
          .split('\n')
          .filter((l: string) => l.length > 0)
          .map((l: string) => JSON.parse(l) as Record<string, unknown>);
        lines[0]!.organizationId = manifest.orgId;
        const rebuiltNdjson = Buffer.from(
          lines.map((l: unknown) => JSON.stringify(l)).join('\n') + '\n',
          'utf8',
        );
        const rebuilt = writeZip([
          ...[...entries.entries()]
            .filter(([name]) => name !== 'action-events.ndjson.gz')
            .map(([name, data]) => ({ name, data })),
          {
            name: 'action-events.ndjson.gz',
            data: gzipDeterministic(rebuiltNdjson),
          },
        ]);
        const report = await verifyBundle(rebuilt, { noRekor: true });
        expect(report.actionEventChain.status).toBe('invalid');
        expect(report.actionEventChain.reason).toMatch(
          /signature does not verify/,
        );
      });
    });

    describe('split view — threat-model row #12, split-view-divergence', () => {
      it('two independently-built bundles for the same actionId diverge deterministically: the untampered one verifies, the altered one does not, at the exact same offender', async () => {
        const honestEvents = successfulActionEvents(
          'aaaaaaaa-0000-7000-8000-0000000000l1',
        );
        const gradeSummary = {
          A: 0,
          B: 0,
          C: 1,
          D: 0,
          enforcementMode: 'observe',
        };
        const { zip: honestZip } = buildV5Bundle({
          events: honestEvents,
          evidenceGradeSummaryOverride: gradeSummary,
        });

        const { zip: tamperedZip } = buildV5Bundle({
          events: honestEvents,
          evidenceGradeSummaryOverride: gradeSummary,
          postSignEvents: (evs) => {
            const target = evs.find((e) => e.actionSeq === 3)!;
            target.prevEventCommitment = 'f'.repeat(64);
          },
        });

        const honestReport = await verifyBundle(honestZip, { noRekor: true });
        const tamperedReport = await verifyBundle(tamperedZip, {
          noRekor: true,
        });

        expect(honestReport.status).toBe('valid');
        expect(tamperedReport.status).toBe('invalid');
        expect(tamperedReport.actionEventChain.firstFailure).toContain(
          'aaaaaaaa-0000-7000-8000-0000000000l1#3',
        );
      });
    });
  });
});
