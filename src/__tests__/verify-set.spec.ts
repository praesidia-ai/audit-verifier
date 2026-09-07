/**
 * SCAN2-004 — cross-bundle continuity (`praesidia-verify verify-set`).
 *
 * `be`'s `bundle-exporter.service.ts` caps a single export at
 * `MAX_RANGE_DAYS = 90`, so any org history longer than 90 days is
 * *necessarily* several bundles. Before this change, `praesidia-verify`
 * only ever looked at one bundle at a time: hand it bundle A (Jan-Apr) and
 * bundle C (Jul-Oct), skipping bundle B (the quarter with the incident),
 * and BOTH verify OK independently. Nothing says a window is missing.
 *
 * These tests build two (or three) real, fully-signed bundles for one org
 * — sharing a signing key, with row 0 of each later bundle's chain
 * anchored to the true hash-chain link of the previous bundle's newest row
 * — and drive the REAL CLI binary (`dist/cli.js`, exactly like
 * `PA-0009 — CLI --json flag and status exit codes` in `verify.spec.ts`)
 * so the test observes the actual code path an auditor runs, not a mocked
 * bundle reader.
 */

import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  signEd25519,
  sha256,
  merkleBuild,
  merkleProof,
  GENESIS_PREV_ROW_HASH,
} from '../crypto.js';
import { writeZip, gzipDeterministic } from '../zip.js';
import type { VerifyReport } from '../verify.js';

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

function keypairFromSeed(seed: Buffer): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
  const der = Buffer.concat([PKCS8_PREFIX, seed]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const jwk = pub.export({ format: 'jwk' }) as { x?: string };
  if (!jwk.x) throw new Error('failed to derive Ed25519 public key');
  const padded = jwk.x + '='.repeat((4 - (jwk.x.length % 4)) % 4);
  const pubBytes = Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return { publicKey: new Uint8Array(pubBytes), privateKey: new Uint8Array(seed) };
}

function isoSecond(base: number, offset: number): string {
  return new Date(base + offset * 1000).toISOString();
}

interface RowSignable {
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
}

/**
 * Build one fully-signed, internally-valid bundle covering `[from, to)`
 * for `orgId`, under a caller-supplied signing key so multiple bundles in
 * a set can share one tenant key exactly as `be` would produce across a
 * quarterly export cadence. `firstRowPrevRowHash` models the leading row's
 * anchor: `GENESIS_PREV_ROW_HASH` for a true history start, or the
 * caller-supplied hash-chain link of a PRIOR bundle's tail row (see
 * `computeChainLink`'s formula, replicated here) to model a genuine
 * continuation — or any other value to model a forged/discontinuous one.
 */
function buildRangeBundle(opts: {
  orgId: string;
  keyVersion: number;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  baseTs: number;
  rowCount: number;
  firstRowPrevRowHash: string;
  from?: string;
  to?: string;
  /** Mutate row content AFTER signing (breaks that row's signature deterministically, mirrors `buildBundleWithTamper`'s `postSignRowByte` in `verify.spec.ts`). */
  postSignRowMutate?: (rows: Array<{ action: string }>) => void;
}): { zip: Buffer; tailChainLink: string; from: string; to: string } {
  const { orgId, keyVersion, privateKey, publicKey, baseTs, rowCount } = opts;
  const periodStart = opts.from ?? isoSecond(baseTs, 0);
  const periodEnd = opts.to ?? isoSecond(baseTs, rowCount * 60);

  const rows: Array<{
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
  }> = [];
  const payloads: Array<{ canonical: Buffer; signatureBase64: string }> = [];

  for (let i = 0; i < rowCount; i++) {
    const createdAt = isoSecond(baseTs, i * 60);
    const signedAt = isoSecond(baseTs, i * 60 + 1);
    const partial: RowSignable = {
      organizationId: orgId,
      action: 'agent.created',
      actorId: '00000000-0000-0000-0000-00000000aa01',
      actorType: 'user',
      resourceType: 'agent',
      resourceId: `agent-${i}`,
      teamId: null,
      agentId: `agent-${i}`,
      summary: `Created agent: Agent ${i}`,
      details: { agentId: `agent-${i}` },
      createdAt,
    };
    const canonical = canonicalJson(partial);

    let prevRowHash: string;
    if (i === 0) {
      prevRowHash = opts.firstRowPrevRowHash;
    } else {
      const prev = payloads[i - 1]!;
      prevRowHash = sha256(
        Buffer.concat([prev.canonical, Buffer.from(prev.signatureBase64, 'base64')]),
      ).toString('base64');
    }

    const rowMessage = Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]);
    const signatureBase64 = signEd25519(rowMessage, privateKey);

    rows.push({
      id: `row-${baseTs}-${i}`,
      ...partial,
      signature: signatureBase64,
      keyVersion,
      signedAt,
      prevRowHash,
    });
    payloads.push({ canonical, signatureBase64 });
  }

  opts.postSignRowMutate?.(rows);

  const tailChainLink = sha256(
    Buffer.concat([
      payloads[payloads.length - 1]!.canonical,
      Buffer.from(payloads[payloads.length - 1]!.signatureBase64, 'base64'),
    ]),
  ).toString('base64');

  const leaves = payloads.map(
    (p) => new Uint8Array(Buffer.concat([p.canonical, Buffer.from(p.signatureBase64, 'base64')])),
  );
  const tree = merkleBuild(leaves);
  const rootHashB64 = Buffer.from(tree.root).toString('base64');

  const rootMessage = canonicalJson({
    rootHash: rootHashB64,
    periodStart,
    periodEnd,
    rowCount: rows.length,
  });
  const rootSignature = signEd25519(rootMessage, privateKey);

  const roots = [
    {
      id: `root-${baseTs}`,
      organizationId: orgId,
      periodStart,
      periodEnd,
      rowCount: rows.length,
      rootHash: rootHashB64,
      signature: rootSignature,
      keyVersion,
      signedAt: isoSecond(baseTs, rowCount * 60 + 5),
      anchoredAt: null,
      anchorReceipt: null,
    },
  ];

  const proofs = rows.map((row, i) => {
    const p = merkleProof(leaves, i);
    return {
      rowId: row.id,
      index: p.index,
      proof: p.siblings.map((s) => Buffer.from(s).toString('base64')),
      rootHash: rootHashB64,
    };
  });

  const publicKeyB64 = Buffer.from(publicKey).toString('base64');
  const generatedAt = isoSecond(baseTs, rowCount * 60 + 30);
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
  const manifest = { ...manifestSans, signature: manifestSignature, signatureKeyVersion: keyVersion };

  const publicKeys: Record<string, string> = { [String(keyVersion)]: publicKeyB64 };
  const zip = writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8') },
    {
      name: 'rows.ndjson.gz',
      data: gzipDeterministic(Buffer.from(rows.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8')),
    },
    {
      name: 'roots.ndjson.gz',
      data: gzipDeterministic(Buffer.from(roots.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8')),
    },
    {
      name: 'proofs.ndjson.gz',
      data: gzipDeterministic(Buffer.from(proofs.map((p) => JSON.stringify(p)).join('\n') + '\n', 'utf8')),
    },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify(publicKeys, null, 2), 'utf8') },
    { name: 'README.md', data: Buffer.from('# Test bundle\n', 'utf8') },
  ]);

  return { zip, tailChainLink, from: periodStart, to: periodEnd };
}

function writeTempBundles(zips: Buffer[]): { tmpDir: string; paths: string[] } {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-verifier-verify-set-'));
  const paths = zips.map((zip, i) => {
    const p = path.join(tmpDir, `bundle-${i}.zip`);
    fs.writeFileSync(p, zip);
    return p;
  });
  return { tmpDir, paths };
}

const ORG_ID = '00000000-0000-0000-0000-0000000000f5';
const KEY_VERSION = 1;
const SEED = Buffer.alloc(32, 9);
const { publicKey, privateKey } = keypairFromSeed(SEED);

describe('SCAN2-004 — red: today, two bundles with a real gap both verify OK independently', () => {
  it('praesidia-verify on bundle A alone -> OK, on bundle C alone -> OK, with NO cross-reference', () => {
    const cliPath = cliPathOrThrow();
    // Bundle A: Jan window. Bundle C: Jul window (bundle B, Apr-Jul, the
    // quarter with the incident, is never handed to the auditor).
    const bundleA = buildRangeBundle({
      orgId: ORG_ID,
      keyVersion: KEY_VERSION,
      privateKey,
      publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0),
      rowCount: 3,
      firstRowPrevRowHash: GENESIS_PREV_ROW_HASH,
      from: '2026-01-01T00:00:00.000Z',
      to: '2026-04-01T00:00:00.000Z',
    });
    const bundleC = buildRangeBundle({
      orgId: ORG_ID,
      keyVersion: KEY_VERSION,
      privateKey,
      publicKey,
      baseTs: Date.UTC(2026, 6, 1, 0, 0, 0),
      rowCount: 3,
      // Opaque anchor — a genuine ranged export is allowed one. Since
      // bundle B was never produced, this is NOT bundleA's real tail link;
      // it is indistinguishable from a legitimate anchor by design
      // (BUGHUNT-SDK-02) to single-bundle verification.
      firstRowPrevRowHash: sha256(Buffer.from('opaque-anchor-into-missing-quarter')).toString('base64'),
      from: '2026-07-01T00:00:00.000Z',
      to: '2026-10-01T00:00:00.000Z',
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip, bundleC.zip]);
    try {
      const runOne = (p: string): VerifyReport => {
        const stdout = execFileSync(
          process.execPath,
          [cliPath, p, '--no-rekor', '--allow-legacy-unattested', '--json'],
          { encoding: 'utf8' },
        );
        return JSON.parse(stdout) as VerifyReport;
      };
      const reportA = runOne(paths[0]!);
      const reportC = runOne(paths[1]!);
      // THIS IS THE RED: both individually report `valid`, and there is no
      // mode that would have told the auditor bundle B is missing.
      expect(reportA.status).toBe('valid');
      expect(reportC.status).toBe('valid');
      expect(reportA.bundle.to).toBe('2026-04-01T00:00:00.000Z');
      expect(reportC.bundle.from).toBe('2026-07-01T00:00:00.000Z');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('SCAN2-004 — green: `verify-set` names the gap and closes AUDIT-03', () => {
  function runVerifySet(paths: string[], extra: string[] = []): { status: number; stdout: string; stderr: string } {
    const cliPath = cliPathOrThrow();
    try {
      const stdout = execFileSync(
        process.execPath,
        [cliPath, 'verify-set', ...paths, '--no-rekor', '--allow-legacy-unattested', '--json', ...extra],
        { encoding: 'utf8' },
      );
      return { status: 0, stdout, stderr: '' };
    } catch (err) {
      const e = err as { status?: number; stdout?: string; stderr?: string };
      return { status: e.status ?? -1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
    }
  }

  it('reports a named gap finding and a distinct exit code when a quarter is missing', () => {
    const bundleA = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: GENESIS_PREV_ROW_HASH,
      from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z',
    });
    const bundleC = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 6, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: sha256(Buffer.from('opaque-anchor-into-missing-quarter')).toString('base64'),
      from: '2026-07-01T00:00:00.000Z', to: '2026-10-01T00:00:00.000Z',
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip, bundleC.zip]);
    try {
      const result = runVerifySet(paths);
      const report = JSON.parse(result.stdout) as {
        ok: boolean;
        status: string;
        findings: Array<{ kind: string }>;
      };
      expect(report.ok).toBe(false);
      expect(report.status).toBe('discontinuous');
      expect(report.findings.some((f) => f.kind === 'date_gap')).toBe(true);
      expect(result.status).toBe(4);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('reports continuous (exit 0) when two bundles genuinely stitch: date-adjacent AND chain-linked', () => {
    const bundleA = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: GENESIS_PREV_ROW_HASH,
      from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z',
    });
    const bundleB = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 3, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: bundleA.tailChainLink,
      from: '2026-04-01T00:00:00.000Z', to: '2026-07-01T00:00:00.000Z',
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip, bundleB.zip]);
    try {
      const result = runVerifySet(paths);
      const report = JSON.parse(result.stdout) as { ok: boolean; status: string; findings: unknown[] };
      expect(report.status).toBe('continuous');
      expect(report.ok).toBe(true);
      expect(report.findings).toHaveLength(0);
      expect(result.status).toBe(0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('catches an adjacent-but-FORGED boundary — dates line up but the chain link does not', () => {
    const bundleA = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: GENESIS_PREV_ROW_HASH,
      from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z',
    });
    const bundleB = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 3, 1, 0, 0, 0), rowCount: 3,
      // Dates are perfectly adjacent, but this anchor is NOT bundleA's
      // real tail link — a forged/replaced boundary.
      firstRowPrevRowHash: sha256(Buffer.from('forged-boundary')).toString('base64'),
      from: '2026-04-01T00:00:00.000Z', to: '2026-07-01T00:00:00.000Z',
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip, bundleB.zip]);
    try {
      const result = runVerifySet(paths);
      const report = JSON.parse(result.stdout) as { ok: boolean; status: string; findings: Array<{ kind: string }> };
      expect(report.ok).toBe(false);
      expect(report.status).toBe('discontinuous');
      expect(report.findings.some((f) => f.kind === 'boundary_chain_mismatch')).toBe(true);
      expect(result.status).toBe(4);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('reports an overlap explicitly rather than silently accepting it', () => {
    const bundleA = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: GENESIS_PREV_ROW_HASH,
      from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z',
    });
    const bundleB = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 2, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: sha256(Buffer.from('overlap-anchor')).toString('base64'),
      from: '2026-03-01T00:00:00.000Z', to: '2026-06-01T00:00:00.000Z',
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip, bundleB.zip]);
    try {
      const result = runVerifySet(paths);
      const report = JSON.parse(result.stdout) as { ok: boolean; status: string; findings: Array<{ kind: string }> };
      expect(report.ok).toBe(false);
      expect(report.status).toBe('discontinuous');
      expect(report.findings.some((f) => f.kind === 'date_overlap')).toBe(true);
      expect(result.status).toBe(4);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('AUDIT-03: the earliest bundle in a set must be genesis-rooted, not an opaque anchor', () => {
    const bundleA = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0), rowCount: 3,
      // The earliest bundle handed to the auditor, but its head is an
      // opaque anchor, not genesis — either an earlier bundle is missing,
      // or the chain has been tampered with. Either way verify-set must
      // say so, not silently accept it as "a legitimate range start".
      firstRowPrevRowHash: sha256(Buffer.from('suspicious-non-genesis-start')).toString('base64'),
      from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z',
    });
    const bundleB = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 3, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: bundleA.tailChainLink,
      from: '2026-04-01T00:00:00.000Z', to: '2026-07-01T00:00:00.000Z',
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip, bundleB.zip]);
    try {
      const result = runVerifySet(paths);
      const report = JSON.parse(result.stdout) as { ok: boolean; status: string; findings: Array<{ kind: string }> };
      expect(report.ok).toBe(false);
      expect(report.status).toBe('discontinuous');
      expect(report.findings.some((f) => f.kind === 'chain_head_not_genesis')).toBe(true);
      expect(result.status).toBe(4);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('a bundle that is itself invalid gets its own distinct exit code, not folded into "gap"', () => {
    const bundleA = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: GENESIS_PREV_ROW_HASH,
      from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z',
    });
    // Bundle B's row-1 is mutated AFTER signing — its own signature and
    // Merkle inclusion proof both fail, independent of any cross-bundle
    // continuity question.
    const bundleB = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 3, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: bundleA.tailChainLink,
      from: '2026-04-01T00:00:00.000Z', to: '2026-07-01T00:00:00.000Z',
      postSignRowMutate: (rows) => {
        rows[1]!.action = 'agent.deleted';
      },
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip, bundleB.zip]);
    try {
      const result = runVerifySet(paths);
      const report = JSON.parse(result.stdout) as { ok: boolean; status: string };
      expect(report.ok).toBe(false);
      expect(report.status).toBe('bundle_invalid');
      // Distinct from the "discontinuous" exit code (4) even though this
      // set is ALSO not continuous by definition — an invalid bundle is a
      // strictly worse signal than a mere gap and must not be silently
      // downgraded to it.
      expect(result.status).toBe(1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('single-bundle `praesidia-verify <bundle.zip>` behaviour is unchanged by the new mode', () => {
    const bundleA = buildRangeBundle({
      orgId: ORG_ID, keyVersion: KEY_VERSION, privateKey, publicKey,
      baseTs: Date.UTC(2026, 0, 1, 0, 0, 0), rowCount: 3,
      firstRowPrevRowHash: GENESIS_PREV_ROW_HASH,
      from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z',
    });
    const { tmpDir, paths } = writeTempBundles([bundleA.zip]);
    try {
      const cliPath = cliPathOrThrow();
      const stdout = execFileSync(
        process.execPath,
        [cliPath, paths[0]!, '--no-rekor', '--allow-legacy-unattested', '--json'],
        { encoding: 'utf8' },
      );
      const report = JSON.parse(stdout) as VerifyReport;
      expect(report.status).toBe('valid');
      expect(report.ok).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
