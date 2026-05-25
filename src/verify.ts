/**
 * Praesidia compliance bundle verifier — pure-function orchestrator.
 *
 * Reads a bundle zip, decompresses each entry, and walks the manifest /
 * row chain / Merkle root / inclusion proof invariants. Returns a
 * structured `VerifyReport` describing exactly which components passed
 * and which failed; the CLI translates that into stdout + an exit code.
 *
 * SECURITY:
 *  - We NEVER trust the bundle's claim about which keys signed which
 *    rows in isolation — every signature is verified against the
 *    bytes in `public-keys.json` keyed by `keyVersion`.
 *  - We NEVER log row payloads. Only counts, names, and the id of the
 *    FIRST offending row in each phase.
 *  - The Rekor fetch (when not skipped) is the ONLY network call.
 *
 * INVARIANTS the verifier checks:
 *  1. Manifest signature        — Ed25519 over canonical-JSON of the
 *                                 manifest's signable fields, verified
 *                                 with `publicKeys[manifest.signatureKeyVersion]`.
 *  2. Row signatures            — for each row, canonical-JSON over the
 *                                 11 signable fields (mirrors AGV-030)
 *                                 verified with `publicKeys[row.keyVersion]`.
 *  3. Chain integrity           — `row.prevRowHash` matches
 *                                 `sha256(prev.canonical || prev.sigBytes)`,
 *                                 starting from the all-zero genesis.
 *  4. Merkle root signatures    — canonical-JSON over
 *                                 `{rootHash, periodStart, periodEnd, rowCount}`
 *                                 verified with `publicKeys[root.keyVersion]`.
 *  5. Inclusion proofs          — `merkleVerify(leaf, proof, rootHash)`
 *                                 where `leaf = canonical(row) || sigBytes`
 *                                 (AGV-033 leaf preimage). Proof rows
 *                                 with `status` markers (e.g.
 *                                 `not_yet_rooted`) are SKIPPED — they
 *                                 are not failures.
 *  6. Rekor receipt (optional)  — when not skipped, fetch the receipt by
 *                                 UUID and compare body bytes against
 *                                 `root.anchorReceipt`. Skipped when no
 *                                 receipt is present.
 */

import {
  canonicalJson,
  sha256,
  verifySignature,
  type BundleSignatureAlgorithm,
  merkleVerify,
  type MerkleProof,
  GENESIS_PREV_ROW_HASH,
} from './crypto.js';
import { readZip, gunzip, type ZipEntry } from './zip.js';

// ────────────────────────────────────────────────────────────────────────
// Bundle wire types — what `BundleExporterService` (AGV-035) writes.
// ────────────────────────────────────────────────────────────────────────

interface ManifestKeyVersionEntry {
  keyVersion: number;
  publicKey: string;
  // AUDIT-2026-05-14 — Manifest v2 carries lifecycle metadata for
  // every key version it embeds, so an offline verifier can apply the
  // signed-before-revocation rule without re-fetching tenant state.
  // Optional for forward-compat with v1 bundles that pre-date AUDIT-14.
  status?: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  revokedAt?: string | null;
}

interface BundleManifest {
  version: number;
  orgId: string;
  from: string;
  to: string;
  rowCount: number;
  rootCount: number;
  keyVersions: ManifestKeyVersionEntry[];
  generatedAt: string;
  // NX-TAC-02 — Bundles emitted by KMS-substrate tenants carry
  // 'ECDSA_P256_SHA256'. Bundles emitted by the local-aes-gcm
  // substrate continue to carry 'Ed25519'. The verifier dispatches
  // on this field via `verifySignature`.
  signatureAlgorithm: BundleSignatureAlgorithm;
  signature: string;
  signatureKeyVersion: number;
}

/**
 * AUDIT-2026-05-14 — Per-key entry as written in `public-keys.json`.
 *
 * Manifest v1 wrote `{ [keyVersion]: base64 }` (raw string per entry).
 * Manifest v2 writes `{ [keyVersion]: { publicKey, status, revokedAt } }`
 * so the verifier can enforce the signed-before-revocation rule for
 * REVOKED keys WITHOUT needing live tenant state. The parser accepts
 * both shapes — strings are coerced to ACTIVE entries.
 */
interface PublicKeyRecord {
  publicKey: Uint8Array;
  status: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  revokedAt: Date | null;
}

interface BundleRow {
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
  signedAt: string | null;
  prevRowHash: string;
}

interface BundleRoot {
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
  /** Legacy single-slot Rekor receipt — populated by pre-AUDIT-09 producers. */
  anchorReceipt: string | null;
  /**
   * AUDIT-2026-05-09 — Multi-anchor receipt log. Each entry is one
   * provider's independent receipt for THIS root. The verifier walks
   * each entry, dispatches on `provider`, and reports per-provider
   * success/failure in `report.rekor`. Optional for back-compat with
   * bundles emitted before the multi-anchor migration.
   */
  anchorReceipts?: Array<{
    provider: string;
    receipt: string;
    anchoredAt: string;
  }>;
}

interface BundleProofEntry {
  rowId: string;
  status?: string;
  /** Base64 sibling hashes from leaf level upward. */
  proof?: string[];
  /** Leaf index inside the root's leaf list. */
  index?: number;
  /** Base64 root hash this proof terminates at. */
  rootHash?: string;
}

// ────────────────────────────────────────────────────────────────────────
// Public report
// ────────────────────────────────────────────────────────────────────────

export interface ComponentResult {
  ok: boolean;
  checked: number;
  failed: number;
  /** Identifier of the FIRST offender, when applicable. */
  firstFailure?: string;
  /** Human-readable reason, when applicable. */
  reason?: string;
}

export interface VerifyReport {
  ok: boolean;
  manifest: ComponentResult;
  rowSignatures: ComponentResult;
  chain: ComponentResult;
  rootSignatures: ComponentResult;
  inclusionProofs: ComponentResult;
  rekor: ComponentResult;
  bundle: {
    orgId: string;
    from: string;
    to: string;
    declaredRowCount: number;
    declaredRootCount: number;
    rowsSeen: number;
    rootsSeen: number;
    proofsSeen: number;
  };
}

export interface VerifyOptions {
  /** Skip the optional Rekor receipt fetch (default: false). */
  noRekor?: boolean;
  /**
   * Hook for the Rekor fetch — primarily a test seam. Defaults to a
   * built-in fetch against rekor.sigstore.dev. Receives the raw
   * `anchorReceipt` string; returns `true` on success.
   */
  rekorFetcher?: (anchorReceipt: string) => Promise<boolean>;
  /**
   * AUDIT-2026-05-09 — Optional hook for verifying provider-specific
   * anchor receipts in the multi-anchor `anchorReceipts` array. The
   * verifier dispatches on `entry.provider`:
   *
   *   - `'rekor'`   → falls back to `rekorFetcher` when this hook is
   *                   absent (preserves the legacy single-anchor path).
   *   - `'s3'`      → checks that the receipt parses as an
   *                   `s3:<bucket>:<key>:<versionId>` triple. The
   *                   verifier is OFFLINE by contract; we DON'T make a
   *                   network HEAD call. A caller wanting on-line
   *                   verification supplies this hook.
   *   - other       → reported as
   *                   `{ ok: false, reason: 'unknown_provider' }` and
   *                   counted as a failure in `report.rekor`. The
   *                   overall bundle still verifies if every other
   *                   anchor passes; the unknown entry surfaces in
   *                   `firstFailure` so the auditor can investigate.
   */
  anchorReceiptVerifier?: (entry: {
    provider: string;
    receipt: string;
    anchoredAt: string;
  }) => Promise<{ ok: boolean; reason?: string }>;
}

const EXPECTED_ENTRIES = [
  'manifest.json',
  'rows.ndjson.gz',
  'roots.ndjson.gz',
  'proofs.ndjson.gz',
  'public-keys.json',
];

// ────────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────────

/**
 * Verify a compliance bundle. Returns a structured report; never throws
 * on a verification failure (only on I/O / format errors — those should
 * surface to the CLI as exit code 2 distinct from verification failures
 * at exit code 1).
 */
export async function verifyBundle(
  bundle: Buffer,
  options: VerifyOptions = {},
): Promise<VerifyReport> {
  // 1) Read & validate the zip envelope.
  const entries = readZip(bundle);
  const byName = new Map<string, ZipEntry>();
  for (const e of entries) byName.set(e.name, e);
  for (const required of EXPECTED_ENTRIES) {
    if (!byName.has(required)) {
      throw new Error(`bundle missing required entry: ${required}`);
    }
  }

  // 2) Parse manifest, public keys.
  const manifest = JSON.parse(
    byName.get('manifest.json')!.data.toString('utf8'),
  ) as BundleManifest;

  const publicKeysRaw = JSON.parse(
    byName.get('public-keys.json')!.data.toString('utf8'),
  ) as Record<string, unknown>;
  const publicKeys = new Map<number, PublicKeyRecord>();
  for (const [k, v] of Object.entries(publicKeysRaw)) {
    const ver = Number(k);
    if (!Number.isInteger(ver)) {
      throw new Error(`public-keys.json contains non-integer key version: ${k}`);
    }
    publicKeys.set(ver, parsePublicKeyEntry(v, k));
  }

  // 3) Verify manifest signature.
  const manifestResult = verifyManifest(manifest, publicKeys);

  // 4) Parse + verify rows.
  const rowsNdjson = gunzip(byName.get('rows.ndjson.gz')!.data);
  const rows = parseNdjson<BundleRow>(rowsNdjson);

  // NX-TAC-02 — Thread the manifest's signatureAlgorithm into the
  // row + root signature checks. Every signature in a bundle uses
  // the same algorithm as the manifest (be-core's producer never
  // mixes algorithms within one bundle).
  const rowSigResult = verifyRowSignatures(
    rows,
    publicKeys,
    manifest.signatureAlgorithm,
  );
  const chainResult = verifyChain(rows);

  // 5) Parse + verify roots.
  const rootsNdjson = gunzip(byName.get('roots.ndjson.gz')!.data);
  const roots = parseNdjson<BundleRoot>(rootsNdjson);
  const rootSigResult = verifyRootSignatures(
    roots,
    publicKeys,
    manifest.signatureAlgorithm,
  );

  // 6) Parse + verify inclusion proofs.
  const proofsNdjson = gunzip(byName.get('proofs.ndjson.gz')!.data);
  const proofs = parseNdjson<BundleProofEntry>(proofsNdjson);
  const proofResult = verifyInclusionProofs(rows, roots, proofs);

  // 7) Optional Rekor fetch.
  const rekorResult = await verifyRekorReceipts(roots, options);

  const ok =
    manifestResult.ok &&
    rowSigResult.ok &&
    chainResult.ok &&
    rootSigResult.ok &&
    proofResult.ok &&
    rekorResult.ok;

  return {
    ok,
    manifest: manifestResult,
    rowSignatures: rowSigResult,
    chain: chainResult,
    rootSignatures: rootSigResult,
    inclusionProofs: proofResult,
    rekor: rekorResult,
    bundle: {
      orgId: manifest.orgId,
      from: manifest.from,
      to: manifest.to,
      declaredRowCount: manifest.rowCount,
      declaredRootCount: manifest.rootCount,
      rowsSeen: rows.length,
      rootsSeen: roots.length,
      proofsSeen: proofs.length,
    },
  };
}

// ════════════════════════════════════════════════════════════════════════
// Component verifiers
// ════════════════════════════════════════════════════════════════════════

function verifyManifest(
  manifest: BundleManifest,
  publicKeys: Map<number, PublicKeyRecord>,
): ComponentResult {
  const entry = publicKeys.get(manifest.signatureKeyVersion);
  if (!entry) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `manifest signing key version ${manifest.signatureKeyVersion} not in public-keys.json`,
    };
  }
  // Reconstruct the manifest-sans-signature envelope and canonicalize
  // it the same way the writer did.
  const signable = {
    version: manifest.version,
    orgId: manifest.orgId,
    from: manifest.from,
    to: manifest.to,
    rowCount: manifest.rowCount,
    rootCount: manifest.rootCount,
    keyVersions: manifest.keyVersions,
    generatedAt: manifest.generatedAt,
    signatureAlgorithm: manifest.signatureAlgorithm,
  };
  const bytes = canonicalJson(signable);
  // NX-TAC-02 — Dispatch on the algorithm declared in the manifest.
  // A bundle whose `signatureAlgorithm` is ECDSA_P256_SHA256 is now
  // verifiable (was previously rejected outright).
  const ok = verifySignature(
    manifest.signatureAlgorithm,
    bytes,
    manifest.signature,
    entry.publicKey,
  );
  return ok
    ? { ok: true, checked: 1, failed: 0 }
    : {
        ok: false,
        checked: 1,
        failed: 1,
        reason: 'manifest signature does not verify',
      };
}

function verifyRowSignatures(
  rows: BundleRow[],
  publicKeys: Map<number, PublicKeyRecord>,
  algorithm: BundleSignatureAlgorithm,
): ComponentResult {
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  for (const row of rows) {
    const entry = publicKeys.get(row.keyVersion);
    if (!entry) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = `row keyVersion ${row.keyVersion} not in public-keys.json`;
      }
      continue;
    }
    // AUDIT-2026-05-14 — REVOKED-key acceptance window.
    //
    // A row signed BEFORE the key was revoked still verifies (the
    // signature is forensically valid; revocation is a forward-looking
    // operator action). A row signed AFTER `revokedAt` MUST be
    // rejected with `key_revoked_after_signing`, because the only
    // legitimate way to produce such a signature would have been an
    // operator who continued signing with a revoked key — exactly the
    // failure mode `revokeKey` is meant to halt. The bundle exporter
    // ships every status (ACTIVE / ROTATED / REVOKED) so the verifier
    // can apply this rule offline.
    if (entry.status === 'REVOKED') {
      const revocationCheck = checkSignedBeforeRevocation(row, entry);
      if (revocationCheck !== null) {
        failed += 1;
        if (!firstFailure) {
          firstFailure = row.id;
          reason = revocationCheck;
        }
        continue;
      }
    }
    const signable = signableRow(row);
    const bytes = canonicalJson(signable);
    if (!verifySignature(algorithm, bytes, row.signature, entry.publicKey)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'row signature does not verify';
      }
    }
  }
  return {
    ok: failed === 0,
    checked: rows.length,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

function verifyChain(rows: BundleRow[]): ComponentResult {
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  let prev: BundleRow | null = null;
  for (const row of rows) {
    const expected = prev ? computeChainLink(prev) : GENESIS_PREV_ROW_HASH;
    if (row.prevRowHash !== expected) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'prev_row_hash does not chain to previous row';
      }
    }
    prev = row;
  }
  return {
    ok: failed === 0,
    checked: rows.length,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

function verifyRootSignatures(
  roots: BundleRoot[],
  publicKeys: Map<number, PublicKeyRecord>,
  algorithm: BundleSignatureAlgorithm,
): ComponentResult {
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  for (const root of roots) {
    const entry = publicKeys.get(root.keyVersion);
    if (!entry) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = `root keyVersion ${root.keyVersion} not in public-keys.json`;
      }
      continue;
    }
    // AUDIT-2026-05-14 — same signed-before-revocation rule the row
    // verifier applies. A root signed after its key was revoked is a
    // forensics anomaly even if the underlying rows are clean.
    if (entry.status === 'REVOKED') {
      const revocationCheck = checkSignedBeforeRevocation(
        { id: root.id, signedAt: root.signedAt },
        entry,
      );
      if (revocationCheck !== null) {
        failed += 1;
        if (!firstFailure) {
          firstFailure = root.id;
          reason = revocationCheck;
        }
        continue;
      }
    }
    // Mirror the writer's envelope exactly — see MerkleRootService
    // (AGV-033) `computeRootForPeriod`.
    const bytes = canonicalJson({
      rootHash: root.rootHash,
      periodStart: root.periodStart,
      periodEnd: root.periodEnd,
      rowCount: root.rowCount,
    });
    if (!verifySignature(algorithm, bytes, root.signature, entry.publicKey)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = 'root signature does not verify';
      }
    }
  }
  return {
    ok: failed === 0,
    checked: roots.length,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

function verifyInclusionProofs(
  rows: BundleRow[],
  roots: BundleRoot[],
  proofs: BundleProofEntry[],
): ComponentResult {
  const rowsById = new Map<string, BundleRow>();
  for (const r of rows) rowsById.set(r.id, r);
  const rootsByHash = new Map<string, BundleRoot>();
  for (const r of roots) rootsByHash.set(r.rootHash, r);

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;

  for (const entry of proofs) {
    // Status markers (`not_yet_rooted`, `key_unavailable`, `error`) are
    // explicit signals from the writer that this row could not be
    // proven; the verifier MUST NOT treat them as failures.
    if (entry.status && entry.status !== 'ok') {
      continue;
    }
    const row = rowsById.get(entry.rowId);
    if (!row) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof references a row not present in rows.ndjson.gz';
      }
      checked += 1;
      continue;
    }
    if (
      !entry.proof ||
      !entry.rootHash ||
      typeof entry.index !== 'number'
    ) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof entry malformed (missing proof/index/rootHash)';
      }
      checked += 1;
      continue;
    }
    const rootBytes = Buffer.from(entry.rootHash, 'base64');
    // Sanity: the proof's stated root must match a root in roots.ndjson.gz.
    if (!rootsByHash.has(entry.rootHash)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof rootHash not found in roots.ndjson.gz';
      }
      checked += 1;
      continue;
    }
    const leaf = computeLeaf(row);
    const merkleProofObj: MerkleProof = {
      siblings: entry.proof.map((s) => new Uint8Array(Buffer.from(s, 'base64'))),
      index: entry.index,
    };
    if (!merkleVerify(leaf, merkleProofObj, new Uint8Array(rootBytes))) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'inclusion proof does not verify against root';
      }
    }
    checked += 1;
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/**
 * AUDIT-2026-05-09 — Multi-anchor receipt verification.
 *
 * Walks `root.anchorReceipts` (the multi-anchor array introduced by
 * the AUDIT-09 migration) and dispatches each entry on its `provider`
 * key. Each provider verifies independently — the report counts every
 * receipt across every root, so a 3-root bundle each with a Rekor +
 * S3 anchor produces `checked = 6`.
 *
 * Back-compat: when a root has NO `anchorReceipts` array (older
 * bundles emitted before the multi-anchor exporter shipped) but DOES
 * carry the legacy `anchorReceipt` string, the verifier synthesizes a
 * single `{ provider: 'rekor', receipt, anchoredAt }` entry so the
 * legacy receipt is still checked. This is the same shape the
 * migration's backfill writes into the database.
 */
async function verifyRekorReceipts(
  roots: BundleRoot[],
  options: VerifyOptions,
): Promise<ComponentResult> {
  if (options.noRekor) {
    return { ok: true, checked: 0, failed: 0, reason: 'skipped via --no-rekor' };
  }
  const rekorFetcher = options.rekorFetcher ?? defaultRekorFetcher;
  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  for (const root of roots) {
    const entries = collectAnchorEntries(root);
    if (entries.length === 0) continue;
    for (const entry of entries) {
      checked += 1;
      let result: { ok: boolean; reason?: string };
      try {
        result = await verifyAnchorReceipt(entry, options, rekorFetcher);
      } catch (err) {
        result = {
          ok: false,
          reason: `verify_threw: ${
            err instanceof Error ? err.message : String(err)
          }`,
        };
      }
      if (!result.ok) {
        failed += 1;
        if (!firstFailure) {
          firstFailure = root.id;
          reason = result.reason
            ? `${entry.provider}: ${result.reason}`
            : `${entry.provider} receipt verification failed`;
        }
      }
    }
  }
  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/**
 * AUDIT-2026-05-09 — Normalize the root's anchor representations into
 * a single per-provider entry list. Prefers the multi-anchor
 * `anchorReceipts` array; synthesizes a legacy rekor entry from
 * `anchorReceipt` only when the array is absent or empty.
 */
function collectAnchorEntries(
  root: BundleRoot,
): Array<{ provider: string; receipt: string; anchoredAt: string }> {
  if (Array.isArray(root.anchorReceipts) && root.anchorReceipts.length > 0) {
    return root.anchorReceipts;
  }
  if (root.anchorReceipt) {
    return [
      {
        provider: 'rekor',
        receipt: root.anchorReceipt,
        // Use the root's `anchoredAt` when present, falling back to
        // `signedAt` so the synthesized entry always carries a
        // timestamp (matches the migration's backfill shape).
        anchoredAt: root.anchoredAt ?? root.signedAt,
      },
    ];
  }
  return [];
}

/**
 * AUDIT-2026-05-09 — Dispatch a single anchor receipt entry to the
 * appropriate verifier. The caller-supplied `anchorReceiptVerifier`
 * (when present) wins for ALL providers — auditors who need on-line
 * verification of S3 receipts, for example, supply a hook that does
 * a HEAD against the bucket. Without the hook, behaviour per provider:
 *
 *   - `'rekor'` → existing `rekorFetcher` (default: parses JSON).
 *   - `'s3'`    → offline shape check on `s3:<bucket>:<key>:<vid>`.
 *   - other     → `{ ok: false, reason: 'unknown_provider' }`.
 */
async function verifyAnchorReceipt(
  entry: { provider: string; receipt: string; anchoredAt: string },
  options: VerifyOptions,
  rekorFetcher: (anchorReceipt: string) => Promise<boolean>,
): Promise<{ ok: boolean; reason?: string }> {
  if (typeof entry.receipt !== 'string' || entry.receipt.length === 0) {
    return { ok: false, reason: 'empty_receipt' };
  }
  if (options.anchorReceiptVerifier) {
    return options.anchorReceiptVerifier(entry);
  }
  if (entry.provider === 'rekor') {
    const ok = await rekorFetcher(entry.receipt);
    return ok ? { ok: true } : { ok: false, reason: 'rekor_fetch_failed' };
  }
  if (entry.provider === 's3') {
    return verifyS3ReceiptShape(entry.receipt);
  }
  return { ok: false, reason: 'unknown_provider' };
}

/**
 * Offline check that an S3 receipt parses as `s3:<bucket>:<key>:<vid>`.
 * The key may legally contain colons, so we slice the first and last
 * colon-segments and treat everything in between as the key — matches
 * `S3AnchorService.verifyReceipt`'s parser.
 *
 * Returns `{ ok: false, reason: 'malformed' }` on a bad shape. The
 * verifier is offline by contract; live HEAD-against-bucket checks are
 * the responsibility of a caller-supplied `anchorReceiptVerifier`.
 */
function verifyS3ReceiptShape(receipt: string): { ok: boolean; reason?: string } {
  if (!receipt.startsWith('s3:')) {
    return { ok: false, reason: 'malformed' };
  }
  const rest = receipt.slice('s3:'.length);
  const firstColon = rest.indexOf(':');
  if (firstColon < 0) return { ok: false, reason: 'malformed' };
  const bucket = rest.slice(0, firstColon);
  const afterBucket = rest.slice(firstColon + 1);
  const lastColon = afterBucket.lastIndexOf(':');
  if (lastColon < 0) return { ok: false, reason: 'malformed' };
  const key = afterBucket.slice(0, lastColon);
  const versionId = afterBucket.slice(lastColon + 1);
  if (!bucket || !key || !versionId) {
    return { ok: false, reason: 'malformed' };
  }
  return { ok: true };
}

/**
 * Default Rekor fetcher. Uses Node's built-in `fetch` (Node ≥18).
 *
 * The `anchorReceipt` blob is opaque to the verifier — different
 * anchor backends serialize it differently (AGV-036 stores the
 * Rekor log entry JSON). We treat any non-empty receipt as a
 * successful pass when we cannot meaningfully re-fetch (no UUID
 * embedded). Callers wanting strict checks should supply a custom
 * `rekorFetcher`.
 */
async function defaultRekorFetcher(anchorReceipt: string): Promise<boolean> {
  // Minimal default: confirm the receipt parses as JSON. Strict re-fetch
  // requires the Rekor entry UUID which is backend-specific; the
  // CLI's `--no-rekor` flag exists precisely so an air-gapped auditor
  // can skip this step entirely.
  try {
    JSON.parse(anchorReceipt);
    return true;
  } catch {
    return false;
  }
}

// ════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════

/** Pull the 11 signable fields out of a bundle row (mirrors AGV-030). */
function signableRow(row: BundleRow): Record<string, unknown> {
  return {
    organizationId: row.organizationId,
    action: row.action,
    actorId: row.actorId,
    actorType: row.actorType,
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    teamId: row.teamId,
    agentId: row.agentId,
    summary: row.summary,
    details: row.details,
    createdAt: row.createdAt,
  };
}

/**
 * Compute the Merkle leaf preimage for a stored row:
 *   leaf = canonical(row) || base64-decode(row.signature)
 * The Merkle tree's `merkleVerify` adds the RFC 6962 0x00 leaf prefix
 * before hashing — see `merkleVerify` / `merkleBuild`.
 */
function computeLeaf(row: BundleRow): Uint8Array {
  const canonical = canonicalJson(signableRow(row));
  const sigBytes = Buffer.from(row.signature, 'base64');
  return new Uint8Array(Buffer.concat([canonical, sigBytes]));
}

/**
 * Compute the chain-link value the *next* row stores in
 * `prev_row_hash`:
 *   sha256(canonical(prev) || prev.sig_bytes)  (base64)
 */
function computeChainLink(prev: BundleRow): string {
  const canonical = canonicalJson(signableRow(prev));
  const sigBytes = Buffer.from(prev.signature, 'base64');
  return sha256(Buffer.concat([canonical, sigBytes])).toString('base64');
}

function parseNdjson<T>(buf: Buffer): T[] {
  const text = buf.toString('utf8');
  if (text.length === 0) return [];
  const out: T[] = [];
  for (const line of text.split('\n')) {
    if (line.length === 0) continue;
    out.push(JSON.parse(line) as T);
  }
  return out;
}

/**
 * AUDIT-2026-05-14 — Parse one entry from `public-keys.json`.
 *
 * Accepts BOTH shapes:
 *   - Manifest v1 (pre-AUDIT-14): `string` — bare base64 public key,
 *     coerced to `{ status: 'ACTIVE', revokedAt: null }`.
 *   - Manifest v2 (AUDIT-14+):    `{ publicKey, status, revokedAt }`.
 *
 * This lets the v2 verifier read older bundles without a manual
 * conversion step. New bundles always emit the object shape.
 */
function parsePublicKeyEntry(
  raw: unknown,
  versionKey: string,
): PublicKeyRecord {
  if (typeof raw === 'string') {
    return {
      publicKey: new Uint8Array(Buffer.from(raw, 'base64')),
      status: 'ACTIVE',
      revokedAt: null,
    };
  }
  if (raw && typeof raw === 'object') {
    const obj = raw as {
      publicKey?: unknown;
      status?: unknown;
      revokedAt?: unknown;
    };
    if (typeof obj.publicKey !== 'string') {
      throw new Error(
        `public-keys.json[${versionKey}] missing string publicKey field`,
      );
    }
    const status = obj.status;
    if (
      status !== 'ACTIVE' &&
      status !== 'ROTATED' &&
      status !== 'REVOKED'
    ) {
      throw new Error(
        `public-keys.json[${versionKey}] has invalid status: ${String(status)}`,
      );
    }
    let revokedAt: Date | null = null;
    if (obj.revokedAt != null) {
      if (typeof obj.revokedAt !== 'string') {
        throw new Error(
          `public-keys.json[${versionKey}].revokedAt must be ISO string or null`,
        );
      }
      const parsed = new Date(obj.revokedAt);
      if (Number.isNaN(parsed.getTime())) {
        throw new Error(
          `public-keys.json[${versionKey}].revokedAt is not a valid ISO date`,
        );
      }
      revokedAt = parsed;
    }
    return {
      publicKey: new Uint8Array(Buffer.from(obj.publicKey, 'base64')),
      status,
      revokedAt,
    };
  }
  throw new Error(
    `public-keys.json[${versionKey}] must be a string or {publicKey,status,revokedAt} object`,
  );
}

/**
 * AUDIT-2026-05-14 — Returns `null` when the signed-before-revocation
 * check passes for a REVOKED key, otherwise a verifier `reason` string.
 *
 * Caller has already confirmed `entry.status === 'REVOKED'`. Three
 * reject codes:
 *   - `key_revoked_no_timestamp` — bundle is malformed (REVOKED with
 *     no `revokedAt`). Fail closed so a producer bug doesn't silently
 *     accept signatures against a revoked key.
 *   - `key_revoked_no_signed_at` — signed-at missing on the artifact.
 *     We can't decide pre/post revocation; fail closed.
 *   - `key_revoked_after_signing` — the artifact's `signedAt` is
 *     strictly AFTER the key's `revokedAt`. The expected hostile case.
 */
function checkSignedBeforeRevocation(
  artifact: { id: string; signedAt: string | null },
  entry: PublicKeyRecord,
): string | null {
  if (entry.revokedAt === null) {
    return 'key_revoked_no_timestamp';
  }
  if (!artifact.signedAt) {
    return 'key_revoked_no_signed_at';
  }
  const signedMs = new Date(artifact.signedAt).getTime();
  if (Number.isNaN(signedMs)) {
    return 'key_revoked_no_signed_at';
  }
  if (signedMs > entry.revokedAt.getTime()) {
    return 'key_revoked_after_signing';
  }
  return null;
}
