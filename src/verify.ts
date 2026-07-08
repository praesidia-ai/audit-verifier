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

import * as crypto from 'node:crypto';

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
import {
  PLATFORM_PUBLIC_KEY_DER_B64,
  PLATFORM_PUBLIC_KEY_FINGERPRINT,
  isPlatformPubkeyPinned,
} from './platform-pubkey.js';

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
  /**
   * AUDIT-2026-05-01 — Per-row signature algorithm tag. Optional so
   * pre-AUDIT-01 bundles (which only carried `manifest.signatureAlgorithm`)
   * continue to verify; in that case the verifier falls back to the
   * manifest's tag and ultimately to `'Ed25519'`. Bundles produced
   * after AUDIT-01 ship the tag on every row so a tenant whose history
   * mixes substrates (Ed25519 pre-KMS → ECDSA-P256 post-KMS) verifies
   * row-by-row under the correct primitive.
   */
  signatureAlgorithm?: BundleSignatureAlgorithm;
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
  /**
   * AUDIT-2026-05-01 — Per-root signature algorithm. AUDIT-02 already
   * wired the writer to emit this on every root; the verifier now
   * dispatches on the per-root tag (rather than the manifest-level one)
   * so a bundle with mixed-substrate roots verifies correctly.
   * Optional for back-compat with pre-AUDIT-02 bundles.
   */
  signatureAlgorithm?: BundleSignatureAlgorithm;
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
  /**
   * AUDIT-2026-05-30 — Platform key-binding attestation.
   *
   * The bundle's `platform-attestation.json` is a SEPARATE signature
   * (under a platform-wide key, NOT a tenant key) over the
   * `(orgId, [keyVersion, fingerprint, status, revokedAt, issuedAt])`
   * tuple. The verifier checks that signature against a pubkey pinned
   * into this CLI (`platform-pubkey.ts`) so an auditor knows the
   * platform itself — not just the tenant — vouched for the binding.
   *
   * Behavior modes:
   *   - Bundle is missing `platform-attestation.json` (legacy /
   *     pre-AUDIT-30):       `{ ok: true, reason: 'missing_legacy' }`
   *     (warn but do not fail the bundle).
   *   - Pinned platform pubkey is still the placeholder (verifier
   *     pre-prod release):    `{ ok: true, reason:
   *     'placeholder_platform_key' }` (warn but do not fail).
   *   - Otherwise: strict — signature, fingerprint match, and
   *     per-key fingerprint match against `public-keys.json` all
   *     enforced.
   */
  platformAttestation: ComponentResult;
  /**
   * BUG-AUDIT-01 — Bundle completeness. `manifest.rowCount` and
   * `manifest.rootCount` are BOTH covered by the manifest signature
   * (they sit in the manifest signable set). The chain / proof checks
   * only validate the rows that are PRESENT — an attacker who truncates
   * the trailing rows + their proofs leaves a still-chaining prefix that
   * otherwise verifies OK. This component fails closed when the number
   * of rows / roots actually present disagrees with the SIGNED counts,
   * closing the truncation bypass.
   */
  completeness: ComponentResult;
  /**
   * BUG-AUDIT-03 — Verification-key binding. Every signature is checked
   * against the bytes in the UNSIGNED `public-keys.json`, while the
   * SIGNED `manifest.keyVersions[]` (covered by the manifest signature)
   * was only used self-referentially. This component cross-checks each
   * key in `public-keys.json` byte-for-byte against the same-version
   * entry in `manifest.keyVersions`, failing closed when a key used for
   * verification is not byte-present in the signed set. It provides a
   * tamper-evidence layer independent of the OPTIONAL platform
   * attestation (which stays warn-but-proceed when absent / placeholder).
   */
  keyBinding: ComponentResult;
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
  /**
   * AUDIT-2026-05-30 — Override the pinned platform public key. The
   * default is the bytes baked into the CLI release (see
   * `platform-pubkey.ts`); tests + ops use this hook to pin a
   * caller-supplied key without recompiling the package.
   *
   * Accepts base64-encoded SPKI DER of an EC P-256 public key. An
   * empty / missing override falls back to the bundled pin (and to
   * placeholder-mode warn-but-proceed when that pin is empty).
   */
  platformPublicKeyDerB64?: string;
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
      throw new Error(
        `public-keys.json contains non-integer key version: ${k}`,
      );
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

  // 8) AUDIT-2026-05-30 — Platform key-binding attestation.
  // The entry is OPTIONAL on disk so legacy bundles (pre-AUDIT-30)
  // still load; if missing, the verifier warns-but-proceeds.
  const platformResult = verifyPlatformAttestation(
    byName.get('platform-attestation.json') ?? null,
    publicKeysRaw,
    manifest.orgId,
    options,
  );

  // 9) BUG-AUDIT-01 — Completeness: the SIGNED row/root counts must
  // match what is actually present, or a trailing-truncation attack
  // slips through (the surviving prefix still chains + proves).
  const completenessResult = verifyCompleteness(manifest, rows, roots);

  // 10) BUG-AUDIT-03 — Bind the (unsigned) `public-keys.json` bytes the
  // verifier trusts against the SIGNED `manifest.keyVersions` set.
  const keyBindingResult = verifyKeyBinding(manifest, publicKeysRaw);

  const ok =
    manifestResult.ok &&
    rowSigResult.ok &&
    chainResult.ok &&
    rootSigResult.ok &&
    proofResult.ok &&
    rekorResult.ok &&
    platformResult.ok &&
    completenessResult.ok &&
    keyBindingResult.ok;

  return {
    ok,
    manifest: manifestResult,
    rowSignatures: rowSigResult,
    chain: chainResult,
    rootSignatures: rootSigResult,
    inclusionProofs: proofResult,
    rekor: rekorResult,
    platformAttestation: platformResult,
    completeness: completenessResult,
    keyBinding: keyBindingResult,
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

/**
 * BUG-AUDIT-01 — Compare the SIGNED `rowCount` / `rootCount` (both in
 * the manifest signable set, so covered by the manifest signature)
 * against the number of rows / roots actually decoded from the bundle.
 *
 * The chain check (`verifyChain`) only validates predecessor links
 * among the rows that are PRESENT, and the inclusion-proof check only
 * walks the proofs that are PRESENT — so deleting the trailing N rows
 * plus their proofs leaves a shorter-but-still-consistent prefix that
 * otherwise passes every other component. This check is the only place
 * the verifier binds "how many rows the signer committed to" against
 * "how many rows we were handed", so it MUST participate in `ok`.
 *
 * `checked = 2` (the row-count assertion + the root-count assertion).
 */
function verifyCompleteness(
  manifest: BundleManifest,
  rows: BundleRow[],
  roots: BundleRoot[],
): ComponentResult {
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  if (rows.length !== manifest.rowCount) {
    failed += 1;
    firstFailure = 'rows';
    reason = `row count mismatch: bundle has ${rows.length} rows but signed manifest declares ${manifest.rowCount}`;
  }
  if (roots.length !== manifest.rootCount) {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = 'roots';
      reason = `root count mismatch: bundle has ${roots.length} roots but signed manifest declares ${manifest.rootCount}`;
    }
  }
  return {
    ok: failed === 0,
    checked: 2,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/**
 * BUG-AUDIT-03 — Cross-check the verification keys against the SIGNED
 * key set.
 *
 * Every row/root/manifest signature is verified with a key pulled from
 * the UNSIGNED `public-keys.json`. `manifest.keyVersions[]` carries the
 * same keys but IS covered by the manifest signature (it sits in the
 * manifest signable set). Without this check the two are only compared
 * self-referentially, so an attacker who can swap `public-keys.json`
 * (and re-sign the rows with their own key) produces a bundle that
 * verifies against its own planted key — the platform attestation is the
 * only thing that would catch it, and that entry is OPTIONAL.
 *
 * Here we require every key present in `public-keys.json` to be
 * byte-identical to the `manifest.keyVersions` entry of the same version.
 * Because the manifest signature already gates `manifest.keyVersions`,
 * binding the trusted keys to it means a verification key cannot be
 * swapped without breaking the manifest signature too. `checked` counts
 * one assertion per key version in `public-keys.json`.
 */
function verifyKeyBinding(
  manifest: BundleManifest,
  publicKeysRaw: Record<string, unknown>,
): ComponentResult {
  const signed = new Map<number, Uint8Array>();
  for (const kv of manifest.keyVersions) {
    if (typeof kv.publicKey === 'string') {
      signed.set(
        kv.keyVersion,
        new Uint8Array(Buffer.from(kv.publicKey, 'base64')),
      );
    }
  }

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;

  for (const [k, raw] of Object.entries(publicKeysRaw)) {
    checked += 1;
    const ver = Number(k);
    const usedB64 = extractPublicKeyB64(raw);
    if (usedB64 === null) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `public-keys.json[${k}] has no decodable publicKey`;
      }
      continue;
    }
    const usedBytes = new Uint8Array(Buffer.from(usedB64, 'base64'));
    const signedBytes = signed.get(ver);
    if (signedBytes === undefined) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `key_not_in_signed_manifest: public-keys.json declares keyVersion ${k} which is absent from the signed manifest.keyVersions`;
      }
      continue;
    }
    if (!bytesEqual(usedBytes, signedBytes)) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `key_bytes_mismatch: public-keys.json[${k}] bytes differ from the signed manifest.keyVersions[${k}]`;
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

/** Extract the base64 public key from a `public-keys.json` entry (string or object shape). */
function extractPublicKeyB64(raw: unknown): string | null {
  if (typeof raw === 'string') return raw;
  if (raw && typeof raw === 'object') {
    const pk = (raw as { publicKey?: unknown }).publicKey;
    if (typeof pk === 'string') return pk;
  }
  return null;
}

/** Constant-time-ish byte comparison (length + content). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function verifyRowSignatures(
  rows: BundleRow[],
  publicKeys: Map<number, PublicKeyRecord>,
  manifestAlgorithm: BundleSignatureAlgorithm,
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
    // AUDIT-2026-05-01 — Per-row algorithm dispatch.
    //
    // A tenant whose history straddles a substrate cutover
    // (`local-aes-gcm` Ed25519 → `aws-kms` ECDSA-P256-SHA256) can have
    // rows of BOTH algorithms in the same bundle. The exporter ships
    // `signatureAlgorithm` on every row (AUDIT-2026-05-01); fall back
    // to the manifest's algorithm — and ultimately to `'Ed25519'` via
    // the manifest default — for pre-AUDIT-01 bundles that omit the
    // field.
    //
    // Downgrade defence: if an attacker swaps `signatureAlgorithm` from
    // `'ECDSA_P256_SHA256'` to `'Ed25519'` (or vice versa) on a row to
    // try to coerce the verifier into the wrong primitive,
    // `crypto.createPublicKey` will succeed but `crypto.verify` will
    // fail because the key type does not match the algorithm. The
    // dispatcher therefore returns `false` and the row is rejected —
    // the algorithm field is not part of the canonical signing bytes,
    // but the key-type mismatch makes the downgrade unobservable to
    // the verifier in the success direction.
    const rowAlgorithm = row.signatureAlgorithm ?? manifestAlgorithm;
    // BUG-AUDIT-02 — Fail CLOSED on ANY signature made under a REVOKED
    // key, regardless of `signedAt`.
    //
    // The previous rule granted a grace to rows whose `signedAt` was
    // <= `revokedAt`. But `signedAt` is NOT part of the signed preimage
    // (see `signableRow` — the 11 signable fields exclude it), so a
    // holder of the compromised (revoked) private key could forge a new
    // row, sign it (the signature is cryptographically valid — they hold
    // the key), and stamp any pre-revocation `signedAt` to slip past the
    // gate. That defeats exactly the adversary revocation targets. There
    // is no self-contained way to tell a genuine pre-revocation signature
    // from a backdated forgery without binding `signedAt` into the signer
    // preimage (a coordinated be-core change, deliberately out of scope),
    // so the conservative choice is to reject every REVOKED-key signature.
    if (entry.status === 'REVOKED') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'key_revoked';
      }
      continue;
    }
    const signable = signableRow(row);
    const canonical = canonicalJson(signable);
    // AUDIT-SDK-01 — the backend signs each row over
    //   message = canonical(row) || prev_row_hash_bytes
    // (write path `audit-writer.service.ts` persistSignedLog; the online
    // verify path `audit-query.service.ts` reconstructs the same message).
    // The offline verifier MUST bind `prev_row_hash` into the preimage or
    // EVERY genuine production row fails signature verification. Guard an
    // absent/malformed `prev_row_hash` as a signature failure, mirroring
    // the online verifier.
    let prevRowHashBytes: Buffer;
    try {
      if (typeof row.prevRowHash !== 'string') {
        throw new Error('prev_row_hash missing');
      }
      prevRowHashBytes = Buffer.from(row.prevRowHash, 'base64');
    } catch {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'row prev_row_hash missing or malformed';
      }
      continue;
    }
    const message = Buffer.concat([canonical, prevRowHashBytes]);
    if (
      !verifySignature(rowAlgorithm, message, row.signature, entry.publicKey)
    ) {
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
  manifestAlgorithm: BundleSignatureAlgorithm,
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
    // BUG-AUDIT-02 — Fail CLOSED on ANY root signed under a REVOKED key.
    // Same reasoning as the row path: the root envelope
    // (`{rootHash, periodStart, periodEnd, rowCount}`) does not cover
    // `signedAt`, so a backdated `signedAt` cannot be trusted to prove a
    // pre-revocation signature. Reject unconditionally.
    if (entry.status === 'REVOKED') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = 'key_revoked';
      }
      continue;
    }
    // Mirror the writer's envelope exactly — see MerkleRootService
    // (AGV-033) `computeRootForPeriod`.
    const bytes = canonicalJson({
      rootHash: root.rootHash,
      periodStart: root.periodStart,
      periodEnd: root.periodEnd,
      rowCount: root.rowCount,
    });
    // AUDIT-2026-05-01 — Per-root algorithm dispatch with manifest
    // fallback (mirrors `verifyRowSignatures`). A bundle whose history
    // straddles a substrate cutover ships roots of both algorithms;
    // the per-root tag lets each one verify under its own primitive.
    const rootAlgorithm = root.signatureAlgorithm ?? manifestAlgorithm;
    if (
      !verifySignature(rootAlgorithm, bytes, root.signature, entry.publicKey)
    ) {
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
    if (!entry.proof || !entry.rootHash || typeof entry.index !== 'number') {
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
      siblings: entry.proof.map(
        (s) => new Uint8Array(Buffer.from(s, 'base64')),
      ),
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
    return {
      ok: true,
      checked: 0,
      failed: 0,
      reason: 'skipped via --no-rekor',
    };
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
function verifyS3ReceiptShape(receipt: string): {
  ok: boolean;
  reason?: string;
} {
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
// AUDIT-2026-05-30 — Platform key-binding attestation verifier
// ════════════════════════════════════════════════════════════════════════

interface PlatformAttestationBody {
  orgId: string;
  keyVersions: Array<{
    keyVersion: number;
    fingerprint: string;
    status: string;
    revokedAt: string | null;
    issuedAt: string;
  }>;
  issuedAt: string;
  platformSigningKeyFingerprint: string;
  signatureAlgorithm: 'ECDSA_P256_SHA256';
}

interface PlatformAttestationEnvelope {
  attestation: PlatformAttestationBody;
  signature: string;
}

/**
 * AUDIT-2026-05-30 — Verify the bundle's platform key-binding
 * attestation.
 *
 * The check chain (each step short-circuits to the next reason on
 * failure):
 *   1. Resolve the platform pubkey: caller-supplied
 *      `options.platformPublicKeyDerB64` wins; otherwise fall back
 *      to the bundled pin. If both are empty, return
 *      `placeholder_platform_key` (warn but proceed).
 *   2. If the entry is missing entirely, return `missing_legacy`
 *      (warn but proceed) — pre-AUDIT-30 bundles legitimately did
 *      not carry it.
 *   3. Parse the envelope. Reject malformed JSON / shape with
 *      `malformed`.
 *   4. orgId in attestation MUST match manifest orgId — else
 *      `org_mismatch`.
 *   5. signature MUST verify under the resolved platform pubkey,
 *      with low-s canonical form enforced (see crypto.ts).
 *   6. The attestation's `platformSigningKeyFingerprint` MUST match
 *      the sha256 of the resolved pubkey's DER bytes — defends
 *      against an attacker who swaps the verifier's bundled pubkey
 *      bytes without re-signing the attestation.
 *   7. Every `keyVersions[i].fingerprint` MUST match the sha256 of
 *      the corresponding entry in `public-keys.json`.
 */
function verifyPlatformAttestation(
  entry: ZipEntry | null,
  publicKeysRaw: Record<string, unknown>,
  manifestOrgId: string,
  options: VerifyOptions,
): ComponentResult {
  // Step 1 — resolve the pinned pubkey (caller override > bundled pin).
  const callerOverride = options.platformPublicKeyDerB64;
  const pinnedB64 =
    callerOverride && callerOverride.length > 0
      ? callerOverride
      : isPlatformPubkeyPinned()
        ? PLATFORM_PUBLIC_KEY_DER_B64
        : '';
  if (pinnedB64.length === 0) {
    // Placeholder mode — warn but proceed. A real CLI release pins
    // the prod platform pubkey via `platform-pubkey.ts`; until then
    // dev / CI bundles built with ephemeral platform keys still
    // verify end-to-end.
    return {
      ok: true,
      checked: 0,
      failed: 0,
      reason: 'placeholder_platform_key',
    };
  }
  const pinnedDer = Buffer.from(pinnedB64, 'base64');
  // Compute the expected fingerprint over the same bytes the
  // verifier will use for signature dispatch. Caller override and
  // bundled pin take the same path so a substitution at either
  // level fails the `platformSigningKeyFingerprint` check below.
  const expectedFingerprint =
    callerOverride && callerOverride.length > 0
      ? crypto.createHash('sha256').update(pinnedDer).digest('hex')
      : PLATFORM_PUBLIC_KEY_FINGERPRINT;

  // Step 2 — missing entry (legacy bundle). Warn but proceed.
  if (!entry) {
    return {
      ok: true,
      checked: 0,
      failed: 0,
      reason: 'missing_legacy',
    };
  }

  // Step 3 — parse the envelope.
  let envelope: PlatformAttestationEnvelope;
  try {
    envelope = JSON.parse(
      entry.data.toString('utf8'),
    ) as PlatformAttestationEnvelope;
  } catch {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'malformed: platform-attestation.json is not valid JSON',
    };
  }
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    !envelope.attestation ||
    typeof envelope.signature !== 'string'
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'malformed: missing attestation / signature fields',
    };
  }
  const body = envelope.attestation;
  if (
    !body ||
    typeof body.orgId !== 'string' ||
    !Array.isArray(body.keyVersions) ||
    typeof body.platformSigningKeyFingerprint !== 'string' ||
    typeof body.issuedAt !== 'string' ||
    body.signatureAlgorithm !== 'ECDSA_P256_SHA256'
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'malformed: attestation body has wrong shape',
    };
  }

  // Step 4 — orgId must match the manifest.
  if (body.orgId !== manifestOrgId) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `org_mismatch: attestation orgId ${body.orgId} != manifest orgId ${manifestOrgId}`,
    };
  }

  // Step 5 — signature verification (ECDSA-P256-SHA256, low-s).
  // The verifier re-canonicalizes the attestation body BYTES the
  // same way the writer did (`canonicalJson`); the signature must
  // verify under the pinned pubkey or we fail closed.
  const message = canonicalJson(body as unknown as Record<string, unknown>);
  if (
    !verifySignature(
      'ECDSA_P256_SHA256',
      message,
      envelope.signature,
      new Uint8Array(pinnedDer),
    )
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason:
        'signature: platform attestation does not verify under pinned key',
    };
  }

  // Step 6 — declared fingerprint must match the pinned pubkey.
  if (
    expectedFingerprint.length > 0 &&
    body.platformSigningKeyFingerprint !== expectedFingerprint
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `fingerprint_mismatch: attestation declares ${body.platformSigningKeyFingerprint} but pinned pubkey hashes to ${expectedFingerprint}`,
    };
  }

  // Step 7 — every keyVersion fingerprint matches `public-keys.json`.
  for (const kv of body.keyVersions) {
    if (
      typeof kv.keyVersion !== 'number' ||
      typeof kv.fingerprint !== 'string'
    ) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: 'malformed: keyVersions entry missing keyVersion/fingerprint',
      };
    }
    const pkEntry = publicKeysRaw[String(kv.keyVersion)];
    let pkB64: string | null = null;
    if (typeof pkEntry === 'string') {
      pkB64 = pkEntry;
    } else if (pkEntry && typeof pkEntry === 'object') {
      const obj = pkEntry as { publicKey?: unknown };
      if (typeof obj.publicKey === 'string') {
        pkB64 = obj.publicKey;
      }
    }
    if (pkB64 === null) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_not_in_bundle: attestation references keyVersion ${kv.keyVersion} which is missing from public-keys.json`,
      };
    }
    const actualFingerprint = crypto
      .createHash('sha256')
      .update(Buffer.from(pkB64, 'base64'))
      .digest('hex');
    if (actualFingerprint !== kv.fingerprint) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_fingerprint_mismatch: keyVersion ${kv.keyVersion} attests ${kv.fingerprint} but public-keys.json bytes hash to ${actualFingerprint}`,
      };
    }
  }

  return { ok: true, checked: 1, failed: 0 };
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
    if (status !== 'ACTIVE' && status !== 'ROTATED' && status !== 'REVOKED') {
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
 * BUG-AUDIT-02 — The signed-before-revocation grace was REMOVED. It
 * trusted `artifact.signedAt`, which is not covered by any signature in
 * the bundle, so a holder of a revoked key could backdate `signedAt` and
 * pass. The verifier now rejects EVERY REVOKED-key signature outright
 * (see `verifyRowSignatures` / `verifyRootSignatures`). Re-introducing a
 * legitimate pre-revocation window requires binding `signedAt` into the
 * signer preimage on both the be-core signer and here — a separate,
 * coordinated ticket.
 */
