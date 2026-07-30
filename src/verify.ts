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
 *  - Verification is fully offline; provider-specific online checks are
 *    available only through explicit caller-supplied hooks.
 *
 * INVARIANTS the verifier checks:
 *  1. Manifest signature        — Ed25519 over canonical-JSON of the
 *                                 manifest's signable fields, verified
 *                                 with `publicKeys[manifest.signatureKeyVersion]`.
 *  2. Row signatures            — for each row, canonical-JSON over the
 *                                 11 signable fields (mirrors AGV-030)
 *                                 verified with `publicKeys[row.keyVersion]`.
 *  3. Chain integrity           — each row's `prevRowHash` matches
 *                                 `sha256(prev.canonical || prev.sigBytes)`
 *                                 of its TRUE in-bundle predecessor, found
 *                                 by following the cryptographic links
 *                                 themselves (PROD16 F10) rather than by
 *                                 trusting the bundle's on-disk row order —
 *                                 be-core's exporter orders rows by
 *                                 `(signedAt, id)`, which does not always
 *                                 match the actual `chainSeq` order, so
 *                                 file-order trust produced false chain-break
 *                                 verdicts on honest bundles. The ONE row
 *                                 with no in-bundle predecessor is an opaque
 *                                 anchor into the org's pre-range history
 *                                 (bundles are date-ranged, not
 *                                 genesis-rooted), so it is accepted, not
 *                                 required to be the all-zero genesis
 *                                 (BUGHUNT-SDK-02).
 *  4. Merkle root signatures    — canonical-JSON over
 *                                 `{rootHash, periodStart, periodEnd, rowCount}`
 *                                 verified with `publicKeys[root.keyVersion]`.
 *  5. Inclusion proofs          — `merkleVerify(leaf, proof, rootHash)`
 *                                 where `leaf = canonical(row) || sigBytes`
 *                                 (AGV-033 leaf preimage). Proof rows
 *                                 and exactly one valid proof is required
 *                                 for every exported row. Status markers
 *                                 are diagnostic failures, not proofs.
 *  6. Rekor receipt (optional)  — when not skipped, REAL offline
 *                                 verification (BUGHUNT-SDK-05): the
 *                                 receipt's Signed Entry Timestamp (SET)
 *                                 is verified against the pinned Sigstore
 *                                 Rekor public key and its inclusion proof
 *                                 is walked to `inclusionProof.rootHash`
 *                                 (see `rekor.ts`). A receipt that is not
 *                                 a genuine, SET-signed, log-included
 *                                 entry fails closed. Skipped only via
 *                                 `--no-rekor` / `noRekor`.
 */

import * as crypto from 'node:crypto';

import {
  canonicalJson,
  decodeBase64Strict,
  sha256,
  verifySignature,
  type BundleSignatureAlgorithm,
  merkleVerify,
  type MerkleProof,
} from './crypto.js';
import { readZip, gunzip, type ZipEntry } from './zip.js';
import { verifyRekorReceipt } from './rekor.js';
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
   * PROD16 F6 (be-compliance) — Signed only for rows produced at/after the
   * be-side `IP_ADDRESS_SIGNABLE_CUTOVER_AT` activation. Optional/absent
   * on the wire for every row signed before that cutover (and for all
   * pre-AUDIT-14 bundles). See {@link signableRow} — the verifier includes
   * this key in the canonical preimage IFF the wire row actually carries
   * it, mirroring `audit-canonical.helper.ts`'s own conditional shape
   * without needing to know the cutover instant.
   */
  ipAddress?: string | null;
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
   * Missing attestation or a missing platform key fails closed. Legacy
   * bundles may be accepted only through the explicit
   * `allowLegacyUnattested` option.
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
  /**
   * PROD16 (be-compliance F5 / audit-verifier's half of the same finding).
   *
   * `verifyChain` only asserts links between rows that are PRESENT in the
   * bundle — a back-linked chain has no forward pointer, so deleting a
   * TRAILING suffix of an org's rows (with no successor left in the
   * bundle to notice a broken link) is invisible to it. `verifyInclusionProofs`
   * only proves that every row it IS given proves into its root — Merkle
   * proofs are existence proofs, not absence proofs. Neither catches "a
   * root's SIGNED `rowCount` says N rows existed in this period, and the
   * bundle now contains fewer than N of them."
   *
   * This component binds each root's signed `rowCount` to how many of the
   * bundle's own rows/proof-entries actually fall inside that root's
   * period, for every period fully contained in the bundle's declared
   * `[from, to)` range (boundary periods that only partially overlap the
   * range are exempted — a genuine ranged export legitimately ships fewer
   * rows for those, since rows outside `[from, to)` are never exported).
   */
  rootCoverage: ComponentResult;
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
   * BUGHUNT-SDK-05 — Explicit override for the `rekor` receipt check
   * (e.g. an on-line re-fetch). When supplied it wins for `rekor`
   * receipts; when ABSENT the verifier now runs REAL offline
   * verification (SET signature under the pinned Sigstore key +
   * inclusion proof — see `rekor.ts`), NOT the old `JSON.parse`-only
   * default that returned `true` for any valid JSON. Receives the raw
   * receipt string; returns `true` on success.
   */
  rekorFetcher?: (anchorReceipt: string) => Promise<boolean>;
  /**
   * BUGHUNT-SDK-05 — Override the pinned Rekor signing public key (PEM
   * SPKI, EC P-256) used to verify the SET. Defaults to the Sigstore
   * key bundled in `rekor.ts`. Supply this for a sovereign / private
   * Rekor instance (or tests). Ignored when a custom `rekorFetcher` /
   * `anchorReceiptVerifier` is provided.
   */
  rekorPublicKeyPem?: string;
  /**
   * AUDIT-2026-05-09 — Optional hook for verifying provider-specific
   * anchor receipts in the multi-anchor `anchorReceipts` array. The
   * verifier dispatches on `entry.provider`:
   *
   *   - `'rekor'`   → falls back to `rekorFetcher` when this hook is
   *                   absent (preserves the legacy single-anchor path).
   *   - `'s3'`      → fails closed because an offline shape check cannot
   *                   prove object existence or immutability. A caller
   *                   wanting verification supplies this hook.
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
   * empty / missing override falls back to the bundled pin. Verification
   * fails closed when neither source contains a key.
   */
  platformPublicKeyDerB64?: string;
  /**
   * Explicitly accept a pre-attestation legacy bundle. Defaults to false so a
   * self-signed bundle cannot pass without an external platform trust anchor.
   */
  allowLegacyUnattested?: boolean;
}

/**
 * PROD16 F6 (be-compliance) — Explicit version negotiation.
 *
 * `manifest.version` was previously accepted with a floor (`>= 1`) but no
 * ceiling — any future schema version parsed and verified positionally
 * against TODAY's field set, silently. That is exactly how the
 * `IP_ADDRESS_SIGNABLE_CUTOVER_AT` skew was reachable: a be-side signable
 * shape change with no matching verifier release would not even be
 * detectable as "a shape this verifier doesn't understand" — it would
 * just verify wrong (or, worse, appear to verify while silently omitting a
 * signed field this build has never heard of). A manifest version beyond
 * what this build implements now fails LOUDLY, as a bundle-format error,
 * instead of being interpreted under the wrong rules.
 *
 * Bump this alongside adding real support for the new version's fields —
 * never bump it "ahead of" support just to silence this check.
 */
const MAX_SUPPORTED_MANIFEST_VERSION = 2;

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
  assertManifestStructure(manifest);

  const publicKeysParsed: unknown = JSON.parse(
    byName.get('public-keys.json')!.data.toString('utf8'),
  );
  if (
    publicKeysParsed === null ||
    typeof publicKeysParsed !== 'object' ||
    Array.isArray(publicKeysParsed)
  ) {
    throw new Error('public-keys.json must contain an object');
  }
  const publicKeysRaw = publicKeysParsed as Record<string, unknown>;
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
  assertRowsStructure(rows, manifest.orgId);

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
  assertRootsStructure(roots, manifest.orgId);
  const rootSigResult = verifyRootSignatures(
    roots,
    publicKeys,
    manifest.signatureAlgorithm,
  );

  // 6) Parse + verify inclusion proofs.
  const proofsNdjson = gunzip(byName.get('proofs.ndjson.gz')!.data);
  const proofs = parseNdjson<BundleProofEntry>(proofsNdjson);
  assertProofsStructure(proofs);
  const proofResult = verifyInclusionProofs(rows, roots, proofs);

  // 7) Optional Rekor fetch.
  const rekorResult = await verifyRekorReceipts(roots, options);

  // 8) AUDIT-2026-05-30 — Platform key-binding attestation.
  // The entry remains optional in the ZIP grammar for backwards parsing,
  // but its absence fails verification unless explicitly allowed.
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

  // 10) BUG-AUDIT-03 / PROD15 — Bind the (unsigned) `public-keys.json`
  // bytes AND lifecycle (status/revokedAt) the verifier trusts against
  // the SIGNED `manifest.keyVersions` set.
  const keyBindingResult = verifyKeyBinding(manifest, publicKeysRaw, publicKeys);

  // 11) PROD16 — Root row-coverage: bind each fully-contained root's
  // SIGNED rowCount to the bundle's own row/proof counts for that period,
  // closing the trailing-suffix-deletion gap `completeness` cannot see
  // (see the `rootCoverage` field doc comment above).
  const rootCoverageResult = verifyRootCoverage(manifest, rows, roots, proofs);

  const ok =
    manifestResult.ok &&
    rowSigResult.ok &&
    chainResult.ok &&
    rootSigResult.ok &&
    proofResult.ok &&
    rekorResult.ok &&
    platformResult.ok &&
    completenessResult.ok &&
    keyBindingResult.ok &&
    rootCoverageResult.ok;

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
    rootCoverage: rootCoverageResult,
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
  // RA-05 (PROD15 re-attack) — Fail CLOSED on a manifest signed under a
  // REVOKED key, mirroring `verifyRowSignatures` / `verifyRootSignatures`.
  //
  // The manifest is itself the signed document carrying `orgId`, `from`,
  // `to`, `rowCount`, `rootCount` and the whole `keyVersions` set — including
  // the very `status`/`revokedAt` fields the PROD15 `verifyKeyBinding` cross
  // -check relies on. A holder of a compromised (revoked) key can mint a
  // brand-new, validly-signed manifest asserting anything they like,
  // including a `keyVersions[]` set that dishonestly re-labels their own
  // key ACTIVE. Without this check, `verifyKeyBinding` would faithfully
  // confirm `public-keys.json` matches that dishonest-but-signed manifest
  // and the forgery would verify.
  //
  // Same reasoning as the row/root siblings applies to why there is no
  // signed-before-revocation grace period here: although `generatedAt` IS
  // part of the manifest's signed preimage (unlike a row's `signedAt`),
  // that does not help — a key holder can sign a FRESH manifest with any
  // `generatedAt` they choose, so a backdated timestamp is exactly as
  // forgeable as an unsigned one. There is no self-contained way to tell a
  // genuine pre-revocation manifest from a backdated forgery, so the
  // conservative choice is to reject every REVOKED-key manifest signature
  // unconditionally, exactly like `verifyRowSignatures` / `verifyRootSignatures`.
  if (entry.status === 'REVOKED') {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'key_revoked',
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
 *
 * PROD15 — `manifest.keyVersions[]` also carries `status`/`revokedAt`
 * (AUDIT-2026-05-14, optional for v1 bundles) but nothing previously
 * compared it to `public-keys.json`. `verifyRowSignatures` /
 * `verifyRootSignatures` read revocation status only from the UNSIGNED
 * `public-keys.json`, so — whenever platform attestation is skipped via
 * `allowLegacyUnattested` — an attacker who edits only that file to
 * relabel a REVOKED key ACTIVE could resurrect signatures made under a
 * compromised key. When the signed manifest entry carries a status, we
 * now also require `status`/`revokedAt` to match; when it does not
 * (true v1 bundles), we fall back to trusting `public-keys.json` alone
 * so those bundles keep verifying.
 *
 * RA-05 (PROD15 re-attack) Gap 2 — the per-entry `status !== undefined`
 * gate above was itself attacker-selectable: the exporter (AUDIT-2026-05-14,
 * `bundle-exporter.service.ts`) bumps `manifest.version` to 2 in the SAME
 * change that starts stamping `status`/`revokedAt` on every
 * `keyVersions[]` entry, so a genuine v2 manifest ALWAYS carries a status
 * for every key. A holder of a compromised key re-signing a fresh v2-shaped
 * manifest could omit `status` on just that one entry (structurally legal —
 * `assertManifestStructure` does not require it) to fall through to the
 * lenient "trust public-keys.json alone" branch while still claiming
 * `version: 2`. We now also require the lifecycle cross-check whenever
 * `manifest.version >= 2`, regardless of whether the signed entry bothered
 * to carry a `status`: an absent signed `status` on a v2 manifest can never
 * equal `usedRecord.status` (which is always a defined enum), so it fails
 * closed as `key_status_mismatch` rather than silently falling back. A
 * TRUE v1 bundle (`manifest.version === 1`) that never carried the field at
 * all is unaffected and keeps verifying under the original fallback — this
 * does not (and structurally cannot) close an attacker who forges the
 * ENTIRE bundle, including `manifest.version: 1` and a v1-shaped
 * `public-keys.json`; that residual is the same trust limit `--allow-legacy
 * -unattested` already accepts for genuinely old, pre-AUDIT-14 archives
 * (see the package README / RA-05 Gap 2 discussion) and requires mandatory
 * platform attestation to close, which is a documented, deliberate escape
 * hatch this fix does not touch.
 */
function verifyKeyBinding(
  manifest: BundleManifest,
  publicKeysRaw: Record<string, unknown>,
  publicKeys: Map<number, PublicKeyRecord>,
): ComponentResult {
  const signed = new Map<
    number,
    { publicKey: Uint8Array; status?: string; revokedAt?: string | null }
  >();
  for (const kv of manifest.keyVersions) {
    if (typeof kv.publicKey === 'string') {
      const decoded = decodeBase64Strict(kv.publicKey);
      if (decoded === null) continue;
      signed.set(kv.keyVersion, {
        publicKey: new Uint8Array(decoded),
        status: kv.status,
        revokedAt: kv.revokedAt,
      });
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
    const decoded = decodeBase64Strict(usedB64);
    if (decoded === null) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `public-keys.json[${k}] is not canonical base64`;
      }
      continue;
    }
    const usedBytes = new Uint8Array(decoded);
    const signedEntry = signed.get(ver);
    if (signedEntry === undefined) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `key_not_in_signed_manifest: public-keys.json declares keyVersion ${k} which is absent from the signed manifest.keyVersions`;
      }
      continue;
    }
    if (!bytesEqual(usedBytes, signedEntry.publicKey)) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `key_bytes_mismatch: public-keys.json[${k}] bytes differ from the signed manifest.keyVersions[${k}]`;
      }
      continue;
    }
    // PROD15 — Bind lifecycle metadata too, not just key bytes.
    //
    // `status`/`revokedAt` on `manifest.keyVersions[]` are optional
    // (true v1 bundles pre-date AUDIT-14 and never carried them). Only
    // enforce the cross-check when the SIGNED manifest actually declares
    // a status for this key version; otherwise fall back to trusting
    // `public-keys.json` alone, exactly as before, so genuine legacy
    // bundles keep verifying. When the signed manifest DOES carry a
    // status, an attacker who edits only the unsigned public-keys.json
    // to relabel a REVOKED key as ACTIVE (or clear revokedAt) must not
    // be able to resurrect that key's signatures merely because platform
    // attestation was skipped.
    //
    // RA-05 Gap 2 — a v2 manifest (`manifest.version >= 2`) is REQUIRED to
    // carry a status on every entry (the exporter change that introduced
    // `status`/`revokedAt` is the same change that bumped the version), so
    // an omitted `status` on a v2-labelled manifest is never legitimate.
    // Force the cross-check to run in that case too — `usedRecord.status`
    // is always a defined enum, so it can never equal an omitted `undefined`
    // signed status, and the entry fails closed as `key_status_mismatch`
    // instead of silently taking the true-v1 fallback.
    if (manifest.version >= 2 || signedEntry.status !== undefined) {
      const usedRecord = publicKeys.get(ver);
      if (usedRecord === undefined || usedRecord.status !== signedEntry.status) {
        failed += 1;
        if (firstFailure === undefined) {
          firstFailure = k;
          reason = `key_status_mismatch: public-keys.json[${k}] status differs from the signed manifest.keyVersions[${k}]`;
        }
        continue;
      }
      const signedRevokedAtTime =
        signedEntry.revokedAt == null ? null : Date.parse(signedEntry.revokedAt);
      const usedRevokedAtTime =
        usedRecord.revokedAt === null ? null : usedRecord.revokedAt.getTime();
      const signedRevokedAtInvalid =
        signedEntry.revokedAt != null && Number.isNaN(signedRevokedAtTime);
      if (
        signedRevokedAtInvalid ||
        signedRevokedAtTime !== usedRevokedAtTime
      ) {
        failed += 1;
        if (firstFailure === undefined) {
          firstFailure = k;
          reason = `key_revoked_at_mismatch: public-keys.json[${k}] revokedAt differs from the signed manifest.keyVersions[${k}]`;
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

/** First index in a sorted ascending array with value >= target. */
function lowerBound(sorted: number[], target: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (sorted[mid]! < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * PROD16 (be-compliance F5(a) / audit-verifier's half of the same finding).
 * See the `rootCoverage` field doc comment on {@link VerifyReport} for the
 * full rationale. Uses independent binary-search counts per root (not a
 * shared advancing pointer) so the result is correct even if a forged
 * bundle declares overlapping root periods.
 */
function verifyRootCoverage(
  manifest: BundleManifest,
  rows: BundleRow[],
  roots: BundleRoot[],
  proofs: BundleProofEntry[],
): ComponentResult {
  const fromMs = Date.parse(manifest.from);
  const toMs = Date.parse(manifest.to);

  const proofCountByRootHash = new Map<string, number>();
  for (const proof of proofs) {
    if (typeof proof.rootHash === 'string') {
      proofCountByRootHash.set(
        proof.rootHash,
        (proofCountByRootHash.get(proof.rootHash) ?? 0) + 1,
      );
    }
  }

  const rowTimes: number[] = [];
  for (const row of rows) {
    if (typeof row.signedAt === 'string') {
      const t = Date.parse(row.signedAt);
      if (!Number.isNaN(t)) rowTimes.push(t);
    }
  }
  rowTimes.sort((a, b) => a - b);

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;

  for (const root of roots) {
    const periodStartMs = Date.parse(root.periodStart);
    const periodEndMs = Date.parse(root.periodEnd);
    // Only assert full coverage for periods entirely inside the bundle's
    // declared range — a boundary period legitimately ships fewer rows
    // than its full rowCount, since rows outside [from, to) are never
    // exported (see bundle-exporter.service.ts's root-selection query).
    if (!(periodStartMs >= fromMs && periodEndMs <= toMs)) {
      continue;
    }
    checked += 1;
    const rowsInPeriod =
      lowerBound(rowTimes, periodEndMs) - lowerBound(rowTimes, periodStartMs);
    if (rowsInPeriod !== root.rowCount) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = `root ${root.id} commits to rowCount ${root.rowCount} but the bundle contains ${rowsInPeriod} rows with signedAt inside its period — a fully-anchored period must not lose rows`;
      }
      continue;
    }
    const proofsForRoot = proofCountByRootHash.get(root.rootHash) ?? 0;
    if (proofsForRoot !== root.rowCount) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = `root ${root.id} commits to rowCount ${root.rowCount} but the bundle contains ${proofsForRoot} proof entries referencing it`;
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
      const decoded = decodeBase64Strict(row.prevRowHash, 32);
      if (decoded === null) throw new Error('prev_row_hash malformed');
      prevRowHashBytes = decoded;
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

/**
 * PROD16 F10 (be-compliance) — reconstruct the true chain order from the
 * cryptographic links themselves, NOT from the bundle's on-disk row order.
 *
 * Before this fix, `verifyChain` trusted `rows.ndjson.gz`'s file order and
 * compared each row's `prevRowHash` to `computeChainLink(previousArrayEntry)`.
 * The producer orders rows by `(signedAt, id)` while the chain is actually
 * built in `chainSeq` order (a DB sequence). Two rows in the same org
 * sharing a `signedAt` millisecond — the expected case for
 * `PendingSignatureDrainService`'s same-transaction signing bursts, not an
 * edge case — are then ordered by random UUID `id`, so an HONEST bundle has
 * roughly even odds of being emitted in reverse chain order and reporting a
 * false `prev_row_hash does not chain to previous row`. A verifier that
 * cries tamper on good evidence is nearly as damaging as one that misses
 * real tampering.
 *
 * The fix removes the file-order dependency entirely: every row's forward
 * chain-link (`computeChainLink`, the value ITS successor must declare as
 * `prevRowHash`) is computed once and indexed. The true predecessor of any
 * row is then found by that value, regardless of where either row sits in
 * the array. This is strictly MORE attack-resistant than the old
 * position-based check (an attacker gains nothing from reordering the
 * ndjson lines) and does not need `be` to emit `chainSeq` on the wire.
 *
 * A well-formed bundle's rows form exactly one linked chain: exactly one
 * row has no in-bundle predecessor (BUGHUNT-SDK-02's opaque range anchor),
 * and following successor links from it visits every row exactly once.
 * Two rows ever declaring the identical `prevRowHash` (a fork — two rows
 * both claiming to succeed the same predecessor) fails closed immediately.
 */
function verifyChain(rows: BundleRow[]): ComponentResult {
  if (rows.length === 0) {
    return { ok: true, checked: 0, failed: 0 };
  }

  // Every row's OWN forward chain-link — the value its true successor (if
  // any, and if present in this bundle) must declare as `prevRowHash`.
  const chainLinkToRow = new Map<string, BundleRow>();
  for (const row of rows) {
    const link = computeChainLink(row);
    if (link !== null && !chainLinkToRow.has(link)) {
      chainLinkToRow.set(link, row);
    }
  }

  // Group rows by their OWN declared `prevRowHash`. Used both to find each
  // row's true predecessor (by value, not position) and to detect forks.
  const byDeclaredPrev = new Map<string, BundleRow[]>();
  for (const row of rows) {
    if (typeof row.prevRowHash === 'string') {
      const arr = byDeclaredPrev.get(row.prevRowHash) ?? [];
      arr.push(row);
      byDeclaredPrev.set(row.prevRowHash, arr);
    }
  }

  // Fork check: two DIFFERENT rows must never declare the identical
  // prevRowHash — that would mean two rows both claim to be the immediate
  // successor of the same predecessor (or both claim to be the bundle's
  // leading anchor row).
  for (const claimants of byDeclaredPrev.values()) {
    if (claimants.length > 1) {
      return {
        ok: false,
        checked: rows.length,
        failed: claimants.length - 1,
        firstFailure: claimants[1]!.id,
        reason: `chain fork: rows ${claimants.map((r) => r.id).join(', ')} all declare the same prevRowHash`,
      };
    }
  }

  // Rows with no in-bundle predecessor. Exactly one is expected (the
  // leading row's opaque anchor); any other count means the rows do not
  // form a single connected chain.
  const headCandidates = rows.filter(
    (row) =>
      typeof row.prevRowHash !== 'string' ||
      !chainLinkToRow.has(row.prevRowHash),
  );
  if (headCandidates.length !== 1) {
    return {
      ok: false,
      checked: rows.length,
      failed: Math.max(1, headCandidates.length),
      firstFailure: (headCandidates[1] ?? headCandidates[0] ?? rows[0])!.id,
      reason:
        headCandidates.length === 0
          ? 'chain has no identifiable leading row (cycle or corrupted links)'
          : 'prev_row_hash does not chain to previous row',
    };
  }

  // Walk forward from the unique head; a fork or an unreachable row would
  // otherwise slip past the checks above.
  let current: BundleRow | undefined = headCandidates[0];
  const visited = new Set<string>();
  let steps = 0;
  while (current) {
    visited.add(current.id);
    steps += 1;
    const link = computeChainLink(current);
    current = link !== null ? byDeclaredPrev.get(link)?.[0] : undefined;
  }
  if (visited.size !== rows.length) {
    const orphan = rows.find((r) => !visited.has(r.id));
    return {
      ok: false,
      checked: rows.length,
      failed: rows.length - visited.size,
      firstFailure: orphan?.id,
      reason:
        'row is not reachable from the bundle chain head (broken or forked link)',
    };
  }

  return {
    ok: true,
    // Number of inter-row link assertions actually made: nodes visited
    // minus the head (whose anchor is accepted, not asserted) — 0 for a
    // single-row bundle, matching the pre-fix semantics.
    checked: Math.max(0, steps - 1),
    failed: 0,
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
  const seenRowIds = new Set<string>();

  for (const entry of proofs) {
    checked += 1;
    if (seenRowIds.has(entry.rowId)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'duplicate proof entry for row';
      }
      continue;
    }
    seenRowIds.add(entry.rowId);

    // Status markers are diagnostics, not proofs, and are not signed. Treating
    // them as success let an attacker replace every proof with a marker.
    if (entry.status && entry.status !== 'ok') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = `row has no verifiable inclusion proof (status=${entry.status})`;
      }
      continue;
    }
    const row = rowsById.get(entry.rowId);
    if (!row) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof references a row not present in rows.ndjson.gz';
      }
      continue;
    }
    if (!entry.proof || !entry.rootHash || typeof entry.index !== 'number') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof entry malformed (missing proof/index/rootHash)';
      }
      continue;
    }
    const rootBytes = decodeBase64Strict(entry.rootHash, 32);
    if (rootBytes === null) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof rootHash is not canonical 32-byte base64';
      }
      continue;
    }
    // Sanity: the proof's stated root must match a root in roots.ndjson.gz.
    if (!rootsByHash.has(entry.rootHash)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof rootHash not found in roots.ndjson.gz';
      }
      continue;
    }
    const root = rootsByHash.get(entry.rootHash)!;
    const expectedProofDepth =
      root.rowCount <= 1 ? 0 : Math.ceil(Math.log2(root.rowCount));
    if (
      !Number.isSafeInteger(entry.index) ||
      entry.index < 0 ||
      !Number.isSafeInteger(root.rowCount) ||
      root.rowCount <= 0 ||
      entry.index >= root.rowCount ||
      entry.proof.length !== expectedProofDepth
    ) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof index/depth is inconsistent with root rowCount';
      }
      continue;
    }
    const leaf = computeLeaf(row);
    if (leaf === null) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'row signature is not canonical base64';
      }
      continue;
    }
    const decodedSiblings = entry.proof.map((s) =>
      decodeBase64Strict(s, 32),
    );
    if (decodedSiblings.some((s) => s === null)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof sibling is not canonical 32-byte base64';
      }
      continue;
    }
    const merkleProofObj: MerkleProof = {
      siblings: decodedSiblings.map((s) => new Uint8Array(s!)),
      index: entry.index,
    };
    if (!merkleVerify(leaf, merkleProofObj, new Uint8Array(rootBytes))) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'inclusion proof does not verify against root';
      }
    }
  }

  // The exporter emits exactly one proof record per row. Removing the proofs
  // file content must not produce a vacuous zero-checked success.
  for (const row of rows) {
    if (!seenRowIds.has(row.id)) {
      checked += 1;
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'row has no entry in proofs.ndjson.gz';
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
      // PROD16 F8 (be-compliance) — `ok:true` here must NEVER be read as
      // "anchoring was verified". The caller explicitly chose not to
      // check the external Sigstore/S3 witness at all; this bundle's
      // pass/fail rests entirely on the tenant + platform signatures
      // above, with no independent bound on how long ago the roots could
      // have been forged. Distinct, on purpose, from `no_external_witness`
      // below (a PRODUCER configuration fact) — this one is a CALLER
      // choice.
      reason:
        'rekor_check_skipped_by_caller: --no-rekor was passed — the external Sigstore witness was NOT checked. This does not mean anchoring is absent or present; it means this run did not look.',
    };
  }
  if (roots.length === 0) {
    return { ok: true, checked: 0, failed: 0 };
  }

  const perRoot = roots.map((root) => ({
    root,
    entries: collectAnchorEntries(root),
  }));
  const unanchoredCount = perRoot.filter((r) => r.entries.length === 0).length;

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  for (const { root, entries } of perRoot) {
    if (entries.length === 0) {
      checked += 1;
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        // PROD16 F8 — distinguish "no witness was ever configured for
        // this bundle" (EVERY root is unanchored — consistent with a
        // deployment shipping `FEATURE_REKOR_ANCHOR=false`, be-core's
        // current default) from "a gap in an otherwise-anchored
        // history" (some roots in THIS bundle ARE anchored, this one is
        // not — a narrower, more concerning anomaly, e.g. an anchoring
        // outage or a deleted receipt). Both still fail closed — an
        // unwitnessed root does not get the benefit of the doubt — but
        // an auditor needs to know which situation they are looking at;
        // they are not the same finding and should not produce the same
        // undifferentiated message.
        reason =
          unanchoredCount === perRoot.length
            ? 'no_external_witness: no root in this bundle carries an anchor receipt at all — this looks like external anchoring was never enabled for this org/deployment (or was off for this export), not a gap in existing coverage. Tenant/platform signatures are unaffected, but tamper cannot be bounded against an independent transparency log.'
            : `anchor_missing_for_partially_anchored_bundle: root ${root.id} has no anchor receipt while ${perRoot.length - unanchoredCount} other root(s) in this bundle do — this looks like a HOLE in an otherwise-anchored history, not a global witness-off configuration.`;
      }
      continue;
    }
    for (const entry of entries) {
      checked += 1;
      let result: { ok: boolean; reason?: string };
      try {
        result = await verifyAnchorReceipt(root, entry, options);
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
 *   - `'rekor'` → cryptographic offline verification bound to this root.
 *   - `'s3'`    → fail closed unless the caller supplies a verifier.
 *   - other     → `{ ok: false, reason: 'unknown_provider' }`.
 */
async function verifyAnchorReceipt(
  root: BundleRoot,
  entry: { provider: string; receipt: string; anchoredAt: string },
  options: VerifyOptions,
): Promise<{ ok: boolean; reason?: string }> {
  if (typeof entry.receipt !== 'string' || entry.receipt.length === 0) {
    return { ok: false, reason: 'empty_receipt' };
  }
  if (options.anchorReceiptVerifier) {
    return options.anchorReceiptVerifier(entry);
  }
  if (entry.provider === 'rekor') {
    // BUGHUNT-SDK-05 — a caller-supplied `rekorFetcher` is still honoured
    // as an explicit seam (e.g. an on-line re-fetch); the DEFAULT is now
    // real offline cryptographic verification (SET + inclusion proof),
    // not the old `JSON.parse`-and-return-true false assurance.
    if (options.rekorFetcher) {
      const ok = await options.rekorFetcher(entry.receipt);
      return ok ? { ok: true } : { ok: false, reason: 'rekor_fetch_failed' };
    }
    return verifyRekorReceipt(entry.receipt, options.rekorPublicKeyPem, {
      rootHashB64: root.rootHash,
      signatureB64: root.signature,
    });
  }
  if (entry.provider === 's3') {
    const shape = verifyS3ReceiptShape(entry.receipt);
    return shape.ok
      ? { ok: false, reason: 'unverifiable_offline' }
      : shape;
  }
  return { ok: false, reason: 'unknown_provider' };
}

/**
 * Offline check that an S3 receipt parses as `s3:<bucket>:<key>:<vid>`.
 * The key may legally contain colons, so we slice the first and last
 * colon-segments and treat everything in between as the key — matches
 * `S3AnchorService.verifyReceipt`'s parser.
 *
 * Returns `{ ok: false, reason: 'malformed' }` on a bad shape. A valid
 * shape is still not proof; callers must use `anchorReceiptVerifier`.
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
 *      `platform_key_not_pinned` (fail closed).
 *   2. If the entry is missing entirely, fail unless the caller explicitly
 *      enables `allowLegacyUnattested`.
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
  // Missing external trust evidence is a verification failure by default. An
  // auditor may explicitly opt into legacy self-signed bundle semantics.
  if (!entry) {
    return options.allowLegacyUnattested
      ? {
          ok: true,
          checked: 0,
          failed: 0,
          reason: 'missing_legacy_explicitly_allowed',
        }
      : {
          ok: false,
          checked: 1,
          failed: 1,
          reason: 'platform_attestation_missing',
        };
  }

  // Step 1 — resolve the pinned pubkey (caller override > bundled pin).
  const callerOverride = options.platformPublicKeyDerB64;
  const pinnedB64 =
    callerOverride && callerOverride.length > 0
      ? callerOverride
      : isPlatformPubkeyPinned()
        ? PLATFORM_PUBLIC_KEY_DER_B64
        : '';
  if (pinnedB64.length === 0) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'platform_key_not_pinned',
    };
  }
  const pinnedDer = decodeBase64Strict(pinnedB64);
  if (pinnedDer === null) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'platform_key_malformed: expected canonical base64 SPKI DER',
    };
  }
  // Compute the expected fingerprint over the same bytes the
  // verifier will use for signature dispatch. Caller override and
  // bundled pin take the same path so a substitution at either
  // level fails the `platformSigningKeyFingerprint` check below.
  const expectedFingerprint =
    callerOverride && callerOverride.length > 0
      ? crypto.createHash('sha256').update(pinnedDer).digest('hex')
      : PLATFORM_PUBLIC_KEY_FINGERPRINT;

  // Parse the envelope.
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
    Number.isNaN(Date.parse(body.issuedAt)) ||
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

  // Step 7 — require a one-to-one key set and bind fingerprint + lifecycle
  // metadata. Omitting a revoked key or relabelling it ACTIVE must not turn a
  // valid platform attestation into permission to trust that key.
  const seenVersions = new Set<number>();
  for (const kv of body.keyVersions) {
    if (
      !Number.isSafeInteger(kv.keyVersion) ||
      kv.keyVersion < 1 ||
      typeof kv.fingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/.test(kv.fingerprint) ||
      (kv.status !== 'ACTIVE' &&
        kv.status !== 'ROTATED' &&
        kv.status !== 'REVOKED') ||
      typeof kv.issuedAt !== 'string' ||
      Number.isNaN(Date.parse(kv.issuedAt)) ||
      (kv.revokedAt !== null &&
        (typeof kv.revokedAt !== 'string' ||
          Number.isNaN(Date.parse(kv.revokedAt))))
    ) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: 'malformed: keyVersions entry missing keyVersion/fingerprint',
      };
    }
    if (seenVersions.has(kv.keyVersion)) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `duplicate_keyversion: attestation repeats keyVersion ${kv.keyVersion}`,
      };
    }
    seenVersions.add(kv.keyVersion);
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
    const pkBytes = decodeBase64Strict(pkB64);
    if (pkBytes === null) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_malformed: keyVersion ${kv.keyVersion} is not canonical base64`,
      };
    }
    const actualFingerprint = crypto
      .createHash('sha256')
      .update(pkBytes)
      .digest('hex');
    if (actualFingerprint !== kv.fingerprint) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_fingerprint_mismatch: keyVersion ${kv.keyVersion} attests ${kv.fingerprint} but public-keys.json bytes hash to ${actualFingerprint}`,
      };
    }
    const actualStatus =
      typeof pkEntry === 'string'
        ? 'ACTIVE'
        : (pkEntry as { status?: unknown }).status;
    const actualRevokedAt =
      typeof pkEntry === 'string'
        ? null
        : ((pkEntry as { revokedAt?: unknown }).revokedAt ?? null);
    if (actualStatus !== kv.status || actualRevokedAt !== kv.revokedAt) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_lifecycle_mismatch: keyVersion ${kv.keyVersion} status/revokedAt differs from platform attestation`,
      };
    }
  }
  if (
    seenVersions.size !== Object.keys(publicKeysRaw).length ||
    Object.keys(publicKeysRaw).some((version) =>
      !seenVersions.has(Number(version)),
    )
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'keyversion_set_mismatch: platform attestation must cover every bundled key exactly once',
    };
  }

  return { ok: true, checked: 1, failed: 0 };
}

// ════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════

function isIsoDate(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function assertManifestStructure(manifest: BundleManifest): void {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('manifest.json has an invalid structure');
  }
  // PROD16 F6 — explicit, non-positional version negotiation: fail loudly
  // on a manifest version newer than this build understands, rather than
  // silently verifying it against today's (possibly wrong) field set.
  if (
    !Number.isSafeInteger(manifest.version) ||
    manifest.version < 1 ||
    manifest.version > MAX_SUPPORTED_MANIFEST_VERSION
  ) {
    throw new Error(
      Number.isSafeInteger(manifest.version) &&
        manifest.version > MAX_SUPPORTED_MANIFEST_VERSION
        ? `manifest.json declares version ${manifest.version}, which is newer than the ${MAX_SUPPORTED_MANIFEST_VERSION} this @praesidia/audit-verifier build supports — upgrade the verifier before trusting this bundle`
        : 'manifest.json has an invalid structure',
    );
  }
  if (
    typeof manifest.orgId !== 'string' ||
    manifest.orgId.length === 0 ||
    !isIsoDate(manifest.from) ||
    !isIsoDate(manifest.to) ||
    Date.parse(manifest.from) > Date.parse(manifest.to) ||
    !isIsoDate(manifest.generatedAt) ||
    !Number.isSafeInteger(manifest.rowCount) ||
    manifest.rowCount < 0 ||
    !Number.isSafeInteger(manifest.rootCount) ||
    manifest.rootCount < 0 ||
    !Array.isArray(manifest.keyVersions) ||
    typeof manifest.signature !== 'string' ||
    !Number.isSafeInteger(manifest.signatureKeyVersion) ||
    (manifest.signatureAlgorithm !== 'Ed25519' &&
      manifest.signatureAlgorithm !== 'ECDSA_P256_SHA256')
  ) {
    throw new Error('manifest.json has an invalid structure');
  }
  const versions = new Set<number>();
  for (const key of manifest.keyVersions) {
    if (
      !key ||
      typeof key !== 'object' ||
      !Number.isSafeInteger(key.keyVersion) ||
      key.keyVersion < 1 ||
      typeof key.publicKey !== 'string' ||
      versions.has(key.keyVersion)
    ) {
      throw new Error('manifest.json contains an invalid/duplicate keyVersion');
    }
    versions.add(key.keyVersion);
  }
}

function assertRowsStructure(rows: BundleRow[], orgId: string): void {
  const ids = new Set<string>();
  for (const row of rows) {
    if (
      !row ||
      typeof row !== 'object' ||
      typeof row.id !== 'string' ||
      row.id.length === 0 ||
      ids.has(row.id) ||
      row.organizationId !== orgId ||
      typeof row.action !== 'string' ||
      typeof row.actorType !== 'string' ||
      !isIsoDate(row.createdAt) ||
      typeof row.signature !== 'string' ||
      !Number.isSafeInteger(row.keyVersion) ||
      row.keyVersion < 1
    ) {
      throw new Error(`rows.ndjson.gz has an invalid/duplicate row: ${String(row?.id)}`);
    }
    ids.add(row.id);
  }
}

function assertRootsStructure(roots: BundleRoot[], orgId: string): void {
  const ids = new Set<string>();
  const hashes = new Set<string>();
  for (const root of roots) {
    if (
      !root ||
      typeof root !== 'object' ||
      typeof root.id !== 'string' ||
      root.id.length === 0 ||
      ids.has(root.id) ||
      root.organizationId !== orgId ||
      !isIsoDate(root.periodStart) ||
      !isIsoDate(root.periodEnd) ||
      Date.parse(root.periodStart) >= Date.parse(root.periodEnd) ||
      !Number.isSafeInteger(root.rowCount) ||
      root.rowCount < 1 ||
      typeof root.rootHash !== 'string' ||
      hashes.has(root.rootHash) ||
      typeof root.signature !== 'string' ||
      !Number.isSafeInteger(root.keyVersion) ||
      root.keyVersion < 1 ||
      !isIsoDate(root.signedAt) ||
      (root.anchoredAt !== null && !isIsoDate(root.anchoredAt)) ||
      (root.anchorReceipt !== null && typeof root.anchorReceipt !== 'string') ||
      (root.anchorReceipts !== undefined && !Array.isArray(root.anchorReceipts))
    ) {
      throw new Error(`roots.ndjson.gz has an invalid/duplicate root: ${String(root?.id)}`);
    }
    ids.add(root.id);
    hashes.add(root.rootHash);
  }
}

function assertProofsStructure(proofs: BundleProofEntry[]): void {
  for (const proof of proofs) {
    if (
      !proof ||
      typeof proof !== 'object' ||
      typeof proof.rowId !== 'string' ||
      proof.rowId.length === 0 ||
      (proof.status !== undefined && typeof proof.status !== 'string') ||
      (proof.proof !== undefined &&
        (!Array.isArray(proof.proof) ||
          !proof.proof.every((sibling) => typeof sibling === 'string')))
    ) {
      throw new Error('proofs.ndjson.gz has an invalid proof entry');
    }
  }
}

/**
 * Pull the signable fields out of a bundle row (mirrors AGV-030's 11-field
 * base shape).
 *
 * PROD16 F6 (be-compliance) — `ipAddress` is included IFF the wire row
 * object actually carries the key (`'ipAddress' in row`), NOT merely if
 * its value is non-null. `canonicalJson` treats an ABSENT key as omitted
 * from the signed bytes but a key PRESENT with value `null` as
 * `"ipAddress":null` — so this exactly reproduces be-core's own
 * conditional signable shape (`audit-canonical.helper.ts` only adds the
 * key at all once `signedAt >= IP_ADDRESS_SIGNABLE_CUTOVER_AT`) without
 * the verifier ever needing to know the cutover instant. Rows signed
 * before the cutover (and every pre-AUDIT-14 row) simply never carry the
 * key on the wire, so the 11-field preimage is unchanged for them.
 */
function signableRow(row: BundleRow): Record<string, unknown> {
  const signable: Record<string, unknown> = {
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
  if ('ipAddress' in row) {
    signable.ipAddress = row.ipAddress ?? null;
  }
  return signable;
}

/**
 * Compute the Merkle leaf preimage for a stored row:
 *   leaf = canonical(row) || base64-decode(row.signature)
 * The Merkle tree's `merkleVerify` adds the RFC 6962 0x00 leaf prefix
 * before hashing — see `merkleVerify` / `merkleBuild`.
 */
function computeLeaf(row: BundleRow): Uint8Array | null {
  const canonical = canonicalJson(signableRow(row));
  const sigBytes = decodeBase64Strict(row.signature);
  if (sigBytes === null) return null;
  return new Uint8Array(Buffer.concat([canonical, sigBytes]));
}

/**
 * Compute the chain-link value the *next* row stores in
 * `prev_row_hash`:
 *   sha256(canonical(prev) || prev.sig_bytes)  (base64)
 */
function computeChainLink(prev: BundleRow): string | null {
  const canonical = canonicalJson(signableRow(prev));
  const sigBytes = decodeBase64Strict(prev.signature);
  if (sigBytes === null) return null;
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
    const publicKey = decodeBase64Strict(raw);
    if (publicKey === null || publicKey.length === 0) {
      throw new Error(
        `public-keys.json[${versionKey}] is not canonical base64`,
      );
    }
    return {
      publicKey: new Uint8Array(publicKey),
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
    const publicKey = decodeBase64Strict(obj.publicKey);
    if (publicKey === null || publicKey.length === 0) {
      throw new Error(
        `public-keys.json[${versionKey}].publicKey is not canonical base64`,
      );
    }
    return {
      publicKey: new Uint8Array(publicKey),
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
