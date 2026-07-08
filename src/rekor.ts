/**
 * BUGHUNT-SDK-05 — Real offline Rekor receipt verification.
 *
 * The offline verifier's DEFAULT Rekor check used to be
 * `JSON.parse(receipt)` — it returned `true` for ANY parseable JSON
 * (even `"{}"`), so the CLI printed a green `rekor receipts OK` that
 * verified NOTHING cryptographic. This module replaces that with a
 * genuine, self-contained (zero-dependency, offline) check that mirrors
 * be-core's `verify-rekor-set.ts` (AUDIT-2026-05-06):
 *
 *   1. Verify the Signed Entry Timestamp (SET) — an ECDSA-P256-SHA256
 *      signature over the canonical `{body, integratedTime, logID,
 *      logIndex}` payload — against Sigstore's PINNED Rekor public key.
 *   2. Verify the inclusion proof — walk the RFC 6962 Merkle audit path
 *      from `leaf = SHA-256(0x00 || base64-decode(body))` up the
 *      sibling list and confirm it reproduces `inclusionProof.rootHash`.
 *
 * A receipt that is not a genuine Rekor entry (missing SET / inclusion
 * proof, or one that does not verify) now FAILS closed. The Rekor
 * public key is PINNED at build time (never fetched at verify time) so a
 * hostile intermediary cannot swap it; sovereign/private Rekor instances
 * (or tests) supply their own key via `VerifyOptions.rekorPublicKeyPem`.
 *
 * NOTE — like be-core's on-line anchor path, this verifies the receipt is
 * a genuine, SET-signed, log-included Rekor entry. Binding the entry
 * BODY to this specific bundle's `root.rootHash` (so a genuine-but-
 * unrelated receipt can't be reattached) is a deeper, format-specific
 * (hashedrekord) check tracked as a coordinated follow-up; the tenant row
 * / Merkle-root / platform-attestation signatures already bind the audit
 * CONTENT to the tenant key.
 */

import * as crypto from 'node:crypto';

// ── Pinned Sigstore Rekor signing key ────────────────────────────────────
//
// Vendored verbatim from be-core `rekor-public-keys.ts`
// (REKOR_DEFAULT_PUBLIC_KEY_PEM) to keep this package zero-dependency and
// fully offline. If Sigstore rotates their log key, follow the rotation
// procedure in be-core and bump this package: move the OLD pair into
// REKOR_HISTORICAL_KEYS and replace the default below. Old receipts MUST
// keep verifying against the old pinned key.
const REKOR_DEFAULT_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
`;

interface RekorPinnedKey {
  logIdHex: string;
  pem: string;
}

/**
 * SHA-256 over the SubjectPublicKeyInfo (SPKI DER) bytes of a PEM public
 * key, hex-lowercase. This is exactly Rekor's `logID` (64-char
 * `^[0-9a-f]{64}$`). Throws on a malformed PEM (a build-time/operator
 * error, never a runtime verdict).
 */
export function computeRekorLogIdHex(pem: string): string {
  const key = crypto.createPublicKey(pem);
  const spkiDer = key.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(spkiDer).digest('hex');
}

const REKOR_DEFAULT_LOG_ID_HEX = computeRekorLogIdHex(
  REKOR_DEFAULT_PUBLIC_KEY_PEM,
);

/**
 * Historical pinned keys — populated on rotation so pre-rotation
 * receipts keep verifying forever. Never remove entries.
 */
const REKOR_HISTORICAL_KEYS: ReadonlyArray<RekorPinnedKey> = [];

/**
 * Resolve the pinned PEM for a receipt's `logID` (hex-lowercase).
 * Returns `null` when no pinned key matches — the caller MUST fail
 * closed (never silently fall back to a default key).
 */
function resolvePinnedRekorPem(logIdHex: string): string | null {
  if (typeof logIdHex !== 'string' || logIdHex.length === 0) return null;
  const needle = logIdHex.toLowerCase();
  const ring: RekorPinnedKey[] = [
    { logIdHex: REKOR_DEFAULT_LOG_ID_HEX, pem: REKOR_DEFAULT_PUBLIC_KEY_PEM },
    ...REKOR_HISTORICAL_KEYS,
  ];
  for (const entry of ring) {
    if (entry.logIdHex.toLowerCase() === needle) return entry.pem;
  }
  return null;
}

// ── Wire types (subset of the persisted receipt / Rekor entry) ────────────

interface RekorInclusionProof {
  logIndex: number;
  treeSize: number;
  rootHash: string;
  hashes: string[];
}

interface NormalizedEntry {
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  signedEntryTimestamp: string;
  inclusionProof: RekorInclusionProof;
}

export type RekorVerifyResult = { ok: boolean; reason?: string };

// ── Canonical SET payload (matches be-core buildRekorSetPayload) ──────────

function buildRekorSetPayload(entry: {
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
}): Buffer {
  // JCS key order for this 4-field object: body, integratedTime, logID,
  // logIndex. Assembled manually so the byte order is audit-visible.
  const json =
    '{' +
    `"body":${JSON.stringify(entry.body)},` +
    `"integratedTime":${JSON.stringify(entry.integratedTime)},` +
    `"logID":${JSON.stringify(entry.logID)},` +
    `"logIndex":${JSON.stringify(entry.logIndex)}` +
    '}';
  return Buffer.from(json, 'utf8');
}

// ── SET signature verification ────────────────────────────────────────────

function verifySet(
  entry: NormalizedEntry,
  pubKeyPem: string,
): RekorVerifyResult {
  let pubKey: crypto.KeyObject;
  try {
    pubKey = crypto.createPublicKey(pubKeyPem);
  } catch (err) {
    return {
      ok: false,
      reason: `set_pubkey_load_failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  const payload = buildRekorSetPayload({
    body: entry.body,
    integratedTime: entry.integratedTime,
    logID: entry.logID,
    logIndex: entry.logIndex,
  });
  const sigBytes = Buffer.from(entry.signedEntryTimestamp, 'base64');
  let ok: boolean;
  try {
    ok = crypto.verify('sha256', payload, pubKey, sigBytes);
  } catch (err) {
    return {
      ok: false,
      reason: `set_verify_threw: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  return ok ? { ok: true } : { ok: false, reason: 'set_signature_invalid' };
}

// ── Inclusion proof verification (RFC 6962 §2.1) ──────────────────────────

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(...parts: Buffer[]): Buffer {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function verifyInclusion(
  proof: RekorInclusionProof,
  body: string,
): RekorVerifyResult {
  if (
    typeof proof.logIndex !== 'number' ||
    typeof proof.treeSize !== 'number' ||
    typeof proof.rootHash !== 'string' ||
    !Array.isArray(proof.hashes)
  ) {
    return { ok: false, reason: 'inclusion_malformed' };
  }
  if (proof.logIndex < 0 || proof.logIndex >= proof.treeSize) {
    return { ok: false, reason: 'inclusion_index_out_of_range' };
  }
  if (!/^[0-9a-f]+$/i.test(proof.rootHash)) {
    return { ok: false, reason: 'inclusion_malformed' };
  }
  for (const h of proof.hashes) {
    if (typeof h !== 'string' || !/^[0-9a-f]+$/i.test(h)) {
      return { ok: false, reason: 'inclusion_malformed' };
    }
  }

  let bodyBytes: Buffer;
  try {
    bodyBytes = Buffer.from(body, 'base64');
  } catch {
    return { ok: false, reason: 'inclusion_malformed' };
  }
  let computed = sha256(LEAF_PREFIX, bodyBytes);

  // Canonical RFC 6962 audit-path walk carrying (index, size); the
  // "promote a lonely right-most leaf without consuming a sibling" case
  // is the odd-width handling. Identical to be-core / Sigstore's verifier.
  let index = proof.logIndex;
  let size = proof.treeSize;
  let cursor = 0;
  while (size > 1) {
    if (index % 2 === 1) {
      if (cursor >= proof.hashes.length) {
        return { ok: false, reason: 'inclusion_path_length_mismatch' };
      }
      const sibling = Buffer.from(proof.hashes[cursor]!, 'hex');
      if (sibling.length !== 32)
        return { ok: false, reason: 'inclusion_malformed' };
      computed = sha256(NODE_PREFIX, sibling, computed);
      cursor += 1;
    } else if (index === size - 1) {
      // Lonely right-most leaf: promote without consuming a sibling.
    } else {
      if (cursor >= proof.hashes.length) {
        return { ok: false, reason: 'inclusion_path_length_mismatch' };
      }
      const sibling = Buffer.from(proof.hashes[cursor]!, 'hex');
      if (sibling.length !== 32)
        return { ok: false, reason: 'inclusion_malformed' };
      computed = sha256(NODE_PREFIX, computed, sibling);
      cursor += 1;
    }
    index = Math.floor(index / 2);
    size = Math.floor((size + 1) / 2);
  }
  if (cursor !== proof.hashes.length) {
    // Extra siblings the path never consumed — refuse so a malicious
    // prover can't pad the proof with bytes the verifier ignores.
    return { ok: false, reason: 'inclusion_path_length_mismatch' };
  }

  const expected = Buffer.from(proof.rootHash, 'hex');
  if (expected.length !== computed.length) {
    return { ok: false, reason: 'inclusion_root_mismatch' };
  }
  return crypto.timingSafeEqual(expected, computed)
    ? { ok: true }
    : { ok: false, reason: 'inclusion_root_mismatch' };
}

// ── Receipt normalization ─────────────────────────────────────────────────

/**
 * Normalize the persisted receipt into a fully-typed entry. Accepts BOTH:
 *   - the FLAT `buildRekorReceiptJson` shape be-core persists:
 *     `{ logIndex, inclusionProof, signedEntryTimestamp, logId,
 *        integratedTime, body }`; AND
 *   - the nested live-API shape:
 *     `{ logIndex, logID, integratedTime, body,
 *        verification: { signedEntryTimestamp, inclusionProof } }`.
 * Returns `null` on any structural mismatch → the caller fails closed.
 */
function normalizeReceipt(raw: unknown): NormalizedEntry | null {
  if (raw == null || typeof raw !== 'object') return null;
  const obj = raw as Record<string, unknown>;
  const verification =
    obj.verification && typeof obj.verification === 'object'
      ? (obj.verification as Record<string, unknown>)
      : undefined;

  const logID = obj.logID ?? obj.logId;
  const signedEntryTimestamp =
    obj.signedEntryTimestamp ?? verification?.signedEntryTimestamp;
  const inclusionProofRaw = obj.inclusionProof ?? verification?.inclusionProof;

  if (
    typeof obj.body !== 'string' ||
    typeof obj.integratedTime !== 'number' ||
    typeof logID !== 'string' ||
    typeof obj.logIndex !== 'number' ||
    typeof signedEntryTimestamp !== 'string' ||
    signedEntryTimestamp.length === 0 ||
    inclusionProofRaw == null ||
    typeof inclusionProofRaw !== 'object'
  ) {
    return null;
  }
  const p = inclusionProofRaw as Record<string, unknown>;
  if (
    typeof p.logIndex !== 'number' ||
    typeof p.treeSize !== 'number' ||
    typeof p.rootHash !== 'string' ||
    !Array.isArray(p.hashes)
  ) {
    return null;
  }
  return {
    body: obj.body,
    integratedTime: obj.integratedTime,
    logID,
    logIndex: obj.logIndex,
    signedEntryTimestamp,
    inclusionProof: {
      logIndex: p.logIndex,
      treeSize: p.treeSize,
      rootHash: p.rootHash,
      hashes: p.hashes.filter((h): h is string => typeof h === 'string'),
    },
  };
}

// ── Public entry point ─────────────────────────────────────────────────────

/**
 * Cryptographically verify a persisted Rekor receipt entirely offline.
 *
 * @param receiptJson  The receipt string from the bundle
 *                     (`root.anchorReceipt` / `anchorReceipts[].receipt`).
 * @param overridePem  Optional PEM to pin instead of the bundled Sigstore
 *                     key — for sovereign/private Rekor instances and tests.
 *
 * Returns `{ ok: true }` ONLY when the SET signature verifies under the
 * resolved pinned key AND the inclusion proof reproduces its rootHash.
 * Every other outcome is `{ ok: false, reason }`.
 */
export function verifyRekorReceipt(
  receiptJson: string,
  overridePem?: string,
): RekorVerifyResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(receiptJson);
  } catch {
    return { ok: false, reason: 'receipt_not_json' };
  }
  const entry = normalizeReceipt(parsed);
  if (!entry) {
    return { ok: false, reason: 'not_a_rekor_entry' };
  }

  // Resolve the pinned verification key. An explicit override (sovereign
  // Rekor / test) is used directly; otherwise resolve by the receipt's
  // logID against the bundled Sigstore pin and fail closed on no match.
  const pem =
    overridePem && overridePem.length > 0
      ? overridePem
      : resolvePinnedRekorPem(entry.logID);
  if (!pem) {
    return { ok: false, reason: 'set_logid_unpinned' };
  }

  const setResult = verifySet(entry, pem);
  if (!setResult.ok) return setResult;

  const inclusionResult = verifyInclusion(entry.inclusionProof, entry.body);
  if (!inclusionResult.ok) return inclusionResult;

  return { ok: true };
}
