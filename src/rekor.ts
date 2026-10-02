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
 *   2. Verify the proof's signed checkpoint under the same pinned log key,
 *      and require its authenticated tree size/root to match the proof.
 *   3. Verify the inclusion proof — walk the RFC 6962 Merkle audit path
 *      from `leaf = SHA-256(0x00 || base64-decode(body))` up the
 *      sibling list and confirm it reproduces `inclusionProof.rootHash`.
 *
 * A receipt that is not a genuine Rekor entry (missing SET / inclusion
 * proof, or one that does not verify) now FAILS closed. The Rekor
 * public key is PINNED at build time (never fetched at verify time) so a
 * hostile intermediary cannot swap it; sovereign/private Rekor instances
 * (or tests) supply their own key via `VerifyOptions.rekorPublicKeyPem`.
 *
 *   4. Decode the hashedrekord body and bind it to the exact Merkle root
 *      being verified (AV-2771): `data.hash` must be SHA-256 of the bytes
 *      the root signature covers (format prefix + canonical root envelope),
 *      `signature.content` must be the root's signature, and that signature
 *      must verify over those bytes under the root's key. A genuine unrelated
 *      Rekor receipt therefore cannot be reattached to another bundle root.
 *   5. SEC-2026-09-12 (MCPSDK-01) — bind the log's SIGNED `integratedTime`
 *      to the root's self-asserted `signedAt`/`anchoredAt` window, so a
 *      freshly-anchored forgery cannot claim an old period.
 */

import * as crypto from 'node:crypto';

import {
  merkleRootEnvelope,
  tenantSignedBytes,
  verifySignature,
  type BundleSignatureAlgorithm,
} from './crypto.js';

// Public Rekor v1 limits uploaded attestations to 100 KiB. Leave ample room
// for the SET, inclusion proof, and private-instance metadata while still
// bounding direct library calls before JSON/base64 processing.
const MAX_REKOR_RECEIPT_BYTES = 1024 * 1024;
const MAX_CHECKPOINT_BYTES = 64 * 1024;
const MAX_CHECKPOINT_SIGNATURES = 32;
const MAX_INCLUSION_HASHES = 64;

/**
 * SEC-2026-09-12 (MCPSDK-01) — permitted clock skew, in milliseconds,
 * between the bundle's SELF-ASSERTED timestamps (`root.signedAt`,
 * `root.anchoredAt` — both attacker-controllable in a forged bundle) and
 * Rekor's `integratedTime`, which is signed by the log and is therefore
 * the only honest clock in the whole artefact.
 *
 * 24h is deliberately generous: it absorbs producer/log clock drift, a
 * queued/retried anchor submission, and an anchor run that straddles a
 * maintenance window, while still making a MONTHS-late backdated forgery
 * (the attack this bound exists to stop — re-anchoring freshly forged
 * roots that claim an old `periodEnd`) fail closed. It is intentionally
 * NOT configurable: a caller-tunable skew is a caller-tunable bypass.
 */
export const REKOR_INTEGRATED_TIME_SKEW_MS = 24 * 60 * 60 * 1000;

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
export function resolvePinnedRekorPem(logIdHex: string): string | null {
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
  checkpoint: string;
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

/**
 * The root a receipt must bind (AV-2771). The envelope fields and
 * `signatureFormat` rebuild the bytes the root signature covers; the
 * receipt's `data.hash` must be their SHA-256.
 */
export interface ExpectedRekorRoot {
  rootHashB64: string;
  periodStart: string;
  periodEnd: string;
  rowCount: number;
  /** AV-0018 — 1 or 2; absent = 1. Anything else fails `expected_root_malformed`. */
  signatureFormat?: number;
  signatureB64: string;
  signatureAlgorithm: BundleSignatureAlgorithm;
  /** The root's key as `public-keys.json` carries it (SPKI DER for ECDSA, raw 32 bytes for Ed25519). */
  publicKey: Uint8Array;
  /**
   * SEC-2026-09-12 (MCPSDK-01) — the root's own `signedAt` (ISO-8601).
   * A genuine transparency-log entry for this root CANNOT have been
   * integrated before the root was signed, so `integratedTime` is
   * required to be >= `signedAt - REKOR_INTEGRATED_TIME_SKEW_MS`.
   * Supplying it is what turns Rekor's signed clock into a bound on the
   * bundle's self-asserted timestamps; `verifyBundle` ALWAYS supplies it.
   * Omitted (direct library callers only) = lower bound not enforced.
   */
  signedAt?: string;
  /**
   * SEC-2026-09-12 (MCPSDK-01) — the time the producer recorded for this
   * anchor (ISO-8601), when one is genuinely recorded. `integratedTime`
   * must then be <= `anchoredAt + REKOR_INTEGRATED_TIME_SKEW_MS`.
   * `null`/omitted = no upper bound (legacy roots that carry a receipt but
   * no anchor timestamp — a later backfill anchoring run is legitimate and
   * must keep verifying).
   */
  anchoredAt?: string | null;
}

interface AuthenticatedCheckpoint {
  treeSize: number;
  rootHash: Buffer;
}

type CheckpointVerifyResult =
  | { ok: true; checkpoint: AuthenticatedCheckpoint }
  | { ok: false; reason: string };

function decodeCanonicalBase64(value: string): Buffer | null {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.toString('base64') === value ? decoded : null;
}

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
  const sigBytes = decodeCanonicalBase64(entry.signedEntryTimestamp);
  if (sigBytes === null) return { ok: false, reason: 'set_signature_malformed' };
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

// ── Signed checkpoint verification (C2SP signed-note checkpoint) ──────────

function verifySignedCheckpoint(
  envelope: string,
  pubKeyPem: string,
): CheckpointVerifyResult {
  if (
    envelope.length === 0 ||
    Buffer.byteLength(envelope, 'utf8') > MAX_CHECKPOINT_BYTES
  ) {
    return { ok: false, reason: 'checkpoint_malformed' };
  }
  if (
    !envelope.endsWith('\n') ||
    envelope.includes('\r') ||
    /[\0\uD800-\uDFFF]/u.test(envelope)
  ) {
    return { ok: false, reason: 'checkpoint_malformed' };
  }

  const separator = envelope.indexOf('\n\n');
  if (separator <= 0) {
    return { ok: false, reason: 'checkpoint_malformed' };
  }
  const note = envelope.slice(0, separator + 1);
  const signatureBlock = envelope.slice(separator + 2);
  const noteLines = note.slice(0, -1).split('\n');
  if (
    noteLines.length < 3 ||
    noteLines[0]!.length === 0 ||
    noteLines[0]!.length > 1024 ||
    !/^[1-9]\d{0,15}$/.test(noteLines[1]!)
  ) {
    return { ok: false, reason: 'checkpoint_malformed' };
  }
  const treeSize = Number(noteLines[1]);
  if (!Number.isSafeInteger(treeSize) || treeSize < 1) {
    return { ok: false, reason: 'checkpoint_malformed' };
  }
  const rootHash = decodeCanonicalBase64(noteLines[2]!);
  if (rootHash === null || rootHash.length !== 32) {
    return { ok: false, reason: 'checkpoint_malformed' };
  }

  const signatureLines = signatureBlock.slice(0, -1).split('\n');
  if (
    signatureLines.length === 0 ||
    signatureLines.length > MAX_CHECKPOINT_SIGNATURES ||
    signatureLines.some((line) => line.length === 0)
  ) {
    return { ok: false, reason: 'checkpoint_malformed' };
  }

  let pubKey: crypto.KeyObject;
  let expectedHint: Buffer;
  try {
    pubKey = crypto.createPublicKey(pubKeyPem);
    const spkiDer = pubKey.export({ type: 'spki', format: 'der' });
    expectedHint = crypto
      .createHash('sha256')
      .update(spkiDer)
      .digest()
      .subarray(0, 4);
  } catch {
    return { ok: false, reason: 'checkpoint_pubkey_load_failed' };
  }

  let matchingHintSeen = false;
  for (const line of signatureLines) {
    const match = /^— (\S{1,1024}) (\S+)$/u.exec(line);
    if (!match) return { ok: false, reason: 'checkpoint_malformed' };
    const signed = decodeCanonicalBase64(match[2]!);
    if (signed === null || signed.length <= 4 || signed.length > 4096) {
      return { ok: false, reason: 'checkpoint_malformed' };
    }
    const keyHint = signed.subarray(0, 4);
    if (!crypto.timingSafeEqual(keyHint, expectedHint)) continue;
    matchingHintSeen = true;
    try {
      if (
        crypto.verify(
          'sha256',
          Buffer.from(note, 'utf8'),
          pubKey,
          signed.subarray(4),
        )
      ) {
        return { ok: true, checkpoint: { treeSize, rootHash } };
      }
    } catch {
      return { ok: false, reason: 'checkpoint_signature_invalid' };
    }
  }
  return {
    ok: false,
    reason: matchingHintSeen
      ? 'checkpoint_signature_invalid'
      : 'checkpoint_signature_untrusted',
  };
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
    !Number.isSafeInteger(proof.logIndex) ||
    !Number.isSafeInteger(proof.treeSize) ||
    typeof proof.rootHash !== 'string' ||
    !Array.isArray(proof.hashes)
  ) {
    return { ok: false, reason: 'inclusion_malformed' };
  }
  if (proof.logIndex < 0 || proof.logIndex >= proof.treeSize) {
    return { ok: false, reason: 'inclusion_index_out_of_range' };
  }
  if (!/^[0-9a-f]{64}$/i.test(proof.rootHash)) {
    return { ok: false, reason: 'inclusion_malformed' };
  }
  for (const h of proof.hashes) {
    if (typeof h !== 'string' || !/^[0-9a-f]{64}$/i.test(h)) {
      return { ok: false, reason: 'inclusion_malformed' };
    }
  }

  const bodyBytes = decodeCanonicalBase64(body);
  if (bodyBytes === null) return { ok: false, reason: 'inclusion_malformed' };
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
    !Number.isSafeInteger(obj.integratedTime) ||
    typeof logID !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(logID) ||
    typeof obj.logIndex !== 'number' ||
    !Number.isSafeInteger(obj.logIndex) ||
    typeof signedEntryTimestamp !== 'string' ||
    signedEntryTimestamp.length === 0 ||
    inclusionProofRaw == null ||
    typeof inclusionProofRaw !== 'object'
  ) {
    return null;
  }
  const p = inclusionProofRaw as Record<string, unknown>;
  const checkpoint =
    typeof p.checkpoint === 'string'
      ? p.checkpoint
      : p.checkpoint &&
          typeof p.checkpoint === 'object' &&
          typeof (p.checkpoint as Record<string, unknown>).envelope === 'string'
        ? ((p.checkpoint as Record<string, unknown>).envelope as string)
        : null;
  if (
    typeof p.logIndex !== 'number' ||
    !Number.isSafeInteger(p.logIndex) ||
    typeof p.treeSize !== 'number' ||
    !Number.isSafeInteger(p.treeSize) ||
    typeof p.rootHash !== 'string' ||
    !Array.isArray(p.hashes) ||
    p.hashes.length > MAX_INCLUSION_HASHES ||
    !p.hashes.every((hash) => typeof hash === 'string') ||
    checkpoint === null ||
    Buffer.byteLength(checkpoint, 'utf8') > MAX_CHECKPOINT_BYTES ||
    signedEntryTimestamp.length > 4096 ||
    obj.integratedTime < 0 ||
    obj.logIndex < 0 ||
    p.treeSize < 1 ||
    p.logIndex !== obj.logIndex
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
      hashes: p.hashes as string[],
      checkpoint,
    },
  };
}

function hasInclusionProofWithoutCheckpoint(raw: unknown): boolean {
  if (raw === null || typeof raw !== 'object') return false;
  const obj = raw as Record<string, unknown>;
  const verification =
    obj.verification && typeof obj.verification === 'object'
      ? (obj.verification as Record<string, unknown>)
      : undefined;
  const proof = obj.inclusionProof ?? verification?.inclusionProof;
  return (
    proof !== null &&
    typeof proof === 'object' &&
    (proof as Record<string, unknown>).checkpoint == null
  );
}

function verifyBodyBinding(
  bodyB64: string,
  expected: ExpectedRekorRoot,
): RekorVerifyResult {
  const bodyBytes = decodeCanonicalBase64(bodyB64);
  const rootHash = decodeCanonicalBase64(expected.rootHashB64);
  const format = expected.signatureFormat === undefined ? 1 : expected.signatureFormat;
  if (bodyBytes === null) return { ok: false, reason: 'body_unparseable' };
  if (rootHash === null || rootHash.length !== 32 || (format !== 1 && format !== 2)) {
    return { ok: false, reason: 'expected_root_malformed' };
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(bodyBytes.toString('utf8'));
  } catch {
    return { ok: false, reason: 'body_unparseable' };
  }
  if (decoded === null || typeof decoded !== 'object') {
    return { ok: false, reason: 'body_unparseable' };
  }
  const obj = decoded as Record<string, unknown>;
  if (obj.kind !== 'hashedrekord') {
    return { ok: false, reason: 'body_not_hashedrekord' };
  }
  const spec = obj.spec as Record<string, unknown> | undefined;
  const data = spec?.data as Record<string, unknown> | undefined;
  const hash = data?.hash as Record<string, unknown> | undefined;
  const signature = spec?.signature as Record<string, unknown> | undefined;
  if (
    hash?.algorithm !== 'sha256' ||
    typeof hash.value !== 'string' ||
    typeof signature?.content !== 'string'
  ) {
    return { ok: false, reason: 'body_binding_malformed' };
  }
  // AV-2771 (be BE-3074) — Rekor verifies `signature.content` over
  // `data.hash` as a prehash, so the only entry a genuine log accepts for
  // this root carries the SHA-256 of the bytes the root signature covers.
  const signedBytes = tenantSignedBytes(format, 'merkle-root', merkleRootEnvelope({
    rootHash: expected.rootHashB64,
    periodStart: expected.periodStart,
    periodEnd: expected.periodEnd,
    rowCount: expected.rowCount,
  }));
  if (
    hash.value.toLowerCase() !== sha256(signedBytes).toString('hex') ||
    signature.content !== expected.signatureB64
  ) {
    return { ok: false, reason: 'body_root_mismatch' };
  }
  // The logged signature is the root's own; it must verify under the root key.
  if (!verifySignature(expected.signatureAlgorithm, signedBytes, signature.content, expected.publicKey)) {
    return { ok: false, reason: 'body_signature_invalid' };
  }
  return { ok: true };
}

/**
 * SEC-2026-09-12 (MCPSDK-01) — bind the log's SIGNED `integratedTime` to
 * the bundle's own claimed time window.
 *
 * Before this check `integratedTime` was only ever used to rebuild the SET
 * payload; it was never compared to anything. That left a hole: a holder of
 * a compromised (and since-REVOKED) tenant key could forge a whole bundle
 * that claims an old period, anchor the forged roots in public Rekor today
 * (anyone may submit a hashedrekord), and every component — including the
 * genuine, root-bound Rekor receipt — would verify. The only artefact in the
 * bundle the forger cannot backdate is Rekor's own clock, so it must be
 * compared against the timestamps the forger DOES control.
 *
 * Fails closed on an unparseable timestamp: an un-evaluable window is a
 * failure, not a skip.
 */
function verifyIntegratedTimeWindow(
  integratedTime: number,
  expected: ExpectedRekorRoot,
): RekorVerifyResult {
  const integratedMs = integratedTime * 1000;
  const integratedIso = new Date(integratedMs).toISOString();
  if (expected.signedAt !== undefined) {
    const signedMs = Date.parse(expected.signedAt);
    if (Number.isNaN(signedMs)) {
      return {
        ok: false,
        reason:
          'rekor_integrated_time_window_unverifiable: root signedAt is not a parseable timestamp',
      };
    }
    if (integratedMs < signedMs - REKOR_INTEGRATED_TIME_SKEW_MS) {
      return {
        ok: false,
        reason: `rekor_integrated_time_out_of_window: log integrated this entry at ${integratedIso}, BEFORE the root claims to have been signed (${expected.signedAt}) by more than the ${
          REKOR_INTEGRATED_TIME_SKEW_MS / 3_600_000
        }h skew allowance — a transparency-log entry cannot predate the thing it witnesses`,
      };
    }
  }
  if (expected.anchoredAt !== undefined && expected.anchoredAt !== null) {
    const anchoredMs = Date.parse(expected.anchoredAt);
    if (Number.isNaN(anchoredMs)) {
      return {
        ok: false,
        reason:
          'rekor_integrated_time_window_unverifiable: root anchoredAt is not a parseable timestamp',
      };
    }
    if (integratedMs > anchoredMs + REKOR_INTEGRATED_TIME_SKEW_MS) {
      return {
        ok: false,
        reason: `rekor_integrated_time_out_of_window: log integrated this entry at ${integratedIso}, AFTER the anchor time the bundle records (${expected.anchoredAt}) by more than the ${
          REKOR_INTEGRATED_TIME_SKEW_MS / 3_600_000
        }h skew allowance — the receipt was created later than the bundle claims, which is what backdating a forged export looks like`,
      };
    }
  }
  return { ok: true };
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
 * Returns `{ ok: true }` ONLY when the SET signature and the inclusion
 * proof's signed checkpoint verify under the resolved pinned key, the
 * checkpoint authenticates the proof's tree size/root, and the audit path
 * reproduces that root. Every other outcome is `{ ok: false, reason }`.
 */
export function verifyRekorReceipt(
  receiptJson: string,
  overridePem?: string,
  expectedRoot?: ExpectedRekorRoot,
): RekorVerifyResult {
  if (
    typeof receiptJson !== 'string' ||
    Buffer.byteLength(receiptJson, 'utf8') > MAX_REKOR_RECEIPT_BYTES
  ) {
    return { ok: false, reason: 'receipt_too_large' };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(receiptJson);
  } catch {
    return { ok: false, reason: 'receipt_not_json' };
  }
  if (hasInclusionProofWithoutCheckpoint(parsed)) {
    return { ok: false, reason: 'checkpoint_missing' };
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
  let pinnedLogId: string;
  try {
    pinnedLogId = computeRekorLogIdHex(pem);
  } catch (err) {
    return {
      ok: false,
      reason: `set_pubkey_load_failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  if (entry.logID.toLowerCase() !== pinnedLogId.toLowerCase()) {
    return { ok: false, reason: 'set_logid_key_mismatch' };
  }

  const setResult = verifySet(entry, pem);
  if (!setResult.ok) return setResult;

  const checkpointResult = verifySignedCheckpoint(
    entry.inclusionProof.checkpoint,
    pem,
  );
  if (!checkpointResult.ok) return checkpointResult;
  if (
    checkpointResult.checkpoint.treeSize !== entry.inclusionProof.treeSize
  ) {
    return { ok: false, reason: 'checkpoint_tree_size_mismatch' };
  }
  if (!/^[0-9a-f]{64}$/i.test(entry.inclusionProof.rootHash)) {
    return { ok: false, reason: 'inclusion_malformed' };
  }
  const proofRoot = Buffer.from(entry.inclusionProof.rootHash, 'hex');
  if (
    proofRoot.length !== checkpointResult.checkpoint.rootHash.length ||
    !crypto.timingSafeEqual(proofRoot, checkpointResult.checkpoint.rootHash)
  ) {
    return { ok: false, reason: 'checkpoint_root_mismatch' };
  }

  const inclusionResult = verifyInclusion(entry.inclusionProof, entry.body);
  if (!inclusionResult.ok) return inclusionResult;

  if (expectedRoot) {
    const bindingResult = verifyBodyBinding(entry.body, expectedRoot);
    if (!bindingResult.ok) return bindingResult;
    // SEC-2026-09-12 (MCPSDK-01) — the entry is genuine AND bound to this
    // root; the remaining question is whether the log's signed clock agrees
    // with the time window the bundle claims for itself.
    const windowResult = verifyIntegratedTimeWindow(
      entry.integratedTime,
      expectedRoot,
    );
    if (!windowResult.ok) return windowResult;
  }

  return { ok: true };
}
