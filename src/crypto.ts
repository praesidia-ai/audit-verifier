/**
 * Vendored cryptographic primitives for the offline audit-bundle verifier.
 *
 * These are intentionally byte-for-byte compatible with the be-core
 * primitives they shadow, so the same bytes that were signed inside the
 * Praesidia runtime can be verified by an external auditor running
 * `praesidia-verify` against a bundle file.
 *
 * - {@link verifyEd25519}    mirrors be-core CryptoUtilsService.verifyEd25519
 *                            (AGV-003) — same SPKI prefix, same 64-byte
 *                            signature guard, never throws.
 * - {@link signEd25519}      test-only helper for fixture generation. Not
 *                            re-exported from `index.ts`. Same PKCS#8
 *                            prefix as be-core.
 * - {@link sha256}           plain SHA-256, returns a Buffer.
 * - {@link merkleBuild}      RFC 6962-style tree (leaf prefix 0x00,
 *                            internal prefix 0x01, duplicate-last for odd
 *                            levels). Test-only — not exported.
 * - {@link merkleVerify}     verifies an inclusion proof against a root,
 *                            constant-time root comparison.
 * - {@link canonicalJson}    JCS-inspired canonical JSON identical in
 *                            output to be-core's AGV-030 implementation.
 *
 * Zero non-built-in dependencies. Pure Node `crypto`.
 */

import * as crypto from 'node:crypto';

// ── Ed25519 DER prefixes (RFC 8410) ─────────────────────────────────────
//
// PKCS#8 wrapper for a raw 32-byte Ed25519 private seed:
//   SEQUENCE (0x30 0x2e)
//     INTEGER 0 (0x02 0x01 0x00)
//     SEQUENCE (0x30 0x05)
//       OID 1.3.101.112 = Ed25519 (0x06 0x03 0x2b 0x65 0x70)
//     OCTET STRING (0x04 0x22)
//       OCTET STRING (0x04 0x20) — 32 raw private key bytes
const ED25519_PKCS8_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);

// SubjectPublicKeyInfo wrapper for a raw 32-byte Ed25519 public key:
//   SEQUENCE (0x30 0x2a)
//     SEQUENCE (0x30 0x05)
//       OID 1.3.101.112 = Ed25519 (0x06 0x03 0x2b 0x65 0x70)
//     BIT STRING (0x03 0x21 0x00) — 32 raw public key bytes
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// ── Merkle prefixes (RFC 6962 §2.1) ─────────────────────────────────────
const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);
const EMPTY_ROOT = Buffer.alloc(32, 0x00);

// ── ECDSA P-256 group order (low-s gate) ────────────────────────────────
//
// AUDIT-2026-05/21 — mirror of be-core CryptoUtilsService.
//
// Plain ECDSA is malleable: for any valid signature (r, s) over the
// P-256 curve, the pair (r, n - s) also verifies. An external auditor
// running this verifier must reject the malleated form so it cannot be
// used to fork the audit trail (different bytes, same logical
// signature) post-export.
//
// We enforce the BIP-66 / EIP-2 canonical "low-s" rule: `s <= n/2`.
// Same constants as be-core; any divergence breaks bundle compat.
const P256_N = BigInt(
  '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
);
const P256_HALF_N = P256_N >> 1n;

/**
 * Extract `s` from a DER-encoded ECDSA signature (or from a raw
 * 64-byte `r || s` concatenation). Returns `null` on any parse error.
 *
 * DER layout (X9.62 / RFC 3279):
 *   0x30 <total-len>
 *     0x02 <r-len> <r-bytes>
 *     0x02 <s-len> <s-bytes>
 *
 * INTEGER fields carry a leading 0x00 pad when the natural high bit
 * is set (so ASN.1 reads them as positive); strip that pad before
 * parsing the magnitude.
 *
 * Exported for direct unit testing.
 */
export function extractEcdsaSFromSignature(sig: Buffer): bigint | null {
  if (sig.length === 64) {
    const r = BigInt('0x' + sig.subarray(0, 32).toString('hex'));
    const s = BigInt('0x' + sig.subarray(32, 64).toString('hex'));
    return r > 0n && r < P256_N && s > 0n && s < P256_N ? s : null;
  }
  // P-256 DER signatures are at most 72 bytes and use short-form lengths.
  // Reject alternative encodings before applying the low-s rule.
  if (
    sig.length < 8 ||
    sig.length > 72 ||
    sig[0] !== 0x30 ||
    sig[1] !== sig.length - 2
  ) {
    return null;
  }
  let offset = 2;
  if (sig[offset] !== 0x02) {
    return null;
  }
  const rLen = sig[offset + 1];
  if (rLen === undefined || rLen < 1 || rLen > 33) {
    return null;
  }
  const rStart = offset + 2;
  const rEnd = rStart + rLen;
  if (rEnd + 2 > sig.length) return null;
  const rBytes = canonicalDerIntegerMagnitude(sig.subarray(rStart, rEnd));
  if (rBytes === null) return null;
  offset = rEnd;
  if (sig[offset] !== 0x02) {
    return null;
  }
  const sLen = sig[offset + 1];
  if (sLen === undefined || sLen < 1 || sLen > 33) {
    return null;
  }
  const sStart = offset + 2;
  const sEnd = sStart + sLen;
  if (sEnd !== sig.length) return null;
  const sBytes = canonicalDerIntegerMagnitude(sig.subarray(sStart, sEnd));
  if (sBytes === null) return null;
  const r = BigInt('0x' + rBytes.toString('hex'));
  const s = BigInt('0x' + sBytes.toString('hex'));
  return r > 0n && r < P256_N && s > 0n && s < P256_N ? s : null;
}

function canonicalDerIntegerMagnitude(encoded: Buffer): Buffer | null {
  if (encoded.length === 0 || encoded.length > 33) return null;
  if ((encoded[0]! & 0x80) !== 0) return null;
  if (encoded.length > 1 && encoded[0] === 0x00) {
    if ((encoded[1]! & 0x80) === 0) return null;
    encoded = encoded.subarray(1);
  }
  return encoded.length <= 32 ? encoded : null;
}

/**
 * Returns `true` iff `sig` is in canonical low-s form
 * (`0 < s <= n/2`). Malformed bytes or `s == 0` return `false`.
 *
 * Exported for direct unit testing.
 */
export function isLowSP256(sig: Buffer): boolean {
  const s = extractEcdsaSFromSignature(sig);
  if (s === null) {
    return false;
  }
  return s > 0n && s <= P256_HALF_N;
}

// ════════════════════════════════════════════════════════════════════════
// SHA-256
// ════════════════════════════════════════════════════════════════════════

/** SHA-256 over a Buffer or Uint8Array. */
export function sha256(data: Buffer | Uint8Array): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

/** Decode canonical padded standard base64, rejecting ignored junk bytes. */
export function decodeBase64Strict(
  value: unknown,
  expectedLength?: number,
): Buffer | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    (expectedLength !== undefined &&
      value.length !== Math.ceil(expectedLength / 3) * 4) ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) return null;
  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    return null;
  }
  return decoded;
}

function leafHash(data: Uint8Array): Buffer {
  return sha256(Buffer.concat([LEAF_PREFIX, Buffer.from(data)]));
}

function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([NODE_PREFIX, left, right]));
}

// ════════════════════════════════════════════════════════════════════════
// Ed25519
// ════════════════════════════════════════════════════════════════════════

const ED25519_P = (1n << 255n) - 19n;

/**
 * AV-2701 — y coordinates of the 8 small-order Ed25519 points: 0 (order 4),
 * 1 (identity), p-1 (order 2) and the two order-8 values. With either sign
 * bit they cover all 8 points (plus the "-0" encodings of y=1 and y=p-1).
 * Mirrors libsodium's ed25519_ref10.c blocklist.
 */
export const ED25519_SMALL_ORDER_Y: ReadonlySet<bigint> = new Set([
  0n,
  1n,
  ED25519_P - 1n,
  2707385501144840649318225287225658788936804267575313519463743609750303402022n,
  55188659117513257062467267217118295137698188065244968500265048394206261417927n,
]);

/**
 * AV-2701 — `true` iff a 32-byte Ed25519 point encoding (public key or a
 * signature's R) must be rejected before it reaches OpenSSL: y (sign bit
 * masked, little-endian) is non-canonical (`y >= p`, RFC 8032 §5.1.3) or is
 * a small-order point's y. Some OpenSSL builds (node v24.14 / OpenSSL 3.5.5)
 * accept an all-zero key with an all-zero signature for ~1 in 4 messages, so
 * the verifier cannot leave this to the runtime. Any other length → `true`.
 */
export function isRejectedEd25519Point(b: Uint8Array): boolean {
  if (b.length !== 32) return true;
  let y = 0n;
  for (let i = 31; i >= 0; i--) {
    y = (y << 8n) | BigInt(i === 31 ? b[i]! & 0x7f : b[i]!);
  }
  return y >= ED25519_P || ED25519_SMALL_ORDER_Y.has(y);
}

/**
 * Verify an Ed25519 signature. Returns `false` (never throws) on any
 * malformed input or mismatched signature.
 *
 * @param message       The exact bytes that were signed.
 * @param signatureB64  The signature as standard base64 (NOT base64url).
 * @param publicKey     Raw 32-byte Ed25519 public key.
 */
export function verifyEd25519(
  message: Uint8Array,
  signatureB64: string,
  publicKey: Uint8Array,
): boolean {
  try {
    if (publicKey.length !== 32) {
      return false;
    }
    if (typeof signatureB64 !== 'string') {
      return false;
    }
    const sig = decodeBase64Strict(signatureB64, 64);
    // Ed25519 signatures are always 64 bytes; reject malformed inputs
    // before handing them to the OpenSSL bindings.
    if (sig === null) {
      return false;
    }
    // AV-2701 — small-order / non-canonical key or R fails closed here,
    // whatever the runtime's OpenSSL would decide.
    if (
      isRejectedEd25519Point(publicKey) ||
      isRejectedEd25519Point(sig.subarray(0, 32))
    ) {
      return false;
    }
    const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]);
    const keyObject = crypto.createPublicKey({
      key: der,
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, Buffer.from(message), keyObject, sig);
  } catch {
    return false;
  }
}

/**
 * Sign `message` with a raw 32-byte Ed25519 private seed. Returns the
 * signature as standard base64.
 *
 * Test-only helper — NOT re-exported from the package's public surface.
 * Used by the in-repo fixture builder to mint a deterministic compliance
 * bundle for the test suite.
 */
export function signEd25519(
  message: Uint8Array,
  privateKey: Uint8Array,
): string {
  if (privateKey.length !== 32) {
    throw new Error('Ed25519 private key must be 32 bytes');
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKey)]);
  const keyObject = crypto.createPrivateKey({
    key: der,
    format: 'der',
    type: 'pkcs8',
  });
  const signature = crypto.sign(null, Buffer.from(message), keyObject);
  return signature.toString('base64');
}

// ════════════════════════════════════════════════════════════════════════
// ECDSA-P256-SHA256
// ════════════════════════════════════════════════════════════════════════

/**
 * Verify an ECDSA-P256-SHA256 signature. Returns `false` (never throws)
 * on any malformed input or mismatched signature.
 *
 * NX-TAC-02 — The KMS substrate path in be-core (AWS KMS, Vault Transit)
 * mints ECDSA-P256 keys and signs with `ECDSA_SHA_256`. Bundles emitted
 * by those tenants carried `signatureAlgorithm: 'ECDSA_P256_SHA256'`
 * but the offline verifier only knew Ed25519, rejecting every
 * KMS-substrate bundle as malformed. This helper closes that gap.
 *
 * On-the-wire format (matches `CryptoUtilsService.verifySignature`):
 *   - publicKey: SPKI DER (≈ 91 bytes for P-256).
 *   - signature: base64 of DER-encoded (r, s).
 *
 * @param message       The exact bytes that were signed.
 * @param signatureB64  Standard base64 of the DER-encoded ECDSA signature.
 * @param publicKey     SPKI-DER-encoded P-256 public key.
 */
export function verifyEcdsaP256(
  message: Uint8Array,
  signatureB64: string,
  publicKey: Uint8Array,
): boolean {
  try {
    // A canonical DER-encoded P-256 signature is at most 72 bytes, hence
    // exactly at most 96 base64 characters. Bound the input before decoding
    // so a hostile bundle cannot turn a signature field into an avoidable
    // large allocation.
    if (
      typeof signatureB64 !== 'string' ||
      signatureB64.length === 0 ||
      signatureB64.length > 96
    ) {
      return false;
    }
    if (publicKey.length === 0) {
      return false;
    }
    const sig = decodeBase64Strict(signatureB64);
    if (sig === null) {
      return false;
    }
    // AUDIT-2026-05/21 — Reject high-s (non-canonical) ECDSA
    // signatures BEFORE handing them to OpenSSL. Both (r, s) and
    // (r, n - s) verify under raw ECDSA, so a third party could
    // re-encode a signed audit row or root into a distinct-but-
    // valid form and partition the audit trail. BIP-66 / EIP-2
    // close this with the `s <= n/2` canonical rule; we mirror it.
    if (!isLowSP256(sig)) {
      return false;
    }
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKey),
      format: 'der',
      type: 'spki',
    });
    // `crypto.verify('sha256', ...)` also accepts other EC curves. The wire
    // algorithm, however, promises P-256 specifically; accepting a P-384
    // key under that label is algorithm confusion and diverges from the KMS
    // producer contract (`ECC_NIST_P256`).
    if (
      keyObject.asymmetricKeyType !== 'ec' ||
      keyObject.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
    ) {
      return false;
    }
    return crypto.verify('sha256', Buffer.from(message), keyObject, sig);
  } catch {
    return false;
  }
}

/**
 * Dispatcher across the supported signature algorithms. Manifest and
 * bundle code call this rather than the per-algorithm helpers so the
 * verifier surface stays algorithm-agnostic.
 *
 * Unknown algorithms fail closed.
 */
export type BundleSignatureAlgorithm = 'Ed25519' | 'ECDSA_P256_SHA256';

export function verifySignature(
  algorithm: BundleSignatureAlgorithm,
  message: Uint8Array,
  signatureB64: string,
  publicKey: Uint8Array,
): boolean {
  if (algorithm === 'Ed25519') {
    return verifyEd25519(message, signatureB64, publicKey);
  }
  if (algorithm === 'ECDSA_P256_SHA256') {
    return verifyEcdsaP256(message, signatureB64, publicKey);
  }
  return false;
}

/**
 * AV-0018 / ADR-0004 (DECISION-SEC-03) — tenant signature formats.
 *
 * Format 1 (legacy): the tenant key signs the payload bytes as-is.
 * Format 2: it signs `ASCII("praesidia:" + purpose + ":v2\n") || payload`.
 * A purpose is lower-case `[a-z0-9-]` (never `:` or a newline), so the
 * prefix is unambiguous. The verifier takes the purpose from the slot it is
 * checking, never from the artefact: a format-2 signature minted for one
 * purpose cannot verify in another slot.
 */
export const SIGNATURE_PURPOSES = [
  'audit-record',
  'merkle-root',
  'merkle-supersession',
  'integrity-checkpoint',
  'retention-seal',
  'bundle-manifest',
  'approval-decision',
  'permit',
  'protected-action-event',
  'attestation',
  'trust-passport',
  'governance-badge',
  'federation-manifest',
] as const;
export type SignaturePurpose = (typeof SIGNATURE_PURPOSES)[number];
export type SignatureFormat = 1 | 2;

/** AV-0018 — the exact bytes a tenant signature of `format` covers. */
export function tenantSignedBytes(
  format: SignatureFormat,
  purpose: SignaturePurpose,
  payload: Uint8Array,
): Buffer {
  if (format === 1) return Buffer.from(payload);
  return Buffer.concat([Buffer.from(`praesidia:${purpose}:v2\n`, 'ascii'), payload]);
}

// ════════════════════════════════════════════════════════════════════════
// Merkle (RFC 6962, SHA-256, duplicate-last for odd levels)
// ════════════════════════════════════════════════════════════════════════

export interface MerkleBuildResult {
  root: Uint8Array;
  depth: number;
}

export interface MerkleProof {
  /** Sibling hashes from leaf level upward. */
  siblings: Uint8Array[];
  /** Leaf index inside the original ordered list. */
  index: number;
}

/**
 * Build a Merkle tree over `leaves`. Test-only fixture helper — not
 * re-exported by `index.ts`. Verifier reads roots from the bundle, it
 * does not rebuild them from leaves.
 *
 * Leaf hash:     SHA-256(0x00 || data)
 * Internal hash: SHA-256(0x01 || left || right)
 *
 * Odd levels duplicate the trailing node before pairing. Empty input
 * collapses to 32 zero bytes (depth 0).
 */
export function merkleBuild(leaves: Uint8Array[]): MerkleBuildResult {
  if (leaves.length === 0) {
    return { root: new Uint8Array(EMPTY_ROOT), depth: 0 };
  }
  let level: Buffer[] = leaves.map((l) => leafHash(l));
  let depth = 0;
  while (level.length > 1) {
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]!);
    }
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(nodeHash(level[i]!, level[i + 1]!));
    }
    level = next;
    depth += 1;
  }
  return { root: new Uint8Array(level[0]!), depth };
}

/**
 * Generate an inclusion proof for `leaves[index]`. Test-only — the
 * verifier reads proofs from the bundle.
 */
export function merkleProof(
  leaves: Uint8Array[],
  index: number,
): MerkleProof {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new Error('Merkle proof index out of range');
  }
  if (leaves.length === 1) {
    return { siblings: [], index };
  }
  let level: Buffer[] = leaves.map((l) => leafHash(l));
  const siblings: Buffer[] = [];
  let pos = index;
  while (level.length > 1) {
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]!);
    }
    const siblingIdx = pos % 2 === 0 ? pos + 1 : pos - 1;
    siblings.push(level[siblingIdx]!);
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(nodeHash(level[i]!, level[i + 1]!));
    }
    level = next;
    pos = Math.floor(pos / 2);
  }
  return {
    siblings: siblings.map((s) => new Uint8Array(s)),
    index,
  };
}

/**
 * Verify an inclusion proof. Constant-time root comparison; returns
 * `false` on any error.
 */
export function merkleVerify(
  leaf: Uint8Array,
  proof: MerkleProof,
  root: Uint8Array,
): boolean {
  try {
    if (!Number.isInteger(proof.index) || proof.index < 0) {
      return false;
    }
    let hash = leafHash(leaf);
    let pos = proof.index;
    for (const sibling of proof.siblings) {
      const sib = Buffer.from(sibling);
      if (sib.length !== 32) {
        return false;
      }
      hash = pos % 2 === 0 ? nodeHash(hash, sib) : nodeHash(sib, hash);
      pos = Math.floor(pos / 2);
    }
    const rootBuf = Buffer.from(root);
    if (hash.length !== rootBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(hash, rootBuf);
  } catch {
    return false;
  }
}

// ════════════════════════════════════════════════════════════════════════
// Canonical JSON (AGV-030 — JCS-style)
// ════════════════════════════════════════════════════════════════════════

/**
 * Deterministic JSON byte encoding. Byte-for-byte identical to be-core's
 * `canonicalJson` (AGV-030). Object keys are sorted in
 * `Array.prototype.sort` order (lexicographic UTF-16 code-unit order).
 *
 * SCAN-AV-01 — an OBJECT PROPERTY whose value is `undefined` is OMITTED
 * entirely (key not emitted), NOT canonicalized as `"key":null`, mirroring
 * be-core's `FT-DEFECT-be-audit-chain-signature-invalid-after-first-row`
 * fix (`be/src/common/security/utils/canonical-json.ts`). A top-level or
 * array-element `undefined` is still `null` (matching `JSON.stringify`'s
 * array behavior) — only object-key omission differs. Found while adding
 * `detailsCommitment` support: `signableRow()` assigns `summary`/`details`
 * unconditionally, which is `undefined` (not present at all) on a
 * post-cutover wire row — without this fix that unconditional assignment
 * would inject a spurious `"summary":null,"details":null` into the
 * reconstructed preimage, breaking byte-for-byte agreement with be-core
 * even after `detailsCommitment` itself is understood.
 */
export function canonicalJson(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

function canonicalize(v: unknown): string {
  if (v === null || v === undefined) {
    return 'null';
  }
  if (typeof v === 'boolean') {
    return v ? 'true' : 'false';
  }
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) {
      throw new Error('canonicalJson: non-finite number');
    }
    return JSON.stringify(v);
  }
  if (typeof v === 'string') {
    return JSON.stringify(v);
  }
  if (typeof v === 'bigint') {
    return JSON.stringify(v.toString());
  }
  if (Array.isArray(v)) {
    return '[' + v.map(canonicalize).join(',') + ']';
  }
  if (typeof v === 'object') {
    if (v instanceof Date) {
      return JSON.stringify(v.toISOString());
    }
    if (Buffer.isBuffer(v)) {
      return JSON.stringify(v.toString('base64'));
    }
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    const parts = keys.map(
      (k) => JSON.stringify(k) + ':' + canonicalize(obj[k]),
    );
    return '{' + parts.join(',') + '}';
  }
  // function, symbol — not JSON-representable. Mirror be-core: emit null.
  return 'null';
}

// ════════════════════════════════════════════════════════════════════════
// Genesis chain link
// ════════════════════════════════════════════════════════════════════════

/** Base64 of 32 zero bytes — the first row's `prev_row_hash`. */
export const GENESIS_PREV_ROW_HASH = Buffer.alloc(32, 0x00).toString('base64');
