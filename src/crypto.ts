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

// ════════════════════════════════════════════════════════════════════════
// SHA-256
// ════════════════════════════════════════════════════════════════════════

/** SHA-256 over a Buffer or Uint8Array. */
export function sha256(data: Buffer | Uint8Array): Buffer {
  return crypto.createHash('sha256').update(data).digest();
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
    const sig = Buffer.from(signatureB64, 'base64');
    // Ed25519 signatures are always 64 bytes; reject malformed inputs
    // before handing them to the OpenSSL bindings.
    if (sig.length !== 64) {
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
    const keys = Object.keys(obj).sort();
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
