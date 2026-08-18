/**
 * AUDIT-2026-05/21 — ECDSA-P256 low-s (BIP-66 / EIP-2) backport tests
 * for the offline verifier.
 *
 * Mirror of the be-core CryptoUtilsService low-s tests. We don't share
 * a test fixture because this package intentionally has no path
 * dependency on be-core's source — bundles must verify in a clean
 * download of `@praesidia/audit-verifier`. The two suites therefore
 * cover the same regression independently.
 *
 * What this proves:
 *   - A canonical (low-s) signature verifies.
 *   - The same signature flipped to (r, n - s) is rejected, even
 *     though OpenSSL on its own still considers it valid (that's the
 *     malleability we close).
 *   - Node's `crypto.sign` for P-256 emits high-s ~50% of the time
 *     (documents WHY the verify-side gate matters).
 *   - Malformed signature bytes are rejected without throwing.
 *   - The boundary case s == n/2 is accepted; s == 0 and s == n/2 + 1
 *     are rejected.
 */

import * as crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  extractEcdsaSFromSignature,
  isLowSP256,
  verifyEcdsaP256,
  verifySignature,
  decodeBase64Strict,
} from '../crypto.js';

// P-256 group order — same constant the verifier enforces.
const P256_N = BigInt(
  '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
);
const P256_HALF_N = P256_N >> 1n;

/** Build a fresh DER ECDSA signature carrying r (from `sig`) and `newS`. */
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

  const rField = Buffer.concat([Buffer.from([0x02, rBytes.length]), rBytes]);
  const sField = Buffer.concat([Buffer.from([0x02, sBytes.length]), sBytes]);
  const inner = Buffer.concat([rField, sField]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

/** Sign and keep flipping until we have a low-s signature in hand. */
function signLowS(
  message: Buffer,
  privateKey: crypto.KeyObject,
): Buffer {
  for (let i = 0; i < 64; i++) {
    const candidate = crypto.sign('sha256', message, privateKey);
    if (isLowSP256(candidate)) {
      return candidate;
    }
    // Flip on the spot.
    const s = extractEcdsaSFromSignature(candidate)!;
    return reencodeDerWithS(candidate, P256_N - s);
  }
  throw new Error('unreachable');
}

describe('audit-verifier ECDSA-P256 low-s gate (AUDIT-2026-05/21)', () => {
  it('accepts a canonical low-s signature', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const spki = new Uint8Array(
      publicKey.export({ format: 'der', type: 'spki' }),
    );
    const message = Buffer.from('canonical', 'utf8');
    const sig = signLowS(message, privateKey);
    expect(isLowSP256(sig)).toBe(true);
    expect(verifyEcdsaP256(message, sig.toString('base64'), spki)).toBe(true);
    expect(
      verifySignature('ECDSA_P256_SHA256', message, sig.toString('base64'), spki),
    ).toBe(true);
  });

  it('REJECTS the (r, n - s) flipped form even though OpenSSL accepts it', () => {
    // This is the offline-verifier mirror of the be-core regression
    // test. Without the backport, any third party could re-encode a
    // signed audit row in a bundle and confuse downstream auditors
    // into believing two distinct signatures came from one signer.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const spki = new Uint8Array(
      publicKey.export({ format: 'der', type: 'spki' }),
    );
    const message = Buffer.from('flip-me', 'utf8');
    const original = signLowS(message, privateKey);

    // Sanity: original verifies.
    expect(verifyEcdsaP256(message, original.toString('base64'), spki)).toBe(
      true,
    );

    const s = extractEcdsaSFromSignature(original);
    expect(s).not.toBeNull();
    expect(s! <= P256_HALF_N).toBe(true);
    const flipped = reencodeDerWithS(original, P256_N - s!);
    expect(isLowSP256(flipped)).toBe(false);

    // OpenSSL by itself would still accept the flipped form.
    const opensslOk = crypto.verify('sha256', message, publicKey, flipped);
    expect(opensslOk).toBe(true);

    // The verifier under test must reject.
    expect(verifyEcdsaP256(message, flipped.toString('base64'), spki)).toBe(
      false,
    );
    expect(
      verifySignature(
        'ECDSA_P256_SHA256',
        message,
        flipped.toString('base64'),
        spki,
      ),
    ).toBe(false);
  });

  it('Node crypto.sign emits non-canonical (high-s) signatures with non-trivial frequency', () => {
    // Documents the operational reality: raw `crypto.sign` cannot be
    // trusted to emit canonical signatures for P-256. The signing
    // side (be-core's AWS KMS substrate) MUST canonicalize before
    // bundles are exported. If a future Node release starts emitting
    // only low-s, this test will fail and force a review of whether
    // the sign-side flip is still required.
    const { privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    let highSCount = 0;
    for (let i = 0; i < 100; i++) {
      const msg = crypto.randomBytes(32);
      const sig = crypto.sign('sha256', msg, privateKey);
      if (!isLowSP256(sig)) {
        highSCount += 1;
      }
    }
    expect(highSCount).toBeGreaterThan(0);
  });

  it('rejects malformed signature bytes without throwing', () => {
    const { publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const spki = new Uint8Array(
      publicKey.export({ format: 'der', type: 'spki' }),
    );
    expect(verifyEcdsaP256(Buffer.from('m'), '', spki)).toBe(false);
    expect(
      verifyEcdsaP256(
        Buffer.from('m'),
        Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00]).toString('base64'),
        spki,
      ),
    ).toBe(false);
    // Garbage that DOES start with 0x30 but isn't valid DER.
    expect(
      verifyEcdsaP256(
        Buffer.from('m'),
        Buffer.from([0x30, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).toString(
          'base64',
        ),
        spki,
      ),
    ).toBe(false);
  });

  it('rejects a valid P-384 signature mislabeled as ECDSA-P256', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-384',
    });
    const message = Buffer.from('wrong curve', 'utf8');
    const signature = crypto.sign('sha256', message, privateKey);
    const spki = new Uint8Array(
      publicKey.export({ format: 'der', type: 'spki' }),
    );

    expect(crypto.verify('sha256', message, publicKey, signature)).toBe(true);
    expect(
      verifyEcdsaP256(message, signature.toString('base64'), spki),
    ).toBe(false);
  });

  it('rejects oversized signature text before base64 decoding', () => {
    const { publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const spki = new Uint8Array(
      publicKey.export({ format: 'der', type: 'spki' }),
    );
    expect(verifyEcdsaP256(Buffer.from('m'), 'A'.repeat(100), spki)).toBe(
      false,
    );
  });

  it('rejects non-canonical base64 instead of ignoring junk', () => {
    const canonical = Buffer.from('strict byte').toString('base64');
    expect(decodeBase64Strict(canonical)?.toString()).toBe('strict byte');
    expect(decodeBase64Strict(`${canonical}!!`)).toBeNull();
    expect(decodeBase64Strict(canonical.replace(/=$/, ''))).toBeNull();
  });

  it('rejects non-canonical DER encodings and trailing bytes', () => {
    const canonical = Buffer.from('3006020101020101', 'hex');
    expect(extractEcdsaSFromSignature(canonical)).toBe(1n);
    expect(
      extractEcdsaSFromSignature(Buffer.concat([canonical, Buffer.from([0])])),
    ).toBeNull();
    expect(
      extractEcdsaSFromSignature(Buffer.from('300702020001020101', 'hex')),
    ).toBeNull();
  });

  it('isLowSP256 honors the s == n/2 boundary', () => {
    // Shell DER (r = 1, s = 1) — we rebuild the s field.
    const shell = Buffer.from('3006020101020101', 'hex');

    // s = 0 — rejected (zero-s is degenerate).
    expect(isLowSP256(reencodeDerWithS(shell, 0n))).toBe(false);

    // s = n/2 — accepted (boundary inclusive).
    expect(isLowSP256(reencodeDerWithS(shell, P256_HALF_N))).toBe(true);

    // s = n/2 + 1 — rejected.
    expect(isLowSP256(reencodeDerWithS(shell, P256_HALF_N + 1n))).toBe(false);
  });

  it('verifySignature dispatcher with unknown algorithm fails closed', () => {
    // Type-cast to bypass the compile-time union — runtime guard
    // must still reject.
    const algo = 'NotAnAlgorithm' as unknown as 'Ed25519';
    expect(verifySignature(algo, Buffer.from('m'), '', new Uint8Array(0))).toBe(
      false,
    );
  });
});
