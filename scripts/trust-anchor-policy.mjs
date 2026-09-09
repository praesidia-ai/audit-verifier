import crypto from 'node:crypto';

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

export class TrustAnchorPolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TrustAnchorPolicyError';
  }
}

function reject(message) {
  throw new TrustAnchorPolicyError(message);
}

/**
 * Validate the public trust anchor embedded in a verifier build.
 *
 * `allowEmpty` exists only for ordinary PR CI while the production key
 * ceremony is outstanding. Release callers must leave it false and must
 * provide `approvedFingerprint`, an operator-owned value obtained from the
 * key ceremony rather than copied from this source tree.
 */
export function validateTrustAnchor({
  derBase64,
  fingerprint,
  allowEmpty = false,
  approvedFingerprint,
}) {
  const derEmpty = derBase64.length === 0;
  const fingerprintEmpty = fingerprint.length === 0;

  if (derEmpty && fingerprintEmpty) {
    if (allowEmpty) {
      return { state: 'placeholder' };
    }
    reject(
      'the embedded platform trust anchor is empty; pin the operator-approved production public key before publishing',
    );
  }

  if (derEmpty !== fingerprintEmpty) {
    reject(
      'exactly one of PLATFORM_PUBLIC_KEY_DER_B64 / PLATFORM_PUBLIC_KEY_FINGERPRINT is empty',
    );
  }

  if (!SHA256_HEX_RE.test(fingerprint)) {
    reject(
      'PLATFORM_PUBLIC_KEY_FINGERPRINT must be exactly 64 lowercase hexadecimal characters',
    );
  }

  const der = Buffer.from(derBase64, 'base64');
  if (der.length === 0 || der.toString('base64') !== derBase64) {
    reject('PLATFORM_PUBLIC_KEY_DER_B64 is not canonical base64');
  }

  let key;
  try {
    key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    reject('the embedded trust anchor is not a valid SPKI DER public key');
  }

  const canonicalDer = key.export({ format: 'der', type: 'spki' });
  if (!Buffer.isBuffer(canonicalDer) || !canonicalDer.equals(der)) {
    reject('the embedded trust anchor is not canonical SPKI DER');
  }

  if (key.asymmetricKeyType !== 'ec') {
    reject('the embedded trust anchor is not an EC public key');
  }

  const jwk = key.export({ format: 'jwk' });
  if (jwk.crv !== 'P-256') {
    reject('the embedded trust anchor is not an ECDSA P-256 public key');
  }

  const computedFingerprint = crypto
    .createHash('sha256')
    .update(der)
    .digest('hex');
  if (computedFingerprint !== fingerprint) {
    reject('the embedded key does not match PLATFORM_PUBLIC_KEY_FINGERPRINT');
  }

  if (approvedFingerprint !== undefined) {
    if (!SHA256_HEX_RE.test(approvedFingerprint)) {
      reject(
        'PRAESIDIA_RELEASE_APPROVED_PLATFORM_KEY_FINGERPRINT must be exactly 64 lowercase hexadecimal characters',
      );
    }
    if (approvedFingerprint !== computedFingerprint) {
      reject(
        'the embedded key does not match the operator-approved release fingerprint',
      );
    }
  } else if (!allowEmpty) {
    reject(
      'PRAESIDIA_RELEASE_APPROVED_PLATFORM_KEY_FINGERPRINT is required for a release',
    );
  }

  return { state: 'pinned', fingerprint: computedFingerprint };
}
