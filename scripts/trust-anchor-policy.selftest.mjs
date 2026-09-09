import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  TrustAnchorPolicyError,
  validateTrustAnchor,
} from './trust-anchor-policy.mjs';

function publicAnchor(namedCurve = 'prime256v1') {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve });
  const der = publicKey.export({ format: 'der', type: 'spki' });
  assert(Buffer.isBuffer(der));
  return {
    der,
    derBase64: der.toString('base64'),
    fingerprint: crypto.createHash('sha256').update(der).digest('hex'),
  };
}

test('ordinary CI may recognize the explicit empty placeholder', () => {
  assert.deepEqual(
    validateTrustAnchor({
      derBase64: '',
      fingerprint: '',
      allowEmpty: true,
    }),
    { state: 'placeholder' },
  );
});

test('release mode rejects the empty placeholder', () => {
  assert.throws(
    () => validateTrustAnchor({ derBase64: '', fingerprint: '' }),
    /embedded platform trust anchor is empty/,
  );
});

test('release mode accepts canonical P-256 only with the approved fingerprint', () => {
  const anchor = publicAnchor();
  assert.deepEqual(
    validateTrustAnchor({
      derBase64: anchor.derBase64,
      fingerprint: anchor.fingerprint,
      approvedFingerprint: anchor.fingerprint,
    }),
    { state: 'pinned', fingerprint: anchor.fingerprint },
  );
});

test('release mode rejects a missing independent operator approval', () => {
  const anchor = publicAnchor();
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: anchor.derBase64,
        fingerprint: anchor.fingerprint,
      }),
    /APPROVED_PLATFORM_KEY_FINGERPRINT is required/,
  );
});

test('release mode rejects a different operator-approved fingerprint', () => {
  const anchor = publicAnchor();
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: anchor.derBase64,
        fingerprint: anchor.fingerprint,
        approvedFingerprint: '0'.repeat(64),
      }),
    /does not match the operator-approved release fingerprint/,
  );
});

test('release mode rejects a noncanonical operator approval', () => {
  const anchor = publicAnchor();
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: anchor.derBase64,
        fingerprint: anchor.fingerprint,
        approvedFingerprint: anchor.fingerprint.toUpperCase(),
      }),
    /APPROVED_PLATFORM_KEY_FINGERPRINT must be exactly 64 lowercase/,
  );
});

test('rejects partial, noncanonical, and internally inconsistent pins', () => {
  const anchor = publicAnchor();

  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: anchor.derBase64,
        fingerprint: '',
        allowEmpty: true,
      }),
    /exactly one.*is empty/,
  );
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: `${anchor.derBase64}\n`,
        fingerprint: anchor.fingerprint,
        allowEmpty: true,
      }),
    /not canonical base64/,
  );
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: anchor.derBase64,
        fingerprint: '0'.repeat(64),
        allowEmpty: true,
      }),
    /does not match PLATFORM_PUBLIC_KEY_FINGERPRINT/,
  );
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: anchor.derBase64,
        fingerprint: anchor.fingerprint.toUpperCase(),
        allowEmpty: true,
      }),
    /64 lowercase hexadecimal characters/,
  );
  assert.throws(() => {
    const withTrailingByte = Buffer.concat([
      anchor.der,
      Buffer.from([0]),
    ]).toString('base64');
    validateTrustAnchor({
      derBase64: withTrailingByte,
      fingerprint: crypto
        .createHash('sha256')
        .update(Buffer.from(withTrailingByte, 'base64'))
        .digest('hex'),
      allowEmpty: true,
    });
  }, /not (?:a valid SPKI DER public key|canonical SPKI DER)/);
});

test('rejects valid EC keys on any curve other than P-256', () => {
  const anchor = publicAnchor('secp384r1');
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: anchor.derBase64,
        fingerprint: anchor.fingerprint,
        allowEmpty: true,
      }),
    /not an ECDSA P-256 public key/,
  );
});

test('rejects valid non-EC public keys', () => {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  assert(Buffer.isBuffer(der));
  assert.throws(
    () =>
      validateTrustAnchor({
        derBase64: der.toString('base64'),
        fingerprint: crypto.createHash('sha256').update(der).digest('hex'),
        allowEmpty: true,
      }),
    /not an EC public key/,
  );
});

test('policy failures use the dedicated error type', () => {
  assert.throws(
    () => validateTrustAnchor({ derBase64: '', fingerprint: '' }),
    TrustAnchorPolicyError,
  );
});
