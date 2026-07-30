/**
 * PROD16 FINDING 5 (ii) — CI-time regression check for the platform trust
 * anchor, distinct from `assert-release-trust-anchor.mjs`.
 *
 * `assert-release-trust-anchor.mjs` gates `npm publish` (via `prepack`) and
 * correctly REQUIRES the pin to be filled in — that script is untouched by
 * this file and stays the strict publish-time gate.
 *
 * This script runs in CI on every push/PR, where the pin is CURRENTLY (and
 * legitimately) still the documented empty-string placeholder pending an
 * ops-side keypair generation (see `platform-pubkey.ts`'s
 * `TODO(AUDIT-2026-05-30 follow-up)`). Failing CI on that known, tracked,
 * pending state would not catch anything new. What CI SHOULD catch, ahead
 * of a publish attempt:
 *
 *   1. A PARTIAL edit — exactly one of the two constants changed while the
 *      other didn't (an incomplete fill-in, or an incomplete revert).
 *   2. An INCONSISTENT filled-in key — bad base64, a non-EC key, or a
 *      fingerprint that no longer matches the DER bytes (e.g. someone
 *      pastes a new key over the DER constant without recomputing the
 *      fingerprint, or vice versa).
 *
 * Both classes are real regressions a reviewer could plausibly miss in a
 * diff; this check fails the PR the moment either happens, instead of
 * only surfacing at `npm publish` time.
 */
import crypto from 'node:crypto';
import {
  PLATFORM_PUBLIC_KEY_DER_B64,
  PLATFORM_PUBLIC_KEY_FINGERPRINT,
} from '../dist/platform-pubkey.js';

function fail(message) {
  process.stderr.write(`trust-anchor CI check failed: ${message}\n`);
  process.exitCode = 1;
}

const derEmpty = PLATFORM_PUBLIC_KEY_DER_B64.length === 0;
const fingerprintEmpty = PLATFORM_PUBLIC_KEY_FINGERPRINT.length === 0;

if (derEmpty && fingerprintEmpty) {
  process.stdout.write(
    'trust-anchor CI check: both constants are still the documented empty ' +
      'placeholder (PROD16 FINDING 5, pending ops-side keypair generation) — OK.\n',
  );
} else if (derEmpty !== fingerprintEmpty) {
  fail(
    'exactly one of PLATFORM_PUBLIC_KEY_DER_B64 / PLATFORM_PUBLIC_KEY_FINGERPRINT ' +
      'is empty — this looks like a partial edit or an incomplete revert. Both must ' +
      'be empty (placeholder) or both filled in together.',
  );
} else {
  try {
    const der = Buffer.from(PLATFORM_PUBLIC_KEY_DER_B64, 'base64');
    if (der.toString('base64') !== PLATFORM_PUBLIC_KEY_DER_B64) {
      fail('PLATFORM_PUBLIC_KEY_DER_B64 is not canonical base64');
    } else {
      const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
      if (key.asymmetricKeyType !== 'ec') {
        fail('the embedded trust anchor is not an EC public key');
      } else {
        const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
        if (fingerprint !== PLATFORM_PUBLIC_KEY_FINGERPRINT.toLowerCase()) {
          fail('the embedded key does not match PLATFORM_PUBLIC_KEY_FINGERPRINT');
        } else {
          process.stdout.write(
            'trust-anchor CI check: pinned key is filled in and internally consistent — OK.\n',
          );
        }
      }
    }
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
