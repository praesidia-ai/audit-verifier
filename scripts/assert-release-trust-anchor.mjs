import {
  PLATFORM_PUBLIC_KEY_DER_B64,
  PLATFORM_PUBLIC_KEY_FINGERPRINT,
} from '../dist/platform-pubkey.js';
import { validateTrustAnchor } from './trust-anchor-policy.mjs';

function fail(message) {
  process.stderr.write(`audit-verifier release blocked: ${message}\n`);
  process.exitCode = 1;
}

try {
  validateTrustAnchor({
    derBase64: PLATFORM_PUBLIC_KEY_DER_B64,
    fingerprint: PLATFORM_PUBLIC_KEY_FINGERPRINT,
    approvedFingerprint:
      process.env.PRAESIDIA_RELEASE_APPROVED_PLATFORM_KEY_FINGERPRINT,
  });
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
