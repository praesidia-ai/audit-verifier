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
 *   2. An INVALID filled-in key — noncanonical base64/SPKI, anything other
 *      than P-256, a noncanonical fingerprint, or a fingerprint that no
 *      longer matches the DER bytes (e.g. someone pastes a new key over the
 *      DER constant without recomputing the fingerprint, or vice versa).
 *
 * Both classes are real regressions a reviewer could plausibly miss in a
 * diff; this check fails the PR the moment either happens, instead of
 * only surfacing at `npm publish` time.
 */
import {
  PLATFORM_PUBLIC_KEY_DER_B64,
  PLATFORM_PUBLIC_KEY_FINGERPRINT,
} from '../dist/platform-pubkey.js';
import { validateTrustAnchor } from './trust-anchor-policy.mjs';

function fail(message) {
  process.stderr.write(`trust-anchor CI check failed: ${message}\n`);
  process.exitCode = 1;
}

try {
  const result = validateTrustAnchor({
    derBase64: PLATFORM_PUBLIC_KEY_DER_B64,
    fingerprint: PLATFORM_PUBLIC_KEY_FINGERPRINT,
    allowEmpty: true,
  });
  process.stdout.write(
    result.state === 'placeholder'
      ? 'trust-anchor CI check: both constants remain the documented empty placeholder pending the production key ceremony — OK.\n'
      : 'trust-anchor CI check: pinned key is canonical P-256 and internally consistent — OK.\n',
  );
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
