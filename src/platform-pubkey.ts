/**
 * AUDIT-2026-05-30 — Pinned platform public key.
 *
 * The compliance bundle ships a `platform-attestation.json` entry
 * signed by a Praesidia-platform ECDSA P-256 key. This file is where
 * the OFFLINE verifier hard-codes the corresponding public key so an
 * auditor verifying a bundle does NOT need to fetch the key over the
 * network from Praesidia (which would defeat the point — the verifier
 * exists precisely so the auditor can verify WITHOUT trusting our
 * runtime).
 *
 * Format: base64-encoded SPKI DER of an EC P-256 (prime256v1) public
 * key. The expected fingerprint (sha256-hex) is also pinned so the
 * verifier can fail loudly if the embedded bytes don't match the
 * fingerprint declared in the bundle's `platformSigningKeyFingerprint`
 * field — defending against a CI-side substitution of the key bytes
 * without the corresponding fingerprint update.
 *
 * RELEASE PROCESS:
 *   1. Deploy (or deliberately rotate) IAC's production
 *      ECC_NIST_P256/SIGN_VERIFY platform-attestation KMS key. Read the
 *      `PlatformAttestationKmsKeyArn` stack output, then fetch its public
 *      SPKI DER bytes (AWS CLI prints them as base64):
 *        aws kms get-public-key --key-id <arn> --query PublicKey --output text
 *   2. Replace {@link PLATFORM_PUBLIC_KEY_DER_B64} with the new base64.
 *   3. Compute the sha256-hex fingerprint of the decoded DER bytes and
 *      verify it through the independent production publication channel.
 *   4. Update {@link PLATFORM_PUBLIC_KEY_FINGERPRINT} to match.
 *   5. Set the protected `audit-verifier-production` environment variable
 *      `PRODUCTION_PLATFORM_KEY_FINGERPRINT` to the independently approved
 *      lowercase fingerprint. Never copy it from this file during approval.
 *   6. Cut a new `@praesidia/audit-verifier` release; auditors update
 *      the CLI before verifying bundles emitted under the new key.
 *
 * Never generate or export a private PEM for this release step. Production
 * private key material stays inside KMS.
 *
 * PINNED 2026-10-08 (0.11.0): production KMS key
 * `alias/praesidia-prod-platform-attestation` (eu-central-1,
 * ECC_NIST_P256 / SIGN_VERIFY / ECDSA_SHA_256). Operators can still supply a
 * different trusted key explicitly with CLI `--platform-key` /
 * `--trust-anchor` or library option `platformPublicKeyDerB64`.
 */

/**
 * Base64-encoded SPKI DER of the pinned platform public key. The
 * empty-string sentinel means there is no embedded trust anchor.
 */
export const PLATFORM_PUBLIC_KEY_DER_B64: string =
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGCtK7vDZBlHyp2OPMBdNYHT5RBZlr5/ND6KeNlQwm3yFmSJmYQ53os6woh+c37lFt+r2s+ECCjOYBuuxuMbykw==';

/**
 * sha256-hex of the DER bytes in {@link PLATFORM_PUBLIC_KEY_DER_B64}.
 * Empty string only in placeholder mode.
 */
export const PLATFORM_PUBLIC_KEY_FINGERPRINT: string =
  '3f7a069ab0e30bd7c1765c8fa9f7b8f0bc164bb5363500d111f5ec0deb4a0a6d';

/**
 * True iff both pin constants are non-empty (a half pin counts as unpinned).
 * Consistency is not checked here: `resolvePlatformKey` in verify.ts recomputes
 * the fingerprint from the DER and fails closed on a mismatch (AV-2750).
 */
export function isPlatformPubkeyPinned(): boolean {
  return (
    PLATFORM_PUBLIC_KEY_DER_B64.length > 0 &&
    PLATFORM_PUBLIC_KEY_FINGERPRINT.length > 0
  );
}
