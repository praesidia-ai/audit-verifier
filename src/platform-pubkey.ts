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
 * TODO(AUDIT-2026-05-30 follow-up): replace the placeholder values
 * below with the production platform pubkey before distribution. The
 * verifier fails closed while the embedded pin is empty; operators can
 * provide a trusted key explicitly with CLI `--platform-key` or library
 * option `platformPublicKeyDerB64`.
 */

/**
 * Base64-encoded SPKI DER of the pinned platform public key. The
 * empty-string sentinel means there is no embedded trust anchor.
 */
export const PLATFORM_PUBLIC_KEY_DER_B64: string = '';

/**
 * sha256-hex of the DER bytes in {@link PLATFORM_PUBLIC_KEY_DER_B64}.
 * Empty string while we're still in placeholder mode.
 */
export const PLATFORM_PUBLIC_KEY_FINGERPRINT: string = '';

/**
 * True iff an internally consistent platform trust anchor is embedded.
 */
export function isPlatformPubkeyPinned(): boolean {
  return (
    PLATFORM_PUBLIC_KEY_DER_B64.length > 0 &&
    PLATFORM_PUBLIC_KEY_FINGERPRINT.length > 0
  );
}
