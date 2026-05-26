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
 *   1. Generate (or rotate) the platform keypair on the ops side:
 *        openssl ecparam -name prime256v1 -genkey -noout -out plat.pem
 *        openssl ec -in plat.pem -pubout -outform DER | base64
 *   2. Replace {@link PLATFORM_PUBLIC_KEY_DER_B64} with the new base64.
 *   3. Compute the sha256 of the DER bytes:
 *        openssl ec -in plat.pem -pubout -outform DER | openssl dgst -sha256 -hex
 *   4. Update {@link PLATFORM_PUBLIC_KEY_FINGERPRINT} to match.
 *   5. Cut a new `@praesidia/audit-verifier` release; auditors update
 *      the CLI before verifying bundles emitted under the new key.
 *
 * TODO(AUDIT-2026-05-30 follow-up): replace the placeholder values
 * below with the production platform pubkey before any external
 * auditor consumes a v3+ bundle. While the placeholder is in place,
 * the verifier:
 *   - emits a `placeholder_platform_key` reason on the
 *     `platformAttestation` component; AND
 *   - treats the attestation as `warn-but-proceed` (does NOT mark
 *     the bundle overall failure), so dev / CI bundles built with
 *     ephemeral platform keys still verify.
 *
 * Once the real key is pinned the verifier flips to strict mode
 * automatically (see `verifyPlatformAttestation` in `verify.ts`).
 */

/**
 * Base64-encoded SPKI DER of the pinned platform public key. The
 * empty-string sentinel triggers placeholder mode — see the file
 * header for the release procedure that replaces it with real bytes.
 */
export const PLATFORM_PUBLIC_KEY_DER_B64: string = '';

/**
 * sha256-hex of the DER bytes in {@link PLATFORM_PUBLIC_KEY_DER_B64}.
 * Empty string while we're still in placeholder mode.
 */
export const PLATFORM_PUBLIC_KEY_FINGERPRINT: string = '';

/**
 * True iff the verifier should treat the platform attestation as a
 * mandatory check. Placeholder mode (both pin values empty) returns
 * `false` so dev / CI bundles built before the production pin is
 * available still verify end-to-end (the attestation entry itself is
 * still surfaced in the report as `warn`).
 */
export function isPlatformPubkeyPinned(): boolean {
  return (
    PLATFORM_PUBLIC_KEY_DER_B64.length > 0 &&
    PLATFORM_PUBLIC_KEY_FINGERPRINT.length > 0
  );
}
