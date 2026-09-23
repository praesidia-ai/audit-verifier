/**
 * AV-0001 — offline verification of be's `attested` AIBOM export
 * (`praesidia-aibom-attestation/v1`, produced by `be/src/aibom/
 * aibom-attestation.ts`). Implements the envelope's own procedure (9 steps
 * since be DOCS-0590; archived 7-step exports verify identically, since the
 * added steps were already these checks) with three fail-closed checks:
 *
 * - `untrusted_key`: the embedded `publicKey` must hash (sha256 over the
 *   decoded bytes — the same fingerprint a compliance bundle's platform
 *   attestation lists per tenant key version) to a caller-supplied pin.
 *   Checking the signature only against the key the bundle ships would let
 *   anyone re-sign an edited document with their own key. With
 *   `organizationId` set (AV-0002), a document naming another org also fails.
 * - `envelope_mismatch`: the envelope's `organizationId`/`aiSystemId` are
 *   unsigned; they must equal the signed document's own fields.
 * - `non_canonical_encoding`: be emits the canonical bytes; anything else
 *   (duplicate keys, whitespace, re-escaping) was re-serialized and may
 *   show other JSON readers content the digest does not cover.
 *
 * Not authenticated by the signature, never reported as verified:
 * {@link AIBOM_UNAUTHENTICATED_FIELDS}.
 */
import { canonicalJson, decodeBase64Strict, sha256, verifySignature, type BundleSignatureAlgorithm } from './crypto.js';
import type { VerifyReport } from './verify.js';

export const AIBOM_ATTESTATION_FORMAT = 'praesidia-aibom-attestation/v1';
export const AIBOM_SIGNING_DOMAIN = 'praesidia:aibom-snapshot:v1';
/** be refuses to write a larger export (`AIBOM_EXPORT_MAX_BYTES`). */
export const MAX_AIBOM_ENVELOPE_BYTES = 8 * 1024 * 1024;
/**
 * AV-0003 — the only `signingAlgorithm` values accepted. Must equal the
 * union on be's `AibomAttestationEnvelope` (`scripts/contract-drift.mjs` [H]).
 */
export const AIBOM_SIGNING_ALGORITHMS: readonly BundleSignatureAlgorithm[] = ['Ed25519', 'ECDSA_P256_SHA256'];
/**
 * AV-0003 — envelope fields the signature does not cover, so never reported
 * as verified. Every field of be's `AibomAttestationEnvelope` must be either
 * read by {@link verifyAibomAttestation} or listed here (contract-drift [H]).
 * AV-0004: the `anchor*` labels (be BE-0738) are the anchor status the
 * exporting server resolved, not a proof. This verifier does not check
 * AIBOM anchoring, so it never reports one.
 */
export const AIBOM_UNAUTHENTICATED_FIELDS = [
  'snapshotId', 'version', 'generatedAt', 'signedAt', 'signingKeyVersion', 'procedure',
  'anchorReference', 'anchorStatus', 'anchoredAt', 'anchorReason',
] as const;

export type AibomVerdict =
  | 'verified'
  | 'unsigned'
  | 'digest_mismatch'
  | 'key_unavailable'
  | 'signature_invalid'
  | 'unsupported_format'
  | 'untrusted_key'
  | 'envelope_mismatch'
  | 'non_canonical_encoding';

export interface AibomVerifyOptions {
  /** sha256 hex of each trusted tenant public key, obtained independently of the bundle. */
  trustedKeyFingerprints: readonly string[];
  /**
   * AV-0002 — the organization those fingerprints belong to. When set, the
   * signed document's `organizationId` must equal it (`untrusted_key`
   * otherwise): a key pinned for one org is not trusted for another's AIBOM.
   */
  organizationId?: string;
}

export interface AibomVerifyReport {
  valid: boolean;
  reason: AibomVerdict;
  detail: string;
  /** Procedure step 3: the document still hashes to `digest`. */
  chainOk: boolean;
  /** sha256 hex of the embedded public key, once it decoded. */
  keyFingerprint: string | null;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** Never throws: every input, however hostile, yields a verdict. */
export function verifyAibomAttestation(
  bytes: Uint8Array,
  options: AibomVerifyOptions,
): AibomVerifyReport {
  const fail = (reason: AibomVerdict, detail: string, chainOk = false, keyFingerprint: string | null = null) =>
    ({ valid: false, reason, detail, chainOk, keyFingerprint });
  try {
    if (bytes.length > MAX_AIBOM_ENVELOPE_BYTES) {
      return fail('unsupported_format', `envelope exceeds ${MAX_AIBOM_ENVELOPE_BYTES} bytes`);
    }
    const env: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!isObject(env)) return fail('unsupported_format', 'envelope is not a JSON object');
    const { document, digest, signature, signingAlgorithm: alg, signingKeyVersion: keyVersion, publicKey } = env;
    const problem =
      env.attestationFormat !== AIBOM_ATTESTATION_FORMAT ? `attestationFormat is not ${AIBOM_ATTESTATION_FORMAT}`
      : env.domain !== AIBOM_SIGNING_DOMAIN ? `domain is not ${AIBOM_SIGNING_DOMAIN}`
      : !isObject(document) ? 'document is not a JSON object'
      : typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest) ? 'digest is not 64 lowercase hex characters'
      : typeof env.organizationId !== 'string' || typeof env.aiSystemId !== 'string' ? 'organizationId/aiSystemId missing'
      : signature !== null && typeof signature !== 'string' ? 'signature is neither null nor a string'
      : alg !== null && !(AIBOM_SIGNING_ALGORITHMS as readonly unknown[]).includes(alg) ? `unknown signingAlgorithm ${JSON.stringify(alg)}`
      : keyVersion !== null && !(Number.isSafeInteger(keyVersion) && (keyVersion as number) >= 1) ? 'signingKeyVersion is not a positive integer'
      : publicKey !== null && decodeBase64Strict(publicKey) === null ? 'publicKey is neither null nor canonical base64'
      : null;
    if (problem !== null) return fail('unsupported_format', problem);
    const doc = document as Record<string, unknown>;

    // Steps 1-3.
    const computed = sha256(canonicalJson(doc)).toString('hex');
    const chainOk = computed === digest;
    // Step 4 — be's order: `unsigned` wins over `digest_mismatch`.
    if (signature === null || alg === null || keyVersion === null) {
      return fail('unsigned', `no signature: proves nothing about origin (document ${chainOk ? 'matches' : 'does NOT match'} digest)`, chainOk);
    }
    if (!chainOk) {
      return fail('digest_mismatch', `document hashes to ${computed} but the signed digest is ${digest}: altered after signing`);
    }
    if (doc.organizationId !== env.organizationId || doc.aiSystemId !== env.aiSystemId) {
      return fail('envelope_mismatch', 'envelope organizationId/aiSystemId differ from the signed document', true);
    }
    if (publicKey === null) {
      return fail('key_unavailable', `no public key: key version ${keyVersion} was revoked or unknown when exported`, true);
    }
    const key = decodeBase64Strict(publicKey)!;
    const fingerprint = sha256(key).toString('hex');
    if (options.organizationId !== undefined && doc.organizationId !== options.organizationId) {
      return fail('untrusted_key', `pinned keys belong to org ${options.organizationId}, but the signed document names org ${String(doc.organizationId)}`, true, fingerprint);
    }
    if (!options.trustedKeyFingerprints.some((pin) => pin.toLowerCase() === fingerprint)) {
      return fail('untrusted_key', `embedded public key sha256 ${fingerprint} is not a pinned tenant key`, true, fingerprint);
    }
    // Steps 5-6 — domain is pinned above, so no cross-artifact replay.
    if (!verifySignature(alg as BundleSignatureAlgorithm, Buffer.from(`${AIBOM_SIGNING_DOMAIN}:${digest}`, 'utf8'), signature as string, key)) {
      return fail('signature_invalid', `${alg} signature does not verify under pinned key ${fingerprint}`, true, fingerprint);
    }
    if (!canonicalJson(env).equals(Buffer.from(bytes))) {
      return fail('non_canonical_encoding', 'file is not byte-identical to its canonical encoding: it was re-serialized or edited after export', true, fingerprint);
    }
    return {
      valid: true,
      reason: 'verified',
      detail: `document ${digest} of AI system ${env.aiSystemId} (org ${env.organizationId}) signed with ${alg} by pinned key ${fingerprint}`,
      chainOk: true,
      keyFingerprint: fingerprint,
    };
  } catch (err) {
    return fail('unsupported_format', `unreadable envelope: ${(err as Error).message}`);
  }
}

/**
 * AV-0002 — the pin for {@link verifyAibomAttestation}, taken from a
 * compliance-bundle report this package produced. Throws (fail closed)
 * unless the whole bundle is `valid` AND carries a verified platform
 * attestation. REVOKED keys are never pinned: an AIBOM signing time is
 * unauthenticated, so a signature cannot be dated before the revocation.
 */
export function aibomTrustFromBundle(report: VerifyReport): Required<AibomVerifyOptions> {
  if (report.status !== 'valid') throw new Error(`audit bundle status is ${report.status}, not valid`);
  const keys = report.bundle.attestedTenantKeys;
  if (!keys) throw new Error('audit bundle has no verified platform attestation, so its tenant keys are not attested');
  return {
    trustedKeyFingerprints: keys.filter((k) => k.status !== 'REVOKED').map((k) => k.fingerprint),
    organizationId: report.bundle.orgId,
  };
}
