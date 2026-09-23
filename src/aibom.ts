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
 *
 * AV-0005 — for a bundle that verifies, the anchor (be BE-1255
 * `anchorProof`, procedure A2-A10) is checked offline against the caller's
 * pins: tenant fingerprints for the row and root keys, pinned Rekor log keys
 * for the receipt. Verdicts and reasons equal be's own offline verifier.
 */
import {
  canonicalJson, decodeBase64Strict, merkleVerify, sha256, verifySignature, type BundleSignatureAlgorithm,
} from './crypto.js';
import { computeRekorLogIdHex, resolvePinnedRekorPem, verifyRekorReceipt } from './rekor.js';
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
 * AV-0005: the four `anchor*` labels (be BE-0738) left this list: each is
 * now checked against `anchorProof` (A3, A10), and the reported anchor time
 * is the log's signed `integratedTime`, never a label.
 */
export const AIBOM_UNAUTHENTICATED_FIELDS = [
  'snapshotId', 'version', 'generatedAt', 'signedAt', 'signingKeyVersion', 'procedure',
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
  /**
   * AV-0005 — PEM public keys of the Rekor logs trusted for `anchorProof`
   * receipts, obtained independently of the bundle. Omitted: the Sigstore
   * public-good key this package pins. `[]` trusts no log.
   */
  rekorPublicKeysPem?: readonly string[];
}

export interface AibomVerifyReport {
  valid: boolean;
  reason: AibomVerdict;
  detail: string;
  /** Procedure step 3: the document still hashes to `digest`. */
  chainOk: boolean;
  /** sha256 hex of the embedded public key, once it decoded. */
  keyFingerprint: string | null;
  /**
   * AV-0005 — `verified_rekor` only for a `valid` bundle whose `anchorProof`
   * passes A2-A10 under the caller's pins. Informational: never changes `valid`.
   */
  anchorStatus: 'verified_rekor' | 'unverified';
  /** With `verified_rekor`: the Rekor log's SET-signed `integratedTime` (ISO-8601). */
  anchoredAt?: string;
  /**
   * With `unverified`: be's reason, e.g. `aibom_not_anchored` (no proof, or
   * the bundle did not verify), `unsigned`, `anchoring_pending`,
   * `anchor_label_mismatch`, `unknown_log_id`.
   */
  anchorReason?: string;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** Never throws: every input, however hostile, yields a verdict. */
export function verifyAibomAttestation(
  bytes: Uint8Array,
  options: AibomVerifyOptions,
): AibomVerifyReport {
  // A1 — an invalid bundle never reports an anchor.
  const fail = (reason: AibomVerdict, detail: string, chainOk = false, keyFingerprint: string | null = null): AibomVerifyReport =>
    ({ valid: false, reason, detail, chainOk, keyFingerprint, ...unanchored(reason === 'unsigned' ? 'unsigned' : AIBOM_NOT_ANCHORED) });
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
      ...verifyAnchorProof(env.anchorProof, {
        organizationId: env.organizationId, aiSystemId: env.aiSystemId, digest,
        reference: env.anchorReference, status: env.anchorStatus, anchoredAt: env.anchoredAt, reason: env.anchorReason,
      }, options),
    };
  } catch (err) {
    return fail('unsupported_format', `unreadable envelope: ${(err as Error).message}`);
  }
}

/** be `AIBOM_ANCHOR_REASON`: no anchor proof (never anchored, exported before BE-1255) or an invalid bundle. */
const AIBOM_NOT_ANCHORED = 'aibom_not_anchored';
const AIBOM_ANCHOR_ACTION = 'aibom.snapshot.anchor_requested';
type AibomAnchor = Pick<AibomVerifyReport, 'anchorStatus' | 'anchoredAt' | 'anchorReason'>;
const unanchored = (anchorReason: string): AibomAnchor => ({ anchorStatus: 'unverified', anchorReason });
/** `v[key]` with JavaScript's semantics: throws on null/undefined, which A2-A10 report as `anchor_proof_malformed`. */
const at = (v: unknown, key: string): unknown => (v as Record<string, unknown>)[key];

interface AnchorContext {
  organizationId: unknown; aiSystemId: unknown; digest: string;
  reference: unknown; status: unknown; anchoredAt: unknown; reason: unknown;
}

/**
 * AV-0005 — be BE-1255 `AIBOM_ANCHOR_VERIFICATION_PROCEDURE` A2-A10, a
 * line-for-line port of be's `verifyAnchorProof`. Never throws: a malformed
 * proof is `anchor_proof_malformed`. No `anchorProof` keeps the pre-BE-1255
 * verdict. Trust comes only from `options`, never from keys the proof ships.
 */
function verifyAnchorProof(proof: unknown, env: AnchorContext, options: AibomVerifyOptions): AibomAnchor {
  if (proof == null) return unanchored(AIBOM_NOT_ANCHORED);
  try {
    return checkAnchorProof(proof, env, options);
  } catch {
    return unanchored('anchor_proof_malformed');
  }
}

function checkAnchorProof(proof: unknown, env: AnchorContext, options: AibomVerifyOptions): AibomAnchor {
  // A2
  const proofStatus = at(proof, 'status');
  if (proofStatus === 'unavailable') {
    const reason = at(proof, 'reason');
    return unanchored(reason === 'not_yet_rooted' || reason === 'anchor_status_unavailable' ? reason : 'anchor_proof_malformed');
  }
  if (proofStatus !== 'included') return unanchored('anchor_proof_malformed');
  // A3
  if (env.reference !== `audit:${at(proof, 'rowId')}`) return unanchored('anchor_label_mismatch');
  // A4 — the digest is bound through the SIGNED row content only.
  const p = at(proof, 'inclusionProof');
  const row = at(p, 'row');
  const commitment = at(row, 'detailsCommitment');
  const details = commitment === undefined ? at(row, 'details') : openDetailsCommitment(commitment, at(proof, 'detailsOpening'));
  if (
    at(row, 'action') !== AIBOM_ANCHOR_ACTION || at(row, 'organizationId') !== env.organizationId ||
    !isObject(details) || details.digest !== env.digest || details.aiSystemId !== env.aiSystemId
  ) {
    return unanchored('anchor_row_unbound');
  }
  // A5 — row and root keys are pinned like the snapshot key.
  const rowKey = pinnedKey(at(p, 'rowPublicKey'), options);
  const rootKey = pinnedKey(at(p, 'rootPublicKey'), options);
  if (rowKey === null || rootKey === null) return unanchored('anchor_untrusted_key');
  if (at(p, 'publicKey') !== at(p, 'rootPublicKey') || at(p, 'keyVersion') !== at(p, 'rootKeyVersion')) {
    return unanchored('anchor_proof_malformed');
  }
  const rowBytes = canonicalJson(row);
  const prevRowHash = decodeBase64Strict(at(p, 'rowPrevHash'), 32);
  const rowSignature = at(p, 'rowSignature') as string;
  const rowSig = decodeBase64Strict(rowSignature);
  if (
    prevRowHash === null || rowSig === null ||
    !verifySignature(at(p, 'rowSignatureAlgorithm') as BundleSignatureAlgorithm, Buffer.concat([rowBytes, prevRowHash]), rowSignature, rowKey)
  ) {
    return unanchored('anchor_row_signature_invalid');
  }
  // A6
  const leaf = Buffer.concat([rowBytes, rowSig]);
  const rootHashB64 = at(p, 'rootHash') as string;
  const rootHash = decodeBase64Strict(rootHashB64, 32);
  const merkle = at(p, 'merkleProof');
  const siblings = (at(merkle, 'siblings') as unknown[]).map((s) => decodeBase64Strict(s, 32));
  const index = at(merkle, 'index') as number;
  const rowCount = at(p, 'rowCount') as number;
  if (
    rootHash === null || siblings.some((s) => s === null) ||
    !Number.isSafeInteger(index) || index < 0 || index >= rowCount ||
    sha256(Buffer.concat([Buffer.from([0x00]), leaf])).toString('base64') !== at(p, 'leafHash') ||
    !merkleVerify(leaf, { siblings: siblings as Buffer[], index }, rootHash)
  ) {
    return unanchored('anchor_inclusion_invalid');
  }
  // A7
  const rootSignature = at(p, 'rootSignature') as string;
  const rootMessage = canonicalJson({ rootHash: rootHashB64, periodStart: at(p, 'periodStart'), periodEnd: at(p, 'periodEnd'), rowCount });
  if (!verifySignature(at(p, 'rootSignatureAlgorithm') as BundleSignatureAlgorithm, rootMessage, rootSignature, rootKey)) {
    return unanchored('anchor_root_signature_invalid');
  }
  // A8-A9 — be's `classifyRootAnchorReceipts` over the proof's receipts only (no legacy columns).
  const receipts = at(proof, 'receipts');
  const entries: unknown[] = Array.isArray(receipts) ? receipts : [];
  const provider = (r: unknown) => (r == null ? undefined : at(r, 'provider'));
  const resolvePem = rekorResolver(options.rekorPublicKeysPem);
  let firstFailure: string | undefined;
  let sawLegacy = false;
  for (const entry of entries.filter((r) => provider(r) === 'rekor')) {
    const receipt = at(entry, 'receipt');
    const parsed = parseFullRekorReceipt(receipt);
    if (parsed === null) {
      sawLegacy = true;
      continue;
    }
    const pem = resolvePem(parsed.logId);
    const verdict = pem === null
      ? { ok: false, reason: 'unknown_log_id' }
      : verifyRekorReceipt(receipt as string, pem, { rootHashB64, signatureB64: rootSignature });
    if (!verdict.ok) {
      firstFailure ??= verdict.reason ?? 'anchor_proof_malformed';
      continue;
    }
    // A10 — the labels must agree; the receipt's `anchoredAt` is an unsigned server stamp.
    if (env.status !== 'verified_rekor' || env.anchoredAt !== (at(entry, 'anchoredAt') ?? undefined) || env.reason !== undefined) {
      return unanchored('anchor_label_mismatch');
    }
    return { anchorStatus: 'verified_rekor', anchoredAt: new Date(parsed.integratedTime * 1000).toISOString() };
  }
  if (entries.some((r) => provider(r) === 's3')) return unanchored('s3_anchor_not_offline_verifiable');
  if (firstFailure !== undefined) return unanchored(firstFailure);
  return unanchored(sawLegacy ? 'legacy_receipt_unverified' : 'anchoring_pending');
}

/** A4 — the opened details, or null when the opening does not match the signed commitment. */
function openDetailsCommitment(commitment: unknown, opening: unknown): Record<string, unknown> | null {
  if (typeof commitment !== 'string' || !isObject(opening) || !isObject(opening.details)) return null;
  const salt = decodeBase64Strict(opening.salt);
  if (salt === null) return null;
  const recomputed = sha256(Buffer.concat([salt, canonicalJson({ details: opening.details })])).toString('base64');
  return recomputed === commitment ? opening.details : null;
}

/** A5 — the decoded key when its sha256 is a pinned fingerprint. */
function pinnedKey(publicKeyB64: unknown, options: AibomVerifyOptions): Buffer | null {
  const key = decodeBase64Strict(publicKeyB64);
  if (key === null) return null;
  const fingerprint = sha256(key).toString('hex');
  return options.trustedKeyFingerprints.some((pin) => pin.toLowerCase() === fingerprint) ? key : null;
}

/** A8 — the caller's Rekor pins, else this package's pinned Sigstore ring. */
function rekorResolver(pems: readonly string[] | undefined): (logIdHex: string) => string | null {
  if (pems === undefined) return resolvePinnedRekorPem;
  const ring = pems.flatMap((pem) => {
    try {
      return [{ logIdHex: computeRekorLogIdHex(pem), pem }];
    } catch {
      return [];
    }
  });
  return (logIdHex) => ring.find((k) => k.logIdHex === logIdHex.toLowerCase())?.pem ?? null;
}

/** be `parseFullRekorReceipt`: a full JSON Rekor entry, else null (a legacy `rekor:<index>` receipt). */
function parseFullRekorReceipt(receipt: unknown): { logId: string; integratedTime: number } | null {
  if (typeof receipt !== 'string' || !receipt.startsWith('{')) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(receipt);
  } catch {
    return null;
  }
  if (!isObject(obj)) return null;
  const { logIndex, logId, integratedTime, body, signedEntryTimestamp, inclusionProof } = obj;
  if (
    typeof logIndex !== 'number' || typeof logId !== 'string' || typeof integratedTime !== 'number' ||
    typeof body !== 'string' || typeof signedEntryTimestamp !== 'string' || inclusionProof == null || typeof inclusionProof !== 'object'
  ) {
    return null;
  }
  return { logId, integratedTime };
}

/**
 * AV-0002 — the pin for {@link verifyAibomAttestation}, taken from a
 * compliance-bundle report this package produced. Throws (fail closed)
 * unless the whole bundle is `valid` AND carries a verified platform
 * attestation. REVOKED keys are never pinned: an AIBOM signing time is
 * unauthenticated, so a signature cannot be dated before the revocation.
 */
export function aibomTrustFromBundle(report: VerifyReport): Required<Omit<AibomVerifyOptions, 'rekorPublicKeysPem'>> {
  if (report.status !== 'valid') throw new Error(`audit bundle status is ${report.status}, not valid`);
  const keys = report.bundle.attestedTenantKeys;
  if (!keys) throw new Error('audit bundle has no verified platform attestation, so its tenant keys are not attested');
  return {
    trustedKeyFingerprints: keys.filter((k) => k.status !== 'REVOKED').map((k) => k.fingerprint),
    organizationId: report.bundle.orgId,
  };
}
