import { deriveProofs, type ProofStatus, type ProofType } from './proofs.js';
import { verifyHttpReceipt, httpTargetKeyFingerprint, httpRequestCommitment, type HttpRequestEnvelope } from './http-receipt.js';
import { jcsCommitment, type JsonValue } from './jcs-canonical.js';
import {
  assertEvidencePrivacyStructure,
  evidencePrivacyReason,
  evidencePrivacyReport,
  type EvidencePrivacyDeclaration,
  type EvidencePrivacyReport,
} from './evidence-privacy.js';
/**
 * Praesidia compliance bundle verifier — pure-function orchestrator.
 *
 * Reads a bundle zip, decompresses each entry, and walks the manifest /
 * row chain / Merkle root / inclusion proof invariants. Returns a
 * structured `VerifyReport` describing exactly which components passed
 * and which failed; the CLI translates that into stdout + an exit code.
 *
 * SECURITY:
 *  - We NEVER trust the bundle's claim about which keys signed which
 *    rows in isolation — every signature is verified against the
 *    bytes in `public-keys.json` keyed by `keyVersion`.
 *  - We NEVER log row payloads. Only counts, names, and the id of the
 *    FIRST offending row in each phase.
 *  - Verification is fully offline; provider-specific online checks are
 *    available only through explicit caller-supplied hooks.
 *
 * INVARIANTS the verifier checks:
 *  1. Manifest signature        — Ed25519 over canonical-JSON of the
 *                                 manifest's signable fields, verified
 *                                 with `publicKeys[manifest.signatureKeyVersion]`.
 *  2. Row signatures            — for each row, canonical-JSON over the
 *                                 11 signable fields (mirrors AGV-030)
 *                                 verified with `publicKeys[row.keyVersion]`.
 *  3. Chain integrity           — each row's `prevRowHash` matches
 *                                 `sha256(prev.canonical || prev.sigBytes)`
 *                                 of its TRUE in-bundle predecessor, found
 *                                 by following the cryptographic links
 *                                 themselves (PROD16 F10) rather than by
 *                                 trusting the bundle's on-disk row order —
 *                                 be-core's exporter orders rows by
 *                                 `(signedAt, id)`, which does not always
 *                                 match the actual `chainSeq` order, so
 *                                 file-order trust produced false chain-break
 *                                 verdicts on honest bundles. The ONE row
 *                                 with no in-bundle predecessor is an opaque
 *                                 anchor into the org's pre-range history
 *                                 (bundles are date-ranged, not
 *                                 genesis-rooted), so it is accepted, not
 *                                 required to be the all-zero genesis
 *                                 (BUGHUNT-SDK-02).
 *  4. Merkle root signatures    — canonical-JSON over
 *                                 `{rootHash, periodStart, periodEnd, rowCount}`
 *                                 verified with `publicKeys[root.keyVersion]`.
 *  5. Inclusion proofs          — `merkleVerify(leaf, proof, rootHash)`
 *                                 where `leaf = canonical(row) || sigBytes`
 *                                 (AGV-033 leaf preimage). Proof rows
 *                                 and exactly one valid proof is required
 *                                 for every exported row. Status markers
 *                                 are diagnostic failures, not proofs.
 *  6. Rekor receipt (optional)  — when not skipped, REAL offline
 *                                 verification (BUGHUNT-SDK-05): the
 *                                 receipt's Signed Entry Timestamp (SET)
 *                                 is verified against the pinned Sigstore
 *                                 Rekor public key; the proof's signed
 *                                 checkpoint authenticates its tree size
 *                                 and root before the inclusion path is walked
 *                                 (see `rekor.ts`). A receipt that is not
 *                                 a genuine, SET-signed, log-included
 *                                 entry fails closed. Skipped only via
 *                                 `--no-rekor` / `noRekor`.
 */

import * as crypto from 'node:crypto';
import { TextDecoder } from 'node:util';

import {
  canonicalJson,
  decodeBase64Strict,
  sha256,
  verifySignature,
  tenantSignedBytes,
  merkleRootEnvelope,
  type BundleSignatureAlgorithm,
  type SignaturePurpose,
  merkleVerify,
  type MerkleProof,
  GENESIS_PREV_ROW_HASH,
} from './crypto.js';
import {
  verifyDecisionDisclosures,
  type DecisionDisclosureSummary,
} from './decision-disclosures.js';
import {
  MAX_ZIP_ARCHIVE_BYTES,
  MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES,
  MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES,
  readZip,
  gunzipChunks,
  type ZipEntry,
  type GzipOutputBudget,
} from './zip.js';
import { verifyRekorReceipt } from './rekor.js';
import { verifyRfc3161Receipt, type Rfc3161RootReport, type Rfc3161Verdict } from './rfc3161.js';
import {
  PLATFORM_PUBLIC_KEY_DER_B64,
  PLATFORM_PUBLIC_KEY_FINGERPRINT,
  isPlatformPubkeyPinned,
} from './platform-pubkey.js';
import type { PlatformTrustAnchor } from './trust-anchor.js';

/** AV-0017 — `platformAttestation.reason` when no trust anchor exists at all; drives top-level `unanchored`. */
const PLATFORM_KEY_NOT_PINNED = 'platform_key_not_pinned';

// ────────────────────────────────────────────────────────────────────────
// Bundle wire types — what `BundleExporterService` (AGV-035) writes.
// ────────────────────────────────────────────────────────────────────────

interface ManifestKeyVersionEntry {
  keyVersion: number;
  publicKey: string;
  // AUDIT-2026-05-14 — Manifest v2 carries lifecycle metadata for
  // every key version it embeds, so an offline verifier can apply the
  // signed-before-revocation rule without re-fetching tenant state.
  // Optional for forward-compat with v1 bundles that pre-date AUDIT-14.
  status?: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  revokedAt?: string | null;
}

interface BundleManifest {
  version: number;
  orgId: string;
  from: string;
  to: string;
  rowCount: number;
  rootCount: number;
  keyVersions: ManifestKeyVersionEntry[];
  generatedAt: string;
  // NX-TAC-02 — Bundles emitted by KMS-substrate tenants carry
  // 'ECDSA_P256_SHA256'. Bundles emitted by the local-aes-gcm
  // substrate continue to carry 'Ed25519'. The verifier dispatches
  // on this field via `verifySignature`.
  signatureAlgorithm: BundleSignatureAlgorithm;
  signature: string;
  signatureKeyVersion: number;
  /**
   * PROD16 §1b / manifest-v3 contract (`PROD16-CONTRACT-manifest-v3.md`) —
   * the chainSeq ceiling this bundle's export snapshot was bounded by, and
   * when that snapshot was taken. Part of the SIGNED preimage: the ceiling
   * defines the bundle's own claimed scope, so leaving it unsigned would
   * make that scope forgeable. A genuine producer emits BOTH fields on
   * every `version: 3` manifest and NEITHER on `version: 1`/`2` — see
   * `verifyManifest`'s version-keyed signable-set selection. Optional here
   * only so this interface can represent all three wire versions; presence
   * is enforced per-version, not left to chance.
   */
  chainSeqCeiling?: number | null;
  chainSeqSnapshotAt?: string | null;
  /**
   * FIX01 F5(b) / manifest-v4 contract
   * (`PROD16-CONTRACT-manifest-v4-checkpoints.md`) — the number of
   * `AuditIntegrityCheckpoint` rows this export includes (in
   * `integrity-checkpoints.ndjson.gz`), i.e. checkpoints whose `asOf` falls
   * inside `[from, to)`. Part of the SIGNED preimage for the same reason
   * `rowCount`/`rootCount` are: an unsigned count could be silently shrunk
   * to suppress the one checkpoint that would reveal a suffix deletion. A
   * genuine producer emits this on EVERY `version: 4` manifest and on NO
   * earlier version — see `verifyManifest`'s version-keyed signable-set
   * selection. Optional here only so this interface can represent all four
   * wire versions; presence is enforced per-version, not left to chance.
   */
  integrityCheckpointCount?: number;
  /**
   * PA-0010 / `PA01-CONTRACT-manifest-v5-actions.md` — count of
   * `protected_action_events` rows this export includes (in
   * `action-events.ndjson.gz`), whose `observedAt` falls inside
   * `[from, to)`. Same anti-suppression rationale as
   * `rowCount`/`integrityCheckpointCount`. Present on every `version: 5`
   * manifest, absent on every earlier version — enforced in
   * `verifyManifest`'s signable-set selection, not left to chance.
   */
  actionEventCount?: number;
  /**
   * PA-0010 — `sha256(canonicalJson(activeCaptureScopeDeclaration))`, hex,
   * lowercase. Makes the org's capture-scope registry itself
   * tamper-evident (ACT-005) — a narrowed scope that silently excludes a
   * whole action class from capture must be a signed, comparable value,
   * not an unsigned side-channel.
   */
  captureScopeDigest?: string;
  /**
   * PA-0010 / corrigendum C4 — count of CLOSED protected actions in
   * `[from, to)` by their CLAIMED evidence grade (D8), plus the org's
   * governance mode at export time. THIS IS A DECLARED FIELD, WRITTEN BY
   * `be` — the grade-C party. The verifier's `evidenceGrade` component
   * (`verifyEvidenceGrade`) independently DERIVES the grade from the
   * evidence actually present in `action-events.ndjson.gz` and flags a
   * declared grade that exceeds the derived one as `invalid` — this field
   * is never trusted at face value. All four keys are always present
   * (`0` for a grade with no actions), never omitted.
   */
  evidenceGradeSummary?: {
    A: number;
    B: number;
    C: number;
    D: number;
    /**
     * Corrigendum C4 — "enforcementMode must be on the record": an
     * observe-mode action must never be countable as enforced. `be`
     * resolves this per-org via `GovernanceFlagService.getModeForOrg`;
     * any mode other than `'enforce'` reads as `'observe'`.
     */
    enforcementMode: 'observe' | 'enforce';
  };
  /**
   * AV-0013 / be BE-1615 — the org's evidence privacy mode timeline over
   * `[from, to)`. Signed; present on every `version: 6` manifest, absent on
   * every earlier one (enforced in `verifyManifest`). Format:
   * `assertEvidencePrivacyStructure`.
   */
  evidencePrivacy?: EvidencePrivacyDeclaration;
  /**
   * AV-0018 / ADR-0004 — v7 only, both signed. `signatureFormat` is the
   * format of `signature` below (1 = untagged, 2 = purpose-tagged).
   * `signatureFormatCutoverAt` is the instant of the org's first format-2
   * signature (null = none yet): every artefact of this bundle whose own
   * signed timestamp is at or after it must carry a format-2 signature.
   */
  signatureFormat?: number;
  signatureFormatCutoverAt?: string | null;
}

/**
 * PA-0010 / `PA01-CONTRACT-manifest-v5-actions.md` — one row per
 * `protected_action_events` record in `[from, to)`, ordered by
 * `(actionId, actionSeq)`. Mirrors `be`'s `serializeActionEvent` wire
 * shape exactly (`bundle-exporter.service.ts`).
 *
 * SEC-PA01-DISCOVERED-01 (found in an earlier pass, now CLOSED) — `be`
 * commit `e9e39b88`'s `serializeActionEvent` originally did NOT ship six
 * fields that `protected-action-canonical.helper.ts`'s
 * `SignableProtectedActionEventRow` requires to reconstruct the exact
 * signed preimage: `timeSource`, `permitNonce` (the top-level entity
 * column — distinct from `payload.permitNonce`, which IS present),
 * `edgeVersion`, `adapterVersion`, `externalReceiptRef`,
 * `artifactStorageRef`. That was a genuine PRODUCER gap (documented in
 * `PA01-CONTRACT-manifest-v5-actions.md`'s amended contract; the backlog
 * ticket originally filed for it at discovery time has since been
 * renumbered and repurposed for an unrelated SDK issue, so it is
 * intentionally not cited here).
 *
 * **Fixed** by `be` commit `3eb81950` ("ship the 6 missing action-event
 * preimage fields + repoint verifier round trip at v5, PA-0027,
 * PA-0031") — `bundle-exporter.service.ts:2040-2051` now emits all six
 * fields, plus `organizationId`/`issuerType`/`dispatched`. Tracked to
 * closure as `.claude/backlog/PA-0027.md` and `.claude/backlog/PA-0031.md`
 * (both `state: done`). This verifier can independently verify
 * action-event signatures against a real `be`-produced v5 bundle today.
 * The fields below remain declared REQUIRED to match the contract — no
 * behavior change here — so a bundle missing any of them still fails
 * closed as a bundle-format error (`assertActionEventsStructure`),
 * exactly like every other missing required field in this file. This
 * remains intentional, fail-closed behavior: an event whose exact
 * signed bytes cannot be reconstructed must never be silently accepted
 * as "probably fine."
 */
interface BundleActionEvent {
  actionId: string;
  /** Wire `number` (be's `toWireActionSeq`, lossless-or-throw); signable preimage uses the bigint-as-string form — see {@link signableActionEvent}. */
  actionSeq: number;
  eventType: string;
  /** Wire `number` (be's plain `Number(...)` cast); signable preimage uses the decimal-string form (D9) — see {@link signableActionEvent}. */
  schemaVersion: number;
  observedAt: string;
  receivedAt: string;
  /** Wire name for the entity's `issuerId` column (contract-pinned rename). */
  issuer: string;
  trustDomain: string;
  payload: Record<string, unknown> | null;
  payloadCommitment: string | null;
  /** Hex, 64 chars. Genesis (first event of an actionId) = 64 hex zeros. */
  prevEventCommitment: string;
  // Signature metadata — NOT part of the signed preimage itself (see
  // {@link signableActionEvent}, which omits all four of these). CD-0002
  // audit note: an earlier version of this comment mis-labeled
  // `organizationId`/`issuerType`/`dispatched`/`producerVersion` below as
  // "superset, not signed" — they DO enter the signed preimage
  // (`signableActionEvent` includes all of them); only the four fields
  // immediately above/below this comment (signature/signatureAlgorithm/
  // keyVersion/eventCommitment) are genuinely outside it, because they
  // describe or derive from the signature rather than being covered by it.
  signature: string;
  signatureAlgorithm: BundleSignatureAlgorithm;
  /** AV-0018 — 1 (untagged) or 2 (purpose-tagged); absent = 1. See {@link signatureFormatRejection}. */
  signatureFormat?: number;
  keyVersion: number;
  // Part of the signed preimage (see {@link signableActionEvent}) —
  // `be` already ships these (bundle-exporter.service.ts
  // `serializeActionEvent`):
  organizationId: string;
  issuerType: string;
  dispatched: boolean;
  /** This event's own commitment — derived from, not part of, the signed preimage. Independently RECOMPUTED and compared, never trusted — see {@link verifyActionEventChain}. */
  eventCommitment: string;
  /** Part of the signed preimage (see {@link signableActionEvent}). */
  producerVersion: string;
  // Required for exact signable-preimage reconstruction (see the
  // SEC-PA01-DISCOVERED-01 note above) — shipped by `be` commit
  // `3eb81950` (PA-0027, PA-0031, both state: done).
  timeSource: string;
  permitNonce: string | null;
  edgeVersion: string | null;
  adapterVersion: string | null;
  externalReceiptRef: string | null;
  artifactStorageRef: string | null;
}

/**
 * FIX01 F5(b) / manifest-v4 contract
 * (`PROD16-CONTRACT-manifest-v4-checkpoints.md`) — one row per org per
 * hourly tick from `AuditIntegrityCheckpointService` (`be`'s producer,
 * `audit-integrity-checkpoint.entity.ts`). Append-only, NOT
 * idempotency-keyed to a period, so duplicate/near-duplicate content
 * across different `id`s is expected and not itself suspicious.
 *
 * Each checkpoint is signed INDEPENDENTLY of the manifest and of every
 * other checkpoint — `signature` covers exactly
 * `canonicalJson({organizationId, chainHeadHash, cumulativeRowCount, asOf})`
 * under the org's active tenant signing key at `keyVersion`, the SAME
 * substrate boundary as `audit_logs.signature` / `audit_merkle_roots
 * .signature`, so a holder of DB write access but not the signing key
 * cannot fabricate or alter a checkpoint's claimed content.
 */
interface BundleIntegrityCheckpoint {
  id: string;
  organizationId: string;
  /** Base64 sha256 — same shape/derivation as `BundleRow.prevRowHash`. */
  chainHeadHash: string;
  /** Bigint-as-string (never re-parsed as a number — see the entity doc). */
  cumulativeRowCount: string;
  /** ISO instant the snapshot was taken. */
  asOf: string;
  signature: string;
  signatureAlgorithm: BundleSignatureAlgorithm;
  /** AV-0018 — 1 (untagged) or 2 (purpose-tagged); absent = 1. See {@link signatureFormatRejection}. */
  signatureFormat?: number;
  keyVersion: number;
  /** Unused by verification; present for wire completeness. */
  createdAt?: string;
}

/**
 * AUDIT-2026-05-14 — Per-key entry as written in `public-keys.json`.
 *
 * Manifest v1 wrote `{ [keyVersion]: base64 }` (raw string per entry).
 * Manifest v2 writes `{ [keyVersion]: { publicKey, status, revokedAt } }`
 * so the verifier can enforce the signed-before-revocation rule for
 * REVOKED keys WITHOUT needing live tenant state. The parser accepts
 * both shapes — strings are coerced to ACTIVE entries.
 */
interface PublicKeyRecord {
  publicKey: Uint8Array;
  status: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  revokedAt: Date | null;
}

interface BundleRow {
  id: string;
  organizationId: string;
  action: string;
  actorId: string | null;
  actorType: string;
  resourceType: string | null;
  resourceId: string | null;
  teamId: string | null;
  agentId: string | null;
  summary: string | null;
  details: Record<string, unknown> | null;
  createdAt: string;
  signature: string;
  keyVersion: number;
  signedAt: string | null;
  prevRowHash: string;
  /**
   * PROD16 F6 (be-compliance) — Signed only for rows produced at/after the
   * be-side `IP_ADDRESS_SIGNABLE_CUTOVER_AT` activation. Optional/absent
   * on the wire for every row signed before that cutover (and for all
   * pre-AUDIT-14 bundles). See {@link signableRow} — the verifier includes
   * this key in the canonical preimage IFF the wire row actually carries
   * it, mirroring `audit-canonical.helper.ts`'s own conditional shape
   * without needing to know the cutover instant.
   */
  ipAddress?: string | null;
  /**
   * SCAN-AV-01 (be-audit N1) — Signed IN PLACE OF `summary`/`details` (not
   * additive alongside them, unlike `ipAddress` above) for rows produced
   * at/after the be-side `AUDIT_DETAILS_COMMITMENT_CUTOVER_AT` activation.
   * Optional/absent on the wire for every row signed before that cutover
   * (and for all pre-PROD16-F1 bundles). See {@link signableRow} — the
   * verifier includes this key in the canonical preimage IFF the wire row
   * actually carries it, mirroring `audit-canonical.helper.ts`'s own
   * conditional shape (`buildSignableRow`'s `detailsCommitment`/
   * `summary`+`details` branch) without needing to know the cutover
   * instant.
   */
  detailsCommitment?: string | null;
  /**
   * AUDIT-2026-05-01 — Per-row signature algorithm tag. Optional so
   * pre-AUDIT-01 bundles (which only carried `manifest.signatureAlgorithm`)
   * continue to verify; in that case the verifier falls back to the
   * manifest's tag and ultimately to `'Ed25519'`. Bundles produced
   * after AUDIT-01 ship the tag on every row so a tenant whose history
   * mixes substrates (Ed25519 pre-KMS → ECDSA-P256 post-KMS) verifies
   * row-by-row under the correct primitive.
   */
  signatureAlgorithm?: BundleSignatureAlgorithm;
  /** AV-0018 — 1 (untagged) or 2 (purpose-tagged); absent = 1. See {@link signatureFormatRejection}. */
  signatureFormat?: number;
  /**
   * DRIFT-0004 — producer-only sort aid (`AuditLog.chainSeq`, monotonic
   * per-org chain-sequence number). NOT part of the signed preimage and
   * NEVER read or trusted by verification — chain continuity is proven
   * by `prevRowHash` walking, not by this field. Declared here only so
   * the wire contract is explicit instead of silently dropped by
   * `JSON.parse(...) as BundleRow`, and so a future field cannot collide
   * with this name unnoticed. Optional because bundles produced before
   * be started emitting it carry no such key at all.
   */
  chainSeq?: number | null;
}

interface BundleRoot {
  id: string;
  organizationId: string;
  periodStart: string;
  periodEnd: string;
  rowCount: number;
  rootHash: string;
  signature: string;
  keyVersion: number;
  signedAt: string;
  anchoredAt: string | null;
  /** Legacy single-slot Rekor receipt — populated by pre-AUDIT-09 producers. */
  anchorReceipt: string | null;
  /**
   * AUDIT-2026-05-09 — Multi-anchor receipt log. Each entry is one
   * provider's independent receipt for THIS root. The verifier walks
   * each entry, dispatches on `provider`, and reports per-provider
   * success/failure in `report.rekor`. Optional for back-compat with
   * bundles emitted before the multi-anchor migration.
   */
  anchorReceipts?: Array<{
    provider: string;
    receipt: string;
    anchoredAt: string;
  }>;
  /**
   * AUDIT-2026-05-01 — Per-root signature algorithm. AUDIT-02 already
   * wired the writer to emit this on every root; the verifier now
   * dispatches on the per-root tag (rather than the manifest-level one)
   * so a bundle with mixed-substrate roots verifies correctly.
   * Optional for back-compat with pre-AUDIT-02 bundles.
   */
  signatureAlgorithm?: BundleSignatureAlgorithm;
  /** AV-0018 — 1 (untagged) or 2 (purpose-tagged); absent = 1. See {@link signatureFormatRejection}. */
  signatureFormat?: number;
  /**
   * AV-0016 — this root supersedes the root with this `id`, which must ship in
   * the same bundle with the same period and a LOWER `rowCount`. Both fields
   * are present together or not at all. See {@link resolveSupersessions}.
   */
  supersedesRootId?: string;
  /**
   * AV-0016 — signature, under this root's own `keyVersion`/algorithm, over
   * {@link supersessionSignable}. Binds the link to the superseded root's hash
   * so a link cannot be added, removed or re-pointed without the org key.
   */
  supersessionSignature?: string;
  /** AV-0018 — format of `supersessionSignature`; absent = 1. */
  supersessionSignatureFormat?: number;
}

/** AV-0016 — `version` field of the signed supersession envelope. */
export const ROOT_SUPERSESSION_VERSION = 'praesidia.root-supersession.v1';

/**
 * AV-0016 — the bytes `supersessionSignature` signs. A separate envelope, so
 * the root signature (`{rootHash, periodStart, periodEnd, rowCount}`) stays
 * byte-compatible with every existing bundle.
 */
function supersessionSignable(root: BundleRoot, supersededRootHash: string): Buffer {
  return canonicalJson({
    version: ROOT_SUPERSESSION_VERSION,
    supersedes: supersededRootHash,
    rootHash: root.rootHash,
    periodStart: root.periodStart,
    periodEnd: root.periodEnd,
    rowCount: root.rowCount,
  });
}

/**
 * AV-2754 (BE-2979) — the bytes a seal's link signature covers (format 1;
 * format 2 prefixes `praesidia:retention-seal-link:v2\n`): the seal's period,
 * row count and root plus its two boundary links, under a `version` key that
 * keeps them distinct from every other envelope. Wire strings are used
 * as-is, like the 6-field seal envelope. Exported for the golden-vector test
 * only; not re-exported by `index.ts`.
 */
export function retentionSealLinkMessage(seal: {
  organizationId: string;
  periodStart: string;
  periodEnd: string;
  rowCount: string;
  rootHash: string;
  chainLinkIn: string;
  chainLinkOut: string;
}): Buffer {
  return canonicalJson({
    version: 'praesidia.retention-seal-link.v1',
    organizationId: seal.organizationId,
    periodStart: seal.periodStart,
    periodEnd: seal.periodEnd,
    rowCount: seal.rowCount,
    rootHash: seal.rootHash,
    chainLinkIn: seal.chainLinkIn,
    chainLinkOut: seal.chainLinkOut,
  });
}

/**
 * AV-0016 — valid supersession links (superseded root id → superseding root)
 * plus one error per invalid link. A link is valid when its target is another
 * root in this bundle with the same period, a strictly lower `rowCount` (so
 * chains are acyclic) and no other successor (so chains are linear). An
 * invalid link supersedes nothing: both roots then face every normal check.
 * The link's signature is checked in `verifyRootSignatures`.
 */
interface Supersessions {
  successorOf: Map<string, BundleRoot>;
  errors: Array<{ rootId: string; reason: string }>;
}

function resolveSupersessions(roots: BundleRoot[]): Supersessions {
  const byId = new Map(roots.map((r) => [r.id, r]));
  const successorOf = new Map<string, BundleRoot>();
  const errors: Supersessions['errors'] = [];
  for (const root of roots) {
    if (root.supersedesRootId === undefined) continue;
    const old = byId.get(root.supersedesRootId);
    const why =
      !old || old === root
        ? `supersedes root ${root.supersedesRootId}, which is not in this bundle`
        : old.periodStart !== root.periodStart || old.periodEnd !== root.periodEnd
          ? `supersedes root ${old.id} with a different period`
          : old.rowCount >= root.rowCount
            ? `has rowCount ${root.rowCount}, not greater than superseded root ${old.id}'s rowCount ${old.rowCount}`
            : successorOf.has(old.id)
              ? `supersedes root ${old.id}, which is already superseded by root ${successorOf.get(old.id)!.id}`
              : null;
    if (why) errors.push({ rootId: root.id, reason: `root ${root.id} ${why}` });
    else successorOf.set(old!.id, root);
  }
  return { successorOf, errors };
}

/**
 * FIX01 (audit-verifier2) / `FIX01-FIXED-be4.md`'s "FOR AUDIT-VERIFIER" spec
 * — one row per `AuditRetentionSeal` whose `[periodStart, periodEnd)`
 * overlaps the bundle's `[from, to)` OR whose `deletedAt` falls inside it.
 *
 * NOT part of the signed manifest preimage (no `sealedPurgeCount` field
 * exists, deliberately — see the "Why this entry is unsigned" reasoning in
 * the spec, reproduced on `verifySealedPurgeAuthenticity` below). Evidence
 * from this file is used ONLY to downgrade an otherwise-failing
 * `rootCoverage` / `integrityCheckpoints` finding to an explained pass —
 * it can never cause a new failure, and an attacker without the tenant
 * signing key cannot fabricate an entry that survives the authenticity
 * gate, so treating this file as wholly optional/unversioned (present or
 * absent, parsed either way, never gated on `manifest.version`) cannot
 * weaken any existing check.
 */
interface BundleSealedPurge {
  id: string;
  organizationId: string;
  /** Inclusive start of the purged period. ISO 8601. */
  periodStart: string;
  /** Exclusive end of the purged period. ISO 8601. */
  periodEnd: string;
  /** Bigint-as-string on the wire. Rows the seal replaces. */
  rowCount: string;
  /** Base64 sha256 — the AuditMerkleRoot.rootHash that covered this period before the purge. */
  rootHash: string;
  rekorReceipt: Record<string, unknown> | null;
  /**
   * Base64 signature over canonicalJson({organizationId, periodStart,
   * periodEnd, rowCount, rootHash, rekorReceipt}) — the seal's OWN
   * envelope. Current producers sign `rowCount` as the same decimal string
   * carried on the wire. A legacy producer signed the safe-integer numeric
   * form before persisting/exporting the string; the verifier accepts that
   * one historical representation as a compatibility fallback. `null` only
   * for legacy backfilled rows that predate the signed-seal path — treated
   * as UNVERIFIABLE, never as evidence of legitimacy.
   */
  signature: string | null;
  signingKeyVersion: number | null;
  signatureAlgorithm: BundleSignatureAlgorithm | null;
  /** AV-0018 — 1 (untagged) or 2 (purpose-tagged); absent = 1. See {@link signatureFormatRejection}. */
  signatureFormat?: number;
  /** Wall-clock instant the purge committed. ISO 8601. */
  deletedAt: string;
  /** users.id of the operator who executed the purge. */
  deletedBy: string;
  /** approval_requests.id of the consumed two-person-approval. */
  approvalId: string;
  /**
   * AV-2754 (BE-2979) — the purged run's boundary chain links, emitted only
   * on seals that signed them, all five together (`chainLinkSignatureFormat`
   * only when 2). `chainLinkIn` = the first purged leaf's `prevRowHash`
   * (= link(P)); `chainLinkOut` = link(last purged leaf) (= the survivor's
   * `prevRowHash`). Base64 of 32 bytes. The second signature covers
   * {@link retentionSealLinkMessage} under purpose `retention-seal-link`;
   * see `verifySealLinkAuthenticity`. Absent on every older seal.
   */
  chainLinkIn?: string;
  chainLinkOut?: string;
  chainLinkSignature?: string;
  chainLinkSigningKeyVersion?: number;
  chainLinkSignatureAlgorithm?: BundleSignatureAlgorithm;
  chainLinkSignatureFormat?: number;
}

interface BundleProofEntry {
  rowId: string;
  status?: string;
  /** Base64 sibling hashes from leaf level upward. */
  proof?: string[];
  /** Leaf index inside the root's leaf list. */
  index?: number;
  /** Base64 root hash this proof terminates at. */
  rootHash?: string;
}

// ────────────────────────────────────────────────────────────────────────
// Public report
// ────────────────────────────────────────────────────────────────────────

/**
 * PA-0009 (`PA01-DECISIONS.md` D15) — four-state component verdict.
 *
 * `ok: boolean` alone cannot express "this component does not apply to
 * this bundle" (e.g. no target-acknowledgment evidence because the org is
 * evidence-grade-D, SDK-only, by design) or "there is not enough evidence
 * present to decide" (distinct from "the evidence present says invalid").
 * Collapsing either of those into `ok: false` is a lie in the other
 * direction: a bundle that legitimately has nothing to check for a given
 * component would drag the whole verdict down even though nothing is
 * wrong.
 *
 * - `valid`       — checked, and every check passed.
 * - `invalid`     — checked, and at least one check failed. The only
 *                   status that should read as "this bundle is suspect."
 * - `incomplete`  — evidence present is insufficient to decide either way
 *                   (distinct from `unsupported`: the component DOES apply,
 *                   but the bundle doesn't carry enough to confirm it).
 * - `unsupported` — this component does not apply to this bundle at all
 *                   (e.g. a manifest version below the one that introduces
 *                   it, or a capture scope that never produces this
 *                   evidence class). Never counted as a failure.
 * - `not_present` — AV-0008: the component applies, but the bundle carries
 *                   none of its evidence (ok with 0 checked), e.g. a v5
 *                   bundle with no TARGET_ACKNOWLEDGED events. Never
 *                   rendered as VALID. Mandatory components (manifest,
 *                   completeness, keyBinding) never take this status.
 *
 * As of this change none of the 11 pre-existing components ever produce
 * `incomplete` or `unsupported` — their pass/fail semantics are preserved
 * byte-for-byte (`status` is mechanically derived from the existing `ok`
 * via `withStatus`, see below). The four-state type exists so the action
 * components landing in PA-0010 (permit binding, target ack, evidence
 * grade, etc. — `PA01-RESEARCH-proof.md` §4/§6) are built against the real
 * shape from day one instead of being migrated twice.
 */
export type ComponentStatus =
  | 'valid'
  | 'invalid'
  | 'incomplete'
  | 'unsupported'
  | 'not_present';

export interface ComponentResult {
  /**
   * Kept for backward compatibility with existing callers of the library
   * (`verifyBundle`/`VerifyReport` have no importers outside this package
   * as of PA-0009, confirmed by repo-wide grep, but the field is public
   * API of a published package). DERIVED: `ok === (status === 'valid')`,
   * always — never set independently of `status`.
   */
  ok: boolean;
  status: ComponentStatus;
  checked: number;
  failed: number;
  /** Identifier of the FIRST offender, when applicable. */
  firstFailure?: string;
  /** Human-readable reason, when applicable. */
  reason?: string;
  /**
   * FIX01 (audit-verifier2) — `BE-0003` / integrity-checkpoint sealed-purge
   * cross-check. Present only on `rootCoverage` / `integrityCheckpoints`
   * when a finding that would otherwise have failed closed was downgraded
   * to a pass because a VERIFIED (independently signature-checked)
   * `AuditRetentionSeal` bundle entry exactly reconciles it. Each entry
   * names the seal(s) responsible so an auditor can distinguish "explained
   * by a legitimate purge" from either "clean" (component ok, no entries)
   * or "tampering" (component not ok). Never present when the component
   * would have passed anyway — this is a downgrade record, not a summary.
   */
  sealExemptions?: string[];
  /**
   * AV-0016 — present only on `rootCoverage` when the bundle ships superseded
   * roots: one line per valid link naming BOTH roots (id, hash, rowCount,
   * anchor-receipt count). The superseded root keeps its own signature,
   * inclusion-proof and anchor checks; it is exempt only from the
   * rows-in-period count, which its successor carries.
   */
  supersessions?: string[];
}

/**
 * The shape every individual `verifyXxx()` function still returns —
 * `ComponentResult` minus `status`. Kept distinct from `ComponentResult`
 * itself so the compiler enforces that `status` is ALWAYS attached via
 * `withStatus` at the `verifyBundle` call site, never hand-set (or
 * forgotten) inside an individual component verifier.
 */
type RawComponentResult = Omit<ComponentResult, 'status'>;

/**
 * PA-0009 — attach a `status` to a `ComponentResult` produced by one of the
 * pre-existing (boolean-only) component verifiers, deriving `ok` FROM
 * `status` rather than the other way around, so a future call site that
 * legitimately needs `incomplete`/`unsupported` can pass it explicitly
 * without a second migration. Every one of today's 11 components calls
 * this with no explicit `status` — i.e. their pass/fail behavior is
 * unchanged, byte-for-byte, by this function's existence.
 */
function withStatus(
  result: RawComponentResult,
  status?: ComponentStatus,
): ComponentResult {
  const resolved: ComponentStatus = status ?? (result.ok ? 'valid' : 'invalid');
  return { ...result, status: resolved, ok: resolved === 'valid' };
}

/**
 * AV-0008 — `withStatus` for an optional-evidence component: a pass with
 * nothing checked is `not_present`, never `valid`. Only a would-be `valid`
 * is rewritten; `invalid`/`incomplete`/`unsupported` stand as they are.
 */
function withEvidenceStatus(
  result: RawComponentResult,
  status?: ComponentStatus,
): ComponentResult {
  const r = withStatus(result, status);
  return r.status === 'valid' && r.checked === 0
    ? { ...r, status: 'not_present', ok: false }
    : r;
}

/**
 * Top-level reduction (`PA01-DECISIONS.md` D15) — NOT "any component
 * failed". `invalid` if any component is invalid; else `incomplete` if any
 * is incomplete; else `valid`. `unsupported` and `not_present` components
 * are excluded from the reduction — they never drag the overall verdict
 * down. AV-0008: but when NO evidence component is `valid` (a zero-row
 * bundle), there is nothing the verdict vouches for, so it is `incomplete`.
 */
function reduceStatus(
  results: readonly ComponentResult[],
  evidence: readonly ComponentResult[],
): Exclude<ComponentStatus, 'unsupported' | 'not_present'> {
  if (results.some((r) => r.status === 'invalid')) return 'invalid';
  if (results.some((r) => r.status === 'incomplete')) return 'incomplete';
  if (!evidence.some((r) => r.status === 'valid')) return 'incomplete';
  return 'valid';
}

/** AV-0002 — one entry of `VerifyReport.bundle.attestedTenantKeys`. */
export interface AttestedTenantKey {
  keyVersion: number;
  /** Lifecycle as of `attestedAt`, not today. */
  status: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  /** Lowercase sha256 hex of the decoded tenant public-key bytes. */
  fingerprint: string;
  /** The attestation's platform-signed `issuedAt`: the only authenticated "as of" for `status`. */
  attestedAt: string;
}

export interface VerifyReport {
  ok: boolean;
  /**
   * PA-0009 — real reduction over every component's `status`, see
   * `reduceStatus`. Never `unsupported` or `not_present` at the top level
   * (D15, AV-0008) — those statuses only ever appear per-component.
   */
  status: Exclude<ComponentStatus, 'unsupported' | 'not_present'> | 'unanchored';
  /**
   * AV-0010 — the six auditor-facing proofs, each reduced from named
   * components (`proofs.ts` `PROOF_COMPONENTS`, docs/ARCHITECTURE.md). Every
   * component maps to exactly one proof: `status: 'invalid'` iff some proof
   * is `fail`.
   */
  proofs: Record<ProofType, ProofStatus>;
  manifest: ComponentResult;
  rowSignatures: ComponentResult;
  chain: ComponentResult;
  rootSignatures: ComponentResult;
  /** AV-0032 — `incomplete` when only unrooted-tail `not_yet_rooted` stubs lack a proof. */
  inclusionProofs: ComponentResult;
  rekor: ComponentResult;
  /** AV-0019 — per-root RFC 3161 rows; a `failed` token also fails `rekor`. */
  rfc3161: Rfc3161RootReport[];
  /**
   * AUDIT-2026-05-30 — Platform key-binding attestation.
   *
   * The bundle's `platform-attestation.json` is a SEPARATE signature
   * (under a platform-wide key, NOT a tenant key) over the
   * `(orgId, [keyVersion, fingerprint, status, revokedAt, issuedAt])`
   * tuple. The verifier checks that signature against a pubkey pinned
   * into this CLI (`platform-pubkey.ts`) so an auditor knows the
   * platform itself — not just the tenant — vouched for the binding.
   *
   * Missing attestation or a missing platform key fails closed. Legacy
   * bundles may be accepted only through the explicit
   * `allowLegacyUnattested` option.
   */
  platformAttestation: ComponentResult;
  /**
   * BUG-AUDIT-01 — Bundle completeness. `manifest.rowCount` and
   * `manifest.rootCount` are BOTH covered by the manifest signature
   * (they sit in the manifest signable set). The chain / proof checks
   * only validate the rows that are PRESENT — an attacker who truncates
   * the trailing rows + their proofs leaves a still-chaining prefix that
   * otherwise verifies OK. This component fails closed when the number
   * of rows / roots actually present disagrees with the SIGNED counts,
   * closing the truncation bypass.
   */
  completeness: ComponentResult;
  /**
   * BUG-AUDIT-03 — Verification-key binding. Every signature is checked
   * against the bytes in the UNSIGNED `public-keys.json`, while the
   * SIGNED `manifest.keyVersions[]` (covered by the manifest signature)
   * was only used self-referentially. This component cross-checks each
   * key in `public-keys.json` byte-for-byte against the same-version
   * entry in `manifest.keyVersions`, failing closed when a key used for
   * verification is not byte-present in the signed set. It provides a
   * tamper-evidence layer independent of the OPTIONAL platform
   * attestation (which stays warn-but-proceed when absent / placeholder).
   */
  keyBinding: ComponentResult;
  /**
   * PROD16 (be-compliance F5 / audit-verifier's half of the same finding).
   *
   * `verifyChain` only asserts links between rows that are PRESENT in the
   * bundle — a back-linked chain has no forward pointer, so deleting a
   * TRAILING suffix of an org's rows (with no successor left in the
   * bundle to notice a broken link) is invisible to it. `verifyInclusionProofs`
   * only proves that every row it IS given proves into its root — Merkle
   * proofs are existence proofs, not absence proofs. Neither catches "a
   * root's SIGNED `rowCount` says N rows existed in this period, and the
   * bundle now contains fewer than N of them."
   *
   * This component binds each root's signed `rowCount` to how many of the
   * bundle's own rows/proof-entries actually fall inside that root's
   * period, for every period fully contained in the bundle's declared
   * `[from, to)` range (boundary periods that only partially overlap the
   * range are exempted — a genuine ranged export legitimately ships fewer
   * rows for those, since rows outside `[from, to)` are never exported).
   *
   * FIX01 (audit-verifier2) / `BE-0003` — a shrinkage this component would
   * otherwise report as a hard failure is downgraded to a pass (recorded
   * in `sealExemptions`, not silently absorbed) when a VERIFIED entry in
   * `sealed-purges.ndjson.gz` names the exact same `(periodStart,
   * periodEnd, rootHash)` as the affected root — i.e. the tenant's own
   * signature attests that period was legitimately, two-person-approval
   * -gated purged via `AuditRetentionSealService.purgeWithSeal`, not
   * silently truncated. A shrinkage with no matching VERIFIED seal keeps
   * failing exactly as before this change: this is strictly a narrowing of
   * the failure surface, never a widening (see
   * `verifySealedPurgeAuthenticity`'s doc comment for why an unverified —
   * missing signature, unknown key, or REVOKED key — seal entry can never
   * be used for this, and why that is sufficient even though the entry
   * itself sits outside the signed manifest preimage).
   */
  rootCoverage: ComponentResult;
  /**
   * FIX01 F5(b) — periodic signed integrity checkpoints
   * (`PROD16-CONTRACT-manifest-v4-checkpoints.md`).
   *
   * `rootCoverage` only binds a root's committed row count once that root
   * exists and its FULL period is inside the bundle's declared range — the
   * newest un-rooted tail and any boundary root have no independent size
   * commitment there. Checkpoints close PART of that gap for `version: 4`+
   * bundles:
   *
   *   1. Every checkpoint's own signature is verified independently (same
   *      REVOKED-key-rejection rule as rows/roots) — an attacker with only
   *      DB write access, not the tenant signing key, cannot fabricate or
   *      alter a checkpoint's claimed content.
   *   2. `cumulativeRowCount` is checked for monotonic non-decrease across
   *      checkpoints in `asOf` order.
   *   3. Each checkpoint's `chainHeadHash` is independently recomputed from
   *      the bundle's OWN rows (restricted to rows signed at/before that
   *      checkpoint's `asOf`) and compared — this is checked for EVERY
   *      checkpoint, not just the latest, which subsumes both the
   *      "reconstruct the latest head" and "walk an earlier head backward"
   *      halves of the recommended algorithm into one uniform check. A
   *      checkpoint whose `asOf` predates every bundled row (a dormant org,
   *      or a historical ranged export whose window ends before that
   *      instant) is a legitimate, NOT-asserted case — see the component's
   *      own doc comment on `verifyIntegrityCheckpoints`.
   *
   * PARTIALLY-CLOSED RESIDUAL (FIX01, audit-verifier2) —
   * `AuditRetentionSealService.purgeWithSeal` is a real, already-shipped
   * mechanism that legitimately hard-deletes signed `audit_logs` rows
   * (GDPR-driven retention, feature-flagged, two-person approval-gated,
   * off by default). A bundle spanning such a purge legitimately shows a
   * `cumulativeRowCount` decrease and/or an unreachable earlier
   * `chainHeadHash` between two checkpoints straddling the purge. When
   * `sealed-purges.ndjson.gz` carries VERIFIED entries whose `deletedAt`
   * falls in the affected checkpoint window and whose summed `rowCount`
   * accounts for the observed decrease, this is now downgraded to a pass
   * (recorded in `sealExemptions`, listing every contributing seal). A
   * window with NO verified seal evidence at all, or whose seals do not
   * account for the full decrease, still fails closed exactly as before —
   * this is a narrowing of the failure surface, never a widening. See
   * `verifySealedPurgeAuthenticity` / `verifyIntegrityCheckpoints` for the
   * exact
   * reconciliation rule, including why an empty seal window is NEVER
   * treated as reconciling (an arithmetic coincidence is not evidence).
   */
  integrityCheckpoints: ComponentResult;
  /**
   * PA-0010 (`PA01-CONTRACT-manifest-v5-actions.md`, `PA01-DECISIONS.md`
   * D7/D9) — per-`actionId` `actionSeq` monotonicity (1-based, gapless,
   * mirroring the DB trigger) + `prevEventCommitment` hash-chain walk,
   * PLUS the per-event signature verification the chain-link recomputation
   * depends on (mirrors `chain` + `rowSignatures` combined, since no
   * separate top-level field exists for action-event signatures — see
   * `PA01-CONTRACT-manifest-v5-actions.md`'s component list). The FIRST
   * event present for a given `actionId` is accepted as an opaque
   * out-of-range anchor (mirrors BUGHUNT-SDK-02) UNLESS its `actionSeq` is
   * `1`, in which case its `prevEventCommitment` MUST equal the genesis
   * value. `unsupported` on `manifest.version < 5`.
   */
  actionEventChain: ComponentResult;
  /**
   * PA-0010 — binds `PERMIT_ISSUED`/`PERMIT_CONSUMED` within one
   * `actionId`'s stream (issued permit id, the consumed event's signed
   * top-level `permitNonce`, its payload mirror, and request commitment all
   * agree). It asserts NO two `PERMIT_CONSUMED` rows in the whole bundle
   * reuse the signed top-level nonce — including two rows under the same
   * actionId, exactly matching the database unique index — and no two
   * distinct actions reuse a non-null destination-idempotency commitment.
   * `unsupported` on `manifest.version < 5`.
   */
  permitBinding: ComponentResult;
  /**
   * PA-0010 (D2) — every `DISPATCH_ATTEMPTED.payload.requestCommitment`
   * must be a well-formed `sha256` hex digest and, when the same
   * `actionId` also carries a `PERMIT_CONSUMED` event, the two commitments
   * must be byte-identical — a mismatch is exactly the TOCTOU
   * request-substitution threat-model row #2 targets.
   * `unsupported` on `manifest.version < 5`.
   */
  requestBinding: ComponentResult;
  /**
   * PA-0010 (D9) — every `DISPATCH_ATTEMPTED` event must carry
   * `dispatched: true`; a POST-dispatch closure (`SUCCEEDED`,
   * `FAILED_NO_EFFECT`, `PARTIAL`, `REVERSED`, `TARGET_REJECTED`,
   * `OUTCOME_UNKNOWN`) requires at least one such event in the same
   * `actionId`'s stream, and a PRE-dispatch closure (`DENIED`, `EXPIRED`,
   * `CANCELLED_BEFORE_DISPATCH`) must never have one. `unsupported` on
   * `manifest.version < 5`.
   */
  dispatchIntegrity: ComponentResult;
  /**
   * PA-0010 (D8) — independently re-checks EVERY `TARGET_ACKNOWLEDGED`
   * event's structural grade consistency (mirrors `be`'s
   * `assertGradeConsistency`, re-derived here rather than trusted): grade
   * `A` requires a non-empty `targetSignature`/`signatureAlgorithm`, grade
   * `B` requires a non-empty `edgeAttestation` and
   * `destinationAuthenticated: true`. `status: 'incomplete'` when the
   * event's `payload` is legitimately redacted (`payload: null` with a
   * present `payloadCommitment`) rather than a hard failure — threat-model
   * row #10. `unsupported` on `manifest.version < 5`.
   */
  targetAck: ComponentResult;
  /**
   * PA-0010 — every `CALLER_RESULT_OBSERVED` event's `payload.success`
   * must be a boolean and, when present, `payload.resultCommitment` a
   * well-formed `sha256` hex digest (mirrors `computeResultCommitment`'s
   * output shape). Same redaction `incomplete` handling as `targetAck`.
   * PA-0033 — when present, `payload.outcomeClass` must be one of
   * `completed_success` / `completed_with_error` / `no_response_received`
   * and consistent with `payload.success`; `outcomeClass` is OPTIONAL here
   * (structurally) but `closureLegality` treats its absence as ambiguous,
   * never as positive evidence — see that component's doc comment.
   * `unsupported` on `manifest.version < 5`.
   */
  callerResult: ComponentResult;
  /**
   * PA-0010 (D7, corrigendum C4's sibling concern) — THE CENTERPIECE.
   * Re-derives `PA01-DECISIONS.md` D7's frozen closure state machine
   * (`REASON_ALLOWED_CLOSURES` / phase-reachability) independently in this
   * package (never imported from `be`) and validates every `ACTION_CLOSED`
   * / `OUTCOME_RECONCILED` event's declared `(closure, reason)` pair
   * against it. On top of the reason/closure table, this component NEVER
   * trusts the declared `reason` field alone: any closure that CLAIMS
   * positive evidence (`TARGET_REJECTED`, `SUCCEEDED`, `FAILED_NO_EFFECT`,
   * `PARTIAL`, `REVERSED`) is independently required to have an ACTUAL
   * `TARGET_ACKNOWLEDGED` or `CALLER_RESULT_OBSERVED` event in the same
   * `actionId`'s stream — regardless of what `reason` says.
   *
   * PA-0033 (HIGH-1) — presence of an evidencing-TYPED event is not
   * evidence: `CALLER_RESULT_OBSERVED{success:false}` is what `be` writes
   * for BOTH a genuine negative result AND a client-side timeout. This
   * component now requires the evidencing event to carry a POSITIVE
   * outcome (`TARGET_ACKNOWLEDGED` always qualifies; `CALLER_RESULT_OBSERVED`
   * qualifies via `payload.outcomeClass` — `completed_success` /
   * `completed_with_error` positive, `no_response_received` a confirmed
   * non-answer, see `be`'s paired PA-0034). A confirmed non-answer is
   * `invalid` (`closure_evidencing_event_not_positive`) — **this is the
   * check that makes a bundle claiming `FAILED_NO_EFFECT` justified only
   * by a timeout verify as `invalid`, not just one claiming no evidence at
   * all.** A bundle whose `CALLER_RESULT_OBSERVED` events predate the
   * `outcomeClass` field (`success: false`, field absent — indistinguishable
   * offline from a timeout) can neither be trusted (`valid`) nor condemned
   * (`invalid`): it downgrades the whole component to `status: 'incomplete'`
   * (`closure_evidencing_event_ambiguous`), never silently `valid`.
   * `unsupported` on `manifest.version < 5`.
   */
  closureLegality: ComponentResult;
  /**
   * PA-0010 (D8, corrigendum C4) — DERIVES, does not believe. For every
   * CLOSED action in `[from, to)`, derives a grade purely from the
   * evidence actually present (target signature → A; customer-edge
   * attestation + authenticated destination → B; else C; SDK-self-report
   * with no Praesidia-observed evidence → D), then compares the derived
   * distribution against the manifest's SIGNED, `be`-DECLARED
   * `evidenceGradeSummary` using a cumulative-from-strongest rule: a
   * declared count in a grade bucket exceeding what the derived evidence
   * can support at that strength (or higher) is `invalid`, named
   * `declared_grade_exceeds_derived_evidence`. Also asserts
   * `enforcementMode`: if the summary declares `'enforce'` but any
   * counted event's own signed payload declares `'observe'`, that is
   * `invalid` (`observe_mode_action_counted_as_enforced`) — an
   * observe-mode action must never be countable as enforced.
   * `unsupported` on `manifest.version < 5`.
   */
  evidenceGrade: ComponentResult;
  /**
   * PA-0010 — binds the SIGNED `manifest.actionEventCount` to the number
   * of rows actually present in `action-events.ndjson.gz`, the same
   * truncation defense `completeness` provides for rows/roots/checkpoints.
   * `unsupported` on `manifest.version < 5`.
   */
  actionCompleteness: ComponentResult;
  /**
   * AV-0009 — `evidence/decision-receipts.ndjson` (be BE-1585, supplied via
   * `VerifyOptions.decisionDisclosures` or read from an audit package): each
   * line's `base64(sha256(salt || canonicalJson({details})))` must equal the
   * SIGNED `detailsCommitment` of the bundle's POLICY_DECISION /
   * POLICY_VIOLATION row it names. A mismatch, a row not in the bundle, an
   * unknown version or an unparseable line is `invalid`; withheld rows are
   * counted in `reason`, not failed; no file is `not_present`. `incomplete`
   * when every opening matched but row signatures did not verify.
   */
  decisionReceipt: ComponentResult;
  /**
   * AV-0009 — every verified Decision Record v1 carries a well-formed
   * `policyId` / `policyVersion` / `decision` consistent with its signed row
   * action, and an ALLOW that consumed a step-up approval names its
   * `approvalId`. Verifies the REFERENCE only: the policy text is not in the
   * package.
   */
  policyReference: ComponentResult;
  /** AV-0009 — present only when `decisionReceipt` is `valid`. */
  decisionDisclosures?: DecisionDisclosureSummary;
  /**
   * AV-0013 — the declared evidence privacy mode timeline (manifest v6, and
   * only once the manifest signature verified; otherwise one `FULL`
   * window with `declared: false`), what each mode lets this bundle prove,
   * and an annotation for every `payload: null` action event. Annotation
   * only: a declared mode never changes any component status.
   */
  evidencePrivacy: EvidencePrivacyReport;
  bundle: {
    orgId: string;
    from: string;
    to: string;
    declaredRowCount: number;
    declaredRootCount: number;
    rowsSeen: number;
    rootsSeen: number;
    proofsSeen: number;
    /**
     * FIX01 (audit-verifier2) — count of lines in `sealed-purges.ndjson.gz`
     * (0 if the entry is absent — it is wholly optional, never required).
     */
    sealedPurgesSeen: number;
    /**
     * Subset of `sealedPurgesSeen` whose own signature verified against a
     * non-REVOKED key in `public-keys.json` — see
     * `verifySealedPurgeAuthenticity`. Only this subset can ever downgrade
     * a `rootCoverage` / `integrityCheckpoints` finding.
     */
    sealedPurgesVerified: number;
    /** PA-0010 — count of lines in `action-events.ndjson.gz` (0 when `manifest.version < 5` — the entry does not exist). */
    actionEventsSeen: number;
    /**
     * AV-0002 — the tenant keys `platform-attestation.json` vouches for,
     * each fingerprint already checked against `public-keys.json`. Present
     * ONLY when `platformAttestation` verified an actual attestation (never
     * under `allowLegacyUnattested`). The verifier-produced pin source for
     * `verifyAibomAttestation` — use it via `aibomTrustFromBundle`, which
     * also requires the whole report to be `valid`.
     */
    attestedTenantKeys?: AttestedTenantKey[];
    /**
     * SCAN2-004 — chain endpoints, present only when `rowsSeen > 0` AND
     * `chain.status !== 'invalid'` (an unhealthy in-bundle chain has no
     * trustworthy endpoint to stitch against — `verify-set` already fails
     * that bundle outright via its own `report.ok`). `chainHeadAnchor` is
     * the bundle's leading row's own declared `prevRowHash`
     * (`GENESIS_PREV_ROW_HASH` for a true history start, an opaque
     * out-of-bundle value for a legitimate ranged export). `chainTailLinkHash`
     * is the hash-chain value ({@link computeChainLink}) the row
     * immediately following this bundle's newest row must declare as ITS
     * `prevRowHash` — this package never trusted `manifest.from`/`to` alone
     * to prove one bundle picks up where a sibling left off; these two
     * fields are what let `verify-set` do that cryptographically instead of
     * by date alone.
     */
    chainHeadRowId?: string;
    chainHeadAnchor?: string;
    chainTailRowId?: string;
    chainTailLinkHash?: string | null;
  };
}

export interface VerifyOptions {
  /** Out-of-band Ed25519 PEM pins keyed by "organizationId:targetId:keyId". Never loaded from a bundle. */
  targetPublicKeys?: Readonly<Record<string, string>>;
  /** Skip the optional Rekor receipt fetch (default: false). */
  noRekor?: boolean;
  /**
   * BUGHUNT-SDK-05 — Explicit override for the `rekor` receipt check
   * (e.g. an on-line re-fetch). When supplied it wins for `rekor`
   * receipts; when ABSENT the verifier now runs REAL offline
   * verification (SET + signed-checkpoint signatures under the pinned
   * Sigstore key, then inclusion proof — see `rekor.ts`), NOT the old
   * `JSON.parse`-only
   * default that returned `true` for any valid JSON. Receives the raw
   * receipt string; returns `true` on success.
   */
  rekorFetcher?: (
    anchorReceipt: string,
    expectedRoot: ExpectedAnchorRoot,
  ) => Promise<boolean>;
  /**
   * BUGHUNT-SDK-05 — Override the pinned Rekor signing public key (PEM
   * SPKI, EC P-256) used to verify the SET. Defaults to the Sigstore
   * key bundled in `rekor.ts`. Supply this for a sovereign / private
   * Rekor instance (or tests). Ignored when a custom `rekorFetcher` /
   * `anchorReceiptVerifier` is provided.
   */
  rekorPublicKeyPem?: string;
  /** AV-0019 — auditor-supplied RFC 3161 TSA anchor PEMs (`--tsa-cert`); never "qualified". */
  tsaTrustAnchorsPem?: readonly string[];
  /**
   * AUDIT-2026-05-09 — Optional hook for verifying provider-specific
   * anchor receipts in the multi-anchor `anchorReceipts` array. The
   * verifier dispatches on `entry.provider`:
   *
   *   - `'rekor'`   → falls back to `rekorFetcher` when this hook is
   *                   absent (preserves the legacy single-anchor path).
   *   - `'s3'`      → fails closed because an offline shape check cannot
   *                   prove object existence or immutability. A caller
   *                   wanting verification supplies this hook.
   *   - other       → reported as
   *                   `{ ok: false, reason: 'unknown_provider' }` and
   *                   counted as a failure in `report.rekor`. The
   *                   overall bundle fails closed; the unknown entry
   *                   surfaces in `firstFailure` so the auditor can
   *                   investigate.
   *
   * The second argument is the exact bundle root the receipt must bind to.
   * An S3 implementation must GET the immutable object version, compare its
   * root hash/signature and other available fields to `expectedRoot`, and
   * validate retention. A HEAD-only existence check is not sufficient.
   */
  anchorReceiptVerifier?: (
    entry: AnchorReceiptEntry,
    expectedRoot: ExpectedAnchorRoot,
  ) => Promise<{ ok: boolean; reason?: string }>;
  /**
   * AUDIT-2026-05-30 — Override the pinned platform public key. The
   * default is the bytes baked into the CLI release (see
   * `platform-pubkey.ts`); tests + ops use this hook to pin a
   * caller-supplied key without recompiling the package.
   *
   * Accepts base64-encoded SPKI DER of an EC P-256 public key. An
   * empty / missing override falls back to the bundled pin. Verification
   * fails closed when neither source contains a key.
   */
  platformPublicKeyDerB64?: string;
  /**
   * AV-0017 — a caller-supplied trust anchor (`parsePlatformTrustAnchor`
   * over be's `/.well-known/praesidia-audit-keys.json`). The attestation's
   * declared `platformSigningKeyFingerprint` selects the key; a document
   * that does not list it fails `trust_anchor_key_not_found`. Mutually
   * exclusive with `platformPublicKeyDerB64` (both → thrown error).
   */
  platformTrustAnchor?: PlatformTrustAnchor;
  /**
   * Explicitly accept a pre-attestation legacy bundle. Defaults to false so a
   * self-signed bundle cannot pass without an external platform trust anchor.
   */
  allowLegacyUnattested?: boolean;
  /**
   * Optional lower resource ceilings for constrained callers and tests.
   * Overrides may only reduce the verifier's built-in hard limits; attempts
   * to widen them are rejected as bundle-format errors.
   */
  resourceLimits?: Partial<VerifyResourceLimits>;
  /**
   * AV-0009 — raw bytes of an UNSIGNED `evidence/decision-receipts.ndjson`
   * for this bundle (CLI `--disclosures`). `verifyAuditPackage` reads the
   * package's own entry and rejects this option alongside it.
   */
  decisionDisclosures?: Buffer;
}

export interface VerifyResourceLimits {
  maxBundleBytes: number;
  maxGzipOutputBytes: number;
  maxTotalGzipOutputBytes: number;
  maxNdjsonLineBytes: number;
  maxTotalNdjsonRecords: number;
  maxRows: number;
  maxRoots: number;
  maxProofs: number;
  maxIntegrityCheckpoints: number;
  maxSealedPurges: number;
  maxActionEvents: number;
  maxPublicKeys: number;
  maxAnchorReceipts: number;
}

export interface AnchorReceiptEntry {
  provider: string;
  receipt: string;
  anchoredAt: string;
}

/** Root values an online receipt verifier must bind its evidence to. */
export interface ExpectedAnchorRoot {
  id: string;
  organizationId: string;
  rootHash: string;
  signature: string;
  keyVersion: number;
  signatureAlgorithm?: BundleSignatureAlgorithm;
  /** AV-0018 — the root signature's format when the bundle declares one (absent = 1; 2 = `merkle-root` tag). */
  signatureFormat?: number;
  periodStart: string;
  periodEnd: string;
  rowCount: number;
  signedAt: string;
}

/**
 * PROD16 F6 (be-compliance) — Explicit version negotiation.
 *
 * `manifest.version` was previously accepted with a floor (`>= 1`) but no
 * ceiling — any future schema version parsed and verified positionally
 * against TODAY's field set, silently. That is exactly how the
 * `IP_ADDRESS_SIGNABLE_CUTOVER_AT` skew was reachable: a be-side signable
 * shape change with no matching verifier release would not even be
 * detectable as "a shape this verifier doesn't understand" — it would
 * just verify wrong (or, worse, appear to verify while silently omitting a
 * signed field this build has never heard of). A manifest version beyond
 * what this build implements now fails LOUDLY, as a bundle-format error,
 * instead of being interpreted under the wrong rules.
 *
 * Bump this alongside adding real support for the new version's fields —
 * never bump it "ahead of" support just to silence this check.
 *
 * v3 (PROD16 §1b / `PROD16-CONTRACT-manifest-v3.md`) — `be` commit
 * `dc5b8a97` added `chainSeqCeiling`/`chainSeqSnapshotAt` INSIDE the signed
 * manifest preimage and bumped the wire version to 3 for bundles carrying
 * them. `verifyManifest` selects the 9-field (v1/v2) or 11-field (v3)
 * signable set by this declared version and fail-closed rejects either
 * direction of mismatch (fields present on v1/v2, or absent on v3) before
 * ever computing a signature — never by stripping/re-deriving fields from
 * the received object, which would let an attacker inject unsigned-looking
 * fields into a signed payload.
 *
 * v4 (FIX01 F5(b) / `PROD16-CONTRACT-manifest-v4-checkpoints.md`) — adds
 * `integrityCheckpointCount` (the 11 v3 fields plus this one, 12 total) and
 * a new, conditionally-required bundle entry `integrity-checkpoints
 * .ndjson.gz` carrying the signed `AuditIntegrityCheckpoint` rows
 * themselves. Same fail-closed-both-directions rule as v3's fields.
 *
 * v5 (PA-0010 / `PA01-CONTRACT-manifest-v5-actions.md`) — adds
 * `actionEventCount`/`captureScopeDigest`/`evidenceGradeSummary` (the 12
 * v4 fields plus these 3, 15 total) and a new, REQUIRED-even-when-empty
 * bundle entry `action-events.ndjson.gz` carrying the signed
 * `protected_action_events` rows. Same fail-closed-both-directions rule.
 *
 * v6 (AV-0013 / be BE-1615) — adds `evidencePrivacy` (the 15 v5 fields plus
 * this one, 16 total): the org's evidence privacy mode timeline. No new
 * bundle entry. Same fail-closed-both-directions rule.
 *
 * v7 (AV-0018 / ADR-0004 / be BE-1957) — adds `signatureFormat` (of the
 * manifest's own signature) and `signatureFormatCutoverAt` (the org's first
 * format-2 signature, or null), 18 signed fields. Same fail-closed rule.
 */
const MAX_SUPPORTED_MANIFEST_VERSION = 7;

const EXPECTED_ENTRIES = [
  'manifest.json',
  'rows.ndjson.gz',
  'roots.ndjson.gz',
  'proofs.ndjson.gz',
  'public-keys.json',
];

const BUNDLE_ALLOWED_ENTRY_NAMES = new Set([
  ...EXPECTED_ENTRIES,
  'integrity-checkpoints.ndjson.gz',
  'action-events.ndjson.gz',
  'sealed-purges.ndjson.gz',
  'platform-attestation.json',
  'README.md',
]);

const GZIP_ENTRY_NAMES = [
  'rows.ndjson.gz',
  'roots.ndjson.gz',
  'proofs.ndjson.gz',
  'integrity-checkpoints.ndjson.gz',
  'action-events.ndjson.gz',
  'sealed-purges.ndjson.gz',
] as const;

// Static documents are parsed in-memory, while gzip members are consumed a
// chunk at a time. These outer-entry limits align with the producer's 2 MiB
// metadata and 32 MiB compressed-artifact ceilings.
const MAX_STATIC_ENTRY_BYTES = 2 * 1024 * 1024;
const MAX_GZIP_COMPRESSED_BYTES = 32 * 1024 * 1024;
const BUNDLE_ENTRY_LIMITS = new Map<string, number>([
  ['manifest.json', MAX_STATIC_ENTRY_BYTES],
  ['public-keys.json', MAX_STATIC_ENTRY_BYTES],
  ['platform-attestation.json', MAX_STATIC_ENTRY_BYTES],
  ['README.md', MAX_STATIC_ENTRY_BYTES],
  ...GZIP_ENTRY_NAMES.map((name) => [name, MAX_GZIP_COMPRESSED_BYTES] as const),
]);

const DEFAULT_RESOURCE_LIMITS: Readonly<VerifyResourceLimits> = {
  maxBundleBytes: MAX_ZIP_ARCHIVE_BYTES,
  maxGzipOutputBytes: 32 * 1024 * 1024,
  maxTotalGzipOutputBytes: 64 * 1024 * 1024,
  maxNdjsonLineBytes: 1024 * 1024,
  maxTotalNdjsonRecords: 300_000,
  maxRows: 250_000,
  maxRoots: 250_000,
  maxProofs: 250_000,
  maxIntegrityCheckpoints: 250_000,
  maxSealedPurges: 250_000,
  maxActionEvents: 250_000,
  maxPublicKeys: 256,
  maxAnchorReceipts: 200_000,
};

const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

function resolveResourceLimits(
  overrides: Partial<VerifyResourceLimits> | undefined,
): VerifyResourceLimits {
  const resolved: VerifyResourceLimits = {
    ...DEFAULT_RESOURCE_LIMITS,
    ...overrides,
  };
  for (const key of Object.keys(DEFAULT_RESOURCE_LIMITS) as Array<
    keyof VerifyResourceLimits
  >) {
    const value = resolved[key];
    const hardLimit = DEFAULT_RESOURCE_LIMITS[key];
    if (!Number.isSafeInteger(value) || value <= 0 || value > hardLimit) {
      throw new Error(
        `invalid resource limit ${key}: expected a positive safe integer no greater than ${hardLimit}`,
      );
    }
  }
  return resolved;
}

function decodeUtf8Strict(data: Buffer, entryName: string): string {
  try {
    return STRICT_UTF8_DECODER.decode(data);
  } catch {
    throw new Error(`${entryName} is not valid UTF-8`);
  }
}

function assertManifestResourceClaims(
  manifest: BundleManifest,
  limits: VerifyResourceLimits,
): void {
  const claims: Array<[string, number | undefined, number]> = [
    ['rowCount', manifest.rowCount, limits.maxRows],
    ['rootCount', manifest.rootCount, limits.maxRoots],
    [
      'integrityCheckpointCount',
      manifest.integrityCheckpointCount,
      limits.maxIntegrityCheckpoints,
    ],
    ['actionEventCount', manifest.actionEventCount, limits.maxActionEvents],
    ['keyVersions.length', manifest.keyVersions.length, limits.maxPublicKeys],
  ];
  for (const [field, value, limit] of claims) {
    if (value !== undefined && value > limit) {
      throw new Error(
        `manifest ${field} ${value} exceeds verifier resource limit ${limit}`,
      );
    }
  }
  // A complete bundle needs one proof record for every audit row. Reject a
  // signed scope that cannot fit the shared record budget before expanding
  // any gzip member; optional sealed-purge records remain accounted exactly
  // by the streaming parser.
  const minimumNdjsonRecords =
    manifest.rowCount * 2 +
    manifest.rootCount +
    (manifest.integrityCheckpointCount ?? 0) +
    (manifest.actionEventCount ?? 0);
  if (minimumNdjsonRecords > limits.maxTotalNdjsonRecords) {
    throw new Error(
      `manifest requires at least ${minimumNdjsonRecords} NDJSON records, exceeding verifier total resource limit ${limits.maxTotalNdjsonRecords}`,
    );
  }
}

// ────────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────────

/**
 * Verify a compliance bundle. Returns a structured report; never throws
 * on a verification failure (only on I/O / format errors — those should
 * surface to the CLI as exit code 2 distinct from verification failures
 * at exit code 1).
 */
export async function verifyBundle(
  bundle: Buffer,
  options: VerifyOptions = {},
): Promise<VerifyReport> {
  return (await verifyBundleAndBridges(bundle, options)).report;
}

/**
 * AV-2755 — `verifyBundle`, plus the sealed-purge bridges whose seal AND link
 * signatures verified (the ones its chain check may follow), for
 * `verify-set`'s boundary check. Not re-exported by `index.ts`; `report` is
 * exactly `verifyBundle`'s. AV-2775: `rowLinks` holds the members of
 * `rowLinkQuery` that are chain links of this bundle's rows, never more than
 * the query. AV-2782: it is empty when `report.status` is `invalid`.
 */
export async function verifyBundleAndBridges(
  bundle: Buffer,
  options: VerifyOptions = {},
  rowLinkQuery: ReadonlySet<string> = new Set(),
): Promise<{ report: VerifyReport; chainBridges: ChainBridge[]; rowLinks: Set<string> }> {
  const resourceLimits = resolveResourceLimits(options.resourceLimits);

  // 1) Read & validate the zip envelope.
  const entries = readZip(bundle, {
    maxArchiveBytes: resourceLimits.maxBundleBytes,
    maxEntries: BUNDLE_ALLOWED_ENTRY_NAMES.size,
    maxEntryUncompressedBytes: MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES,
    maxTotalUncompressedBytes: MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES,
    allowedEntryNames: BUNDLE_ALLOWED_ENTRY_NAMES,
    maxEntryUncompressedBytesByName: BUNDLE_ENTRY_LIMITS,
  });
  const byName = new Map<string, ZipEntry>();
  for (const e of entries) byName.set(e.name, e);
  for (const required of EXPECTED_ENTRIES) {
    if (!byName.has(required)) {
      throw new Error(`bundle missing required entry: ${required}`);
    }
  }

  // 2) Parse manifest, public keys.
  const manifest = JSON.parse(
    decodeUtf8Strict(byName.get('manifest.json')!.data, 'manifest.json'),
  ) as BundleManifest;
  assertManifestStructure(manifest);
  assertManifestResourceClaims(manifest, resourceLimits);

  // FIX01 F5(b) / manifest-v4 — `integrity-checkpoints.ndjson.gz` is only
  // required once the DECLARED version says it should exist; checked here
  // (not added to the static `EXPECTED_ENTRIES`) because its presence is
  // conditional on a field inside the file we just parsed.
  if (manifest.version >= 4 && !byName.has('integrity-checkpoints.ndjson.gz')) {
    throw new Error(
      `bundle declares manifest.version ${manifest.version} (>= 4) but is missing required entry: integrity-checkpoints.ndjson.gz`,
    );
  }
  // PA-0010 / manifest-v5 — `action-events.ndjson.gz` is REQUIRED whenever
  // `manifest.version >= 5`, even when the org has zero protected-action
  // activity in range (an empty-but-present file) — identical rule to
  // `integrity-checkpoints.ndjson.gz` on `>= 4`.
  if (manifest.version >= 5 && !byName.has('action-events.ndjson.gz')) {
    throw new Error(
      `bundle declares manifest.version ${manifest.version} (>= 5) but is missing required entry: action-events.ndjson.gz`,
    );
  }

  const publicKeysParsed: unknown = JSON.parse(
    decodeUtf8Strict(byName.get('public-keys.json')!.data, 'public-keys.json'),
  );
  if (
    publicKeysParsed === null ||
    typeof publicKeysParsed !== 'object' ||
    Array.isArray(publicKeysParsed)
  ) {
    throw new Error('public-keys.json must contain an object');
  }
  const publicKeysRaw = publicKeysParsed as Record<string, unknown>;
  if (Object.keys(publicKeysRaw).length > resourceLimits.maxPublicKeys) {
    throw new Error(
      `public-keys.json key count exceeds verifier resource limit ${resourceLimits.maxPublicKeys}`,
    );
  }
  const publicKeys = new Map<number, PublicKeyRecord>();
  const keyMaterialOwners = new Map<string, string>();
  for (const [k, v] of Object.entries(publicKeysRaw)) {
    const ver = Number(k);
    if (!/^[1-9]\d*$/.test(k) || !Number.isSafeInteger(ver) || ver < 1) {
      throw new Error(
        `public-keys.json contains a non-canonical positive key version: ${k}`,
      );
    }
    const record = parsePublicKeyEntry(v, k);
    const fingerprint = crypto
      .createHash('sha256')
      .update(record.publicKey)
      .digest('hex');
    const priorOwner = keyMaterialOwners.get(fingerprint);
    if (priorOwner !== undefined) {
      // keyVersion is unsigned signature metadata on rows, roots, and the
      // manifest. Reusing the same key bytes under two lifecycle records
      // would let an attacker relabel a REVOKED signature as the ACTIVE
      // alias without changing the signature itself.
      throw new Error(
        `public-keys.json reuses identical key material for key versions ${priorOwner} and ${k}`,
      );
    }
    keyMaterialOwners.set(fingerprint, k);
    publicKeys.set(ver, record);
  }

  // 3) Verify manifest signature.
  const manifestResult = withStatus(verifyManifest(manifest, publicKeys));
  // AV-0018 — the signed v7 format-2 cutover; null on v1..v6 and when unset.
  const cutoverMs = signatureCutoverMs(manifest);

  const gzipOutputBudget: GzipOutputBudget = {
    remainingBytes: resourceLimits.maxTotalGzipOutputBytes,
  };
  const ndjsonRecordBudget: NdjsonRecordBudget = {
    remainingRecords: resourceLimits.maxTotalNdjsonRecords,
  };
  const parseGzipNdjson = async <T>(
    entryName: string,
    maxRecords: number,
  ): Promise<T[]> => {
    const entry = byName.get(entryName);
    if (!entry) throw new Error(`bundle missing required entry: ${entryName}`);
    return parseNdjsonChunks<T>(
      gunzipChunks(entry.data, {
        entryName,
        maxCompressedBytes: MAX_GZIP_COMPRESSED_BYTES,
        maxOutputBytes: resourceLimits.maxGzipOutputBytes,
        outputBudget: gzipOutputBudget,
      }),
      entryName,
      maxRecords,
      resourceLimits.maxNdjsonLineBytes,
      ndjsonRecordBudget,
    );
  };

  // 4) Parse + verify rows.
  const rows = await parseGzipNdjson<BundleRow>(
    'rows.ndjson.gz',
    resourceLimits.maxRows,
  );
  assertRowsStructure(rows, manifest.orgId);

  // NX-TAC-02 — Thread the manifest's signatureAlgorithm into the
  // row + root signature checks. Every signature in a bundle uses
  // the same algorithm as the manifest (be-core's producer never
  // mixes algorithms within one bundle).
  const rowSigResult = withEvidenceStatus(
    verifyRowSignatures(rows, publicKeys, manifest.signatureAlgorithm, cutoverMs),
  );
  // The chain (`verifyChain`) is verified at 6c, once the sealed-purge
  // bridges it may follow are authenticated.

  // 5) Parse + verify roots.
  const roots = await parseGzipNdjson<BundleRoot>(
    'roots.ndjson.gz',
    resourceLimits.maxRoots,
  );
  assertRootsStructure(roots, manifest.orgId);
  const supersessions = resolveSupersessions(roots);
  let anchorReceiptCount = 0;
  for (const root of roots) {
    anchorReceiptCount +=
      Array.isArray(root.anchorReceipts) && root.anchorReceipts.length > 0
        ? root.anchorReceipts.length
        : root.anchorReceipt
          ? 1
          : 0;
    if (anchorReceiptCount > resourceLimits.maxAnchorReceipts) {
      throw new Error(
        `bundle anchor receipt count exceeds verifier resource limit ${resourceLimits.maxAnchorReceipts}`,
      );
    }
  }
  const rootSigResult = withEvidenceStatus(
    verifyRootSignatures(roots, publicKeys, manifest.signatureAlgorithm, cutoverMs),
  );

  // 6) Parse + verify inclusion proofs.
  const proofs = await parseGzipNdjson<BundleProofEntry>(
    'proofs.ndjson.gz',
    resourceLimits.maxProofs,
  );
  assertProofsStructure(proofs);
  const proofRaw = verifyInclusionProofs(rows, roots, proofs, supersessions);
  const proofResult = withEvidenceStatus(proofRaw.result, proofRaw.status);

  // 6b) FIX01 F5(b) — parse + verify integrity checkpoints (v4+ only; an
  // empty array for every earlier version).
  const checkpoints: BundleIntegrityCheckpoint[] =
    manifest.version >= 4
      ? await parseGzipNdjson<BundleIntegrityCheckpoint>(
          'integrity-checkpoints.ndjson.gz',
          resourceLimits.maxIntegrityCheckpoints,
        )
      : [];
  assertIntegrityCheckpointsStructure(checkpoints, manifest.orgId);

  // 6c) FIX01 (audit-verifier2) — parse + authenticity-check sealed-purge
  // evidence. Wholly OPTIONAL and UNVERSIONED (never gated on
  // `manifest.version`, unlike integrity checkpoints): the entry is not
  // part of the signed manifest preimage (see `BundleSealedPurge`'s doc
  // comment), so its absence is never a bundle-format error and its
  // presence never changes what a genuine bundle is required to contain.
  // `verifiedSeals` is the authenticity-gated subset actually usable for
  // the downstream cross-checks (2 and 3 in the spec's numbered
  // algorithm) — see `verifySealedPurgeAuthenticity`.
  const sealedPurgesEntry = byName.get('sealed-purges.ndjson.gz') ?? null;
  const sealedPurges: BundleSealedPurge[] = sealedPurgesEntry
    ? await parseGzipNdjson<BundleSealedPurge>(
        'sealed-purges.ndjson.gz',
        resourceLimits.maxSealedPurges,
      )
    : [];
  assertSealedPurgesStructure(sealedPurges, manifest.orgId);
  const verifiedSeals = verifySealedPurgeAuthenticity(sealedPurges, publicKeys, cutoverMs);

  // SCAN2-004 — `chainRaw` carries the head/tail endpoint fields
  // `ChainVerification` adds on top of `RawComponentResult`; narrow
  // explicitly before `withStatus` so those extra fields never leak into
  // the public `chain: ComponentResult` surface. They are surfaced
  // separately, on `bundle`, for `verify-set` to consume. AV-2754: the
  // chain may cross a purged run only through a seal whose 6-field AND
  // link signatures both verify.
  const chainBridges = verifySealLinkAuthenticity(verifiedSeals, publicKeys, cutoverMs);
  const chainRaw = verifyChain(rows, chainBridges);
  const rowLinks = new Set<string>();
  if (rowLinkQuery.size > 0) {
    for (const row of rows) {
      const link = computeChainLink(row);
      if (link !== null && rowLinkQuery.has(link)) rowLinks.add(link);
    }
  }
  const chainResult = withEvidenceStatus({
    ok: chainRaw.ok,
    checked: chainRaw.checked,
    failed: chainRaw.failed,
    firstFailure: chainRaw.firstFailure,
    reason: chainRaw.reason,
  });

  const integrityCheckpointsResult = withEvidenceStatus(
    verifyIntegrityCheckpoints(
      manifest,
      rows,
      checkpoints,
      publicKeys,
      verifiedSeals,
      cutoverMs,
    ),
  );

  // 6d) PA-0010 — parse + verify action-event evidence (v5+ only; an
  // empty array for every earlier version, mirroring integrity checkpoints).
  const actionEvents: BundleActionEvent[] =
    manifest.version >= 5
      ? await parseGzipNdjson<BundleActionEvent>(
          'action-events.ndjson.gz',
          resourceLimits.maxActionEvents,
        )
      : [];
  assertActionEventsStructure(actionEvents, manifest.orgId);
  const actionEventsSupported = manifest.version >= 5;
  // AV-0013 — trust the declared mode only once the manifest signature did.
  const evidencePrivacy = evidencePrivacyReport(
    manifest.version >= 6 && manifestResult.status === 'valid' ? manifest.evidencePrivacy : undefined,
    manifest.from,
    manifest.to,
    actionEvents,
  );
  const privacyAnnotated = (r: ComponentResult, eventType: string): ComponentResult => {
    const reason =
      r.status === 'incomplete' && r.reason === undefined
        ? evidencePrivacyReason(evidencePrivacy, eventType)
        : undefined;
    return reason ? { ...r, reason } : r;
  };

  const actionEventChainResult = actionEventsSupported
    ? withEvidenceStatus(
        verifyActionEventChain(
          actionEvents,
          publicKeys,
          manifest.signatureAlgorithm,
          cutoverMs,
        ),
      )
    : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported');
  const permitBindingResult = actionEventsSupported
    ? withEvidenceStatus(verifyPermitBinding(actionEvents))
    : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported');
  const requestBindingResult = actionEventsSupported
    ? withEvidenceStatus(verifyRequestBinding(actionEvents))
    : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported');
  const dispatchIntegrityResult = actionEventsSupported
    ? withEvidenceStatus(verifyDispatchIntegrity(actionEvents))
    : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported');
  const targetAckRaw = actionEventsSupported
    ? verifyTargetAck(actionEvents, options.targetPublicKeys)
    : null;
  const targetAckResult = privacyAnnotated(
    actionEventsSupported
      ? withEvidenceStatus(targetAckRaw!.result, targetAckRaw!.status)
      : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported'),
    'TARGET_ACKNOWLEDGED',
  );
  const callerResultRaw = actionEventsSupported
    ? verifyCallerResult(actionEvents)
    : null;
  const callerResultResult = privacyAnnotated(
    actionEventsSupported
      ? withEvidenceStatus(callerResultRaw!.result, callerResultRaw!.status)
      : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported'),
    'CALLER_RESULT_OBSERVED',
  );
  const closureLegalityRaw = actionEventsSupported
    ? verifyClosureLegality(actionEvents)
    : null;
  const closureLegalityResult = actionEventsSupported
    ? withEvidenceStatus(closureLegalityRaw!.result, closureLegalityRaw!.status)
    : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported');
  const evidenceGradeResult = actionEventsSupported
    ? withEvidenceStatus(verifyEvidenceGrade(actionEvents, manifest, options.targetPublicKeys))
    : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported');
  const actionCompletenessResult = actionEventsSupported
    ? withEvidenceStatus(verifyActionCompleteness(manifest, actionEvents))
    : withStatus({ ok: true, checked: 0, failed: 0 }, 'unsupported');

  // 7) Optional Rekor fetch.
  const rekorResult = withEvidenceStatus(
    await verifyRekorReceipts(roots, options, publicKeys, manifest.signatureAlgorithm),
  );

  // 8) AUDIT-2026-05-30 — Platform key-binding attestation.
  // The entry remains optional in the ZIP grammar for backwards parsing,
  // but its absence fails verification unless explicitly allowed.
  const { attestedKeys, ...platformRaw } = verifyPlatformAttestation(
    byName.get('platform-attestation.json') ?? null,
    publicKeysRaw,
    manifest,
    options,
  );
  // AV-0017 — no trust anchor at all cannot decide origin: `incomplete`
  // here, `unanchored` at the top level (below), never `valid`.
  const platformResult = withEvidenceStatus(
    platformRaw,
    platformRaw.reason === PLATFORM_KEY_NOT_PINNED ? 'incomplete' : undefined,
  );

  // 9) BUG-AUDIT-01 — Completeness: the SIGNED row/root counts must
  // match what is actually present, or a trailing-truncation attack
  // slips through (the surviving prefix still chains + proves).
  const completenessResult = withStatus(
    verifyCompleteness(manifest, rows, roots, checkpoints),
  );

  // 10) BUG-AUDIT-03 / PROD15 — Bind the (unsigned) `public-keys.json`
  // bytes AND lifecycle (status/revokedAt) the verifier trusts against
  // the SIGNED `manifest.keyVersions` set.
  const keyBindingResult = withStatus(
    verifyKeyBinding(manifest, publicKeysRaw, publicKeys),
  );

  // 11) PROD16 — Root row-coverage: bind each fully-contained root's
  // SIGNED rowCount to the bundle's own row/proof counts for that period,
  // closing the trailing-suffix-deletion gap `completeness` cannot see
  // (see the `rootCoverage` field doc comment above).
  const rootCoverageResult = withEvidenceStatus(
    verifyRootCoverage(manifest, rows, roots, proofs, verifiedSeals, supersessions),
  );

  // 12) AV-0009 — decision disclosures, bound to the signed rows above.
  const disclosures = verifyDecisionDisclosures(options.decisionDisclosures ?? null, rows, {
    maxLines: resourceLimits.maxRows + 1,
    maxLineBytes: resourceLimits.maxNdjsonLineBytes,
  });
  const rowsTrusted = rowSigResult.status === 'valid';
  const disclosureStatus = (r: RawComponentResult): ComponentStatus | undefined =>
    r.ok && r.checked > 0 && !rowsTrusted ? 'incomplete' : undefined;
  const decisionReceiptResult = withEvidenceStatus(disclosures.receipt, disclosureStatus(disclosures.receipt));
  const policyReferenceResult = withEvidenceStatus(disclosures.policy, disclosureStatus(disclosures.policy));

  // PA-0009 (D15) — real reduction over `status`, not an AND of `ok`. See
  // `reduceStatus` doc comment: `invalid` beats `incomplete` beats `valid`,
  // and `unsupported`/`not_present` components are excluded rather than
  // counted as failure (AV-0008: unless no evidence component is valid).
  const allResults = [
    manifestResult,
    rowSigResult,
    chainResult,
    rootSigResult,
    proofResult,
    rekorResult,
    platformResult,
    completenessResult,
    keyBindingResult,
    rootCoverageResult,
    integrityCheckpointsResult,
    actionEventChainResult,
    permitBindingResult,
    requestBindingResult,
    dispatchIntegrityResult,
    targetAckResult,
    callerResultResult,
    closureLegalityResult,
    evidenceGradeResult,
    actionCompletenessResult,
    decisionReceiptResult,
    policyReferenceResult,
  ];
  // AV-0008 — the components that carry audit evidence (every
  // optional-evidence component except platformAttestation, which is key
  // provenance, not evidence). None `valid` → top level `incomplete`.
  const evidenceResults = allResults.filter(
    (r) => r !== manifestResult && r !== platformResult && r !== completenessResult && r !== keyBindingResult,
  );
  // AV-0017 — invalid beats unanchored beats incomplete beats valid.
  const reduced = reduceStatus(allResults, evidenceResults);
  const status: VerifyReport['status'] =
    reduced === 'incomplete' && platformResult.reason === PLATFORM_KEY_NOT_PINNED ? 'unanchored' : reduced;
  const ok = status === 'valid';

  const report: Omit<VerifyReport, 'proofs'> = {
    ok,
    status,
    manifest: manifestResult,
    rowSignatures: rowSigResult,
    chain: chainResult,
    rootSignatures: rootSigResult,
    inclusionProofs: proofResult,
    rekor: rekorResult,
    rfc3161: summarizeRfc3161(roots, options),
    platformAttestation: platformResult,
    completeness: completenessResult,
    keyBinding: keyBindingResult,
    rootCoverage: rootCoverageResult,
    integrityCheckpoints: integrityCheckpointsResult,
    actionEventChain: actionEventChainResult,
    permitBinding: permitBindingResult,
    requestBinding: requestBindingResult,
    dispatchIntegrity: dispatchIntegrityResult,
    targetAck: targetAckResult,
    callerResult: callerResultResult,
    closureLegality: closureLegalityResult,
    evidenceGrade: evidenceGradeResult,
    actionCompleteness: actionCompletenessResult,
    decisionReceipt: decisionReceiptResult,
    policyReference: policyReferenceResult,
    ...(decisionReceiptResult.status === 'valid' && disclosures.summary
      ? { decisionDisclosures: disclosures.summary }
      : {}),
    evidencePrivacy,
    bundle: {
      orgId: manifest.orgId,
      from: manifest.from,
      to: manifest.to,
      declaredRowCount: manifest.rowCount,
      declaredRootCount: manifest.rootCount,
      rowsSeen: rows.length,
      rootsSeen: roots.length,
      proofsSeen: proofs.length,
      sealedPurgesSeen: sealedPurges.length,
      sealedPurgesVerified: verifiedSeals.length,
      actionEventsSeen: actionEvents.length,
      ...(attestedKeys ? { attestedTenantKeys: attestedKeys } : {}),
      ...(rows.length > 0 && chainResult.status !== 'invalid'
        ? {
            chainHeadRowId: chainRaw.headRowId,
            chainHeadAnchor: chainRaw.headAnchor,
            chainTailRowId: chainRaw.tailRowId,
            chainTailLinkHash: chainRaw.tailChainLink,
          }
        : {}),
    },
  };
  return { report: { ...report, proofs: deriveProofs(report) }, chainBridges, rowLinks: status === 'invalid' ? new Set() : rowLinks };
}

// ════════════════════════════════════════════════════════════════════════
// Component verifiers
// ════════════════════════════════════════════════════════════════════════

/**
 * Reconstruct the manifest-sans-signature envelope and canonicalize it the
 * same way the writer did. The two chainSeq fields join the signable set
 * ONLY for version >= 3 — validated by `verifyManifest`'s version checks to
 * be exactly the versions that carry them, so this is a closed selection,
 * not a strip-and-reconstruct of whatever the wire object happens to hold.
 *
 * Extracted (SEC-2026-09-12, MCPSDK-01) so the platform attestation's
 * optional `manifestDigest` is computed over the IDENTICAL bytes the
 * manifest signature covers. Two copies of this selection would be a latent
 * divergence: a digest over a slightly different preimage would either
 * always fail or, worse, cover fewer fields than the signature does.
 */
/**
 * AV-0018 / ADR-0004 — the manifest-v7 format-2 cutover as epoch ms, or null
 * (no cutover declared, or a pre-v7 bundle, which cannot carry one).
 */
function signatureCutoverMs(manifest: BundleManifest): number | null {
  if (manifest.version < 7 || manifest.signatureFormatCutoverAt == null) return null;
  return Date.parse(manifest.signatureFormatCutoverAt);
}

/**
 * AV-0018 / ADR-0004 — why a declared signature format is unacceptable, or
 * null. Absent = 1 (pre-format bundles). Anything but 1 or 2 fails closed.
 * Downgrade guard: a format-1 (untagged) signature on an artefact whose own
 * SIGNED timestamp is at or after the org's cutover fails.
 */
function signatureFormatRejection(
  format: unknown,
  signedTimestamp: unknown,
  cutoverMs: number | null,
): string | null {
  const f = format === undefined ? 1 : format;
  if (f !== 1 && f !== 2) {
    return `signature_format_unsupported: signatureFormat ${JSON.stringify(f)} is neither 1 nor 2`;
  }
  if (f === 1 && cutoverMs !== null) {
    const t = typeof signedTimestamp === 'string' ? Date.parse(signedTimestamp) : NaN;
    if (!(t < cutoverMs)) {
      return `signature_format_downgrade: format-1 (untagged) signature on an artefact signed at ${String(signedTimestamp)}, at or after the org's format-2 cutover ${new Date(cutoverMs).toISOString()}`;
    }
  }
  return null;
}

/**
 * AV-0018 — verify a tenant signature in the slot `purpose`, under its
 * declared format. Returns the rejection reason, `false` for a signature that
 * does not verify, or `true`. The purpose comes from the caller's slot, never
 * from the artefact.
 */
function verifyTenantSignature(
  algorithm: BundleSignatureAlgorithm,
  format: unknown,
  purpose: SignaturePurpose,
  payload: Uint8Array,
  signature: string,
  publicKey: Uint8Array,
  signedTimestamp: unknown,
  cutoverMs: number | null,
): true | false | string {
  const rejection = signatureFormatRejection(format, signedTimestamp, cutoverMs);
  if (rejection !== null) return rejection;
  const f = format === 2 ? 2 : 1;
  return verifySignature(algorithm, tenantSignedBytes(f, purpose, payload), signature, publicKey);
}

function manifestSignableBytes(manifest: BundleManifest): Buffer {
  const signable: Record<string, unknown> = {
    version: manifest.version,
    orgId: manifest.orgId,
    from: manifest.from,
    to: manifest.to,
    rowCount: manifest.rowCount,
    rootCount: manifest.rootCount,
    keyVersions: manifest.keyVersions,
    generatedAt: manifest.generatedAt,
    signatureAlgorithm: manifest.signatureAlgorithm,
  };
  if (manifest.version >= 3) {
    signable.chainSeqCeiling = manifest.chainSeqCeiling;
    signable.chainSeqSnapshotAt = manifest.chainSeqSnapshotAt;
  }
  if (manifest.version >= 4) {
    signable.integrityCheckpointCount = manifest.integrityCheckpointCount;
  }
  if (manifest.version >= 5) {
    signable.actionEventCount = manifest.actionEventCount;
    signable.captureScopeDigest = manifest.captureScopeDigest;
    signable.evidenceGradeSummary = manifest.evidenceGradeSummary;
  }
  if (manifest.version >= 6) {
    signable.evidencePrivacy = manifest.evidencePrivacy;
  }
  if (manifest.version >= 7) {
    signable.signatureFormat = manifest.signatureFormat;
    signable.signatureFormatCutoverAt = manifest.signatureFormatCutoverAt;
  }
  return canonicalJson(signable);
}

function verifyManifest(
  manifest: BundleManifest,
  publicKeys: Map<number, PublicKeyRecord>,
): RawComponentResult {
  const entry = publicKeys.get(manifest.signatureKeyVersion);
  if (!entry) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `manifest signing key version ${manifest.signatureKeyVersion} not in public-keys.json`,
    };
  }
  // RA-05 (PROD15 re-attack) — Fail CLOSED on a manifest signed under a
  // REVOKED key, mirroring `verifyRowSignatures` / `verifyRootSignatures`.
  //
  // The manifest is itself the signed document carrying `orgId`, `from`,
  // `to`, `rowCount`, `rootCount` and the whole `keyVersions` set — including
  // the very `status`/`revokedAt` fields the PROD15 `verifyKeyBinding` cross
  // -check relies on. A holder of a compromised (revoked) key can mint a
  // brand-new, validly-signed manifest asserting anything they like,
  // including a `keyVersions[]` set that dishonestly re-labels their own
  // key ACTIVE. Without this check, `verifyKeyBinding` would faithfully
  // confirm `public-keys.json` matches that dishonest-but-signed manifest
  // and the forgery would verify.
  //
  // Same reasoning as the row/root siblings applies to why there is no
  // signed-before-revocation grace period here: although `generatedAt` IS
  // part of the manifest's signed preimage (unlike a row's `signedAt`),
  // that does not help — a key holder can sign a FRESH manifest with any
  // `generatedAt` they choose, so a backdated timestamp is exactly as
  // forgeable as an unsigned one. There is no self-contained way to tell a
  // genuine pre-revocation manifest from a backdated forgery, so the
  // conservative choice is to reject every REVOKED-key manifest signature
  // unconditionally, exactly like `verifyRowSignatures` / `verifyRootSignatures`.
  if (entry.status === 'REVOKED') {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'key_revoked',
    };
  }
  // PROD16 §1b / `PROD16-CONTRACT-manifest-v3.md` — the signable field set
  // is selected by the manifest's DECLARED version, from a closed
  // whitelist, never by inspecting which fields happen to be present on
  // the received object (that would let an attacker bolt unsigned-looking
  // fields onto a signed payload and have this verifier ignore them
  // silently). Both directions of version/field mismatch are themselves
  // evidence of tampering — a genuine `be` producer (bundle-exporter
  // .service.ts) emits `chainSeqCeiling`/`chainSeqSnapshotAt` on EVERY
  // v3 manifest and on NEITHER v1 nor v2 manifest — so each direction gets
  // its own distinct, specific reason rather than falling through to a
  // generic "manifest signature does not verify", which would read as
  // ordinary tampering to an auditor instead of the version-skew problem
  // it actually is. Same principle PROD15-FIXED-av2.md Gap 2 applied to
  // `keyVersions[].status`: a field a genuine producer always emits at a
  // version is never legitimately missing there, and one it never emits
  // at an older version is never legitimately present there.
  const hasChainSeqCeiling = 'chainSeqCeiling' in manifest;
  const hasChainSeqSnapshotAt = 'chainSeqSnapshotAt' in manifest;
  if (manifest.version <= 2 && (hasChainSeqCeiling || hasChainSeqSnapshotAt)) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `chainseq_fields_present_on_v${manifest.version}_manifest: manifest declares version ${manifest.version} but carries chainSeqCeiling/chainSeqSnapshotAt — no genuine v1/v2 producer ever emits these fields; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }
  if (manifest.version >= 3 && !(hasChainSeqCeiling && hasChainSeqSnapshotAt)) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `chainseq_fields_missing_on_v3_manifest: manifest declares version ${manifest.version} but is missing chainSeqCeiling/chainSeqSnapshotAt — every genuine v3 producer emits both; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }
  // FIX01 F5(b) / manifest-v4 contract — same both-directions rule for
  // `integrityCheckpointCount`.
  const hasIntegrityCheckpointCount = 'integrityCheckpointCount' in manifest;
  if (manifest.version <= 3 && hasIntegrityCheckpointCount) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `integrity_checkpoint_count_present_on_v${manifest.version}_manifest: manifest declares version ${manifest.version} but carries integrityCheckpointCount — no genuine producer below v4 ever emits this field; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }
  if (manifest.version >= 4 && !hasIntegrityCheckpointCount) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `integrity_checkpoint_count_missing_on_v4_manifest: manifest declares version ${manifest.version} but is missing integrityCheckpointCount — every genuine v4 producer emits it; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }
  // PA-0010 / manifest-v5 contract — same both-directions rule for the
  // three action-evidence fields, each with its own named reason so an
  // auditor can tell version-skew from tampering.
  const hasActionEventCount = 'actionEventCount' in manifest;
  const hasCaptureScopeDigest = 'captureScopeDigest' in manifest;
  const hasEvidenceGradeSummary = 'evidenceGradeSummary' in manifest;
  if (manifest.version <= 4) {
    if (hasActionEventCount) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `action_event_count_present_on_v${manifest.version}_manifest: manifest declares version ${manifest.version} but carries actionEventCount — no genuine producer below v5 ever emits this field; this is version-downgrade skew or tampering, not a signature failure`,
      };
    }
    if (hasCaptureScopeDigest) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `capture_scope_digest_present_on_v${manifest.version}_manifest: manifest declares version ${manifest.version} but carries captureScopeDigest — no genuine producer below v5 ever emits this field; this is version-downgrade skew or tampering, not a signature failure`,
      };
    }
    if (hasEvidenceGradeSummary) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `evidence_grade_summary_present_on_v${manifest.version}_manifest: manifest declares version ${manifest.version} but carries evidenceGradeSummary — no genuine producer below v5 ever emits this field; this is version-downgrade skew or tampering, not a signature failure`,
      };
    }
  }
  if (manifest.version >= 5) {
    if (!hasActionEventCount) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `action_event_count_missing_on_v5_manifest: manifest declares version ${manifest.version} but is missing actionEventCount — every genuine v5 producer emits it; this is version-downgrade skew or tampering, not a signature failure`,
      };
    }
    if (!hasCaptureScopeDigest) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `capture_scope_digest_missing_on_v5_manifest: manifest declares version ${manifest.version} but is missing captureScopeDigest — every genuine v5 producer emits it; this is version-downgrade skew or tampering, not a signature failure`,
      };
    }
    if (!hasEvidenceGradeSummary) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `evidence_grade_summary_missing_on_v5_manifest: manifest declares version ${manifest.version} but is missing evidenceGradeSummary — every genuine v5 producer emits it; this is version-downgrade skew or tampering, not a signature failure`,
      };
    }
  }
  // AV-0013 / manifest-v6 — same both-directions rule for `evidencePrivacy`.
  const hasEvidencePrivacy = 'evidencePrivacy' in manifest;
  if (manifest.version <= 5 && hasEvidencePrivacy) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `evidence_privacy_present_on_v${manifest.version}_manifest: manifest declares version ${manifest.version} but carries evidencePrivacy — no genuine producer below v6 ever emits this field; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }
  if (manifest.version >= 6 && !hasEvidencePrivacy) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `evidence_privacy_missing_on_v6_manifest: manifest declares version ${manifest.version} but is missing evidencePrivacy — every genuine v6 producer emits it; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }
  // AV-0018 / manifest-v7 — same both-directions rule for the two format fields.
  const hasFormatFields = 'signatureFormat' in manifest || 'signatureFormatCutoverAt' in manifest;
  const hasBothFormatFields = 'signatureFormat' in manifest && 'signatureFormatCutoverAt' in manifest;
  if (manifest.version <= 6 && hasFormatFields) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `signature_format_fields_present_on_v${manifest.version}_manifest: manifest declares version ${manifest.version} but carries signatureFormat/signatureFormatCutoverAt — no genuine producer below v7 ever emits these fields; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }
  if (manifest.version >= 7 && !hasBothFormatFields) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `signature_format_fields_missing_on_v7_manifest: manifest declares version ${manifest.version} but is missing signatureFormat/signatureFormatCutoverAt — every genuine v7 producer emits both; this is version-downgrade skew or tampering, not a signature failure`,
    };
  }

  const bytes = manifestSignableBytes(manifest);
  // NX-TAC-02 — Dispatch on the algorithm declared in the manifest.
  // A bundle whose `signatureAlgorithm` is ECDSA_P256_SHA256 is now
  // verifiable (was previously rejected outright).
  // AV-0018 — v1..v6 manifests are format 1 (the field cannot be present).
  const ok = verifyTenantSignature(
    manifest.signatureAlgorithm,
    manifest.signatureFormat,
    'bundle-manifest',
    bytes,
    manifest.signature,
    entry.publicKey,
    manifest.generatedAt,
    signatureCutoverMs(manifest),
  );
  return ok === true
    ? { ok: true, checked: 1, failed: 0 }
    : {
        ok: false,
        checked: 1,
        failed: 1,
        reason: ok === false ? 'manifest signature does not verify' : ok,
      };
}

/**
 * BUG-AUDIT-01 — Compare the SIGNED `rowCount` / `rootCount` (both in
 * the manifest signable set, so covered by the manifest signature)
 * against the number of rows / roots actually decoded from the bundle.
 *
 * The chain check (`verifyChain`) only validates predecessor links
 * among the rows that are PRESENT, and the inclusion-proof check only
 * walks the proofs that are PRESENT — so deleting the trailing N rows
 * plus their proofs leaves a shorter-but-still-consistent prefix that
 * otherwise passes every other component. This check is the only place
 * the verifier binds "how many rows the signer committed to" against
 * "how many rows we were handed", so it MUST participate in `ok`.
 *
 * `checked = 2` (the row-count assertion + the root-count assertion), or
 * `3` on a `version >= 4` manifest (see FIX01 F5(b) below).
 */
function verifyCompleteness(
  manifest: BundleManifest,
  rows: BundleRow[],
  roots: BundleRoot[],
  checkpoints: BundleIntegrityCheckpoint[],
): RawComponentResult {
  let checked = 2;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  if (rows.length !== manifest.rowCount) {
    failed += 1;
    firstFailure = 'rows';
    reason = `row count mismatch: bundle has ${rows.length} rows but signed manifest declares ${manifest.rowCount}`;
  }
  if (roots.length !== manifest.rootCount) {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = 'roots';
      reason = `root count mismatch: bundle has ${roots.length} roots but signed manifest declares ${manifest.rootCount}`;
    }
  }
  // FIX01 F5(b) / manifest-v4 — bind the SIGNED `integrityCheckpointCount`
  // to what is actually present, same anti-suppression rationale as
  // `rowCount`/`rootCount`: without this, an attacker who can delete
  // `audit_integrity_checkpoints` rows before an honest re-export would
  // get a smaller, honestly re-signed count with nothing to catch it.
  if (manifest.version >= 4) {
    checked += 1;
    if (checkpoints.length !== manifest.integrityCheckpointCount) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = 'integrityCheckpoints';
        reason = `integrity checkpoint count mismatch: bundle has ${checkpoints.length} checkpoints but signed manifest declares ${manifest.integrityCheckpointCount}`;
      }
    }
  }
  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/**
 * BUG-AUDIT-03 — Cross-check the verification keys against the SIGNED
 * key set.
 *
 * Every row/root/manifest signature is verified with a key pulled from
 * the UNSIGNED `public-keys.json`. `manifest.keyVersions[]` carries the
 * same keys but IS covered by the manifest signature (it sits in the
 * manifest signable set). Without this check the two are only compared
 * self-referentially, so an attacker who can swap `public-keys.json`
 * (and re-sign the rows with their own key) produces a bundle that
 * verifies against its own planted key — the platform attestation is the
 * only thing that would catch it, and that entry is OPTIONAL.
 *
 * Here we require every key present in `public-keys.json` to be
 * byte-identical to the `manifest.keyVersions` entry of the same version.
 * Because the manifest signature already gates `manifest.keyVersions`,
 * binding the trusted keys to it means a verification key cannot be
 * swapped without breaking the manifest signature too. `checked` counts
 * one assertion per key version in `public-keys.json`.
 *
 * PROD15 — `manifest.keyVersions[]` also carries `status`/`revokedAt`
 * (AUDIT-2026-05-14, optional for v1 bundles) but nothing previously
 * compared it to `public-keys.json`. `verifyRowSignatures` /
 * `verifyRootSignatures` read revocation status only from the UNSIGNED
 * `public-keys.json`, so — whenever platform attestation is skipped via
 * `allowLegacyUnattested` — an attacker who edits only that file to
 * relabel a REVOKED key ACTIVE could resurrect signatures made under a
 * compromised key. When the signed manifest entry carries a status, we
 * now also require `status`/`revokedAt` to match; when it does not
 * (true v1 bundles), we fall back to trusting `public-keys.json` alone
 * so those bundles keep verifying.
 *
 * RA-05 (PROD15 re-attack) Gap 2 — the per-entry `status !== undefined`
 * gate above was itself attacker-selectable: the exporter (AUDIT-2026-05-14,
 * `bundle-exporter.service.ts`) bumps `manifest.version` to 2 in the SAME
 * change that starts stamping `status`/`revokedAt` on every
 * `keyVersions[]` entry, so a genuine v2 manifest ALWAYS carries a status
 * for every key. A holder of a compromised key re-signing a fresh v2-shaped
 * manifest could omit `status` on just that one entry (structurally legal —
 * `assertManifestStructure` does not require it) to fall through to the
 * lenient "trust public-keys.json alone" branch while still claiming
 * `version: 2`. We now also require the lifecycle cross-check whenever
 * `manifest.version >= 2`, regardless of whether the signed entry bothered
 * to carry a `status`: an absent signed `status` on a v2 manifest can never
 * equal `usedRecord.status` (which is always a defined enum), so it fails
 * closed as `key_status_mismatch` rather than silently falling back. A
 * TRUE v1 bundle (`manifest.version === 1`) that never carried the field at
 * all is unaffected and keeps verifying under the original fallback — this
 * does not (and structurally cannot) close an attacker who forges the
 * ENTIRE bundle, including `manifest.version: 1` and a v1-shaped
 * `public-keys.json`; that residual is the same trust limit `--allow-legacy
 * -unattested` already accepts for genuinely old, pre-AUDIT-14 archives
 * (see the package README / RA-05 Gap 2 discussion) and requires mandatory
 * platform attestation to close, which is a documented, deliberate escape
 * hatch this fix does not touch.
 */
function verifyKeyBinding(
  manifest: BundleManifest,
  publicKeysRaw: Record<string, unknown>,
  publicKeys: Map<number, PublicKeyRecord>,
): RawComponentResult {
  const signed = new Map<
    number,
    { publicKey: Uint8Array; status?: string; revokedAt?: string | null }
  >();
  for (const kv of manifest.keyVersions) {
    if (typeof kv.publicKey === 'string') {
      const decoded = decodeBase64Strict(kv.publicKey);
      if (decoded === null) continue;
      signed.set(kv.keyVersion, {
        publicKey: new Uint8Array(decoded),
        status: kv.status,
        revokedAt: kv.revokedAt,
      });
    }
  }

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;

  for (const [k, raw] of Object.entries(publicKeysRaw)) {
    checked += 1;
    const ver = Number(k);
    const usedB64 = extractPublicKeyB64(raw);
    if (usedB64 === null) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `public-keys.json[${k}] has no decodable publicKey`;
      }
      continue;
    }
    const decoded = decodeBase64Strict(usedB64);
    if (decoded === null) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `public-keys.json[${k}] is not canonical base64`;
      }
      continue;
    }
    const usedBytes = new Uint8Array(decoded);
    const signedEntry = signed.get(ver);
    if (signedEntry === undefined) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `key_not_in_signed_manifest: public-keys.json declares keyVersion ${k} which is absent from the signed manifest.keyVersions`;
      }
      continue;
    }
    if (!bytesEqual(usedBytes, signedEntry.publicKey)) {
      failed += 1;
      if (firstFailure === undefined) {
        firstFailure = k;
        reason = `key_bytes_mismatch: public-keys.json[${k}] bytes differ from the signed manifest.keyVersions[${k}]`;
      }
      continue;
    }
    // PROD15 — Bind lifecycle metadata too, not just key bytes.
    //
    // `status`/`revokedAt` on `manifest.keyVersions[]` are optional
    // (true v1 bundles pre-date AUDIT-14 and never carried them). Only
    // enforce the cross-check when the SIGNED manifest actually declares
    // a status for this key version; otherwise fall back to trusting
    // `public-keys.json` alone, exactly as before, so genuine legacy
    // bundles keep verifying. When the signed manifest DOES carry a
    // status, an attacker who edits only the unsigned public-keys.json
    // to relabel a REVOKED key as ACTIVE (or clear revokedAt) must not
    // be able to resurrect that key's signatures merely because platform
    // attestation was skipped.
    //
    // RA-05 Gap 2 — a v2 manifest (`manifest.version >= 2`) is REQUIRED to
    // carry a status on every entry (the exporter change that introduced
    // `status`/`revokedAt` is the same change that bumped the version), so
    // an omitted `status` on a v2-labelled manifest is never legitimate.
    // Force the cross-check to run in that case too — `usedRecord.status`
    // is always a defined enum, so it can never equal an omitted `undefined`
    // signed status, and the entry fails closed as `key_status_mismatch`
    // instead of silently taking the true-v1 fallback.
    if (manifest.version >= 2 || signedEntry.status !== undefined) {
      const usedRecord = publicKeys.get(ver);
      if (
        usedRecord === undefined ||
        usedRecord.status !== signedEntry.status
      ) {
        failed += 1;
        if (firstFailure === undefined) {
          firstFailure = k;
          reason = `key_status_mismatch: public-keys.json[${k}] status differs from the signed manifest.keyVersions[${k}]`;
        }
        continue;
      }
      const signedRevokedAtTime =
        signedEntry.revokedAt == null
          ? null
          : Date.parse(signedEntry.revokedAt);
      const usedRevokedAtTime =
        usedRecord.revokedAt === null ? null : usedRecord.revokedAt.getTime();
      const signedRevokedAtInvalid =
        signedEntry.revokedAt != null && Number.isNaN(signedRevokedAtTime);
      if (signedRevokedAtInvalid || signedRevokedAtTime !== usedRevokedAtTime) {
        failed += 1;
        if (firstFailure === undefined) {
          firstFailure = k;
          reason = `key_revoked_at_mismatch: public-keys.json[${k}] revokedAt differs from the signed manifest.keyVersions[${k}]`;
        }
      }
    }
  }

  // Exact-set binding in the other direction: a signed manifest key must
  // not disappear from the unsigned lookup file merely because no surviving
  // row happens to reference it. Suppression is still a bundle-integrity
  // mismatch and can otherwise hide lifecycle history from an auditor.
  for (const ver of signed.keys()) {
    if (publicKeys.has(ver)) continue;
    checked += 1;
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = String(ver);
      reason = `signed_key_missing_from_public_keys: manifest.keyVersions declares keyVersion ${ver} which is absent from public-keys.json`;
    }
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/** Extract the base64 public key from a `public-keys.json` entry (string or object shape). */
function extractPublicKeyB64(raw: unknown): string | null {
  if (typeof raw === 'string') return raw;
  if (raw && typeof raw === 'object') {
    const pk = (raw as { publicKey?: unknown }).publicKey;
    if (typeof pk === 'string') return pk;
  }
  return null;
}

/** Constant-time-ish byte comparison (length + content). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** First index in a sorted ascending array with value >= target. */
function lowerBound(sorted: number[], target: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (sorted[mid]! < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * PROD16 (be-compliance F5(a) / audit-verifier's half of the same finding).
 * See the `rootCoverage` field doc comment on {@link VerifyReport} for the
 * full rationale. Uses independent binary-search counts per root (not a
 * shared advancing pointer) so the result is correct even if a forged
 * bundle declares overlapping root periods.
 */
function verifyRootCoverage(
  manifest: BundleManifest,
  rows: BundleRow[],
  roots: BundleRoot[],
  proofs: BundleProofEntry[],
  verifiedSeals: BundleSealedPurge[],
  supersessions: Supersessions,
): RawComponentResult {
  const fromMs = Date.parse(manifest.from);
  const toMs = Date.parse(manifest.to);

  const proofCountByRootHash = new Map<string, number>();
  for (const proof of proofs) {
    if (typeof proof.rootHash === 'string') {
      proofCountByRootHash.set(
        proof.rootHash,
        (proofCountByRootHash.get(proof.rootHash) ?? 0) + 1,
      );
    }
  }

  const verifiedSealByRootAndCount = new Map<string, BundleSealedPurge>();
  for (const seal of verifiedSeals) {
    const key = [
      seal.periodStart,
      seal.periodEnd,
      seal.rootHash,
      seal.rowCount,
    ].join('\0');
    if (!verifiedSealByRootAndCount.has(key)) {
      verifiedSealByRootAndCount.set(key, seal);
    }
  }
  const matchingSeal = (
    root: BundleRoot,
    missingCount: number,
  ): BundleSealedPurge | null => {
    // A seal can only account for complete removal of the root's committed
    // rows under the existing contract. Include both committed and missing
    // counts in the predicate before the O(1) lookup.
    if (root.rowCount !== missingCount) return null;
    return (
      verifiedSealByRootAndCount.get(
        [
          root.periodStart,
          root.periodEnd,
          root.rootHash,
          String(root.rowCount),
        ].join('\0'),
      ) ?? null
    );
  };

  const rowTimes: number[] = [];
  for (const row of rows) {
    if (typeof row.signedAt === 'string') {
      const t = Date.parse(row.signedAt);
      if (!Number.isNaN(t)) rowTimes.push(t);
    }
  }
  rowTimes.sort((a, b) => a - b);

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const sealExemptions: string[] = [];
  const supersessionLines: string[] = [];

  // AV-0016 — every invalid link fails; every valid link must keep the
  // superseded root's rows: each row proven into it is proven into its
  // successor too (with the per-root proof count below, a row subset).
  checked += supersessions.errors.length + supersessions.successorOf.size;
  for (const e of supersessions.errors) {
    failed += 1;
    if (!firstFailure) {
      firstFailure = e.rootId;
      reason = e.reason;
    }
  }
  const proofKeys = new Set(proofs.map((p) => `${p.rowId}\0${String(p.rootHash)}`));
  for (const old of roots) {
    const next = supersessions.successorOf.get(old.id);
    if (!next) continue;
    const dropped = proofs.find(
      (p) => p.rootHash === old.rootHash && !proofKeys.has(`${p.rowId}\0${next.rootHash}`),
    );
    if (dropped) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = next.id;
        reason = `root ${next.id} supersedes root ${old.id} but does not prove its row ${dropped.rowId} — a superseding root must keep every row of the root it supersedes`;
      }
      continue;
    }
    supersessionLines.push(
      `superseded: root ${old.id} (rootHash ${old.rootHash}, rowCount ${old.rowCount}, ${collectAnchorEntries(old).length} anchor receipt(s), checked under rekor) superseded by root ${next.id} (rootHash ${next.rootHash}, rowCount ${next.rowCount}) for period ${old.periodStart}..${old.periodEnd}`,
    );
  }

  for (const root of roots) {
    const periodStartMs = Date.parse(root.periodStart);
    const periodEndMs = Date.parse(root.periodEnd);
    // Only assert full coverage for periods entirely inside the bundle's
    // declared range — a boundary period legitimately ships fewer rows
    // than its full rowCount, since rows outside [from, to) are never
    // exported (see bundle-exporter.service.ts's root-selection query).
    if (!(periodStartMs >= fromMs && periodEndMs <= toMs)) {
      continue;
    }
    checked += 1;
    const rowsInPeriod =
      lowerBound(rowTimes, periodEndMs) - lowerBound(rowTimes, periodStartMs);
    // AV-0016 — a superseded root committed to fewer rows than its hour
    // holds; its successor carries the rows-in-period check. Its proof count
    // below is still enforced.
    if (rowsInPeriod !== root.rowCount && !supersessions.successorOf.has(root.id)) {
      // FIX01 (audit-verifier2) / `BE-0003` — only a SHRINKAGE
      // (rowsInPeriod < root.rowCount) is a candidate for the sealed-purge
      // exemption. A period that has MORE rows than its own signed root
      // committed to is a different, unexplained anomaly a purge record
      // can never account for, so that direction keeps failing
      // unconditionally regardless of any matching seal.
      const seal =
        rowsInPeriod < root.rowCount
          ? matchingSeal(root, root.rowCount - rowsInPeriod)
          : null;
      if (seal) {
        sealExemptions.push(
          `seal_exempted: root ${root.id} for period ${root.periodStart}..${root.periodEnd} legitimately purged per AuditRetentionSeal ${seal.id} (approval ${seal.approvalId})`,
        );
        continue;
      }
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = `root ${root.id} commits to rowCount ${root.rowCount} but the bundle contains ${rowsInPeriod} rows with signedAt inside its period — a fully-anchored period must not lose rows (unless explained by a verified AuditRetentionSeal covering this exact period+root — none found)`;
      }
      continue;
    }
    const proofsForRoot = proofCountByRootHash.get(root.rootHash) ?? 0;
    if (proofsForRoot !== root.rowCount) {
      const seal =
        proofsForRoot < root.rowCount
          ? matchingSeal(root, root.rowCount - proofsForRoot)
          : null;
      if (seal) {
        sealExemptions.push(
          `seal_exempted: root ${root.id} for period ${root.periodStart}..${root.periodEnd} legitimately purged per AuditRetentionSeal ${seal.id} (approval ${seal.approvalId})`,
        );
        continue;
      }
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = `root ${root.id} commits to rowCount ${root.rowCount} but the bundle contains ${proofsForRoot} proof entries referencing it (unless explained by a verified AuditRetentionSeal covering this exact period+root — none found)`;
      }
    }
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
    ...(sealExemptions.length > 0 ? { sealExemptions } : {}),
    ...(supersessionLines.length > 0 ? { supersessions: supersessionLines } : {}),
  };
}

/**
 * FIX01 F5(b) — see the `integrityCheckpoints` field doc comment on
 * {@link VerifyReport} for the full rationale and the documented residual
 * (legitimate `AuditRetentionSeal` purges can trigger these reasons too).
 *
 * No-ops (returns `{ok:true, checked:0, failed:0}`) for `manifest.version
 * < 4` — earlier manifests carry no checkpoint commitment at all, so
 * there is nothing to check, not a pass on a claim that was never made.
 */
function verifyIntegrityCheckpoints(
  manifest: BundleManifest,
  rows: BundleRow[],
  checkpoints: BundleIntegrityCheckpoint[],
  publicKeys: Map<number, PublicKeyRecord>,
  verifiedSeals: BundleSealedPurge[],
  cutoverMs: number | null,
): RawComponentResult {
  if (manifest.version < 4) {
    return { ok: true, checked: 0, failed: 0 };
  }

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const sealExemptions: string[] = [];
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  // 1) Per-checkpoint signature authenticity — same REVOKED-key-rejection
  // rule as rows/roots. This is the part of F5(b) with NO known
  // false-positive path: it only fails on a genuinely wrong signature, a
  // signature under a key not in this bundle's own signed set, or a
  // REVOKED key.
  for (const cp of checkpoints) {
    checked += 1;
    const entry = publicKeys.get(cp.keyVersion);
    if (!entry) {
      fail(
        cp.id,
        `checkpoint keyVersion ${cp.keyVersion} not in public-keys.json`,
      );
      continue;
    }
    if (entry.status === 'REVOKED') {
      fail(cp.id, 'key_revoked');
      continue;
    }
    const message = canonicalJson({
      organizationId: cp.organizationId,
      chainHeadHash: cp.chainHeadHash,
      cumulativeRowCount: cp.cumulativeRowCount,
      asOf: cp.asOf,
    });
    const cpOk = verifyTenantSignature(
      cp.signatureAlgorithm, cp.signatureFormat, 'integrity-checkpoint', message, cp.signature, entry.publicKey, cp.asOf, cutoverMs,
    );
    if (cpOk !== true) {
      fail(cp.id, cpOk === false ? 'checkpoint signature does not verify' : cpOk);
    }
  }

  // 2) `cumulativeRowCount` must be monotonically non-decreasing in `asOf`
  // order. Compared as BigInt (the wire value is bigint-as-string) to
  // avoid Number precision loss on a very chatty tenant.
  //
  // FIX01 (audit-verifier2) — `AuditRetentionSealService.purgeWithSeal` can
  // legitimately DECREASE this value. The pre-indexed purge-window check
  // downgrades this to a pass ONLY when a VERIFIED seal (or seals) whose
  // `deletedAt`
  // falls in `(prev.asOf, cur.asOf]` sums to at least the observed
  // decrease. An empty seal window is never treated as reconciling even
  // when the arithmetic is trivially satisfied.
  const byAsOf = [...checkpoints].sort(
    (a, b) => Date.parse(a.asOf) - Date.parse(b.asOf),
  );
  const checkpointTimes = byAsOf.map((cp) => Date.parse(cp.asOf));
  const checkpointIndexById = new Map(
    byAsOf.map((cp, index) => [cp.id, index] as const),
  );

  // Adjacent checkpoint windows are disjoint. Assign each verified seal to
  // its one `(prev.asOf, cur.asOf]` window once, instead of filtering the
  // full seal list for every checkpoint comparison.
  const sealsByWindow: BundleSealedPurge[][] = Array.from(
    { length: byAsOf.length },
    () => [],
  );
  const sealRowsByWindow = Array.from({ length: byAsOf.length }, () => 0n);
  for (const seal of verifiedSeals) {
    const sealTime = Date.parse(seal.deletedAt);
    const windowIndex = lowerBound(checkpointTimes, sealTime);
    if (
      windowIndex <= 0 ||
      windowIndex >= checkpointTimes.length ||
      sealTime <= checkpointTimes[windowIndex - 1]!
    ) {
      continue;
    }
    sealsByWindow[windowIndex]!.push(seal);
    sealRowsByWindow[windowIndex] =
      sealRowsByWindow[windowIndex]! + BigInt(seal.rowCount);
  }
  const reconcileAtIndex = (
    index: number,
    decrease: bigint,
  ): { exempted: boolean; seals: BundleSealedPurge[] } => {
    const seals = sealsByWindow[index] ?? [];
    return {
      exempted: seals.length > 0 && decrease <= (sealRowsByWindow[index] ?? 0n),
      seals,
    };
  };

  // Compute each row's canonical link once, then advance a tip set as the
  // sorted checkpoints move forward. This preserves the former per-window
  // link-not-claimed semantics while reducing C checkpoints x R rows work
  // to one row sort plus a single advancing pass.
  const timedRows = rows
    .map((row) => ({
      row,
      time:
        typeof row.signedAt === 'string'
          ? Date.parse(row.signedAt)
          : Number.POSITIVE_INFINITY,
      link: computeChainLink(row),
    }))
    .sort((a, b) => a.time - b.time);
  const chainLinkByRow = new Map(
    timedRows.map(({ row, link }) => [row, link] as const),
  );
  const claimedLinks = new Set<string>();
  const candidateTips = new Set<BundleRow>();
  const candidatesByLink = new Map<string, BundleRow[]>();
  const tipsByCheckpointId = new Map<string, BundleRow | null>();
  let rowCursor = 0;
  for (
    let checkpointIndex = 0;
    checkpointIndex < byAsOf.length;
    checkpointIndex++
  ) {
    const checkpointTime = checkpointTimes[checkpointIndex]!;
    while (
      rowCursor < timedRows.length &&
      timedRows[rowCursor]!.time <= checkpointTime
    ) {
      const timed = timedRows[rowCursor]!;
      rowCursor += 1;
      if (typeof timed.row.prevRowHash === 'string') {
        claimedLinks.add(timed.row.prevRowHash);
        const predecessors = candidatesByLink.get(timed.row.prevRowHash);
        if (predecessors) {
          for (const predecessor of predecessors) {
            candidateTips.delete(predecessor);
          }
          candidatesByLink.delete(timed.row.prevRowHash);
        }
      }
      if (timed.link !== null && !claimedLinks.has(timed.link)) {
        candidateTips.add(timed.row);
        const sameLink = candidatesByLink.get(timed.link) ?? [];
        sameLink.push(timed.row);
        candidatesByLink.set(timed.link, sameLink);
      }
    }
    const soleTip =
      candidateTips.size === 1
        ? (candidateTips.values().next().value ?? null)
        : null;
    tipsByCheckpointId.set(byAsOf[checkpointIndex]!.id, soleTip);
  }
  // Precomputed once, shared with the chainHeadHash loop (3) below so both
  // checks reconcile against the exact same prev/cur pair and BigInt
  // parse — `null` marks a checkpoint whose cumulativeRowCount failed to
  // parse (already reported as its own failure here; the hash-mismatch
  // loop below silently skips reconciliation for such a pair rather than
  // double-reporting the format error).
  const countsByAsOf: Array<bigint | null> = byAsOf.map((cp) => {
    try {
      return BigInt(cp.cumulativeRowCount);
    } catch {
      return null;
    }
  });
  for (let i = 1; i < byAsOf.length; i++) {
    checked += 1;
    const prev = byAsOf[i - 1]!;
    const cur = byAsOf[i]!;
    const prevCount = countsByAsOf[i - 1];
    const curCount = countsByAsOf[i];
    if (prevCount === null || curCount === null) {
      fail(
        cur.id,
        'checkpoint cumulativeRowCount is not a valid integer string',
      );
      continue;
    }
    if (curCount < prevCount) {
      const decrease = prevCount - curCount;
      const { exempted, seals } = reconcileAtIndex(i, decrease);
      if (exempted) {
        sealExemptions.push(
          `seal_exempted: cumulativeRowCount decrease of ${decrease} between checkpoints ${prev.asOf}..${cur.asOf} reconciled by AuditRetentionSeal(s) ${seals.map((s) => `${s.id} (approval ${s.approvalId})`).join(', ')}`,
        );
        continue;
      }
      fail(
        cur.id,
        `cumulative_row_count_decreased: checkpoint at ${cur.asOf} claims cumulativeRowCount ${curCount} but an earlier checkpoint at ${prev.asOf} claimed ${prevCount} — a decrease means rows were deleted between these two signed snapshots and no verified AuditRetentionSeal in sealed-purges.ndjson.gz accounts for it (confirm against the org's AuditRetentionSeal records before treating this as tampering)`,
      );
    }
  }

  // 3) Each checkpoint's `chainHeadHash` must match the true tip of the
  // bundle's OWN rows restricted to `signedAt <= asOf`. This subsumes both
  // halves of the originally-recommended algorithm (recompute the latest
  // head; walk an earlier head backward) into one per-checkpoint check.
  //
  // A checkpoint whose window contains NO bundled rows is legitimately
  // ambiguous — either the org was dormant through `asOf` (its true head
  // predates the bundle's `[from, to)` range, a boundary case exactly like
  // `rootCoverage`'s boundary-period exemption) or a genuine
  // `AuditRetentionSeal` purge removed every row in that window. Neither
  // is distinguishable from the bundle alone, so it is SKIPPED (not
  // asserted), EXCEPT when the checkpoint itself claims the all-zero
  // genesis hash — that claim ("no rows existed yet") is fully consistent
  // with an empty window and is checked as a pass, not skipped.
  for (const cp of checkpoints) {
    const tip = tipsByCheckpointId.get(cp.id) ?? null;
    if (tip === null) {
      if (cp.chainHeadHash === GENESIS_PREV_ROW_HASH) {
        checked += 1; // consistent: no rows at/before asOf, claims genesis.
      }
      continue; // ambiguous (dormant/boundary/purged/broken) — not asserted.
    }
    checked += 1;
    const computedLink = chainLinkByRow.get(tip) ?? null;
    if (computedLink !== cp.chainHeadHash) {
      // FIX01 (audit-verifier2) — reconcile against the SAME prev/cur pair
      // and decrease amount as check (2) above, per the spec ("For a
      // cumulative_row_count_decreased OR chain_head_hash_mismatch finding
      // ... collect every verifiedSeals entry ..."). Only applies when `cp`
      // has a predecessor in asOf order; the very first checkpoint has
      // nothing to reconcile against and keeps failing as before (no
      // regression — this matches the pre-existing, unaffected behavior).
      const idx = checkpointIndexById.get(cp.id) ?? -1;
      let exempted = false;
      let sealNames: string[] = [];
      if (idx > 0) {
        const prevCount = countsByAsOf[idx - 1];
        const curCount = countsByAsOf[idx];
        if (prevCount !== null && curCount !== null) {
          const decrease = prevCount - curCount;
          const reconciled = reconcileAtIndex(idx, decrease);
          exempted = reconciled.exempted;
          sealNames = reconciled.seals.map(
            (s) => `${s.id} (approval ${s.approvalId})`,
          );
        }
      }
      if (exempted) {
        sealExemptions.push(
          `seal_exempted: chainHeadHash mismatch at checkpoint ${cp.id} (asOf ${cp.asOf}) reconciled by AuditRetentionSeal(s) ${sealNames.join(', ')}`,
        );
        continue;
      }
      fail(
        cp.id,
        `chain_head_hash_mismatch: checkpoint at ${cp.asOf} claims chainHeadHash ${cp.chainHeadHash} but the bundle's own rows (as of that instant) chain to ${String(computedLink)} — this means rows were altered or deleted after the checkpoint was signed and no verified AuditRetentionSeal in sealed-purges.ndjson.gz accounts for it`,
      );
    }
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
    ...(sealExemptions.length > 0 ? { sealExemptions } : {}),
  };
}

// ════════════════════════════════════════════════════════════════════════
// PA-0010 — action-event evidence components (manifest v5)
// ════════════════════════════════════════════════════════════════════════

/** Genesis previous-commitment value for a `protected_action_events` stream — 64 hex zeros, mirrors `protected-action-canonical.helper.ts`'s `GENESIS_EVENT_COMMITMENT`. */
const GENESIS_EVENT_COMMITMENT = '0'.repeat(64);

/**
 * D7 (`PA01-DECISIONS.md`, frozen) — re-derived independently here (never
 * imported from `be`, a separate published package) so `closureLegality`
 * does not trust `be`'s own transition logic, only the frozen DECISION.
 */
const PRE_DISPATCH_ALLOWED_CLOSURES = new Set([
  'DENIED',
  'EXPIRED',
  'CANCELLED_BEFORE_DISPATCH',
  'DUPLICATE_SUPPRESSED',
  'EVIDENCE_INCOMPLETE',
]);
const POST_DISPATCH_ALLOWED_CLOSURES = new Set([
  'TARGET_REJECTED',
  'SUCCEEDED',
  'FAILED_NO_EFFECT',
  'PARTIAL',
  'REVERSED',
  'OUTCOME_UNKNOWN',
  'EVIDENCE_INCOMPLETE',
  'DUPLICATE_SUPPRESSED',
]);
/** Closures that CLAIM positive evidence about what happened — the set `closureLegality` requires an actual evidencing event for, regardless of the declared `reason`. */
const EVIDENCE_CLAIMING_CLOSURES = new Set([
  'TARGET_REJECTED',
  'SUCCEEDED',
  'FAILED_NO_EFFECT',
  'PARTIAL',
  'REVERSED',
]);
const REASON_ALLOWED_CLOSURES: Record<string, Set<string>> = {
  // D7's hard rule, encoded structurally: a reason with NO positive
  // evidence about the outcome may never resolve to a closure that claims
  // to know it.
  TIMEOUT: new Set(['OUTCOME_UNKNOWN', 'EVIDENCE_INCOMPLETE']),
  EVIDENCED: EVIDENCE_CLAIMING_CLOSURES,
  POLICY: new Set(['DENIED']),
  EXPIRY: new Set(['EXPIRED']),
  CANCELLATION: new Set(['CANCELLED_BEFORE_DISPATCH']),
  REPLAY: new Set(['DUPLICATE_SUPPRESSED']),
};
const RECONCILABLE_FROM = new Set(['OUTCOME_UNKNOWN', 'EVIDENCE_INCOMPLETE']);
const RECONCILABLE_TO = new Set([
  ...EVIDENCE_CLAIMING_CLOSURES,
  'OUTCOME_UNKNOWN',
  'EVIDENCE_INCOMPLETE',
  'DUPLICATE_SUPPRESSED',
]);
const FIXED_ACTION_EVENT_TYPES = new Set([
  'ACTION_PROPOSED',
  'AUTHORITY_RESOLVED',
  'POLICY_DECIDED',
  'PERMIT_ISSUED',
  'PERMIT_CONSUMED',
  'DISPATCH_ATTEMPTED',
  'TARGET_ACKNOWLEDGED',
  'CALLER_RESULT_OBSERVED',
  'OUTCOME_RECONCILED',
  'ACTION_CLOSED',
]);

/** D9's fixed vocabulary plus its deliberately open compensation family. */
function isSupportedActionEventType(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    (FIXED_ACTION_EVENT_TYPES.has(value) ||
      // The producer intentionally defines `COMPENSATION_${string}` as an
      // open family and its database constraint accepts every literal
      // `COMPENSATION_` prefix. Match that contract byte-for-byte so a valid
      // future compensation subtype does not become unverifiable here.
      value.startsWith('COMPENSATION_'))
  );
}

/**
 * PA-0033 (HIGH-1 fix, `PA01-CONTRACT-manifest-v5-actions.md`) —
 * `CALLER_RESULT_OBSERVED.payload.outcomeClass`, paired with `be`'s
 * PA-0034. `payload.success` alone is NOT evidence of what happened: `be`'s
 * generic exception handler records a client-side TIMEOUT as
 * `success: false`, indistinguishable on that field alone from a target
 * that actually answered negatively. `outcomeClass` disambiguates:
 * `completed_success`/`completed_with_error` mean the target genuinely
 * answered (positive evidence, `success` must be `true`/`false`
 * respectively); `no_response_received` means no answer was ever obtained
 * (timeout/transport failure — `success` must be `false`, and this value
 * is exactly HIGH-1's shape). An unrecognized value is a structural
 * failure (`verifyCallerResult`) and, independently, `closureLegality`
 * never treats an unrecognized value as capable of justifying a
 * determined outcome (fail-closed either way).
 */
const CALLER_RESULT_OUTCOME_CLASS_EXPECTS_SUCCESS: Record<string, boolean> = {
  completed_success: true,
  completed_with_error: false,
  no_response_received: false,
};

/** Strict lowercase-hex decoder — mirrors `decodeBase64Strict`'s discipline for the event chain's hex-encoded commitments. */
function decodeHex64Strict(value: unknown): Buffer | null {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) return null;
  return Buffer.from(value, 'hex');
}

function isSha256HexDigest(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/**
 * Reconstructs the exact `SignableProtectedActionEventRow` shape
 * `protected-action-canonical.helper.ts` signs — see
 * {@link BundleActionEvent}'s SEC-PA01-DISCOVERED-01 doc comment for why
 * every one of these fields must be present on the wire for this to be
 * possible at all.
 */
function signableActionEvent(e: BundleActionEvent): Record<string, unknown> {
  return {
    organizationId: e.organizationId,
    actionId: e.actionId,
    actionSeq: String(e.actionSeq),
    eventType: e.eventType,
    schemaVersion: String(e.schemaVersion),
    issuerType: e.issuerType,
    issuerId: e.issuer,
    trustDomain: e.trustDomain,
    timeSource: e.timeSource,
    observedAt: e.observedAt,
    receivedAt: e.receivedAt,
    dispatched: e.dispatched,
    permitNonce: e.permitNonce,
    payload: e.payload,
    payloadCommitment: e.payloadCommitment,
    producerVersion: e.producerVersion,
    edgeVersion: e.edgeVersion,
    adapterVersion: e.adapterVersion,
    externalReceiptRef: e.externalReceiptRef,
    artifactStorageRef: e.artifactStorageRef,
    prevEventCommitment: e.prevEventCommitment,
  };
}

/**
 * Verifies one event's signature against `message = canonicalBytes ||
 * prevEventCommitmentBytes` (mirrors `ProtectedActionEventService.runAppend`
 * exactly) and, on success, independently RECOMPUTES this event's own
 * commitment (`sha256(canonicalBytes || sigBytes)`, hex) — the value the
 * verifier trusts for chain-walking, never the wire-declared
 * `eventCommitment` field.
 */
function verifyEventSignatureAndCommitment(
  e: BundleActionEvent,
  publicKeys: Map<number, PublicKeyRecord>,
  manifestAlgorithm: BundleSignatureAlgorithm,
  cutoverMs: number | null,
): { ok: boolean; reason?: string; computedCommitment: string | null } {
  const entry = publicKeys.get(e.keyVersion);
  if (!entry) {
    return {
      ok: false,
      reason: `event keyVersion ${e.keyVersion} not in public-keys.json`,
      computedCommitment: null,
    };
  }
  if (entry.status === 'REVOKED') {
    return { ok: false, reason: 'key_revoked', computedCommitment: null };
  }
  const prevBytes = decodeHex64Strict(e.prevEventCommitment);
  if (prevBytes === null) {
    return {
      ok: false,
      reason: 'event prevEventCommitment missing or malformed',
      computedCommitment: null,
    };
  }
  const canonical = canonicalJson(signableActionEvent(e));
  const message = Buffer.concat([canonical, prevBytes]);
  const algorithm = e.signatureAlgorithm ?? manifestAlgorithm;
  // AV-0018 — `receivedAt` (signed) is the event's latest signed timestamp.
  const eventOk = verifyTenantSignature(
    algorithm, e.signatureFormat, 'protected-action-event', message, e.signature, entry.publicKey, e.receivedAt, cutoverMs,
  );
  if (eventOk !== true) {
    return {
      ok: false,
      reason: eventOk === false ? 'event signature does not verify' : eventOk,
      computedCommitment: null,
    };
  }
  const sigBytes = decodeBase64Strict(e.signature);
  if (sigBytes === null) {
    return {
      ok: false,
      reason: 'event signature is not canonical base64',
      computedCommitment: null,
    };
  }
  const computedCommitment = sha256(
    Buffer.concat([canonical, sigBytes]),
  ).toString('hex');
  return { ok: true, computedCommitment };
}

/** Group action events by `actionId`, sorted by `actionSeq` ascending within each group. */
function groupActionEvents(
  events: BundleActionEvent[],
): Map<string, BundleActionEvent[]> {
  const byAction = new Map<string, BundleActionEvent[]>();
  for (const e of events) {
    const arr = byAction.get(e.actionId) ?? [];
    arr.push(e);
    byAction.set(e.actionId, arr);
  }
  for (const arr of byAction.values()) {
    arr.sort((a, b) => a.actionSeq - b.actionSeq);
  }
  return byAction;
}

/**
 * PA-0010 — per-`actionId` `actionSeq` monotonicity + `prevEventCommitment`
 * hash-chain walk, PLUS the per-event signature verification the chain-link
 * recomputation depends on. See {@link VerifyReport.actionEventChain}'s doc
 * comment for the full rationale, including the BUGHUNT-SDK-02-style
 * boundary-anchor exemption for the first event of each `actionId` present
 * in this bundle.
 */
function verifyActionEventChain(
  events: BundleActionEvent[],
  publicKeys: Map<number, PublicKeyRecord>,
  manifestAlgorithm: BundleSignatureAlgorithm,
  cutoverMs: number | null,
): RawComponentResult {
  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  const byAction = groupActionEvents(events);
  for (const [actionId, stream] of byAction) {
    let prevComputed: string | null = null;
    for (let i = 0; i < stream.length; i++) {
      const e = stream[i]!;
      const id = `${actionId}#${e.actionSeq}`;
      checked += 1;

      // Clock sanity: an event must never claim it was received before it
      // was observed (threat-model row #6, clock manipulation).
      const observedMs = Date.parse(e.observedAt);
      const receivedMs = Date.parse(e.receivedAt);
      if (
        Number.isNaN(observedMs) ||
        Number.isNaN(receivedMs) ||
        receivedMs < observedMs
      ) {
        fail(
          id,
          'clock_skew: receivedAt is before observedAt (or either is unparseable) — platform-received time can never precede issuer-observed time',
        );
        continue;
      }

      const sigResult = verifyEventSignatureAndCommitment(
        e,
        publicKeys,
        manifestAlgorithm,
        cutoverMs,
      );
      if (!sigResult.ok) {
        fail(id, sigResult.reason ?? 'event signature does not verify');
        prevComputed = null;
        continue;
      }
      if (e.eventCommitment !== sigResult.computedCommitment) {
        fail(
          id,
          'event_commitment_mismatch: wire eventCommitment does not match sha256(canonical event bytes || signature bytes)',
        );
      }

      if (i === 0) {
        // First event of this actionId present in the bundle. A genuine
        // genesis (actionSeq === 1) MUST declare the genesis commitment;
        // any other actionSeq is accepted as an opaque out-of-range
        // anchor (the action's earlier events fall before the bundle's
        // declared [from, to) range) — mirrors BUGHUNT-SDK-02.
        if (
          e.actionSeq === 1 &&
          e.prevEventCommitment !== GENESIS_EVENT_COMMITMENT
        ) {
          fail(
            id,
            'genesis_prev_event_commitment_mismatch: actionSeq 1 must declare the all-zero genesis prevEventCommitment',
          );
        }
      } else {
        const prev = stream[i - 1]!;
        if (e.actionSeq !== prev.actionSeq + 1) {
          fail(
            id,
            `action_event_seq_gap: actionSeq ${e.actionSeq} does not immediately follow ${prev.actionSeq} for actionId ${actionId} — actionSeq must be monotonic and gapless within the bundle`,
          );
        } else if (e.prevEventCommitment !== prevComputed) {
          fail(
            id,
            "action_event_chain_break: prevEventCommitment does not match the independently recomputed commitment of the previous event in this actionId's stream",
          );
        }
      }
      prevComputed = sigResult.computedCommitment;
    }
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/** Extract a non-empty string field from a payload, or `null`. */
function payloadStr(
  payload: Record<string, unknown> | null,
  key: string,
): string | null {
  const v = payload?.[key];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/**
 * PA-0010 (D2, SEC-PA01-01/corrigendum C1) — see
 * {@link VerifyReport.permitBinding}'s doc comment.
 */
function verifyPermitBinding(events: BundleActionEvent[]): RawComponentResult {
  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  const consumedNonceToEvent = new Map<string, string>();
  const destinationCommitmentToActionIds = new Map<string, Set<string>>();
  const byAction = groupActionEvents(events);
  for (const [actionId, stream] of byAction) {
    const issuedEvents = stream.filter((e) => e.eventType === 'PERMIT_ISSUED');
    const consumedEvents = stream.filter(
      (e) => e.eventType === 'PERMIT_CONSUMED',
    );
    for (const consumed of consumedEvents) {
      checked += 1;
      const id = `${actionId}#${consumed.actionSeq}`;
      const signedNonce =
        typeof consumed.permitNonce === 'string' &&
        consumed.permitNonce.length > 0
          ? consumed.permitNonce
          : null;
      const payloadNonce = payloadStr(consumed.payload, 'permitNonce');
      if (!signedNonce) {
        fail(
          id,
          'PERMIT_CONSUMED.permitNonce is missing or empty — the signed top-level field is the durable single-use key',
        );
      }
      if (!payloadNonce) {
        fail(id, 'PERMIT_CONSUMED.payload.permitNonce is missing or empty');
      }
      if (signedNonce && payloadNonce && signedNonce !== payloadNonce) {
        fail(
          id,
          'permit_nonce_mirror_mismatch: PERMIT_CONSUMED.permitNonce does not match payload.permitNonce',
        );
      }

      if (signedNonce) {
        const prior = consumedNonceToEvent.get(signedNonce);
        if (prior) {
          fail(
            id,
            `permit_nonce_reused: permitNonce "${signedNonce}" is consumed more than once (${prior}, ${id}) — the durable unique gate permits exactly one PERMIT_CONSUMED row per nonce`,
          );
        } else {
          consumedNonceToEvent.set(signedNonce, id);
        }
      }

      const consumedCommitment = payloadStr(
        consumed.payload,
        'requestCommitment',
      );
      if (!isSha256HexDigest(consumedCommitment ?? undefined)) {
        fail(
          id,
          'PERMIT_CONSUMED.payload.requestCommitment is missing or not a well-formed sha256 hex digest',
        );
      }

      const issued = [...issuedEvents]
        .reverse()
        .find((candidate) => candidate.actionSeq < consumed.actionSeq);
      if (issued) {
        const issuedPermitId = payloadStr(issued.payload, 'permitId');
        if (!issuedPermitId) {
          fail(id, 'PERMIT_ISSUED.payload.permitId is missing or empty');
        } else if (signedNonce && issuedPermitId !== signedNonce) {
          fail(
            id,
            'permit_binding_mismatch: PERMIT_CONSUMED.permitNonce does not match the most recent preceding PERMIT_ISSUED.payload.permitId',
          );
        }
        const issuedCommitment = payloadStr(
          issued.payload,
          'requestCommitment',
        );
        if (!isSha256HexDigest(issuedCommitment ?? undefined)) {
          fail(
            id,
            'PERMIT_ISSUED.payload.requestCommitment is missing or not a well-formed sha256 hex digest',
          );
        } else if (
          consumedCommitment &&
          issuedCommitment !== consumedCommitment
        ) {
          fail(
            id,
            'permit_request_commitment_mismatch: PERMIT_ISSUED and PERMIT_CONSUMED disagree on requestCommitment for the same actionId — D2 commitment substitution',
          );
        }
      }

      const destinationCommitment =
        consumed.payload?.destinationIdempotencyCommitment;
      if (
        destinationCommitment !== undefined &&
        destinationCommitment !== null
      ) {
        if (!isSha256HexDigest(destinationCommitment)) {
          fail(
            id,
            'PERMIT_CONSUMED.payload.destinationIdempotencyCommitment is present but not a well-formed sha256 hex digest',
          );
        } else {
          const actionIds =
            destinationCommitmentToActionIds.get(destinationCommitment) ??
            new Set<string>();
          actionIds.add(actionId);
          destinationCommitmentToActionIds.set(
            destinationCommitment,
            actionIds,
          );
        }
      }
    }
  }

  // CLOSE-005 — the projection's tenant-scoped unique index permits a
  // commitment to map to at most one actionId. Repeated attempts under the
  // SAME actionId are legitimate; a second distinct actionId is not.
  for (const [commitment, actionIds] of destinationCommitmentToActionIds) {
    if (actionIds.size > 1) {
      checked += 1;
      fail(
        commitment,
        `destination_idempotency_reused: destinationIdempotencyCommitment "${commitment}" was consumed by ${actionIds.size} distinct actionIds (${[...actionIds].join(', ')}) — the durable double-apply gate maps one commitment to at most one actionId`,
      );
    }
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/** PA-0010 (D2) — see {@link VerifyReport.requestBinding}'s doc comment. */
function verifyRequestBinding(events: BundleActionEvent[]): RawComponentResult {
  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  const byAction = groupActionEvents(events);
  for (const [actionId, stream] of byAction) {
    const consumedEvents = stream.filter(
      (e) => e.eventType === 'PERMIT_CONSUMED',
    );
    for (const dispatched of stream.filter(
      (e) => e.eventType === 'DISPATCH_ATTEMPTED',
    )) {
      checked += 1;
      const id = `${actionId}#${dispatched.actionSeq}`;
      const dispatchCommitment = payloadStr(
        dispatched.payload,
        'requestCommitment',
      );
      if (!isSha256HexDigest(dispatchCommitment ?? undefined)) {
        fail(
          id,
          'DISPATCH_ATTEMPTED.payload.requestCommitment is missing or not a well-formed sha256 hex digest',
        );
        continue;
      }
      const consumed = [...consumedEvents]
        .reverse()
        .find((candidate) => candidate.actionSeq < dispatched.actionSeq);
      if (!consumed) {
        if (consumedEvents.length > 0) {
          fail(
            id,
            'permit_consumed_after_dispatch: this action has PERMIT_CONSUMED evidence, but none precedes DISPATCH_ATTEMPTED',
          );
        }
        continue; // observe-mode dispatches legitimately have no permit.
      }
      const consumedCommitment = payloadStr(
        consumed.payload,
        'requestCommitment',
      );
      if (!isSha256HexDigest(consumedCommitment ?? undefined)) {
        fail(
          id,
          'PERMIT_CONSUMED.payload.requestCommitment is missing or not a well-formed sha256 hex digest',
        );
      } else if (consumedCommitment !== dispatchCommitment) {
        fail(
          id,
          'commitment_mismatch: DISPATCH_ATTEMPTED and the preceding PERMIT_CONSUMED disagree on requestCommitment for the same actionId — request substitution (threat-model row #2)',
        );
      }
    }
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/** PA-0010 (D9) — see {@link VerifyReport.dispatchIntegrity}'s doc comment. */
function verifyDispatchIntegrity(
  events: BundleActionEvent[],
): RawComponentResult {
  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  const byAction = groupActionEvents(events);
  for (const [actionId, stream] of byAction) {
    for (const e of stream.filter(
      (x) => x.eventType === 'DISPATCH_ATTEMPTED',
    )) {
      checked += 1;
      if (e.dispatched !== true) {
        fail(
          `${actionId}#${e.actionSeq}`,
          'DISPATCH_ATTEMPTED event must carry dispatched: true (D9)',
        );
      }
    }
    const closed = stream.find((e) => e.eventType === 'ACTION_CLOSED');
    if (!closed) continue;
    const closure = payloadStr(closed.payload, 'closure');
    if (!closure) continue;
    const reachedDispatch = stream.some(
      (e) => e.eventType === 'DISPATCH_ATTEMPTED' && e.dispatched === true,
    );
    checked += 1;
    const id = `${actionId}#${closed.actionSeq}`;
    if (
      POST_DISPATCH_ALLOWED_CLOSURES.has(closure) &&
      !PRE_DISPATCH_ALLOWED_CLOSURES.has(closure) &&
      !reachedDispatch
    ) {
      fail(
        id,
        `dispatch_evidence_missing: closure "${closure}" requires a prior DISPATCH_ATTEMPTED(dispatched:true) event, none found for actionId ${actionId}`,
      );
    }
    if (
      PRE_DISPATCH_ALLOWED_CLOSURES.has(closure) &&
      !POST_DISPATCH_ALLOWED_CLOSURES.has(closure) &&
      reachedDispatch
    ) {
      fail(
        id,
        `dispatch_evidence_contradiction: closure "${closure}" is pre-dispatch-only but a DISPATCH_ATTEMPTED(dispatched:true) event exists for actionId ${actionId}`,
      );
    }
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

interface HttpTargetActionContext {
  stream: BundleActionEvent[];
  closed: BundleActionEvent | undefined;
  legal: boolean;
}

/** Verify a target under a separately supplied identity pin and the original request/result evidence. */
function verifiedHttpTarget(event: BundleActionEvent, events: BundleActionEvent[], pins: VerifyOptions['targetPublicKeys'], contexts: Map<string, HttpTargetActionContext>): boolean {
  try {
    const payload = event.payload;
    if (!payload || !payload.receipt || typeof payload.receipt !== 'object') return false;
    const receipt = payload.receipt as { statement?: Record<string, unknown> };
    const statement = receipt.statement;
    if (payload.signatureAlgorithm !== 'Ed25519' || payload.targetSignature !== (payload.receipt as { signature?: unknown }).signature) return false;
    if (!statement || typeof statement.targetId !== 'string' || typeof statement.keyId !== 'string') return false;
    const pin = pins?.[`${event.organizationId}:${statement.targetId}:${statement.keyId}`];
    if (!pin) return false;
    // A late response may follow an honest timeout closure. Only the validated
    // append-only closure chain can establish the effective outcome; selecting
    // the first closure rejects reconciliation, while trusting the last payload
    // would allow a determined outcome to be overwritten or an action re-closed.
    // Cache once per action/component, not once per target acknowledgement.
    const actionKey = JSON.stringify([event.organizationId, event.actionId]);
    let context = contexts.get(actionKey);
    if (!context) {
      const stream = events.filter(e => e.actionId === event.actionId && e.organizationId === event.organizationId)
        .sort((a, b) => a.actionSeq - b.actionSeq);
      const legality = verifyClosureLegality(stream);
      context = { stream, legal: legality.result.ok && legality.status !== 'incomplete',
        closed: [...stream].reverse().find(e => e.eventType === 'ACTION_CLOSED' || e.eventType === 'OUTCOME_RECONCILED') };
      contexts.set(actionKey, context);
    }
    if (!context.legal) return false;
    const { stream, closed } = context;
    const closure = closed?.payload?.[closed.eventType === 'OUTCOME_RECONCILED' ? 'toClosure' : 'closure'];
    const expectedClosure = ({ succeeded: 'SUCCEEDED', failed_no_effect: 'FAILED_NO_EFFECT', partial: 'PARTIAL', unknown: 'OUTCOME_UNKNOWN' } as Record<string, string>)[String(statement.effect)];
    if (!expectedClosure || (closed && (closure !== expectedClosure || event.actionSeq >= closed.actionSeq))) return false;
    const proposal = stream.find(e => e.eventType === 'ACTION_PROPOSED' && e.actionSeq < event.actionSeq);
    // Match the receipt's result, not an earlier timeout observation. The old
    // body-bearing producer observed the caller before ACK; the current producer
    // emits ACK first. Both pieces must precede the effective closure, if present.
    const caller = stream.find(e => e.eventType === 'CALLER_RESULT_OBSERVED' &&
      e.payload?.observer === 'praesidia-http-edge' &&
      e.payload.requestCommitment === statement.requestCommitment &&
      e.payload.resultCommitment === statement.resultCommitment &&
      (!closed || e.actionSeq < closed.actionSeq));
    if (!proposal?.payload || !caller?.payload) return false;
    let requestCommitment: string;
    let resultCommitment: string;
    if (proposal.payload.evidenceContent === 'commitments-only.v1') {
      // The explicit new producer shape attests commitments, not undisclosed content.
      // Do not reinterpret a legacy body-bearing event with missing content as this shape.
      if (caller.payload.evidenceContent !== 'commitments-only.v1' ||
          Object.hasOwn(proposal.payload, 'request') || Object.hasOwn(proposal.payload, 'checkpoint') ||
          Object.hasOwn(caller.payload, 'result') || proposal.payload.targetIdentity !== statement.targetId ||
          proposal.payload.targetKeyFingerprint !== httpTargetKeyFingerprint(pin) ||
          typeof proposal.payload.requestCommitment !== 'string' || typeof caller.payload.resultCommitment !== 'string') return false;
      requestCommitment = proposal.payload.requestCommitment;
      resultCommitment = caller.payload.resultCommitment;
    } else {
      const request = proposal.payload.request as HttpRequestEnvelope | undefined;
      if (!request || request.version !== 'praesidia.http-request.v1' || request.method !== 'POST' || request.contentType !== 'application/json' || request.targetId !== statement.targetId || request.targetKeyFingerprint !== httpTargetKeyFingerprint(pin) || !Object.hasOwn(caller.payload, 'result')) return false;
      requestCommitment = httpRequestCommitment(request);
      resultCommitment = jcsCommitment(caller.payload.result as JsonValue);
    }
    if (proposal.payload.requestCommitment !== requestCommitment || caller.payload.requestCommitment !== requestCommitment || caller.payload.resultCommitment !== resultCommitment || payload.resultCommitment !== resultCommitment || payload.requestCommitment !== requestCommitment) return false;
    return verifyHttpReceipt(payload.receipt, pin, { organizationId: event.organizationId, actionId: event.actionId,
      targetId: statement.targetId, keyId: statement.keyId, requestCommitment, resultCommitment });
  } catch { return false; }
}

/** PA-0010 (D8) — see {@link VerifyReport.targetAck}'s doc comment. */
function verifyTargetAck(events: BundleActionEvent[], pins?: VerifyOptions['targetPublicKeys']): {
  result: RawComponentResult;
  status?: ComponentStatus;
} {
  const httpContexts = new Map<string, HttpTargetActionContext>();
  let checked = 0;
  let failed = 0;
  let redacted = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  for (const e of events) {
    if (e.eventType !== 'TARGET_ACKNOWLEDGED') continue;
    checked += 1;
    const id = `${e.actionId}#${e.actionSeq}`;
    if (e.payload === null) {
      if (e.payloadCommitment) {
        redacted += 1;
        continue;
      }
      fail(
        id,
        'TARGET_ACKNOWLEDGED carries neither payload nor payloadCommitment',
      );
      continue;
    }
    const grade = e.payload.grade;
    if (grade === 'A') {
      const sig = payloadStr(e.payload, 'targetSignature');
      const alg = payloadStr(e.payload, 'signatureAlgorithm');
      if (!sig || !alg) {
        fail(
          id,
          'target_ack_grade_a_missing_signature: grade A requires a non-empty targetSignature and signatureAlgorithm',
        );
      } else if (!verifiedHttpTarget(e, events, pins, httpContexts)) {
        fail(id, 'target_ack_grade_a_unverified: a separately pinned target key and matching original request/result commitments are required; signature presence is not verification');
      }
    } else if (grade === 'B') {
      const attestation = payloadStr(e.payload, 'edgeAttestation');
      if (!attestation || e.payload.destinationAuthenticated !== true) {
        fail(
          id,
          'target_ack_grade_b_missing_attestation: grade B requires a non-empty edgeAttestation and destinationAuthenticated: true',
        );
      }
    } else if (grade !== 'C' && grade !== 'D') {
      fail(id, `target_ack_unknown_grade: "${String(grade)}"`);
    }
  }

  return {
    result: {
      ok: failed === 0,
      checked,
      failed,
      ...(firstFailure !== undefined ? { firstFailure } : {}),
      ...(reason !== undefined ? { reason } : {}),
    },
    status: failed === 0 && redacted > 0 ? 'incomplete' : undefined,
  };
}

/** PA-0010 — see {@link VerifyReport.callerResult}'s doc comment. */
function verifyCallerResult(events: BundleActionEvent[]): {
  result: RawComponentResult;
  status?: ComponentStatus;
} {
  let checked = 0;
  let failed = 0;
  let redacted = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  for (const e of events) {
    if (e.eventType !== 'CALLER_RESULT_OBSERVED') continue;
    checked += 1;
    const id = `${e.actionId}#${e.actionSeq}`;
    if (e.payload === null) {
      if (e.payloadCommitment) {
        redacted += 1;
        continue;
      }
      fail(
        id,
        'CALLER_RESULT_OBSERVED carries neither payload nor payloadCommitment',
      );
      continue;
    }
    if (typeof e.payload.success !== 'boolean') {
      fail(id, 'CALLER_RESULT_OBSERVED.payload.success must be a boolean');
      continue;
    }
    const commitment = e.payload.resultCommitment;
    if (
      commitment !== undefined &&
      commitment !== null &&
      !isSha256HexDigest(commitment)
    ) {
      fail(
        id,
        'CALLER_RESULT_OBSERVED.payload.resultCommitment is present but not a well-formed sha256 hex digest',
      );
      continue;
    }
    // PA-0033 (HIGH-1) — `outcomeClass` is OPTIONAL on the wire (bundles
    // predating `be`'s PA-0034 never carry it — see `closureLegality`'s
    // ambiguous-evidence handling for what that means for THAT check).
    // When present, though, it must be a recognized value and consistent
    // with `success` — a producer that ships both must not be allowed to
    // contradict itself.
    const outcomeClass = e.payload.outcomeClass;
    if (outcomeClass !== undefined) {
      if (
        typeof outcomeClass !== 'string' ||
        !(outcomeClass in CALLER_RESULT_OUTCOME_CLASS_EXPECTS_SUCCESS)
      ) {
        fail(
          id,
          `CALLER_RESULT_OBSERVED.payload.outcomeClass is present but not a recognized value (completed_success | completed_with_error | no_response_received): ${JSON.stringify(outcomeClass)}`,
        );
      } else if (
        CALLER_RESULT_OUTCOME_CLASS_EXPECTS_SUCCESS[outcomeClass] !==
        e.payload.success
      ) {
        fail(
          id,
          `CALLER_RESULT_OBSERVED.payload.outcomeClass ("${outcomeClass}") is inconsistent with payload.success (${String(e.payload.success)})`,
        );
      }
    }
  }

  return {
    result: {
      ok: failed === 0,
      checked,
      failed,
      ...(firstFailure !== undefined ? { firstFailure } : {}),
      ...(reason !== undefined ? { reason } : {}),
    },
    status: failed === 0 && redacted > 0 ? 'incomplete' : undefined,
  };
}

/**
 * PA-0033 (HIGH-1 fix) — classifies a single candidate evidencing event
 * (`TARGET_ACKNOWLEDGED` or `CALLER_RESULT_OBSERVED`) for
 * `evidencingSupport` below. THIS is where "presence of an event" is
 * turned into "the event actually evidences something", which is the gap
 * the security re-attack found: the pre-fix check only asked "does an
 * evidencing-TYPED event exist", never "does it carry positive content".
 *
 * - `TARGET_ACKNOWLEDGED` is unconditionally `'positive'`: this event type
 *   is, by D9's vocabulary, only ever emitted when the target actually
 *   acknowledged the request — there is no "we never heard back" shape of
 *   a `TARGET_ACKNOWLEDGED` event, redacted or not. This is NOT true of
 *   `CALLER_RESULT_OBSERVED` — see below — and that asymmetry is exactly
 *   why HIGH-1 exists on one event type and not the other.
 * - `CALLER_RESULT_OBSERVED` with a redacted payload (`payload: null` +
 *   `payloadCommitment`) is `'ambiguous'`: the commitment proves an event
 *   was signed, not what it says.
 * - `CALLER_RESULT_OBSERVED` with `payload.outcomeClass` present is
 *   `'positive'` for `completed_success`/`completed_with_error`,
 *   `'negative'` for `no_response_received` (exactly HIGH-1's shape —
 *   `be`'s PA-0034 sets this on the timeout/transport-failure branches)
 *   or any value `verifyCallerResult` doesn't recognize (fail-closed: an
 *   unrecognized value must never rescue a determined closure).
 * - `CALLER_RESULT_OBSERVED` with NO `outcomeClass` at all (a bundle that
 *   predates `be`'s PA-0034 field) is `'positive'` when `payload.success
 *   === true` — a genuine completion cannot be produced by a timeout, so
 *   `success: true` was never ambiguous even before the field existed —
 *   and `'ambiguous'` when `payload.success === false`, because THAT is
 *   the exact byte pattern a timeout and a genuine negative result both
 *   produce pre-PA-0034; this verifier cannot tell them apart offline and
 *   must not guess either way.
 */
function callerResultEvidencePositivity(
  payload: Record<string, unknown> | null,
): 'positive' | 'negative' | 'ambiguous' {
  if (payload === null) return 'ambiguous';
  const outcomeClass = payload.outcomeClass;
  if (typeof outcomeClass === 'string') {
    if (outcomeClass === 'no_response_received') return 'negative';
    if (outcomeClass in CALLER_RESULT_OUTCOME_CLASS_EXPECTS_SUCCESS)
      return 'positive';
    return 'negative'; // unrecognized value — verifyCallerResult flags it invalid separately; never treat it as positive support here.
  }
  return payload.success === true ? 'positive' : 'ambiguous';
}

/**
 * PA-0033 (HIGH-1 fix) — the single positivity verdict for an
 * `ACTION_CLOSED`/`OUTCOME_RECONCILED` event at `beforeSeq`, over every
 * candidate evidencing event earlier in `stream`. `'positive'` wins over
 * everything else the moment it is seen (one genuine acknowledgment or
 * completion is sufficient); short of that, `'negative'` (a confirmed
 * non-answer, e.g. a timeout) is distinguished from `'ambiguous'` (cannot
 * tell offline, pre-PA-0034 shape) so the caller can fail closed on the
 * former while degrading to `incomplete` — never `valid` — on the latter.
 * `'none'` means no candidate evidencing event exists at all.
 */
function evidencingSupport(
  stream: BundleActionEvent[],
  beforeSeq: number,
): 'positive' | 'negative' | 'ambiguous' | 'none' {
  let sawNegative = false;
  let sawAmbiguous = false;
  for (const x of stream) {
    if (x.actionSeq >= beforeSeq) continue;
    if (x.eventType === 'TARGET_ACKNOWLEDGED') return 'positive';
    if (x.eventType === 'CALLER_RESULT_OBSERVED') {
      const p = callerResultEvidencePositivity(x.payload);
      if (p === 'positive') return 'positive';
      if (p === 'ambiguous') sawAmbiguous = true;
      else sawNegative = true;
    }
  }
  if (sawAmbiguous) return 'ambiguous';
  if (sawNegative) return 'negative';
  return 'none';
}

/**
 * PA-0010 (D7) — THE CENTERPIECE. See
 * {@link VerifyReport.closureLegality}'s doc comment.
 */
function verifyClosureLegality(events: BundleActionEvent[]): {
  result: RawComponentResult;
  status?: ComponentStatus;
} {
  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };
  // PA-0033 — evidence that EXISTS but cannot be confirmed positive
  // offline (a bundle whose `CALLER_RESULT_OBSERVED` events predate
  // `be`'s PA-0034 `outcomeClass` field, with `success: false`). Never
  // counted toward `failed` — this is not proof of tampering — but never
  // silently accepted either: it downgrades the WHOLE component to
  // `incomplete` (unless something else genuinely fails), so it can never
  // read as `valid`.
  let ambiguousCount = 0;
  let firstAmbiguous: string | undefined;
  let ambiguousReason: string | undefined;
  const flagAmbiguous = (id: string, msg: string): void => {
    ambiguousCount += 1;
    if (firstAmbiguous === undefined) {
      firstAmbiguous = id;
      ambiguousReason = msg;
    }
  };

  const byAction = groupActionEvents(events);
  for (const [actionId, stream] of byAction) {
    let currentClosure: string | null = null;
    let firstClosureSeen = false;
    for (const e of stream) {
      if (
        e.eventType !== 'ACTION_CLOSED' &&
        e.eventType !== 'OUTCOME_RECONCILED'
      ) {
        continue;
      }
      checked += 1;
      const id = `${actionId}#${e.actionSeq}`;
      const support = evidencingSupport(stream, e.actionSeq);

      if (e.eventType === 'ACTION_CLOSED') {
        if (firstClosureSeen) {
          fail(
            id,
            'multiple_action_closed: an actionId may only be first-closed once (append-only D6 — a re-close is a defect or forgery)',
          );
          continue;
        }
        firstClosureSeen = true;
        const closure = payloadStr(e.payload, 'closure');
        const closureReason = payloadStr(e.payload, 'reason');
        if (!closure || !closureReason) {
          fail(id, 'ACTION_CLOSED.payload must carry both closure and reason');
          continue;
        }
        const reachedDispatch = stream.some(
          (x) =>
            x.actionSeq < e.actionSeq &&
            x.eventType === 'DISPATCH_ATTEMPTED' &&
            x.dispatched === true,
        );
        const phaseAllowed = reachedDispatch
          ? POST_DISPATCH_ALLOWED_CLOSURES
          : PRE_DISPATCH_ALLOWED_CLOSURES;
        if (!phaseAllowed.has(closure)) {
          fail(
            id,
            `closure_not_reachable_from_phase: closure "${closure}" is not reachable from ${reachedDispatch ? 'a dispatched' : 'a pre-dispatch'} action`,
          );
          currentClosure = closure;
          continue;
        }
        const reasonAllowed = REASON_ALLOWED_CLOSURES[closureReason];
        if (!reasonAllowed || !reasonAllowed.has(closure)) {
          // D7's hard rule, structurally: this is what catches a bundle
          // claiming e.g. FAILED_NO_EFFECT with reason: TIMEOUT.
          fail(
            id,
            `closure_reason_mismatch: closure "${closure}" cannot be produced by reason "${closureReason}" (D7 — a reason with no positive evidence about the outcome may never resolve to a closure that claims to know it)`,
          );
          currentClosure = closure;
          continue;
        }
        if (EVIDENCE_CLAIMING_CLOSURES.has(closure)) {
          // THE single most important assertion in this package: even
          // when the declared `reason` field passed the check above (an
          // attacker who lies about `reason` too), an evidence-claiming
          // closure needs an ACTUAL positive evidencing event, not merely
          // an event of an evidencing TYPE — PA-0033 (HIGH-1): a bundle
          // claiming FAILED_NO_EFFECT justified only by a timeout-shaped
          // `CALLER_RESULT_OBSERVED` (`outcomeClass: 'no_response_received'`,
          // or pre-PA-0034 `success: false` with no `outcomeClass` at all)
          // must never verify `valid` here.
          if (support === 'none') {
            fail(
              id,
              `closure_lacks_evidencing_event: closure "${closure}" claims a determined outcome but no TARGET_ACKNOWLEDGED or CALLER_RESULT_OBSERVED event exists earlier in this actionId's stream to support it`,
            );
          } else if (support === 'negative') {
            fail(
              id,
              `closure_evidencing_event_not_positive: closure "${closure}" claims a determined outcome but every TARGET_ACKNOWLEDGED/CALLER_RESULT_OBSERVED event earlier in this actionId's stream carries a confirmed non-positive outcome (outcomeClass: "no_response_received") — HIGH-1: presence of an evidencing-typed event is not evidence of what happened`,
            );
          } else if (support === 'ambiguous') {
            flagAmbiguous(
              id,
              `closure_evidencing_event_ambiguous: closure "${closure}" claims a determined outcome but its only supporting CALLER_RESULT_OBSERVED event(s) predate the outcomeClass field (or are redacted) and cannot be confirmed positive offline — re-export from a producer carrying PA-0034's field to resolve`,
            );
          }
        }
        currentClosure = closure;
      } else {
        // OUTCOME_RECONCILED
        const toClosure = payloadStr(e.payload, 'toClosure');
        if (!toClosure) {
          fail(id, 'OUTCOME_RECONCILED.payload must carry toClosure');
          continue;
        }
        if (currentClosure === null || !RECONCILABLE_FROM.has(currentClosure)) {
          fail(
            id,
            `illegal_reconciliation: closure "${currentClosure ?? 'none'}" is terminal and cannot be reconciled`,
          );
          currentClosure = toClosure;
          continue;
        }
        if (!RECONCILABLE_TO.has(toClosure)) {
          fail(
            id,
            `illegal_reconciliation_target: reconciliation cannot resolve to closure "${toClosure}" — it is not an evidence-backed terminal outcome`,
          );
          currentClosure = toClosure;
          continue;
        }
        // Older producers omitted reconciliation reasons. When one is present,
        // it must obey the same D7 reason/outcome contract as an initial closure.
        if (e.payload && Object.hasOwn(e.payload, 'reason')) {
          const reconciliationReason = payloadStr(e.payload, 'reason');
          if (!reconciliationReason || !Object.hasOwn(REASON_ALLOWED_CLOSURES, reconciliationReason) ||
              !REASON_ALLOWED_CLOSURES[reconciliationReason]!.has(toClosure)) {
            fail(id, `closure_reason_mismatch: reconciled closure "${toClosure}" cannot be produced by reason "${String(e.payload.reason)}"`);
            continue;
          }
        }
        if (EVIDENCE_CLAIMING_CLOSURES.has(toClosure)) {
          if (support === 'none') {
            fail(
              id,
              `closure_lacks_evidencing_event: reconciled closure "${toClosure}" claims a determined outcome but no TARGET_ACKNOWLEDGED or CALLER_RESULT_OBSERVED event exists earlier in this actionId's stream to support it`,
            );
          } else if (support === 'negative') {
            fail(
              id,
              `closure_evidencing_event_not_positive: reconciled closure "${toClosure}" claims a determined outcome but every TARGET_ACKNOWLEDGED/CALLER_RESULT_OBSERVED event earlier in this actionId's stream carries a confirmed non-positive outcome (outcomeClass: "no_response_received") — HIGH-1: presence of an evidencing-typed event is not evidence of what happened`,
            );
          } else if (support === 'ambiguous') {
            flagAmbiguous(
              id,
              `closure_evidencing_event_ambiguous: reconciled closure "${toClosure}" claims a determined outcome but its only supporting CALLER_RESULT_OBSERVED event(s) predate the outcomeClass field (or are redacted) and cannot be confirmed positive offline — re-export from a producer carrying PA-0034's field to resolve`,
            );
          }
        }
        currentClosure = toClosure;
      }
    }
  }

  const status: ComponentStatus | undefined =
    failed === 0 && ambiguousCount > 0 ? 'incomplete' : undefined;
  return {
    result: {
      ok: failed === 0,
      checked,
      failed,
      ...(firstFailure !== undefined
        ? { firstFailure }
        : status === 'incomplete' && firstAmbiguous !== undefined
          ? { firstFailure: firstAmbiguous }
          : {}),
      ...(reason !== undefined
        ? { reason }
        : status === 'incomplete' && ambiguousReason !== undefined
          ? { reason: ambiguousReason }
          : {}),
    },
    status,
  };
}

/**
 * PA-0010 (D8, corrigendum C4) — DERIVES, does not believe. See
 * {@link VerifyReport.evidenceGrade}'s doc comment.
 */
function verifyEvidenceGrade(
  events: BundleActionEvent[],
  manifest: BundleManifest,
  pins?: VerifyOptions['targetPublicKeys'],
): RawComponentResult {
  const httpContexts = new Map<string, HttpTargetActionContext>();
  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const fail = (id: string, msg: string): void => {
    failed += 1;
    if (firstFailure === undefined) {
      firstFailure = id;
      reason = msg;
    }
  };

  const declared = manifest.evidenceGradeSummary;
  if (!declared) {
    // v5 presence is already enforced by `verifyManifest`; nothing to
    // cross-check if somehow absent (structural error caught elsewhere).
    return { ok: true, checked: 0, failed: 0 };
  }

  const derived = { A: 0, B: 0, C: 0, D: 0 };
  const byAction = groupActionEvents(events);
  let observeModeEventSeen = false;
  for (const [, stream] of byAction) {
    const closed = stream.find((e) => e.eventType === 'ACTION_CLOSED');
    if (!closed) continue;
    // Best (strongest) grade any TARGET_ACKNOWLEDGED event in this
    // action's stream structurally supports.
    let best: 'A' | 'B' | 'C' | 'D' | null = null;
    let sdkOnly = true;
    for (const e of stream) {
      if (e.eventType === 'TARGET_ACKNOWLEDGED' && e.payload) {
        const grade = e.payload.grade;
        if (
          grade === 'A' &&
          verifiedHttpTarget(e, events, pins, httpContexts)
        ) {
          best = 'A';
        } else if (
          grade === 'B' &&
          payloadStr(e.payload, 'edgeAttestation') &&
          e.payload.destinationAuthenticated === true &&
          best !== 'A'
        ) {
          best = 'B';
        }
      }
      // Any Praesidia-issued (non-SDK) event beyond proposal is
      // "Praesidia observed" evidence — at least grade C.
      const trustDomain = e.trustDomain.toLowerCase();
      const issuerType = e.issuerType.toLowerCase();
      if (!trustDomain.includes('sdk') && issuerType !== 'sdk-report') {
        sdkOnly = false;
      }
    }
    let actionGrade: 'A' | 'B' | 'C' | 'D';
    if (best === 'A') actionGrade = 'A';
    else if (best === 'B') actionGrade = 'B';
    else if (sdkOnly) actionGrade = 'D';
    else actionGrade = 'C';
    derived[actionGrade] += 1;

    for (const e of stream) {
      const mode = e.payload?.enforcementMode;
      if (mode === 'observe') observeModeEventSeen = true;
    }
  }

  checked += 4; // three strength checks plus exact total closed-action count.
  const declaredCumA = declared.A;
  const declaredCumAB = declared.A + declared.B;
  const declaredCumABC = declared.A + declared.B + declared.C;
  const derivedCumA = derived.A;
  const derivedCumAB = derived.A + derived.B;
  const derivedCumABC = derived.A + derived.B + derived.C;
  const declaredTotal = declaredCumABC + declared.D;
  const derivedTotal = derivedCumABC + derived.D;
  if (declaredCumA > derivedCumA) {
    fail(
      'evidenceGradeSummary.A',
      `declared_grade_exceeds_derived_evidence: manifest declares ${declared.A} grade-A actions but only ${derived.A} action(s) in the shipped event stream carry grade-A-shaped evidence (a target signature)`,
    );
  } else if (declaredCumAB > derivedCumAB) {
    fail(
      'evidenceGradeSummary.B',
      `declared_grade_exceeds_derived_evidence: manifest declares ${declaredCumAB} grade-A/B actions but only ${derivedCumAB} action(s) in the shipped event stream carry grade-A/B-shaped evidence`,
    );
  } else if (declaredCumABC > derivedCumABC) {
    fail(
      'evidenceGradeSummary.C',
      `declared_grade_exceeds_derived_evidence: manifest declares ${declaredCumABC} grade-A/B/C actions but only ${derivedCumABC} action(s) in the shipped event stream support at least grade C`,
    );
  } else if (declaredTotal !== derivedTotal) {
    fail(
      'evidenceGradeSummary.total',
      `declared_grade_summary_count_mismatch: manifest grade buckets total ${declaredTotal} closed action(s), but the shipped event stream contains ${derivedTotal} ACTION_CLOSED stream(s)`,
    );
  }

  checked += 1;
  if (declared.enforcementMode === 'enforce' && observeModeEventSeen) {
    fail(
      'evidenceGradeSummary.enforcementMode',
      'observe_mode_action_counted_as_enforced: manifest declares enforcementMode "enforce" but at least one counted event\'s own signed payload declares enforcementMode "observe"',
    );
  }

  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/** PA-0010 — see {@link VerifyReport.actionCompleteness}'s doc comment. */
function verifyActionCompleteness(
  manifest: BundleManifest,
  events: BundleActionEvent[],
): RawComponentResult {
  if (events.length !== manifest.actionEventCount) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `action event count mismatch: bundle has ${events.length} action events but signed manifest declares ${manifest.actionEventCount}`,
    };
  }
  return { ok: true, checked: 1, failed: 0 };
}

function assertActionEventsStructure(
  events: BundleActionEvent[],
  orgId: string,
): void {
  const seen = new Set<string>();
  for (const e of events) {
    const dupKey = `${String(e?.actionId)}#${String(e?.actionSeq)}`;
    if (seen.has(dupKey)) {
      throw new Error(
        `action-events.ndjson.gz has an invalid/duplicate event: (actionId, actionSeq) = (${String(e?.actionId)}, ${String(e?.actionSeq)}) appears more than once — the DB's own UNIQUE (actionId, actionSeq) constraint means a genuine producer can never emit this; a resubmitted/replayed event was spliced into the export`,
      );
    }
    seen.add(dupKey);
    if (
      !e ||
      typeof e !== 'object' ||
      typeof e.actionId !== 'string' ||
      e.actionId.length === 0 ||
      !Number.isSafeInteger(e.actionSeq) ||
      e.actionSeq < 1 ||
      !isSupportedActionEventType(e.eventType) ||
      typeof e.schemaVersion !== 'number' ||
      !Number.isFinite(e.schemaVersion) ||
      e.schemaVersion <= 0 ||
      !isIsoDate(e.observedAt) ||
      !isIsoDate(e.receivedAt) ||
      typeof e.issuer !== 'string' ||
      typeof e.trustDomain !== 'string' ||
      (e.payload !== null &&
        (typeof e.payload !== 'object' || Array.isArray(e.payload))) ||
      (e.payload === null && !e.payloadCommitment) ||
      (e.payloadCommitment !== null &&
        !isSha256HexDigest(e.payloadCommitment)) ||
      typeof e.prevEventCommitment !== 'string' ||
      !/^[0-9a-f]{64}$/.test(e.prevEventCommitment) ||
      typeof e.signature !== 'string' ||
      (e.signatureAlgorithm !== 'Ed25519' &&
        e.signatureAlgorithm !== 'ECDSA_P256_SHA256') ||
      !Number.isSafeInteger(e.keyVersion) ||
      e.keyVersion < 1 ||
      e.organizationId !== orgId ||
      typeof e.issuerType !== 'string' ||
      typeof e.dispatched !== 'boolean' ||
      !isSha256HexDigest(e.eventCommitment) ||
      typeof e.producerVersion !== 'string' ||
      // SEC-PA01-DISCOVERED-01 — required for exact signable-preimage
      // reconstruction; see BundleActionEvent's doc comment.
      typeof e.timeSource !== 'string' ||
      (e.permitNonce !== null && typeof e.permitNonce !== 'string') ||
      (e.edgeVersion !== null && typeof e.edgeVersion !== 'string') ||
      (e.adapterVersion !== null && typeof e.adapterVersion !== 'string') ||
      (e.externalReceiptRef !== null &&
        typeof e.externalReceiptRef !== 'string') ||
      (e.artifactStorageRef !== null &&
        typeof e.artifactStorageRef !== 'string')
    ) {
      throw new Error(
        `action-events.ndjson.gz has an invalid/incomplete event: actionId=${String(e?.actionId)} actionSeq=${String(e?.actionSeq)} — every field required to reconstruct the signed preimage (organizationId, issuerType, dispatched, timeSource, permitNonce, edgeVersion, adapterVersion, externalReceiptRef, artifactStorageRef) must be present, per PA01-CONTRACT-manifest-v5-actions.md`,
      );
    }
  }
}

function verifyRowSignatures(
  rows: BundleRow[],
  publicKeys: Map<number, PublicKeyRecord>,
  manifestAlgorithm: BundleSignatureAlgorithm,
  cutoverMs: number | null,
): RawComponentResult {
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  for (const row of rows) {
    const entry = publicKeys.get(row.keyVersion);
    if (!entry) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = `row keyVersion ${row.keyVersion} not in public-keys.json`;
      }
      continue;
    }
    // AUDIT-2026-05-01 — Per-row algorithm dispatch.
    //
    // A tenant whose history straddles a substrate cutover
    // (`local-aes-gcm` Ed25519 → `aws-kms` ECDSA-P256-SHA256) can have
    // rows of BOTH algorithms in the same bundle. The exporter ships
    // `signatureAlgorithm` on every row (AUDIT-2026-05-01); fall back
    // to the manifest's algorithm — and ultimately to `'Ed25519'` via
    // the manifest default — for pre-AUDIT-01 bundles that omit the
    // field.
    //
    // Downgrade defence: if an attacker swaps `signatureAlgorithm` from
    // `'ECDSA_P256_SHA256'` to `'Ed25519'` (or vice versa) on a row to
    // try to coerce the verifier into the wrong primitive,
    // `crypto.createPublicKey` will succeed but `crypto.verify` will
    // fail because the key type does not match the algorithm. The
    // dispatcher therefore returns `false` and the row is rejected —
    // the algorithm field is not part of the canonical signing bytes,
    // but the key-type mismatch makes the downgrade unobservable to
    // the verifier in the success direction.
    const rowAlgorithm = row.signatureAlgorithm ?? manifestAlgorithm;
    // BUG-AUDIT-02 — Fail CLOSED on ANY signature made under a REVOKED
    // key, regardless of `signedAt`.
    //
    // The previous rule granted a grace to rows whose `signedAt` was
    // <= `revokedAt`. But `signedAt` is NOT part of the signed preimage
    // (see `signableRow` — the 11 signable fields exclude it), so a
    // holder of the compromised (revoked) private key could forge a new
    // row, sign it (the signature is cryptographically valid — they hold
    // the key), and stamp any pre-revocation `signedAt` to slip past the
    // gate. That defeats exactly the adversary revocation targets. There
    // is no self-contained way to tell a genuine pre-revocation signature
    // from a backdated forgery without binding `signedAt` into the signer
    // preimage (a coordinated be-core change, deliberately out of scope),
    // so the conservative choice is to reject every REVOKED-key signature.
    if (entry.status === 'REVOKED') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'key_revoked';
      }
      continue;
    }
    const signable = signableRow(row);
    const canonical = canonicalJson(signable);
    // AUDIT-SDK-01 — the backend signs each row over
    //   message = canonical(row) || prev_row_hash_bytes
    // (write path `audit-writer.service.ts` persistSignedLog; the online
    // verify path `audit-query.service.ts` reconstructs the same message).
    // The offline verifier MUST bind `prev_row_hash` into the preimage or
    // EVERY genuine production row fails signature verification. Guard an
    // absent/malformed `prev_row_hash` as a signature failure, mirroring
    // the online verifier.
    let prevRowHashBytes: Buffer;
    try {
      if (typeof row.prevRowHash !== 'string') {
        throw new Error('prev_row_hash missing');
      }
      const decoded = decodeBase64Strict(row.prevRowHash, 32);
      if (decoded === null) throw new Error('prev_row_hash malformed');
      prevRowHashBytes = decoded;
    } catch {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'row prev_row_hash missing or malformed';
      }
      continue;
    }
    const message = Buffer.concat([canonical, prevRowHashBytes]);
    // AV-0018 — `createdAt` is the row's signed timestamp (in `signableRow`).
    const rowOk = verifyTenantSignature(
      rowAlgorithm, row.signatureFormat, 'audit-record', message, row.signature, entry.publicKey, row.createdAt, cutoverMs,
    );
    if (rowOk !== true) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = rowOk === false ? 'row signature does not verify' : rowOk;
      }
    }
  }
  return {
    ok: failed === 0,
    checked: rows.length,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/**
 * PROD16 F10 (be-compliance) — reconstruct the true chain order from the
 * cryptographic links themselves, NOT from the bundle's on-disk row order.
 *
 * Before this fix, `verifyChain` trusted `rows.ndjson.gz`'s file order and
 * compared each row's `prevRowHash` to `computeChainLink(previousArrayEntry)`.
 * The producer orders rows by `(signedAt, id)` while the chain is actually
 * built in `chainSeq` order (a DB sequence). Two rows in the same org
 * sharing a `signedAt` millisecond — the expected case for
 * `PendingSignatureDrainService`'s same-transaction signing bursts, not an
 * edge case — are then ordered by random UUID `id`, so an HONEST bundle has
 * roughly even odds of being emitted in reverse chain order and reporting a
 * false `prev_row_hash does not chain to previous row`. A verifier that
 * cries tamper on good evidence is nearly as damaging as one that misses
 * real tampering.
 *
 * The fix removes the file-order dependency entirely: every row's forward
 * chain-link (`computeChainLink`, the value ITS successor must declare as
 * `prevRowHash`) is computed once and indexed. The true predecessor of any
 * row is then found by that value, regardless of where either row sits in
 * the array. This is strictly MORE attack-resistant than the old
 * position-based check (an attacker gains nothing from reordering the
 * ndjson lines) and does not need `be` to emit `chainSeq` on the wire.
 *
 * A well-formed bundle's rows form exactly one linked chain: exactly one
 * row has no in-bundle predecessor (BUGHUNT-SDK-02's opaque range anchor),
 * and following successor links from it visits every row exactly once.
 * Two rows ever declaring the identical `prevRowHash` (a fork — two rows
 * both claiming to succeed the same predecessor) fails closed immediately.
 */
/**
 * SCAN2-004 — chain endpoints, exposed ONLY when the walk fully succeeds.
 * `headAnchor` is the unique head row's own declared `prevRowHash` — either
 * `GENESIS_PREV_ROW_HASH` or an opaque out-of-bundle anchor (legitimate for
 * a ranged export, BUGHUNT-SDK-02). `tailChainLink` is the hash-chain value
 * `computeChainLink` says the row immediately AFTER the newest row in this
 * bundle must declare as ITS `prevRowHash`. Neither value is asserted by
 * `verifyChain` itself (a single bundle has no sibling to compare against);
 * `verify-set` (`cli.ts`) is the sole consumer, using `headAnchor` to close
 * AUDIT-03 (the earliest bundle in a claimed-complete set must be
 * genesis-rooted) and `tailChainLink` to bind adjacent bundles' boundary
 * (AUDIT-01) instead of trusting a mere date match.
 */
interface ChainVerification extends RawComponentResult {
  headRowId?: string;
  headAnchor?: string;
  tailRowId?: string;
  tailChainLink?: string | null;
}

/**
 * AV-2754 (BE-2979) — sealed-purge bridges. A retention purge deletes a run
 * of leaves; the survivor S keeps `prevRowHash` = link(last purged leaf).
 * `bridges` (from `verifySealLinkAuthenticity` only) map link(P) → that
 * value. Rules, all fail closed:
 *  - two bridges sharing a `linkIn` or a `linkOut` are all dropped (the gap
 *    then fails as before);
 *  - a row whose `prevRowHash` is reachable from a row link through bridges
 *    is not a head candidate;
 *  - a link value with both a direct successor row and a bridge is a fork;
 *  - the walk follows bridges only when no row follows directly, and a link
 *    value reached twice is a cycle.
 * With no bridges this is the pre-AV-2754 algorithm, verdicts unchanged.
 */
function verifyChain(rows: BundleRow[], bridges: ChainBridge[] = []): ChainVerification {
  if (rows.length === 0) {
    return { ok: true, checked: 0, failed: 0 };
  }

  // Every row's OWN forward chain-link — the value its true successor (if
  // any, and if present in this bundle) must declare as `prevRowHash`.
  const chainLinkToRow = new Map<string, BundleRow>();
  for (const row of rows) {
    const link = computeChainLink(row);
    if (link !== null && !chainLinkToRow.has(link)) {
      chainLinkToRow.set(link, row);
    }
  }

  // Group rows by their OWN declared `prevRowHash`. Used both to find each
  // row's true predecessor (by value, not position) and to detect forks.
  const byDeclaredPrev = new Map<string, BundleRow[]>();
  for (const row of rows) {
    if (typeof row.prevRowHash === 'string') {
      const arr = byDeclaredPrev.get(row.prevRowHash) ?? [];
      arr.push(row);
      byDeclaredPrev.set(row.prevRowHash, arr);
    }
  }

  // Fork check: two DIFFERENT rows must never declare the identical
  // prevRowHash — that would mean two rows both claim to be the immediate
  // successor of the same predecessor (or both claim to be the bundle's
  // leading anchor row).
  for (const claimants of byDeclaredPrev.values()) {
    if (claimants.length > 1) {
      return {
        ok: false,
        checked: rows.length,
        failed: claimants.length - 1,
        firstFailure: claimants[1]!.id,
        reason: `chain fork: rows ${claimants.map((r) => r.id).join(', ')} all declare the same prevRowHash`,
      };
    }
  }

  const bridgeOut = bridgeSuccessors(bridges);
  for (const linkIn of bridgeOut.keys()) {
    const direct = byDeclaredPrev.get(linkIn);
    if (direct) {
      return {
        ok: false,
        checked: rows.length,
        failed: 1,
        firstFailure: direct[0]!.id,
        reason: `chain fork: row ${direct[0]!.id} and a sealed-purge bridge both succeed the same link`,
      };
    }
  }
  // Link values a row link reaches through one or more bridges.
  const bridged = new Set<string>();
  for (const link of chainLinkToRow.keys()) {
    let next = bridgeOut.get(link);
    while (next !== undefined && !bridged.has(next)) {
      bridged.add(next);
      next = bridgeOut.get(next);
    }
  }

  // Rows with no in-bundle predecessor. Exactly one is expected (the
  // leading row's opaque anchor); any other count means the rows do not
  // form a single connected chain.
  const headCandidates = rows.filter(
    (row) =>
      typeof row.prevRowHash !== 'string' ||
      (!chainLinkToRow.has(row.prevRowHash) && !bridged.has(row.prevRowHash)),
  );
  if (headCandidates.length !== 1) {
    return {
      ok: false,
      checked: rows.length,
      failed: Math.max(1, headCandidates.length),
      firstFailure: (headCandidates[1] ?? headCandidates[0] ?? rows[0])!.id,
      reason:
        headCandidates.length === 0
          ? 'chain has no identifiable leading row (cycle or corrupted links)'
          : 'prev_row_hash does not chain to previous row',
    };
  }

  // Walk forward from the unique head; a fork or an unreachable row would
  // otherwise slip past the checks above.
  let current: BundleRow | undefined = headCandidates[0];
  let tailRow: BundleRow = headCandidates[0]!;
  const visited = new Set<string>();
  const visitedLinks = new Set<string>();
  let steps = 0;
  while (current) {
    visited.add(current.id);
    tailRow = current;
    steps += 1;
    const link = computeChainLink(current);
    const next = link === null ? null : nextDeclaredLink(link, bridgeOut, byDeclaredPrev, visitedLinks);
    if (next === BRIDGE_CYCLE) {
      return { ok: false, checked: rows.length, failed: 1, firstFailure: tailRow.id, reason: BRIDGE_CYCLE_REASON };
    }
    current = next === null ? undefined : byDeclaredPrev.get(next)![0];
  }
  if (visited.size !== rows.length) {
    const orphan = rows.find((r) => !visited.has(r.id));
    return {
      ok: false,
      checked: rows.length,
      failed: rows.length - visited.size,
      firstFailure: orphan?.id,
      reason:
        'row is not reachable from the bundle chain head (broken or forked link)',
    };
  }

  const head = headCandidates[0]!;
  return {
    ok: true,
    // Number of inter-row link assertions actually made: nodes visited
    // minus the head (whose anchor is accepted, not asserted) — 0 for a
    // single-row bundle, matching the pre-fix semantics.
    checked: Math.max(0, steps - 1),
    failed: 0,
    headRowId: head.id,
    headAnchor: typeof head.prevRowHash === 'string' ? head.prevRowHash : undefined,
    tailRowId: tailRow.id,
    tailChainLink: computeChainLink(tailRow),
  };
}

/**
 * AV-2754 — in → out over the signed bridges. A `linkIn` or `linkOut`
 * carried by more than one bridge drops every bridge carrying it (fail
 * closed: the gap then fails as before).
 */
function bridgeSuccessors(bridges: readonly ChainBridge[]): Map<string, string> {
  const countOf = (values: string[]): Map<string, number> => {
    const m = new Map<string, number>();
    for (const v of values) m.set(v, (m.get(v) ?? 0) + 1);
    return m;
  };
  const inCount = countOf(bridges.map((b) => b.linkIn));
  const outCount = countOf(bridges.map((b) => b.linkOut));
  const bridgeOut = new Map<string, string>();
  for (const b of bridges) {
    if (inCount.get(b.linkIn) === 1 && outCount.get(b.linkOut) === 1) {
      bridgeOut.set(b.linkIn, b.linkOut);
    }
  }
  return bridgeOut;
}

const BRIDGE_CYCLE = Symbol('bridge-cycle');
const BRIDGE_CYCLE_REASON = 'chain cycle: a sealed-purge bridge leads back to a link already walked';

/**
 * AV-2754 — from `link`, the first link value some row declares as its
 * `prevRowHash` (`declared`), following bridges only where no row does.
 * null at a dead end; BRIDGE_CYCLE when a link value already in `walked`
 * comes round again (`walked` grows in place).
 */
function nextDeclaredLink(
  link: string,
  bridgeOut: ReadonlyMap<string, string>,
  declared: { has(link: string): boolean },
  walked: Set<string>,
): string | null | typeof BRIDGE_CYCLE {
  let at: string | undefined = link;
  while (at !== undefined) {
    if (walked.has(at)) return BRIDGE_CYCLE;
    walked.add(at);
    if (declared.has(at)) return at;
    at = bridgeOut.get(at);
  }
  return null;
}

/**
 * AV-2755 — `verify-set`'s boundary between two date-adjacent bundles, under
 * `verifyChain`'s bridge rules. `tailLink` is the left bundle's
 * `chainTailLinkHash` (GENESIS_PREV_ROW_HASH for the genesis check),
 * `headAnchor` the right bundle's `chainHeadAnchor`, `bridges` the
 * `chainBridges` of every bundle from the left one to the right one (for the
 * genesis check, of the bundles up to the earliest one with rows). A seal
 * exported by several of them counts once, by (sealId, linkIn, linkOut).
 * Continuous when the tail link is the head anchor or reaches it through
 * bridges. A bridge back to a walked link is a cycle. A bridge out of the
 * head anchor (beside the right bundle's head row) is a fork, unless it lands
 * on one of `rightRowLinks`, the right bundle's own row links (AV-2775): that
 * is a purge of rows the right bundle still holds, its seal exported after
 * the right bundle with a bundle on the left. Fork and cycle carry a reason.
 * Each bundle's own `verifyChain` holds its bridges against its row links, so
 * a right bundle that carries a bridge out of its own head row is invalid.
 *
 * AV-2757 — documented limit, kept on purpose: a bridge from one bundle that
 * forks off, or cycles back to, a row link inside the OTHER bundle is not
 * seen here. Such a bridge needs two valid tenant-key signatures, and a
 * holder of that key can sign a clean bridge anyway, so it adds no attack.
 * Indexing the other bundle's row links would also report a false fork: be
 * exports a seal with every bundle whose window its purged period overlaps or
 * holds its `deletedAt`, so a pre-purge archive meets the seal of its own
 * later purge, and `deletedAt` is unsigned, so nothing tells that apart from
 * a contradiction. The index would cost about 170 bytes per row (about 41 MiB
 * at the 250k-row limit), held for every bundle in the set. Pinned by the
 * AV-2757 tests. `rightRowLinks` is no such index: it holds only the
 * `linkOut`s of bridges out of the head anchor that are row links.
 */
export function verifyChainBoundary(
  tailLink: string,
  headAnchor: string,
  bridges: readonly ChainBridge[],
  rightRowLinks: ReadonlySet<string> = new Set(),
): { ok: boolean; reason?: string } {
  const unique = new Map(bridges.map((b) => [JSON.stringify([b.sealId, b.linkIn, b.linkOut]), b]));
  const bridgeOut = bridgeSuccessors([...unique.values()]);
  const outOfHead = bridgeOut.get(headAnchor);
  if (outOfHead !== undefined && !rightRowLinks.has(outOfHead)) {
    return {
      ok: false,
      reason: "chain fork: the right bundle's leading row and a sealed-purge bridge both succeed the same link",
    };
  }
  const next = nextDeclaredLink(tailLink, bridgeOut, new Set([headAnchor]), new Set());
  if (next === BRIDGE_CYCLE) return { ok: false, reason: BRIDGE_CYCLE_REASON };
  return { ok: next !== null };
}

function verifyRootSignatures(
  roots: BundleRoot[],
  publicKeys: Map<number, PublicKeyRecord>,
  manifestAlgorithm: BundleSignatureAlgorithm,
  cutoverMs: number | null,
): RawComponentResult {
  let checked = roots.length;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  for (const root of roots) {
    const entry = publicKeys.get(root.keyVersion);
    if (!entry) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = `root keyVersion ${root.keyVersion} not in public-keys.json`;
      }
      continue;
    }
    // BUG-AUDIT-02 — Fail CLOSED on ANY root signed under a REVOKED key.
    // Same reasoning as the row path: the root envelope
    // (`{rootHash, periodStart, periodEnd, rowCount}`) does not cover
    // `signedAt`, so a backdated `signedAt` cannot be trusted to prove a
    // pre-revocation signature. Reject unconditionally.
    if (entry.status === 'REVOKED') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = 'key_revoked';
      }
      continue;
    }
    // Mirror the writer's envelope exactly — see MerkleRootService
    // (AGV-033) `computeRootForPeriod`.
    const bytes = merkleRootEnvelope(root);
    // AUDIT-2026-05-01 — Per-root algorithm dispatch with manifest
    // fallback (mirrors `verifyRowSignatures`). A bundle whose history
    // straddles a substrate cutover ships roots of both algorithms;
    // the per-root tag lets each one verify under its own primitive.
    const rootAlgorithm = root.signatureAlgorithm ?? manifestAlgorithm;
    // AV-0018 — `periodEnd` is the root's latest signed timestamp (the
    // envelope does not cover `signedAt`); a root is signed after it closes.
    const rootOk = verifyTenantSignature(
      rootAlgorithm, root.signatureFormat, 'merkle-root', bytes, root.signature, entry.publicKey, root.periodEnd, cutoverMs,
    );
    if (rootOk !== true) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = rootOk === false ? 'root signature does not verify' : rootOk;
      }
    }
    // AV-0016 — the supersession link is signed under the SAME key as this
    // root's own signature (the revoked check above covers both).
    if (root.supersedesRootId === undefined && root.supersessionSignature === undefined) continue;
    checked += 1;
    const superseded = roots.find((r) => r.id === root.supersedesRootId && r !== root);
    const linkOk =
      !superseded || root.supersessionSignature === undefined
        ? false
        : verifyTenantSignature(
            rootAlgorithm, root.supersessionSignatureFormat, 'merkle-supersession',
            supersessionSignable(root, superseded.rootHash), root.supersessionSignature, entry.publicKey,
            root.periodEnd, cutoverMs,
          );
    if (linkOk !== true) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        reason = linkOk === false
          ? 'root supersession signature missing or does not verify against the superseded root'
          : linkOk;
      }
    }
  }
  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

function verifyInclusionProofs(
  rows: BundleRow[],
  roots: BundleRoot[],
  proofs: BundleProofEntry[],
  supersessions: Supersessions,
): { result: RawComponentResult; status?: ComponentStatus } {
  // AV-0016 — a row proves once into a current root and at most once more
  // into each superseded root it was committed to.
  const supersededHashes = new Set(
    roots.filter((r) => supersessions.successorOf.has(r.id)).map((r) => r.rootHash),
  );
  const rowsById = new Map<string, BundleRow>();
  for (const r of rows) rowsById.set(r.id, r);
  const rootsByHash = new Map<string, BundleRoot>();
  for (const r of roots) rootsByHash.set(r.rootHash, r);

  let checked = 0;
  let failed = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  const seenRowIds = new Set<string>();

  const seenKeys = new Set<string>();

  // AV-0032 — `not_yet_rooted` stubs (includeUnrooted=true exports) are
  // accepted ONLY for the unrooted tail: rows signed at/after the end of the
  // latest root in the bundle (the root set is bound by the signed manifest's
  // `rootCount`). They make the component `incomplete`, never `valid`.
  // Root periods are ISO-validated by `assertRootsStructure`.
  let latestRoot: BundleRoot | undefined;
  for (const r of roots) {
    if (latestRoot === undefined || Date.parse(r.periodEnd) > Date.parse(latestRoot.periodEnd)) latestRoot = r;
  }
  let unrooted = 0;
  let firstUnrooted: string | undefined;

  for (const entry of proofs) {
    checked += 1;
    const toSuperseded =
      typeof entry.rootHash === 'string' && supersededHashes.has(entry.rootHash);
    const key = toSuperseded ? `${entry.rowId}\0${entry.rootHash}` : entry.rowId;
    if (seenKeys.has(key)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'duplicate proof entry for row';
      }
      continue;
    }
    seenKeys.add(key);
    if (!toSuperseded) seenRowIds.add(entry.rowId);

    // Status markers are diagnostics, not proofs, and are not signed. Treating
    // them as success let an attacker replace every proof with a marker.
    // AV-0032 — the one exception is a well-formed `not_yet_rooted` stub in
    // the unrooted tail, counted as unproven (`incomplete`), never as a pass.
    if (entry.status === NOT_YET_ROOTED) {
      const stubFailure = unrootedStubFailure(entry, rowsById.get(entry.rowId), roots, latestRoot);
      if (stubFailure === null) {
        unrooted += 1;
        firstUnrooted ??= entry.rowId;
      } else {
        failed += 1;
        if (!firstFailure) {
          firstFailure = entry.rowId;
          reason = stubFailure;
        }
      }
      continue;
    }
    if (entry.status && entry.status !== 'ok') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = `row has no verifiable inclusion proof (status=${entry.status})`;
      }
      continue;
    }
    const row = rowsById.get(entry.rowId);
    if (!row) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof references a row not present in rows.ndjson.gz';
      }
      continue;
    }
    if (!entry.proof || !entry.rootHash || typeof entry.index !== 'number') {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof entry malformed (missing proof/index/rootHash)';
      }
      continue;
    }
    const rootBytes = decodeBase64Strict(entry.rootHash, 32);
    if (rootBytes === null) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof rootHash is not canonical 32-byte base64';
      }
      continue;
    }
    // Sanity: the proof's stated root must match a root in roots.ndjson.gz.
    if (!rootsByHash.has(entry.rootHash)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof rootHash not found in roots.ndjson.gz';
      }
      continue;
    }
    const root = rootsByHash.get(entry.rootHash)!;
    const expectedProofDepth =
      root.rowCount <= 1 ? 0 : Math.ceil(Math.log2(root.rowCount));
    if (
      !Number.isSafeInteger(entry.index) ||
      entry.index < 0 ||
      !Number.isSafeInteger(root.rowCount) ||
      root.rowCount <= 0 ||
      entry.index >= root.rowCount ||
      entry.proof.length !== expectedProofDepth
    ) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof index/depth is inconsistent with root rowCount';
      }
      continue;
    }
    const leaf = computeLeaf(row);
    if (leaf === null) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'row signature is not canonical base64';
      }
      continue;
    }
    const decodedSiblings = entry.proof.map((s) => decodeBase64Strict(s, 32));
    if (decodedSiblings.some((s) => s === null)) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'proof sibling is not canonical 32-byte base64';
      }
      continue;
    }
    const merkleProofObj: MerkleProof = {
      siblings: decodedSiblings.map((s) => new Uint8Array(s!)),
      index: entry.index,
    };
    if (!merkleVerify(leaf, merkleProofObj, new Uint8Array(rootBytes))) {
      failed += 1;
      if (!firstFailure) {
        firstFailure = entry.rowId;
        reason = 'inclusion proof does not verify against root';
      }
    }
  }

  // The exporter emits exactly one proof record per row. Removing the proofs
  // file content must not produce a vacuous zero-checked success.
  for (const row of rows) {
    if (!seenRowIds.has(row.id)) {
      checked += 1;
      failed += 1;
      if (!firstFailure) {
        firstFailure = row.id;
        reason = 'row has no entry in proofs.ndjson.gz';
      }
    }
  }

  if (failed === 0 && unrooted > 0) {
    const after = latestRoot === undefined
      ? 'this bundle carries no Merkle root'
      : `signed after the latest published root in this bundle (${latestRoot.id}, periodEnd ${latestRoot.periodEnd})`;
    return {
      result: {
        ok: true,
        checked,
        failed,
        firstFailure: firstUnrooted!,
        reason: `${NOT_YET_ROOTED}: ${unrooted} of ${rows.length} row(s) have no inclusion proof yet — ${after}; their signatures and chain are verified, their Merkle inclusion is not. Re-export once those hours are rooted to prove them.`,
      },
      status: 'incomplete',
    };
  }
  return {
    result: {
      ok: failed === 0,
      checked,
      failed,
      ...(firstFailure !== undefined ? { firstFailure } : {}),
      ...(reason !== undefined ? { reason } : {}),
    },
  };
}

const NOT_YET_ROOTED = 'not_yet_rooted';

/**
 * AV-0032 — why a `not_yet_rooted` stub is NOT acceptable, or `null` when it
 * is: exactly `{ rowId, status }` (the exporter's shape), for a row present
 * in the bundle whose `signedAt` is at/after the latest root's `periodEnd`.
 * A stub inside a root's period or in a gap before a later root is invalid.
 */
function unrootedStubFailure(
  entry: BundleProofEntry,
  row: BundleRow | undefined,
  roots: BundleRoot[],
  latestRoot: BundleRoot | undefined,
): string | null {
  if (Object.keys(entry).some((k) => k !== 'rowId' && k !== 'status')) {
    return 'malformed not_yet_rooted stub: a stub carries only rowId and status';
  }
  if (!row) return 'proof references a row not present in rows.ndjson.gz';
  const t = typeof row.signedAt === 'string' ? Date.parse(row.signedAt) : NaN;
  if (Number.isNaN(t)) return 'not_yet_rooted stub for a row with no parseable signedAt';
  const covering = roots.find((r) => Date.parse(r.periodStart) <= t && t < Date.parse(r.periodEnd));
  if (covering) {
    return `not_yet_rooted stub for a row inside the period of published root ${covering.id} (${covering.periodStart}..${covering.periodEnd}) — a rooted row must carry its inclusion proof`;
  }
  if (latestRoot !== undefined && !(t >= Date.parse(latestRoot.periodEnd))) {
    return `not_yet_rooted stub for a row before the end of the latest published root (${latestRoot.id}, periodEnd ${latestRoot.periodEnd}) — only rows after every root in the bundle may be unrooted`;
  }
  return null;
}

/**
 * AUDIT-2026-05-09 — Multi-anchor receipt verification.
 *
 * Walks `root.anchorReceipts` (the multi-anchor array introduced by
 * the AUDIT-09 migration) and dispatches each entry on its `provider`
 * key. Each provider verifies independently — the report counts every
 * receipt across every root, so a 3-root bundle each with a Rekor +
 * S3 anchor produces `checked = 6`.
 *
 * Back-compat: when a root has NO `anchorReceipts` array (older
 * bundles emitted before the multi-anchor exporter shipped) but DOES
 * carry the legacy `anchorReceipt` string, the verifier synthesizes a
 * single `{ provider: 'rekor', receipt, anchoredAt }` entry so the
 * legacy receipt is still checked. This is the same shape the
 * migration's backfill writes into the database.
 */
async function verifyRekorReceipts(
  roots: BundleRoot[],
  options: VerifyOptions,
  publicKeys: Map<number, PublicKeyRecord>,
  manifestAlgorithm: BundleSignatureAlgorithm,
): Promise<RawComponentResult> {
  if (roots.length === 0) {
    return {
      ok: true,
      checked: 0,
      failed: 0,
      ...(options.noRekor
        ? {
            reason:
              'rekor_check_skipped_by_caller: --no-rekor was passed — Rekor receipts were NOT checked; non-Rekor anchors, if present, remain in scope.',
          }
        : {}),
    };
  }

  const perRoot = roots.map((root) => ({
    root,
    entries: collectAnchorEntries(root),
  }));
  const unanchoredCount = perRoot.filter((r) => r.entries.length === 0).length;

  let checked = 0;
  let failed = 0;
  let skippedRekor = 0;
  let firstFailure: string | undefined;
  let reason: string | undefined;
  for (const { root, entries } of perRoot) {
    if (entries.length === 0) {
      if (options.noRekor) {
        // Historical `--no-rekor` semantics allow roots without a Rekor
        // receipt. This opt-out must not also bypass an S3/private-notary
        // receipt that is actually present, so non-Rekor entries continue
        // through the normal verifier below.
        skippedRekor += 1;
        continue;
      }
      checked += 1;
      failed += 1;
      if (!firstFailure) {
        firstFailure = root.id;
        // PROD16 F8 — distinguish "no witness was ever configured for
        // this bundle" (EVERY root is unanchored — consistent with a
        // deployment shipping `FEATURE_REKOR_ANCHOR=false`, be-core's
        // current default) from "a gap in an otherwise-anchored
        // history" (some roots in THIS bundle ARE anchored, this one is
        // not — a narrower, more concerning anomaly, e.g. an anchoring
        // outage or a deleted receipt). Both still fail closed — an
        // unwitnessed root does not get the benefit of the doubt — but
        // an auditor needs to know which situation they are looking at;
        // they are not the same finding and should not produce the same
        // undifferentiated message.
        reason =
          unanchoredCount === perRoot.length
            ? 'no_external_witness: no root in this bundle carries an anchor receipt at all — this looks like external anchoring was never enabled for this org/deployment (or was off for this export), not a gap in existing coverage. Tenant/platform signatures are unaffected, but tamper cannot be bounded against an independent transparency log.'
            : `anchor_missing_for_partially_anchored_bundle: root ${root.id} has no anchor receipt while ${perRoot.length - unanchoredCount} other root(s) in this bundle do — this looks like a HOLE in an otherwise-anchored history, not a global witness-off configuration.`;
      }
      continue;
    }
    for (const entry of entries) {
      if (options.noRekor && entry.provider === 'rekor') {
        skippedRekor += 1;
        continue;
      }
      checked += 1;
      let result: { ok: boolean; reason?: string };
      try {
        result = await verifyAnchorReceipt(root, entry, options, publicKeys, manifestAlgorithm);
      } catch (err) {
        result = {
          ok: false,
          reason: `verify_threw: ${
            err instanceof Error ? err.message : String(err)
          }`,
        };
      }
      if (!result.ok) {
        failed += 1;
        if (!firstFailure) {
          firstFailure = root.id;
          reason = result.reason
            ? `${entry.provider}: ${result.reason}`
            : `${entry.provider} receipt verification failed`;
        }
      }
    }
  }
  return {
    ok: failed === 0,
    checked,
    failed,
    ...(firstFailure !== undefined ? { firstFailure } : {}),
    ...(reason !== undefined
      ? { reason }
      : options.noRekor && skippedRekor > 0
        ? {
            reason:
              'rekor_check_skipped_by_caller: --no-rekor was passed — Rekor receipts were NOT checked; non-Rekor anchors, if present, were still evaluated.',
          }
        : {}),
  };
}

/**
 * AUDIT-2026-05-09 — Normalize the root's anchor representations into
 * a single per-provider entry list. Prefers the multi-anchor
 * `anchorReceipts` array; synthesizes a legacy rekor entry from
 * `anchorReceipt` only when the array is absent or empty.
 */
function collectAnchorEntries(root: BundleRoot): AnchorReceiptEntry[] {
  if (Array.isArray(root.anchorReceipts) && root.anchorReceipts.length > 0) {
    return root.anchorReceipts;
  }
  if (root.anchorReceipt) {
    return [
      {
        provider: 'rekor',
        receipt: root.anchorReceipt,
        // Use the root's `anchoredAt` when present, falling back to
        // `signedAt` so the synthesized entry always carries a
        // timestamp (matches the migration's backfill shape).
        anchoredAt: root.anchoredAt ?? root.signedAt,
      },
    ];
  }
  return [];
}

/**
 * SEC-2026-09-12 (MCPSDK-01) — resolve the UPPER bound of the window a
 * Rekor `integratedTime` must fall in, or `null` when the bundle records no
 * genuine anchor time at all (no upper bound is then enforced).
 *
 * Deliberately does NOT use `entry.anchoredAt` unconditionally:
 * `collectAnchorEntries` SYNTHESIZES that field as `root.anchoredAt ??
 * root.signedAt` for legacy single-slot `anchorReceipt` roots, and treating
 * that `signedAt` fallback as an anchor time would reject bundles whose old
 * roots were legitimately anchored later by a backfill run. Only the
 * multi-anchor array carries a per-provider anchor time the producer
 * actually recorded.
 *
 * When both a root-level and a per-provider anchor time exist, the LATER one
 * wins: `root.anchoredAt` may record only the first provider's anchor while
 * a second provider legitimately anchored later.
 */
function anchorWindowUpperBound(
  root: BundleRoot,
  entry: AnchorReceiptEntry,
): string | null {
  const candidates: string[] = [];
  if (typeof root.anchoredAt === 'string') candidates.push(root.anchoredAt);
  if (
    Array.isArray(root.anchorReceipts) &&
    root.anchorReceipts.length > 0 &&
    typeof entry.anchoredAt === 'string'
  ) {
    candidates.push(entry.anchoredAt);
  }
  let best: string | null = null;
  let bestMs = Number.NEGATIVE_INFINITY;
  for (const candidate of candidates) {
    const ms = Date.parse(candidate);
    // An unparseable value is impossible after `assertRootStructure`, but if
    // one ever reaches here it must NOT silently widen the window — pass it
    // through so `verifyRekorReceipt` fails closed on it.
    if (Number.isNaN(ms)) return candidate;
    if (ms > bestMs) {
      bestMs = ms;
      best = candidate;
    }
  }
  return best;
}

/**
 * AUDIT-2026-05-09 — Dispatch a single anchor receipt entry to the
 * appropriate verifier. The caller-supplied `anchorReceiptVerifier`
 * (when present) wins for ALL providers — auditors who need on-line
 * verification of S3 receipts, for example, supply a hook that does
 * a HEAD against the bucket. Without the hook, behaviour per provider:
 *
 *   - `'rekor'` → cryptographic offline verification bound to this root.
 *   - `'s3'`    → fail closed unless the caller supplies a verifier.
 *   - `'rfc3161'` → offline TimeStampToken check (AV-0019, `rfc3161.ts`).
 *   - other     → `{ ok: false, reason: 'unknown_provider' }`.
 */
async function verifyAnchorReceipt(
  root: BundleRoot,
  entry: AnchorReceiptEntry,
  options: VerifyOptions,
  publicKeys: Map<number, PublicKeyRecord>,
  manifestAlgorithm: BundleSignatureAlgorithm,
): Promise<{ ok: boolean; reason?: string }> {
  if (typeof entry.receipt !== 'string' || entry.receipt.length === 0) {
    return { ok: false, reason: 'empty_receipt' };
  }
  const expectedRoot: ExpectedAnchorRoot = {
    id: root.id,
    organizationId: root.organizationId,
    rootHash: root.rootHash,
    signature: root.signature,
    keyVersion: root.keyVersion,
    ...(root.signatureAlgorithm !== undefined
      ? { signatureAlgorithm: root.signatureAlgorithm }
      : {}),
    ...(root.signatureFormat !== undefined ? { signatureFormat: root.signatureFormat } : {}),
    periodStart: root.periodStart,
    periodEnd: root.periodEnd,
    rowCount: root.rowCount,
    signedAt: root.signedAt,
  };
  if (options.anchorReceiptVerifier) {
    return options.anchorReceiptVerifier(entry, expectedRoot);
  }
  if (entry.provider === 'rekor') {
    // BUGHUNT-SDK-05 — a caller-supplied `rekorFetcher` is still honoured
    // as an explicit seam (e.g. an on-line re-fetch); the DEFAULT is now
    // real offline cryptographic verification (SET + inclusion proof),
    // not the old `JSON.parse`-and-return-true false assurance.
    if (options.rekorFetcher) {
      const ok = await options.rekorFetcher(entry.receipt, expectedRoot);
      return ok ? { ok: true } : { ok: false, reason: 'rekor_fetch_failed' };
    }
    // AV-2771 — the binding verifies the logged signature under the root's
    // key, with the same algorithm dispatch as `verifyRootSignatures`.
    const rootKey = publicKeys.get(root.keyVersion);
    if (!rootKey) return { ok: false, reason: 'root_key_unavailable' };
    return verifyRekorReceipt(entry.receipt, options.rekorPublicKeyPem, {
      rootHashB64: root.rootHash,
      periodStart: root.periodStart,
      periodEnd: root.periodEnd,
      rowCount: root.rowCount,
      ...(root.signatureFormat !== undefined ? { signatureFormat: root.signatureFormat } : {}),
      signatureB64: root.signature,
      signatureAlgorithm: root.signatureAlgorithm ?? manifestAlgorithm,
      publicKey: rootKey.publicKey,
      // SEC-2026-09-12 (MCPSDK-01) — hand the root's own time window to the
      // receipt verifier so Rekor's signed `integratedTime` bounds it.
      signedAt: root.signedAt,
      anchoredAt: anchorWindowUpperBound(root, entry),
    });
  }
  if (entry.provider === 'rfc3161') {
    const v = verifyRfc3161(root, entry, options);
    return v.status === 'verified' ? { ok: true } : { ok: false, reason: v.reason };
  }
  if (entry.provider === 's3') {
    const shape = verifyS3ReceiptShape(entry.receipt);
    return shape.ok ? { ok: false, reason: 'unverifiable_offline' } : shape;
  }
  return { ok: false, reason: 'unknown_provider' };
}

/** AV-0019 — offline RFC 3161 check of one entry, bound to its root and time window. */
function verifyRfc3161(root: BundleRoot, entry: AnchorReceiptEntry, options: VerifyOptions): Rfc3161Verdict {
  return verifyRfc3161Receipt(
    entry.receipt,
    { rootHashB64: root.rootHash, signedAt: root.signedAt, anchoredAt: anchorWindowUpperBound(root, entry) },
    options.tsaTrustAnchorsPem,
  );
}

/** AV-0019 — the report's per-root RFC 3161 rows (offline, independent of any caller hook). */
function summarizeRfc3161(roots: BundleRoot[], options: VerifyOptions): Rfc3161RootReport[] {
  return roots.flatMap((root): Rfc3161RootReport[] => {
    const entries = collectAnchorEntries(root).filter((e) => e.provider === 'rfc3161');
    if (entries.length === 0) return [{ rootId: root.id, status: 'absent' as const }];
    return entries.map((entry) => ({ rootId: root.id, ...verifyRfc3161(root, entry, options) }));
  });
}

/**
 * Offline check that an S3 receipt parses as `s3:<bucket>:<key>:<vid>`.
 * The key may legally contain colons, so we slice the first and last
 * colon-segments and treat everything in between as the key — matches
 * `S3AnchorService.verifyReceipt`'s parser.
 *
 * Returns `{ ok: false, reason: 'malformed' }` on a bad shape. A valid
 * shape is still not proof; callers must use `anchorReceiptVerifier`.
 */
function verifyS3ReceiptShape(receipt: string): {
  ok: boolean;
  reason?: string;
} {
  if (!receipt.startsWith('s3:')) {
    return { ok: false, reason: 'malformed' };
  }
  const rest = receipt.slice('s3:'.length);
  const firstColon = rest.indexOf(':');
  if (firstColon < 0) return { ok: false, reason: 'malformed' };
  const bucket = rest.slice(0, firstColon);
  const afterBucket = rest.slice(firstColon + 1);
  const lastColon = afterBucket.lastIndexOf(':');
  if (lastColon < 0) return { ok: false, reason: 'malformed' };
  const key = afterBucket.slice(0, lastColon);
  const versionId = afterBucket.slice(lastColon + 1);
  if (!bucket || !key || !versionId) {
    return { ok: false, reason: 'malformed' };
  }
  return { ok: true };
}

// ════════════════════════════════════════════════════════════════════════
// AUDIT-2026-05-30 — Platform key-binding attestation verifier
// ════════════════════════════════════════════════════════════════════════

/**
 * SEC-2026-09-12 (MCPSDK-01) — permitted clock skew, in milliseconds,
 * between the platform attestation's `issuedAt` and the manifest's
 * `generatedAt`. Same rationale and same value as
 * `rekor.ts`'s `REKOR_INTEGRATED_TIME_SKEW_MS`: wide enough for producer clock
 * drift and for an attestation minted slightly ahead of the export it
 * covers, narrow enough that replaying an attestation from a previous
 * export (days/months old) fails closed. Not configurable.
 */
const ATTESTATION_TIME_SKEW_MS = 24 * 60 * 60 * 1000;

interface PlatformAttestationBody {
  orgId: string;
  keyVersions: Array<{
    keyVersion: number;
    fingerprint: string;
    status: string;
    revokedAt: string | null;
    issuedAt: string;
  }>;
  issuedAt: string;
  platformSigningKeyFingerprint: string;
  /**
   * MIL-0003 — additive, optional. Present only when `be`'s
   * `PLATFORM_ATTESTATION_KEY_VERSION` is configured (reserved for a
   * future platform-key rotation; unset by default, so omitted entirely
   * rather than emitted as `null` — see `platform-attestation.service.ts`'s
   * `attestBundle`). This field is never structurally required by
   * `verifyPlatformAttestation` — its absence/presence must never gate
   * verification — and CD-0002's `scripts/contract-drift.mjs` check [E]
   * enforces that any future `be`-side addition here is signature-safe
   * (see the load-bearing comment on `canonicalJson(body...)` in
   * {@link verifyPlatformAttestation} below) before it needs a matching
   * interface field at all.
   */
  platformKeyVersion?: number;
  /**
   * SEC-2026-09-12 (MCPSDK-01) — additive, optional: the `generatedAt` of
   * the manifest THIS attestation was minted for. Emitted by current `be`
   * exporters; absent on every attestation produced before that change.
   * When present it is verified (fail closed on mismatch); when absent the
   * attestation is only weakly bound to the export (see the
   * `attestation_unbound_legacy` note in `verifyPlatformAttestation`).
   */
  manifestGeneratedAt?: string;
  /**
   * SEC-2026-09-12 (MCPSDK-01) — additive, optional: lowercase sha256 hex
   * over the manifest's canonical SIGNABLE bytes (see
   * {@link manifestSignableBytes}) — i.e. exactly the preimage the tenant
   * manifest signature covers. This is the strong form of the binding: it
   * pins the attestation to one specific export, so a genuine
   * pre-revocation attestation cannot be replayed onto a forged bundle.
   */
  manifestDigest?: string;
  signatureAlgorithm: 'ECDSA_P256_SHA256';
}

interface PlatformAttestationEnvelope {
  attestation: PlatformAttestationBody;
  signature: string;
}

/**
 * AUDIT-2026-05-30 — Verify the bundle's platform key-binding
 * attestation.
 *
 * The check chain (each step short-circuits to the next reason on
 * failure):
 *   1. Resolve the platform pubkey ({@link resolvePlatformKey}, run
 *      after step 3): `options.platformPublicKeyDerB64`, else the
 *      `options.platformTrustAnchor` key the attestation names, else the
 *      bundled pin. None → `platform_key_not_pinned` (never valid: the
 *      top-level status is `unanchored`, AV-0017).
 *   2. If the entry is missing entirely, fail unless the caller explicitly
 *      enables `allowLegacyUnattested`.
 *   3. Parse the envelope. Reject malformed JSON / shape with
 *      `malformed`.
 *   4. orgId in attestation MUST match manifest orgId — else
 *      `org_mismatch`.
 *   5. signature MUST verify under the resolved platform pubkey,
 *      with low-s canonical form enforced (see crypto.ts).
 *   6. The attestation's `platformSigningKeyFingerprint` MUST match
 *      the sha256 of the resolved pubkey's DER bytes — defends
 *      against an attacker who swaps the verifier's bundled pubkey
 *      bytes without re-signing the attestation.
 *   6b. SEC-2026-09-12 (MCPSDK-01) — the attestation MUST be bound to
 *      THIS export: `issuedAt` may not predate `manifest.generatedAt`
 *      by more than `ATTESTATION_TIME_SKEW_MS`, and the optional
 *      `manifestGeneratedAt` / `manifestDigest` fields, when present,
 *      MUST match this manifest exactly. An attestation carrying
 *      neither field is a legacy one: accepted, but flagged with the
 *      `attestation_unbound_legacy` reason the CLI prints as a NOTE.
 *   7. Every `keyVersions[i].fingerprint` MUST match the sha256 of
 *      the corresponding entry in `public-keys.json`.
 */
/**
 * AUDIT-2026-05-30 / AV-0017 — the platform key the attestation must verify
 * under: caller key > caller trust anchor > build-time pin. None of them →
 * `platform_key_not_pinned` (top-level `unanchored`). The returned fingerprint
 * is what step 6 compares the declared one against — always recomputed from
 * the DER, so neither a hand-built anchor nor the build-time pin can assert a
 * fingerprint. AV-2750: a build-time pin whose DER does not hash to its pinned
 * fingerprint is a substituted or half-updated pin and fails closed.
 */
function resolvePlatformKey(
  body: PlatformAttestationBody,
  options: VerifyOptions,
): { der: Buffer; fingerprint: string } | { reason: string } {
  const override = options.platformPublicKeyDerB64;
  const anchor = options.platformTrustAnchor;
  if (override && anchor) {
    throw new Error('platformPublicKeyDerB64 and platformTrustAnchor are mutually exclusive');
  }
  const sha256Hex = (der: Buffer): string => crypto.createHash('sha256').update(der).digest('hex');
  if (anchor) {
    const key = anchor.keys.find((k) => k.fingerprint === body.platformSigningKeyFingerprint);
    if (!key) {
      return {
        reason: `trust_anchor_key_not_found: attestation is signed by platform key ${body.platformSigningKeyFingerprint}, which the supplied trust anchor does not list`,
      };
    }
    const issuedMs = Date.parse(body.issuedAt);
    if (
      (key.notBefore !== null && issuedMs < Date.parse(key.notBefore)) ||
      (key.notAfter !== null && issuedMs > Date.parse(key.notAfter))
    ) {
      return {
        reason: `trust_anchor_key_not_valid_at_issuedAt: attestation issuedAt ${body.issuedAt} is outside the anchored key's [${key.notBefore}, ${key.notAfter}] window`,
      };
    }
    const der = Buffer.from(key.spkiDerB64, 'base64');
    return { der, fingerprint: sha256Hex(der) };
  }
  const b64 = override ? override : isPlatformPubkeyPinned() ? PLATFORM_PUBLIC_KEY_DER_B64 : '';
  if (b64.length === 0) return { reason: PLATFORM_KEY_NOT_PINNED };
  const der = b64.length <= 512 ? decodeBase64Strict(b64) : null;
  if (der === null) {
    return { reason: 'platform_key_malformed: expected canonical base64 SPKI DER' };
  }
  // Caller override and bundled pin take the same path so a substitution at
  // either level fails the `platformSigningKeyFingerprint` check (step 6).
  const fingerprint = sha256Hex(der);
  if (!override && fingerprint !== PLATFORM_PUBLIC_KEY_FINGERPRINT) {
    return {
      reason: `platform_key_pin_mismatch: embedded platform key DER hashes to ${fingerprint}, not the pinned fingerprint ${PLATFORM_PUBLIC_KEY_FINGERPRINT}`,
    };
  }
  return { der, fingerprint };
}

function verifyPlatformAttestation(
  entry: ZipEntry | null,
  publicKeysRaw: Record<string, unknown>,
  manifest: BundleManifest,
  options: VerifyOptions,
): RawComponentResult & { attestedKeys?: AttestedTenantKey[] } {
  const manifestOrgId = manifest.orgId;
  // Missing external trust evidence is a verification failure by default. An
  // auditor may explicitly opt into legacy self-signed bundle semantics.
  if (!entry) {
    return options.allowLegacyUnattested
      ? {
          ok: true,
          checked: 0,
          failed: 0,
          reason: 'missing_legacy_explicitly_allowed',
        }
      : {
          ok: false,
          checked: 1,
          failed: 1,
          reason: 'platform_attestation_missing',
        };
  }

  // Parse the envelope.
  let envelope: PlatformAttestationEnvelope;
  try {
    envelope = JSON.parse(
      entry.data.toString('utf8'),
    ) as PlatformAttestationEnvelope;
  } catch {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'malformed: platform-attestation.json is not valid JSON',
    };
  }
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    !envelope.attestation ||
    typeof envelope.signature !== 'string'
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'malformed: missing attestation / signature fields',
    };
  }
  const body = envelope.attestation;
  if (
    !body ||
    typeof body.orgId !== 'string' ||
    !Array.isArray(body.keyVersions) ||
    typeof body.platformSigningKeyFingerprint !== 'string' ||
    typeof body.issuedAt !== 'string' ||
    Number.isNaN(Date.parse(body.issuedAt)) ||
    body.signatureAlgorithm !== 'ECDSA_P256_SHA256'
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: 'malformed: attestation body has wrong shape',
    };
  }

  // Step 1 (AV-0017: after parsing, so a trust anchor can select by the
  // declared fingerprint) — resolve the platform pubkey.
  const resolved = resolvePlatformKey(body, options);
  if ('reason' in resolved) {
    return { ok: false, checked: 1, failed: 1, reason: resolved.reason };
  }
  const { der: pinnedDer, fingerprint: expectedFingerprint } = resolved;

  // Step 4 — orgId must match the manifest.
  if (body.orgId !== manifestOrgId) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `org_mismatch: attestation orgId ${body.orgId} != manifest orgId ${manifestOrgId}`,
    };
  }

  // Step 5 — signature verification (ECDSA-P256-SHA256, low-s).
  // The verifier re-canonicalizes the attestation body BYTES the
  // same way the writer did (`canonicalJson`); the signature must
  // verify under the pinned pubkey or we fail closed.
  //
  // LOAD-BEARING forward-compatibility property (CD-0002 follow-up,
  // MIL-0003): `body` here is the PARSED JSON object, cast to
  // `Record<string, unknown>` — deliberately NOT rebuilt field-by-field
  // into a fresh literal the way `signableActionEvent()` reconstructs its
  // preimage. Canonicalizing the parsed object means EVERY key `be` put on
  // the wire — including one this build's `PlatformAttestationBody`
  // interface has never heard of (e.g. MIL-0003's additive
  // `platformKeyVersion`) — flows into the signed bytes automatically and
  // the signature still verifies. This is structurally the OPPOSITE of
  // SEC-PA01-DISCOVERED-01, where a typed reconstruction silently dropped
  // fields the real signer included, making the signature unverifiable.
  // Do not "fix" this into a typed reconstruction (`{orgId: body.orgId,
  // ...}`) without re-deriving this exact property — that change would
  // reintroduce the SEC-PA01-DISCOVERED-01 failure mode for this seam.
  const message = canonicalJson(body as unknown as Record<string, unknown>);
  if (
    !verifySignature(
      'ECDSA_P256_SHA256',
      message,
      envelope.signature,
      new Uint8Array(pinnedDer),
    )
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason:
        'signature: platform attestation does not verify under pinned key',
    };
  }

  // Step 6 — declared fingerprint must match the pinned pubkey.
  if (body.platformSigningKeyFingerprint !== expectedFingerprint) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `fingerprint_mismatch: attestation declares ${body.platformSigningKeyFingerprint} but pinned pubkey hashes to ${expectedFingerprint}`,
    };
  }

  // Step 6b (SEC-2026-09-12, MCPSDK-01) — bind the attestation to THIS
  // export.
  //
  // The attestation is the only PLATFORM-signed input in the bundle; every
  // other input (manifest, rows, roots, public-keys.json) is signed by the
  // tenant key. Before this step the attestation was bound to an org and a
  // key set but to no particular bundle and to no point in time, so a
  // holder of a compromised-then-REVOKED tenant key could keep any genuine
  // PRE-revocation attestation, forge a whole bundle that re-labels that
  // key ACTIVE, and attach the old attestation: the key set matches
  // (the forger mirrors the pre-revocation state) and everything verifies.
  //
  // Two bindings, strongest first:
  //   (a) `manifestDigest` / `manifestGeneratedAt` — present on attestations
  //       from current exporters; pin the attestation to one export.
  //   (b) `issuedAt` vs `manifest.generatedAt` — always available. A
  //       platform attestation cannot have been issued meaningfully before
  //       the manifest it vouches for was generated.
  const manifestGeneratedMs = Date.parse(manifest.generatedAt);
  if (Number.isNaN(manifestGeneratedMs)) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason:
        'malformed: manifest generatedAt is not a parseable timestamp, so the attestation cannot be bound to this export',
    };
  }
  if (Date.parse(body.issuedAt) < manifestGeneratedMs - ATTESTATION_TIME_SKEW_MS) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason: `attestation_predates_manifest: attestation issuedAt ${
        body.issuedAt
      } is more than ${
        ATTESTATION_TIME_SKEW_MS / 3_600_000
      }h before manifest generatedAt ${
        manifest.generatedAt
      } — the platform cannot have vouched for an export that did not exist yet; this is what replaying an older attestation onto a newer (forged) bundle looks like`,
    };
  }
  const boundGeneratedAt: unknown = body.manifestGeneratedAt;
  const boundDigest: unknown = body.manifestDigest;
  if (boundGeneratedAt !== undefined) {
    if (
      typeof boundGeneratedAt !== 'string' ||
      Number.isNaN(Date.parse(boundGeneratedAt)) ||
      Date.parse(boundGeneratedAt) !== manifestGeneratedMs
    ) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `attestation_manifest_binding_mismatch: attestation is bound to a manifest generated at ${String(
          boundGeneratedAt,
        )} but this bundle's manifest declares ${manifest.generatedAt}`,
      };
    }
  }
  if (boundDigest !== undefined) {
    const actualDigest = crypto
      .createHash('sha256')
      .update(manifestSignableBytes(manifest))
      .digest('hex');
    if (
      typeof boundDigest !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(boundDigest) ||
      boundDigest.toLowerCase() !== actualDigest
    ) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `attestation_manifest_binding_mismatch: attestation is bound to manifest digest ${String(
          boundDigest,
        )} but this bundle's manifest signable bytes hash to ${actualDigest}`,
      };
    }
  }
  // MIL-0002-style loud-but-not-fatal note: a legacy attestation carries no
  // per-export binding at all. It is still accepted (customers verify
  // archives, not just today's exports) but the auditor must be told that
  // "platform attested" here means "attested for this ORG", not "attested
  // for THIS bundle".
  const bindingNote =
    boundGeneratedAt === undefined && boundDigest === undefined
      ? 'attestation_unbound_legacy: this attestation carries no manifestDigest/manifestGeneratedAt, so it vouches for the org key set, NOT for this specific export; upgrade the exporter'
      : undefined;

  // Step 7 — require a one-to-one key set and bind fingerprint + lifecycle
  // metadata. Omitting a revoked key or relabelling it ACTIVE must not turn a
  // valid platform attestation into permission to trust that key.
  const seenVersions = new Set<number>();
  for (const kv of body.keyVersions) {
    if (
      !Number.isSafeInteger(kv.keyVersion) ||
      kv.keyVersion < 1 ||
      typeof kv.fingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/.test(kv.fingerprint) ||
      (kv.status !== 'ACTIVE' &&
        kv.status !== 'ROTATED' &&
        kv.status !== 'REVOKED') ||
      typeof kv.issuedAt !== 'string' ||
      Number.isNaN(Date.parse(kv.issuedAt)) ||
      (kv.revokedAt !== null &&
        (typeof kv.revokedAt !== 'string' ||
          Number.isNaN(Date.parse(kv.revokedAt))))
    ) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: 'malformed: keyVersions entry missing keyVersion/fingerprint',
      };
    }
    if (seenVersions.has(kv.keyVersion)) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `duplicate_keyversion: attestation repeats keyVersion ${kv.keyVersion}`,
      };
    }
    seenVersions.add(kv.keyVersion);
    const pkEntry = publicKeysRaw[String(kv.keyVersion)];
    let pkB64: string | null = null;
    if (typeof pkEntry === 'string') {
      pkB64 = pkEntry;
    } else if (pkEntry && typeof pkEntry === 'object') {
      const obj = pkEntry as { publicKey?: unknown };
      if (typeof obj.publicKey === 'string') {
        pkB64 = obj.publicKey;
      }
    }
    if (pkB64 === null) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_not_in_bundle: attestation references keyVersion ${kv.keyVersion} which is missing from public-keys.json`,
      };
    }
    const pkBytes = decodeBase64Strict(pkB64);
    if (pkBytes === null) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_malformed: keyVersion ${kv.keyVersion} is not canonical base64`,
      };
    }
    const actualFingerprint = crypto
      .createHash('sha256')
      .update(pkBytes)
      .digest('hex');
    if (actualFingerprint !== kv.fingerprint) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_fingerprint_mismatch: keyVersion ${kv.keyVersion} attests ${kv.fingerprint} but public-keys.json bytes hash to ${actualFingerprint}`,
      };
    }
    const actualStatus =
      typeof pkEntry === 'string'
        ? 'ACTIVE'
        : (pkEntry as { status?: unknown }).status;
    const actualRevokedAt =
      typeof pkEntry === 'string'
        ? null
        : ((pkEntry as { revokedAt?: unknown }).revokedAt ?? null);
    if (actualStatus !== kv.status || actualRevokedAt !== kv.revokedAt) {
      return {
        ok: false,
        checked: 1,
        failed: 1,
        reason: `keyversion_lifecycle_mismatch: keyVersion ${kv.keyVersion} status/revokedAt differs from platform attestation`,
      };
    }
  }
  if (
    seenVersions.size !== Object.keys(publicKeysRaw).length ||
    Object.keys(publicKeysRaw).some(
      (version) => !seenVersions.has(Number(version)),
    )
  ) {
    return {
      ok: false,
      checked: 1,
      failed: 1,
      reason:
        'keyversion_set_mismatch: platform attestation must cover every bundled key exactly once',
    };
  }

  return {
    ok: true,
    checked: 1,
    failed: 0,
    ...(bindingNote !== undefined ? { reason: bindingNote } : {}),
    // AV-0002 — only this fully-verified path yields the key set.
    attestedKeys: body.keyVersions
      .map(({ keyVersion, status, fingerprint }) => ({
        keyVersion,
        status: status as AttestedTenantKey['status'],
        fingerprint,
        attestedAt: body.issuedAt,
      }))
      .sort((a, b) => a.keyVersion - b.keyVersion),
  };
}

// ════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════

function isIsoDate(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function assertManifestStructure(manifest: BundleManifest): void {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('manifest.json has an invalid structure');
  }
  // PROD16 F6 — explicit, non-positional version negotiation: fail loudly
  // on a manifest version newer than this build understands, rather than
  // silently verifying it against today's (possibly wrong) field set.
  if (
    !Number.isSafeInteger(manifest.version) ||
    manifest.version < 1 ||
    manifest.version > MAX_SUPPORTED_MANIFEST_VERSION
  ) {
    throw new Error(
      Number.isSafeInteger(manifest.version) &&
        manifest.version > MAX_SUPPORTED_MANIFEST_VERSION
        ? `manifest.json declares version ${manifest.version}, which is newer than the ${MAX_SUPPORTED_MANIFEST_VERSION} this @praesidia/audit-verifier build supports — upgrade the verifier before trusting this bundle`
        : 'manifest.json has an invalid structure',
    );
  }
  if (
    typeof manifest.orgId !== 'string' ||
    manifest.orgId.length === 0 ||
    !isIsoDate(manifest.from) ||
    !isIsoDate(manifest.to) ||
    Date.parse(manifest.from) > Date.parse(manifest.to) ||
    !isIsoDate(manifest.generatedAt) ||
    !Number.isSafeInteger(manifest.rowCount) ||
    manifest.rowCount < 0 ||
    !Number.isSafeInteger(manifest.rootCount) ||
    manifest.rootCount < 0 ||
    !Array.isArray(manifest.keyVersions) ||
    typeof manifest.signature !== 'string' ||
    !Number.isSafeInteger(manifest.signatureKeyVersion) ||
    (manifest.signatureAlgorithm !== 'Ed25519' &&
      manifest.signatureAlgorithm !== 'ECDSA_P256_SHA256')
  ) {
    throw new Error('manifest.json has an invalid structure');
  }
  const versions = new Set<number>();
  const keyFingerprints = new Set<string>();
  for (const key of manifest.keyVersions) {
    const decodedPublicKey =
      typeof key?.publicKey === 'string' && key.publicKey.length <= 512
        ? decodeBase64Strict(key.publicKey)
        : null;
    const fingerprint =
      decodedPublicKey === null
        ? null
        : crypto.createHash('sha256').update(decodedPublicKey).digest('hex');
    if (
      !key ||
      typeof key !== 'object' ||
      !Number.isSafeInteger(key.keyVersion) ||
      key.keyVersion < 1 ||
      decodedPublicKey === null ||
      decodedPublicKey.length === 0 ||
      fingerprint === null ||
      versions.has(key.keyVersion) ||
      keyFingerprints.has(fingerprint)
    ) {
      throw new Error('manifest.json contains an invalid/duplicate keyVersion');
    }
    versions.add(key.keyVersion);
    keyFingerprints.add(fingerprint);
  }
  // PROD16 §1b — basic type sanity for the two v3-only fields, IF present
  // at all (their presence-vs-absence relative to `manifest.version` is a
  // signable-set / tampering concern checked in `verifyManifest`, not a
  // format concern; this only rejects a garbage-typed value).
  if (
    'chainSeqCeiling' in manifest &&
    manifest.chainSeqCeiling !== null &&
    !Number.isSafeInteger(manifest.chainSeqCeiling)
  ) {
    throw new Error('manifest.json has an invalid structure');
  }
  if (
    'chainSeqSnapshotAt' in manifest &&
    manifest.chainSeqSnapshotAt !== null &&
    !isIsoDate(manifest.chainSeqSnapshotAt)
  ) {
    throw new Error('manifest.json has an invalid structure');
  }
  // FIX01 F5(b) — same format-sanity-only check for
  // `integrityCheckpointCount`; presence-vs-version is a tampering/skew
  // concern checked in `verifyManifest`, not a format concern.
  if (
    'integrityCheckpointCount' in manifest &&
    (!Number.isSafeInteger(manifest.integrityCheckpointCount) ||
      manifest.integrityCheckpointCount! < 0)
  ) {
    throw new Error('manifest.json has an invalid structure');
  }
  // PA-0010 — same format-sanity-only checks for the three v5 fields;
  // presence-vs-version is a tampering/skew concern checked in
  // `verifyManifest`, not a format concern.
  if (
    'actionEventCount' in manifest &&
    (!Number.isSafeInteger(manifest.actionEventCount) ||
      manifest.actionEventCount! < 0)
  ) {
    throw new Error('manifest.json has an invalid structure');
  }
  if (
    'captureScopeDigest' in manifest &&
    !isSha256HexDigest(manifest.captureScopeDigest)
  ) {
    throw new Error(
      'manifest.captureScopeDigest must be a lowercase sha256 hex digest',
    );
  }
  if ('evidenceGradeSummary' in manifest) {
    const s = manifest.evidenceGradeSummary;
    if (
      !s ||
      typeof s !== 'object' ||
      !Number.isSafeInteger(s.A) ||
      s.A < 0 ||
      !Number.isSafeInteger(s.B) ||
      s.B < 0 ||
      !Number.isSafeInteger(s.C) ||
      s.C < 0 ||
      !Number.isSafeInteger(s.D) ||
      s.D < 0 ||
      (s.enforcementMode !== 'observe' && s.enforcementMode !== 'enforce')
    ) {
      throw new Error('manifest.json has an invalid structure');
    }
  }
  // AV-0013 — format only; presence-vs-version is checked in `verifyManifest`.
  if ('evidencePrivacy' in manifest) {
    assertEvidencePrivacyStructure(manifest.evidencePrivacy, manifest.from, manifest.to);
  }
  // AV-0018 — format only; presence-vs-version is checked in `verifyManifest`.
  if (
    ('signatureFormat' in manifest && manifest.signatureFormat !== 1 && manifest.signatureFormat !== 2) ||
    ('signatureFormatCutoverAt' in manifest &&
      manifest.signatureFormatCutoverAt !== null &&
      !isIsoDate(manifest.signatureFormatCutoverAt))
  ) {
    throw new Error('manifest.json has an invalid signatureFormat/signatureFormatCutoverAt');
  }
}

function assertIntegrityCheckpointsStructure(
  checkpoints: BundleIntegrityCheckpoint[],
  orgId: string,
): void {
  const ids = new Set<string>();
  for (const cp of checkpoints) {
    if (
      !cp ||
      typeof cp !== 'object' ||
      typeof cp.id !== 'string' ||
      cp.id.length === 0 ||
      ids.has(cp.id) ||
      cp.organizationId !== orgId ||
      decodeBase64Strict(cp.chainHeadHash, 32) === null ||
      typeof cp.cumulativeRowCount !== 'string' ||
      cp.cumulativeRowCount.length > 20 ||
      !/^\d+$/.test(cp.cumulativeRowCount) ||
      !isIsoDate(cp.asOf) ||
      typeof cp.signature !== 'string' ||
      (cp.signatureAlgorithm !== 'Ed25519' &&
        cp.signatureAlgorithm !== 'ECDSA_P256_SHA256') ||
      !Number.isSafeInteger(cp.keyVersion) ||
      cp.keyVersion < 1
    ) {
      throw new Error(
        `integrity-checkpoints.ndjson.gz has an invalid/duplicate checkpoint: ${String(cp?.id)}`,
      );
    }
    ids.add(cp.id);
  }
}

/**
 * FIX01 (audit-verifier2) — format-sanity check for
 * `sealed-purges.ndjson.gz`. This file is NEVER part of the signed
 * manifest preimage (see `BundleSealedPurge`'s doc comment), so unlike
 * `assertIntegrityCheckpointsStructure` there is no version-gated
 * presence rule to enforce here — only that whatever IS present is
 * well-formed enough to parse safely. `rowCount` is validated as a
 * digit-string and never converted with `Number(...)` anywhere in this
 * file — see `verifySealedPurgeAuthenticity` / `verifyIntegrityCheckpoints`.
 */
function assertSealedPurgesStructure(
  purges: BundleSealedPurge[],
  orgId: string,
): void {
  const ids = new Set<string>();
  for (const p of purges) {
    const authFieldsAllNull =
      p?.signature === null &&
      p?.signingKeyVersion === null &&
      p?.signatureAlgorithm === null;
    const authFieldsAllPresent =
      typeof p?.signature === 'string' &&
      Number.isSafeInteger(p?.signingKeyVersion) &&
      (p.signatureAlgorithm === 'Ed25519' ||
        p.signatureAlgorithm === 'ECDSA_P256_SHA256');
    if (
      !p ||
      typeof p !== 'object' ||
      typeof p.id !== 'string' ||
      p.id.length === 0 ||
      ids.has(p.id) ||
      p.organizationId !== orgId ||
      !isIsoDate(p.periodStart) ||
      !isIsoDate(p.periodEnd) ||
      Date.parse(p.periodStart) >= Date.parse(p.periodEnd) ||
      typeof p.rowCount !== 'string' ||
      p.rowCount.length > 20 ||
      !/^[1-9]\d*$/.test(p.rowCount) ||
      decodeBase64Strict(p.rootHash, 32) === null ||
      (p.rekorReceipt !== null &&
        (typeof p.rekorReceipt !== 'object' ||
          Array.isArray(p.rekorReceipt))) ||
      !(authFieldsAllNull || authFieldsAllPresent) ||
      (p.signingKeyVersion !== null && p.signingKeyVersion < 1) ||
      !isIsoDate(p.deletedAt) ||
      typeof p.deletedBy !== 'string' ||
      p.deletedBy.length === 0 ||
      typeof p.approvalId !== 'string' ||
      p.approvalId.length === 0 ||
      !sealChainLinkFieldsWellFormed(p)
    ) {
      throw new Error(
        `sealed-purges.ndjson.gz has an invalid/duplicate entry: ${String(p?.id)}`,
      );
    }
    ids.add(p.id);
  }
}

const SEAL_CHAIN_LINK_FIELDS = [
  'chainLinkIn',
  'chainLinkOut',
  'chainLinkSignature',
  'chainLinkSigningKeyVersion',
  'chainLinkSignatureAlgorithm',
  'chainLinkSignatureFormat',
] as const;

/**
 * AV-2754 — the link fields are all absent (a seal from before BE-2979), or
 * all five present and well-formed with a format of absent, 1 or 2. Any other
 * combination is an invalid entry, never a seal that silently cannot bridge.
 */
function sealChainLinkFieldsWellFormed(p: BundleSealedPurge): boolean {
  if (SEAL_CHAIN_LINK_FIELDS.every((k) => p[k] === undefined)) return true;
  return (
    decodeBase64Strict(p.chainLinkIn, 32) !== null &&
    decodeBase64Strict(p.chainLinkOut, 32) !== null &&
    decodeBase64Strict(p.chainLinkSignature) !== null &&
    Number.isSafeInteger(p.chainLinkSigningKeyVersion) &&
    p.chainLinkSigningKeyVersion! >= 1 &&
    (p.chainLinkSignatureAlgorithm === 'Ed25519' ||
      p.chainLinkSignatureAlgorithm === 'ECDSA_P256_SHA256') &&
    (p.chainLinkSignatureFormat === undefined ||
      p.chainLinkSignatureFormat === 1 ||
      p.chainLinkSignatureFormat === 2)
  );
}

/**
 * FIX01 (audit-verifier2) / `FIX01-FIXED-be4.md`'s "FOR AUDIT-VERIFIER"
 * spec, step 1 ("Authenticity gate"). `sealed-purges.ndjson.gz` is NOT
 * part of the signed manifest preimage (see `BundleSealedPurge`'s doc
 * comment for why that is deliberate and safe), so each entry's OWN
 * signature — over `canonicalJson({organizationId, periodStart, periodEnd,
 * rowCount, rootHash, rekorReceipt})`, the seal's existing envelope from
 * `AuditRetentionSealService.purgeWithSeal` — is the ONLY thing standing
 * between "the tenant's signing key attested to this purge" and "an
 * attacker with raw DB write access typed some JSON into a purge-shaped
 * row." A holder of DB write access but not the signing key cannot
 * produce an entry that survives this gate, so omission-by-suppression
 * (an attacker who deletes rows AND scrubs the matching seal entry from
 * the wire) only returns the affected root/checkpoint to today's
 * conservative fail-closed state — never a forgery of a purge that did not
 * happen.
 *
 * Rejects (excludes from the returned set, WITHOUT affecting `ok` — see
 * this file's callers) an entry whose `signature`/`signingKeyVersion`/
 * `signatureAlgorithm` is `null` (legacy backfilled row — explicitly
 * unverifiable per the wire contract, never treated as evidence), whose
 * `signingKeyVersion` is not present in `public-keys.json`, or whose key
 * is `REVOKED` — the same three rejection conditions `verifyRowSignatures`
 * / `verifyRootSignatures` / the checkpoint authenticity check already
 * apply, reused here for consistency.
 */
function verifySealedPurgeAuthenticity(
  purges: BundleSealedPurge[],
  publicKeys: Map<number, PublicKeyRecord>,
  cutoverMs: number | null,
): BundleSealedPurge[] {
  const verified: BundleSealedPurge[] = [];
  for (const p of purges) {
    if (
      p.signature === null ||
      p.signingKeyVersion === null ||
      p.signatureAlgorithm === null
    ) {
      continue;
    }
    const entry = publicKeys.get(p.signingKeyVersion);
    if (!entry || entry.status === 'REVOKED') {
      continue;
    }
    const envelope = {
      organizationId: p.organizationId,
      periodStart: p.periodStart,
      periodEnd: p.periodEnd,
      rowCount: p.rowCount,
      rootHash: p.rootHash,
      rekorReceipt: p.rekorReceipt,
    };
    const currentMessage = canonicalJson(envelope);
    // AV-0018 — the envelope's latest signed timestamp is `periodEnd`
    // (`deletedAt` is unsigned, so it cannot be trusted for the cutover).
    let authentic =
      verifyTenantSignature(
        p.signatureAlgorithm, p.signatureFormat, 'retention-seal', currentMessage, p.signature, entry.publicKey,
        p.periodEnd, cutoverMs,
      ) === true;
    // Compatibility for seals emitted before the producer aligned its signed
    // representation with the bigint-as-string persistence/wire contract.
    // Those seals signed a JSON number, then stored/exported the same value as
    // a string. The source Merkle root uses a SQL integer, so only a canonical,
    // safely representable decimal is eligible for this exact legacy fallback.
    // The legacy numeric form predates format 2, so it is format-1 only.
    const legacyRowCount = Number(p.rowCount);
    if (!authentic && (p.signatureFormat === undefined || p.signatureFormat === 1) && Number.isSafeInteger(legacyRowCount) &&
      signatureFormatRejection(1, p.periodEnd, cutoverMs) === null) {
      authentic = verifySignature(
        p.signatureAlgorithm,
        canonicalJson({ ...envelope, rowCount: legacyRowCount }),
        p.signature,
        entry.publicKey,
      );
    }
    if (authentic) {
      verified.push(p);
    }
  }
  return verified;
}

/** AV-2754 — a signed purge-boundary link pair: link(P) → the survivor's `prevRowHash`. */
export interface ChainBridge {
  /** AV-2755 — the seal's `id`, so one seal exported by two bundles counts once in `verify-set`. */
  sealId: string;
  linkIn: string;
  linkOut: string;
}

/**
 * AV-2754 (BE-2979) — the bridges `verifyChain` may follow. `seals` MUST be
 * the output of `verifySealedPurgeAuthenticity` (6-field signature already
 * verified); of those, a seal bridges only if it carries links AND its link
 * signature verifies under purpose `retention-seal-link` over
 * {@link retentionSealLinkMessage}, with key `chainLinkSigningKeyVersion`
 * present and not REVOKED and the format-2 cutover checked against
 * `periodEnd` (as for the seal). The envelope names the seal's own
 * `organizationId`, which `assertSealedPurgesStructure` pinned to the
 * manifest's org, so a link signed for another org never verifies.
 */
function verifySealLinkAuthenticity(
  seals: BundleSealedPurge[],
  publicKeys: Map<number, PublicKeyRecord>,
  cutoverMs: number | null,
): ChainBridge[] {
  const bridges: ChainBridge[] = [];
  for (const p of seals) {
    // `sealChainLinkFieldsWellFormed` guarantees all-or-none.
    if (p.chainLinkIn === undefined || p.chainLinkOut === undefined) continue;
    const entry = publicKeys.get(p.chainLinkSigningKeyVersion!);
    if (!entry || entry.status === 'REVOKED') continue;
    const authentic = verifyTenantSignature(
      p.chainLinkSignatureAlgorithm!,
      p.chainLinkSignatureFormat,
      'retention-seal-link',
      retentionSealLinkMessage({
        organizationId: p.organizationId,
        periodStart: p.periodStart,
        periodEnd: p.periodEnd,
        rowCount: p.rowCount,
        rootHash: p.rootHash,
        chainLinkIn: p.chainLinkIn,
        chainLinkOut: p.chainLinkOut,
      }),
      p.chainLinkSignature!,
      entry.publicKey,
      p.periodEnd,
      cutoverMs,
    );
    if (authentic === true) {
      bridges.push({ sealId: p.id, linkIn: p.chainLinkIn, linkOut: p.chainLinkOut });
    }
  }
  return bridges;
}

function assertRowsStructure(rows: BundleRow[], orgId: string): void {
  const ids = new Set<string>();
  for (const row of rows) {
    if (
      !row ||
      typeof row !== 'object' ||
      typeof row.id !== 'string' ||
      row.id.length === 0 ||
      ids.has(row.id) ||
      row.organizationId !== orgId ||
      typeof row.action !== 'string' ||
      typeof row.actorType !== 'string' ||
      !isIsoDate(row.createdAt) ||
      !isIsoDate(row.signedAt) ||
      typeof row.signature !== 'string' ||
      !Number.isSafeInteger(row.keyVersion) ||
      row.keyVersion < 1
    ) {
      throw new Error(
        `rows.ndjson.gz has an invalid/duplicate row: ${String(row?.id)}`,
      );
    }
    ids.add(row.id);
  }
}

function assertRootsStructure(roots: BundleRoot[], orgId: string): void {
  const ids = new Set<string>();
  const hashes = new Set<string>();
  for (const root of roots) {
    if (
      !root ||
      typeof root !== 'object' ||
      typeof root.id !== 'string' ||
      root.id.length === 0 ||
      ids.has(root.id) ||
      root.organizationId !== orgId ||
      !isIsoDate(root.periodStart) ||
      !isIsoDate(root.periodEnd) ||
      Date.parse(root.periodStart) >= Date.parse(root.periodEnd) ||
      !Number.isSafeInteger(root.rowCount) ||
      root.rowCount < 1 ||
      decodeBase64Strict(root.rootHash, 32) === null ||
      hashes.has(root.rootHash) ||
      typeof root.signature !== 'string' ||
      !Number.isSafeInteger(root.keyVersion) ||
      root.keyVersion < 1 ||
      !isIsoDate(root.signedAt) ||
      (root.anchoredAt !== null && !isIsoDate(root.anchoredAt)) ||
      (root.anchorReceipt !== null &&
        (typeof root.anchorReceipt !== 'string' ||
          root.anchorReceipt.length === 0 ||
          Buffer.byteLength(root.anchorReceipt, 'utf8') > 1024 * 1024)) ||
      (root.anchorReceipts !== undefined &&
        (!Array.isArray(root.anchorReceipts) ||
          root.anchorReceipts.length > 64 ||
          !root.anchorReceipts.every(
            (entry) =>
              entry &&
              typeof entry === 'object' &&
              typeof entry.provider === 'string' &&
              entry.provider.length > 0 &&
              entry.provider.length <= 64 &&
              typeof entry.receipt === 'string' &&
              entry.receipt.length > 0 &&
              Buffer.byteLength(entry.receipt, 'utf8') <= 1024 * 1024 &&
              isIsoDate(entry.anchoredAt),
          ))) ||
      (root.signatureAlgorithm !== undefined &&
        root.signatureAlgorithm !== 'Ed25519' &&
        root.signatureAlgorithm !== 'ECDSA_P256_SHA256') ||
      (root.supersedesRootId !== undefined &&
        (typeof root.supersedesRootId !== 'string' || root.supersedesRootId.length === 0)) ||
      (root.supersessionSignature !== undefined && typeof root.supersessionSignature !== 'string')
    ) {
      throw new Error(
        `roots.ndjson.gz has an invalid/duplicate root: ${String(root?.id)}`,
      );
    }
    ids.add(root.id);
    hashes.add(root.rootHash);
  }
}

function assertProofsStructure(proofs: BundleProofEntry[]): void {
  for (const proof of proofs) {
    if (
      !proof ||
      typeof proof !== 'object' ||
      typeof proof.rowId !== 'string' ||
      proof.rowId.length === 0 ||
      (proof.status !== undefined && typeof proof.status !== 'string') ||
      (proof.proof !== undefined &&
        (!Array.isArray(proof.proof) ||
          !proof.proof.every((sibling) => typeof sibling === 'string')))
    ) {
      throw new Error('proofs.ndjson.gz has an invalid proof entry');
    }
  }
}

/**
 * Pull the signable fields out of a bundle row (mirrors AGV-030's 11-field
 * base shape).
 *
 * PROD16 F6 (be-compliance) — `ipAddress` is included IFF the wire row
 * object actually carries the key (`'ipAddress' in row`), NOT merely if
 * its value is non-null. `canonicalJson` treats an ABSENT key as omitted
 * from the signed bytes but a key PRESENT with value `null` as
 * `"ipAddress":null` — so this exactly reproduces be-core's own
 * conditional signable shape (`audit-canonical.helper.ts` only adds the
 * key at all once `signedAt >= IP_ADDRESS_SIGNABLE_CUTOVER_AT`) without
 * the verifier ever needing to know the cutover instant. Rows signed
 * before the cutover (and every pre-AUDIT-14 row) simply never carry the
 * key on the wire, so the 11-field preimage is unchanged for them.
 *
 * SCAN-AV-01 (be-audit N1) — `detailsCommitment` follows the identical
 * presence-guarded pattern, but REPLACES `summary`/`details` rather than
 * sitting alongside them: a post-cutover wire row omits `summary`/
 * `details` entirely and carries `detailsCommitment` instead. The
 * unconditional `summary: row.summary, details: row.details` assignment
 * below still correctly OMITS both from the canonical bytes for such a
 * row (their value is `undefined` — the keys are absent on the wire
 * object — and `canonicalJson` omits, never `null`-ifies, an
 * undefined-valued object property; see `crypto.ts`), so no extra guard
 * is needed for them. `detailsCommitment` itself needs the same `in`
 * guard as `ipAddress` (not just `?? null`) so an absent key is never
 * coalesced into an explicit signed `null`.
 */
function signableRow(row: BundleRow): Record<string, unknown> {
  const signable: Record<string, unknown> = {
    organizationId: row.organizationId,
    action: row.action,
    actorId: row.actorId,
    actorType: row.actorType,
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    teamId: row.teamId,
    agentId: row.agentId,
    summary: row.summary,
    details: row.details,
    createdAt: row.createdAt,
  };
  if ('ipAddress' in row) {
    signable.ipAddress = row.ipAddress ?? null;
  }
  if ('detailsCommitment' in row) {
    signable.detailsCommitment = row.detailsCommitment ?? null;
  }
  return signable;
}

/**
 * Compute the Merkle leaf preimage for a stored row:
 *   leaf = canonical(row) || base64-decode(row.signature)
 * The Merkle tree's `merkleVerify` adds the RFC 6962 0x00 leaf prefix
 * before hashing — see `merkleVerify` / `merkleBuild`.
 */
function computeLeaf(row: BundleRow): Uint8Array | null {
  const canonical = canonicalJson(signableRow(row));
  if (typeof row.signature !== 'string' || row.signature.length > 96) {
    return null;
  }
  const sigBytes = decodeBase64Strict(row.signature);
  if (sigBytes === null) return null;
  return new Uint8Array(Buffer.concat([canonical, sigBytes]));
}

/**
 * Compute the chain-link value the *next* row stores in
 * `prev_row_hash`:
 *   sha256(canonical(prev) || prev.sig_bytes)  (base64)
 */
function computeChainLink(prev: BundleRow): string | null {
  const canonical = canonicalJson(signableRow(prev));
  if (typeof prev.signature !== 'string' || prev.signature.length > 96) {
    return null;
  }
  const sigBytes = decodeBase64Strict(prev.signature);
  if (sigBytes === null) return null;
  return sha256(Buffer.concat([canonical, sigBytes])).toString('base64');
}

async function parseNdjsonChunks<T>(
  chunks: AsyncIterable<Buffer>,
  entryName: string,
  maxRecords: number,
  maxLineBytes: number,
  recordBudget: NdjsonRecordBudget,
): Promise<T[]> {
  const out: T[] = [];
  let lineParts: Buffer[] = [];
  let lineBytes = 0;
  let lineNumber = 1;

  const parseCurrentLine = (): void => {
    if (lineBytes === 0) {
      throw new Error(`${entryName} line ${lineNumber} is empty`);
    }
    if (out.length >= maxRecords) {
      throw new Error(
        `${entryName} record count exceeds verifier resource limit ${maxRecords}`,
      );
    }
    if (recordBudget.remainingRecords === 0) {
      throw new Error(
        `bundle NDJSON record count exceeds total resource limit while reading ${entryName}`,
      );
    }
    const lineBuffer =
      lineParts.length === 1
        ? lineParts[0]!
        : Buffer.concat(lineParts, lineBytes);
    let line: string;
    try {
      line = STRICT_UTF8_DECODER.decode(lineBuffer);
    } catch {
      throw new Error(`${entryName} line ${lineNumber} is not valid UTF-8`);
    }
    try {
      out.push(JSON.parse(line) as T);
      recordBudget.remainingRecords -= 1;
    } catch {
      throw new Error(`${entryName} line ${lineNumber} is not valid JSON`);
    }
    lineParts = [];
    lineBytes = 0;
  };

  for await (const chunk of chunks) {
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(0x0a, start);
      const end = newline === -1 ? chunk.length : newline;
      const partBytes = end - start;
      if (lineBytes > maxLineBytes - partBytes) {
        throw new Error(
          `${entryName} line ${lineNumber} exceeds verifier resource limit ${maxLineBytes} bytes`,
        );
      }
      if (partBytes > 0) {
        lineParts.push(chunk.subarray(start, end));
        lineBytes += partBytes;
      }
      if (newline === -1) break;

      parseCurrentLine();
      lineNumber += 1;
      start = newline + 1;
    }
  }

  // A final newline terminates the previous record and deliberately leaves
  // no pending line. Empty members remain the canonical encoding of zero
  // records; an internal/consecutive blank line is rejected above.
  if (lineBytes > 0) {
    if (lineBytes > maxLineBytes) {
      throw new Error(
        `${entryName} line ${lineNumber} exceeds verifier resource limit ${maxLineBytes} bytes`,
      );
    }
    parseCurrentLine();
  }
  return out;
}

interface NdjsonRecordBudget {
  remainingRecords: number;
}

/**
 * AUDIT-2026-05-14 — Parse one entry from `public-keys.json`.
 *
 * Accepts BOTH shapes:
 *   - Manifest v1 (pre-AUDIT-14): `string` — bare base64 public key,
 *     coerced to `{ status: 'ACTIVE', revokedAt: null }`.
 *   - Manifest v2 (AUDIT-14+):    `{ publicKey, status, revokedAt }`.
 *
 * This lets the v2 verifier read older bundles without a manual
 * conversion step. New bundles always emit the object shape.
 */
function parsePublicKeyEntry(
  raw: unknown,
  versionKey: string,
): PublicKeyRecord {
  if (typeof raw === 'string') {
    const publicKey = raw.length <= 512 ? decodeBase64Strict(raw) : null;
    if (publicKey === null || publicKey.length === 0) {
      throw new Error(
        `public-keys.json[${versionKey}] is not canonical base64`,
      );
    }
    return {
      publicKey: new Uint8Array(publicKey),
      status: 'ACTIVE',
      revokedAt: null,
    };
  }
  if (raw && typeof raw === 'object') {
    const obj = raw as {
      publicKey?: unknown;
      status?: unknown;
      revokedAt?: unknown;
    };
    if (typeof obj.publicKey !== 'string') {
      throw new Error(
        `public-keys.json[${versionKey}] missing string publicKey field`,
      );
    }
    const status = obj.status;
    if (status !== 'ACTIVE' && status !== 'ROTATED' && status !== 'REVOKED') {
      throw new Error(
        `public-keys.json[${versionKey}] has invalid status: ${String(status)}`,
      );
    }
    let revokedAt: Date | null = null;
    if (obj.revokedAt != null) {
      if (typeof obj.revokedAt !== 'string') {
        throw new Error(
          `public-keys.json[${versionKey}].revokedAt must be ISO string or null`,
        );
      }
      const parsed = new Date(obj.revokedAt);
      if (Number.isNaN(parsed.getTime())) {
        throw new Error(
          `public-keys.json[${versionKey}].revokedAt is not a valid ISO date`,
        );
      }
      revokedAt = parsed;
    }
    const publicKey =
      obj.publicKey.length <= 512 ? decodeBase64Strict(obj.publicKey) : null;
    if (publicKey === null || publicKey.length === 0) {
      throw new Error(
        `public-keys.json[${versionKey}].publicKey is not canonical base64`,
      );
    }
    return {
      publicKey: new Uint8Array(publicKey),
      status,
      revokedAt,
    };
  }
  throw new Error(
    `public-keys.json[${versionKey}] must be a string or {publicKey,status,revokedAt} object`,
  );
}

/**
 * BUG-AUDIT-02 — The signed-before-revocation grace was REMOVED. It
 * trusted `artifact.signedAt`, which is not covered by any signature in
 * the bundle, so a holder of a revoked key could backdate `signedAt` and
 * pass. The verifier now rejects EVERY REVOKED-key signature outright
 * (see `verifyRowSignatures` / `verifyRootSignatures`). Re-introducing a
 * legitimate pre-revocation window requires binding `signedAt` into the
 * signer preimage on both the be-core signer and here — a separate,
 * coordinated ticket.
 */
