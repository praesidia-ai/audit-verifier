/**
 * Public API surface for `@praesidia/audit-verifier`.
 *
 * Intentionally narrow — only the orchestrator and its report type are
 * exposed. The vendored crypto / zip primitives are implementation
 * details; consumers who need them should depend on a proper crypto
 * library rather than reaching into this package.
 */

export { verifyBundle, ROOT_SUPERSESSION_VERSION } from './verify.js';
export { verifyAuditPackage, isAuditPackage } from './package.js';
export { parsePlatformTrustAnchor, PLATFORM_TRUST_ANCHOR_PURPOSE } from './trust-anchor.js';
export type { PlatformTrustAnchor, PlatformTrustAnchorKey } from './trust-anchor.js';
export type { PackageIntegrity, PackageVerifyReport } from './package.js';
export type {
  VerifyReport,
  ComponentResult,
  ComponentStatus,
  VerifyOptions,
  VerifyResourceLimits,
  AnchorReceiptEntry,
  ExpectedAnchorRoot,
  AttestedTenantKey,
} from './verify.js';

export { formatProofLines, PROOF_COMPONENTS } from './proofs.js';
export { formatEvidencePrivacyLines, EVIDENCE_PRIVACY_MODES, EVIDENCE_PRIVACY_SCHEMA_VERSION } from './evidence-privacy.js';
export type {
  EvidencePrivacyMode,
  EvidencePrivacyProperty,
  EvidencePrivacyReport,
  EvidencePrivacyWindow,
  PayloadAbsence,
  PayloadAbsenceAnnotation,
} from './evidence-privacy.js';
export type { ProofType, ProofStatus } from './proofs.js';

export { findVerifiedDecision, DECISION_DISCLOSURE_VERSION } from './decision-disclosures.js';
export type { VerifiedDecision, DecisionDisclosureSummary } from './decision-disclosures.js';

export { verifyHttpReceipt, httpRequestCommitment, httpTargetKeyFingerprint } from './http-receipt.js';
export type { SignedHttpReceipt, HttpReceiptStatement, HttpRequestEnvelope, HttpReceiptExpected } from './http-receipt.js';

export { verifyAibomAttestation, aibomTrustFromBundle, AIBOM_ATTESTATION_FORMAT, AIBOM_SIGNING_DOMAIN } from './aibom.js';
export type { Rfc3161RootReport } from './rfc3161.js';
export type { AibomVerdict, AibomVerifyOptions, AibomVerifyReport } from './aibom.js';
