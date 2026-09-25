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
export type { ProofType, ProofStatus } from './proofs.js';

export { findVerifiedDecision, DECISION_DISCLOSURE_VERSION } from './decision-disclosures.js';
export type { VerifiedDecision, DecisionDisclosureSummary } from './decision-disclosures.js';

export { verifyHttpReceipt, httpRequestCommitment, httpTargetKeyFingerprint } from './http-receipt.js';
export type { SignedHttpReceipt, HttpReceiptStatement, HttpRequestEnvelope, HttpReceiptExpected } from './http-receipt.js';

export { verifyAibomAttestation, aibomTrustFromBundle, AIBOM_ATTESTATION_FORMAT, AIBOM_SIGNING_DOMAIN } from './aibom.js';
export type { AibomVerdict, AibomVerifyOptions, AibomVerifyReport } from './aibom.js';
