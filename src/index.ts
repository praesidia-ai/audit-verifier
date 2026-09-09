/**
 * Public API surface for `@praesidia/audit-verifier`.
 *
 * Intentionally narrow — only the orchestrator and its report type are
 * exposed. The vendored crypto / zip primitives are implementation
 * details; consumers who need them should depend on a proper crypto
 * library rather than reaching into this package.
 */

export { verifyBundle } from './verify.js';
export type {
  VerifyReport,
  ComponentResult,
  ComponentStatus,
  VerifyOptions,
  VerifyResourceLimits,
  AnchorReceiptEntry,
  ExpectedAnchorRoot,
} from './verify.js';

export { verifyHttpReceipt, httpRequestCommitment, httpTargetKeyFingerprint } from './http-receipt.js';
export type { SignedHttpReceipt, HttpReceiptStatement, HttpRequestEnvelope, HttpReceiptExpected } from './http-receipt.js';
