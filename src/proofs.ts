/**
 * AV-0010 — the six auditor-facing proof types, each a reduction over named
 * `VerifyReport` components (table: docs/ARCHITECTURE.md "Proof summary").
 * Every component maps to exactly one proof, so `RESULT: FAIL` (status
 * `invalid`) always has a `FAIL <proof>` line beside it and vice versa.
 */
import type { ComponentResult, ComponentStatus, VerifyReport } from './verify.js';

export type ProofType =
  | 'signature'
  | 'hashChain'
  | 'decisionReceipt'
  | 'policyReference'
  | 'evidenceIntegrity'
  | 'targetReceipt';

export type ProofStatus = 'pass' | 'fail' | 'not_present' | 'incomplete';

type ComponentKey = {
  [K in keyof VerifyReport]-?: VerifyReport[K] extends ComponentResult ? K : never;
}[keyof VerifyReport];

export const PROOF_COMPONENTS: Readonly<Record<ProofType, readonly ComponentKey[]>> = {
  signature: ['manifest', 'rowSignatures', 'rootSignatures', 'platformAttestation', 'keyBinding'],
  hashChain: ['chain', 'inclusionProofs', 'rekor', 'completeness', 'rootCoverage', 'integrityCheckpoints'],
  decisionReceipt: ['decisionReceipt'],
  policyReference: ['policyReference'],
  // + the audit package's verification.txt receipt, when verifying a package.
  evidenceIntegrity: [
    'actionEventChain', 'permitBinding', 'requestBinding', 'dispatchIntegrity',
    'callerResult', 'closureLegality', 'evidenceGrade', 'actionCompleteness',
  ],
  targetReceipt: ['targetAck'],
};

const LABELS: Record<ProofType, string> = {
  signature: 'signature',
  hashChain: 'hash chain',
  decisionReceipt: 'decision receipt',
  policyReference: 'policy reference',
  evidenceIntegrity: 'evidence integrity',
  targetReceipt: 'target receipt',
};

/** Same order as `reduceStatus`: invalid beats incomplete beats valid; unsupported counts as absent. */
function reduce(statuses: readonly ComponentStatus[]): ProofStatus {
  if (statuses.includes('invalid')) return 'fail';
  if (statuses.includes('incomplete')) return 'incomplete';
  return statuses.includes('valid') ? 'pass' : 'not_present';
}

/** `packageStatus` — the audit package receipt check, folded into `evidenceIntegrity`. */
export function deriveProofs(
  report: Pick<VerifyReport, ComponentKey>,
  packageStatus?: ComponentStatus,
): Record<ProofType, ProofStatus> {
  const out = {} as Record<ProofType, ProofStatus>;
  for (const [proof, keys] of Object.entries(PROOF_COMPONENTS) as [ProofType, readonly ComponentKey[]][]) {
    const statuses = keys.map((k) => report[k].status);
    if (proof === 'evidenceIntegrity' && packageStatus) statuses.push(packageStatus);
    out[proof] = reduce(statuses);
  }
  return out;
}

/** The six `PASS|FAIL|NOT_PRESENT|INCOMPLETE <proof>` lines, in `PROOF_COMPONENTS` order. */
export function formatProofLines(proofs: Record<ProofType, ProofStatus>): string[] {
  return (Object.keys(PROOF_COMPONENTS) as ProofType[]).map(
    (p) => `${proofs[p].toUpperCase()} ${LABELS[p]}`,
  );
}
