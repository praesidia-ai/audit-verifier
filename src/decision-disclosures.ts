/**
 * AV-0009 — offline check of `evidence/decision-receipts.ndjson` (be BE-1585,
 * `DecisionReceiptService.collectDecisionDisclosures`).
 *
 * The file is UNSIGNED. Each disclosure line opens one commitment-signed
 * Decision Record row of the bundle; it is trusted only because
 * `base64(sha256(salt || canonicalJson({details})))` equals the SIGNED
 * `detailsCommitment` of the bundle row it names. Nothing in a line that
 * fails that binding is ever reported as verified. See
 * `docs/decision-disclosures.md` for the line schema (the contract with be).
 */
import { canonicalJson, decodeBase64Strict, sha256 } from './crypto.js';

export const DECISION_DISCLOSURE_VERSION = 'praesidia.decision-disclosure.v1';
export const DECISION_DISCLOSURES_ENTRY = 'evidence/decision-receipts.ndjson';

const DECISION_ACTIONS = new Set(['POLICY_DECISION', 'POLICY_VIOLATION']);
const DECISION_OUTCOMES = new Set(['ALLOW', 'DENY', 'STEP_UP', 'OBSERVED']);
const DISCLOSURE_KEYS = ['decisionId', 'details', 'detailsSalt', 'rowId', 'version'];
const TRAILER_KEYS = ['version', 'withheld'];

/** The bundle-row fields this check reads (a structural subset of `BundleRow`). */
export interface DisclosedRow {
  id: string;
  action: string;
  createdAt: string;
  detailsCommitment?: string | null;
}

/** One disclosure whose opening matched its signed row's `detailsCommitment`. */
export interface VerifiedDecision {
  rowId: string;
  decisionId: string | null;
  /** From the SIGNED row. */
  rowAction: string;
  /** From the SIGNED row. */
  createdAt: string;
  /** The opened Decision Record payload, bound by the row's commitment. */
  details: Record<string, unknown>;
}

export interface DecisionDisclosureSummary {
  /** The trailer's (unsigned) count of rows the producer withheld. */
  withheld: number;
  /** Commitment-signed decision rows in the bundle with no disclosure line. */
  undisclosed: number;
  /** Distinct `(policyId, policyVersion)` over verified Decision Record v1 payloads. */
  policyReferences: Array<{ policyId: string; policyVersion: string | null }>;
  decisions: VerifiedDecision[];
}

interface Result {
  ok: boolean;
  checked: number;
  failed: number;
  firstFailure?: string;
  reason?: string;
}

export interface DecisionDisclosureCheck {
  receipt: Result;
  policy: Result;
  /** Present when the file was supplied and every line parsed. */
  summary?: DecisionDisclosureSummary;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const hasExactKeys = (o: Record<string, unknown>, keys: string[]): boolean =>
  Object.keys(o).sort().join(',') === keys.join(',');
const nullableId = (v: unknown): boolean => v === null || (typeof v === 'string' && v.length > 0);

function fail(r: Result, id: string, reason: string): void {
  r.ok = false;
  r.failed += 1;
  if (r.firstFailure === undefined) {
    r.firstFailure = id;
    r.reason = reason;
  }
}

/** Why a verified Decision Record v1 payload has a malformed policy reference, or null. */
function policyReferenceProblem(d: Record<string, unknown>, rowAction: string): string | null {
  if (!('policyId' in d) || !nullableId(d.policyId)) return 'policyId missing or not a non-empty string/null';
  if (!('policyVersion' in d) || !nullableId(d.policyVersion)) {
    return 'policyVersion missing or not a non-empty string/null';
  }
  if (typeof d.decision !== 'string' || !DECISION_OUTCOMES.has(d.decision)) {
    return `decision ${JSON.stringify(d.decision)} is not ALLOW|DENY|STEP_UP|OBSERVED`;
  }
  // be `auditActionFor`: a DENY is a POLICY_VIOLATION row, anything else a POLICY_DECISION.
  if ((d.decision === 'DENY') !== (rowAction === 'POLICY_VIOLATION')) {
    return `decision ${d.decision} on a signed ${rowAction} row`;
  }
  // be `canonicalDecisionFor` (BE-1590; absent on older rows).
  if ('canonicalDecision' in d) {
    const expected =
      d.decision === 'DENY' ? ['DENY'] : d.decision === 'STEP_UP' ? ['REQUIRE_APPROVAL'] : ['ALLOW', 'LIMIT'];
    if (!expected.includes(d.canonicalDecision as string)) {
      return `canonicalDecision ${JSON.stringify(d.canonicalDecision)} contradicts decision ${d.decision}`;
    }
  }
  // An ALLOW that consumed a step-up approval must name that approval.
  if (d.decision === 'ALLOW' && d.reasonCode === 'approval_consumed' && !(typeof d.approvalId === 'string' && d.approvalId)) {
    return 'ALLOW after step-up approval (approval_consumed) carries no approvalId';
  }
  if ('approvalId' in d && !nullableId(d.approvalId)) return 'approvalId is not a non-empty string/null';
  return null;
}

/**
 * Verify disclosure lines against the bundle's rows. `raw === null` (no
 * file) checks nothing, which the caller reports as `not_present`.
 * `limits` bound the parse; exceeding one, a non-UTF-8 byte, a line that
 * is not a JSON object, an unknown `version`, a missing or misplaced
 * trailer, or a duplicate `rowId` all fail the component.
 */
export function verifyDecisionDisclosures(
  raw: Buffer | null,
  rows: readonly DisclosedRow[],
  limits: { maxLines: number; maxLineBytes: number },
): DecisionDisclosureCheck {
  const receipt: Result = { ok: true, checked: 0, failed: 0 };
  const policy: Result = { ok: true, checked: 0, failed: 0 };
  if (raw === null) return { receipt, policy };

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    fail(receipt, DECISION_DISCLOSURES_ENTRY, 'not valid UTF-8');
    return { receipt, policy };
  }
  const lines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : [text];
  if (lines.length > limits.maxLines) {
    fail(receipt, DECISION_DISCLOSURES_ENTRY, `more than ${limits.maxLines} lines`);
    return { receipt, policy };
  }
  const parsed: Record<string, unknown>[] = [];
  for (const [i, line] of lines.entries()) {
    if (Buffer.byteLength(line) > limits.maxLineBytes) {
      fail(receipt, `line ${i + 1}`, `exceeds ${limits.maxLineBytes} bytes`);
      return { receipt, policy };
    }
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      value = undefined;
    }
    if (!isObject(value)) {
      fail(receipt, `line ${i + 1}`, 'not a JSON object');
      return { receipt, policy };
    }
    parsed.push(value);
  }
  const trailer = parsed.pop();
  if (!trailer || trailer.version !== DECISION_DISCLOSURE_VERSION || !hasExactKeys(trailer, TRAILER_KEYS)
    || !Number.isSafeInteger(trailer.withheld) || (trailer.withheld as number) < 0) {
    fail(receipt, `line ${lines.length}`, `last line is not the ${DECISION_DISCLOSURE_VERSION} {version, withheld} trailer`);
    return { receipt, policy };
  }

  const rowsById = new Map(rows.map((r) => [r.id, r]));
  const seen = new Set<string>();
  const decisions: VerifiedDecision[] = [];
  for (const [i, line] of parsed.entries()) {
    receipt.checked += 1;
    const id = typeof line.rowId === 'string' && line.rowId ? line.rowId : `line ${i + 1}`;
    if (line.version !== DECISION_DISCLOSURE_VERSION || !hasExactKeys(line, DISCLOSURE_KEYS)) {
      fail(receipt, id, `not a ${DECISION_DISCLOSURE_VERSION} disclosure line (unknown version or keys)`);
      continue;
    }
    const { rowId, decisionId, details, detailsSalt } = line;
    const salt = decodeBase64Strict(detailsSalt);
    if (id !== rowId || !nullableId(decisionId) || !isObject(details) || salt === null) {
      fail(receipt, id, 'malformed rowId, decisionId, details or detailsSalt');
      continue;
    }
    if (seen.has(rowId)) {
      fail(receipt, id, 'duplicate disclosure for one row');
      continue;
    }
    seen.add(rowId);
    const row = rowsById.get(rowId);
    if (!row) {
      fail(receipt, id, 'disclosure names a row that is not in the bundle');
      continue;
    }
    if (!DECISION_ACTIONS.has(row.action) || typeof row.detailsCommitment !== 'string') {
      fail(receipt, id, `row is a ${row.action} row without a signed detailsCommitment`);
      continue;
    }
    let commitment: string | null;
    try {
      commitment = sha256(Buffer.concat([salt, canonicalJson({ details })])).toString('base64');
    } catch {
      commitment = null; // e.g. a non-finite number: not canonicalisable, cannot match
    }
    if (commitment !== row.detailsCommitment) {
      fail(receipt, id, 'opening does not match the signed detailsCommitment');
      continue;
    }
    if (decisionId !== (typeof details.decisionId === 'string' ? details.decisionId : null)) {
      fail(receipt, id, 'decisionId does not match details.decisionId');
      continue;
    }
    decisions.push({ rowId, decisionId: decisionId as string | null, rowAction: row.action, createdAt: row.createdAt, details });
  }

  const pairs = new Map<string, { policyId: string; policyVersion: string | null }>();
  let legacy = 0;
  let unreferenced = 0;
  for (const d of decisions) {
    if (!('schemaVersion' in d.details)) {
      legacy += 1; // pre-MP-B06 payload: never carried a policy reference
      continue;
    }
    policy.checked += 1;
    const problem =
      d.details.schemaVersion === 1
        ? policyReferenceProblem(d.details, d.rowAction)
        : `unknown Decision Record schemaVersion ${JSON.stringify(d.details.schemaVersion)}`;
    if (problem) {
      fail(policy, d.rowId, problem);
      continue;
    }
    const policyId = d.details.policyId as string | null;
    const policyVersion = d.details.policyVersion as string | null;
    if (policyId === null) unreferenced += 1;
    else pairs.set(JSON.stringify([policyId, policyVersion]), { policyId, policyVersion });
  }

  const inBundle = rows.filter((r) => DECISION_ACTIONS.has(r.action) && 'detailsCommitment' in r).length;
  const withheld = trailer.withheld as number;
  const undisclosed = inBundle - decisions.length;
  if (receipt.ok) {
    receipt.reason = `${decisions.length} opened; ${withheld} withheld (unsigned trailer); ${undisclosed} commitment-signed decision rows in the bundle not opened`;
  }
  if (policy.ok) {
    policy.reason =
      `${pairs.size} distinct (policyId, policyVersion); ${unreferenced} decisions name no policy; ` +
      `${legacy} pre-Decision-Record-v1 payloads carry none; policy text is not in the package and is NOT verified`;
  }
  return {
    receipt,
    policy,
    summary: { withheld, undisclosed, policyReferences: [...pairs.values()], decisions },
  };
}

/**
 * `--decision <id>`: the verified decision, or null when it is not disclosed
 * or not verified. Verified means the whole report is `valid` (row
 * signatures, chain, keys, platform attestation all pass) AND its opening
 * matched the signed commitment AND its policy reference is well-formed.
 */
export function findVerifiedDecision(
  report: {
    status: string;
    decisionReceipt: { status: string };
    policyReference: { status: string };
    decisionDisclosures?: DecisionDisclosureSummary;
  },
  decisionId: string,
): VerifiedDecision | null {
  if (report.status !== 'valid' || report.decisionReceipt.status !== 'valid' || report.policyReference.status === 'invalid') {
    return null;
  }
  return report.decisionDisclosures?.decisions.find((d) => d.decisionId === decisionId) ?? null;
}

/** Human-readable verified fields of one decision (`--decision`). */
export function formatDecision(d: VerifiedDecision): string[] {
  const s = (v: unknown): string => (typeof v === 'string' && v ? v : v == null ? 'none' : JSON.stringify(v));
  const x = d.details;
  const actor = isObject(x.actor) ? `${s(x.actor.type)}:${s(x.actor.id)}` : 'none';
  const resource = isObject(x.resource) ? `${s(x.resource.type)}:${s(x.resource.id)}` : 'none';
  return [
    `decisionId:      ${s(d.decisionId)}  (row ${d.rowId}, signed ${d.rowAction})`,
    `timestamp:       ${d.createdAt}  (signed row createdAt)`,
    `decision:        ${s(x.decision)}${'canonicalDecision' in x ? `  (canonical ${s(x.canonicalDecision)})` : ''}`,
    `policy:          ${s(x.policyId)}@${s(x.policyVersion)}  rule ${s(x.ruleId)}  (reference only; policy text is not in the package)`,
    `approvalId:      ${s(x.approvalId)}`,
    `actor:           ${actor}`,
    `action:          ${s(x.action)}  resource ${resource}`,
    `tool:            ${s(x.fnName)}`,
    `reasonCode:      ${s(x.reasonCode)}  enforcement ${s(x.enforcementMode)}`,
  ];
}
