/**
 * AV-0013 — manifest v6 `evidencePrivacy` (be BE-1615): the org's declared
 * evidence privacy mode over `[from, to)`, and what each mode lets this bundle
 * prove. Everything here is annotation: it never changes a component status.
 *
 * Wire shape (inside the signed manifest preimage):
 *   { modes: [{ mode, effectiveFrom }], schemaVersion }
 * `modes[0].effectiveFrom === manifest.from`; later entries are ascending and
 * fall in `[from, to)`. `schemaVersion` is be's
 * `EVIDENCE_PRIVACY_SCHEMA_VERSION` (the meaning of each mode, per field).
 */

export const EVIDENCE_PRIVACY_MODES = ['FULL', 'REDACTED', 'METADATA_ONLY', 'ZERO_RETENTION'] as const;
export type EvidencePrivacyMode = (typeof EVIDENCE_PRIVACY_MODES)[number];

/** The be mode-table version this build knows. Any other fails closed. */
export const EVIDENCE_PRIVACY_SCHEMA_VERSION = 1;

export type EvidencePrivacyProperty =
  | 'chain_integrity'
  | 'signatures'
  | 'ordering'
  | 'commitment_binding'
  | 'content_equality'
  | 'target_ack_body';

export interface EvidencePrivacyDeclaration {
  modes: Array<{ mode: EvidencePrivacyMode; effectiveFrom: string }>;
  schemaVersion: number;
}

export interface EvidencePrivacyWindow {
  mode: EvidencePrivacyMode;
  effectiveFrom: string;
  effectiveTo: string;
  proven: EvidencePrivacyProperty[];
  notProvable: EvidencePrivacyProperty[];
}

export type PayloadAbsenceAnnotation =
  | `evidence_privacy_mode:${EvidencePrivacyMode}`
  | 'undeclared_payload_absence';

export interface PayloadAbsence {
  /** `actionId#actionSeq`. */
  event: string;
  eventType: string;
  receivedAt: string;
  annotation: PayloadAbsenceAnnotation;
}

export interface EvidencePrivacyReport {
  /** `false` on manifest v1–v5: no signed declaration, read as one `FULL (undeclared)` window. */
  declared: boolean;
  schemaVersion: number | null;
  modes: EvidencePrivacyWindow[];
  /** Every action event with `payload: null`. Never a failure by itself (erasure is a legitimate cause). */
  payloadAbsences: PayloadAbsence[];
}

const ALWAYS: EvidencePrivacyProperty[] = ['chain_integrity', 'signatures', 'ordering', 'commitment_binding'];
const CONTENT: EvidencePrivacyProperty[] = ['content_equality', 'target_ack_body'];

/**
 * Only a declared FULL window claims the stored content is the original. An
 * undeclared (pre-v6) bundle claims no mode, so it cannot rule out a reduced
 * payload and does not claim content equality either.
 */
function properties(mode: EvidencePrivacyMode, declared: boolean): Pick<EvidencePrivacyWindow, 'proven' | 'notProvable'> {
  return mode === 'FULL' && declared
    ? { proven: [...ALWAYS, ...CONTENT], notProvable: [] }
    : { proven: [...ALWAYS], notProvable: [...CONTENT] };
}

function fail(msg: string): never {
  throw new Error(`manifest.evidencePrivacy ${msg}`);
}

const hasExactKeys = (o: object, keys: string[]): boolean =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/** Format check, run on any manifest that carries the field. Throws (bundle-format error). */
export function assertEvidencePrivacyStructure(
  value: unknown,
  from: string,
  to: string,
): asserts value is EvidencePrivacyDeclaration {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !hasExactKeys(value, ['modes', 'schemaVersion'])) {
    fail('must be exactly { modes, schemaVersion }');
  }
  const { modes, schemaVersion } = value as { modes: unknown; schemaVersion: unknown };
  if (!Number.isSafeInteger(schemaVersion)) fail('schemaVersion must be an integer');
  if (schemaVersion !== EVIDENCE_PRIVACY_SCHEMA_VERSION) {
    fail(`schemaVersion ${String(schemaVersion)} is not the ${EVIDENCE_PRIVACY_SCHEMA_VERSION} this build knows — upgrade the verifier before trusting this bundle`);
  }
  if (!Array.isArray(modes) || modes.length === 0) fail('modes must be a non-empty array');
  let prev = Number.NEGATIVE_INFINITY;
  modes.forEach((m: unknown, i) => {
    if (!m || typeof m !== 'object' || !hasExactKeys(m, ['mode', 'effectiveFrom'])) {
      fail(`modes[${i}] must be exactly { mode, effectiveFrom }`);
    }
    const { mode, effectiveFrom } = m as { mode: unknown; effectiveFrom: unknown };
    if (!EVIDENCE_PRIVACY_MODES.includes(mode as EvidencePrivacyMode)) fail(`modes[${i}].mode ${JSON.stringify(mode)} is not a known mode`);
    const at = typeof effectiveFrom === 'string' ? Date.parse(effectiveFrom) : Number.NaN;
    if (Number.isNaN(at)) fail(`modes[${i}].effectiveFrom must be an ISO-8601 date`);
    if (i === 0 && effectiveFrom !== from) fail('modes[0].effectiveFrom must equal manifest.from');
    if (i > 0 && (at < prev || at >= Date.parse(to))) fail(`modes[${i}].effectiveFrom must be ascending and before manifest.to`);
    prev = at;
  });
}

/** The mode timeline, per-mode proof properties, and the `payload: null` annotations. */
export function evidencePrivacyReport(
  declaration: EvidencePrivacyDeclaration | undefined,
  from: string,
  to: string,
  events: ReadonlyArray<{ actionId: string; actionSeq: number; eventType: string; receivedAt: string; payload: unknown }>,
): EvidencePrivacyReport {
  const declared = declaration !== undefined;
  const timeline = declaration?.modes ?? [{ mode: 'FULL' as const, effectiveFrom: from }];
  const modes = timeline.map((m, i) => ({
    mode: m.mode,
    effectiveFrom: m.effectiveFrom,
    effectiveTo: timeline[i + 1]?.effectiveFrom ?? to,
    ...properties(m.mode, declared),
  }));
  const annotate = (receivedAt: string): PayloadAbsenceAnnotation => {
    const t = Date.parse(receivedAt);
    const w = modes.find((m) => Date.parse(m.effectiveFrom) <= t && t < Date.parse(m.effectiveTo));
    return declared && w && w.mode !== 'FULL' ? `evidence_privacy_mode:${w.mode}` : 'undeclared_payload_absence';
  };
  const payloadAbsences = events
    .filter((e) => e.payload === null)
    .map((e) => ({
      event: `${e.actionId}#${e.actionSeq}`,
      eventType: e.eventType,
      receivedAt: e.receivedAt,
      annotation: annotate(e.receivedAt),
    }));
  return { declared, schemaVersion: declaration?.schemaVersion ?? null, modes, payloadAbsences };
}

/**
 * `reason` for a component left `incomplete` by `payload: null` events of
 * `eventType`: set only when EVERY such event sits in a declared reduced-mode
 * window. The status itself is never touched.
 */
export function evidencePrivacyReason(report: EvidencePrivacyReport, eventType: string): string | undefined {
  const notes = report.payloadAbsences.filter((a) => a.eventType === eventType).map((a) => a.annotation);
  if (notes.length === 0 || notes.includes('undeclared_payload_absence')) return undefined;
  return [...new Set(notes)].join(',');
}

/** Text-report lines for the `evidencePrivacy` section. */
export function formatEvidencePrivacyLines(report: EvidencePrivacyReport): string[] {
  const lines = [`evidence privacy: ${report.declared ? `declared (schema v${report.schemaVersion})` : 'not declared (manifest < v6)'}`];
  for (const m of report.modes) {
    lines.push(
      `  ${m.mode}${report.declared ? '' : ' (undeclared)'} [${m.effectiveFrom}, ${m.effectiveTo}) proven: ${m.proven.join(', ')}; not provable: ${m.notProvable.join(', ') || 'none'}`,
    );
  }
  for (const a of report.payloadAbsences) lines.push(`  payload absent ${a.event} ${a.eventType}: ${a.annotation}`);
  return lines;
}
