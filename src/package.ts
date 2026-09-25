/**
 * AV-0007 — verify an audit package (`GET audit/packages/:id/download`,
 * be `audit-package.service.ts`) directly. The package is an outer zip: the
 * signed bundle sits byte-for-byte at `evidence/audit-bundle.zip`, next to an
 * UNSIGNED `verification.txt` stating its SHA-256 and byte count.
 *
 * Trust: only the inner bundle's signatures authenticate anything. The
 * receipt check binds this package to that bundle (a swapped or altered
 * bundle is caught even if it is itself validly signed); every other entry
 * is reported as an unsigned side artifact and never marked verified.
 */
import * as crypto from 'node:crypto';
import { verifyBundle, type VerifyOptions, type VerifyReport } from './verify.js';
import { MAX_ZIP_ARCHIVE_BYTES, readZip, type ZipEntry } from './zip.js';
import { DECISION_DISCLOSURES_ENTRY } from './decision-disclosures.js';
import { deriveProofs } from './proofs.js';

export const PACKAGE_BUNDLE_ENTRY = 'evidence/audit-bundle.zip';
const RECEIPT_ENTRY = 'verification.txt';
const MAX_RECEIPT_BYTES = 64 * 1024;

export interface PackageIntegrity {
  /** `incomplete` only when verification.txt is absent; unparseable = `invalid`. */
  status: 'valid' | 'invalid' | 'incomplete';
  /** `null` = not checked (no receipt). */
  sha256Matches: boolean | null;
  byteCountMatches: boolean | null;
  reason?: string;
  /** Every other package entry: unsigned, NOT verified. */
  sideArtifacts: string[];
}

export interface PackageVerifyReport extends VerifyReport {
  package: PackageIntegrity;
}

/** Package entries, or null when `buffer` is not an audit package (or not a readable zip). */
function packageEntries(buffer: Buffer): Map<string, ZipEntry> | null {
  let entries: ZipEntry[];
  try {
    // STORED-only reader: an entry can never exceed the archive, so capping
    // entries at the archive cap adds no amplification; the inner bundle then
    // meets the exact caps of a direct bundle inside verifyBundle.
    entries = readZip(buffer, {
      maxEntryUncompressedBytes: MAX_ZIP_ARCHIVE_BYTES,
      maxTotalUncompressedBytes: MAX_ZIP_ARCHIVE_BYTES,
    });
  } catch {
    return null; // left to verifyBundle's own (strict) format error
  }
  const byName = new Map(entries.map((e) => [e.name, e]));
  return !byName.has('manifest.json') && byName.has(PACKAGE_BUNDLE_ENTRY) ? byName : null;
}

/** True when `buffer` is an audit package rather than a signed bundle. */
export function isAuditPackage(buffer: Buffer): boolean {
  return packageEntries(buffer) !== null;
}

function checkReceipt(inner: Buffer, receipt: ZipEntry | undefined): Omit<PackageIntegrity, 'sideArtifacts'> {
  if (!receipt) {
    return { status: 'incomplete', sha256Matches: null, byteCountMatches: null, reason: `${RECEIPT_ENTRY} missing` };
  }
  const invalid = (reason: string) =>
    ({ status: 'invalid', sha256Matches: null, byteCountMatches: null, reason }) as const;
  if (receipt.data.length > MAX_RECEIPT_BYTES) return invalid(`${RECEIPT_ENTRY} exceeds ${MAX_RECEIPT_BYTES} bytes`);
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(receipt.data);
  } catch {
    return invalid(`${RECEIPT_ENTRY} is not valid UTF-8`);
  }
  const field = (label: string, shape: RegExp): string | null => {
    const values = text.split('\n').filter((l) => l.startsWith(label)).map((l) => l.slice(label.length).trim());
    return values.length === 1 && shape.test(values[0]!) ? values[0]! : null;
  };
  const statedSha = field('Evidence archive SHA-256: ', /^[0-9a-f]{64}$/);
  const statedBytes = field('Evidence archive bytes: ', /^(0|[1-9][0-9]{0,15})$/);
  if (statedSha === null || statedBytes === null) {
    return invalid(`${RECEIPT_ENTRY} lacks exactly one well-formed SHA-256 and bytes line`);
  }
  const actualSha = crypto.createHash('sha256').update(inner).digest('hex');
  const sha256Matches = actualSha === statedSha;
  const byteCountMatches = Number(statedBytes) === inner.length;
  const problems = [
    ...(sha256Matches ? [] : [`SHA-256 ${actualSha} != stated ${statedSha}`]),
    ...(byteCountMatches ? [] : [`byte count ${inner.length} != stated ${statedBytes}`]),
  ];
  return problems.length === 0
    ? { status: 'valid', sha256Matches, byteCountMatches }
    : { status: 'invalid', sha256Matches, byteCountMatches, reason: `${PACKAGE_BUNDLE_ENTRY} ${problems.join('; ')}` };
}

/**
 * Verify an audit package: receipt check, then the inner bundle exactly as
 * `verifyBundle`. Top-level status: `invalid` if either is invalid, else
 * `incomplete` if either is, else `valid`. Throws (like `verifyBundle`) on a
 * format error or when `buffer` is not an audit package.
 */
export async function verifyAuditPackage(
  buffer: Buffer,
  options: VerifyOptions = {},
): Promise<PackageVerifyReport> {
  const byName = packageEntries(buffer);
  if (byName === null) {
    throw new Error(`not an audit package: need ${PACKAGE_BUNDLE_ENTRY} and no manifest.json`);
  }
  const inner = byName.get(PACKAGE_BUNDLE_ENTRY)!.data;
  const integrity = checkReceipt(inner, byName.get(RECEIPT_ENTRY));
  // AV-0009 — the decision disclosures are checked line by line against the
  // bundle's signed rows (`decisionReceipt`), so they are not a side artifact.
  const disclosures = byName.get(DECISION_DISCLOSURES_ENTRY)?.data;
  if (disclosures && options.decisionDisclosures) {
    throw new Error(`the package carries ${DECISION_DISCLOSURES_ENTRY}; do not also pass --disclosures`);
  }
  const consumed = new Set([PACKAGE_BUNDLE_ENTRY, RECEIPT_ENTRY, DECISION_DISCLOSURES_ENTRY]);
  const sideArtifacts = [...byName.keys()].filter((n) => !consumed.has(n));
  let report: VerifyReport;
  try {
    report = await verifyBundle(inner, disclosures ? { ...options, decisionDisclosures: disclosures } : options);
  } catch (err) {
    const msg = `${PACKAGE_BUNDLE_ENTRY}: ${(err as Error).message}`;
    throw new Error(integrity.status === 'invalid' ? `${integrity.reason}; ${msg}` : msg);
  }
  const statuses = [report.status, integrity.status];
  const status = statuses.includes('invalid') ? 'invalid' : statuses.includes('incomplete') ? 'incomplete' : 'valid';
  return {
    ...report,
    ok: status === 'valid',
    status,
    proofs: deriveProofs(report, integrity.status),
    package: { ...integrity, sideArtifacts },
  };
}
