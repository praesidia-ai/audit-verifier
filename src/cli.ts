#!/usr/bin/env node
/**
 * `praesidia-verify` CLI entry point.
 *
 * Usage:
 *   praesidia-verify <bundle.zip> [--no-rekor] [--quiet] [--json] [--help]
 *
 * Exit codes:
 *   0  All checks passed (status: valid).
 *   1  Verification failure (status: invalid — signature / chain / proof
 *      mismatch, or any component invalid).
 *   2  I/O or bundle-format error (missing file, malformed zip, etc.).
 *   3  Incomplete (status: incomplete — evidence present is insufficient
 *      to decide; not the same as a failure, PA-0009 / `PA01-DECISIONS.md`
 *      D15). PA-0010's `targetAck`/`callerResult` components produce this
 *      when the relevant evidence event is legitimately redacted (a
 *      `payload: null` with a present `payloadCommitment` — threat-model
 *      row #10).
 */

import * as fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { verifyBundle, type VerifyReport, type ComponentResult } from './verify.js';
import { MAX_ZIP_ARCHIVE_BYTES } from './zip.js';
import { GENESIS_PREV_ROW_HASH } from './crypto.js';
import { verifyAibomAttestation, MAX_AIBOM_ENVELOPE_BYTES } from './aibom.js';

interface CliArgs {
  bundlePath: string | null;
  noRekor: boolean;
  quiet: boolean;
  json: boolean;
  help: boolean;
  platformKeyPath: string | null;
  /**
   * SEC-2026-09-12 (MCPSDK-03) — optional out-of-band sha256 (hex) of the
   * SPKI DER of the key `--platform-key` points at. Supplying it forces the
   * key and its identity to arrive through TWO channels: a forger who ships
   * a bundle together with their own platform key cannot also produce the
   * fingerprint the auditor got from Praesidia's published trust-anchor
   * document. Mismatch is a hard exit-2 error, never a warning.
   */
  platformKeyFingerprint: string | null;
  targetKeysPath: string | null;
  allowLegacyUnattested: boolean;
}

/** A PEM/SPKI public key is tiny; leave ample room for comments/cert wrappers. */
const MAX_PLATFORM_KEY_BYTES = 64 * 1024;

const HELP = `praesidia-verify — offline verifier for Praesidia compliance bundles

USAGE
  praesidia-verify <bundle.zip> [options]
  praesidia-verify verify-set <bundle1.zip> <bundle2.zip> [...] [options]
  praesidia-verify aibom <aibom.attested.json> --tenant-key-fingerprint <sha256hex> [...]

  SCAN2-004 — \`verify-set\` checks that TWO OR MORE bundles for the same
  org form one continuous history: it sorts them by manifest \`from\`,
  requires the earliest bundle's chain head to be a true genesis anchor
  (not an opaque range start — closes AUDIT-03), and for every adjacent
  pair asserts BOTH the date range is exactly contiguous (no gap, no
  overlap) AND the left bundle's newest-row hash-chain link equals the
  right bundle's declared head anchor (an adjacent-but-forged boundary is
  caught, not just a date gap). Every discontinuity is a NAMED finding —
  never silence. Does not change the single-bundle command above in any
  way.

  AV-0001 — \`aibom\` verifies one attested AIBOM export
  (praesidia-aibom-attestation/v1): the document digest, the Ed25519 /
  ECDSA-P256 signature, and that the embedded public key hashes to a
  --tenant-key-fingerprint obtained independently of the file (e.g. the
  keyVersions[].fingerprint in a verified compliance bundle's platform
  attestation for the same org). Repeat the flag to pin several key
  versions. Accepts --json and --quiet. Exit 0 verified, 1 any failed
  check, 2 I/O, usage or unsupported-format error.

OPTIONS
  --no-rekor   Skip the offline Sigstore Rekor receipt verification.
  --target-keys <file>
               JSON map of organizationId:targetId:keyId to trusted Ed25519 PEM.
  --platform-key <file>
               Trust this PEM or SPKI-DER platform attestation public key.
               The result is only as strong as the provenance of that file;
               a WARNING line says so on every run that uses it.
  --platform-key-fingerprint <sha256hex>
               Require --platform-key's SPKI DER to hash to this digest.
               Obtain it from a DIFFERENT channel than the bundle (e.g.
               Praesidia's published trust-anchor document). Mismatch exits 2.
  --allow-legacy-unattested
               Explicitly accept bundles without platform attestation.
  --quiet      Print only the final OK/FAIL/INCOMPLETE summary line.
  --json       Print the full VerifyReport as stable machine-readable JSON
               instead of the human-readable report (mutually exclusive
               with --quiet; --json wins if both are passed).
  --help, -h   Show this help message.

EXIT CODES
  0   status: valid   — all signatures, chain links, and inclusion proofs
      verified.
  1   status: invalid — a real verification failure.
  2   I/O or bundle-format error.
  3   status: incomplete — evidence present is insufficient to decide.

EXIT CODES (verify-set)
  0   status: continuous      — every bundle valid, no gap/overlap/mismatch.
  1   status: bundle_invalid  — at least one bundle itself fails verification
      (checked before continuity — a broken bundle is reported as broken,
      never downgraded to a mere gap).
  2   I/O or bundle-format error (including: fewer than 2 bundles supplied,
      or bundles that do not share one organizationId).
  3   status: bundle_incomplete — no bundle invalid, no discontinuity found,
      but at least one bundle's own evidence was insufficient to decide.
  4   status: discontinuous   — every bundle individually verifies, but the
      set has a named gap, overlap, forged boundary, or non-genesis first
      bundle (AUDIT-03).

The bundle is verified entirely offline — the verifier makes NO network
calls. The Rekor receipt is verified against a PINNED Sigstore public key
(SET signature + signed checkpoint + inclusion proof); pass --no-rekor to
skip that step.
`;

type CommonFlags = Omit<CliArgs, 'bundlePath'>;

function newCommonFlags(): CommonFlags {
  return {
    noRekor: false,
    quiet: false,
    json: false,
    help: false,
    platformKeyPath: null,
    platformKeyFingerprint: null,
    targetKeysPath: null,
    allowLegacyUnattested: false,
  };
}

/**
 * SCAN2-004 — flag parsing shared by single-bundle mode and `verify-set`.
 * Every non-flag token is appended to `positionals`; this function itself
 * enforces no arity rule on them — each caller (`parseArgs`,
 * `parseVerifySetArgs`) owns its own positional-count contract, since
 * single-bundle mode wants exactly one and `verify-set` wants two or more.
 */
function parseCommonArgs(
  argv: string[],
  flags: CommonFlags,
  positionals: string[],
): void {
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--no-rekor') flags.noRekor = true;
    else if (arg === '--quiet') flags.quiet = true;
    else if (arg === '--json') flags.json = true;
    else if (arg === '--help' || arg === '-h') flags.help = true;
    else if (arg === '--allow-legacy-unattested') {
      flags.allowLegacyUnattested = true;
    } else if (arg === '--target-keys') {
      const value = argv[i + 1];
      if (!value || value.startsWith('-')) throw new Error('--target-keys requires a file path');
      flags.targetKeysPath = value;
      i += 1;
    } else if (arg === '--platform-key') {
      const value = argv[i + 1];
      if (!value || value.startsWith('-')) {
        throw new Error('--platform-key requires a file path');
      }
      flags.platformKeyPath = value;
      i += 1;
    } else if (arg === '--platform-key-fingerprint') {
      const value = argv[i + 1];
      if (!value || value.startsWith('-')) {
        throw new Error(
          '--platform-key-fingerprint requires a sha256 hex digest',
        );
      }
      if (!/^[0-9a-fA-F]{64}$/.test(value)) {
        throw new Error(
          '--platform-key-fingerprint must be 64 hex characters (sha256 of the SPKI DER)',
        );
      }
      flags.platformKeyFingerprint = value.toLowerCase();
      i += 1;
    } else if (arg.startsWith('-')) {
      // Unknown flag — surface as format error (exit 2) so silent
      // typos don't get treated as success.
      throw new Error(`unknown option: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
}

function parseArgs(argv: string[]): CliArgs {
  const flags = newCommonFlags();
  const positionals: string[] = [];
  parseCommonArgs(argv, flags, positionals);
  if (positionals.length > 1) {
    throw new Error('only one bundle path may be supplied');
  }
  return { ...flags, bundlePath: positionals[0] ?? null };
}

interface VerifySetArgs extends CommonFlags {
  bundlePaths: string[];
}

function parseVerifySetArgs(argv: string[]): VerifySetArgs {
  const flags = newCommonFlags();
  const positionals: string[] = [];
  parseCommonArgs(argv, flags, positionals);
  if (!flags.help && positionals.length < 2) {
    throw new Error(
      `verify-set requires at least two bundle paths, got ${positionals.length}`,
    );
  }
  return { ...flags, bundlePaths: positionals };
}

/**
 * Read one regular file without permitting a FIFO/device to block before the
 * file-type check, and without allocating beyond the caller's explicit cap.
 *
 * `O_NONBLOCK` is inert for regular files but makes opening a FIFO/device return
 * promptly. The descriptor is then authoritative: `stat` + reads happen on the
 * same open object, closing path-swap races.
 */
async function readRegularFileBounded(
  filePath: string,
  maxBytes: number,
  label: string,
): Promise<Buffer> {
  const handle = await fs.open(
    filePath,
    fsConstants.O_RDONLY | fsConstants.O_NONBLOCK,
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) {
      throw new Error(`${label} path is not a regular file`);
    }
    if (
      !Number.isSafeInteger(stat.size) ||
      stat.size < 0 ||
      stat.size > maxBytes
    ) {
      throw new Error(
        `${label} size ${stat.size} exceeds limit ${maxBytes}`,
      );
    }

    const buffer = Buffer.allocUnsafe(stat.size);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        offset,
      );
      if (bytesRead === 0) {
        throw new Error(`${label} changed size while it was being read`);
      }
      offset += bytesRead;
    }

    // Reading from the already-open descriptor closes the path-swap race.
    // One byte beyond the snapshotted length detects concurrent growth
    // without ever allocating in proportion to the new size.
    const extra = Buffer.allocUnsafe(1);
    const { bytesRead: extraBytes } = await handle.read(
      extra,
      0,
      1,
      buffer.length,
    );
    if (extraBytes !== 0) {
      throw new Error(`${label} changed size while it was being read`);
    }
    return buffer;
  } finally {
    await handle.close();
  }
}

async function readBundleFileBounded(bundlePath: string): Promise<Buffer> {
  return readRegularFileBounded(
    bundlePath,
    MAX_ZIP_ARCHIVE_BYTES,
    'bundle',
  );
}

/** `status` → the one-word summary token used by `--quiet` and `RESULT:`. */
function statusWord(status: VerifyReport['status'] | ComponentResult['status']): string {
  switch (status) {
    case 'valid':
      return 'OK';
    case 'invalid':
      return 'FAIL';
    case 'incomplete':
      return 'INCOMPLETE';
    case 'unsupported':
      return 'UNSUPPORTED';
  }
}

function printReport(
  report: VerifyReport,
  quiet: boolean,
  noRekor: boolean,
  platformKeySupplied: boolean,
): void {
  if (quiet) {
    process.stdout.write(`${statusWord(report.status)}\n`);
    return;
  }
  const lines: string[] = [];
  lines.push('Praesidia compliance bundle verification');
  lines.push('────────────────────────────────────────');
  lines.push(`org:             ${report.bundle.orgId}`);
  lines.push(`from:            ${report.bundle.from}`);
  lines.push(`to:              ${report.bundle.to}`);
  lines.push(
    `rows:            ${report.bundle.rowsSeen}/${report.bundle.declaredRowCount} (seen/declared)`,
  );
  lines.push(
    `roots:           ${report.bundle.rootsSeen}/${report.bundle.declaredRootCount} (seen/declared)`,
  );
  lines.push(`proofs:          ${report.bundle.proofsSeen}`);
  // FIX01 (audit-verifier2) — only mentioned when sealed-purge evidence is
  // actually present; the entry is wholly optional so a bundle without it
  // prints identically to before this change.
  if (report.bundle.sealedPurgesSeen > 0) {
    lines.push(
      `sealed purges:   ${report.bundle.sealedPurgesVerified}/${report.bundle.sealedPurgesSeen} (verified/seen)`,
    );
  }
  lines.push('');
  lines.push(fmtComponent('manifest          ', report.manifest));
  lines.push(fmtComponent('row signatures    ', report.rowSignatures));
  lines.push(fmtComponent('chain integrity   ', report.chain));
  lines.push(fmtComponent('root signatures   ', report.rootSignatures));
  lines.push(fmtComponent('inclusion proofs  ', report.inclusionProofs));
  lines.push(fmtComponent('rekor receipts    ', report.rekor));
  lines.push(fmtComponent('platform attest.  ', report.platformAttestation));
  lines.push(fmtComponent('completeness      ', report.completeness));
  lines.push(fmtComponent('key binding       ', report.keyBinding));
  lines.push(fmtComponent('root coverage     ', report.rootCoverage));
  for (const line of report.rootCoverage.sealExemptions ?? []) {
    lines.push(`             ${line}`);
  }
  lines.push(fmtComponent('integrity chkpts  ', report.integrityCheckpoints));
  for (const line of report.integrityCheckpoints.sealExemptions ?? []) {
    lines.push(`             ${line}`);
  }
  // PA-0010 — action-event evidence components (manifest v5). Print
  // unconditionally (not gated on manifest version) so `unsupported` is
  // visible rather than silently omitted — an auditor should be able to
  // tell "this bundle predates action evidence" from "this build doesn't
  // check it" at a glance.
  lines.push(fmtComponent('action chain      ', report.actionEventChain));
  lines.push(fmtComponent('permit binding    ', report.permitBinding));
  lines.push(fmtComponent('request binding   ', report.requestBinding));
  lines.push(fmtComponent('dispatch integrity', report.dispatchIntegrity));
  lines.push(fmtComponent('target ack        ', report.targetAck));
  lines.push(fmtComponent('caller result     ', report.callerResult));
  lines.push(fmtComponent('closure legality  ', report.closureLegality));
  lines.push(fmtComponent('evidence grade    ', report.evidenceGrade));
  lines.push(fmtComponent('action completeness', report.actionCompleteness));
  lines.push('');
  lines.push(`RESULT: ${statusWord(report.status)}`);
  // PROD16 F8 — a bare "RESULT: OK" must never be read as "the external
  // Rekor witness was verified" when the caller explicitly skipped that
  // check. Repeat the caveat as its own line so it survives a skim.
  if (noRekor) {
    lines.push(
      'NOTE: --no-rekor was passed — the external Rekor witness was NOT checked. ' +
        'Non-Rekor anchors were still evaluated when present.',
    );
  }
  // MIL-0002 — `--allow-legacy-unattested` is an explicit, loudly-logged
  // opt-in (mirroring the Rekor-skip NOTE above): a bundle with no
  // platform-attestation entry at all is NOT platform-attested, and a
  // "RESULT: OK" must never read as "Praesidia's platform vouched for
  // this bundle" when that check was explicitly bypassed by the caller.
  // SEC-2026-09-12 (MCPSDK-03) — with `--platform-key` the caller IS the
  // trust anchor. Nothing here can tell an operator-obtained key from one
  // that arrived in the same email/zip as the bundle, and the attestation's
  // own `platformSigningKeyFingerprint` check degenerates to hashing the key
  // it was handed. `--no-rekor` and `--allow-legacy-unattested` both announce
  // themselves; this must too, or `[VALID] platform attest.` reads as an
  // assurance Praesidia never gave.
  if (platformKeySupplied) {
    lines.push(
      'WARNING: platform key supplied by caller — result is only as strong as ' +
        'the provenance of that key file. Obtain it from Praesidia\'s published ' +
        'trust-anchor document over a channel independent of this bundle, and ' +
        'pin it with --platform-key-fingerprint <sha256hex>.',
    );
  }
  // SEC-2026-09-12 (MCPSDK-01) — a legacy attestation (no
  // `manifestDigest`/`manifestGeneratedAt`) still verifies, but it vouches
  // for the org's KEY SET, not for this specific export, so a genuine older
  // attestation can accompany a bundle it was never minted for. Say so.
  if (
    report.platformAttestation.reason?.startsWith('attestation_unbound_legacy')
  ) {
    lines.push(
      'NOTE: this bundle\'s platform attestation is not bound to this manifest ' +
        '(no manifestDigest/manifestGeneratedAt) — it attests the org key set, ' +
        'not this specific export; upgrade the exporter.',
    );
  }
  if (report.platformAttestation.reason === 'missing_legacy_explicitly_allowed') {
    lines.push(
      'WARNING: --allow-legacy-unattested was passed and this bundle carries NO ' +
        'platform-attestation entry — platform key-binding was NOT checked. This ' +
        'result only confirms the tenant-signed chain/Merkle evidence, not that ' +
        'Praesidia vouches for the signing keys used.',
    );
  }
  process.stdout.write(lines.join('\n') + '\n');
}

function fmtComponent(label: string, c: ComponentResult): string {
  // PA-0009 — render the real `status`, not a derived checkmark. `ok` is
  // still the source for nothing here; `status` is authoritative.
  const tag = c.status.toUpperCase().padEnd(11, ' ').slice(0, 11);
  const counts =
    c.failed > 0 ? `${c.failed}/${c.checked} failed` : `${c.checked} checked`;
  let extra = '';
  if (c.status === 'invalid') {
    if (c.firstFailure) extra += `  first=${c.firstFailure}`;
    if (c.reason) extra += `  (${c.reason})`;
  } else if (c.reason) {
    extra = `  (${c.reason})`;
  }
  return `[${tag}] ${label}  ${counts}${extra}`;
}

/** Shared by single-bundle mode and `verify-set` — loads/validates `--platform-key`. */
async function resolvePlatformPublicKeyDerB64(
  platformKeyPath: string,
  expectedFingerprint: string | null,
): Promise<string> {
  const keyBytes = await readRegularFileBounded(
    path.resolve(platformKeyPath),
    MAX_PLATFORM_KEY_BYTES,
    'platform key',
  );
  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey(keyBytes.toString('utf8'));
  } catch {
    key = crypto.createPublicKey({ key: keyBytes, format: 'der', type: 'spki' });
  }
  if (key.asymmetricKeyType !== 'ec') {
    throw new Error('platform key must be an EC P-256 public key');
  }
  const details = key.asymmetricKeyDetails;
  if (details?.namedCurve !== 'prime256v1') {
    throw new Error('platform key must use the P-256 curve');
  }
  const der = Buffer.from(key.export({ type: 'spki', format: 'der' }));
  // SEC-2026-09-12 (MCPSDK-03) — second-channel check. Without it the
  // "fingerprint check" inside verifyPlatformAttestation is a tautology for
  // a caller-supplied key (it hashes the very key it was handed).
  if (expectedFingerprint !== null) {
    const actual = crypto.createHash('sha256').update(der).digest('hex');
    if (actual !== expectedFingerprint) {
      throw new Error(
        `platform key fingerprint mismatch: file hashes to ${actual}, ` +
          `--platform-key-fingerprint expects ${expectedFingerprint}`,
      );
    }
  }
  return der.toString('base64');
}

/** Shared by single-bundle mode and `verify-set` — loads/validates `--target-keys`. */
async function resolveTargetPublicKeys(
  targetKeysPath: string,
): Promise<Record<string, string>> {
  const raw: unknown = JSON.parse(
    (
      await readRegularFileBounded(path.resolve(targetKeysPath), 1024 * 1024, 'target keys')
    ).toString('utf8'),
  );
  if (
    !raw ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    Object.values(raw).some(
      (v) => typeof v !== 'string' || crypto.createPublicKey(v).asymmetricKeyType !== 'ed25519',
    )
  ) {
    throw new Error('Expected a map of target identity to Ed25519 PEM');
  }
  return raw as Record<string, string>;
}

// ════════════════════════════════════════════════════════════════════════
// SCAN2-004 — `verify-set`: cross-bundle continuity.
//
// `be`'s bundle-exporter caps a single export at 90 days
// (`MAX_RANGE_DAYS`), so any org history longer than that is necessarily
// several bundles. Before this, `praesidia-verify` only ever looked at one
// bundle at a time — a set with a bundle silently missing from the middle
// verified as two independent "OK"s, with nothing naming the hole
// (AUDIT-01). This section adds a mode; it never changes what a single
// `praesidia-verify <bundle.zip>` invocation does or returns.
// ════════════════════════════════════════════════════════════════════════

interface ContinuityFinding {
  kind: 'date_gap' | 'date_overlap' | 'boundary_chain_mismatch' | 'chain_head_not_genesis';
  /** Index into the SORTED bundle list this finding concerns (or the pair either side of it). */
  leftIndex?: number;
  rightIndex?: number;
  reason: string;
}

interface VerifySetBundleSummary {
  path: string;
  status: VerifyReport['status'];
  orgId: string;
  from: string;
  to: string;
  rowsSeen: number;
}

interface VerifySetReport {
  ok: boolean;
  /**
   * `bundle_invalid` beats `discontinuous` beats `bundle_incomplete` beats
   * `continuous` — a bundle that is itself tampered is a strictly worse
   * signal than a mere gap between otherwise-good bundles, and is never
   * downgraded to one. Drives the exit code (`verifySetExitCode`), which
   * is what lets a script tell "set is continuous" / "set has a gap" /
   * "a bundle is invalid" apart, per the item's Definition of Done.
   */
  status: 'continuous' | 'discontinuous' | 'bundle_invalid' | 'bundle_incomplete';
  orgId: string;
  bundles: VerifySetBundleSummary[];
  findings: ContinuityFinding[];
}

/**
 * Sorts the given bundles' reports by manifest `from` and cross-checks
 * every adjacent pair. Pure function over already-computed `VerifyReport`s
 * so it is trivially testable and never re-parses a bundle.
 */
function buildVerifySetReport(
  entries: ReadonlyArray<{ path: string; report: VerifyReport }>,
): VerifySetReport {
  const sorted = [...entries].sort(
    (a, b) => Date.parse(a.report.bundle.from) - Date.parse(b.report.bundle.from),
  );
  const orgId = sorted[0]!.report.bundle.orgId;
  const findings: ContinuityFinding[] = [];

  const bundleInvalid = sorted.some((e) => e.report.status === 'invalid');
  const bundleIncomplete = sorted.some((e) => e.report.status === 'incomplete');

  // AUDIT-03 — the earliest bundle in a set an auditor is treating as the
  // complete history must be genesis-rooted. An opaque anchor there means
  // either an earlier bundle is missing from this set, or the chain has
  // been tampered with; single-bundle verification cannot tell those
  // apart from a legitimate ranged export (BUGHUNT-SDK-02) and must keep
  // accepting it — but `verify-set`, which claims to see the whole set,
  // can and must. Skipped only when the earliest bundle has zero rows
  // (nothing to anchor) or is itself invalid (already counted above).
  const first = sorted[0]!.report;
  if (first.status !== 'invalid' && first.bundle.rowsSeen > 0) {
    if (first.bundle.chainHeadAnchor !== GENESIS_PREV_ROW_HASH) {
      findings.push({
        kind: 'chain_head_not_genesis',
        rightIndex: 0,
        reason:
          `earliest bundle in this set (${sorted[0]!.path}) is not genesis-rooted — ` +
          'its chain head is an opaque anchor, not GENESIS_PREV_ROW_HASH. Either an ' +
          'earlier bundle is missing from this set, or the chain has been tampered with.',
      });
    }
  }

  for (let i = 0; i + 1 < sorted.length; i++) {
    const left = sorted[i]!;
    const right = sorted[i + 1]!;
    // Each bundle's own validity is already reflected in `bundleInvalid`
    // above; a broken bundle has no trustworthy `to`/chain endpoint to
    // stitch against, so skip pairing it into a continuity finding here
    // rather than reporting a confusing secondary symptom.
    if (left.report.status === 'invalid' || right.report.status === 'invalid') continue;

    const leftToMs = Date.parse(left.report.bundle.to);
    const rightFromMs = Date.parse(right.report.bundle.from);
    if (rightFromMs < leftToMs) {
      findings.push({
        kind: 'date_overlap',
        leftIndex: i,
        rightIndex: i + 1,
        reason:
          `${left.path} [${left.report.bundle.from}, ${left.report.bundle.to}) overlaps ` +
          `${right.path} [${right.report.bundle.from}, ${right.report.bundle.to})`,
      });
      continue; // an overlapping pair has no well-defined boundary to chain-link check
    }
    if (rightFromMs > leftToMs) {
      findings.push({
        kind: 'date_gap',
        leftIndex: i,
        rightIndex: i + 1,
        reason:
          `missing window [${left.report.bundle.to}, ${right.report.bundle.from}) — ` +
          `${left.path} ends at ${left.report.bundle.to}, ${right.path} does not start ` +
          `until ${right.report.bundle.from}`,
      });
      continue;
    }
    // Dates are exactly adjacent — AUDIT-01 also requires binding the
    // CRYPTOGRAPHIC boundary, not just the date match, so a forged
    // replacement bundle with a convenient `from` cannot pass as
    // continuous.
    if (left.report.bundle.rowsSeen > 0 && right.report.bundle.rowsSeen > 0) {
      if (left.report.bundle.chainTailLinkHash !== right.report.bundle.chainHeadAnchor) {
        findings.push({
          kind: 'boundary_chain_mismatch',
          leftIndex: i,
          rightIndex: i + 1,
          reason:
            `${left.path}'s newest-row hash-chain link does not equal ${right.path}'s ` +
            'declared chain-head anchor — the boundary is date-adjacent but not ' +
            'cryptographically continuous (adjacent-but-forged boundary)',
        });
      }
    }
    // Both/either side genuinely empty (a quiet window, zero rows): there
    // is no chain link to assert; the date-adjacency check above is the
    // full assertion available and it already passed for this pair.
  }

  const status: VerifySetReport['status'] = bundleInvalid
    ? 'bundle_invalid'
    : findings.length > 0
      ? 'discontinuous'
      : bundleIncomplete
        ? 'bundle_incomplete'
        : 'continuous';

  return {
    ok: status === 'continuous',
    status,
    orgId,
    bundles: sorted.map((e) => ({
      path: e.path,
      status: e.report.status,
      orgId: e.report.bundle.orgId,
      from: e.report.bundle.from,
      to: e.report.bundle.to,
      rowsSeen: e.report.bundle.rowsSeen,
    })),
    findings,
  };
}

function verifySetStatusWord(status: VerifySetReport['status']): string {
  switch (status) {
    case 'continuous':
      return 'OK';
    case 'discontinuous':
      return 'GAP';
    case 'bundle_invalid':
      return 'FAIL';
    case 'bundle_incomplete':
      return 'INCOMPLETE';
  }
}

/** Exit code contract for `verify-set` — see the HELP text's "EXIT CODES (verify-set)" block. */
function verifySetExitCode(status: VerifySetReport['status']): number {
  switch (status) {
    case 'continuous':
      return 0;
    case 'bundle_invalid':
      return 1;
    case 'bundle_incomplete':
      return 3;
    case 'discontinuous':
      return 4;
  }
}

function printVerifySetReport(
  report: VerifySetReport,
  quiet: boolean,
  noRekor: boolean,
  platformKeySupplied: boolean,
): void {
  if (quiet) {
    process.stdout.write(`${verifySetStatusWord(report.status)}\n`);
    return;
  }
  const lines: string[] = [];
  lines.push('Praesidia compliance bundle SET verification (continuity)');
  lines.push('───────────────────────────────────────────────────────');
  lines.push(`org:      ${report.orgId}`);
  lines.push(`bundles:  ${report.bundles.length}`);
  lines.push('');
  for (const b of report.bundles) {
    lines.push(
      `  [${b.status.toUpperCase().padEnd(11, ' ')}] ${b.path}  [${b.from}, ${b.to})  rows=${b.rowsSeen}`,
    );
  }
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('continuity: no gap, overlap, or boundary mismatch found');
  } else {
    lines.push(`continuity: ${report.findings.length} finding(s)`);
    for (const f of report.findings) {
      lines.push(`  - [${f.kind}] ${f.reason}`);
    }
  }
  lines.push('');
  lines.push(`RESULT: ${verifySetStatusWord(report.status)}`);
  if (noRekor) {
    lines.push('NOTE: --no-rekor was passed — the external Rekor witness was NOT checked for any bundle in this set.');
  }
  // SEC-2026-09-12 (MCPSDK-03) — same caveat as single-bundle mode.
  if (platformKeySupplied) {
    lines.push(
      'WARNING: platform key supplied by caller — result is only as strong as ' +
        'the provenance of that key file; pin it with --platform-key-fingerprint <sha256hex>.',
    );
  }
  process.stdout.write(lines.join('\n') + '\n');
}

async function mainVerifySet(argv: string[]): Promise<number> {
  let args: VerifySetArgs;
  try {
    args = parseVerifySetArgs(argv);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n\n${HELP}`);
    return 2;
  }
  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }

  let platformPublicKeyDerB64: string | undefined;
  if (!args.platformKeyPath && args.platformKeyFingerprint) {
    process.stderr.write(
      'error: --platform-key-fingerprint requires --platform-key\n',
    );
    return 2;
  }
  if (args.platformKeyPath) {
    try {
      platformPublicKeyDerB64 = await resolvePlatformPublicKeyDerB64(
        args.platformKeyPath,
        args.platformKeyFingerprint,
      );
    } catch (err) {
      process.stderr.write(`error: cannot load platform key: ${(err as Error).message}\n`);
      return 2;
    }
  }
  let targetPublicKeys: Record<string, string> | undefined;
  if (args.targetKeysPath) {
    try {
      targetPublicKeys = await resolveTargetPublicKeys(args.targetKeysPath);
    } catch (err) {
      process.stderr.write(`error: cannot load target keys: ${(err as Error).message}\n`);
      return 2;
    }
  }

  const entries: Array<{ path: string; report: VerifyReport }> = [];
  for (const bundlePath of args.bundlePaths) {
    let buffer: Buffer;
    try {
      buffer = await readBundleFileBounded(path.resolve(bundlePath));
    } catch (err) {
      process.stderr.write(
        `error: cannot read bundle ${bundlePath}: ${(err as Error).message}\n`,
      );
      return 2;
    }
    try {
      const report = await verifyBundle(buffer, {
        noRekor: args.noRekor,
        ...(targetPublicKeys ? { targetPublicKeys } : {}),
        allowLegacyUnattested: args.allowLegacyUnattested,
        ...(platformPublicKeyDerB64 ? { platformPublicKeyDerB64 } : {}),
      });
      entries.push({ path: bundlePath, report });
    } catch (err) {
      process.stderr.write(
        `error: bundle format error in ${bundlePath}: ${(err as Error).message}\n`,
      );
      return 2;
    }
  }

  // A gap/overlap/boundary comparison across two different orgs is
  // meaningless and would silently produce nonsense findings — reject it
  // as a usage error before computing anything, same class of failure as
  // "fewer than two bundles supplied".
  const orgIds = new Set(entries.map((e) => e.report.bundle.orgId));
  if (orgIds.size > 1) {
    process.stderr.write(
      `error: bundles do not share one organizationId: ${[...orgIds].join(', ')}\n`,
    );
    return 2;
  }

  const setReport = buildVerifySetReport(entries);

  if (args.json) {
    process.stdout.write(`${JSON.stringify(setReport, null, 2)}\n`);
  } else {
    printVerifySetReport(
      setReport,
      args.quiet,
      args.noRekor,
      args.platformKeyPath !== null,
    );
  }
  return verifySetExitCode(setReport.status);
}

async function main(): Promise<number> {
  let args: CliArgs;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n\n${HELP}`);
    return 2;
  }
  if (args.help || args.bundlePath === null) {
    process.stdout.write(HELP);
    return args.help ? 0 : 2;
  }
  const resolvedPath = path.resolve(args.bundlePath);
  let buffer: Buffer;
  try {
    buffer = await readBundleFileBounded(resolvedPath);
  } catch (err) {
    process.stderr.write(
      `error: cannot read bundle: ${(err as Error).message}\n`,
    );
    return 2;
  }
  let report: VerifyReport;
  let platformPublicKeyDerB64: string | undefined;
  if (!args.platformKeyPath && args.platformKeyFingerprint) {
    process.stderr.write(
      'error: --platform-key-fingerprint requires --platform-key\n',
    );
    return 2;
  }
  if (args.platformKeyPath) {
    try {
      platformPublicKeyDerB64 = await resolvePlatformPublicKeyDerB64(
        args.platformKeyPath,
        args.platformKeyFingerprint,
      );
    } catch (err) {
      process.stderr.write(`error: cannot load platform key: ${(err as Error).message}\n`);
      return 2;
    }
  }
  let targetPublicKeys: Record<string, string> | undefined;
  if (args.targetKeysPath) {
    try {
      targetPublicKeys = await resolveTargetPublicKeys(args.targetKeysPath);
    } catch (err) {
      process.stderr.write(`error: cannot load target keys: ${(err as Error).message}\n`);
      return 2;
    }
  }
  try {
    report = await verifyBundle(buffer, {
      noRekor: args.noRekor,
      ...(targetPublicKeys ? { targetPublicKeys } : {}),
      allowLegacyUnattested: args.allowLegacyUnattested,
      ...(platformPublicKeyDerB64 ? { platformPublicKeyDerB64 } : {}),
    });
  } catch (err) {
    // verifyBundle throws ONLY on I/O / format errors. Verification
    // failures come through as `report.ok === false`.
    process.stderr.write(
      `error: bundle format error: ${(err as Error).message}\n`,
    );
    return 2;
  }
  if (args.json) {
    // PA-0009 — stable machine-readable JSON mode. Prints the full
    // `VerifyReport` (which now carries `status` at both the top level and
    // per-component, see `verify.ts`) as the ONLY stdout output — no human
    // text is interleaved, so callers can pipe this straight into a JSON
    // parser. `--quiet` is ignored when `--json` is also passed.
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    printReport(report, args.quiet, args.noRekor, args.platformKeyPath !== null);
  }
  // PA-0009 (D15) — exit code is a function of `report.status`, not `ok`:
  // 0 valid, 1 invalid, 3 incomplete. `unsupported` never appears at the
  // top level (see `reduceStatus`), so no exit code is reserved for it.
  switch (report.status) {
    case 'valid':
      return 0;
    case 'invalid':
      return 1;
    case 'incomplete':
      return 3;
  }
}

/**
 * SCAN2-004 — `verify-set` is a subcommand, dispatched on a literal first
 * argument, exactly like `npm <command>` / `git <command>`. Any other
 * first argument (including none) is unaffected and reaches the ORIGINAL
 * single-bundle `main()` unchanged.
 */
function runCli(): Promise<number> {
  if (process.argv[2] === 'aibom') return mainAibom(process.argv.slice(3));
  return process.argv[2] === 'verify-set'
    ? mainVerifySet(process.argv.slice(3))
    : main();
}

/** AV-0001 — `aibom <envelope> --tenant-key-fingerprint <hex>...`; see HELP. */
async function mainAibom(argv: string[]): Promise<number> {
  const usage = (msg: string): number => {
    process.stderr.write(`error: ${msg}\n\n${HELP}`);
    return 2;
  };
  const pins: string[] = [];
  const files: string[] = [];
  let json = false;
  let quiet = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--json') json = true;
    else if (arg === '--quiet') quiet = true;
    else if (arg === '--help' || arg === '-h') {
      process.stdout.write(HELP);
      return 0;
    } else if (arg === '--tenant-key-fingerprint') {
      const value = argv[(i += 1)] ?? '';
      if (!/^[0-9a-fA-F]{64}$/.test(value)) {
        return usage('--tenant-key-fingerprint requires a sha256 hex digest (64 characters)');
      }
      pins.push(value.toLowerCase());
    } else if (arg.startsWith('-')) return usage(`unknown option: ${arg}`);
    else files.push(arg);
  }
  if (files.length !== 1) return usage('aibom requires exactly one envelope path');
  // Fail closed: the embedded key alone proves integrity, never origin.
  if (pins.length === 0) return usage('aibom requires --tenant-key-fingerprint <sha256hex>');
  let bytes: Buffer;
  try {
    bytes = await readRegularFileBounded(path.resolve(files[0]!), MAX_AIBOM_ENVELOPE_BYTES, 'envelope');
  } catch (err) {
    process.stderr.write(`error: cannot read envelope: ${(err as Error).message}\n`);
    return 2;
  }
  const report = verifyAibomAttestation(bytes, { trustedKeyFingerprints: pins });
  if (json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else if (quiet) process.stdout.write(report.valid ? 'OK\n' : 'FAIL\n');
  else {
    process.stdout.write(
      `AIBOM attestation: ${report.valid ? 'OK' : 'FAIL'} (${report.reason})\n${report.detail}\n` +
        (report.valid
          ? 'NOTE: snapshotId, version, generatedAt, signedAt, signingKeyVersion and procedure are not covered by the signature.\n'
          : ''),
    );
  }
  if (report.valid) return 0;
  return report.reason === 'unsupported_format' ? 2 : 1;
}

runCli().then(
  (code) => {
    // Let stdout/stderr drain naturally. `process.exit()` can truncate a
    // large `--json` report when output is piped and the stream is under
    // backpressure.
    process.exitCode = code;
  },
  (err) => {
    // Truly unexpected — the structured paths above already cover the
    // expected error classes. Surface as exit 2 so callers can
    // distinguish from a regular verification failure.
    process.stderr.write(
      `fatal: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exitCode = 2;
  },
);
