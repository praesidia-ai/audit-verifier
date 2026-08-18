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
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { verifyBundle, type VerifyReport, type ComponentResult } from './verify.js';

interface CliArgs {
  bundlePath: string | null;
  noRekor: boolean;
  quiet: boolean;
  json: boolean;
  help: boolean;
  platformKeyPath: string | null;
  allowLegacyUnattested: boolean;
}

const HELP = `praesidia-verify — offline verifier for Praesidia compliance bundles

USAGE
  praesidia-verify <bundle.zip> [options]

OPTIONS
  --no-rekor   Skip the offline Sigstore Rekor receipt verification.
  --platform-key <file>
               Trust this PEM or SPKI-DER platform attestation public key.
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

The bundle is verified entirely offline — the verifier makes NO network
calls. The Rekor receipt is verified against a PINNED Sigstore public key
(SET signature + inclusion proof); pass --no-rekor to skip that step.
`;

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = {
    bundlePath: null,
    noRekor: false,
    quiet: false,
    json: false,
    help: false,
    platformKeyPath: null,
    allowLegacyUnattested: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--no-rekor') out.noRekor = true;
    else if (arg === '--quiet') out.quiet = true;
    else if (arg === '--json') out.json = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--allow-legacy-unattested') {
      out.allowLegacyUnattested = true;
    } else if (arg === '--platform-key') {
      const value = argv[i + 1];
      if (!value || value.startsWith('-')) {
        throw new Error('--platform-key requires a file path');
      }
      out.platformKeyPath = value;
      i += 1;
    }
    else if (arg.startsWith('-')) {
      // Unknown flag — surface as format error (exit 2) so silent
      // typos don't get treated as success.
      throw new Error(`unknown option: ${arg}`);
    } else if (out.bundlePath === null) {
      out.bundlePath = arg;
    } else {
      throw new Error('only one bundle path may be supplied');
    }
  }
  return out;
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
    buffer = await fs.readFile(resolvedPath);
  } catch (err) {
    process.stderr.write(
      `error: cannot read bundle: ${(err as Error).message}\n`,
    );
    return 2;
  }
  let report: VerifyReport;
  let platformPublicKeyDerB64: string | undefined;
  if (args.platformKeyPath) {
    try {
      const keyBytes = await fs.readFile(path.resolve(args.platformKeyPath));
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
      platformPublicKeyDerB64 = Buffer.from(
        key.export({ type: 'spki', format: 'der' }),
      ).toString('base64');
    } catch (err) {
      process.stderr.write(`error: cannot load platform key: ${(err as Error).message}\n`);
      return 2;
    }
  }
  try {
    report = await verifyBundle(buffer, {
      noRekor: args.noRekor,
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
    printReport(report, args.quiet, args.noRekor);
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

main().then(
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
