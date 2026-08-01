#!/usr/bin/env node
/**
 * `praesidia-verify` CLI entry point.
 *
 * Usage:
 *   praesidia-verify <bundle.zip> [--no-rekor] [--quiet] [--help]
 *
 * Exit codes:
 *   0  All checks passed.
 *   1  Verification failure (signature / chain / proof mismatch).
 *   2  I/O or bundle-format error (missing file, malformed zip, etc.).
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { verifyBundle, type VerifyReport } from './verify.js';

interface CliArgs {
  bundlePath: string | null;
  noRekor: boolean;
  quiet: boolean;
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
  --quiet      Print only the final OK/FAIL summary line.
  --help, -h   Show this help message.

EXIT CODES
  0   All signatures, chain links, and inclusion proofs verified.
  1   Verification failure.
  2   I/O or bundle-format error.

The bundle is verified entirely offline — the verifier makes NO network
calls. The Rekor receipt is verified against a PINNED Sigstore public key
(SET signature + inclusion proof); pass --no-rekor to skip that step.
`;

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = {
    bundlePath: null,
    noRekor: false,
    quiet: false,
    help: false,
    platformKeyPath: null,
    allowLegacyUnattested: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--no-rekor') out.noRekor = true;
    else if (arg === '--quiet') out.quiet = true;
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

function printReport(report: VerifyReport, quiet: boolean): void {
  if (quiet) {
    process.stdout.write(report.ok ? 'OK\n' : 'FAIL\n');
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
  lines.push('');
  lines.push(report.ok ? 'RESULT: OK' : 'RESULT: FAIL');
  // PROD16 F8 — a bare "RESULT: OK" must never be read as "the external
  // Rekor witness was verified" when the caller explicitly skipped that
  // check. Repeat the caveat as its own line so it survives a skim.
  if (report.rekor.reason?.startsWith('rekor_check_skipped_by_caller')) {
    lines.push(
      'NOTE: --no-rekor was passed — the external Rekor witness was NOT checked. ' +
        'This result does not confirm or rule out anchoring.',
    );
  }
  process.stdout.write(lines.join('\n') + '\n');
}

function fmtComponent(
  label: string,
  c: {
    ok: boolean;
    checked: number;
    failed: number;
    firstFailure?: string;
    reason?: string;
  },
): string {
  const tag = c.ok ? 'OK  ' : 'FAIL';
  const counts =
    c.failed > 0 ? `${c.failed}/${c.checked} failed` : `${c.checked} checked`;
  let extra = '';
  if (!c.ok) {
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
  printReport(report, args.quiet);
  return report.ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    // Truly unexpected — the structured paths above already cover the
    // expected error classes. Surface as exit 2 so callers can
    // distinguish from a regular verification failure.
    process.stderr.write(
      `fatal: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(2);
  },
);
