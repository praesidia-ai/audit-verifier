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
import { verifyBundle, type VerifyReport } from './verify.js';

interface CliArgs {
  bundlePath: string | null;
  noRekor: boolean;
  quiet: boolean;
  help: boolean;
}

const HELP = `praesidia-verify — offline verifier for Praesidia compliance bundles

USAGE
  praesidia-verify <bundle.zip> [options]

OPTIONS
  --no-rekor   Skip the optional Sigstore Rekor receipt fetch.
  --quiet      Print only the final OK/FAIL summary line.
  --help, -h   Show this help message.

EXIT CODES
  0   All signatures, chain links, and inclusion proofs verified.
  1   Verification failure.
  2   I/O or bundle-format error.

The bundle is read entirely offline. The verifier makes NO network
calls except an optional Rekor receipt fetch (disable with --no-rekor).
`;

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = {
    bundlePath: null,
    noRekor: false,
    quiet: false,
    help: false,
  };
  for (const arg of argv) {
    if (arg === '--no-rekor') out.noRekor = true;
    else if (arg === '--quiet') out.quiet = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
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
  lines.push('');
  lines.push(fmtComponent('manifest          ', report.manifest));
  lines.push(fmtComponent('row signatures    ', report.rowSignatures));
  lines.push(fmtComponent('chain integrity   ', report.chain));
  lines.push(fmtComponent('root signatures   ', report.rootSignatures));
  lines.push(fmtComponent('inclusion proofs  ', report.inclusionProofs));
  lines.push(fmtComponent('rekor receipts    ', report.rekor));
  lines.push(fmtComponent('platform attest.  ', report.platformAttestation));
  lines.push('');
  lines.push(report.ok ? 'RESULT: OK' : 'RESULT: FAIL');
  process.stdout.write(lines.join('\n') + '\n');
}

function fmtComponent(
  label: string,
  c: { ok: boolean; checked: number; failed: number; firstFailure?: string; reason?: string },
): string {
  const tag = c.ok ? 'OK  ' : 'FAIL';
  const counts = c.failed > 0 ? `${c.failed}/${c.checked} failed` : `${c.checked} checked`;
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
  try {
    report = await verifyBundle(buffer, { noRekor: args.noRekor });
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
