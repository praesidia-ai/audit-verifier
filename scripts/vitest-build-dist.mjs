/**
 * AV-0031 — vitest globalSetup: compile src/ into dist/ before any spec runs.
 * Six specs spawn dist/cli.js and samples.spec regenerates the samples from
 * dist/*.js, so a stale dist/ silently tested old code (and failed the
 * byte-for-byte drift gate after a src fix). A tsc error fails the run.
 */
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

export default function buildDist() {
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const tsc = path.join(path.dirname(createRequire(import.meta.url).resolve('typescript/package.json')), 'bin', 'tsc');
  execFileSync(process.execPath, [tsc], { cwd: root, stdio: 'inherit' });
}
