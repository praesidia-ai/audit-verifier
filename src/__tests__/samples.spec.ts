/**
 * AV-0011 — the committed `samples/` packages: a drift gate (regenerating
 * reproduces the committed bytes) and pinned CLI verdicts, so a verifier
 * change that breaks a sample, or its README output, goes red.
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cli = path.join(root, 'dist/cli.js');
if (!fs.existsSync(cli)) throw new Error('dist/cli.js not found — `npm run build` must run before `npm test`.');

const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: 'utf8' });
const tryIt = (name: string, ...extra: string[]) =>
  run(`samples/audit-package.${name}.zip`, '--platform-key', 'samples/sample-platform-key.pem', '--no-rekor', '--summary', ...extra);

const TAIL = [
  'NOTE: --no-rekor was passed — the external Rekor witness was NOT checked. Non-Rekor anchors were still evaluated when present.',
  "WARNING: platform key supplied by caller — result is only as strong as the provenance of that key file. Obtain it from Praesidia's published trust-anchor document over a channel independent of this bundle, and pin it with --platform-key-fingerprint <sha256hex>.",
  '',
];
const EXPECTED: Record<string, { code: number; lines: string[] }> = {
  valid: { code: 0, lines: ['PASS signature', 'PASS hash chain', 'PASS decision receipt', 'PASS policy reference', 'PASS evidence integrity', 'NOT_PRESENT target receipt', '', 'RESULT: OK'] },
  corrupted: { code: 1, lines: ['FAIL signature', 'FAIL hash chain', 'INCOMPLETE decision receipt', 'INCOMPLETE policy reference', 'PASS evidence integrity', 'NOT_PRESENT target receipt', '', 'RESULT: FAIL'] },
  'wrong-key': { code: 1, lines: ['FAIL signature', 'PASS hash chain', 'PASS decision receipt', 'PASS policy reference', 'PASS evidence integrity', 'NOT_PRESENT target receipt', '', 'RESULT: FAIL'] },
};

describe('AV-0011 committed samples', () => {
  it('regenerating reproduces every committed sample byte for byte', async () => {
    const script = pathToFileURL(path.join(root, 'scripts/make-sample-bundles.mjs')).href;
    const { buildSamples } = (await import(script)) as { buildSamples: () => Map<string, Buffer> };
    const samples = buildSamples();
    expect(fs.readdirSync(path.join(root, 'samples')).sort()).toEqual([...samples.keys(), 'README.md'].sort());
    for (const [name, data] of samples) {
      expect(fs.readFileSync(path.join(root, 'samples', name)).equals(data), name).toBe(true);
    }
  });

  for (const [name, { code, lines }] of Object.entries(EXPECTED)) {
    it(`${name}: exit ${code}, pinned proof lines, and both READMEs show this exact output`, () => {
      const r = tryIt(name);
      expect(r.stdout).toBe([...lines, ...TAIL].join('\n'));
      expect(r.status).toBe(code);
      for (const readme of ['README.md', 'samples/README.md']) {
        expect(fs.readFileSync(path.join(root, readme), 'utf8'), readme).toContain(lines.join('\n'));
      }
    });
  }

  it('names the failing check: the flipped row, and the attestation under the wrong key', () => {
    const corrupted = JSON.parse(tryIt('corrupted', '--json').stdout);
    expect(corrupted.rowSignatures).toMatchObject({ status: 'invalid', failed: 1, firstFailure: 'row-approval' });
    expect(corrupted.package.status).toBe('valid'); // the receipt was fixed up; only the signature catches it
    const wrongKey = JSON.parse(tryIt('wrong-key', '--json').stdout);
    expect(wrongKey.platformAttestation.status).toBe('invalid');
    expect(wrongKey.platformAttestation.reason).toMatch(/^signature: /);
    expect(wrongKey.rowSignatures.status).toBe('valid');
  });

  it('never trusts the sample key implicitly: without --platform-key the valid sample does not verify', () => {
    const r = run('samples/audit-package.valid.zip', '--no-rekor', '--json');
    const report = JSON.parse(r.stdout);
    expect(r.status).not.toBe(0);
    expect(report.status).not.toBe('valid');
    expect(report.platformAttestation.status).not.toBe('valid');
  });

  it('without --no-rekor the valid sample fails closed on the missing Rekor anchor', () => {
    const r = run('samples/audit-package.valid.zip', '--platform-key', 'samples/sample-platform-key.pem', '--json');
    expect(r.status).toBe(1);
    expect(JSON.parse(r.stdout).rekor.reason).toMatch(/^no_external_witness/);
  });
});
