/**
 * AV-2750 (audit F02, gap G2) — self-test of `scripts/assert-release-fixture.mjs`
 * against real `npm pack` tarballs: a build pinned to the SAMPLE key (never a
 * production key), the current unpinned build, and a CLI that accepts anything.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-2750-'));
const VALID = path.join(root, 'samples/audit-package.valid.zip');
const npmEnv = { ...process.env, npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false' };

function sh(cmd: string, args: string[], cwd: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', env: npmEnv });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}
/** `npm pack` without lifecycle scripts (prepack would demand the production pin). */
function pack(dir: string, dest: string): string {
  fs.mkdirSync(dest, { recursive: true });
  const [{ filename }] = JSON.parse(sh('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', dest], dir));
  return path.join(dest, filename);
}

let pinned: string;
let unpinned: string;
let acceptsAnything: string;

beforeAll(() => {
  unpinned = pack(root, path.join(tmp, 'unpinned')); // dist/ is built by vitest globalSetup

  // The release edit (two literals in platform-pubkey) applied with the SAMPLE key to a copy of
  // the built package, then packed: the same dist/ a pinned `tsc` build ships.
  const build = path.join(tmp, 'build');
  fs.cpSync(path.join(root, 'package.json'), path.join(build, 'package.json'));
  fs.cpSync(path.join(root, 'dist'), path.join(build, 'dist'), { recursive: true });
  const der = crypto.createPublicKey(fs.readFileSync(path.join(root, 'samples/sample-platform-key.pem'), 'utf8'))
    .export({ type: 'spki', format: 'der' });
  const pubkeyJs = path.join(build, 'dist/platform-pubkey.js');
  const pinnedJs = fs.readFileSync(pubkeyJs, 'utf8')
    .replace(/(PLATFORM_PUBLIC_KEY_DER_B64 = )(''|"")/, `$1'${der.toString('base64')}'`)
    .replace(/(PLATFORM_PUBLIC_KEY_FINGERPRINT = )(''|"")/, `$1'${crypto.createHash('sha256').update(der).digest('hex')}'`);
  expect(pinnedJs.match(/PLATFORM_PUBLIC_KEY_(DER_B64|FINGERPRINT) = '[A-Za-z0-9+/=]+'/g)).toHaveLength(2);
  fs.writeFileSync(pubkeyJs, pinnedJs);
  pinned = pack(build, path.join(tmp, 'pinned'));

  const fake = path.join(tmp, 'fake/package');
  fs.mkdirSync(path.join(fake, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(fake, 'package.json'), '{"type":"module"}');
  fs.writeFileSync(path.join(fake, 'dist/cli.js'), 'process.exitCode = 0;\n');
  acceptsAnything = path.join(tmp, 'accepts-anything.tgz');
  sh('tar', ['-czf', acceptsAnything, '-C', path.dirname(fake), 'package'], tmp);
}, 120_000);
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

function check(env: Record<string, string>) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('PRAESIDIA_RELEASE_')));
  return spawnSync(process.execPath, [path.join(root, 'scripts/assert-release-fixture.mjs')], {
    cwd: root, encoding: 'utf8', env: { ...clean, ...env },
  });
}

describe('AV-2750 check:release-fixture (packed CLI, embedded pin only)', () => {
  it('passes a sample-pinned build: genuine fixture exits 0, byte-flipped copy exits non-zero', () => {
    const r = check({ PRAESIDIA_RELEASE_TARBALL: pinned, PRAESIDIA_RELEASE_FIXTURE: VALID, PRAESIDIA_RELEASE_FIXTURE_NO_REKOR: '1' });
    expect(r.stderr).toBe('');
    expect(r.stdout).toContain('RESULT: OK');
    expect(r.stdout).toMatch(/release fixture check OK: .* rejects a byte-flipped copy \(exit [1-9]\d*\)\./);
    expect(r.status).toBe(0);
  });

  it('the sample-pinned packed CLI alone (no key flag) fails a signed-byte flip and a foreign attestation key', () => {
    const cli = path.join(tmp, 'unpacked/package/dist/cli.js');
    fs.mkdirSync(path.join(tmp, 'unpacked'));
    sh('tar', ['-xzf', pinned, '-C', path.join(tmp, 'unpacked')], tmp);
    const run = (name: string) =>
      spawnSync(process.execPath, [cli, path.join(root, `samples/audit-package.${name}.zip`), '--no-rekor', '--json'], { encoding: 'utf8' });
    const corrupted = run('corrupted');
    expect(JSON.parse(corrupted.stdout).rowSignatures).toMatchObject({ status: 'invalid', firstFailure: 'row-approval' });
    expect(corrupted.status).toBe(1);
    const wrongKey = run('wrong-key');
    expect(JSON.parse(wrongKey.stdout).platformAttestation.reason).toMatch(/^signature: /);
    expect(wrongKey.status).toBe(1);
  });

  it('blocks the current unpinned build: the genuine fixture is only UNANCHORED (exit 5)', () => {
    const r = check({ PRAESIDIA_RELEASE_TARBALL: unpinned, PRAESIDIA_RELEASE_FIXTURE: VALID, PRAESIDIA_RELEASE_FIXTURE_NO_REKOR: '1' });
    expect(r.stderr).toMatch(/^audit-verifier release blocked: the packed CLI did not verify the genuine fixture with its embedded pin \(exit 5\)/);
    expect(r.status).toBe(1);
  });

  it('blocks a CLI that does not reject the byte-flipped copy', () => {
    const r = check({ PRAESIDIA_RELEASE_TARBALL: acceptsAnything, PRAESIDIA_RELEASE_FIXTURE: VALID });
    expect(r.stderr).toBe('audit-verifier release blocked: the packed CLI did not reject a byte-flipped fixture (exit 0)\n');
    expect(r.status).toBe(1);
  });

  it('blocks when no fixture is configured', () => {
    const r = check({ PRAESIDIA_RELEASE_TARBALL: pinned });
    expect(r.stderr).toMatch(/^audit-verifier release blocked: PRAESIDIA_RELEASE_FIXTURE is not set/);
    expect(r.status).toBe(1);
  });

  it('blocks when the tarball is missing', () => {
    const r = check({ PRAESIDIA_RELEASE_TARBALL: path.join(tmp, 'nope.tgz'), PRAESIDIA_RELEASE_FIXTURE: VALID });
    expect(r.stderr).toMatch(/^audit-verifier release blocked: cannot unpack /);
    expect(r.status).toBe(1);
  });
});
