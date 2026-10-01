/**
 * AV-2750 (audit F02, gap G2) — release gate on the PACKED CLI. Unpacks the
 * `npm pack` tarball and runs its `dist/cli.js` with NO key flag, so the only
 * trust anchor is the embedded pin a customer gets from `npm install`:
 *   - the genuine production fixture must exit 0;
 *   - a copy with one byte flipped must exit non-zero.
 * Run after `npm pack`, never from `prepack` (only the release job has the fixture).
 *
 * Env:
 *   PRAESIDIA_RELEASE_FIXTURE           required: genuine audit package or bundle
 *                                       (exported from a synthetic org, never customer data)
 *   PRAESIDIA_RELEASE_TARBALL           default: release/<npm pack name>-<version>.tgz
 *   PRAESIDIA_RELEASE_FIXTURE_NO_REKOR  '1' forwards --no-rekor (fixture carries no Rekor anchor)
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const env = process.env;
const blocked = (message) => Object.assign(new Error(message), { blocked: true });

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-release-fixture-'));
try {
  if (!env.PRAESIDIA_RELEASE_FIXTURE) {
    throw blocked('PRAESIDIA_RELEASE_FIXTURE is not set; point it at the genuine production fixture');
  }
  const fixture = path.resolve(env.PRAESIDIA_RELEASE_FIXTURE);
  const { name, version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const tarball = path.resolve(
    env.PRAESIDIA_RELEASE_TARBALL || path.join(root, 'release', `${name.replace(/^@/, '').replace('/', '-')}-${version}.tgz`),
  );
  const untar = spawnSync('tar', ['-xzf', tarball, '-C', tmp], { encoding: 'utf8' });
  if (untar.status !== 0) throw blocked(`cannot unpack ${tarball}: ${untar.stderr.trim()}`);

  const cli = path.join(tmp, 'package', 'dist', 'cli.js');
  const flags = ['--summary', ...(env.PRAESIDIA_RELEASE_FIXTURE_NO_REKOR === '1' ? ['--no-rekor'] : [])];
  const verify = (file) => spawnSync(process.execPath, [cli, file, ...flags], { cwd: tmp, encoding: 'utf8' });

  const genuine = verify(fixture);
  process.stdout.write(genuine.stdout);
  if (genuine.status !== 0) {
    throw blocked(`the packed CLI did not verify the genuine fixture with its embedded pin (exit ${genuine.status ?? genuine.signal}) ${genuine.stderr.trim()}`.trim());
  }
  const flipped = fs.readFileSync(fixture);
  flipped[flipped.length >> 1] ^= 0x01;
  const tamperedPath = path.join(tmp, `tampered${path.extname(fixture)}`);
  fs.writeFileSync(tamperedPath, flipped);
  const tampered = verify(tamperedPath);
  if (typeof tampered.status !== 'number' || tampered.status === 0) {
    throw blocked(`the packed CLI did not reject a byte-flipped fixture (exit ${tampered.status ?? tampered.signal})`);
  }
  process.stdout.write(
    `release fixture check OK: ${path.basename(tarball)} verifies the genuine fixture with its embedded pin (exit 0) and rejects a byte-flipped copy (exit ${tampered.status}).\n`,
  );
} catch (error) {
  process.stderr.write(`audit-verifier release blocked: ${error.blocked ? error.message : error.stack}\n`);
  process.exitCode = 1;
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
