/**
 * AV-2750 / AV-2752 (audit F02, gap G2) — release gate on the PACKED CLI. Unpacks
 * the `npm pack` tarball and runs its `dist/cli.js` with NO key flag, so the only
 * trust anchor is the embedded pin a customer gets from `npm install`:
 *   - the genuine production fixture must exit 0;
 *   - the fixture's bundle with its platform attestation re-signed by a throwaway
 *     foreign P-256 key must exit 1 with a `signature: ` reason. The attestation
 *     body is unchanged (it still declares the pinned fingerprint) and the zip is
 *     well-formed, so only the signature check under the embedded pin rejects it:
 *     a build whose signature or pin check does nothing fails this gate.
 * Run after `npm pack`, never from `prepack` (only the release job needs the fixture).
 *
 * Env (all optional):
 *   PRAESIDIA_RELEASE_FIXTURE           default: release-fixture/production-audit-package.zip,
 *                                       committed by the operator (AV-2751): an audit package or
 *                                       bundle exported from a synthetic org, never customer data
 *   PRAESIDIA_RELEASE_TARBALL           default: release/<filename `npm pack --dry-run --json` reports>
 *   PRAESIDIA_RELEASE_FIXTURE_NO_REKOR  '1' forwards --no-rekor (fixture carries no Rekor anchor)
 */
import { spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, isLowSP256 } from '../dist/crypto.js';
import { readZip, writeZip } from '../dist/zip.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const env = process.env;
const DEFAULT_FIXTURE = 'release-fixture/production-audit-package.zip';
const PACKAGE_BUNDLE_ENTRY = 'evidence/audit-bundle.zip';
const ATTESTATION_ENTRY = 'platform-attestation.json';

function fail(message) {
  process.stderr.write(`audit-verifier release blocked: ${message}\n`);
  process.exitCode = 1;
}

/** The fixture's bundle, its platform attestation re-signed by an in-memory foreign key; null if it has none. */
function foreignSignedBundle(fixtureBytes) {
  const outer = readZip(fixtureBytes);
  const inner = outer.find((e) => e.name === PACKAGE_BUNDLE_ENTRY);
  const entries = inner ? readZip(inner.data) : outer;
  const i = entries.findIndex((e) => e.name === ATTESTATION_ENTRY);
  if (i < 0) return null;
  const { attestation } = JSON.parse(entries[i].data.toString('utf8'));
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  let signature;
  do signature = crypto.sign('sha256', canonicalJson(attestation), privateKey);
  while (!isLowSP256(signature));
  entries[i] = { name: ATTESTATION_ENTRY, data: Buffer.from(JSON.stringify({ attestation, signature: signature.toString('base64') })) };
  return writeZip(entries);
}

function gate(tmp) {
  const fixture = path.resolve(root, env.PRAESIDIA_RELEASE_FIXTURE || DEFAULT_FIXTURE);
  if (!fs.existsSync(fixture)) {
    return fail(`no release fixture at ${fixture}; commit the genuine production fixture there (AV-2751)`);
  }
  let tarball = env.PRAESIDIA_RELEASE_TARBALL;
  if (!tarball) {
    const dry = spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' });
    if (dry.status !== 0) return fail(`npm pack --dry-run failed: ${dry.stderr.trim()}`);
    tarball = path.join(root, 'release', JSON.parse(dry.stdout)[0].filename);
  }
  const untar = spawnSync('tar', ['-xzf', tarball, '-C', tmp], { encoding: 'utf8' });
  if (untar.status !== 0) return fail(`cannot unpack ${tarball}: ${untar.stderr.trim()}`);

  const cli = path.join(tmp, 'package', 'dist', 'cli.js');
  const noRekor = env.PRAESIDIA_RELEASE_FIXTURE_NO_REKOR === '1' ? ['--no-rekor'] : [];
  const verify = (file, format) => spawnSync(process.execPath, [cli, file, format, ...noRekor], { cwd: tmp, encoding: 'utf8' });

  const genuine = verify(fixture, '--summary');
  process.stdout.write(genuine.stdout);
  if (genuine.status !== 0) {
    return fail(`the packed CLI did not verify the genuine fixture with its embedded pin (exit ${genuine.status ?? genuine.signal}) ${genuine.stderr.trim()}`.trim());
  }
  const forged = foreignSignedBundle(fs.readFileSync(fixture));
  if (!forged) return fail(`${fixture} has no ${ATTESTATION_ENTRY}`);
  const forgedPath = path.join(tmp, 'foreign-signed-bundle.zip');
  fs.writeFileSync(forgedPath, forged);
  const tampered = verify(forgedPath, '--json');
  let reason = null;
  try {
    reason = JSON.parse(tampered.stdout).platformAttestation?.reason ?? null;
  } catch {
    // not a report: the exit-code check below reports it
  }
  if (tampered.status !== 1 || !/^signature: /.test(reason ?? '')) {
    return fail(
      `the packed CLI did not reject the fixture re-signed under a foreign platform key with exit 1 and a signature reason (exit ${tampered.status ?? tampered.signal}, reason ${reason})`,
    );
  }
  process.stdout.write(
    `release fixture check OK: ${path.basename(tarball)} verifies the genuine fixture with its embedded pin (exit 0) and rejects it re-signed under a foreign platform key (exit 1, ${reason}).\n`,
  );
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-release-fixture-'));
try {
  gate(tmp);
} catch (error) {
  fail(error instanceof Error ? error.stack : String(error));
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
