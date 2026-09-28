/**
 * AV-0017 — `--trust-anchor <file>`: the be-published trust-anchor document
 * (`GET /.well-known/praesidia-audit-keys.json`, BE-1800) anchors the
 * platform attestation; no anchor at all is the distinct UNANCHORED verdict.
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cli = path.join(root, 'dist/cli.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-0017-'));
const run = (pkg: string, ...args: string[]) =>
  spawnSync(process.execPath, [cli, `samples/audit-package.${pkg}.zip`, '--no-rekor', ...args], { cwd: root, encoding: 'utf8' });

const K = fs.readFileSync(path.join(root, 'samples/sample-platform-key.pem'), 'utf8');
const OTHER = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' }).toString();

/** The exact shape be's `AuditTrustAnchorController` serves. */
function anchorEntry(pem: string, extra: Record<string, unknown> = {}) {
  const key = crypto.createPublicKey(pem);
  const fp = crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
  const { kty, crv, x, y } = key.export({ format: 'jwk' });
  return {
    kid: fp, alg: 'ES256', signatureAlgorithm: 'ECDSA_P256_SHA256',
    jwk: { kty, crv, x, y, kid: fp, alg: 'ES256', use: 'sig' },
    publicKeyPem: key.export({ format: 'pem', type: 'spki' }).toString(),
    fingerprint: fp, fingerprintAlgorithm: 'sha256-spki-der',
    keyVersion: null, status: 'active', notBefore: null, notAfter: null, ...extra,
  };
}
function anchorFile(name: string, keys: unknown[]): string {
  const file = path.join(tmp, `${name}.json`);
  fs.writeFileSync(file, JSON.stringify({ purpose: 'audit-bundle-platform-attestation', keys }));
  return file;
}

describe('AV-0017 trust anchor', () => {
  it('a bundle signed by K verifies with an anchor containing K', () => {
    const r = run('valid', '--json', '--trust-anchor', anchorFile('with-k', [anchorEntry(OTHER), anchorEntry(K)]));
    const report = JSON.parse(r.stdout);
    expect(report.platformAttestation.status).toBe('valid');
    expect(report.status).toBe('valid');
    expect(r.status).toBe(0);
  });

  it('fails closed with an anchor lacking K', () => {
    const r = run('valid', '--json', '--trust-anchor', anchorFile('without-k', [anchorEntry(OTHER)]));
    const report = JSON.parse(r.stdout);
    expect(report.platformAttestation.reason).toMatch(/^trust_anchor_key_not_found: /);
    expect(report.status).toBe('invalid');
    expect(r.status).toBe(1);
  });

  it('fails closed when the attestation was issued outside the anchored key validity window', () => {
    const r = run('valid', '--json', '--trust-anchor', anchorFile('expired', [anchorEntry(K, { status: 'retired', notAfter: '2000-01-01T00:00:00.000Z' })]));
    expect(JSON.parse(r.stdout).platformAttestation.reason).toMatch(/^trust_anchor_key_not_valid_at_issuedAt: /);
    expect(r.status).toBe(1);
  });

  it('with no anchor returns the UNANCHORED exit code (5), never OK', () => {
    const json = run('valid', '--json');
    const report = JSON.parse(json.stdout);
    expect(report.status).toBe('unanchored');
    expect(report.ok).toBe(false);
    expect(report.platformAttestation).toMatchObject({ status: 'incomplete', reason: 'platform_key_not_pinned' });
    expect(json.status).toBe(5);
    const summary = run('valid', '--summary');
    expect(summary.stdout).toContain('RESULT: UNANCHORED');
    expect(summary.stdout).toContain('INCOMPLETE signature');
    expect(summary.status).toBe(5);
    expect(run('valid', '--quiet').stdout).toBe('UNANCHORED\n');
  });

  it('a real verification failure beats UNANCHORED', () => {
    const r = run('corrupted', '--json');
    expect(JSON.parse(r.stdout).status).toBe('invalid');
    expect(r.status).toBe(1);
  });

  it.each([
    ['fingerprint that does not hash the key', [anchorEntry(K, { fingerprint: 'a'.repeat(64), kid: 'a'.repeat(64) })], /fingerprint does not match/],
    ['jwk that is a different key than the PEM', [anchorEntry(K, { jwk: anchorEntry(OTHER).jwk })], /different keys/],
    ['unknown signature algorithm', [anchorEntry(K, { signatureAlgorithm: 'ED25519' })], /unsupported/],
    ['empty key list', [], /non-empty/],
  ])('a malformed anchor document (%s) is an exit-2 error', (_name, keys, message) => {
    const r = run('valid', '--trust-anchor', anchorFile(`bad-${Math.random()}`, keys));
    expect(r.stderr).toMatch(message);
    expect(r.status).toBe(2);
  });

  it('never fetches: a URL is rejected with the offline instruction, and --platform-key cannot be combined', () => {
    const url = run('valid', '--trust-anchor', 'https://api.praesidia.ai/.well-known/praesidia-audit-keys.json');
    expect(url.stderr).toMatch(/never fetches/);
    expect(url.status).toBe(2);
    const both = run('valid', '--trust-anchor', anchorFile('both', [anchorEntry(K)]), '--platform-key', 'samples/sample-platform-key.pem');
    expect(both.stderr).toMatch(/mutually exclusive/);
    expect(both.status).toBe(2);
  });
});
