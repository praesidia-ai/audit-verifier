/**
 * AV-0001 — offline verification of be's `praesidia-aibom-attestation/v1`
 * envelopes. Every fixture under `test-fixtures/aibom/` is REAL be output,
 * produced by `scripts/make-aibom-fixtures.cts` through be's own
 * `AibomService.exportSnapshot(…, 'attested')`; the pins in
 * `trusted-keys.json` come from the generator's key material, never from an
 * envelope. Only attacker-side forgeries are built here.
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { AIBOM_UNAUTHENTICATED_FIELDS, verifyAibomAttestation, type AibomVerdict } from '../aibom.js';
import { canonicalJson } from '../crypto.js';

const dir = path.resolve(process.cwd(), 'test-fixtures/aibom');
const load = (name: string) => fs.readFileSync(path.join(dir, `${name}.attested.json`));
const pins = JSON.parse(fs.readFileSync(path.join(dir, 'trusted-keys.json'), 'utf8')) as {
  ed25519: string;
  ecdsaP256: string;
};
const trusted = { trustedKeyFingerprints: [pins.ed25519, pins.ecdsaP256] };
const reasonOf = (bytes: Uint8Array, opts = trusted) => verifyAibomAttestation(bytes, opts).reason;
const envOf = (bytes: Buffer) => JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;

describe('AV-0001 aibom — be-produced fixtures get be’s verdict', () => {
  it.each([
    ['verified-ed25519', 'verified'],
    ['verified-ecdsa-p256', 'verified'],
    ['unsigned', 'unsigned'],
    ['key-unavailable', 'key_unavailable'],
    ['signature-invalid', 'signature_invalid'],
    ['digest-mismatch', 'digest_mismatch'],
  ] as const)('%s → %s', (name, verdict) => {
    const report = verifyAibomAttestation(load(name), trusted);
    expect(report.reason).toBe(verdict);
    expect(report.valid).toBe(verdict === 'verified');
    // AV-0005 — no `anchorProof` in these exports: be's pre-BE-1255 verdict.
    expect(report).toMatchObject({ anchorStatus: 'unverified', anchorReason: verdict === 'unsigned' ? 'unsigned' : 'aibom_not_anchored' });
  });

  it('rejects an unknown format, domain or algorithm as unsupported_format', () => {
    const env = envOf(load('verified-ed25519'));
    for (const patch of [
      { attestationFormat: 'praesidia-aibom-attestation/v2' },
      { domain: 'praesidia:aibom-snapshot:v2' },
      { signingAlgorithm: 'RSA_PSS_SHA256' },
    ]) {
      expect(reasonOf(canonicalJson({ ...env, ...patch }))).toBe('unsupported_format');
    }
    expect(reasonOf(Buffer.from('not json'))).toBe('unsupported_format');
  });

  // AV-0003 — customers verify archives: exports be produced before
  // DOCS-0590 carry the 7-step procedure (the envelope's unsigned label) and
  // must keep verifying exactly as before.
  it.each(['verified-ed25519', 'verified-ecdsa-p256'])('archived 7-step export %s still verifies', (name) => {
    const archive = path.join(dir, 'archive-7-step');
    const bytes = fs.readFileSync(path.join(archive, `${name}.attested.json`));
    const oldPins = JSON.parse(fs.readFileSync(path.join(archive, 'trusted-keys.json'), 'utf8')) as typeof pins;
    expect((envOf(bytes).procedure as string[]).length).toBe(7);
    expect((envOf(load(name)).procedure as string[]).length).toBe(9);
    expect(reasonOf(bytes, { trustedKeyFingerprints: [oldPins.ed25519, oldPins.ecdsaP256] })).toBe('verified');
    expect(reasonOf(bytes)).toBe('untrusted_key');
  });
});

describe('AV-0001 aibom — one-byte mutation sweep over the signed content', () => {
  const bytes = load('verified-ed25519');
  const env = envOf(bytes);
  // Fields the signature (domain:digest over the document) does not cover;
  // the verifier never reports them as authenticated.
  const UNSIGNED = new Set(['snapshotId', 'version', 'generatedAt', 'signedAt', 'signingKeyVersion', 'procedure']);
  const ALLOWED: Record<string, AibomVerdict[]> = {
    document: ['digest_mismatch', 'unsupported_format'],
    digest: ['digest_mismatch', 'unsupported_format'],
    signature: ['signature_invalid', 'unsupported_format'],
    publicKey: ['untrusted_key', 'unsupported_format'],
    domain: ['unsupported_format'],
    attestationFormat: ['unsupported_format'],
    signingAlgorithm: ['unsupported_format'],
    organizationId: ['envelope_mismatch', 'unsupported_format'],
    aiSystemId: ['envelope_mismatch', 'unsupported_format'],
  };
  // Byte span of each top-level member (key + value) in the canonical file.
  const spans: Array<[string, number, number]> = [];
  let at = 1;
  for (const key of Object.keys(env).sort()) {
    const len = Buffer.byteLength(JSON.stringify(key)) + 1 + canonicalJson(env[key]).length;
    spans.push([key, at, at + len]);
    at += len + 1;
  }

  it('the fixture is canonical and the spans tile it', () => {
    expect(canonicalJson(env).equals(bytes)).toBe(true);
    expect(at).toBe(bytes.length);
    expect(spans.map(([k]) => k).filter((k) => !UNSIGNED.has(k)).sort()).toEqual(Object.keys(ALLOWED).sort());
  });

  // AV-2763 — the 2.6 kB `document` member is swept in fixed 256-byte chunks,
  // one test each, so no single test carries the whole sweep (it timed out
  // under load). Every byte of every member is still flipped with every mask.
  const CHUNK = 256;
  const sweeps: Array<[string, string, number, number]> = [];
  for (const [field, start, end] of spans) {
    if (!(field in ALLOWED)) continue;
    const step = field === 'document' ? CHUNK : end - start;
    for (let from = start; from < end; from += step) {
      const to = Math.min(from + step, end);
      sweeps.push([step < end - start ? `\`${field}\` bytes ${from - start}-${to - start - 1}` : `\`${field}\``, field, from, to]);
    }
  }

  it.each(sweeps)('every flipped byte of %s fails with a field-specific reason', (_label, field, from, to) => {
    const [, start] = spans.find(([k]) => k === field)!;
    for (let i = from; i < to; i += 1) {
      for (const mask of [0x01, 0x02, 0x20]) {
        const mutated = Buffer.from(bytes);
        mutated[i] = mutated[i]! ^ mask;
        const reason = reasonOf(mutated);
        expect(ALLOWED[field], `byte ${i} ^ ${mask}`).toContain(reason);
        let parses = true;
        try { JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(mutated)); } catch { parses = false; }
        // The headline case: a parseable edit of the document VALUE (past
        // `"document":`, whose renaming is a format error) is a digest mismatch.
        if (field === 'document' && i >= start + 11 && parses) expect(reason, `byte ${i} ^ ${mask}`).toBe('digest_mismatch');
      }
    }
  });

  it('flips of the structural bytes between members fail as unsupported_format', () => {
    for (const [, start] of spans) {
      const mutated = Buffer.from(bytes);
      mutated[start - 1] = mutated[start - 1]! ^ 0x01;
      expect(reasonOf(mutated)).toBe('unsupported_format');
    }
  });
});

describe('AV-0001 aibom — trust comes from the caller’s pin, never the bundle', () => {
  const genuine = load('verified-ed25519');
  const env = envOf(genuine);

  it('fails a genuine bundle under a different pin, or with no pin at all', () => {
    expect(reasonOf(genuine, { trustedKeyFingerprints: [pins.ecdsaP256] })).toBe('untrusted_key');
    expect(reasonOf(genuine, { trustedKeyFingerprints: [] })).toBe('untrusted_key');
    expect(reasonOf(genuine, { trustedKeyFingerprints: [pins.ed25519.toUpperCase()] })).toBe('verified');
  });

  it('fails a self-consistent forgery re-signed with the attacker’s own embedded key', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const document = { ...(env.document as object), aiSystemId: env.aiSystemId, organizationId: env.organizationId, components: [] };
    const digest = crypto.createHash('sha256').update(canonicalJson(document)).digest('hex');
    const forged = canonicalJson({
      ...env,
      document,
      digest,
      publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64'),
      signature: crypto.sign(null, Buffer.from(`${env.domain}:${digest}`), privateKey).toString('base64'),
    });
    // be's in-repo reference verifier trusts the embedded key and calls this `verified`.
    expect(reasonOf(forged)).toBe('untrusted_key');
  });

  it('checks the signature under the pinned key: another pinned key swapped in fails', () => {
    const other = crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
    const swapped = canonicalJson({ ...env, publicKey: other.toString('base64') });
    const otherPin = crypto.createHash('sha256').update(other).digest('hex');
    expect(reasonOf(swapped, { trustedKeyFingerprints: [pins.ed25519, otherPin] })).toBe('signature_invalid');
  });

  it('fails an envelope relabelled to another AI system', () => {
    expect(reasonOf(canonicalJson({ ...env, aiSystemId: '00000000-0000-4000-8000-000000000000' }))).toBe('envelope_mismatch');
  });

  it('fails re-serialized bytes: pretty-printing, and a duplicate key hiding content from last-wins parsers', () => {
    expect(reasonOf(Buffer.from(JSON.stringify(env, null, 2)))).toBe('non_canonical_encoding');
    const text = genuine.toString('utf8');
    const dup = text.replace('"name":"Claims triage agent"', '"name":"Evil agent","name":"Claims triage agent"');
    expect(dup).not.toBe(text);
    expect(reasonOf(Buffer.from(dup))).toBe('non_canonical_encoding');
  });

  it('does not authenticate the unsigned metadata (documented limitation)', () => {
    expect(reasonOf(canonicalJson({ ...env, snapshotId: 'relabelled' }))).toBe('verified');
  });
});

// AV-0004 — be BE-0738 adds the anchor status the SERVER resolved at export
// time, outside the signed document. Anyone can write these labels.
const genuineEd = load('verified-ed25519');
const anchorLabels = {
  anchorReference: 'audit:00000000-0000-4000-8000-000000000001',
  anchorStatus: 'verified_rekor',
  anchoredAt: '2026-09-23T00:00:00.000Z',
  anchorReason: 'forged',
};
const labelled = canonicalJson({ ...envOf(genuineEd), ...anchorLabels });

describe('AV-0004 aibom — be’s anchor labels alone are never an anchor verdict', () => {
  it('without anchorProof they change nothing: verified, anchor unverified (AV-0005 checks them against the proof)', () => {
    expect(AIBOM_UNAUTHENTICATED_FIELDS).not.toEqual(expect.arrayContaining(['anchorStatus']));
    const report = verifyAibomAttestation(labelled, trusted);
    expect(report).toEqual(verifyAibomAttestation(genuineEd, trusted));
    expect(report).toMatchObject({ valid: true, reason: 'verified', anchorStatus: 'unverified', anchorReason: 'aibom_not_anchored' });
    expect(report).not.toHaveProperty('anchoredAt');
  });
});

describe('AV-0001 aibom — CLI (`praesidia-verify aibom`)', () => {
  const cli = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js');
  const run = (args: string[]): { code: number; stdout: string } => {
    try {
      return { code: 0, stdout: execFileSync(process.execPath, [cli, 'aibom', ...args], { encoding: 'utf8', stdio: 'pipe' }) };
    } catch (e) {
      const err = e as { status: number; stdout: string };
      return { code: err.status, stdout: err.stdout };
    }
  };
  const file = (name: string) => path.join(dir, `${name}.attested.json`);

  it('exits 0 on a real be bundle with the right pin, 1 after a one-byte mutation or with the wrong pin', () => {
    expect(fs.existsSync(cli), 'npm run build must run before npm test').toBe(true);
    expect(run([file('verified-ecdsa-p256'), '--tenant-key-fingerprint', pins.ecdsaP256, '--quiet'])).toEqual({ code: 0, stdout: 'OK\n' });

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-0001-'));
    try {
      const bytes = load('verified-ed25519');
      const mutated = Buffer.from(bytes);
      const i = bytes.indexOf('Claims triage agent');
      mutated[i] = mutated[i]! ^ 0x01; // 'C' → 'B'
      fs.writeFileSync(path.join(tmp, 'm.json'), mutated);
      const bad = run([path.join(tmp, 'm.json'), '--tenant-key-fingerprint', pins.ed25519, '--json']);
      expect(bad.code).toBe(1);
      expect(JSON.parse(bad.stdout)).toMatchObject({ valid: false, reason: 'digest_mismatch' });
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    const wrong = run([file('verified-ed25519'), '--tenant-key-fingerprint', pins.ecdsaP256, '--json']);
    expect(wrong.code).toBe(1);
    expect(JSON.parse(wrong.stdout).reason).toBe('untrusted_key');
  });

  it('AV-0004/AV-0005: labels claiming verified_rekor without a proof verify, and the CLI reports the anchor unverified', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-0004-'));
    try {
      const p = path.join(tmp, 'a.json');
      fs.writeFileSync(p, labelled);
      const human = run([p, '--tenant-key-fingerprint', pins.ed25519]);
      expect(human.code).toBe(0);
      expect(human.stdout).toMatch(/^anchor: UNVERIFIED \(aibom_not_anchored\)/m);
      expect(human.stdout).not.toMatch(/verified_rekor/);
      expect(JSON.parse(run([p, '--tenant-key-fingerprint', pins.ed25519, '--json']).stdout)).toMatchObject({
        valid: true, anchorStatus: 'unverified', anchorReason: 'aibom_not_anchored',
      });
      // The CLI trusts only the bundled Sigstore log key: the fixture log is not it.
      const anchored = path.join(dir, 'anchored', 'anchored-rekor.attested.json');
      const fp = (JSON.parse(fs.readFileSync(path.join(dir, 'anchored', 'pins.json'), 'utf8')) as { trustedKeyFingerprints: string[] }).trustedKeyFingerprints[0]!;
      const out = run([anchored, '--tenant-key-fingerprint', fp]);
      expect(out.code).toBe(0);
      expect(out.stdout).toMatch(/^anchor: UNVERIFIED \(unknown_log_id\)/m);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('exits 2 without a pin and on an unsupported format', () => {
    expect(run([file('verified-ed25519')]).code).toBe(2);
    expect(run([path.join(dir, 'trusted-keys.json'), '--tenant-key-fingerprint', pins.ed25519]).code).toBe(2);
  });
});
