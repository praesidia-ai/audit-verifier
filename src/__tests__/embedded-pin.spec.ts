/**
 * AV-2750 (audit F02, gap G1) — the build-time embedded pin is the only trust
 * anchor a customer has when no key flag is passed. Every other spec supplies
 * the key explicitly; this one pins the SAMPLE key (never a production key)
 * into `platform-pubkey` and verifies with no key option at all.
 *
 * The pinned fingerprint constant must be recomputed from the pinned DER, not
 * trusted: a build whose DER bytes were swapped (fingerprint left intact) must
 * not accept a bundle forged under the swapped-in key.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const pin = vi.hoisted(() => ({ der: '', fingerprint: '' }));
vi.mock('../platform-pubkey.js', () => ({
  get PLATFORM_PUBLIC_KEY_DER_B64() { return pin.der; },
  get PLATFORM_PUBLIC_KEY_FINGERPRINT() { return pin.fingerprint; },
  isPlatformPubkeyPinned: () => pin.der.length > 0 && pin.fingerprint.length > 0,
}));

import { verifyAuditPackage, verifyBundle } from '../index.js';
import { canonicalJson, isLowSP256 } from '../crypto.js';
import { readZip, writeZip } from '../zip.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sample = (name: string) => fs.readFileSync(path.join(root, 'samples', name));
const spkiDer = (key: crypto.KeyObject) => key.export({ type: 'spki', format: 'der' });
const sha256Hex = (b: Buffer) => crypto.createHash('sha256').update(b).digest('hex');

const SAMPLE_DER = spkiDer(crypto.createPublicKey(sample('sample-platform-key.pem').toString('utf8')));
const SAMPLE_FP = sha256Hex(SAMPLE_DER);
const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ATTACKER_DER = spkiDer(attacker.publicKey);

const pinWith = (der: Buffer, fingerprint: string) => {
  pin.der = der.toString('base64');
  pin.fingerprint = fingerprint;
};
const verifySample = (name: string) => verifyAuditPackage(sample(`audit-package.${name}.zip`), { noRekor: true });

/** The valid sample's inner bundle with its platform attestation re-signed by `key`, body unchanged. */
function resignedBundle(key: crypto.KeyObject): Buffer {
  const inner = readZip(sample('audit-package.valid.zip')).find((e) => e.name === 'evidence/audit-bundle.zip')!.data;
  return writeZip(
    readZip(inner).map((e) => {
      if (e.name !== 'platform-attestation.json') return e;
      const { attestation } = JSON.parse(e.data.toString('utf8'));
      let sig: Buffer;
      do sig = crypto.sign('sha256', canonicalJson(attestation), key);
      while (!isLowSP256(sig));
      return { name: e.name, data: Buffer.from(JSON.stringify({ attestation, signature: sig.toString('base64') })) };
    }),
  );
}

describe('AV-2750 embedded platform-key pin (sample key, no key options)', () => {
  beforeEach(() => pinWith(SAMPLE_DER, SAMPLE_FP));

  it('a genuine bundle verifies under the embedded pin alone', async () => {
    const report = await verifySample('valid');
    expect(report.platformAttestation).toMatchObject({ status: 'valid' });
    expect(report.status).toBe('valid');
  });

  it('a byte-flipped bundle fails', async () => {
    const report = await verifySample('corrupted');
    expect(report.rowSignatures).toMatchObject({ status: 'invalid', firstFailure: 'row-approval' });
    expect(report.status).toBe('invalid');
  });

  it('a bundle attested by a different platform key fails', async () => {
    const report = await verifySample('wrong-key');
    expect(report.platformAttestation.reason).toMatch(/^signature: /);
    expect(report.status).toBe('invalid');
  });

  it('a pinned fingerprint that does not hash from the pinned DER fails closed, even on a genuine bundle', async () => {
    pinWith(SAMPLE_DER, sha256Hex(ATTACKER_DER));
    const report = await verifySample('valid');
    expect(report.status).toBe('invalid');
    expect(report.platformAttestation.reason).toMatch(/^platform_key_pin_mismatch: /);
  });

  it('swapped DER bytes under the genuine fingerprint do not accept a bundle forged with the swapped-in key', async () => {
    pinWith(ATTACKER_DER, SAMPLE_FP); // the attestation still declares SAMPLE_FP
    const report = await verifyBundle(resignedBundle(attacker.privateKey), { noRekor: true });
    expect(report.status).toBe('invalid');
    expect(report.platformAttestation.reason).toMatch(/^platform_key_pin_mismatch: /);
  });

  it('control: the re-signed bundle is otherwise well-formed, so only the pin check rejects it', async () => {
    pinWith(ATTACKER_DER, sha256Hex(ATTACKER_DER)); // a consistent pin of the attacker key
    const report = await verifyBundle(resignedBundle(attacker.privateKey), { noRekor: true });
    expect(report.platformAttestation.reason).toMatch(/^fingerprint_mismatch: /);
  });
});
