/**
 * AV-0019 — offline RFC 3161 time-stamp token verification. Fixtures are
 * produced by `test-fixtures/rfc3161/generate.sh` with a LOCAL openssl TSA
 * (test-only PKI, keys discarded): RSA TSA under an intermediate (ESS v1),
 * EC TSA directly under the root (ESS v2).
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyRfc3161Receipt } from '../rfc3161.js';

const dir = path.resolve(process.cwd(), 'test-fixtures/rfc3161');
const read = (f: string) => fs.readFileSync(path.join(dir, f), 'utf8').trim();
const tokenRsa = read('token-rsa.b64');
const tokenEc = read('token-ec.b64');
const rootCa = read('root-ca.pem');
const otherCa = read('other-ca.pem');
const interCa = read('intermediate-ca.pem');
const rootA = read('root-hash-a.b64');
const rootB = Buffer.alloc(32, 0xb).toString('base64');

function flip(b64: string, at: (der: Buffer) => number): string {
  const der = Buffer.from(b64, 'base64');
  const i = at(der);
  der[i] = der[i]! ^ 0x01;
  return der.toString('base64');
}

describe('AV-0019 verifyRfc3161Receipt', () => {
  it('verifies a valid token (RSA TSA via intermediate, ESS v1) against the supplied root anchor', () => {
    const v = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA }, [rootCa]);
    expect(v).toMatchObject({ status: 'verified', qualified: false, label: 'RFC 3161 timestamp' });
    if (v.status !== 'verified') throw new Error('unreachable');
    expect(v.tsaSubject).toContain('AV-0019 TEST TSA RSA');
    expect(v.genTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(v.policy).toBe('1.3.6.1.4.1.99999.3161.1');
  });

  it('verifies a valid token (EC TSA, ESS v2) and when the anchor is the intermediate', () => {
    expect(verifyRfc3161Receipt(tokenEc, { rootHashB64: rootA }, [rootCa]).status).toBe('verified');
    expect(verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA }, [interCa]).status).toBe('verified');
  });

  it('states "qualified" only when the chain ends in a pinned QTSP anchor', () => {
    const v = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA }, [], [{ name: 'Test QTSP', pem: rootCa }]);
    expect(v).toMatchObject({ status: 'verified', qualified: true, label: 'qualified timestamp (Test QTSP)' });
  });

  it('fails when the token stamps another root', () => {
    const v = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootB }, [rootCa]);
    expect(v.status).toBe('failed');
    expect(v.status === 'failed' && v.reason).toMatch(/^message_imprint_mismatch/);
  });

  it('fails under the wrong trust anchor, and with no anchor at all', () => {
    const wrong = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA }, [otherCa]);
    expect(wrong.status === 'failed' && wrong.reason).toMatch(/^tsa_chain_untrusted/);
    const none = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA });
    expect(none.status === 'failed' && none.reason).toMatch(/^no_tsa_trust_anchor/);
    const badPem = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA }, ['not a pem']);
    expect(badPem.status === 'failed' && badPem.reason).toMatch(/^invalid_tsa_trust_anchor/);
  });

  it('fails closed on malformed DER', () => {
    const der = Buffer.from(tokenRsa, 'base64');
    for (const bad of [
      der.subarray(0, der.length - 7).toString('base64'), // truncated
      Buffer.concat([der, Buffer.from([0])]).toString('base64'), // trailing byte
      Buffer.from('30800000', 'hex').toString('base64'), // indefinite length
      Buffer.from('garbage').toString('base64'),
      'not base64!',
    ]) {
      const v = verifyRfc3161Receipt(bad, { rootHashB64: rootA }, [rootCa]);
      expect(v.status === 'failed' && v.reason).toMatch(/^malformed_token/);
    }
  });

  it('fails when the signature or the signed TSTInfo is tampered with', () => {
    const sig = verifyRfc3161Receipt(flip(tokenRsa, (d) => d.length - 1), { rootHashB64: rootA }, [rootCa]);
    expect(sig.status === 'failed' && sig.reason).toBe('cms_signature_invalid');
    // Re-point the imprint to another hash inside the signed TSTInfo.
    const imprintAt = (d: Buffer) => d.indexOf(Buffer.from(rootA, 'base64'));
    const tst = verifyRfc3161Receipt(flip(tokenRsa, imprintAt), { rootHashB64: rootA }, [rootCa]);
    expect(tst.status === 'failed' && tst.reason).toMatch(/^message_digest_mismatch/);
  });

  it("binds genTime to the root's signedAt/anchoredAt window", () => {
    const ok = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA }, [rootCa]);
    if (ok.status !== 'verified') throw new Error('fixture must verify');
    const gen = Date.parse(ok.genTime);
    const iso = (ms: number) => new Date(ms).toISOString();
    const day = 24 * 3600 * 1000;
    const inWindow = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA, signedAt: iso(gen - 60_000), anchoredAt: iso(gen + 1000) }, [rootCa]);
    expect(inWindow.status).toBe('verified');
    const early = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA, signedAt: iso(gen + 2 * day) }, [rootCa]);
    expect(early.status === 'failed' && early.reason).toMatch(/^gentime_out_of_window/);
    const late = verifyRfc3161Receipt(tokenRsa, { rootHashB64: rootA, anchoredAt: iso(gen - 2 * day) }, [rootCa]);
    expect(late.status === 'failed' && late.reason).toMatch(/^gentime_out_of_window/);
  });
});
