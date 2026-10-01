/**
 * AV-2702 — the HTTP receipt and RFC 3161 Ed25519 verify paths apply
 * AV-2701's small-order / non-canonical guard to the key AND to R.
 *
 * Real crypto, no mock, one check at a time:
 *   (a) forgedR   — a real key, R = identity, S = k·a mod L
 *                   ([S]B = R + [k]A holds; only the R check rejects it);
 *   (b) forgedKey — key = identity, R = [a]B, S = a
 *                   ([k]·identity vanishes; only the key check rejects it).
 * Each test first asserts the runtime's OpenSSL ACCEPTS the forgery, so
 * removing either check alone turns exactly one of them red. A permissive
 * `crypto.verify` sweep then covers every small-order / non-canonical
 * encoding on both paths.
 */
import * as nodeCrypto from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:crypto', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:crypto')>();
  return { ...real, verify: vi.fn(real.verify) };
});

import { ED25519_SMALL_ORDER_Y } from '../crypto.js';
import { verifyHttpReceipt, type HttpReceiptStatement } from '../http-receipt.js';
import { jcsCanonicalize, type JsonValue } from '../jcs-canonical.js';
import { verifyRfc3161Receipt, type Rfc3161Verdict } from '../rfc3161.js';

type VerifyFn = (...a: unknown[]) => boolean;
const verifyMock = vi.mocked(nodeCrypto.verify) as unknown as ReturnType<typeof vi.fn<VerifyFn>>;
const realVerify = (await vi.importActual<typeof import('node:crypto')>('node:crypto')).verify as unknown as VerifyFn;
afterEach(() => {
  verifyMock.mockImplementation(realVerify);
});

// ── Ed25519 forgeries (scalar arithmetic only) ──────────────────────────
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const le = (b: Uint8Array) => BigInt('0x' + (Buffer.from(b).reverse().toString('hex') || '0'));
const enc = (n: bigint, sign: 0 | 1 = 0) => {
  const b = Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse();
  b[31] = (b[31]! & 0x7f) | (sign << 7);
  return b;
};
const IDENTITY = enc(1n);
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const keyFromRaw = (raw: Uint8Array) =>
  nodeCrypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
const pemFromRaw = (raw: Uint8Array) => keyFromRaw(raw).export({ format: 'pem', type: 'spki' }).toString();
const h = (...parts: Uint8Array[]) => le(nodeCrypto.createHash('sha512').update(Buffer.concat(parts)).digest()) % L;

function realKey() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const seed = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16);
  const d = nodeCrypto.createHash('sha512').update(seed).digest();
  d[0]! &= 248;
  d[31]! &= 127;
  d[31]! |= 64;
  return { raw, privateKey, a: le(d.subarray(0, 32)) % L };
}
/** (a) real key, small-order R. */
function forgedR(msg: Buffer) {
  const { raw, a } = realKey();
  return { key: raw, sig: Buffer.concat([IDENTITY, enc((h(IDENTITY, raw, msg) * a) % L)]) };
}
/** (b) small-order key, prime-order R. */
function forgedKey() {
  const { raw, a } = realKey();
  return { key: IDENTITY, sig: Buffer.concat([raw, enc(a)]) };
}

const SMALL_ORDER = [...ED25519_SMALL_ORDER_Y].flatMap((y) => [enc(y, 0), enc(y, 1)]);
const NON_CANONICAL = [P, P + 1n, (1n << 255n) - 1n].flatMap((y) => [enc(y, 0), enc(y, 1)]);
const REJECTED = [...SMALL_ORDER, ...NON_CANONICAL].map((e) => [e.toString('hex'), e] as const);

// ── HTTP receipt ────────────────────────────────────────────────────────
const statement: HttpReceiptStatement = {
  version: 'praesidia.http-receipt.v1', actionId: 'act-1', organizationId: 'org-1', targetId: 'tgt-1',
  keyId: 'key-1', requestCommitment: 'a'.repeat(64), resultCommitment: 'b'.repeat(64), effect: 'succeeded',
  issuedAt: '2026-05-01T00:00:00.000Z', targetTransactionId: 'tx-1',
};
const { version: _v, effect: _e, issuedAt: _i, targetTransactionId: _t, ...expected } = statement;
const receiptMsg = Buffer.from(jcsCanonicalize(statement as unknown as JsonValue));
const receipt = (sig: Buffer) => ({ statement, signature: sig.toString('base64') });

describe('AV-2702 — verifyHttpReceipt rejects small-order key / R', () => {
  it('control: a real signature verifies', () => {
    const { raw, privateKey } = realKey();
    expect(verifyHttpReceipt(receipt(nodeCrypto.sign(null, receiptMsg, privateKey)), pemFromRaw(raw), expected)).toBe(true);
  });

  it('(a) real key + small-order R: OpenSSL accepts, the verifier rejects', () => {
    const { key, sig } = forgedR(receiptMsg);
    expect(realVerify(null, receiptMsg, keyFromRaw(key), sig)).toBe(true);
    expect(verifyHttpReceipt(receipt(sig), pemFromRaw(key), expected)).toBe(false);
  });

  it('(b) small-order key + prime-order R: OpenSSL accepts, the verifier rejects', () => {
    const { key, sig } = forgedKey();
    expect(realVerify(null, receiptMsg, keyFromRaw(key), sig)).toBe(true);
    expect(verifyHttpReceipt(receipt(sig), pemFromRaw(key), expected)).toBe(false);
  });

  it.each(REJECTED)('permissive verify: rejects %s as the key and as R', (_, point) => {
    const { raw, privateKey } = realKey();
    const sig = nodeCrypto.sign(null, receiptMsg, privateKey);
    verifyMock.mockImplementation(() => true);
    expect(verifyHttpReceipt(receipt(sig), pemFromRaw(raw), expected)).toBe(true);
    expect(verifyHttpReceipt(receipt(sig), pemFromRaw(point), expected)).toBe(false);
    expect(verifyHttpReceipt(receipt(Buffer.concat([point, sig.subarray(32)])), pemFromRaw(raw), expected)).toBe(false);
  });
});

// ── RFC 3161: a minimal Ed25519 TSA token, DER built by hand ────────────
const tlv = (tag: number, ...v: Buffer[]) => {
  const body = Buffer.concat(v);
  const n = body.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...len]), body]);
};
const seq = (...v: Buffer[]) => tlv(0x30, ...v);
const set = (...v: Buffer[]) => tlv(0x31, ...v);
const int = (n: number) => tlv(0x02, Buffer.from([n]));
const octet = (b: Buffer) => tlv(0x04, b);
const oid = (s: string) => {
  const [a, b, ...rest] = s.split('.').map(Number);
  const out = [a! * 40 + b!];
  for (const n of rest) {
    const g: number[] = [];
    for (let x = n; ; x = Math.floor(x / 128)) { g.unshift((x % 128) | (g.length ? 0x80 : 0)); if (x < 128) break; }
    out.push(...g);
  }
  return tlv(0x06, Buffer.from(out));
};
const ED25519 = seq(oid('1.3.101.112'));
const SHA256 = seq(oid('2.16.840.1.101.3.4.2.1'), Buffer.from([0x05, 0x00]));
const NAME = seq(set(seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from('AV-2702 TEST TSA')))));
const sha256 = (b: Buffer) => nodeCrypto.createHash('sha256').update(b).digest();
const ROOT_HASH = Buffer.alloc(32, 0x27);

/** Self-issued TSA certificate for `rawKey` (critical EKU = timeStamping); its own signature is not checked. */
function tsaCert(rawKey: Uint8Array): Buffer {
  const tbs = seq(
    tlv(0xa0, int(2)), int(7), ED25519, NAME,
    seq(tlv(0x17, Buffer.from('250101000000Z')), tlv(0x17, Buffer.from('350101000000Z'))), NAME,
    seq(ED25519, tlv(0x03, Buffer.from([0]), Buffer.from(rawKey))),
    tlv(0xa3, seq(seq(oid('2.5.29.37'), tlv(0x01, Buffer.from([0xff])), octet(seq(oid('1.3.6.1.5.5.7.3.8')))))),
  );
  return seq(tbs, ED25519, tlv(0x03, Buffer.alloc(65)));
}

/** Token over ROOT_HASH; `sign` receives the bytes CMS signs (signedAttrs as SET OF). */
function token(cert: Buffer, sign: (signed: Buffer) => Buffer): string {
  const tstInfo = seq(int(1), oid('1.2.3.4'), seq(SHA256, octet(ROOT_HASH)), int(1), tlv(0x18, Buffer.from('20260501000000Z')));
  const attrs = [
    seq(oid('1.2.840.113549.1.9.3'), set(oid('1.2.840.113549.1.9.16.1.4'))),
    seq(oid('1.2.840.113549.1.9.4'), set(octet(sha256(tstInfo)))),
    seq(oid('1.2.840.113549.1.9.16.2.47'), set(seq(seq(seq(octet(sha256(cert))))))),
  ];
  const signerInfo = seq(
    int(1), seq(NAME, int(7)), SHA256, tlv(0xa0, ...attrs), ED25519, octet(sign(set(...attrs))),
  );
  const signedData = seq(
    int(3), set(SHA256), seq(oid('1.2.840.113549.1.9.16.1.4'), tlv(0xa0, octet(tstInfo))),
    tlv(0xa0, cert), set(signerInfo),
  );
  return seq(oid('1.2.840.113549.1.7.2'), tlv(0xa0, signedData)).toString('base64');
}
const pem = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64')}\n-----END CERTIFICATE-----`;
const verify3161 = (cert: Buffer, sign: (signed: Buffer) => Buffer): Rfc3161Verdict =>
  verifyRfc3161Receipt(token(cert, sign), { rootHashB64: ROOT_HASH.toString('base64') }, [pem(cert)]);
const CMS_INVALID = { status: 'failed', reason: 'cms_signature_invalid' };

describe('AV-2702 — verifyRfc3161Receipt rejects a small-order TSA key / R', () => {
  it('control: a real Ed25519 TSA signature verifies', () => {
    const { raw, privateKey } = realKey();
    expect(verify3161(tsaCert(raw), (m) => nodeCrypto.sign(null, m, privateKey))).toMatchObject({
      status: 'verified', tsaSubject: 'CN=AV-2702 TEST TSA',
    });
  });

  it('(a) real key + small-order R: OpenSSL accepts, the verifier rejects', () => {
    const { raw, a } = realKey();
    const sign = (m: Buffer) => Buffer.concat([IDENTITY, enc((h(IDENTITY, raw, m) * a) % L)]);
    let signed: Buffer = Buffer.alloc(0);
    expect(verify3161(tsaCert(raw), (m) => { signed = m; return sign(m); })).toMatchObject(CMS_INVALID);
    expect(realVerify(null, signed, keyFromRaw(raw), sign(signed))).toBe(true);
  });

  it('(b) small-order key + prime-order R: OpenSSL accepts, the verifier rejects', () => {
    const { key, sig } = forgedKey();
    let signed: Buffer = Buffer.alloc(0);
    expect(verify3161(tsaCert(key), (m) => { signed = m; return sig; })).toMatchObject(CMS_INVALID);
    expect(realVerify(null, signed, keyFromRaw(key), sig)).toBe(true);
  });

  it.each(REJECTED)('permissive verify: rejects %s as the TSA key and as R', (_, point) => {
    const { raw, privateKey } = realKey();
    const sign = (m: Buffer) => nodeCrypto.sign(null, m, privateKey);
    verifyMock.mockImplementation(() => true);
    expect(verify3161(tsaCert(raw), sign).status).toBe('verified');
    const asKey = verify3161(tsaCert(point), sign);
    expect(asKey).toMatchObject(CMS_INVALID);
    expect(JSON.stringify(asKey)).not.toContain(point.toString('hex'));
    expect(JSON.stringify(asKey)).not.toContain(point.toString('base64'));
    const asR = verify3161(tsaCert(raw), (m) => Buffer.concat([point, sign(m).subarray(32)]));
    expect(asR).toMatchObject(CMS_INVALID);
  });
});
