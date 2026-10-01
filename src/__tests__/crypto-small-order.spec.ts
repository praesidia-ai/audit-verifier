/**
 * AV-2701 — small-order / non-canonical Ed25519 points (RFC 8032 §5.1.3,
 * libsodium ed25519_ref10.c blocklist).
 *
 * An all-zero Ed25519 key with an all-zero signature verifies for 481/2000
 * messages on node v24.14.0 / OpenSSL 3.5.5: an auditor on such a runtime
 * would accept a bundle "signed" by the identity point. The verifier must
 * reject a small-order or non-canonical public key or R itself, whatever the
 * OpenSSL underneath decides — so these tests replace `crypto.verify` with a
 * permissive stand-in and require the guard alone to fail closed.
 *
 * The 8-torsion is derived here with BigInt curve maths ([L]P over curve
 * points), independently of the constant table in `crypto.ts`.
 */
import * as nodeCrypto from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:crypto', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:crypto')>();
  return { ...real, verify: vi.fn(real.verify) };
});

import {
  ED25519_SMALL_ORDER_Y,
  canonicalJson,
  isRejectedEd25519Point,
  merkleBuild,
  merkleProof,
  sha256,
  signEd25519,
  verifyEd25519,
  verifySignature,
  GENESIS_PREV_ROW_HASH,
} from '../crypto.js';
import { verifyBundle } from '../verify.js';
import { gzipDeterministic, writeZip } from '../zip.js';

type VerifyFn = (...a: unknown[]) => boolean;
const verifyMock = vi.mocked(nodeCrypto.verify) as unknown as ReturnType<typeof vi.fn<VerifyFn>>;
const realVerify = (await vi.importActual<typeof import('node:crypto')>('node:crypto')).verify as unknown as VerifyFn;
afterEach(() => {
  verifyMock.mockImplementation(realVerify);
});

// ── Curve maths (twisted Edwards, -x^2 + y^2 = 1 + d x^2 y^2) ───────────
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (a: bigint) => ((a % P) + P) % P;
const pow = (b: bigint, e: bigint) => {
  let r = 1n;
  b = mod(b);
  for (; e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) r = (r * b) % P;
  return r;
};
const inv = (a: bigint) => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
type Pt = readonly [bigint, bigint];
const add = ([x1, y1]: Pt, [x2, y2]: Pt): Pt => {
  const t = (((((D * x1) % P) * x2) % P) * y1 % P) * y2 % P;
  return [mod((x1 * y2 + x2 * y1) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
};
const mul = (k: bigint, pt: Pt): Pt => {
  let r: Pt = [0n, 1n];
  for (; k > 0n; k >>= 1n, pt = add(pt, pt)) if (k & 1n) r = add(r, pt);
  return r;
};
/** Recover x from y (RFC 8032 §5.1.3 steps 2-3); null if y is not on the curve. */
const xFromY = (y: bigint): bigint | null => {
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = pow(mod(u * inv(v)), (P + 3n) / 8n);
  if (mod(v * x * x - u) !== 0n) x = mod(x * pow(2n, (P - 1n) / 4n));
  return mod(v * x * x - u) === 0n ? x : null;
};
/** 32-byte little-endian encoding of y with the sign bit set to `sign`. */
const enc = (y: bigint, sign: 0 | 1): Uint8Array => {
  const b = Buffer.from(y.toString(16).padStart(64, '0'), 'hex').reverse();
  b[31] = (b[31]! & 0x7f) | (sign << 7);
  return new Uint8Array(b);
};
const encPt = ([x, y]: Pt) => enc(y, (x & 1n) === 1n ? 1 : 0);

/** The 8-torsion: [L]Q for curve points Q until 8 distinct points are seen. */
function deriveTorsion(): Pt[] {
  const seen = new Map<string, Pt>();
  for (let n = 0; seen.size < 8 && n < 64; n++) {
    const y = mod(BigInt('0x' + nodeCrypto.randomBytes(32).toString('hex')));
    const x = xFromY(y);
    if (x === null) continue;
    const t = mul(L, [x, y]); // torsion component of the point
    let q: Pt = t;
    for (let i = 0; i < 8; i++, q = add(q, t)) seen.set(`${q[0]},${q[1]}`, q);
  }
  return [...seen.values()];
}

// ── Inputs ──────────────────────────────────────────────────────────────
const SMALL_ORDER_ENCODINGS = [...ED25519_SMALL_ORDER_Y].flatMap((y) => [enc(y, 0), enc(y, 1)]);
const NON_CANONICAL_ENCODINGS = [P, P + 1n, (1n << 255n) - 1n].flatMap((y) => [enc(y, 0), enc(y, 1)]);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function realKey() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const raw = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(12));
  const seed = new Uint8Array(privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16));
  return { raw, seed };
}

describe('AV-2701 — isRejectedEd25519Point: constant table equals the derived 8-torsion', () => {
  it('derived torsion has exactly 8 points of order dividing 8, and their y values are the table', () => {
    const torsion = deriveTorsion();
    expect(torsion).toHaveLength(8);
    for (const t of torsion) expect(mul(8n, t)).toEqual([0n, 1n]);
    const derivedY = new Set(torsion.map(([, y]) => y));
    expect([...derivedY].sort()).toEqual([...ED25519_SMALL_ORDER_Y].sort());
    // Every small-order point, under its actual sign bit, is rejected.
    for (const t of torsion) expect(isRejectedEd25519Point(encPt(t)), hex(encPt(t))).toBe(true);
  });

  it('a random prime-order point and a real key are accepted (guard is not vacuous)', () => {
    for (let i = 0; i < 4; i++) {
      const y = mod(BigInt('0x' + nodeCrypto.randomBytes(32).toString('hex')));
      const x = xFromY(y);
      if (x === null) continue;
      const q = mul(8n, [x, y]); // clear the cofactor
      expect(isRejectedEd25519Point(encPt(q))).toBe(false);
    }
    expect(isRejectedEd25519Point(realKey().raw)).toBe(false);
  });

  it('non-canonical y >= p and wrong lengths are rejected', () => {
    for (const e of NON_CANONICAL_ENCODINGS) expect(isRejectedEd25519Point(e), hex(e)).toBe(true);
    expect(isRejectedEd25519Point(new Uint8Array(31))).toBe(true);
    expect(isRejectedEd25519Point(new Uint8Array(33).fill(9))).toBe(true);
  });
});

describe('AV-2701 — verifyEd25519 under a permissive crypto.verify', () => {
  const msg = Buffer.from('praesidia AV-2701');

  it('a real key with a real signature still verifies (real and permissive verify)', () => {
    const { raw, seed } = realKey();
    const sig = signEd25519(msg, seed);
    expect(verifyEd25519(msg, sig, raw)).toBe(true);
    expect(verifyEd25519(Buffer.from('tampered'), sig, raw)).toBe(false);
    verifyMock.mockImplementation(() => true);
    expect(verifyEd25519(msg, sig, raw)).toBe(true);
    expect(verifySignature('Ed25519', msg, sig, raw)).toBe(true);
  });

  it.each([...SMALL_ORDER_ENCODINGS, ...NON_CANONICAL_ENCODINGS].map((e) => [hex(e), e] as const))(
    'rejects %s as the public key and as R',
    (_, point) => {
      const { raw, seed } = realKey();
      const realSig = Buffer.from(signEd25519(msg, seed), 'base64');
      verifyMock.mockImplementation(() => true);
      // as the public key, with an otherwise well-formed signature
      expect(verifyEd25519(msg, realSig.toString('base64'), point)).toBe(false);
      expect(verifySignature('Ed25519', msg, realSig.toString('base64'), point)).toBe(false);
      // as R, under a real key
      const forged = Buffer.concat([Buffer.from(point), realSig.subarray(32)]).toString('base64');
      expect(verifyEd25519(msg, forged, raw)).toBe(false);
      expect(verifySignature('Ed25519', msg, forged, raw)).toBe(false);
    },
  );

  it('the repro pair (all-zero key, all-zero signature) is rejected without consulting OpenSSL', () => {
    verifyMock.mockImplementation(() => true);
    verifyMock.mockClear();
    expect(verifyEd25519(msg, Buffer.alloc(64).toString('base64'), new Uint8Array(32))).toBe(false);
    expect(verifyMock).not.toHaveBeenCalled();
  });
});

// ── End-to-end ──────────────────────────────────────────────────────────
const ORG = '00000000-0000-0000-0000-000000000001';
const BASE = Date.UTC(2026, 4, 1);
const iso = (sec: number) => new Date(BASE + sec * 1000).toISOString();

/** Minimal v6 bundle (format-1 signatures): 2 chained rows, 1 root, manifest. */
function bundle(pub: Uint8Array, sign: (m: Buffer) => string): Buffer {
  const rows: Record<string, unknown>[] = [];
  const leaves: Uint8Array[] = [];
  let prevRowHash = GENESIS_PREV_ROW_HASH;
  for (let i = 0; i < 2; i++) {
    const signable = {
      organizationId: ORG, action: 'agent.created', actorId: null, actorType: 'user',
      resourceType: 'agent', resourceId: `agent-${i}`, teamId: null, agentId: null,
      summary: null, details: null, createdAt: iso(i * 60),
    };
    const canonical = canonicalJson(signable);
    const signature = sign(Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]));
    rows.push({
      id: `row-${i}`, ...signable, signature, keyVersion: 1, signedAt: iso(i * 60 + 1), prevRowHash,
      signatureAlgorithm: 'Ed25519',
    });
    const leaf = Buffer.concat([canonical, Buffer.from(signature, 'base64')]);
    leaves.push(new Uint8Array(leaf));
    prevRowHash = sha256(leaf).toString('base64');
  }
  const rootHash = Buffer.from(merkleBuild(leaves).root).toString('base64');
  const env = { rootHash, periodStart: iso(0), periodEnd: iso(3600), rowCount: 2 };
  const roots = [{
    id: 'root-1', organizationId: ORG, ...env, keyVersion: 1, signedAt: iso(3605), anchoredAt: null,
    anchorReceipt: null, signatureAlgorithm: 'Ed25519', signature: sign(canonicalJson(env)),
  }];
  const proofs = leaves.map((_, i) => {
    const p = merkleProof(leaves, i);
    return { rowId: `row-${i}`, index: p.index, proof: p.siblings.map((x) => Buffer.from(x).toString('base64')), rootHash };
  });
  const publicKey = Buffer.from(pub).toString('base64');
  const manifestSans = {
    version: 6, orgId: ORG, from: iso(0), to: iso(3600), rowCount: 2, rootCount: 1,
    keyVersions: [{ keyVersion: 1, publicKey, status: 'ACTIVE', revokedAt: null }],
    generatedAt: iso(3600), signatureAlgorithm: 'Ed25519', chainSeqCeiling: 2, chainSeqSnapshotAt: iso(3600),
    integrityCheckpointCount: 0, actionEventCount: 0, captureScopeDigest: sha256(Buffer.from('scope')).toString('hex'),
    evidenceGradeSummary: { A: 0, B: 0, C: 0, D: 0, enforcementMode: 'observe' },
    evidencePrivacy: { modes: [{ mode: 'FULL', effectiveFrom: iso(0) }], schemaVersion: 1 },
  };
  const manifest = { ...manifestSans, signature: sign(canonicalJson(manifestSans)), signatureKeyVersion: 1 };
  const nd = (xs: unknown[]) => gzipDeterministic(Buffer.from(xs.map((x) => JSON.stringify(x)).join('\n') + '\n'));
  return writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest)) },
    { name: 'rows.ndjson.gz', data: nd(rows) },
    { name: 'roots.ndjson.gz', data: nd(roots) },
    { name: 'proofs.ndjson.gz', data: nd(proofs) },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify({ 1: { publicKey, status: 'ACTIVE', revokedAt: null } })) },
    { name: 'integrity-checkpoints.ndjson.gz', data: gzipDeterministic(Buffer.alloc(0)) },
    { name: 'action-events.ndjson.gz', data: gzipDeterministic(Buffer.alloc(0)) },
    { name: 'README.md', data: Buffer.from('# t\n') },
  ]);
}

/** OpenSSL 3.5.5 behaviour, made deterministic: an all-zero key verifies anything. */
function permissiveForZeroKey() {
  verifyMock.mockImplementation((...a: unknown[]) => {
    const key = a[2] as nodeCrypto.KeyObject;
    const raw = key.asymmetricKeyType === 'ed25519' ? key.export({ format: 'der', type: 'spki' }).subarray(12) : null;
    return (raw !== null && raw.every((b) => b === 0)) || realVerify(...a);
  });
}
const SIGNED = ['manifest', 'rowSignatures', 'rootSignatures'] as const;
const run = (zip: Buffer) => verifyBundle(zip, { allowLegacyUnattested: true, noRekor: true });

describe('AV-2701 — end-to-end: all-zero signing key and signatures', () => {
  it('control: the same bundle under a real key verifies (permissive verify in place)', async () => {
    permissiveForZeroKey();
    const { raw, seed } = realKey();
    const r = await run(bundle(raw, (m) => signEd25519(m, seed)));
    for (const c of SIGNED) expect(r[c].status, `${c}: ${r[c].reason}`).toBe('valid');
    expect(r.chain.status).toBe('valid');
    expect(r.inclusionProofs.status).toBe('valid');
  });

  it('an all-zero key with all-zero signatures is reported invalid', async () => {
    permissiveForZeroKey();
    const zeroSig = Buffer.alloc(64).toString('base64');
    const r = await run(bundle(new Uint8Array(32), () => zeroSig));
    expect(r.ok).toBe(false);
    expect(r.status).toBe('invalid');
    for (const c of SIGNED) expect(r[c].status, c).toBe('invalid');
  });
});
