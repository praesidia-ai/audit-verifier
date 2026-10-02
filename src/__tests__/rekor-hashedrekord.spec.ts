/**
 * AV-2771 (lockstep with be BE-3074) — a Rekor receipt binds the bytes the
 * root signature covers, never the bare Merkle root.
 *
 * Rekor's hashedrekord v0.0.1 `validate()` verifies `spec.signature.content`
 * over `spec.data.hash` as a PREHASH. be signs the root ENVELOPE, so the only
 * entry a genuine Rekor accepts carries `data.hash = SHA-256(signed bytes)`.
 * An entry with `data.hash = rootHash` never verified at any Rekor, so no such
 * receipt exists.
 *
 * Every key is generated here: the tenant key is P-256, the key type of the
 * aws-kms substrate, and the log key is pinned via `rekorPublicKeyPem`. The
 * signed-bytes layout is written out literally, not built with the verifier's
 * own helper.
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';

import { verifyBundle } from '../verify.js';
import { verifyRekorReceipt } from '../rekor.js';
import { canonicalJson, isLowSP256, merkleBuild, merkleProof, GENESIS_PREV_ROW_HASH } from '../crypto.js';
import { writeZip, gzipDeterministic } from '../zip.js';

type Fmt = 1 | 2;
interface Envelope { rootHash: string; periodStart: string; periodEnd: string; rowCount: number }

const ORG = '00000000-0000-0000-0000-000000000abc';
const BASE = Date.UTC(2026, 4, 1);
const iso = (sec: number) => new Date(BASE + sec * 1000).toISOString();
const sha256 = (b: Buffer) => crypto.createHash('sha256').update(b).digest();
const p256 = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

/**
 * be `MerkleRootService` signed bytes: format 2 prefixes ASCII
 * `praesidia:merkle-root:v2\n`; the payload is canonical JSON of the envelope,
 * keys sorted, timestamps as `Date#toISOString()` (ms, `Z`), rowCount a bare
 * integer.
 */
function rootSignedBytes(format: Fmt, e: Envelope): Buffer {
  const json =
    `{"periodEnd":${JSON.stringify(e.periodEnd)},"periodStart":${JSON.stringify(e.periodStart)},` +
    `"rootHash":${JSON.stringify(e.rootHash)},"rowCount":${e.rowCount}}`;
  return Buffer.from((format === 2 ? 'praesidia:merkle-root:v2\n' : '') + json, 'utf8');
}

/** ECDSA-P256-SHA256 DER with low s, the only form the verifier accepts. */
function signP256(message: Buffer, key: crypto.KeyObject): string {
  for (let i = 0; i < 64; i++) {
    const sig = crypto.sign('sha256', message, key);
    if (isLowSP256(sig)) return sig.toString('base64');
  }
  throw new Error('no low-s signature in 64 tries');
}

/** The hashedrekord body be's anchor runner submits after BE-3074. */
function hashedrekord(digestHex: string, signatureB64: string, tenantPem: string) {
  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: { hash: { algorithm: 'sha256', value: digestHex } },
      signature: { content: signatureB64, publicKey: { content: Buffer.from(tenantPem).toString('base64') } },
    },
  };
}
type Body = ReturnType<typeof hashedrekord>;

/**
 * Rekor's ECDSA rule is `VerifyASN1(pub, hexdecode(data.hash), sig)`. Node
 * cannot verify over a raw digest, so check the equivalent: data.hash is
 * SHA-256(M) and the signature verifies over M under the body's own key.
 */
function rekorAccepts(body: Body, message: Buffer): boolean {
  const pem = Buffer.from(body.spec.signature.publicKey.content, 'base64').toString('utf8');
  return (
    body.spec.data.hash.value === sha256(message).toString('hex') &&
    crypto.verify('sha256', message, pem, Buffer.from(body.spec.signature.content, 'base64'))
  );
}

/** A single-leaf log entry for `body`: SET, signed checkpoint, inclusion proof, under a fresh log key. */
function logEntry(body: Body, integratedTime: number): { receiptJson: string; logPem: string } {
  const { publicKey, privateKey } = p256();
  const logPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const logID = sha256(publicKey.export({ type: 'spki', format: 'der' })).toString('hex');
  const bodyB64 = Buffer.from(JSON.stringify(body)).toString('base64');
  const set = crypto.sign(
    'sha256',
    Buffer.from(`{"body":${JSON.stringify(bodyB64)},"integratedTime":${integratedTime},"logID":"${logID}","logIndex":0}`),
    privateKey,
  );
  const leaf = sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(bodyB64, 'base64')]));
  const note = `rekor.test\n1\n${leaf.toString('base64')}\n`;
  const noteSig = Buffer.concat([Buffer.from(logID, 'hex').subarray(0, 4), crypto.sign('sha256', Buffer.from(note), privateKey)]);
  const receipt = {
    logIndex: 0,
    logId: logID,
    integratedTime,
    body: bodyB64,
    signedEntryTimestamp: set.toString('base64'),
    inclusionProof: { logIndex: 0, treeSize: 1, rootHash: leaf.toString('hex'), hashes: [], checkpoint: `${note}\n— rekor.test ${noteSig.toString('base64')}\n` },
  };
  return { receiptJson: JSON.stringify(receipt), logPem };
}

interface Tenant { env: Envelope; signedBytes: Buffer; signature: string; pem: string }

/**
 * A one-row, one-root bundle signed by a P-256 tenant key, rows and root in
 * `format`, whose root carries `receipt(tenant)` as its Rekor anchor.
 * `rootSignature` replaces the root's signature (forgery cases).
 */
function anchoredBundle(
  format: Fmt,
  receipt: (t: Tenant) => string,
  o: { rootSignature?: (t: Tenant) => string; keyVersion?: number } = {},
): Buffer {
  const { publicKey, privateKey } = p256();
  const spkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const fmt = format === 2 ? { signatureFormat: 2 } : {};
  const prefix = (purpose: string) => Buffer.from(format === 2 ? `praesidia:${purpose}:v2\n` : '', 'ascii');

  const signable = {
    organizationId: ORG, action: 'agent.created', actorId: null, actorType: 'user', resourceType: 'agent',
    resourceId: 'agent-0', teamId: null, agentId: null, summary: null, details: null, createdAt: iso(0),
  };
  const canonical = canonicalJson(signable);
  const rowSig = signP256(Buffer.concat([prefix('audit-record'), canonical, Buffer.from(GENESIS_PREV_ROW_HASH, 'base64')]), privateKey);
  const row = {
    id: 'row-0', ...signable, signature: rowSig, keyVersion: 1, signedAt: iso(1), prevRowHash: GENESIS_PREV_ROW_HASH,
    signatureAlgorithm: 'ECDSA_P256_SHA256', ...fmt,
  };
  const leaf = new Uint8Array(Buffer.concat([canonical, Buffer.from(rowSig, 'base64')]));
  const env: Envelope = { rootHash: Buffer.from(merkleBuild([leaf]).root).toString('base64'), periodStart: iso(0), periodEnd: iso(3600), rowCount: 1 };
  const signedBytes = rootSignedBytes(format, env);
  const tenant: Tenant = {
    env, signedBytes, signature: signP256(signedBytes, privateKey),
    pem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
  if (o.rootSignature) tenant.signature = o.rootSignature(tenant);
  const root = {
    id: 'root-1', organizationId: ORG, ...env, signature: tenant.signature, keyVersion: o.keyVersion ?? 1, signedAt: iso(3605),
    anchoredAt: iso(3610), anchorReceipt: null, signatureAlgorithm: 'ECDSA_P256_SHA256', ...fmt,
    anchorReceipts: [{ provider: 'rekor', receipt: receipt(tenant), anchoredAt: iso(3610) }],
  };
  const proof = merkleProof([leaf], 0);
  const manifestSans = {
    version: 1, orgId: ORG, from: iso(0), to: iso(3600), rowCount: 1, rootCount: 1,
    keyVersions: [{ keyVersion: 1, publicKey: spkiB64 }], generatedAt: iso(3630), signatureAlgorithm: 'ECDSA_P256_SHA256',
  };
  const manifest = { ...manifestSans, signature: signP256(canonicalJson(manifestSans), privateKey), signatureKeyVersion: 1 };
  const nd = (x: unknown) => gzipDeterministic(Buffer.from(JSON.stringify(x) + '\n'));
  return writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest)) },
    { name: 'rows.ndjson.gz', data: nd(row) },
    { name: 'roots.ndjson.gz', data: nd(root) },
    { name: 'proofs.ndjson.gz', data: nd({ rowId: 'row-0', index: proof.index, proof: [], rootHash: env.rootHash }) },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify({ 1: spkiB64 })) },
    { name: 'README.md', data: Buffer.from('# t\n') },
  ]);
}

/** Integrated two seconds before the recorded anchor time, inside the window. */
const LOG_TIME = Math.floor(Date.parse(iso(3608)) / 1000);

/** Build the bundle, log `body(tenant)` with a fresh log key and verify the Rekor component under that pin. */
async function verifyAnchored(
  format: Fmt,
  body: (t: Tenant) => Body,
  o: { rootSignature?: (t: Tenant) => string; keyVersion?: number; expectRekorAccepts?: boolean } = {},
) {
  let logPem = '';
  const zip = anchoredBundle(format, (t) => {
    const b = body(t);
    if (o.expectRekorAccepts !== undefined) expect(rekorAccepts(b, t.signedBytes)).toBe(o.expectRekorAccepts);
    const entry = logEntry(b, LOG_TIME);
    logPem = entry.logPem;
    return entry.receiptJson;
  }, o);
  // No platform attestation: that trust anchor is out of scope here (as in verify.spec.ts).
  return verifyBundle(zip, { rekorPublicKeyPem: logPem, allowLegacyUnattested: true });
}

/** The BE-3074 receipt: data.hash = SHA-256(signed bytes), the root's own signature and key. */
const be3074 = (t: Tenant): Body => hashedrekord(sha256(t.signedBytes).toString('hex'), t.signature, t.pem);

describe('AV-2771 — Rekor receipts bind SHA-256(root signed bytes) (BE-3074)', () => {
  it('signed-bytes recipe, known answer (be BE-3074 must produce this data.hash)', () => {
    const env: Envelope = {
      rootHash: Buffer.alloc(32, 0x11).toString('base64'),
      periodStart: '2026-05-01T00:00:00.000Z',
      periodEnd: '2026-05-01T01:00:00.000Z',
      rowCount: 4,
    };
    const json =
      '{"periodEnd":"2026-05-01T01:00:00.000Z","periodStart":"2026-05-01T00:00:00.000Z",' +
      '"rootHash":"ERERERERERERERERERERERERERERERERERERERERERE=","rowCount":4}';
    expect(rootSignedBytes(2, env).toString('utf8')).toBe('praesidia:merkle-root:v2\n' + json);
    expect(rootSignedBytes(1, env).toString('utf8')).toBe(json);
    expect(canonicalJson(env).toString('utf8')).toBe(json);
    expect(sha256(rootSignedBytes(2, env)).toString('hex')).toBe(
      '08405a82a292b52a9a71350fbced69d0ae82be6b9cccc25d5c409307dc30d6ce',
    );
    expect(sha256(rootSignedBytes(1, env)).toString('hex')).toBe(
      '6e067a1bf397c5a6e004327d637ce1ec4beb7c27d243a47911f147520dbe6bea',
    );
  });

  it.each([2, 1] as const)('a P-256 root anchored the BE-3074 way verifies (format %d)', async (format) => {
    const report = await verifyAnchored(format, be3074, { expectRekorAccepts: true });
    expect(report.rootSignatures.ok).toBe(true);
    expect(report.rekor.reason).toBeUndefined();
    expect(report.rekor).toMatchObject({ ok: true, checked: 1, failed: 0 });
    expect(report.ok).toBe(true);
  });

  it.each([2, 1] as const)('the pre-BE-3074 receipt (data.hash = rootHash) fails body_root_mismatch (format %d)', async (format) => {
    const report = await verifyAnchored(
      format,
      (t) => hashedrekord(Buffer.from(t.env.rootHash, 'base64').toString('hex'), t.signature, t.pem),
      { expectRekorAccepts: false },
    );
    expect(report.rekor.ok).toBe(false);
    expect(report.rekor.reason).toBe('rekor: body_root_mismatch');
    expect(report.ok).toBe(false);
  });

  it('the digest binds the format prefix: the other format’s digest fails body_root_mismatch', async () => {
    for (const [format, other] of [[2, 1], [1, 2]] as const) {
      const report = await verifyAnchored(format, (t) =>
        hashedrekord(sha256(rootSignedBytes(other, t.env)).toString('hex'), t.signature, t.pem));
      expect(report.rekor.reason).toBe('rekor: body_root_mismatch');
    }
  });

  it('the digest binds the period: a receipt for another periodEnd fails body_root_mismatch', async () => {
    const report = await verifyAnchored(2, (t) =>
      hashedrekord(sha256(rootSignedBytes(2, { ...t.env, periodEnd: iso(7200) })).toString('hex'), t.signature, t.pem));
    expect(report.rekor.reason).toBe('rekor: body_root_mismatch');
  });

  it('anyone can log the root’s signed bytes under their own key; that entry fails body_root_mismatch', async () => {
    const other = p256();
    const otherPem = other.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const report = await verifyAnchored(
      2,
      (t) => hashedrekord(sha256(t.signedBytes).toString('hex'), signP256(t.signedBytes, other.privateKey), otherPem),
      { expectRekorAccepts: true },
    );
    expect(report.rekor.reason).toBe('rekor: body_root_mismatch');
  });

  it('a root signature that does not verify under the root key fails body_signature_invalid, receipt and all', async () => {
    const other = p256();
    const otherPem = other.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const report = await verifyAnchored(
      2,
      (t) => hashedrekord(sha256(t.signedBytes).toString('hex'), t.signature, otherPem),
      { rootSignature: (t) => signP256(t.signedBytes, other.privateKey), expectRekorAccepts: true },
    );
    expect(report.rootSignatures.ok).toBe(false);
    expect(report.rekor.reason).toBe('rekor: body_signature_invalid');
  });

  it('a root whose key version is not in public-keys.json fails closed', async () => {
    const report = await verifyAnchored(2, be3074, { keyVersion: 2 });
    expect(report.rootSignatures.ok).toBe(false);
    expect(report.rekor.reason).toBe('rekor: root_key_unavailable');
  });
});

describe('AV-2771 — verifyRekorReceipt fails closed on an unusable expected root', () => {
  it('an unknown signatureFormat is expected_root_malformed', () => {
    const { publicKey, privateKey } = p256();
    const env: Envelope = { rootHash: Buffer.alloc(32, 1).toString('base64'), periodStart: iso(0), periodEnd: iso(3600), rowCount: 1 };
    const signedBytes = rootSignedBytes(2, env);
    const signature = signP256(signedBytes, privateKey);
    const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const { receiptJson, logPem } = logEntry(hashedrekord(sha256(signedBytes).toString('hex'), signature, pem), LOG_TIME);
    const expected = {
      rootHashB64: env.rootHash,
      periodStart: env.periodStart,
      periodEnd: env.periodEnd,
      rowCount: env.rowCount,
      signatureB64: signature,
      signatureAlgorithm: 'ECDSA_P256_SHA256' as const,
      publicKey: publicKey.export({ type: 'spki', format: 'der' }),
    };
    expect(verifyRekorReceipt(receiptJson, logPem, { ...expected, signatureFormat: 2 })).toEqual({ ok: true });
    for (const signatureFormat of [3, 0, '2'] as unknown as number[]) {
      expect(verifyRekorReceipt(receiptJson, logPem, { ...expected, signatureFormat })).toEqual({
        ok: false,
        reason: 'expected_root_malformed',
      });
    }
  });
});
