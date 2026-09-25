/**
 * AV-0011 — deterministic generator for `samples/` (valid, corrupted and
 * wrong-key audit packages), so anyone can try the verifier before owning a
 * Praesidia org. `npm run build && node scripts/make-sample-bundles.mjs [out]`
 * (default out: samples/). `src/__tests__/samples.spec.ts` regenerates into a
 * tmp dir and requires byte equality with the committed files.
 *
 * SAMPLE — NOT A PRAESIDIA KEY. Every key below is a TEST key derived from a
 * public label in this file, so its private half is public by construction.
 * No private key is written to disk; `sample-platform-key.pem` is the PUBLIC
 * half of the sample platform key. Nothing signed by these keys proves
 * anything about Praesidia, and the verifier never trusts them implicitly.
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, signEd25519, sha256, merkleBuild, merkleProof, GENESIS_PREV_ROW_HASH } from '../dist/crypto.js';
import { writeZip, gzipDeterministic } from '../dist/zip.js';

const LABEL = 'SAMPLE — NOT A PRAESIDIA KEY';
const seedOf = (name) => sha256(Buffer.from(`${LABEL} / audit-verifier samples / ${name}`, 'utf8'));
const ORG = '5a3b1e00-0000-4000-8000-00000000a011';
const BASE = Date.UTC(2026, 8, 1); // fixed timestamps: 2026-09-01T00:00:00Z + s
const iso = (s) => new Date(BASE + s * 1000).toISOString();
const b64 = (b) => Buffer.from(b).toString('base64');
const hex = (b) => Buffer.from(b).toString('hex');

// ── Tenant row-signing key: Ed25519 (deterministic by construction). ──
const tenantSeed = seedOf('tenant Ed25519 v1');
const tenantPub = Buffer.from(
  crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), tenantSeed]), format: 'der', type: 'pkcs8',
  })).export({ format: 'jwk' }).x, 'base64url');

// ── Platform attestation keys: ECDSA P-256 with a deterministic nonce. ──
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const big = (b) => BigInt(`0x${hex(b)}`);
const bytes32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
const modpow = (b, e, m) => { let r = 1n; for (b %= m; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m; return r; };
/** scalar·G, uncompressed (04 || x || y) — Node does the curve arithmetic. */
const pointOf = (scalar) => { const e = crypto.createECDH('prime256v1'); e.setPrivateKey(bytes32(scalar)); return e.getPublicKey(); };
const derInt = (n) => { let b = bytes32(n); while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return Buffer.concat([Buffer.from([2, b.length]), b]); };
function p256Key(name) {
  const d = (big(seedOf(name)) % (N - 1n)) + 1n;
  const spki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), pointOf(d)]);
  const sign = (msg) => {
    const z = big(sha256(msg));
    // k = HMAC-SHA256(d, z || counter) until 0 < k < n: deterministic, secret-derived.
    for (let c = 0; ; c++) {
      const k = big(crypto.createHmac('sha256', bytes32(d)).update(Buffer.concat([bytes32(z), Buffer.from([c])])).digest());
      if (k === 0n || k >= N) continue;
      const r = big(pointOf(k).subarray(1, 33)) % N;
      let s = (modpow(k, N - 2n, N) * ((z + r * d) % N)) % N;
      if (r === 0n || s === 0n) continue;
      if (s > N / 2n) s = N - s; // low-s, as be's enforceLowSP256
      const body = Buffer.concat([derInt(r), derInt(s)]);
      const sig = Buffer.concat([Buffer.from([0x30, body.length]), body]);
      const pub = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
      if (!crypto.verify('sha256', msg, pub, sig)) throw new Error('sample ECDSA self-check failed');
      return sig;
    }
  };
  return { spki, sign };
}
const platformKey = p256Key('platform P-256');
const otherPlatformKey = p256Key('some other platform P-256 (never published)');

// ── Rows: a plain row, then the decision / approval / outcome trio. ──
const decisions = [
  { rowId: 'row-decision', action: 'POLICY_DECISION', at: 60, salt: seedOf('salt decision').subarray(0, 16), details: {
    schemaVersion: 1, decisionId: 'dec-sample-1', decision: 'STEP_UP', canonicalDecision: 'REQUIRE_APPROVAL',
    policyId: 'pol-outbound-email', policyVersion: '4', approvalId: 'appr-sample-1', fnName: 'send_email' } },
  { rowId: 'row-outcome', action: 'POLICY_DECISION', at: 180, salt: seedOf('salt outcome').subarray(0, 16), details: {
    schemaVersion: 1, decisionId: 'dec-sample-2', decision: 'ALLOW', canonicalDecision: 'ALLOW', reasonCode: 'approval_consumed',
    policyId: 'pol-outbound-email', policyVersion: '4', approvalId: 'appr-sample-1', fnName: 'send_email' } },
];
const commitment = (d) => b64(sha256(Buffer.concat([d.salt, canonicalJson({ details: d.details })])));
const plain = (id, at, action, resourceType, summary, details) => ({ id, signable: {
  organizationId: ORG, action, actorId: null, actorType: 'user', resourceType, resourceId: null, teamId: null,
  agentId: 'agent-sample', summary, details, createdAt: iso(at) } });
const committed = (d) => ({ id: d.rowId, signable: {
  organizationId: ORG, action: d.action, actorId: null, actorType: 'agent', resourceType: 'policy', resourceId: null,
  teamId: null, agentId: 'agent-sample', createdAt: iso(d.at), detailsCommitment: commitment(d) } });
const specs = [
  plain('row-agent', 0, 'agent.created', 'agent', 'Created agent: Sample Agent', { name: 'Sample Agent' }),
  committed(decisions[0]),
  plain('row-approval', 120, 'approval.approved', 'approval', 'Approved send_email for Sample Agent', { approvalId: 'appr-sample-1' }),
  committed(decisions[1]),
];

function buildBundle(platform) {
  const rows = [];
  const leaves = [];
  let prevRowHash = GENESIS_PREV_ROW_HASH;
  for (const s of specs) {
    const canonical = canonicalJson(s.signable);
    const signature = signEd25519(Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]), new Uint8Array(tenantSeed));
    rows.push({ id: s.id, ...s.signable, signature, keyVersion: 1, signedAt: s.signable.createdAt, prevRowHash });
    const leaf = Buffer.concat([canonical, Buffer.from(signature, 'base64')]);
    leaves.push(new Uint8Array(leaf));
    prevRowHash = b64(sha256(leaf));
  }
  const rootHash = b64(merkleBuild(leaves).root);
  const [periodStart, periodEnd] = [iso(0), iso(3600)];
  const root = {
    id: 'root-sample', organizationId: ORG, periodStart, periodEnd, rowCount: rows.length, rootHash,
    signature: signEd25519(canonicalJson({ rootHash, periodStart, periodEnd, rowCount: rows.length }), new Uint8Array(tenantSeed)),
    keyVersion: 1, signedAt: iso(3605), anchoredAt: null, anchorReceipt: null,
  };
  const proofs = rows.map((r, i) => {
    const p = merkleProof(leaves, i);
    return { rowId: r.id, index: p.index, proof: p.siblings.map(b64), rootHash };
  });
  const signable = {
    version: 1, orgId: ORG, from: periodStart, to: periodEnd, rowCount: rows.length, rootCount: 1,
    keyVersions: [{ keyVersion: 1, publicKey: b64(tenantPub) }], generatedAt: iso(3606), signatureAlgorithm: 'Ed25519',
  };
  const manifest = { ...signable, signature: signEd25519(canonicalJson(signable), new Uint8Array(tenantSeed)), signatureKeyVersion: 1 };
  const attestation = {
    orgId: ORG,
    keyVersions: [{ keyVersion: 1, fingerprint: hex(sha256(tenantPub)), status: 'ACTIVE', revokedAt: null, issuedAt: iso(-86400) }],
    issuedAt: iso(3606),
    platformSigningKeyFingerprint: hex(sha256(platform.spki)),
    manifestGeneratedAt: manifest.generatedAt,
    manifestDigest: hex(sha256(canonicalJson(signable))),
    signatureAlgorithm: 'ECDSA_P256_SHA256',
  };
  const ndjsonGz = (xs) => gzipDeterministic(Buffer.from(xs.map((x) => JSON.stringify(x) + '\n').join(''), 'utf8'));
  const json = (x) => Buffer.from(JSON.stringify(x, null, 2) + '\n', 'utf8');
  return { rows, entries: [
    { name: 'manifest.json', data: json(manifest) },
    { name: 'rows.ndjson.gz', data: ndjsonGz(rows) },
    { name: 'roots.ndjson.gz', data: ndjsonGz([root]) },
    { name: 'proofs.ndjson.gz', data: ndjsonGz(proofs) },
    { name: 'public-keys.json', data: json({ 1: b64(tenantPub) }) },
    { name: 'platform-attestation.json', data: json({ attestation, signature: b64(platform.sign(canonicalJson(attestation))) }) },
    { name: 'README.md', data: Buffer.from(`# SAMPLE bundle — signed with test keys (${LABEL})\n`, 'utf8') },
  ] };
}

const disclosures = Buffer.from([
  ...decisions.map((d) => ({ version: 'praesidia.decision-disclosure.v1', rowId: d.rowId, decisionId: d.details.decisionId, details: d.details, detailsSalt: b64(d.salt) })),
  { version: 'praesidia.decision-disclosure.v1', withheld: 0 },
].map((l) => JSON.stringify(l) + '\n').join(''), 'utf8');

function auditPackage(bundle) {
  const receipt = `SAMPLE audit package — signed with test keys (${LABEL}).\n` +
    `Evidence archive SHA-256: ${hex(sha256(bundle))}\nEvidence archive bytes: ${bundle.length}\n`;
  return writeZip([
    { name: 'evidence/audit-bundle.zip', data: bundle },
    { name: 'verification.txt', data: Buffer.from(receipt, 'utf8') },
    { name: 'evidence/decision-receipts.ndjson', data: disclosures },
  ]);
}

/** Every sample file name → its exact bytes. */
export function buildSamples() {
  const valid = buildBundle(platformKey);
  // Corrupted: flip ONE byte ('d' → 'e') of one signed row's summary. The
  // unsigned receipt is recomputed, so only the signatures can catch it.
  const rowsNdjson = Buffer.from(valid.rows.map((x) => JSON.stringify(x) + '\n').join(''), 'utf8');
  const at = rowsNdjson.indexOf('Approved send_email') + 'Approve'.length;
  rowsNdjson[at] ^= 0x01;
  const corrupted = valid.entries.map((e) => (e.name === 'rows.ndjson.gz' ? { ...e, data: gzipDeterministic(rowsNdjson) } : e));
  const pem = crypto.createPublicKey({ key: platformKey.spki, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' });
  return new Map([
    ['audit-package.valid.zip', auditPackage(writeZip(valid.entries))],
    ['audit-package.corrupted.zip', auditPackage(writeZip(corrupted))],
    // Wrong key: a well-formed package whose platform attestation is signed by
    // a key other than sample-platform-key.pem.
    ['audit-package.wrong-key.zip', auditPackage(writeZip(buildBundle(otherPlatformKey).entries))],
    ['sample-platform-key.pem', Buffer.from(`# ${LABEL} — public half of the SAMPLE platform attestation test key.\n${pem}`, 'utf8')],
  ]);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'samples'));
  fs.mkdirSync(out, { recursive: true });
  for (const [name, data] of buildSamples()) fs.writeFileSync(path.join(out, name), data);
  process.stdout.write(`wrote ${[...buildSamples().keys()].join(', ')} to ${out}\n`);
}
