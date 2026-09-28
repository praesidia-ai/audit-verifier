/**
 * AV-0018 / ADR-0004 (DECISION-SEC-03) — tenant signature format 2 and
 * manifest v7. Format 2 signs `ASCII("praesidia:<purpose>:v2\n") || payload`;
 * the verifier takes the purpose from the slot. A v7 manifest signs the org's
 * format-2 cutover; a format-1 signature dated at or after it fails.
 *
 * Every fixture is signed here with a throwaway seed key, using the byte
 * layout written out literally below (not the verifier's own helper).
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';

import { verifyBundle } from '../verify.js';
import {
  canonicalJson, signEd25519, sha256, merkleBuild, merkleProof, GENESIS_PREV_ROW_HASH, tenantSignedBytes,
} from '../crypto.js';
import { writeZip, gzipDeterministic } from '../zip.js';

const ORG = '00000000-0000-0000-0000-000000000001';
const BASE = Date.UTC(2026, 4, 1);
const iso = (sec: number) => new Date(BASE + sec * 1000).toISOString();
const seed = Buffer.alloc(32, 11);
const pub = (() => {
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const x = (crypto.createPublicKey(priv).export({ format: 'jwk' }) as { x: string }).x;
  return Buffer.from(x, 'base64url').toString('base64');
})();

type Fmt = 1 | 2 | undefined;
type Slot = 'row' | 'root' | 'supersession' | 'checkpoint' | 'event' | 'manifest';
const PURPOSE: Record<Slot, string> = {
  row: 'audit-record',
  root: 'merkle-root',
  supersession: 'merkle-supersession',
  checkpoint: 'integrity-checkpoint',
  event: 'protected-action-event',
  manifest: 'bundle-manifest',
};

/** be's format-2 layout, written out independently of `tenantSignedBytes`. */
function sign(format: Fmt, purpose: string, payload: Buffer): string {
  const bytes = format === 2 ? Buffer.concat([Buffer.from(`praesidia:${purpose}:v2\n`, 'ascii'), payload]) : payload;
  return signEd25519(bytes, new Uint8Array(seed));
}
const withFormat = (f: Fmt) => (f === undefined ? {} : { signatureFormat: f });

interface Opts {
  version?: number;
  cutover?: string | null;
  /** Format per slot (row gets its index). Default: 2 on v7, absent on v6. */
  format?: Partial<{ [K in Slot]: K extends 'row' ? (i: number) => Fmt : Fmt }>;
  /** Purpose actually used to sign a slot (wrong-purpose attacks). */
  purpose?: Partial<Record<Slot, string>>;
  post?: (b: { manifest: Record<string, unknown>; rows: Record<string, unknown>[]; roots: Record<string, unknown>[]; checkpoints: Record<string, unknown>[]; events: Record<string, unknown>[] }) => void;
}

/** 4 rows at 0/60/120/180 s, a partial + superseding root for [0, 3600), a checkpoint at 200 s, one event received at 300 s. */
function build(o: Opts = {}): Buffer {
  const version = o.version ?? 7;
  const dflt: Fmt = version >= 7 ? 2 : undefined;
  const fmt = <K extends Exclude<Slot, 'row'>>(k: K): Fmt => (o.format && k in o.format ? (o.format[k] as Fmt) : dflt);
  const rowFmt = (i: number): Fmt => (o.format?.row ? o.format.row(i) : dflt);
  const purpose = (k: Slot) => o.purpose?.[k] ?? PURPOSE[k];

  const rows: Record<string, unknown>[] = [];
  const leaves: Buffer[] = [];
  let prevRowHash = GENESIS_PREV_ROW_HASH;
  for (let i = 0; i < 4; i++) {
    const signable = {
      organizationId: ORG, action: 'agent.created', actorId: null, actorType: 'user',
      resourceType: 'agent', resourceId: `agent-${i}`, teamId: null, agentId: null,
      summary: null, details: null, createdAt: iso(i * 60),
    };
    const canonical = canonicalJson(signable);
    const signature = sign(rowFmt(i), purpose('row'), Buffer.concat([canonical, Buffer.from(prevRowHash, 'base64')]));
    rows.push({
      id: `row-${i}`, ...signable, signature, keyVersion: 1, signedAt: iso(i * 60 + 1), prevRowHash,
      signatureAlgorithm: 'Ed25519', ...withFormat(rowFmt(i)),
    });
    const leaf = Buffer.concat([canonical, Buffer.from(signature, 'base64')]);
    leaves.push(leaf);
    prevRowHash = sha256(leaf).toString('base64');
  }

  const roots: Record<string, unknown>[] = [];
  const proofs: unknown[] = [];
  for (const [id, idx] of [['root-1', [0, 1]], ['root-2', [0, 1, 2, 3]]] as const) {
    const ls = idx.map((i) => new Uint8Array(leaves[i]!));
    const rootHash = Buffer.from(merkleBuild(ls).root).toString('base64');
    const env = { rootHash, periodStart: iso(0), periodEnd: iso(3600), rowCount: idx.length };
    roots.push({
      id, organizationId: ORG, ...env, keyVersion: 1, signedAt: iso(3605), anchoredAt: null, anchorReceipt: null,
      signatureAlgorithm: 'Ed25519', signature: sign(fmt('root'), purpose('root'), canonicalJson(env)), ...withFormat(fmt('root')),
    });
    idx.forEach((rowIdx, i) => {
      const p = merkleProof(ls, i);
      proofs.push({ rowId: `row-${rowIdx}`, index: p.index, proof: p.siblings.map((x) => Buffer.from(x).toString('base64')), rootHash });
    });
  }
  const [oldRoot, newRoot] = roots as [Record<string, unknown>, Record<string, unknown>];
  newRoot.supersedesRootId = oldRoot.id;
  newRoot.supersessionSignature = sign(fmt('supersession'), purpose('supersession'), canonicalJson({
    version: 'praesidia.root-supersession.v1', supersedes: oldRoot.rootHash, rootHash: newRoot.rootHash,
    periodStart: newRoot.periodStart, periodEnd: newRoot.periodEnd, rowCount: newRoot.rowCount,
  }));
  if (fmt('supersession') !== undefined) newRoot.supersessionSignatureFormat = fmt('supersession');

  const cpEnv = { organizationId: ORG, chainHeadHash: prevRowHash, cumulativeRowCount: '4', asOf: iso(200) };
  const checkpoints: Record<string, unknown>[] = [{
    id: 'cp-1', ...cpEnv, keyVersion: 1, signatureAlgorithm: 'Ed25519',
    signature: sign(fmt('checkpoint'), purpose('checkpoint'), canonicalJson(cpEnv)), ...withFormat(fmt('checkpoint')),
  }];

  const prevEventCommitment = '0'.repeat(64);
  const evSignable = {
    organizationId: ORG, actionId: 'action-1', actionSeq: '1', eventType: 'ACTION_PROPOSED', schemaVersion: '0.1',
    issuerType: 'system', issuerId: 'mcp-proof-edge', trustDomain: 'praesidia', timeSource: 'system',
    observedAt: iso(290), receivedAt: iso(300), dispatched: false, permitNonce: null,
    payload: { actionClass: 'mcp.tool.call', protocol: 'mcp' }, payloadCommitment: null, producerVersion: '1.0.0',
    edgeVersion: null, adapterVersion: null, externalReceiptRef: null, artifactStorageRef: null, prevEventCommitment,
  };
  const evCanonical = canonicalJson(evSignable);
  const evSig = sign(fmt('event'), purpose('event'), Buffer.concat([evCanonical, Buffer.from(prevEventCommitment, 'hex')]));
  const events: Record<string, unknown>[] = [{
    ...evSignable, actionSeq: 1, schemaVersion: 0.1, issuer: 'mcp-proof-edge', signature: evSig,
    signatureAlgorithm: 'Ed25519', keyVersion: 1, ...withFormat(fmt('event')),
    eventCommitment: sha256(Buffer.concat([evCanonical, Buffer.from(evSig, 'base64')])).toString('hex'),
  }];
  delete events[0]!.issuerId;

  const manifestSans: Record<string, unknown> = {
    version, orgId: ORG, from: iso(0), to: iso(3600), rowCount: 4, rootCount: 2,
    keyVersions: [{ keyVersion: 1, publicKey: pub, status: 'ACTIVE', revokedAt: null }],
    generatedAt: iso(3600), signatureAlgorithm: 'Ed25519',
    chainSeqCeiling: 4, chainSeqSnapshotAt: iso(3600), integrityCheckpointCount: 1,
    actionEventCount: 1, captureScopeDigest: sha256(Buffer.from('scope')).toString('hex'),
    evidenceGradeSummary: { A: 0, B: 0, C: 0, D: 0, enforcementMode: 'observe' },
    evidencePrivacy: { modes: [{ mode: 'FULL', effectiveFrom: iso(0) }], schemaVersion: 1 },
  };
  if (version >= 7) {
    manifestSans.signatureFormat = fmt('manifest');
    manifestSans.signatureFormatCutoverAt = o.cutover === undefined ? iso(0) : o.cutover;
  }
  const manifest: Record<string, unknown> = {
    ...manifestSans, signature: sign(fmt('manifest'), purpose('manifest'), canonicalJson(manifestSans)), signatureKeyVersion: 1,
  };
  o.post?.({ manifest, rows, roots, checkpoints, events });

  const nd = (xs: unknown[]) => gzipDeterministic(Buffer.from(xs.map((x) => JSON.stringify(x)).join('\n') + '\n'));
  return writeZip([
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest)) },
    { name: 'rows.ndjson.gz', data: nd(rows) },
    { name: 'roots.ndjson.gz', data: nd(roots) },
    { name: 'proofs.ndjson.gz', data: nd(proofs) },
    { name: 'public-keys.json', data: Buffer.from(JSON.stringify({ 1: { publicKey: pub, status: 'ACTIVE', revokedAt: null } })) },
    { name: 'integrity-checkpoints.ndjson.gz', data: nd(checkpoints) },
    { name: 'action-events.ndjson.gz', data: nd(events) },
    { name: 'README.md', data: Buffer.from('# t\n') },
  ]);
}

const verify = (zip: Buffer) => verifyBundle(zip, { allowLegacyUnattested: true, noRekor: true });
const SIG_COMPONENTS = ['manifest', 'rowSignatures', 'rootSignatures', 'integrityCheckpoints', 'actionEventChain'] as const;
async function expectSignaturesValid(zip: Buffer) {
  const r = await verify(zip);
  for (const c of SIG_COMPONENTS) expect(r[c].status, `${c}: ${r[c].reason}`).toBe('valid');
  return r;
}
const ALL_V1 = { row: () => 1 as Fmt, root: 1, supersession: 1, checkpoint: 1, event: 1, manifest: 1 } as const;

describe('AV-0018 — tenant signature format 2 and manifest v7', () => {
  it('format-2 signed bytes are the ADR-0004 prefix followed by the payload (known answer)', () => {
    const bytes = tenantSignedBytes(2, 'audit-record', Buffer.from('{}'));
    expect(bytes.toString('hex')).toBe(Buffer.from('praesidia:audit-record:v2\n{}', 'ascii').toString('hex'));
    expect(tenantSignedBytes(1, 'audit-record', Buffer.from('{}')).toString()).toBe('{}');
  });

  it('v6 bundle with no format fields verifies unchanged (format 1)', async () => {
    await expectSignaturesValid(build({ version: 6 }));
  });

  it('v7, every slot format 2, verifies', async () => {
    const r = await expectSignaturesValid(build());
    expect(r.rootSignatures.checked).toBe(3);
  });

  it('v7 with no cutover (null), every slot format 1 (explicit or absent), verifies', async () => {
    await expectSignaturesValid(build({ cutover: null, format: ALL_V1 }));
    await expectSignaturesValid(build({
      cutover: null,
      format: { row: () => undefined, root: undefined, supersession: undefined, checkpoint: undefined, event: undefined, manifest: 1 },
    }));
  });

  it('cutover straddle: format 1 before the cutover and format 2 after it verifies', async () => {
    await expectSignaturesValid(build({ cutover: iso(100), format: { row: (i) => (i < 2 ? 1 : 2) } }));
  });

  it('a format-1 row dated at or after the cutover fails as a downgrade', async () => {
    for (const cutover of [iso(100), iso(120)]) {
      const r = await verify(build({ cutover, format: { row: (i) => (i < 3 ? 1 : 2) } }));
      expect(r.rowSignatures.status).toBe('invalid');
      expect(r.rowSignatures.firstFailure).toBe('row-2');
      expect(r.rowSignatures.reason).toMatch(/^signature_format_downgrade/);
      expect(r.status).toBe('invalid');
    }
  });

  it.each([
    ['root', 'rootSignatures'],
    ['supersession', 'rootSignatures'],
    ['checkpoint', 'integrityCheckpoints'],
    ['event', 'actionEventChain'],
    ['manifest', 'manifest'],
  ] as const)('a format-1 %s signature after the cutover fails as a downgrade', async (slot, component) => {
    const r = await verify(build({ cutover: iso(100), format: { row: (i) => (i < 2 ? 1 : 2), [slot]: 1 } }));
    expect(r[component].status).toBe('invalid');
    expect(r[component].reason).toMatch(/signature_format_downgrade/);
    expect(r.status).toBe('invalid');
  });

  it.each([
    ['row', 'merkle-root', 'rowSignatures'],
    ['root', 'audit-record', 'rootSignatures'],
    ['supersession', 'merkle-root', 'rootSignatures'],
    ['checkpoint', 'audit-record', 'integrityCheckpoints'],
    ['event', 'audit-record', 'actionEventChain'],
    ['manifest', 'merkle-root', 'manifest'],
  ] as const)('a format-2 %s signature minted for another purpose (%s) fails', async (slot, wrong, component) => {
    const r = await verify(build({ purpose: { [slot]: wrong } }));
    expect(r[component].status).toBe('invalid');
    expect(r[component].reason).not.toMatch(/signature_format/);
    expect(r.status).toBe('invalid');
  });

  it('a format-2 signature relabelled as format 1 (and vice versa) fails', async () => {
    const relabelled = await verify(build({ cutover: null, post: (b) => { b.rows[1]!.signatureFormat = 1; } }));
    expect(relabelled.rowSignatures.status).toBe('invalid');
    expect(relabelled.rowSignatures.firstFailure).toBe('row-1');
    const upgraded = await verify(build({ cutover: null, format: ALL_V1, post: (b) => { b.roots[0]!.signatureFormat = 2; } }));
    expect(upgraded.rootSignatures.status).toBe('invalid');
  });

  it('an unknown signatureFormat fails closed', async () => {
    for (const bad of [3, 0, '2', null]) {
      const r = await verify(build({ post: (b) => { b.rows[0]!.signatureFormat = bad; } }));
      expect(r.rowSignatures.status).toBe('invalid');
      expect(r.rowSignatures.reason).toMatch(/^signature_format_unsupported/);
    }
  });

  it('the cutover is signed: moving it after signing fails the manifest', async () => {
    const r = await verify(build({ cutover: iso(100), format: { row: (i) => (i < 2 ? 1 : 2) }, post: (b) => {
      b.manifest.signatureFormatCutoverAt = null;
    } }));
    expect(r.manifest.status).toBe('invalid');
    expect(r.status).toBe('invalid');
  });

  it('v7 without the format fields, or v6 with them, fails the manifest', async () => {
    const missing = await verify(build({ post: (b) => { delete b.manifest.signatureFormatCutoverAt; } }));
    expect(missing.manifest.reason).toMatch(/^signature_format_fields_missing_on_v7_manifest/);
    const present = await verify(build({ version: 6, post: (b) => { b.manifest.signatureFormat = 1; } }));
    expect(present.manifest.reason).toMatch(/^signature_format_fields_present_on_v6_manifest/);
  });

  it('a malformed manifest signatureFormat or cutover is a bundle-format error', async () => {
    await expect(verify(build({ post: (b) => { b.manifest.signatureFormat = 3; } }))).rejects.toThrow(/signatureFormat/);
    await expect(verify(build({ post: (b) => { b.manifest.signatureFormatCutoverAt = 'yesterday'; } }))).rejects.toThrow(/signatureFormat/);
  });

  it('a v8 manifest is still rejected as newer than this build', async () => {
    await expect(verify(build({ post: (b) => { b.manifest.version = 8; } }))).rejects.toThrow(/newer than the 7/);
  });
});
