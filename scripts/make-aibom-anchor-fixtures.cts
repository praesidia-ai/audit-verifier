/**
 * AV-0005 — regenerate `test-fixtures/aibom/anchored/` from be's REAL BE-1255
 * export path: `AibomService.exportSnapshot(…, 'attested')` over a real
 * `AuditProofService` (anchor-request row + Merkle inclusion proof) and a real
 * `AnchorStatusService` (the `anchor*` labels). The setup mirrors
 * `be/src/aibom/aibom-anchor-proof.spec.ts`; only persistence is in-memory.
 * `be-verdicts.json` records be's own `verifyAibomAttestation` verdict for
 * every file, so this package's spec proves both verifiers agree on the same
 * bytes. Dev-only: not compiled, not published. Needs a sibling `be` checkout:
 *
 *   cd <core>/be && NODE_PATH=$PWD/node_modules npx ts-node --transpile-only --project tsconfig.json \
 *     <audit-verifier>/scripts/make-aibom-anchor-fixtures.cts <core>/be <out-dir>
 *
 * No server, no DB, no network. Keys (tenant Ed25519, fixture Rekor log
 * P-256) are throwaway and die with the process.
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

const [beDir, outDir] = process.argv.slice(2);
if (!beDir || !outDir) throw new Error('usage: make-aibom-anchor-fixtures.cts <be-dir> <out-dir>');
const be = (p: string) => require(path.resolve(beDir, 'src', p));
const { AibomService } = be('aibom/aibom.service');
const { AIBOM_SIGNING_DOMAIN, verifyAibomAttestation } = be('aibom/aibom-attestation');
const { aibomDigest } = be('aibom/aibom-canonical');
const { AuditCanonicalHelper, GENESIS_PREV_ROW_HASH } = be('audit/audit-canonical.helper');
const { AuditProofService, detachedDigestMessage } = be('audit/services/audit-proof.service');
const { AnchorStatusService } = be('audit/services/anchor-status.service');
const { buildRekorReceiptJson } = be('audit/services/rekor/verify-rekor-set');
const { buildRekorFixture } = be('audit/services/rekor/__test-helpers__/rekor-entry-fixture');
const { CryptoUtilsService } = be('common/security/services/crypto-utils.service');
const { canonicalJson } = be('common/security/utils/canonical-json');

type Json = Record<string, any>;
const ORG = '11111111-1111-4111-8111-111111111111';
const SYSTEM_ID = 'system-1';
const ROW_ID = '0b8f5c1e-3d2a-4f6b-9c7d-1e2f3a4b5c6d';
const FILLER_ID = '0b8f5c1e-3d2a-4f6b-9c7d-000000000000';
const PERIOD_START = new Date('2026-09-01T09:00:00.000Z');
const PERIOD_END = new Date('2026-09-01T10:00:00.000Z');
const ANCHORED_AT = '2026-09-01T10:05:00.000Z';
const LOG_TIME = '2026-09-01T10:04:58.000Z';
const SALT = Buffer.alloc(16, 7).toString('base64');
const DOCUMENT = { organizationId: ORG, aiSystemId: SYSTEM_ID, components: [] };
const DIGEST = aibomDigest(DOCUMENT);

const cu = new CryptoUtilsService();
const helper = new AuditCanonicalHelper();
const tenantKey = cu.generateEd25519KeyPair();
const rekorPems: string[] = [];

function signedRow(id: string, offsetMs: number, action: string, details: Json | null, commitment = false): Json {
  const createdAt = new Date(PERIOD_START.getTime() + offsetMs);
  const row: Json = {
    id, organizationId: ORG, action, userId: null, teamId: null, agentId: null, details, ipAddress: null,
    signatureAlgorithm: 'Ed25519', keyVersion: 1, signedAt: createdAt, createdAt, prevRowHash: GENESIS_PREV_ROW_HASH,
    signableResourceId: null, detailsCommitmentSigned: commitment,
    detailsCommitment: helper.computeDetailsCommitment(details, SALT), detailsCommitmentSalt: SALT,
  };
  row.signature = cu.signEd25519(
    Buffer.concat([helper.canonicalizeRow(helper.buildSignableRow(row)), Buffer.from(row.prevRowHash, 'base64')]),
    tenantKey.privateKey,
  );
  return row;
}

/** Root over `rows`, signed by the tenant key; with a Rekor receipt whose hashedrekord binds it. */
function rootOver(rows: Json[], withReceipt: boolean): Json {
  const leaves = rows.map((r) => new Uint8Array(Buffer.concat([
    helper.canonicalizeRow(helper.buildSignableRow(r)), Buffer.from(r.signature, 'base64'),
  ])));
  const rootHash = Buffer.from(cu.merkleBuild(leaves).root).toString('base64');
  const rootMessage = canonicalJson({
    rootHash, periodStart: PERIOD_START.toISOString(), periodEnd: PERIOD_END.toISOString(), rowCount: rows.length,
  });
  const signature = cu.signEd25519(rootMessage, tenantKey.privateKey);
  const rekor = buildRekorFixture({
    integratedTime: Date.parse(LOG_TIME) / 1000,
    body: JSON.stringify({
      apiVersion: '0.0.1', kind: 'hashedrekord',
      spec: {
        // AV-2771 (be BE-3074) — SHA-256 of the bytes the root signature covers (format 1).
        data: { hash: { algorithm: 'sha256', value: crypto.createHash('sha256').update(rootMessage).digest('hex') } },
        signature: { content: signature, publicKey: { content: 'cGs=' } },
      },
    }),
  });
  if (withReceipt) rekorPems.push(rekor.publicKeyPem);
  return {
    id: 'root-1', organizationId: ORG, periodStart: PERIOD_START, periodEnd: PERIOD_END, rowCount: rows.length,
    rootHash, signature, signatureAlgorithm: 'Ed25519', keyVersion: 1, signedAt: PERIOD_END,
    anchoredAt: new Date(ANCHORED_AT), anchorReceipt: null, s3AnchorReceipt: null, anchorVerifiedAt: null,
    anchorReceipts: withReceipt ? [{ provider: 'rekor', receipt: buildRekorReceiptJson(rekor.entry), anchoredAt: ANCHORED_AT }] : [],
    rekor,
  };
}

/** One attested export, as `aibom-anchor-proof.spec.ts` `arrange` + `exportEnvelope` build it. */
async function exportAnchored(opts: { commitment?: boolean; redacted?: boolean; root?: 'receipt' | 'no-receipt' | 'none' }): Promise<Buffer> {
  const anchorRow = signedRow(ROW_ID, 2000, 'aibom.snapshot.anchor_requested', { aiSystemId: SYSTEM_ID, digest: DIGEST }, opts.commitment);
  if (opts.redacted) anchorRow.details = null; // retention redaction nulls the plaintext AFTER signing
  const rows = [signedRow(FILLER_ID, 1000, 'agent.create', { agentName: 'Nova' }), anchorRow];
  const root = opts.root === 'none' ? null : rootOver(rows, opts.root !== 'no-receipt');
  const merkleRootRepo = { findOne: async () => root };
  const auditLogRepo = {
    findOne: async ({ where }: { where: Json }) => (where.organizationId === ORG ? (rows.find((r) => r.id === where.id) ?? null) : null),
    createQueryBuilder: () => {
      const qb: Json = { where: () => qb, andWhere: () => qb, orderBy: () => qb, addOrderBy: () => qb, getMany: async () => rows };
      return qb;
    },
  };
  const tenantKeys = {
    findByOrgAndVersion: async (orgId: string, v: number) =>
      orgId === ORG && v === 1 ? { publicKey: Buffer.from(tenantKey.publicKey).toString('base64') } : null,
  };
  const shim = { buildSignableRow: (r: Json) => helper.buildSignableRow(r), canonicalizeRow: (r: Json) => helper.canonicalizeRow(r) };
  const proof = new AuditProofService(auditLogRepo, merkleRootRepo, shim, tenantKeys, cu);
  const anchorStatus = new AnchorStatusService(merkleRootRepo, {
    resolvePem: (id: string) => (root && id === root.rekor.logIdHex ? root.rekor.publicKeyPem : null),
  });
  const auditService = {
    getRowContent: async (orgId: string) => (orgId === ORG ? { action: anchorRow.action, details: anchorRow.details } : null),
    verifyRowSignature: async () => ({ valid: true, reason: 'verified', chainOk: true, ...(await anchorStatus.getRowAnchorStatus(ORG, anchorRow)) }),
  };
  const snapshot = {
    id: 'snap-1', organizationId: ORG, aiSystemId: SYSTEM_ID, version: 1, generatedAt: PERIOD_START, document: DOCUMENT,
    digest: DIGEST, componentCount: 0, signingAlgorithm: 'Ed25519', signingKeyVersion: 1, signedAt: PERIOD_START,
    signature: cu.signEd25519(detachedDigestMessage(AIBOM_SIGNING_DOMAIN, DIGEST), tenantKey.privateKey),
    anchorReference: `audit:${ROW_ID}`,
  };
  const unused = {};
  const service = new AibomService(
    unused, unused, unused, { findOne: async () => snapshot }, unused, unused, unused,
    { findOne: async () => ({ id: SYSTEM_ID }) }, proof, undefined, auditService,
  );
  return (await service.exportSnapshot(ORG, SYSTEM_ID, 'snap-1', 'attested')).bytes as Buffer;
}

async function main(): Promise<void> {
  fs.mkdirSync(outDir, { recursive: true });
  const out: Record<string, Buffer> = {
    'anchored-rekor': await exportAnchored({}),
    'anchored-commitment': await exportAnchored({ commitment: true }),
    'anchor-pending': await exportAnchored({ root: 'no-receipt' }),
    'anchor-not-yet-rooted': await exportAnchored({ root: 'none' }),
    'anchor-redacted': await exportAnchored({ commitment: true, redacted: true }),
  };
  // Pins come from the generator's OWN key material, never from an envelope.
  const pins = {
    trustedKeyFingerprints: [crypto.createHash('sha256').update(tenantKey.publicKey).digest('hex')],
    rekorPublicKeysPem: rekorPems,
  };
  const verdicts: Record<string, Json> = {};
  for (const [name, bytes] of Object.entries(out)) {
    fs.writeFileSync(path.join(outDir, `${name}.attested.json`), bytes);
    const env = JSON.parse(bytes.toString('utf8'));
    verdicts[name] = {
      pinned: verifyAibomAttestation(env, pins),
      sigstoreOnly: verifyAibomAttestation(env, { trustedKeyFingerprints: pins.trustedKeyFingerprints }),
    };
  }
  fs.writeFileSync(path.join(outDir, 'pins.json'), JSON.stringify(pins, null, 2) + '\n');
  fs.writeFileSync(path.join(outDir, 'be-verdicts.json'), JSON.stringify(verdicts, null, 2) + '\n');
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
