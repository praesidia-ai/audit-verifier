/**
 * AV-0001 — regenerate `test-fixtures/aibom/*.attested.json` from be's REAL
 * AIBOM export path (`AibomService.generate` → `AuditProofService.
 * signDetachedDigest` → `AibomService.exportSnapshot(…, 'attested')`), so
 * the verifier is tested against producer bytes, never hand-built ones.
 * Dev-only: not compiled, not published. Needs a sibling `be` checkout:
 *
 *   cd <core>/be && NODE_PATH=$PWD/node_modules npx ts-node --transpile-only --project tsconfig.json \
 *     <audit-verifier>/scripts/make-aibom-fixtures.cts <core>/be <out-dir>
 *
 * No server, no DB, no network. Repositories are in-memory; keys are
 * throwaway and die with the process. Ed25519 signs via be's
 * CryptoUtilsService; P-256 mimics the aws-kms substrate exactly (DER
 * ECDSA-SHA256 + be's `enforceLowSP256`, SPKI-DER public key).
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

const [beDir, outDir] = process.argv.slice(2);
if (!beDir || !outDir) throw new Error('usage: make-aibom-fixtures.cts <be-dir> <out-dir>');
const be = (p: string) => require(path.resolve(beDir, 'src', p));
const { AibomService } = be('aibom/aibom.service');
const { AuditProofService } = be('audit/services/audit-proof.service');
const { CryptoUtilsService, enforceLowSP256 } = be('common/security/services/crypto-utils.service');
const { AIBOM_SIGNING_DOMAIN } = be('aibom/aibom-attestation');

const ORG = '4b0f5a3e-2c1d-4e8f-9a7b-0c1d2e3f4a5b';
const SYSTEM = '7d9e1f20-3a4b-4c5d-8e6f-a1b2c3d4e5f6';
const cu = new CryptoUtilsService();

type Signer = { algorithm: string; publicKey: Buffer; sign(m: Uint8Array): string };
function ed25519(): Signer {
  const kp = cu.generateEd25519KeyPair();
  return { algorithm: 'Ed25519', publicKey: Buffer.from(kp.publicKey), sign: (m) => cu.signEd25519(m, kp.privateKey) };
}
function p256(): Signer {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    algorithm: 'ECDSA_P256_SHA256',
    publicKey: publicKey.export({ type: 'spki', format: 'der' }),
    sign: (m) => enforceLowSP256(crypto.sign('sha256', Buffer.from(m), privateKey)).toString('base64'),
  };
}

function harness(signer: Signer) {
  const stored: Record<string, unknown>[] = [];
  const state = { failSigning: false, revoked: false };
  const keys = {
    async signWithActiveKey(orgId: string, message: Uint8Array) {
      if (orgId !== ORG || state.failSigning) throw new Error('KMS circuit open');
      return { signature: signer.sign(message), publicKey: signer.publicKey, keyVersion: 1, message, algorithm: signer.algorithm };
    },
    async findByOrgAndVersion(orgId: string, v: number) {
      return orgId === ORG && v === 1 && !state.revoked ? { publicKey: signer.publicKey.toString('base64') } : null;
    },
  };
  const rows = (r: unknown[]) => ({ find: async () => r });
  const snapshots = {
    count: async () => stored.length,
    save: async (row: Record<string, unknown>) => (stored.push({ id: `a1b2c3d4-0000-4000-8000-00000000000${stored.length + 1}`, ...row }), stored.at(-1)),
    findOne: async ({ where }: { where: Record<string, unknown> }) =>
      stored.find((s) => s.id === where.id && s.organizationId === where.organizationId) ?? null,
  };
  const proof = new AuditProofService(null, null, null, keys, cu);
  const service = new AibomService(
    rows([{ id: 'm-1', organizationId: ORG, aiSystemId: SYSTEM, assetId: 'asset-agent', role: 'primary', deletedAt: null },
          { id: 'm-2', organizationId: ORG, aiSystemId: SYSTEM, assetId: 'asset-model', role: 'dependency', deletedAt: null }]),
    rows([{ id: 'asset-agent', organizationId: ORG, name: 'Claims triage agent', assetType: 'AGENT', entityType: 'agent', entityId: 'agent-42', source: 'manual', metadata: {} },
          { id: 'asset-model', organizationId: ORG, name: 'Modèle de résumé — v2 ✓', assetType: 'MODEL', entityType: null, entityId: null, source: 'discovered', metadata: {} }]),
    rows([{ organizationId: ORG, sourceAssetId: 'asset-agent', targetAssetId: 'asset-model', relationshipType: 'USES' }]),
    snapshots,
    rows([{ id: 'policy-1', organizationId: ORG, agentId: 'agent-42', mode: 'deny', toolPattern: 'payments.*' }]),
    { findOne: async () => ({ id: SYSTEM, organizationId: ORG }),
      getAiActRole: async () => ({ override: null, orgDefault: 'deployer', effective: 'deployer' }) },
    proof,
  );
  const exportLatest = async () =>
    (await service.exportSnapshot(ORG, SYSTEM, stored.at(-1)!.id, 'attested')).bytes as Buffer;
  return { service, proof, stored, state, exportLatest };
}

async function main(): Promise<void> {
  fs.mkdirSync(outDir, { recursive: true });
  const out: Record<string, Buffer> = {};
  const ed = ed25519();
  const ec = p256();

  let h = harness(ed);
  await h.service.generate(ORG, SYSTEM);
  out['verified-ed25519'] = await h.exportLatest();
  h.state.revoked = true; // be omits the public key of a REVOKED version
  out['key-unavailable'] = await h.exportLatest();

  h = harness(ed); // a genuine signature by the right key, over a different digest
  await h.service.generate(ORG, SYSTEM);
  h.stored[0]!.signature = (await h.proof.signDetachedDigest(ORG, AIBOM_SIGNING_DOMAIN, 'f'.repeat(64))).signature;
  out['signature-invalid'] = await h.exportLatest();

  h = harness(ed); // stored document altered after signing (DB-level tamper)
  await h.service.generate(ORG, SYSTEM);
  (h.stored[0]!.document as { components: { name: string }[] }).components[0]!.name += '!';
  out['digest-mismatch'] = await h.exportLatest();

  h = harness(ed); // signing substrate down → be persists the snapshot unsigned
  h.state.failSigning = true;
  await h.service.generate(ORG, SYSTEM);
  out['unsigned'] = await h.exportLatest();

  h = harness(ec);
  await h.service.generate(ORG, SYSTEM);
  out['verified-ecdsa-p256'] = await h.exportLatest();

  for (const [name, bytes] of Object.entries(out)) fs.writeFileSync(path.join(outDir, `${name}.attested.json`), bytes);
  // Pins come from the signer's OWN key material, never from an envelope.
  const fp = (s: Signer) => crypto.createHash('sha256').update(s.publicKey).digest('hex');
  fs.writeFileSync(path.join(outDir, 'trusted-keys.json'),
    JSON.stringify({ ed25519: fp(ed), ecdsaP256: fp(ec) }, null, 2) + '\n');
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
