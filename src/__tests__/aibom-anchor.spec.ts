/**
 * AV-0005 — offline check of be BE-1255's `anchorProof` (procedure A2-A10).
 * Every file under `test-fixtures/aibom/anchored/` is REAL be output from
 * `scripts/make-aibom-anchor-fixtures.cts` (be `AibomService.exportSnapshot`
 * over a real `AuditProofService` and `AnchorStatusService`), and
 * `be-verdicts.json` is be's own `verifyAibomAttestation` over the same bytes.
 * The tamper table ports `be/src/aibom/aibom-anchor-proof.spec.ts` with be's
 * reasons verbatim. Only attacker-side edits are built here.
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyAibomAttestation, type AibomVerifyOptions } from '../aibom.js';
import { canonicalJson } from '../crypto.js';

type Json = Record<string, any>;
const dir = path.resolve(process.cwd(), 'test-fixtures/aibom/anchored');
const read = (name: string): Json => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
const load = (name: string) => fs.readFileSync(path.join(dir, `${name}.attested.json`));
const pins = read('pins.json') as { trustedKeyFingerprints: string[]; rekorPublicKeysPem: string[] };
const tenantOnly = { trustedKeyFingerprints: pins.trustedKeyFingerprints };
const beVerdicts = read('be-verdicts.json') as Record<string, { pinned: Json; sigstoreOnly: Json }>;
/** The fixture log's SET-signed `integratedTime`; the receipts' unsigned `anchoredAt` is 10:05:00. */
const LOG_TIME = '2026-09-01T10:04:58.000Z';

/** be's verdict shape: this report minus its `detail` and `keyFingerprint`. */
const verdict = (bytes: Uint8Array, options: AibomVerifyOptions = pins): Json =>
  Object.fromEntries(
    Object.entries(verifyAibomAttestation(bytes, options)).filter(([k]) => k !== 'detail' && k !== 'keyFingerprint'),
  );
const edited = (name: string, edit: (env: Json) => void): Buffer => {
  const env = JSON.parse(load(name).toString('utf8')) as Json;
  edit(env);
  return canonicalJson(env);
};
const unverified = (anchorReason: string) => ({ valid: true, reason: 'verified', chainOk: true, anchorStatus: 'unverified', anchorReason });
const verifiedRekor = { valid: true, reason: 'verified', chainOk: true, anchorStatus: 'verified_rekor', anchoredAt: LOG_TIME };

describe('AV-0005 aibom anchor — be-produced fixtures get be’s own verdict', () => {
  it.each([
    ['anchored-rekor', verifiedRekor],
    ['anchored-commitment', verifiedRekor],
    ['anchor-pending', unverified('anchoring_pending')],
    ['anchor-not-yet-rooted', unverified('not_yet_rooted')],
    ['anchor-redacted', unverified('anchor_status_unavailable')],
  ] as const)('%s', (name, expected) => {
    expect(beVerdicts[name]!.pinned).toEqual(expected);
    expect(verdict(load(name))).toEqual(expected);
    // Only a pinned Rekor log key is trusted: the bundled Sigstore key did not sign the fixture log.
    expect(verdict(load(name), tenantOnly)).toEqual(beVerdicts[name]!.sigstoreOnly);
  });

  it('trusts no log under an empty Rekor pin list, and never the envelope’s own material', () => {
    expect(beVerdicts['anchored-rekor']!.sigstoreOnly).toEqual(unverified('unknown_log_id'));
    expect(verdict(load('anchored-rekor'), { ...tenantOnly, rekorPublicKeysPem: [] })).toEqual(unverified('unknown_log_id'));
  });

  // The receipt's `anchoredAt` is be's persistence stamp, signed by nothing:
  // editing it AND the label together is undetectable, so the verdict reports
  // the SET-signed `integratedTime`, which no edit can move.
  it.each(['2026-08-01T00:00:00.000Z', '2026-12-31T00:00:00.000Z'])(
    'a matching edit of the anchoredAt label and receipt (%s) cannot move the verified anchor time',
    (forged) => {
      const bytes = edited('anchored-rekor', (e) => {
        e.anchoredAt = forged;
        e.anchorProof.receipts[0].anchoredAt = forged;
      });
      expect(verdict(bytes)).toEqual(verifiedRekor);
    },
  );
});

const foreignKey = () =>
  crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');
const flipB64 = (b64: string): string => {
  const bytes = Buffer.from(b64, 'base64');
  bytes[0] = bytes[0]! ^ 0xff;
  return bytes.toString('base64');
};
const editReceipt = (e: Json, edit: (r: Json) => void) => {
  const r = JSON.parse(e.anchorProof.receipts[0].receipt) as Json;
  edit(r);
  e.anchorProof.receipts[0].receipt = JSON.stringify(r);
};

describe('AV-0005 aibom anchor — editing any anchor field yields unverified with be’s reason', () => {
  const FILLER_ID = '0b8f5c1e-3d2a-4f6b-9c7d-000000000000';
  it.each<[string, (e: Json) => void, string]>([
    // anchor labels (A3, A10)
    ['anchorStatus label', (e) => (e.anchorStatus = 'verified_s3'), 'anchor_label_mismatch'],
    ['anchoredAt label', (e) => (e.anchoredAt = '2026-09-02T00:00:00.000Z'), 'anchor_label_mismatch'],
    ['anchorReason label', (e) => (e.anchorReason = 'anything'), 'anchor_label_mismatch'],
    ['anchorReference label', (e) => (e.anchorReference = `audit:${FILLER_ID}`), 'anchor_label_mismatch'],
    // the signed anchor-request row (A4, A5)
    ['row details.digest', (e) => (e.anchorProof.inclusionProof.row.details.digest = 'f'.repeat(64)), 'anchor_row_unbound'],
    ['row details.aiSystemId', (e) => (e.anchorProof.inclusionProof.row.details.aiSystemId = 'system-2'), 'anchor_row_unbound'],
    ['row action', (e) => (e.anchorProof.inclusionProof.row.action = 'agent.create'), 'anchor_row_unbound'],
    ['row createdAt', (e) => (e.anchorProof.inclusionProof.row.createdAt = '2026-09-01T10:00:00.000Z'), 'anchor_row_signature_invalid'],
    ['rowSignature', (e) => (e.anchorProof.inclusionProof.rowSignature = flipB64(e.anchorProof.inclusionProof.rowSignature)), 'anchor_row_signature_invalid'],
    ['rowPrevHash', (e) => (e.anchorProof.inclusionProof.rowPrevHash = flipB64(e.anchorProof.inclusionProof.rowPrevHash)), 'anchor_row_signature_invalid'],
    ['rowPublicKey (unpinned)', (e) => (e.anchorProof.inclusionProof.rowPublicKey = foreignKey()), 'anchor_untrusted_key'],
    // the Merkle inclusion proof and the signed root (A6, A7)
    ['merkle sibling', (e) => (e.anchorProof.inclusionProof.merkleProof.siblings[0] = flipB64(e.anchorProof.inclusionProof.merkleProof.siblings[0])), 'anchor_inclusion_invalid'],
    ['merkle index', (e) => (e.anchorProof.inclusionProof.merkleProof.index = 0), 'anchor_inclusion_invalid'],
    ['leafHash', (e) => (e.anchorProof.inclusionProof.leafHash = flipB64(e.anchorProof.inclusionProof.leafHash)), 'anchor_inclusion_invalid'],
    ['rootHash', (e) => (e.anchorProof.inclusionProof.rootHash = flipB64(e.anchorProof.inclusionProof.rootHash)), 'anchor_inclusion_invalid'],
    ['rowCount', (e) => (e.anchorProof.inclusionProof.rowCount = 3), 'anchor_root_signature_invalid'],
    ['periodEnd', (e) => (e.anchorProof.inclusionProof.periodEnd = '2026-09-01T11:00:00.000Z'), 'anchor_root_signature_invalid'],
    ['rootSignature', (e) => (e.anchorProof.inclusionProof.rootSignature = flipB64(e.anchorProof.inclusionProof.rootSignature)), 'anchor_root_signature_invalid'],
    ['rootPublicKey (unpinned)', (e) => (e.anchorProof.inclusionProof.rootPublicKey = foreignKey()), 'anchor_untrusted_key'],
    ['deprecated publicKey alias', (e) => (e.anchorProof.inclusionProof.publicKey = e.anchorProof.inclusionProof.rowPublicKey.slice(0, -4) + 'AAA='), 'anchor_proof_malformed'],
    // the covering root's Rekor receipt (A8-A10)
    ['receipt SET', (e) => editReceipt(e, (r) => (r.signedEntryTimestamp = flipB64(r.signedEntryTimestamp))), 'set_signature_invalid'],
    ['receipt anchoredAt', (e) => (e.anchorProof.receipts[0].anchoredAt = '2026-09-02T00:00:00.000Z'), 'anchor_label_mismatch'],
    ['receipt provider', (e) => (e.anchorProof.receipts[0].provider = 's3'), 's3_anchor_not_offline_verifiable'],
    ['receipt removed', (e) => (e.anchorProof.receipts = []), 'anchoring_pending'],
    ['receipt as a legacy rekor:<index> string', (e) => (e.anchorProof.receipts[0].receipt = 'rekor:9001'), 'legacy_receipt_unverified'],
    // structural garbage never throws
    ['inclusionProof dropped', (e) => (e.anchorProof.inclusionProof = null), 'anchor_proof_malformed'],
    ['proof status', (e) => (e.anchorProof.status = 'verified'), 'anchor_proof_malformed'],
  ])('%s', (_field, edit, reason) => {
    expect(verdict(load('anchored-rekor'))).toEqual(verifiedRekor);
    expect(verdict(edited('anchored-rekor', edit))).toEqual(unverified(reason));
  });

  it('a genuine receipt of another root cannot be reattached (both logs pinned)', () => {
    const other = JSON.parse(load('anchored-commitment').toString('utf8')) as Json;
    const bytes = edited('anchored-rekor', (e) => (e.anchorProof.receipts = other.anchorProof.receipts));
    expect(verdict(bytes)).toEqual(unverified('body_root_mismatch'));
  });

  it.each<[string, (e: Json) => void]>([
    ['opened digest', (e) => (e.anchorProof.detailsOpening.details.digest = 'f'.repeat(64))],
    ['salt', (e) => (e.anchorProof.detailsOpening.salt = Buffer.alloc(16, 8).toString('base64'))],
    ['opening dropped', (e) => delete e.anchorProof.detailsOpening],
  ])('commitment row: editing the %s yields anchor_row_unbound', (_field, edit) => {
    const env = JSON.parse(load('anchored-commitment').toString('utf8')) as Json;
    expect(env.anchorProof.inclusionProof.row).not.toHaveProperty('details');
    expect(verdict(edited('anchored-commitment', edit))).toEqual(unverified('anchor_row_unbound'));
  });

  it.each(['not_yet_rooted', 'anchor_status_unavailable'])('an unavailable proof reports its reason (%s); any other is malformed', (reason) => {
    const bytes = edited('anchor-not-yet-rooted', (e) => (e.anchorProof.reason = reason));
    expect(verdict(bytes)).toEqual(unverified(reason));
    expect(verdict(edited('anchor-not-yet-rooted', (e) => (e.anchorProof.reason = 'verified_rekor')))).toEqual(unverified('anchor_proof_malformed'));
  });
});

describe('AV-2778 aibom anchor — a Rekor reason that is not be’s', () => {
  it('a receipt whose inclusionProof.rootHash was replaced is checkpoint_root_mismatch (be: inclusion_root_mismatch)', () => {
    // be checks the log's inclusion proof before its checkpoint; this package checks the checkpoint first.
    const bytes = edited('anchored-rekor', (e) => editReceipt(e, (r) => (r.inclusionProof.rootHash = 'f'.repeat(64))));
    expect(verdict(bytes)).toEqual(unverified('checkpoint_root_mismatch'));
  });
});

describe('AV-0005 aibom anchor — older envelopes and invalid bundles', () => {
  it('an envelope without anchorProof (pre-BE-1255 export, BE-0738 labels only) verifies exactly as before', () => {
    const bytes = edited('anchored-rekor', (e) => delete e.anchorProof);
    expect(verdict(bytes)).toEqual(unverified('aibom_not_anchored'));
    expect(verdict(bytes, tenantOnly)).toEqual(unverified('aibom_not_anchored'));
  });

  it('an invalid bundle never reports an anchor, whatever the proof says', () => {
    const bytes = edited('anchored-rekor', (e) => (e.document.components = [{ injected: true }]));
    expect(verdict(bytes)).toEqual({
      valid: false, reason: 'digest_mismatch', chainOk: false, anchorStatus: 'unverified', anchorReason: 'aibom_not_anchored',
    });
  });

  it('a pinned tenant key is required before any anchor is considered', () => {
    expect(verdict(load('anchored-rekor'), { ...pins, trustedKeyFingerprints: [] })).toMatchObject({
      valid: false, reason: 'untrusted_key', anchorStatus: 'unverified', anchorReason: 'aibom_not_anchored',
    });
  });
});
