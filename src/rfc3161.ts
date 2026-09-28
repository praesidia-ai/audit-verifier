/**
 * AV-0019 — offline verification of an RFC 3161 time-stamp token on a Merkle root.
 *
 * be (BE-1960, `FEATURE_RFC3161_ANCHOR`, off by default) appends
 * `{provider:'rfc3161', receipt:<base64 DER TimeStampToken>, anchoredAt}` to a
 * root's `anchorReceipts`. This module checks that token with no network and no
 * dependency beyond `node:crypto`:
 *
 *   1. strict-DER parse of ContentInfo → SignedData → TSTInfo (trailing bytes,
 *      indefinite lengths, non-minimal lengths and unknown critical TSTInfo
 *      extensions all fail);
 *   2. `messageImprint` is SHA-256 and equals the root's 32-byte `rootHash`
 *      (the Merkle root already IS a SHA-256 output, so it is the imprint);
 *   3. exactly one SignerInfo; signed attributes carry contentType = TSTInfo,
 *      messageDigest = digest(TSTInfo) and an ESS signing-certificate (v1 or v2)
 *      whose hash names the signer certificate, which must also match the sid;
 *   4. the signer certificate carries a CRITICAL extendedKeyUsage whose only
 *      purpose is id-kp-timeStamping (RFC 3161 §2.3);
 *   5. the CMS signature verifies under that certificate, and the certificate
 *      chains (via CA certificates carried in the token) to a trust anchor —
 *      pinned at build time for a contracted QTSP, or supplied by the auditor
 *      (`--tsa-cert`). Anchors are NEVER fetched. Every certificate on the path
 *      must be valid at `genTime`;
 *   6. `genTime` falls inside the root's own signedAt/anchoredAt window (same
 *      bound and skew as Rekor's `integratedTime`, see `rekor.ts`).
 *
 * "qualified" is stated only when the chain ends in a PINNED QTSP anchor; an
 * auditor-supplied anchor yields a plain "RFC 3161 timestamp". Revocation
 * (CRL/OCSP) and ETSI EN 319 102-1 long-term validation are out of scope:
 * both need data the offline bundle does not carry.
 */

import * as crypto from 'node:crypto';
import { decodeBase64Strict } from './crypto.js';
import { REKOR_INTEGRATED_TIME_SKEW_MS } from './rekor.js';

/**
 * Build-time pins for contracted QTSPs (DECISION-PRAE-193). Empty until a QTSP
 * is contracted: adding one is a release of this package, never a runtime fetch.
 */
export const PINNED_QTSP_TRUST_ANCHORS: ReadonlyArray<{ name: string; pem: string }> = [];

const MAX_TOKEN_BYTES = 64 * 1024;
const MAX_CHAIN_DEPTH = 8;

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  extKeyUsage: '2.5.29.37',
  subjectKeyId: '2.5.29.14',
  timeStamping: '1.3.6.1.5.5.7.3.8',
} as const;

const DIGESTS: Record<string, string> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

/** Signature algorithm OID → required key type and (for combined OIDs) digest. */
const SIG_ALGS: Record<string, { keyType: string; digest?: string }> = {
  '1.2.840.113549.1.1.1': { keyType: 'rsa' },
  '1.2.840.113549.1.1.11': { keyType: 'rsa', digest: 'sha256' },
  '1.2.840.113549.1.1.12': { keyType: 'rsa', digest: 'sha384' },
  '1.2.840.113549.1.1.13': { keyType: 'rsa', digest: 'sha512' },
  '1.2.840.10045.2.1': { keyType: 'ec' },
  '1.2.840.10045.4.3.2': { keyType: 'ec', digest: 'sha256' },
  '1.2.840.10045.4.3.3': { keyType: 'ec', digest: 'sha384' },
  '1.2.840.10045.4.3.4': { keyType: 'ec', digest: 'sha512' },
  '1.3.101.112': { keyType: 'ed25519' },
};

export type Rfc3161Verdict =
  | {
      status: 'verified';
      genTime: string;
      tsaSubject: string;
      policy: string;
      /** true only when the chain ends in a {@link PINNED_QTSP_TRUST_ANCHORS} entry. */
      qualified: boolean;
      /** "qualified timestamp (<QTSP>)" or "RFC 3161 timestamp". */
      label: string;
    }
  | { status: 'failed'; reason: string; genTime?: string; tsaSubject?: string };

/** Per-root row in `VerifyReport.rfc3161`. */
export type Rfc3161RootReport = { rootId: string } & (Rfc3161Verdict | { status: 'absent' });

export interface Rfc3161Expected {
  /** The bundle root's base64 32-byte `rootHash`. */
  rootHashB64: string;
  signedAt?: string;
  anchoredAt?: string | null;
}

class DerError extends Error {}

interface Tlv {
  tag: number;
  /** whole TLV */
  raw: Buffer;
  /** value bytes */
  value: Buffer;
}

function readTlv(buf: Buffer, off: number): Tlv {
  if (off + 2 > buf.length) throw new DerError('truncated');
  const tag = buf[off]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError('high tag number');
  let len = buf[off + 1]!;
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new DerError('indefinite or oversized length');
    if (off + 2 + n > buf.length) throw new DerError('truncated length');
    len = 0;
    for (let i = 0; i < n; i += 1) len = len * 256 + buf[off + 2 + i]!;
    if (len < 0x80 || buf[off + 2]! === 0) throw new DerError('non-minimal length');
    hdr += n;
  }
  const end = off + hdr + len;
  if (end > buf.length) throw new DerError('truncated value');
  return { tag, raw: buf.subarray(off, end), value: buf.subarray(off + hdr, end) };
}

/** Parse `buf` as exactly one TLV with the expected tag. */
function one(buf: Buffer, tag: number, what: string): Tlv {
  const t = readTlv(buf, 0);
  if (t.tag !== tag) throw new DerError(`${what}: expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}`);
  if (t.raw.length !== buf.length) throw new DerError(`${what}: trailing bytes`);
  return t;
}

function kids(t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let off = 0; off < t.value.length; ) {
    const c = readTlv(t.value, off);
    out.push(c);
    off += c.raw.length;
  }
  return out;
}

function need(t: Tlv | undefined, tag: number, what: string): Tlv {
  if (!t || t.tag !== tag) throw new DerError(`${what} missing or wrong type`);
  return t;
}

function oid(t: Tlv): string {
  if (t.tag !== 0x06 || t.value.length === 0) throw new DerError('bad OID');
  const parts: number[] = [];
  let v = 0;
  for (const b of t.value) {
    v = v * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  if (t.value[t.value.length - 1]! & 0x80) throw new DerError('bad OID');
  const first = parts.shift()!;
  const a = first < 80 ? Math.floor(first / 40) : 2;
  return [a, first - a * 40, ...parts].join('.');
}

function algOid(t: Tlv | undefined, what: string): string {
  return oid(need(kids(need(t, 0x30, what))[0], 0x06, what));
}

function genTimeIso(t: Tlv): string {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d*[1-9])?Z$/.exec(need(t, 0x18, 'genTime').value.toString('latin1'));
  if (!m) throw new DerError('genTime is not DER GeneralizedTime');
  const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ''}Z`;
  if (Number.isNaN(Date.parse(iso))) throw new DerError('genTime out of range');
  return iso;
}

interface ParsedCert {
  x509: crypto.X509Certificate;
  der: Buffer;
  issuer: Buffer;
  serial: Buffer;
  ski?: Buffer;
  eku?: { critical: boolean; purposes: string[] };
}

function parseCert(der: Buffer): ParsedCert {
  const tbs = kids(need(kids(one(der, 0x30, 'certificate'))[0], 0x30, 'tbsCertificate'));
  const i = tbs[0]?.tag === 0xa0 ? 1 : 0;
  const cert: ParsedCert = {
    x509: new crypto.X509Certificate(der),
    der,
    serial: need(tbs[i], 0x02, 'serial').value,
    issuer: need(tbs[i + 2], 0x30, 'issuer').raw,
  };
  const exts = tbs.find((t) => t.tag === 0xa3);
  for (const ext of exts ? kids(one(exts.value, 0x30, 'extensions')) : []) {
    // parse each Extension: extnID, optional critical BOOLEAN, extnValue OCTET STRING
    const parts = kids(need(ext, 0x30, 'Extension'));
    const hasCrit = parts[1]?.tag === 0x01;
    const critical = hasCrit && parts[1]!.value[0] === 0xff;
    const extnValue = need(parts[hasCrit ? 2 : 1], 0x04, 'extnValue').value;
    const extId = oid(need(parts[0], 0x06, 'extnID'));
    if (extId === OID.subjectKeyId) cert.ski = one(extnValue, 0x04, 'subjectKeyIdentifier').value;
    if (extId === OID.extKeyUsage) cert.eku = { critical, purposes: kids(one(extnValue, 0x30, 'extKeyUsage')).map(oid) };
  }
  return cert;
}

function pemCerts(pem: string): Buffer[] {
  const blocks = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)];
  if (blocks.length === 0) throw new DerError('no PEM certificate');
  return blocks.map((b) => {
    const der = decodeBase64Strict(b[1]!.replace(/\s+/g, ''));
    if (!der) throw new DerError('PEM certificate is not canonical base64');
    return der;
  });
}

function validAt(c: ParsedCert, ms: number): boolean {
  return Date.parse(c.x509.validFrom) <= ms && ms <= Date.parse(c.x509.validTo);
}

function issues(child: ParsedCert, parent: ParsedCert): boolean {
  return parent.x509.ca && child.x509.checkIssued(parent.x509) && child.x509.verify(parent.x509.publicKey);
}

function fail(reason: string, extra: { genTime?: string; tsaSubject?: string } = {}): Rfc3161Verdict {
  return { status: 'failed', reason, ...extra };
}

/**
 * Verify one base64 DER `TimeStampToken` against the root it claims to stamp.
 * Never throws; every problem is a `failed` verdict (fail closed).
 * `pinned` is the build-time QTSP set; it is a parameter only so the spec can
 * exercise the "qualified" branch — `verify.ts` always passes the default.
 */
export function verifyRfc3161Receipt(
  receiptB64: string,
  expected: Rfc3161Expected,
  tsaTrustAnchorsPem: readonly string[] = [],
  pinned: ReadonlyArray<{ name: string; pem: string }> = PINNED_QTSP_TRUST_ANCHORS,
): Rfc3161Verdict {
  const der = decodeBase64Strict(receiptB64);
  if (!der) return fail('malformed_token: receipt is not canonical base64');
  if (der.length > MAX_TOKEN_BYTES) return fail('malformed_token: token exceeds 64 KiB');
  const rootHash = decodeBase64Strict(expected.rootHashB64, 32);
  if (!rootHash) return fail('root_hash_not_32_byte_base64');

  let anchors: Array<{ cert: ParsedCert; qtsp?: string }>;
  try {
    anchors = [
      ...pinned.flatMap((p) => pemCerts(p.pem).map((d) => ({ cert: parseCert(d), qtsp: p.name }))),
      ...tsaTrustAnchorsPem.flatMap((p) => pemCerts(p).map((d) => ({ cert: parseCert(d) }))),
    ];
  } catch (err) {
    return fail(`invalid_tsa_trust_anchor: ${(err as Error).message}`);
  }

  let genTime: string | undefined;
  let tsaSubject: string | undefined;
  try {
    // ── ContentInfo → SignedData ───────────────────────────────────────
    const [ctype, wrapped] = kids(one(der, 0x30, 'ContentInfo'));
    if (oid(need(ctype, 0x06, 'contentType')) !== OID.signedData) throw new DerError('not CMS SignedData');
    const sd = kids(one(need(wrapped, 0xa0, 'content').value, 0x30, 'SignedData'));
    need(sd[0], 0x02, 'SignedData.version');
    need(sd[1], 0x31, 'digestAlgorithms');
    const encap = kids(need(sd[2], 0x30, 'encapContentInfo'));
    if (oid(need(encap[0], 0x06, 'eContentType')) !== OID.tstInfo) throw new DerError('eContentType is not TSTInfo');
    const eContent = one(need(encap[1], 0xa0, 'eContent').value, 0x04, 'eContent').value;
    let idx = 3;
    const tokenCerts: ParsedCert[] = [];
    if (sd[idx]?.tag === 0xa0) {
      for (const c of kids(sd[idx]!)) tokenCerts.push(parseCert(need(c, 0x30, 'certificate').raw));
      idx += 1;
    }
    if (sd[idx]?.tag === 0xa1) idx += 1;
    const signerInfos = kids(need(sd[idx], 0x31, 'signerInfos'));
    if (idx + 1 !== sd.length) throw new DerError('SignedData has trailing fields');
    if (signerInfos.length !== 1) throw new DerError(`expected exactly one SignerInfo, got ${signerInfos.length}`);

    // ── TSTInfo ────────────────────────────────────────────────────────
    const tst = kids(one(eContent, 0x30, 'TSTInfo'));
    if (need(tst[0], 0x02, 'TSTInfo.version').value.toString('hex') !== '01') throw new DerError('TSTInfo.version is not 1');
    const policy = oid(need(tst[1], 0x06, 'policy'));
    const [imprintAlg, imprintHash] = kids(need(tst[2], 0x30, 'messageImprint'));
    need(tst[3], 0x02, 'serialNumber');
    genTime = genTimeIso(tst[4]!);
    const ext = tst.slice(5).find((t) => t.tag === 0xa1);
    if (ext && kids(ext).some((e) => kids(e)[1]?.tag === 0x01 && kids(e)[1]!.value[0] === 0xff)) {
      return fail('unsupported_critical_tstinfo_extension', { genTime });
    }

    // ── SignerInfo ─────────────────────────────────────────────────────
    const si = kids(need(signerInfos[0], 0x30, 'SignerInfo'));
    const sid = si[1]!;
    const digest = DIGESTS[algOid(si[2], 'digestAlgorithm')];
    const signedAttrs = need(si[3], 0xa0, 'signedAttrs');
    const sigAlg = SIG_ALGS[algOid(si[4], 'signatureAlgorithm')];
    const signature = need(si[5], 0x04, 'signature').value;
    const attrs = new Map<string, Tlv[]>();
    for (const a of kids(signedAttrs)) {
      const [type, values] = kids(need(a, 0x30, 'Attribute'));
      const id = oid(need(type, 0x06, 'attrType'));
      if (attrs.has(id)) throw new DerError(`duplicate signed attribute ${id}`);
      attrs.set(id, kids(need(values, 0x31, 'attrValues')));
    }

    // ── signer certificate: ESS cert id → sid ─────────────────────────
    const essV2 = attrs.get(OID.signingCertificateV2);
    const essV1 = attrs.get(OID.signingCertificate);
    const essCerts = kids(need(kids(need((essV2 ?? essV1)?.[0], 0x30, 'SigningCertificate'))[0], 0x30, 'ESS certs'));
    const essId = kids(need(essCerts[0], 0x30, 'ESSCertID'));
    let essAlg = 'sha1';
    if (essV2) {
      essAlg = 'sha256';
      if (essId[0]?.tag === 0x30) essAlg = DIGESTS[algOid(essId.shift(), 'ESSCertIDv2.hashAlgorithm')] ?? '';
      if (!essAlg || essAlg === 'sha1') return fail('unsupported_ess_cert_hash_algorithm', { genTime });
    }
    const essHash = need(essId[0], 0x04, 'certHash').value;
    const signer = [...tokenCerts, ...anchors.map((a) => a.cert)].find((c) =>
      crypto.createHash(essAlg).update(c.der).digest().equals(essHash),
    );
    if (!signer) return fail('tsa_certificate_not_found: no certificate matches the ESS signing-certificate hash', { genTime });
    tsaSubject = signer.x509.subject;
    const sidOk =
      sid.tag === 0x30
        ? kids(sid)[0]!.raw.equals(signer.issuer) && need(kids(sid)[1], 0x02, 'sid.serial').value.equals(signer.serial)
        : sid.tag === 0x80 && !!signer.ski && sid.value.equals(signer.ski);
    if (!sidOk) return fail('signer_identifier_mismatch', { genTime, tsaSubject });
    if (!signer.eku || !signer.eku.critical || signer.eku.purposes.length !== 1 || signer.eku.purposes[0] !== OID.timeStamping) {
      return fail('tsa_certificate_not_timestamping: extendedKeyUsage must be critical and exactly id-kp-timeStamping', { genTime, tsaSubject });
    }

    // ── signed attributes + CMS signature ─────────────────────────────
    if (!digest || digest === 'sha1') return fail('unsupported_digest_algorithm', { genTime, tsaSubject });
    if (!sigAlg || (sigAlg.digest && sigAlg.digest !== digest)) return fail('unsupported_signature_algorithm', { genTime, tsaSubject });
    const ct = attrs.get(OID.contentType);
    if (ct?.length !== 1 || oid(ct[0]!) !== OID.tstInfo) return fail('content_type_attribute_mismatch', { genTime, tsaSubject });
    const md = attrs.get(OID.messageDigest);
    if (md?.length !== 1 || !need(md[0], 0x04, 'messageDigest').value.equals(crypto.createHash(digest).update(eContent).digest())) {
      return fail('message_digest_mismatch: TSTInfo does not match the signed digest', { genTime, tsaSubject });
    }
    const key = signer.x509.publicKey;
    if (key.asymmetricKeyType !== sigAlg.keyType) return fail('signature_key_type_mismatch', { genTime, tsaSubject });
    const signedBytes = Buffer.from(signedAttrs.raw);
    signedBytes[0] = 0x31; // RFC 5652 §5.4: signed over the EXPLICIT SET OF encoding
    const sigOk = crypto.verify(sigAlg.keyType === 'ed25519' ? null : digest, signedBytes, key, signature);
    if (!sigOk) return fail('cms_signature_invalid', { genTime, tsaSubject });

    // ── imprint binds THIS root ────────────────────────────────────────
    if (DIGESTS[algOid(imprintAlg, 'messageImprint.hashAlgorithm')] !== 'sha256') {
      return fail('unsupported_imprint_algorithm: messageImprint must be SHA-256', { genTime, tsaSubject });
    }
    if (!need(imprintHash, 0x04, 'hashedMessage').value.equals(rootHash)) {
      return fail('message_imprint_mismatch: the token stamps a different root', { genTime, tsaSubject });
    }

    // ── chain to a pinned / supplied anchor at genTime ────────────────
    if (anchors.length === 0) {
      return fail('no_tsa_trust_anchor: supply the TSA root with --tsa-cert <pem> (no QTSP is pinned in this build)', { genTime, tsaSubject });
    }
    const at = Date.parse(genTime);
    let cur = signer;
    let anchor: { cert: ParsedCert; qtsp?: string } | undefined;
    for (let depth = 0; depth <= MAX_CHAIN_DEPTH && !anchor; depth += 1) {
      if (!validAt(cur, at)) return fail(`tsa_certificate_not_valid_at_gentime: ${cur.x509.subject}`, { genTime, tsaSubject });
      const c = cur;
      anchor =
        anchors.find((a) => a.qtsp && a.cert.der.equals(c.der)) ??
        anchors.find((a) => a.cert.der.equals(c.der)) ??
        anchors.find((a) => a.qtsp && issues(c, a.cert) && validAt(a.cert, at)) ??
        anchors.find((a) => issues(c, a.cert) && validAt(a.cert, at));
      if (anchor) break;
      const next = tokenCerts.find((p) => p !== c && issues(c, p));
      if (!next) break;
      cur = next;
    }
    if (!anchor) return fail('tsa_chain_untrusted: the TSA certificate does not chain to a pinned or supplied anchor', { genTime, tsaSubject });

    // ── genTime inside the root's own window ──────────────────────────
    if (expected.signedAt !== undefined) {
      const signedMs = Date.parse(expected.signedAt);
      if (Number.isNaN(signedMs) || at < signedMs - REKOR_INTEGRATED_TIME_SKEW_MS) {
        return fail(`gentime_out_of_window: ${genTime} precedes the root's signedAt ${expected.signedAt} by more than 24h`, { genTime, tsaSubject });
      }
    }
    if (expected.anchoredAt != null) {
      const anchoredMs = Date.parse(expected.anchoredAt);
      if (Number.isNaN(anchoredMs) || at > anchoredMs + REKOR_INTEGRATED_TIME_SKEW_MS) {
        return fail(`gentime_out_of_window: ${genTime} is more than 24h after the recorded anchoredAt ${expected.anchoredAt}`, { genTime, tsaSubject });
      }
    }
    return {
      status: 'verified',
      genTime,
      tsaSubject,
      policy,
      qualified: anchor.qtsp !== undefined,
      label: anchor.qtsp !== undefined ? `qualified timestamp (${anchor.qtsp})` : 'RFC 3161 timestamp',
    };
  } catch (err) {
    return fail(`malformed_token: ${err instanceof Error ? err.message : String(err)}`, {
      ...(genTime ? { genTime } : {}),
      ...(tsaSubject ? { tsaSubject } : {}),
    });
  }
}
