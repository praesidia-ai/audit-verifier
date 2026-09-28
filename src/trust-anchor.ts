/**
 * AV-0017 — the published platform trust-anchor document: be's
 * `GET /.well-known/praesidia-audit-keys.json` (BE-1800), read from a LOCAL
 * file (the verifier never fetches). Every key is self-checked here: a PEM, JWK
 * and fingerprint that disagree, an unknown algorithm, or a private member is a
 * thrown error, never a skipped key.
 */
import * as crypto from 'node:crypto';

export const PLATFORM_TRUST_ANCHOR_PURPOSE = 'audit-bundle-platform-attestation';
const MAX_ANCHOR_KEYS = 64;

export interface PlatformTrustAnchorKey {
  /** Lowercase sha256 hex of the SPKI DER — recomputed, equal to the document's `fingerprint`. */
  fingerprint: string;
  /** Base64 SPKI DER of the EC P-256 key. */
  spkiDerB64: string;
  status: 'active' | 'retired';
  /** Validity window for the attestation's `issuedAt`; `null` = unbounded. */
  notBefore: string | null;
  notAfter: string | null;
}

export interface PlatformTrustAnchor {
  keys: PlatformTrustAnchorKey[];
}

/** Parse and self-check a trust-anchor document. Throws on anything malformed. */
export function parsePlatformTrustAnchor(json: string): PlatformTrustAnchor {
  const fail = (msg: string): never => {
    throw new Error(`trust anchor: ${msg}`);
  };
  let doc: { purpose?: unknown; keys?: unknown } | null;
  try {
    doc = JSON.parse(json) as { purpose?: unknown; keys?: unknown } | null;
  } catch {
    return fail('not valid JSON');
  }
  if (!doc || typeof doc !== 'object' || doc.purpose !== PLATFORM_TRUST_ANCHOR_PURPOSE) {
    return fail(`purpose must be "${PLATFORM_TRUST_ANCHOR_PURPOSE}"`);
  }
  const rawKeys = doc.keys;
  if (!Array.isArray(rawKeys) || rawKeys.length === 0 || rawKeys.length > MAX_ANCHOR_KEYS) {
    return fail(`keys must be a non-empty array of at most ${MAX_ANCHOR_KEYS}`);
  }
  const keys = rawKeys.map((raw: unknown, i): PlatformTrustAnchorKey => {
    const at = `keys[${i}]`;
    const k = (raw && typeof raw === 'object' ? raw : fail(`${at} is not an object`)) as Record<string, unknown>;
    if (k.signatureAlgorithm !== 'ECDSA_P256_SHA256' || k.fingerprintAlgorithm !== 'sha256-spki-der') {
      fail(`${at}: unsupported signatureAlgorithm/fingerprintAlgorithm`);
    }
    const pem = typeof k.publicKeyPem === 'string' && !k.publicKeyPem.includes('PRIVATE')
      ? k.publicKeyPem
      : fail(`${at}.publicKeyPem must be a public SPKI PEM`);
    const spki = (key: crypto.KeyObject): Buffer =>
      key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
        ? key.export({ type: 'spki', format: 'der' })
        : fail(`${at} is not an EC P-256 key`);
    const parse = (what: string, input: string | crypto.JsonWebKeyInput): Buffer => {
      let key: crypto.KeyObject;
      try {
        key = crypto.createPublicKey(input);
      } catch {
        return fail(`${at}.${what} does not parse`);
      }
      return spki(key);
    };
    const der = parse('publicKeyPem', pem);
    const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
    if (k.fingerprint !== fingerprint || (k.kid !== undefined && k.kid !== fingerprint)) {
      fail(`${at}.fingerprint does not match its public key (computed ${fingerprint})`);
    }
    if (k.jwk !== undefined) {
      const jwk = k.jwk as crypto.JsonWebKey | null;
      if (!jwk || typeof jwk !== 'object' || 'd' in jwk) fail(`${at}.jwk must be a public JWK`);
      if (!parse('jwk', { key: jwk!, format: 'jwk' }).equals(der)) fail(`${at}.jwk and publicKeyPem are different keys`);
    }
    if (k.status !== 'active' && k.status !== 'retired') fail(`${at}.status must be active or retired`);
    const when = (name: 'notBefore' | 'notAfter'): string | null =>
      k[name] === null || k[name] === undefined
        ? null
        : typeof k[name] === 'string' && !Number.isNaN(Date.parse(k[name] as string))
          ? (k[name] as string)
          : fail(`${at}.${name} must be null or an ISO timestamp`);
    return {
      fingerprint,
      spkiDerB64: der.toString('base64'),
      status: k.status as 'active' | 'retired',
      notBefore: when('notBefore'),
      notAfter: when('notAfter'),
    };
  });
  if (new Set(keys.map((k) => k.fingerprint)).size !== keys.length) fail('duplicate key fingerprint');
  return { keys };
}
