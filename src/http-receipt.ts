import { createHash, createPublicKey, verify } from 'node:crypto';
import { jcsCanonicalize, jcsCommitment, type JsonValue } from './jcs-canonical.js';

export const HTTP_RECEIPT_VERSION = 'praesidia.http-receipt.v1' as const;
export type HttpEffect = 'succeeded' | 'failed_no_effect' | 'partial' | 'unknown';
export interface HttpReceiptStatement {
  version: typeof HTTP_RECEIPT_VERSION;
  actionId: string;
  organizationId: string;
  targetId: string;
  keyId: string;
  requestCommitment: string;
  resultCommitment: string;
  effect: HttpEffect;
  issuedAt: string;
  targetTransactionId: string;
}
export interface SignedHttpReceipt { statement: HttpReceiptStatement; signature: string }
export interface HttpRequestEnvelope {
  version: 'praesidia.http-request.v1';
  targetId: string;
  destination: string;
  targetKeyFingerprint: string;
  method: 'POST';
  contentType: 'application/json';
  body: JsonValue;
}
export type HttpReceiptExpected = Pick<HttpReceiptStatement,
  'actionId' | 'organizationId' | 'targetId' | 'keyId' | 'requestCommitment' | 'resultCommitment'>;

/** Pin is supplied by the operator/verifier, never taken from receipt contents. */
export function httpTargetKeyFingerprint(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Target key must be Ed25519');
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}
export function httpRequestCommitment(request: HttpRequestEnvelope): string {
  return jcsCommitment(request as unknown as JsonValue);
}
/** Validates exact protocol shape and bindings before cryptographic verification. */
export function verifyHttpReceipt(receipt: unknown, publicKeyPem: string, expected: HttpReceiptExpected): receipt is SignedHttpReceipt {
  try {
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return false;
    const r = receipt as Record<string, unknown>;
    if (Object.keys(r).sort().join(',') !== 'signature,statement' || typeof r.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(r.signature)) return false;
    if (!r.statement || typeof r.statement !== 'object' || Array.isArray(r.statement)) return false;
    const s = r.statement as Record<string, unknown>;
    if (Object.keys(s).sort().join(',') !== 'actionId,effect,issuedAt,keyId,organizationId,requestCommitment,resultCommitment,targetId,targetTransactionId,version') return false;
    if (s.version !== HTTP_RECEIPT_VERSION || !['succeeded','failed_no_effect','partial','unknown'].includes(String(s.effect))) return false;
    if (typeof s.issuedAt !== 'string' || !Number.isFinite(Date.parse(s.issuedAt)) || new Date(s.issuedAt).toISOString() !== s.issuedAt) return false;
    if (typeof s.targetTransactionId !== 'string' || !s.targetTransactionId.trim() || s.targetTransactionId.length > 256) return false;
    for (const [key, value] of Object.entries(expected)) if (s[key] !== value) return false;
    if (!/^[a-f0-9]{64}$/.test(String(s.requestCommitment)) || !/^[a-f0-9]{64}$/.test(String(s.resultCommitment))) return false;
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') return false;
    return verify(null, jcsCanonicalize(s as JsonValue), key, Buffer.from(r.signature, 'base64'));
  } catch { return false; }
}
