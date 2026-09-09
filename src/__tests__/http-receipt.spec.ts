import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { httpRequestCommitment, verifyHttpReceipt, type HttpRequestEnvelope, type SignedHttpReceipt } from '../http-receipt.js';
import { jcsCommitment, type JsonValue } from '../jcs-canonical.js';
interface Fixture { organizationId: string; envelope: HttpRequestEnvelope;
  target: { publicKeyPem: string; targetId: string; keyId: string };
  response: { actionId: string; requestCommitment: string; resultCommitment: string; result: JsonValue; receipt: SignedHttpReceipt } }
const fixture = JSON.parse(readFileSync(resolve(process.cwd(), 'test-fixtures/http-receipt-v1.json'), 'utf8')) as Fixture;
describe('cross-language HTTP receipt golden contract', () => {
  const expected = { actionId: fixture.response.actionId, organizationId: fixture.organizationId,
    targetId: fixture.target.targetId, keyId: fixture.target.keyId, requestCommitment: fixture.response.requestCommitment,
    resultCommitment: fixture.response.resultCommitment };
  it('matches exact RFC8785 request/result commitments and independently pinned target signature', () => {
    expect(httpRequestCommitment(fixture.envelope)).toBe(expected.requestCommitment);
    expect(jcsCommitment(fixture.response.result)).toBe(expected.resultCommitment);
    expect(verifyHttpReceipt(fixture.response.receipt, fixture.target.publicKeyPem, expected)).toBe(true);
  });
  it.each(['actionId','organizationId','targetId','keyId','requestCommitment','resultCommitment'] as const)('rejects different %s', key => {
    expect(verifyHttpReceipt(fixture.response.receipt, fixture.target.publicKeyPem, { ...expected, [key]: 'substituted' })).toBe(false);
  });
  it('rejects extra unsigned/unknown protocol fields and noncanonical signatures', () => {
    expect(verifyHttpReceipt({ ...fixture.response.receipt, publicKeyPem: fixture.target.publicKeyPem }, fixture.target.publicKeyPem, expected)).toBe(false);
    expect(verifyHttpReceipt({ ...fixture.response.receipt, signature: fixture.response.receipt.signature + '\n' }, fixture.target.publicKeyPem, expected)).toBe(false);
  });
});
