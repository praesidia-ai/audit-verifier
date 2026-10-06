/**
 * AV-2793 — `scripts/contract-drift.mjs` against be's conditionally emitted
 * fields. be HEAD 67dfaea5 emits `signatureFormat` only for a format-2
 * artefact (`...(x.signatureFormat === 2 ? { signatureFormat: 2 as const } : {})`)
 * and adds the v7 manifest fields only in a `{ ...manifestSansSignature, … }`
 * extension. The checker missed both: it reported verifier fields as absent
 * from be, and a be-only field behind a condition went unchecked.
 * The snippets below copy be's shapes.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(root, 'scripts/contract-drift.mjs');

type Drift = {
  extractDepth1Keys: (source: string, openBraceIndex: number) => Set<string>;
  newestManifestFields: (source: string) => Set<string> | null;
};
let drift: Drift;
beforeAll(async () => {
  drift = (await import(pathToFileURL(scriptPath).href)) as Drift;
});

const returnKeys = (source: string) => [...drift.extractDepth1Keys(source, source.indexOf('{'))].sort();

describe('AV-2793 contract-drift: conditional producer fields', () => {
  it('counts a field behind an inline conditional spread as emitted', () => {
    const src = `{
      signatureAlgorithm: event.signatureAlgorithm,
      ...(event.signatureFormat === 2 ? { signatureFormat: 2 as const } : {}),
      keyVersion: event.keyVersion,
    }`;
    expect(returnKeys(src)).toEqual(['keyVersion', 'signatureAlgorithm', 'signatureFormat']);
  });

  it('counts the same spread when it is wrapped over several lines', () => {
    const src = `{
      signatureAlgorithm: checkpoint.signatureAlgorithm,
      ...(checkpoint.signatureFormat === 2
        ? { signatureFormat: 2 as const }
        : {}),
    }`;
    expect(returnKeys(src)).toEqual(['signatureAlgorithm', 'signatureFormat']);
  });

  it('checks every branch, so a be-only field behind a condition is visible', () => {
    const src = `{
      id: row.id,
      ...(ok ? { a: f(x, y), b: { inner: 1 } } : { c, ...(z ? { d: 1 } : {}) }),
    }`;
    expect(returnKeys(src)).toEqual(['a', 'b', 'c', 'd', 'id']);
  });

  it('a spread of a plain value contributes no keys', () => {
    const src = `{
      ...(manifestUnsigned as typeof manifestSansSignature),
      signature: manifestSignature,
    }`;
    expect(returnKeys(src)).toEqual(['signature']);
  });

  it("includes the format-2 v7 extension in be's newest manifest", () => {
    const src = `
    const manifestSansSignature = {
      version: 6,
      orgId,
      evidencePrivacy,
      generatedAt: generatedAt.toISOString(),
    };
    manifestUnsigned =
      signatureFormat === 2
        ? {
            ...manifestSansSignature,
            version: 7,
            signatureFormat,
            signatureFormatCutoverAt:
              signatureFormatCutoverAt?.toISOString() ?? null,
          }
        : manifestSansSignature;`;
    expect([...(drift.newestManifestFields(src) ?? [])].sort()).toEqual([
      'evidencePrivacy', 'generatedAt', 'orgId', 'signatureFormat', 'signatureFormatCutoverAt', 'version',
    ]);
  });

  it('a producer with no v7 extension has no v7 fields, so [B]/[D] stay red', () => {
    const src = `const manifestSansSignature = {
      version: 6,
      orgId,
    };
    const manifest = { ...manifestSansSignature, signature };`;
    expect([...(drift.newestManifestFields(src) ?? [])].sort()).toEqual(['orgId', 'signature', 'version']);
    expect(drift.newestManifestFields('const manifest = {};')).toBeNull();
  });

  it('still runs as a CLI when invoked by path', () => {
    const r = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('usage: node scripts/contract-drift.mjs');
  });
});
