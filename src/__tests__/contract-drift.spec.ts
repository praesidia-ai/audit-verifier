/**
 * AV-2793 / AV-2794 — `scripts/contract-drift.mjs` against be's conditionally
 * emitted fields. be HEAD 67dfaea5 emits `signatureFormat` only for a format-2
 * artefact (`...(x.signatureFormat === 2 ? { signatureFormat: 2 as const } : {})`)
 * and builds the v7 manifest only in the `manifestUnsigned = … ? { ...manifestSansSignature, … } : …`
 * assignment it signs. AV-2793 taught the checker both. AV-2794 anchors [B]/[D]
 * on that assignment (before BE-1957, be 6b380bc9^, there is none and be signs
 * `manifestSansSignature` itself), reports a spread the checker cannot see
 * into, and walks brackets in one place. The snippets below copy be's shapes.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(root, 'scripts/contract-drift.mjs');

type OnOpaqueSpread = (expression: string) => void;
type Drift = {
  extractDepth1Keys: (
    source: string,
    openBraceIndex: number,
    opts?: { onOpaqueSpread?: OnOpaqueSpread },
  ) => Set<string>;
  newestManifestFields: (source: string, onOpaqueSpread?: OnOpaqueSpread) => Set<string> | null;
};
let drift: Drift;
beforeAll(async () => {
  drift = (await import(pathToFileURL(scriptPath).href)) as Drift;
});

const returnKeys = (source: string) => [...drift.extractDepth1Keys(source, source.indexOf('{'))].sort();
const manifestKeys = (source: string) => [...(drift.newestManifestFields(source) ?? [])].sort();

// be HEAD 67dfaea5, `bundle-exporter.service.ts:870-968`, trimmed.
const BE_HEAD_MANIFEST = `
    const manifestSansSignature = {
      version: 6,
      orgId,
      keyVersions: Object.keys(publicKeys)
        .map((v) => ({ keyVersion: Number(v), status: publicKeys[v].status }))
        .sort((a, b) => a.keyVersion - b.keyVersion),
      generatedAt: generatedAt.toISOString(),
    };
    let manifestUnsigned: Record<string, unknown> = manifestSansSignature;
    const { signature: manifestSignature, keyVersion: manifestSignerKeyVersion } =
      await this.tenantSigningKeyService.signWithActiveKey(
        orgId,
        ({ algorithm, signatureFormat, signatureFormatCutoverAt }) => {
          manifestAlgorithm = algorithm;
          manifestUnsigned =
            signatureFormat === 2
              ? {
                  ...manifestSansSignature,
                  version: 7,
                  signatureFormat,
                  signatureFormatCutoverAt:
                    signatureFormatCutoverAt?.toISOString() ?? null,
                }
              : manifestSansSignature;
          manifestSignableBytes = canonicalJson({
            ...manifestUnsigned,
            signatureAlgorithm: algorithm,
          });
          return manifestSignableBytes;
        },
        SignaturePurpose.BUNDLE_MANIFEST,
      );
    const manifest = {
      ...(manifestUnsigned as typeof manifestSansSignature),
      signatureAlgorithm: manifestAlgorithm,
      signature: manifestSignature,
      signatureKeyVersion: manifestSignerKeyVersion,
    };`;

// be 6b380bc9^ (before BE-1957), `bundle-exporter.service.ts:868-950`, trimmed:
// no `manifestUnsigned`; be signs `{ ...manifestSansSignature, signatureAlgorithm }`.
const BE_PRE_1957_MANIFEST = `
    const manifestSansSignature = {
      version: 6,
      orgId,
      generatedAt: generatedAt.toISOString(),
    };
    const { signature: manifestSignature, keyVersion: manifestSignerKeyVersion } =
      await this.tenantSigningKeyService.signWithActiveKey(orgId, ({ algorithm }) => {
        manifestAlgorithm = algorithm;
        manifestSignableBytes = canonicalJson({
          ...manifestSansSignature,
          signatureAlgorithm: algorithm,
        });
        return manifestSignableBytes;
      });
    const manifest = {
      ...manifestSansSignature,
      signatureAlgorithm: manifestAlgorithm,
      signature: manifestSignature,
      signatureKeyVersion: manifestSignerKeyVersion,
    };`;

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

  it("be HEAD: the newest manifest is manifestSansSignature plus manifestUnsigned's v7 branch", () => {
    expect(manifestKeys(BE_HEAD_MANIFEST)).toEqual([
      'generatedAt', 'keyVersions', 'orgId', 'signatureFormat', 'signatureFormatCutoverAt', 'version',
    ]);
  });

  it('before BE-1957 the signed manifest is manifestSansSignature alone; the wire literal adds nothing to [B]', () => {
    expect(manifestKeys(BE_PRE_1957_MANIFEST)).toEqual(['generatedAt', 'orgId', 'version']);
  });

  it('without a manifestSansSignature literal there are no newest manifest fields (null)', () => {
    expect(drift.newestManifestFields('const manifest = {};')).toBeNull();
  });

  it('still runs as a CLI when invoked by path', () => {
    const r = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('usage: node scripts/contract-drift.mjs');
  });
});

describe('AV-2794 contract-drift: opaque spreads, one bracket walker, CLI guard', () => {
  it('reports each spread it cannot see into instead of dropping it silently', () => {
    const src = `{
      id: row.id,
      ...helper(row),
      ...(row.extra ? buildExtra(row) : {}),
      ...(row.signatureFormat === 2
        ? { signatureFormat: 2 as const }
        : {}),
      ...(manifestUnsigned as typeof manifestSansSignature),
      ...(row.legacy ? { legacy: true } : undefined),
      ...base,
    }`;
    const opaque: string[] = [];
    const keys = drift.extractDepth1Keys(src, src.indexOf('{'), { onOpaqueSpread: (e) => opaque.push(e) });
    expect([...keys].sort()).toEqual(['id', 'legacy', 'signatureFormat']);
    expect(opaque).toEqual(['helper(row)', 'buildExtra(row)', 'manifestUnsigned', 'base']);
  });

  it('reports a spread nested inside a conditional literal too', () => {
    const src = `{
      ...(ok ? { a: 1, ...extra(x) } : {}),
    }`;
    const opaque: string[] = [];
    expect([...drift.extractDepth1Keys(src, 0, { onOpaqueSpread: (e) => opaque.push(e) })]).toEqual(['a']);
    expect(opaque).toEqual(['extra(x)']);
  });

  it("be's own manifest shapes have no opaque spread: manifestSansSignature is the known base", () => {
    for (const src of [BE_HEAD_MANIFEST, BE_PRE_1957_MANIFEST]) {
      const opaque: string[] = [];
      drift.newestManifestFields(src, (e) => opaque.push(e));
      expect(opaque).toEqual([]);
    }
  });

  it('reports a manifestUnsigned branch it cannot see into', () => {
    const src = `const manifestSansSignature = {
      version: 6,
      orgId,
    };
    manifestUnsigned =
      signatureFormat === 3
        ? buildV8(manifestSansSignature)
        : signatureFormat === 2
          ? { ...manifestSansSignature, version: 7, signatureFormat }
          : manifestSansSignature;`;
    const opaque: string[] = [];
    expect([...(drift.newestManifestFields(src, (e) => opaque.push(e)) ?? [])].sort()).toEqual([
      'orgId', 'signatureFormat', 'version',
    ]);
    expect(opaque).toEqual(['buildV8(manifestSansSignature)']);
  });

  it('a multi-line call inside a literal adds no keys of its own', () => {
    const src = `{
      chainSeqCeiling: this.toWireChainSeq(
        chainSeqSnapshot,
        orgId,
      ),
      rowCount,
    }`;
    expect(returnKeys(src)).toEqual(['chainSeqCeiling', 'rowCount']);
  });

  it('importing the script with an argv[1] that is not a file does not throw', () => {
    const r = spawnSync(
      process.execPath,
      ['-e', `import(${JSON.stringify(pathToFileURL(scriptPath).href)}).then(() => console.log('imported'))`, 'not-a-file'],
      { encoding: 'utf8' },
    );
    expect(r.stderr).toBe('');
    expect(r.stdout.trim()).toBe('imported');
  });

  it('still runs as a CLI through a symlink that node keeps (--preserve-symlinks-main)', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'contract-drift-'));
    try {
      const link = path.join(dir, 'contract-drift.mjs');
      symlinkSync(scriptPath, link);
      const r = spawnSync(process.execPath, ['--preserve-symlinks-main', link], { encoding: 'utf8' });
      expect(r.status).toBe(2);
      expect(r.stderr).toContain('usage: node scripts/contract-drift.mjs');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
