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
  checkManifestContract: (
    bundleExporterSrc: string,
    verifyTsSrc: string,
  ) => { failures: string[]; warnings: string[] };
  stripComments: (source: string) => string;
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

// The verifier side of [B]/[D] for each producer era, written like verify.ts
// (`interface BundleManifest`, `manifestSignableBytes`'s `signable` object plus
// its version-gated `signable.x =` lines), with exactly the fields the matching
// producer fixture emits.
const VERIFIER_V6 = `
interface BundleManifest {
  version: number;
  orgId: string;
  generatedAt: string;
  signatureAlgorithm: string;
  signature: string;
  signatureKeyVersion: number;
}
function manifestSignableBytes(manifest: BundleManifest): string {
  const signable: Record<string, unknown> = {
    version: manifest.version,
    orgId: manifest.orgId,
    generatedAt: manifest.generatedAt,
    signatureAlgorithm: manifest.signatureAlgorithm,
  };
  return canonicalJson(signable);
}`;
const VERIFIER_V7 = `
interface BundleManifest {
  version: number;
  orgId: string;
  keyVersions: Array<{ keyVersion: number; status: string }>;
  generatedAt: string;
  signatureFormat?: 2;
  signatureFormatCutoverAt?: string | null;
  signatureAlgorithm: string;
  signature: string;
  signatureKeyVersion: number;
}
function manifestSignableBytes(manifest: BundleManifest): string {
  const signable: Record<string, unknown> = {
    version: manifest.version,
    orgId: manifest.orgId,
    keyVersions: manifest.keyVersions,
    generatedAt: manifest.generatedAt,
    signatureAlgorithm: manifest.signatureAlgorithm,
  };
  if (manifest.version >= 7) {
    signable.signatureFormat = manifest.signatureFormat;
    signable.signatureFormatCutoverAt = manifest.signatureFormatCutoverAt;
  }
  return canonicalJson(signable);
}`;

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

  it('anchors on a manifestUnsigned declaration with a type annotation', () => {
    const src = `const manifestSansSignature = {
      version: 6,
      orgId,
    };
    let manifestUnsigned: Record<string, unknown> = { ...manifestSansSignature, extraSigned: 1 };`;
    expect(manifestKeys(src)).toEqual(['extraSigned', 'orgId', 'version']);
  });

  it('a manifestUnsigned property is no declaration: a later `=` is not its value', () => {
    const src = `const manifestSansSignature = {
      version: 6,
    };
    log({ manifestUnsigned: true }, function () {
      const later = { notSigned: 1 };
    });`;
    expect(manifestKeys(src)).toEqual(['version']);
  });

  it('a call argument is not a spread field: only literals the spread can evaluate to count', () => {
    const src = `{
      id: row.id,
      ...withDefaults(row, { retries: 3 }),
      ...(row.legacy ? legacyFields(row, { since: 1 }) : {}),
      ...(isV2({ format: 2 }) ? { signatureFormat: 2 as const } : {}),
    }`;
    const opaque: string[] = [];
    const keys = drift.extractDepth1Keys(src, 0, { onOpaqueSpread: (e) => opaque.push(e) });
    expect([...keys].sort()).toEqual(['id', 'signatureFormat']);
    expect(opaque).toEqual(['withDefaults(row, { retries: 3 })', 'legacyFields(row, { since: 1 })']);
  });

  it('`cond && { … }` contributes its literal and is not opaque (a falsy left side spreads nothing)', () => {
    const src = `{
      ...(ok && { a: 1 }),
      ...(ok && extra(x)),
      ...(row.b ?? { b: 1 }),
    }`;
    const opaque: string[] = [];
    const keys = drift.extractDepth1Keys(src, 0, { onOpaqueSpread: (e) => opaque.push(e) });
    expect([...keys].sort()).toEqual(['a', 'b']);
    expect(opaque).toEqual(['extra(x)', 'row.b']);
  });

  it('a bracket, comma or quote inside a string, template, regex or comment does not end the block', () => {
    const src = `{
      note: row.note ?? ':)',
      bogus: 1,
      label: "a, {b",
      tpl: \`(\${row.id}] \${'}'}\`,
      re: /[(\]]\(/.test(x) ? 1 : 2,
      cmt: 1, // ) it's
      last: 1,
    }`;
    expect(returnKeys(src)).toEqual(['bogus', 'cmt', 'label', 'last', 'note', 're', 'tpl']);
  });

  it('stripComments keeps a // or /* inside a string, template or regex', () => {
    const src = "a = 'https://x'; // c\nb = `//${y}/*`; /* d */ c = /\\/\\//g;";
    expect(drift.stripComments(src)).toBe("a = 'https://x'; \nb = `//${y}/*`;  c = /\\/\\//g;");
  });

  it('[B]/[D] comparison path: be HEAD vs a v7 verifier and pre-BE-1957 vs a v6 verifier are both clean, no warnings', () => {
    expect(drift.checkManifestContract(BE_HEAD_MANIFEST, VERIFIER_V7)).toEqual({ failures: [], warnings: [] });
    expect(drift.checkManifestContract(BE_PRE_1957_MANIFEST, VERIFIER_V6)).toEqual({ failures: [], warnings: [] });
  });

  it('[B]/[D] comparison path: pre-BE-1957 vs a v7 verifier reports only the fields that producer lacks', () => {
    const { failures } = drift.checkManifestContract(BE_PRE_1957_MANIFEST, VERIFIER_V7);
    const named = (check: string) => failures.filter((f) => f.startsWith(check)).map((f) => f.split(':')[0]).sort();
    expect(named('[B]')).toEqual(['[B] keyVersions', '[B] signatureFormat', '[B] signatureFormatCutoverAt']);
    expect(named('[D]')).toEqual(['[D] keyVersions', '[D] signatureFormat', '[D] signatureFormatCutoverAt']);
  });

  it('[B]/[D] comparison path: a be-only field in an annotated manifestUnsigned literal is red in both', () => {
    const src = BE_HEAD_MANIFEST.replace(
      'let manifestUnsigned: Record<string, unknown> = manifestSansSignature;',
      'let manifestUnsigned: Record<string, unknown> = { ...manifestSansSignature, extraSigned: 1 };',
    );
    expect(src).not.toBe(BE_HEAD_MANIFEST);
    const { failures } = drift.checkManifestContract(src, VERIFIER_V7);
    expect(failures.filter((f) => f.includes('extraSigned')).map((f) => f.slice(0, 3)).sort()).toEqual(['[B]', '[D]']);
  });

  it('[D] warns on a wire-literal spread it cannot see into, and only on that one', () => {
    const src = BE_HEAD_MANIFEST.replace(
      '      signature: manifestSignature,\n',
      '      signature: manifestSignature,\n      ...wireExtras(orgId),\n',
    );
    expect(src).not.toBe(BE_HEAD_MANIFEST);
    const { warnings } = drift.checkManifestContract(src, VERIFIER_V7);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^\[D\] .*`wireExtras\(orgId\)`/);
  });

  it('a realpath error on argv[1] other than ENOENT fails closed instead of skipping the gate', () => {
    const r = spawnSync(
      process.execPath,
      ['-e', `import(${JSON.stringify(pathToFileURL(scriptPath).href)}).then(() => console.log('imported'))`, path.join(scriptPath, 'x')],
      { encoding: 'utf8' },
    );
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('ENOTDIR');
    expect(r.stdout).not.toContain('imported');
  });
});
