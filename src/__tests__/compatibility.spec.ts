/**
 * AV-0012 — drift gate for docs/COMPATIBILITY.md: the matrix must have a row
 * for the current package version, its manifest ceiling and Node floor must be
 * the ones the code enforces, and every `path:line` citation must still point
 * at the code it quotes.
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (rel: string) => fs.readFileSync(path.join(root, rel), 'utf8');
const doc = read('docs/COMPATIBILITY.md');
const pkg = JSON.parse(read('package.json')) as { version: string; engines: { node: string } };
const maxManifest = Number(/^const MAX_SUPPORTED_MANIFEST_VERSION = (\d+);$/m.exec(read('src/verify.ts'))?.[1]);

const cells = (line: string) => line.split('|').slice(1, -1).map((c) => c.trim());
/** The matrix is the first table in the file (later tables are provenance notes). */
const lines = doc.split('\n');
const start = lines.findIndex((l) => l.startsWith('|'));
const end = lines.findIndex((l, i) => i > start && !l.startsWith('|'));
const tableLines = lines.slice(start, end === -1 ? undefined : end);
const header = cells(tableLines[0] ?? '');
const rows = tableLines.slice(2).map(cells);
const col = (name: string) => header.findIndex((h) => h.toLowerCase().includes(name));
/** Highest manifest version a cell like `1–5` / `1-5` / `≥ 1 (no ceiling)` names. */
const manifestMax = (cell: string) => Math.max(...(cell.match(/\d+/g) ?? []).map(Number));

describe('docs/COMPATIBILITY.md', () => {
  it('has the columns the matrix promises', () => {
    for (const name of ['verifier', 'manifest', 'package', 'decision disclosure', 'http-receipt', 'aibom', 'node']) {
      expect(col(name), `column "${name}"`).toBeGreaterThanOrEqual(0);
    }
  });

  it('has a row for the current package.json version', () => {
    expect(rows.map((r) => r[col('verifier')]?.split(' ')[0])).toContain(pkg.version);
  });

  it('the current row states the enforced manifest ceiling and Node floor', () => {
    expect(Number.isSafeInteger(maxManifest)).toBe(true);
    const row = rows.find((r) => r[col('verifier')]?.split(' ')[0] === pkg.version)!;
    expect(manifestMax(row[col('manifest')]!)).toBe(maxManifest);
    expect(row[col('node')]).toContain(pkg.engines.node);
  });

  it('no row claims a manifest version above the enforced ceiling', () => {
    expect(Math.max(...rows.map((r) => manifestMax(r[col('manifest')]!)))).toBe(maxManifest);
  });

  it('every `path:line` `quote` citation still points at the quoted code', () => {
    const cites = [...doc.matchAll(/`((?:src\/[\w./-]+|package\.json)):(\d+)` `([^`]+)`/g)];
    expect(cites.length).toBeGreaterThanOrEqual(6);
    for (const [, file, line, quote] of cites) {
      expect(read(file!).split('\n')[Number(line) - 1], `${file}:${line}`).toContain(quote);
    }
  });
});
