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
});

/**
 * AV-2760 — a citation is `` `src/x.ts:N` `quote` `` (or `:N-M`). The quote
 * must sit on exactly the cited lines and on no other line of the file, so
 * any shift of the cited code turns this red. A line anchor in any other
 * spelling (`cli.ts:12`, `(:12)`) cannot be checked, so it is a failure too.
 * AV-2761 — `README.md:N` citations are checked the same way, and a bare
 * anchor into any `.md`, `.json` or JS/TS file fails.
 */
const CITE = /`((?:src\/[\w./-]+|package\.json|README\.md)):(\d+)(?:-(\d+))?` `([^`]+)`/g;
const BARE = /(?:src\/[\w./-]+|[\w-]+\.(?:[cm]?[jt]s|json|md)):\d+|\(:\d+/g;

describe.each([
  ['docs/COMPATIBILITY.md', 6],
  ['docs/ARCHITECTURE.md', 4],
  ['docs/OPERATIONS.md', 2],
  ['docs/INDEX.md', 5],
])('%s citations', (rel, floor) => {
  const text = read(rel);

  it('every `path:line` `quote` citation points at exactly the lines holding the quote', () => {
    const cites = [...text.matchAll(CITE)];
    const wrong = cites.flatMap(([cite, file, from, to, quote]) => {
      const hits = read(file!).split('\n').flatMap((l, i) => (l.includes(quote!) ? [i + 1] : []));
      const cited = Array.from({ length: Number(to ?? from) - Number(from) + 1 }, (_, k) => Number(from) + k);
      return hits.join() === cited.join() ? [] : [`${cite} is on line(s) [${hits.join(', ')}]`];
    });
    expect(wrong).toEqual([]);
    expect(cites.length).toBeGreaterThanOrEqual(floor);
  });

  it('has no line anchor outside a `path:line` `quote` citation', () => {
    expect(text.replace(CITE, '').match(BARE) ?? []).toEqual([]);
  });
});

/**
 * AV-2761 — every subcommand a doc spells is one the CLI dispatches on. The
 * set is read from the `cmd === '<name>'` branches of `runCli` in
 * src/cli.ts, never copied here. In an invocation, a first argument that is
 * a bare word (not a path, `<placeholder>`, `$VAR` or flag) is a subcommand
 * and must be in that set. A subcommand spelled as a flag (`--verify-set`)
 * fails anywhere in the text: the CLI has no such flag, so a copied command
 * exits 2.
 */
const runCliBody = /^function runCli\(\)[^{\n]*\{$([\s\S]*?)^\}$/m.exec(read('src/cli.ts'))?.[1] ?? '';
const SUBCOMMANDS = [...runCliBody.matchAll(/\bcmd === '([^']+)'/g)].map((m) => m[1]!);
const INVOCATION = /(?:praesidia-verify|cli\.js|npx @praesidia\/audit-verifier(?:@\S+)?)[ \t]+([^\s`]+)/g;
const mdFiles = (dir: string): string[] =>
  fs.readdirSync(path.join(root, dir), { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? mdFiles(`${dir}/${e.name}`) : e.name.endsWith('.md') ? [`${dir}/${e.name}`] : [],
  );

describe('CLI subcommands spelled in README.md and docs/', () => {
  it('reads the subcommand set from runCli', () => {
    expect(SUBCOMMANDS.length).toBeGreaterThan(0);
  });

  it.each(['README.md', ...mdFiles('docs')])('%s spells only real subcommands', (rel) => {
    const asFlag = new RegExp(`(?<![\\w-])--(?:${SUBCOMMANDS.join('|')})(?![\\w-])`, 'g');
    const wrong = read(rel).split('\n').flatMap((line, i) => [
      ...[...line.matchAll(INVOCATION)]
        .filter(([, arg]) => /^[a-z][\w-]*$/.test(arg!) && !SUBCOMMANDS.includes(arg!))
        .map(([inv]) => `${rel}:${i + 1} \`${inv}\` is not a subcommand`),
      ...(line.match(asFlag) ?? []).map((flag) => `${rel}:${i + 1} \`${flag}\` is a subcommand spelled as a flag`),
    ]);
    expect(wrong).toEqual([]);
  });
});
