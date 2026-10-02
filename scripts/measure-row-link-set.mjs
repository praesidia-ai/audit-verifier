/**
 * Heap cost of a Set holding every row's chain link: the index the AV-2757 note on
 * `verifyChainBoundary` (src/verify.ts) declines to build. A link is a 44-character base64
 * SHA-256, as `computeChainLink` returns it and as rows.ndjson declares it in `prevRowHash`.
 * Builds the Set from JSON-parsed rows and from flat strings; prints heapUsed growth after gc.
 *
 *   node --expose-gc scripts/measure-row-link-set.mjs [rows, default 250000 = maxRows]
 */
import { createHash, randomBytes } from 'node:crypto';

if (typeof globalThis.gc !== 'function') throw new Error('run with node --expose-gc');
const rows = Number(process.argv[2] ?? 250_000);
const link = () => createHash('sha256').update(randomBytes(32)).digest('base64');
const heap = () => (globalThis.gc(), globalThis.gc(), process.memoryUsage().heapUsed);
const ndjson = Array.from({ length: rows }, () => JSON.stringify({ prevRowHash: link() })).join('\n');

const measure = (build) => {
  const before = heap();
  const set = build();
  const bytes = heap() - before;
  if (set.size !== rows) throw new Error(`expected ${rows} distinct links, got ${set.size}`);
  return { bytesPerRow: Math.round(bytes / rows), MiB: +(bytes / 2 ** 20).toFixed(1) };
};
const parsed = measure(() => new Set(ndjson.split('\n').map((line) => JSON.parse(line).prevRowHash)));
const flat = measure(() => new Set(Array.from({ length: rows }, link)));
console.log(JSON.stringify({ node: process.version, arch: process.arch, rows, parsed, flat }));
