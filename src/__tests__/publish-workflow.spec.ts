/**
 * AV-2753 (INFRA-REVIEW-2026-10-01 CI-12) — no dependency code may execute in a
 * job that can mint the OIDC token (`id-token: write`) or holds the npm publish
 * secret. A malicious install script, a trojaned `tsc`/`vitest`, or an `npx`
 * download running there could mint a token that produces a provenance-attested
 * publish of this verifier. Build, test, pack and SBOM run in a token-less job;
 * the publish job only downloads the packed tarball and publishes it.
 *
 * Dependency-free line scan (the repo ships no YAML parser), so the workflows
 * keep the 2-space job layout they have today.
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const workflowsDir = path.join(root, '.github/workflows');
const workflowFiles = fs.readdirSync(workflowsDir).filter((f) => /\.ya?ml$/.test(f));

interface Job { id: string; body: string[] }
interface Workflow { file: string; header: string[]; jobs: Job[] }

/** Drop comment-only lines and trailing ` # ...` comments so prose never matches. */
function code(lines: string[]): string[] {
  return lines.filter((l) => !/^\s*#/.test(l)).map((l) => l.replace(/\s+#\s.*$/, ''));
}

function parse(file: string): Workflow {
  const lines = fs.readFileSync(path.join(workflowsDir, file), 'utf8').split('\n');
  const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (jobsAt < 0) throw new Error(`${file}: no top-level jobs:`);
  const jobs: Job[] = [];
  for (const line of lines.slice(jobsAt + 1)) {
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (m) jobs.push({ id: m[1], body: [] });
    else if (jobs.length > 0) jobs[jobs.length - 1].body.push(line);
  }
  return { file, header: code(lines.slice(0, jobsAt)), jobs: jobs.map((j) => ({ ...j, body: code(j.body) })) };
}

const workflows = workflowFiles.map(parse);
const mintsToken = (lines: string[]) => lines.some((l) => /^\s+id-token:\s*write\s*$/.test(l));
const holdsPublishSecret = (lines: string[]) => lines.some((l) => /secrets\.NPM_TOKEN|NODE_AUTH_TOKEN/.test(l));
const privileged = workflows.flatMap((w) =>
  w.jobs.filter((j) => mintsToken(j.body) || holdsPublishSecret(j.body)).map((j) => ({ w, j })),
);

/** Commands that execute dependency or repo code (lifecycle scripts, bins, npx downloads). */
const EXECUTES_CODE: Array<[string, RegExp]> = [
  ['npm ci / install / rebuild', /\bnpm\s+(ci|install|i|rebuild|update)\b/],
  ['npm run / test / exec', /\bnpm\s+(run|run-script|test|exec|start)\b/],
  ['npm pack (prepack runs tsc)', /\bnpm\s+pack\b/],
  ['npx', /\bnpx\b/],
  ['yarn / pnpm', /\b(yarn|pnpm)\b/],
  ['node <script>', /(^|[\s;&|(`])node\s+(?!--version)\S/],
  ['repo checkout', /actions\/checkout@/],
];

describe('publish workflow — no dependency code where a publish credential lives (AV-2753)', () => {
  it('finds the publish job (guards against a vacuous pass)', () => {
    expect(privileged.map(({ w, j }) => `${w.file}:${j.id}`)).toContain('publish.yml:publish');
  });

  it('no workflow grants id-token: write at workflow level', () => {
    for (const w of workflows) expect(mintsToken(w.header), w.file).toBe(false);
  });

  it('a job holding id-token: write or the npm secret executes no dependency or repo code', () => {
    const offences: string[] = [];
    for (const { w, j } of privileged) {
      for (const line of j.body) {
        for (const [what, re] of EXECUTES_CODE) {
          if (re.test(line)) offences.push(`${w.file}:${j.id}: ${what}: ${line.trim()}`);
        }
      }
    }
    expect(offences).toEqual([]);
  });

  it('the publish job publishes the downloaded tarball with provenance, after the build job', () => {
    const publish = parse('publish.yml').jobs.find((j) => j.id === 'publish')!;
    const text = publish.body.join('\n');
    expect(text).toMatch(/^\s+needs:\s*build\s*$/m);
    expect(text).toMatch(/actions\/download-artifact@/);
    expect(text).toMatch(/sha256sum -c --strict SHA256SUMS/);
    // A path argument (the packed .tgz), never a bare `npm publish` of a source folder.
    expect(text).toMatch(/\bnpm publish\s+"?\.\/\S+/);
    expect(text).toMatch(/\.tgz\b/);
    expect(text).toMatch(/--provenance\b/);
  });

  it('the build job holds no token yet keeps every release gate', () => {
    const build = parse('publish.yml').jobs.find((j) => j.id === 'build');
    expect(build, 'publish.yml has a build job').toBeDefined();
    expect(mintsToken(build!.body)).toBe(false);
    expect(holdsPublishSecret(build!.body)).toBe(false);
    const text = build!.body.join('\n');
    for (const gate of [
      'Verify release tag matches package version',
      'git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
      'npm run check:release-trust-anchor',
      'npm pack --pack-destination release',
      'npm run check:release-fixture',
      'npm run sbom',
      'name: release-assets',
      'name: sbom-cyclonedx',
    ]) {
      expect(text, gate).toContain(gate);
    }
  });

  it('every action is pinned by full commit SHA', () => {
    const unpinned: string[] = [];
    for (const w of workflows) {
      for (const line of [...w.header, ...w.jobs.flatMap((j) => j.body)]) {
        const m = /\buses:\s*(\S+)/.exec(line);
        if (m && !/^[^@\s]+@[0-9a-f]{40}$/.test(m[1])) unpinned.push(`${w.file}: ${m[1]}`);
      }
    }
    expect(unpinned).toEqual([]);
  });
});
