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
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
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

/** The `run: |` script of step `step` in job `jobId` of publish.yml, dedented. */
function runScript(jobId: string, step: string): string {
  const lines = fs.readFileSync(path.join(workflowsDir, 'publish.yml'), 'utf8').split('\n');
  const jobAt = lines.findIndex((l) => l === `  ${jobId}:`);
  const stepAt = lines.findIndex((l, i) => i > jobAt && l.trim() === `- name: ${step}`);
  const runAt = lines.findIndex((l, i) => i > stepAt && /^\s+run: \|\s*$/.test(l));
  if (jobAt < 0 || stepAt < 0 || runAt < 0) throw new Error(`publish.yml: no run: | in ${jobId} / ${step}`);
  const indent = lines[runAt].search(/\S/);
  const end = lines.findIndex((l, i) => i > runAt && l.trim() !== '' && l.search(/\S/) <= indent);
  const body = lines.slice(runAt + 1, end < 0 ? undefined : end);
  return body.map((l) => l.slice(indent + 2)).join('\n');
}

describe('publish job — publishes the tarball npm pack wrote, never a hand-built name (AV-2776)', () => {
  const script = runScript('publish', 'Publish to npm');

  /** Runs the step as Actions does (`bash -e`, in release/) with a stub `npm` that records its argv. */
  function publishStep(files: string[]): { status: number | null; npmArgs: string[] | null; stderr: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'av-2776-'));
    try {
      const release = path.join(dir, 'release');
      const bin = path.join(dir, 'bin');
      fs.mkdirSync(release);
      fs.mkdirSync(bin);
      for (const f of files) fs.writeFileSync(path.join(release, f), 'x');
      const argsFile = path.join(dir, 'npm-args');
      fs.writeFileSync(path.join(bin, 'npm'), `#!/bin/sh\nprintf '%s\\n' "$@" > '${argsFile}'\n`, { mode: 0o755 });
      const r = spawnSync('bash', ['-e', '-c', script], {
        cwd: release,
        encoding: 'utf8',
        env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`, RELEASE_TAG: 'v9.9.9' },
      });
      const npmArgs = fs.existsSync(argsFile) ? fs.readFileSync(argsFile, 'utf8').trim().split('\n') : null;
      return { status: r.status, npmArgs, stderr: r.stderr };
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  const assets = ['SHA256SUMS', 'README.md', 'audit-package.valid.zip', 'sample-platform-key.pem'];

  it('publishes the one .tgz in release/, whatever npm named it', () => {
    // A renamed package: the old step rebuilt `praesidia-audit-verifier-<tag>.tgz` and failed here.
    const r = publishStep(['acme-renamed-verifier-9.9.9.tgz', ...assets]);
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
    expect(r.npmArgs).toEqual(['publish', './acme-renamed-verifier-9.9.9.tgz', '--access', 'public', '--provenance']);
  });

  it('fails closed, without publishing, when release/ holds no .tgz', () => {
    const r = publishStep(assets);
    expect(r.status).not.toBe(0);
    expect(r.npmArgs).toBeNull();
  });

  it('fails closed, without publishing, when release/ holds more than one .tgz', () => {
    const r = publishStep(['praesidia-audit-verifier-9.9.9.tgz', 'praesidia-audit-verifier-9.9.8.tgz', ...assets]);
    expect(r.status).not.toBe(0);
    expect(r.npmArgs).toBeNull();
  });
});
