import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/**
 * The release edit (the two literals in platform-pubkey) re-applied to a copy of the built
 * package in `dir`: the same dist/ a `tsc` build with that pin ships. Two empty strings give
 * the placeholder (unpinned) build. Returns `dir`.
 */
export function repin(dir: string, derB64: string, fingerprint: string): string {
  fs.cpSync(path.join(root, 'package.json'), path.join(dir, 'package.json'));
  fs.cpSync(path.join(root, 'dist'), path.join(dir, 'dist'), { recursive: true });
  const pubkeyJs = path.join(dir, 'dist/platform-pubkey.js');
  let replaced = 0;
  const js = fs.readFileSync(pubkeyJs, 'utf8').replace(
    /(PLATFORM_PUBLIC_KEY_(DER_B64|FINGERPRINT) = )'[^']*'/g,
    (_match, decl: string, which: string) => {
      replaced += 1;
      return `${decl}'${which === 'DER_B64' ? derB64 : fingerprint}'`;
    },
  );
  expect(replaced).toBe(2);
  fs.writeFileSync(pubkeyJs, js);
  return dir;
}
