import { defineConfig } from 'vitest/config';

// AV-0031 — specs exercise dist/ (CLI spawns, sample regeneration): rebuild it first.
// AV-2700 — coverage floor over ALL of src/ (untested files count as 0%, dist/ excluded),
// set at the measured value rounded down. Ratchet up only; target 80 on every metric.
export default defineConfig({
  test: {
    globalSetup: ['./scripts/vitest-build-dist.mjs'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/__tests__/**'],
      thresholds: { statements: 75, branches: 73, functions: 83, lines: 76 },
    },
  },
});
