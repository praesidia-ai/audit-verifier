import { defineConfig } from 'vitest/config';

// AV-0031 — specs exercise dist/ (CLI spawns, sample regeneration): rebuild it first.
export default defineConfig({ test: { globalSetup: ['./scripts/vitest-build-dist.mjs'] } });
