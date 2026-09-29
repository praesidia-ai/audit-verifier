# @praesidia/audit-verifier — build + test image.
# Purpose: CI / reproducible builds and a `--help` smoke check. This is NOT a
# deployable service — the package is an offline verifier CLI published to npm
# (bin: praesidia-verify, zero runtime dependencies). The image exists so the
# build + test pipeline is reproducible on any host.
#
# Base: node:26.10.0-alpine3.24 (current stable), npm (bundled). Runs as a non-root user.

FROM node:26.10.0-alpine3.24@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS build
# node:26.10.0-alpine3.24
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.spec.json vitest.config.mjs ./
COPY src ./src
COPY test-fixtures ./test-fixtures
COPY samples ./samples
COPY docs ./docs
COPY scripts ./scripts
COPY README.md LICENSE ./
RUN npm run build && npm run typecheck:spec && npx vitest run

# ---- runtime: minimal, non-root, zero runtime deps ----
FROM node:26.10.0-alpine3.24@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS runtime
# node:26.10.0-alpine3.24
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S praesidia && adduser -S praesidia -G praesidia
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/dist ./dist
USER praesidia
# Smoke: print verifier help (exits 0 on --help).
CMD ["node", "dist/cli.js", "--help"]
