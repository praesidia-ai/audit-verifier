# @praesidia/audit-verifier — build + test image.
# Purpose: CI / reproducible builds and a `--help` smoke check. This is NOT a
# deployable service — the package is an offline verifier CLI published to npm
# (bin: praesidia-verify, zero runtime dependencies). The image exists so the
# build + test pipeline is reproducible on any host.
#
# Base: node:24-alpine (Active LTS), npm 11 (bundled). Runs as a non-root user.

FROM node:24.18-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS build
# node:24.18-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.spec.json ./
COPY src ./src
COPY README.md LICENSE ./
RUN npm run build && npm run typecheck:spec && npx vitest run

# ---- runtime: minimal, non-root, zero runtime deps ----
FROM node:24.18-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS runtime
# node:24.18-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S praesidia && adduser -S praesidia -G praesidia
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/dist ./dist
USER praesidia
# Smoke: print verifier help (exits 0 on --help).
CMD ["node", "dist/cli.js", "--help"]
