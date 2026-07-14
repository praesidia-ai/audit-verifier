# @praesidia/audit-verifier — build + test image.
# Purpose: CI / reproducible builds and a `--help` smoke check. This is NOT a
# deployable service — the package is an offline verifier CLI published to npm
# (bin: praesidia-verify, zero runtime dependencies). The image exists so the
# build + test pipeline is reproducible on any host.
#
# Base: node:24-alpine (Active LTS), npm 11 (bundled). Runs as a non-root user.

FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY README.md LICENSE ./
RUN npm run build && npx vitest run

# ---- runtime: minimal, non-root, zero runtime deps ----
FROM node:24-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S praesidia && adduser -S praesidia -G praesidia
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/dist ./dist
USER praesidia
# Smoke: print verifier help (exits 0 on --help).
CMD ["node", "dist/cli.js", "--help"]
