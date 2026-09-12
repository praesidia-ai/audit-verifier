# `@praesidia/audit-verifier` — docs

Dated 2026-09-12. Owner (per `core/.claude/POLICY.md:102`): `audit-verifier-dev`. Written for
`DOCS-0001-audit-verifier`.

This `docs/` directory holds `design/platform-key-hierarchy.md` and
`trust-anchor-verification.md` plus the DOCS-0001 triad added here. The root
`audit-verifier/README.md` is the primary reference (usage, verdict shape, what it verifies, trust
anchor); read that first. This triad adds a platform-fit statement, a module map with
`path:line` anchors, and a condensed build/test/CLI-usage reference.

## What it is

`@praesidia/audit-verifier` is an offline compliance-bundle verifier CLI (`praesidia-verify`),
zero runtime dependencies (`audit-verifier/README.md:3,10`). It lets an external auditor verify a
Praesidia compliance bundle's cryptographic evidence (Ed25519/ECDSA-P256 signatures, RFC 6962
Merkle proofs, JCS canonical JSON, Sigstore Rekor SET/inclusion-proof) entirely offline, with zero
trust in Praesidia's own infrastructure at verify time (`audit-verifier/README.md:7-10,594-596`).
Node.js `>=22.12` required (`audit-verifier/README.md:12`).

## Publishing status

**Not yet published to npm.** `README.md:17` already documents this honestly: "From npm (once
published)". `.claude/tickets/CLOSE/TRIAGE-rest.md`'s `MKT-0002` row re-confirmed `npm view
@praesidia/audit-verifier` → `404` live on 2026-09-12. The **public-facing story is that an
external auditor obtains this tool from Praesidia directly** (per this ticket's own instruction),
not that it is currently `npm install`-able.

## Where it sits in the platform

- **Deliberately decoupled from `be`**: zero runtime dependencies, no imports can escape the
  package boundary (`tsconfig.json` empty `paths` map), no network calls at all
  (`audit-verifier/README.md:582-601`). Its crypto primitives are vendored and are
  **byte-for-byte compatible** with `be`'s `CryptoUtilsService` (AGV-003), `canonicalJson`
  (AGV-030), and `MerkleRootService` (AGV-033) — same DER prefixes, domain-separation bytes, and
  key-ordering rules (`audit-verifier/README.md:585-592`).
- **Reads what `be` writes**: `src/zip.ts`'s PKZIP reader reads STORED-method entries produced by
  `be`'s `BundleExporterService`'s `ZipStreamWriter` (AGV-035, `audit-verifier/README.md:593-595`).
- **Contract gate**: `scripts/contract-drift.mjs` — the CD-0002 cross-repo contract gate,
  extended (SCAN-AV-03) to also cover the audit-row contract — checks this package's expectations
  of `be`'s signable-row/bundle shape stay in sync. See `ARCHITECTURE.md`.
- **Trust anchor**: the platform public key this build trusts is compiled into
  `src/platform-pubkey.ts`, not fetched at verify time — reintroducing a fetch would defeat the
  tool's own offline-trust purpose (`audit-verifier/README.md:530-582`). A production out-of-band
  confirmation channel is **USER-OWED, pending the key ceremony (MIL-0003)** — `README.md:546-550`
  already states this precisely; this triad does not restate the mechanism beyond that.

## Verification limits

Source-verified this pass: module list via `src/` directory listing + `grep`-confirmed export
sites; publish status corroborated by the same-day live `npm view` check already on record in
this run's triage, not re-run independently from this file. Nothing here was exercised against a
live compliance bundle export/verify round-trip in this pass — the README's own "What it
verifies" and Changelog sections carry that history (e.g. `0.10.0`'s `detailsCommitment`
addition), not this triad.

See also: `ARCHITECTURE.md`, `OPERATIONS.md`, `design/platform-key-hierarchy.md`,
`trust-anchor-verification.md`.
