# `@praesidia/audit-verifier` — docs

Dated 2026-09-12. Written for `DOCS-0001-audit-verifier`.

The root `audit-verifier/README.md` is the primary reference (usage, verdict shape, what it
verifies, trust anchor); read that first. This `docs/` directory holds these files:

| File | Purpose | In the npm tarball |
|---|---|---|
| `INDEX.md` | This file: what the package is, where it sits in the platform, and a map of `docs/`. | no |
| `ARCHITECTURE.md` | Module map of `src/` and `scripts/` with checked `path:line` anchors, the verification pipeline, and byte-for-byte compatibility with `be`. | no |
| `OPERATIONS.md` | Condensed build, test and CLI-usage reference: release and contract-drift gates, failure modes, and the `verify-set` limit on rows deleted from the end of the history. | no |
| `COMPATIBILITY.md` | Which verifier version reads which bundle manifest version and artefact format, and where the code decides each cell. | yes |
| `decision-disclosures.md` | Format of the unsigned `evidence/decision-receipts.ndjson` audit-package file, and how each line is trusted only through the signed bundle row it opens. | yes |
| `trust-anchor-verification.md` | Where the platform public key is pinned in this CLI, and how an auditor confirms that pin out-of-band. | yes |
| `design/platform-key-hierarchy.md` | Design only, not built: an offline root key that cross-signs rotating operational keys. | yes |

The last column follows the `files` list in `package.json`, which names exactly the `docs/` files
marked yes. The others are in the source repository only. `src/__tests__/compatibility.spec.ts`
fails if this table misses a file under `docs/`, names one that is gone, or disagrees with `files`.

`INDEX.md`, `ARCHITECTURE.md` and `OPERATIONS.md` are the DOCS-0001 triad: a platform-fit
statement, a module map, and a condensed build/test/CLI-usage reference.

## What it is

`@praesidia/audit-verifier` is an offline compliance-bundle verifier CLI (`praesidia-verify`),
zero runtime dependencies. It lets an external auditor verify a Praesidia compliance bundle's
cryptographic evidence (Ed25519/ECDSA-P256 signatures, RFC 6962 Merkle proofs, JCS canonical
JSON, Sigstore Rekor SET/inclusion-proof) entirely offline, with zero trust in Praesidia's own
infrastructure at verify time (`README.md:1` `# @praesidia/audit-verifier`). Node.js `>=22.12`
required (`README.md:12` `Node.js 22.12 or newer is required.`).

## Where it sits in the platform

- **Deliberately decoupled from `be`**: zero runtime dependencies, no imports can escape the
  package boundary (`tsconfig.json` empty `paths` map), no network calls at all. Its crypto
  primitives are vendored and are **byte-for-byte compatible** with `be`'s `CryptoUtilsService`
  (AGV-003), `canonicalJson` (AGV-030), and `MerkleRootService` (AGV-033) — same DER prefixes,
  domain-separation bytes, and key-ordering rules (`README.md:1128` `## Architecture`).
- **Reads what `be` writes**: `src/zip.ts`'s PKZIP reader reads STORED-method entries produced by
  `be`'s `BundleExporterService`'s `ZipStreamWriter` (AGV-035, `README.md:1128` `## Architecture`).
- **Contract gate**: `scripts/contract-drift.mjs` — the CD-0002 cross-repo contract gate,
  extended (SCAN-AV-03) to also cover the audit-row contract — checks this package's expectations
  of `be`'s signable-row/bundle shape stay in sync. See `ARCHITECTURE.md`.
- **Trust anchor**: the platform public key this build trusts is compiled into
  `src/platform-pubkey.ts`, not fetched at verify time — reintroducing a fetch would defeat the
  tool's own offline-trust purpose
  (`README.md:1038` `## Trust anchor — verifying the CLI's embedded pin out-of-band`). A production
  out-of-band confirmation channel is **USER-OWED, pending the key ceremony (MIL-0003)** — that
  README section already states this precisely; this triad does not restate the mechanism beyond
  that.

## Verification limits

Source-verified this pass: module list via `src/` directory listing + `grep`-confirmed export
sites. Every `README.md:N` `quote` citation here is checked by
`src/__tests__/compatibility.spec.ts`. Nothing here was exercised against a
live compliance bundle export/verify round-trip in this pass — the README's own "What it
verifies" and Changelog sections carry that history (e.g. `0.10.0`'s `detailsCommitment`
addition), not this triad.
