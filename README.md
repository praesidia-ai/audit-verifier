# @praesidia/audit-verifier

> Offline verifier CLI for Praesidia compliance bundles. Zero runtime dependencies.

This package is a self-contained command-line tool an external auditor can
run to verify a Praesidia compliance bundle entirely offline. It does NOT
depend on `be-core` or any other Praesidia package — all required
cryptographic primitives (Ed25519, ECDSA-P256, RFC 6962 Merkle, JCS-style
canonical JSON, Rekor SET / inclusion-proof verification, PKZIP) are
vendored in `src/`.

Node.js 22.12 or newer is required.

## Install

```bash
# From npm (once published)
npm install -g @praesidia/audit-verifier

# Or run via npx without installing
npx @praesidia/audit-verifier bundle.zip
```

## Usage

```bash
praesidia-verify <bundle.zip> [options]

Options:
  --no-rekor   Skip the offline Sigstore Rekor receipt verification.
  --platform-key <file>
               Trust this PEM or SPKI-DER platform public key.
  --allow-legacy-unattested
               Explicitly accept a pre-attestation legacy bundle.
  --quiet      Print only the final OK/FAIL line.
  --help       Show this help message.

Exit codes:
  0   All signatures, chain links, and proofs verified.
  1   Verification failure (signature, chain, or proof mismatch).
  2   I/O or bundle-format error (malformed zip, missing file, etc.).
```

## What it verifies

For a bundle produced by `BundleExporterService` (AGV-035) the verifier
checks every cryptographic invariant the bundle commits to:

1. **Manifest signature** — Ed25519 signature over the canonical-JSON of
   the manifest fields, signed with the tenant's currently-active key.
2. **Row signatures** — every row in `rows.ndjson.gz` is re-canonicalized
   from its signable fields and verified against the public key at
   `row.keyVersion` from `public-keys.json`. The signed preimage is
   `canonical_bytes || base64-decode(prev_row_hash)` — the row signature
   binds the row's chain position, byte-for-byte as the backend writer
   produces it. A row whose `prev_row_hash` is missing/malformed fails
   closed.
3. **Chain integrity** — `prev_row_hash` is recomputed from the previous
   row's `(canonical_bytes || signature_bytes)` digest and matched
   against the stored value. Bundles are **date-ranged** (hard-capped at
   90 days), so the FIRST row's `prev_row_hash` is an opaque anchor into
   the org's pre-range history — it is accepted, not required to be the
   all-zero genesis. Internal linkage is enforced for every subsequent
   row, so reorder/insert/mutate of a non-leading row still breaks a link;
   leading truncation is caught by **completeness** (see 7).
4. **Merkle root signatures** — every root in `roots.ndjson.gz` is
   re-canonicalized and verified.
5. **Inclusion proofs** — exactly one valid proof is required for every
   exported row. Every proof is walked against the corresponding root via
   RFC 6962-style verification (leaf prefix `0x00`, internal prefix `0x01`),
   with index and path depth checked against the signed root row count.
   Diagnostic status markers are failures, not substitutes for proofs.
6. **Rekor receipt** — when `--no-rekor` is NOT passed, each root's
   Sigstore Rekor receipt is verified **cryptographically and offline**:
   its Signed Entry Timestamp (SET) is checked against the **pinned**
   Sigstore Rekor public key, and its inclusion proof is walked to the
   receipt's `rootHash`. Its `hashedrekord` body must also contain the exact
   audit root hash and root signature from the bundle, preventing a genuine
   but unrelated receipt from being reattached. A receipt that is not a
   genuine, SET-signed, log-included entry (e.g. an empty `{}`) **fails**.
   The pinned key
   is baked in at build time (never fetched at verify time); a sovereign
   Rekor instance can pass its own key via `verifyBundle`'s
   `rekorPublicKeyPem` option. Skipped only via `--no-rekor`.
7. **Completeness** — the number of rows / roots actually present must
   equal the SIGNED `manifest.rowCount` / `manifest.rootCount`. This
   fails closed on a trailing-truncation attack, where an attacker
   deletes the last N rows (and their proofs): the surviving prefix
   still chains and still proves, but the signed counts no longer match
   what was handed to the verifier.
8. **Platform key-binding attestation** — `platform-attestation.json` is
   checked against a trusted platform key. The current source distribution
   does not embed a deployment-specific key, so operators must pass the key
   with `--platform-key` (or `platformPublicKeyDerB64` through the library).
   Missing attestation or trust key fails closed. Pre-attestation bundles are
   accepted only with explicit `--allow-legacy-unattested`. The attestation
   must cover every bundled key exactly once and binds its fingerprint,
   lifecycle status, and revocation timestamp.
9. **Archive integrity and resource bounds** — duplicate filenames,
   local/central-header disagreement, invalid UTF-8 names, CRC mismatches,
   unsupported encryption, malformed ZIP64, and excessive decompression are
   rejected before bundle contents are trusted.

S3 anchor receipts cannot be proven offline from their locator string alone.
The library therefore fails closed for S3 by default; callers can provide an
`anchorReceiptVerifier` that validates the object/version against their S3
trust boundary.

## Architecture

This package is intentionally **decoupled** from `be-core`:

- `package.json` `dependencies` is `{}` — zero runtime dependencies.
- `tsconfig.json` sets `rootDir: "src"` and an empty `paths` map; no
  imports can escape the package boundary.
- All crypto primitives are vendored under `src/crypto.ts`. They are
  byte-for-byte compatible with `be-core`'s
  `CryptoUtilsService` (AGV-003), `canonicalJson` (AGV-030), and
  `MerkleRootService` (AGV-033) — same DER prefixes, same RFC 6962
  domain-separation bytes, same key-ordering rules.
- The PKZIP reader in `src/zip.ts` reads STORED-method entries produced
  by `BundleExporterService`'s `ZipStreamWriter` (AGV-035).
- **No network calls at all** — the Rekor receipt is verified offline
  against a public key pinned into `src/rekor.ts` (SET signature +
  inclusion proof), so even the transparency-log check needs no network.
- No telemetry, no analytics, no payload logging — the verifier prints
  per-component pass/fail counts and the id of the first offending row.

## Changelog

### 0.3.0

- Platform attestation and trust-key absence now fail closed by default;
  explicit legacy opt-in and `--platform-key` are available for controlled
  migration.
- Rekor receipts are bound to the exact root hash and signature, S3 receipts
  require a real caller-supplied verifier, and proof coverage is complete.
- ZIP parsing now enforces unique names, CRC/header integrity, strict UTF-8,
  and decompression/resource limits.

- **Rekor receipts are now verified cryptographically (BUGHUNT-SDK-05).**
  The default Rekor check was previously `JSON.parse(receipt)` — it passed
  for any parseable JSON (even `{}`), so `rekor receipts OK` was false
  assurance. The verifier now checks the receipt's SET signature against
  the pinned Sigstore key and walks its inclusion proof to `rootHash`
  (fully offline, `src/rekor.ts`); a non-genuine receipt now fails. New
  optional `verifyBundle` option `rekorPublicKeyPem` pins a sovereign
  Rekor key. `report.rekor.checked` still counts one per anchor entry.
- **Partial-range (non-genesis) bundles verify (BUGHUNT-SDK-02).** The
  chain check treated the first bundle row's `prev_row_hash` as an opaque
  anchor into the org's pre-range history instead of requiring the all-zero
  genesis, so a legitimate date-ranged export from an org older than 90
  days no longer falsely FAILS. Internal linkage for rows `[1..]` is still
  enforced; leading truncation is still caught by `completeness`.
  `report.chain.checked` now counts inter-row link assertions
  (`rows − 1`) rather than rows.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
