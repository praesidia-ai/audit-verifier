# @praesidia/audit-verifier

> Offline verifier CLI for Praesidia compliance bundles. Zero runtime dependencies.

This package is a self-contained command-line tool an external auditor can
run to verify a Praesidia compliance bundle entirely offline. It does NOT
depend on `be-core` or any other Praesidia package — all required
cryptographic primitives (Ed25519, ECDSA-P256, RFC 6962 Merkle, JCS-style
canonical JSON, Rekor SET / inclusion-proof verification, PKZIP) are
vendored in `src/`.

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
5. **Inclusion proofs** — every proof in `proofs.ndjson.gz` is walked
   against the corresponding root via RFC 6962-style verification (leaf
   prefix `0x00`, internal prefix `0x01`).
6. **Rekor receipt** — when `--no-rekor` is NOT passed, each root's
   Sigstore Rekor receipt is verified **cryptographically and offline**:
   its Signed Entry Timestamp (SET) is checked against the **pinned**
   Sigstore Rekor public key, and its inclusion proof is walked to the
   receipt's `rootHash`. A receipt that is not a genuine, SET-signed,
   log-included entry (e.g. an empty `{}`) now **fails**. The pinned key
   is baked in at build time (never fetched at verify time); a sovereign
   Rekor instance can pass its own key via `verifyBundle`'s
   `rekorPublicKeyPem` option. Skipped only via `--no-rekor`.
7. **Completeness** — the number of rows / roots actually present must
   equal the SIGNED `manifest.rowCount` / `manifest.rootCount`. This
   fails closed on a trailing-truncation attack, where an attacker
   deletes the last N rows (and their proofs): the surviving prefix
   still chains and still proves, but the signed counts no longer match
   what was handed to the verifier.
8. **Platform key-binding attestation** — the optional
   `platform-attestation.json` is checked against the CLI's pinned
   platform key. Independently, every key in `public-keys.json` is
   cross-checked byte-for-byte against the SIGNED `manifest.keyVersions`
   set, so verification keys cannot be swapped even when the platform
   attestation is absent or still the placeholder pin.

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

## Cutover plan — physical location

> **Spec deviation.** AGV-040 originally specified a top-level
> `packages/audit-verifier/` directory at the repo root. Due to a sandbox
> permission boundary at the time of authoring, the package currently
> lives under `be-core/packages/audit-verifier/`.

The **architectural** claim of zero-dependency-on-be-core is preserved
by enforcement at the TypeScript and `package.json` layer:

- `tsconfig.json` has `rootDir: "src"` and an empty `paths` map.
- All imports inside the package are relative within `src/`.
- `dependencies` in `package.json` is `{}`.
- `npm pack` produces a fully standalone tarball.

The cutover ticket — **AGV-040-FOLLOWUP** — will perform:

```bash
# Once the top-level path is writable in the dev environment:
git mv be-core/packages/audit-verifier packages/audit-verifier
# Then update any relative references in CI / scripts.
```

No code inside the package itself needs to change for the move; the
package is location-independent by construction.

## Changelog

### 0.3.0

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
