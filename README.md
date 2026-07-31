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

1. **Manifest signature** — Ed25519 (or ECDSA-P256) signature over the
   canonical-JSON of the manifest fields, signed with the tenant's
   currently-active key. The signable field set is selected by the
   manifest's declared `version`, from a closed whitelist — never by
   inspecting which fields happen to be present on the received object.
   `version: 1`/`2` sign 9 fields; `version: 3` signs those 9 plus
   `chainSeqCeiling`/`chainSeqSnapshotAt` (the chainSeq snapshot a bundle
   export was bounded by). Either direction of mismatch — the two v3
   fields present on a `version: 1`/`2` manifest, or absent on a
   `version: 3` one — fails closed with its own distinct reason
   (`chainseq_fields_present_on_v{1,2}_manifest` /
   `chainseq_fields_missing_on_v3_manifest`) rather than a generic
   signature failure, so an auditor can tell version skew from tampering.
2. **Row signatures** — every row in `rows.ndjson.gz` is re-canonicalized
   from its signable fields and verified against the public key at
   `row.keyVersion` from `public-keys.json`. The signed preimage is
   `canonical_bytes || base64-decode(prev_row_hash)` — the row signature
   binds the row's chain position, byte-for-byte as the backend writer
   produces it. A row whose `prev_row_hash` is missing/malformed fails
   closed. `ipAddress` is included in the canonical preimage IFF the wire
   row object carries that key at all (present-with-`null` still counts as
   present) — this mirrors `be-core`'s own conditional signing of
   `ipAddress` only for rows produced at/after its
   `IP_ADDRESS_SIGNABLE_CUTOVER_AT` activation, with no cutover-date
   knowledge required in this verifier.
3. **Chain integrity** — the true chain order is reconstructed from the
   cryptographic links themselves (each row's forward link vs. the next
   row's declared `prev_row_hash`), **not** from the bundle's on-disk row
   order. `rows.ndjson.gz` is exported ordered by `(signedAt, id)`, which
   does not always match the actual signing order when two rows in the
   same org share a `signedAt` millisecond (a same-transaction signing
   burst is the realistic case, not an edge case) — trusting file order in
   that case would report a false chain break on an honest bundle. Bundles
   are **date-ranged** (hard-capped at 90 days), so the ONE row with no
   in-bundle predecessor is accepted as an opaque anchor into the org's
   pre-range history, not required to be the all-zero genesis. Any other
   row missing an in-bundle predecessor, or two rows claiming the same
   predecessor (a fork), fails closed; leading truncation is caught by
   **completeness** (see 7) and per-period trailing truncation is caught
   by **root coverage** (see 10).
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
   `rekorPublicKeyPem` option.
   - **A root with no anchor receipt at all still fails closed** — an
     unwitnessed root does not get the benefit of the doubt. The `reason`
     distinguishes two different situations rather than reporting them
     identically: `no_external_witness` means every root in the bundle is
     unanchored (consistent with a deployment that has never enabled
     Rekor/S3 anchoring); `anchor_missing_for_partially_anchored_bundle`
     means only SOME roots lack a receipt while others have one — a much
     narrower, more concerning gap (e.g. an anchoring outage or a deleted
     receipt). These are different findings; do not treat them the same.
   - `--no-rekor` skips the check entirely (`reason:
     'rekor_check_skipped_by_caller: ...'`) — this is a CALLER opt-out, not
     a verdict about whether anchoring exists. `praesidia-verify`'s output
     prints an explicit `NOTE:` line whenever this flag was used, so a
     skimmed `RESULT: OK` cannot be mistaken for "anchoring was verified".
7. **Completeness** — the number of rows / roots actually present must
   equal the SIGNED `manifest.rowCount` / `manifest.rootCount`. This
   fails closed on a whole-bundle trailing-truncation attack, where an
   attacker deletes the last N rows (and their proofs) and the manifest
   is NOT re-signed to match: the surviving prefix still chains and still
   proves, but the aggregate signed counts no longer match what was
   handed to the verifier. This does **not**, by itself, catch a
   suffix deleted before a HONEST re-export recomputes a smaller count —
   see **root coverage** (10).
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
10. **Root coverage** — for every Merkle root whose full period lies
    inside the bundle's declared `[from, to)` date range, the number of
    bundle rows whose `signedAt` falls in that period, AND the number of
    proof entries pointing at that root, must both equal the root's own
    SIGNED `rowCount`. A Merkle root is signed and Rekor-anchored
    independently of the manifest, at anchor time — if rows are deleted
    from the underlying table AFTER a period's root was anchored but
    BEFORE the bundle is (re-)exported, the exporter's manifest honestly
    reflects the new (smaller) total and **completeness alone would
    pass**, while the untouched, already-anchored root still commits to
    the original, larger count. This component is what actually catches
    that class of deletion; a boundary root that only partially overlaps
    the bundle's date range is exempted (a genuine ranged export
    legitimately ships fewer rows for it, since rows outside `[from, to)`
    are never exported).
11. **Integrity checkpoints** (`version: 4`+ only) — `be`'s
    `AuditIntegrityCheckpointService` periodically (hourly) signs and
    persists `{organizationId, chainHeadHash, cumulativeRowCount, asOf}`
    for every org, independent of any Merkle-root period or bundle export.
    When present, the verifier: (a) authenticates every checkpoint's own
    signature (REVOKED-key rejection, same as rows/roots); (b) requires
    `cumulativeRowCount` to be monotonically non-decreasing across
    checkpoints in `asOf` order; (c) independently recomputes each
    checkpoint's `chainHeadHash` from the bundle's OWN rows restricted to
    `signedAt <= asOf` and compares. A checkpoint whose window contains no
    bundled rows (a dormant org, or a historical ranged export ending
    before that instant) is a legitimate boundary case and is skipped, not
    asserted — mirroring root coverage's own boundary exemption — UNLESS
    the checkpoint claims the all-zero genesis hash, which is fully
    consistent with an empty window and IS checked. **Known residual:**
    `AuditRetentionSealService.purgeWithSeal` (a real, already-shipped,
    feature-flagged, two-person-approval-gated hard-delete of signed rows)
    can legitimately trigger (b) or (c); no seal evidence is in the bundle
    today to distinguish that from tampering, so this still fails closed,
    with a reason string that names the possibility explicitly rather than
    reading as certain tampering.

S3 anchor receipts cannot be proven offline from their locator string alone.
The library therefore fails closed for S3 by default; callers can provide an
`anchorReceiptVerifier` that validates the object/version against their S3
trust boundary.

`manifest.version` is checked against an explicit ceiling
(`MAX_SUPPORTED_MANIFEST_VERSION`, currently 4) — a bundle declaring a newer
version than this build implements is rejected as a bundle-format error
(exit code 2) rather than silently verified under the wrong (older) rules.
Never bump the ceiling without landing real support for the new version's
fields in the same change.

## What this verifier does — and does NOT — prove

**Does prove**, when it reports `ok: true` for a given bundle:

- Every row, root, and the manifest are validly signed by a key present in
  the bundle's own signed key set, and that key was not marked `REVOKED` at
  verification time. For the manifest, "validly signed" includes the
  version-keyed signable set matching the manifest's own declared version
  exactly (invariant 1) — a `chainSeqCeiling`/`chainSeqSnapshotAt` mismatch
  relative to the declared version fails closed before the signature is
  even computed.
- The rows form a single, internally consistent hash chain (order-independent
  reconstruction — see invariant 3) with no fork, no orphan, and no broken
  link, up to one accepted opaque anchor for a date-ranged export.
- No row or Merkle root has been added, removed from the middle, or had its
  content altered since it was signed.
- For every Merkle-root period fully inside the bundle's declared date
  range, the number of rows and proofs present matches what that root's own
  signature committed to at anchor time (invariant 10) — this is what lets
  the verifier catch a deleted trailing suffix, not just a truncated
  archive.
- If Rekor/S3 anchoring is present and not skipped via `--no-rekor`, that
  the anchor receipt is a genuine, cryptographically valid transparency-log
  entry bound to the exact root hash in the bundle.
- If `platform-attestation.json` is present (or `--allow-legacy-unattested`
  is NOT passed), that Praesidia's platform — not just the tenant — vouched
  for the key-to-org binding.
- For `version: 4`+ bundles, that the org's cumulative signed-row count and
  chain head at each checkpointed hour were not shrunk or rewritten after
  the fact — bounding an undetectable suffix deletion in the un-rooted
  tail, or a boundary period, to at most one checkpoint interval, in the
  common case where the bundle's own rows span up to (or past) the
  checkpoint's `asOf` (see invariant 11's boundary exemption and residual).

**Does NOT prove**, even on `ok: true`:

- **That every action was captured in the first place.** A signing outage
  (governance mode `off`, or a failed sign under `observe`) can produce an
  invisible hole: an unsigned row is invisible to the chain, the Merkle
  roots, the checkpoints, and the exported bundle alike, with no marker in
  the artifact. Two hours of signing downtime and two hours of deleted
  rows currently look identical to this verifier.
- **That a not-yet-anchored (or boundary/partially-anchored) period wasn't
  truncated — in full.** Root coverage (10) only binds a root's committed
  count once that root exists and its FULL period is inside the bundle's
  range. `version: 4`+ integrity checkpoints (11) now close PART of this:
  when the bundle's rows demonstrably extend up to a checkpoint's `asOf`,
  a suffix deletion after that instant is caught, bounding the
  undetectable window to at most one checkpoint interval (hourly) for both
  the un-rooted tail and a boundary period. The residual that remains
  open even on `ok: true`: (a) bundles on `version <= 3` (no checkpoint
  commitment at all — the original gap, unchanged); (b) a checkpoint whose
  `asOf` predates every bundled row is a legitimate boundary/dormant-org
  case and is deliberately NOT asserted, so a bundle whose ENTIRE checked
  range sits before its org's actual current head (a narrow historical
  export of a still-active org) gets no independent size commitment from
  checkpoints either, same as before; (c) the checkpoint checks can
  legitimately fail closed (report `ok: false`, not a silent pass) across
  a genuine, signed `AuditRetentionSeal` hard-purge — that residual is
  documented on the `integrityCheckpoints` component, not silently
  absorbed.
- **That Rekor/S3 anchoring exists at all**, unless you read the `rekor`
  component specifically. A bundle can report overall `ok: true` while
  `rekor.reason` says `no_external_witness` (this deployment has anchoring
  off) — that is a materially weaker guarantee than an anchored bundle, and
  `--no-rekor` weakens it further by not checking at all. Read the `rekor`
  component, not just the top-level `ok`, before treating a bundle as
  Rekor-witnessed.
- **That a REVOKED key's pre-revocation signatures are trustworthy.** This
  verifier rejects EVERY signature made under a revoked key, including ones
  that were genuinely signed before revocation — because `signedAt` is not
  itself part of the signed bytes, a backdated forgery and a genuine
  pre-revocation signature are indistinguishable without an external
  timestamp proof, which this verifier does not currently cross-check
  against Rekor's own inclusion timestamp. The practical effect: revoking a
  tenant signing key after a suspected compromise makes that key's entire
  history unverifiable going forward, including the legitimate part.
- **That privileged, non-audit-logged actions didn't happen.** This
  verifier can only attest to what is IN the bundle. Whether every
  security-relevant mutation in the product is actually written to
  `audit_logs` in the first place is a `be`-side coverage question, not
  something an offline bundle verifier can detect.
- **Anything about network reachability, uptime, or `be`'s live behavior.**
  This is a static, offline artifact check. It says nothing about whether
  the platform is currently signing correctly, whether retention jobs are
  about to destroy signed data, or any other live operational property.

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

### 0.6.0 (FIX01 F5(b))

- **`manifest.version: 4` is now understood** (`PROD16-CONTRACT-manifest-v4-checkpoints.md`).
  Adds `integrityCheckpointCount` inside the signed manifest preimage and a
  new, conditionally-required bundle entry `integrity-checkpoints.ndjson.gz`
  carrying `be`'s `AuditIntegrityCheckpointService` rows
  (`{organizationId, chainHeadHash, cumulativeRowCount, asOf}`, each
  independently signed). Same both-directions version/field-presence rule
  as v3's `chainSeqCeiling`/`chainSeqSnapshotAt`
  (`integrity_checkpoint_count_present_on_v{1,2,3}_manifest` /
  `integrity_checkpoint_count_missing_on_v4_manifest`).
- **New `integrityCheckpoints` component** (see invariant 11 above):
  authenticates each checkpoint's signature, requires monotonic
  non-decreasing `cumulativeRowCount` across checkpoints, and cross-checks
  each checkpoint's `chainHeadHash` against the bundle's own reconstructed
  row chain as of that instant — closing PART of the previously-documented
  "un-rooted tail / boundary period has no independent size commitment"
  gap. See the "does NOT prove" section above for exactly which part
  remains open (pre-v4 bundles; a checkpoint whose window predates every
  bundled row; and a documented, explicit residual against the
  already-shipped `AuditRetentionSeal` hard-purge mechanism, which this
  verifier cannot yet distinguish from tampering).
- `MAX_SUPPORTED_MANIFEST_VERSION` raised from 3 to 4.
- `manifest.integrityCheckpointCount` (optional, additive) and
  `completeness` now also binds it to the number of checkpoints actually
  present, same anti-suppression rationale as `rowCount`/`rootCount`.
- New `VerifyReport.integrityCheckpoints` field (additive) and a new CLI
  output line. v1/v2/v3 bundles are completely unaffected — confirmed by
  the full pre-existing 84-test suite passing unmodified alongside 11 new
  tests built from `be`'s actual entity/service field set and signed
  preimage, not a hand-built guess of it.

### 0.5.0 (PROD16 §1b)

- **`manifest.version: 3` is now understood.** `be` commit `dc5b8a97` added
  `chainSeqCeiling`/`chainSeqSnapshotAt` INSIDE the signed manifest preimage
  and bumps the wire version to 3 for bundles carrying them
  (`PROD16-CONTRACT-manifest-v3.md`). Every bundle exported by that `be`
  version previously failed with a generic `manifest signature does not
  verify` because the verifier's signable whitelist was fixed at 9 fields
  regardless of declared version. The whitelist is now selected by
  `manifest.version` (9 fields for v1/v2, 9 + the two new fields for v3),
  still a closed selection — never reconstructed by stripping `signature`
  from the received object, which would let an attacker inject
  unsigned-looking fields into a signed payload.
- **Two new fail-closed reason codes**, one per direction of version/field
  mismatch: `chainseq_fields_present_on_v{1,2}_manifest` (the two v3 fields
  illegitimately present on an older-declared manifest — no genuine v1/v2
  producer ever emits them) and `chainseq_fields_missing_on_v3_manifest`
  (a `version: 3` manifest missing one or both — no genuine v3 producer
  ever omits them). Distinct from the generic signature-failure reason so
  an auditor can tell version skew from tampering.
- `MAX_SUPPORTED_MANIFEST_VERSION` raised from 2 to 3.
- No `VerifyReport` shape change. v1/v2 bundles (everything produced before
  `dc5b8a97`, and everything produced by `be` deployments that stay on v2)
  verify exactly as before — confirmed by the full pre-existing suite
  passing unmodified.

### 0.4.0 (PROD16)

- **New `rootCoverage` component** closes the suffix-deletion gap: a
  Merkle root's signed `rowCount` is now bound to the rows/proofs actually
  present in the bundle for every fully-contained period. Before this, a
  root anchored before rows were deleted (and never recomputed) would
  verify `ok:true` even though the rows it committed to no longer existed.
- **Chain verification (`chain`) no longer depends on the bundle's on-disk
  row order.** The true chain is now reconstructed from the cryptographic
  links themselves, closing a false-positive "chain break" that could fire
  on an honest bundle whenever two rows in the same org share a `signedAt`
  millisecond (the exporter orders by `(signedAt, id)`, not by the actual
  signing/chain order).
- **`manifest.version` now has an explicit ceiling.** A manifest declaring
  a version newer than this build implements is rejected as a bundle-format
  error instead of being silently verified under the wrong (older) rules.
- **`ipAddress` is now a recognized (optional) signable row field.** Rows
  produced under `be-core`'s `IP_ADDRESS_SIGNABLE_CUTOVER_AT` activation
  now verify correctly; rows without the field are unaffected.
- **Rekor "no receipt" messaging is now specific.** `no_external_witness`
  (no root in the bundle is anchored) and
  `anchor_missing_for_partially_anchored_bundle` (some roots are anchored,
  this one isn't) are now distinct reason codes instead of one generic
  `missing_anchor_receipt`. `--no-rekor` now prints an explicit CLI `NOTE:`
  line so a skimmed `RESULT: OK` cannot be mistaken for a verified anchor.
- New `VerifyReport.rootCoverage` field (additive).

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
