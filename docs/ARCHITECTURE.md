# `@praesidia/audit-verifier` — architecture

Module map with `path:line` anchors, verified against the current tree 2026-09-12.

## `src/` layout

```
src/cli.ts               # entrypoint (832 lines): flag parsing, mainVerifySet (:644),
                          # main (:725) — dispatches to verifyBundle or the verify-set path
src/verify.ts             # verifyBundle (:1189, 5548 lines total) — the actual bundle
                          # verification pipeline: signatures, Merkle proofs, chain
                          # continuity, cross-bundle verify-set (SCAN2-004)
src/crypto.ts             # vendored Ed25519/ECDSA-P256 primitives, byte-for-byte
                          # compatible with be's CryptoUtilsService (AGV-003)
src/jcs-canonical.ts      # vendored JSON Canonicalization Scheme, compatible with be's
                          # canonicalJson (AGV-030) — includes the __proto__-key
                          # canonicalization pinned against be-core (SCAN-AV-02)
src/zip.ts                # PKZIP reader/writer (849 lines): readZip (:101), writeZip (:589),
                          # gzipDeterministic (:773); bounded archive/entry size caps
                          # (MAX_ZIP_ARCHIVE_BYTES etc., :71-73) reject oversized bundles
                          # before full decompression
src/rekor.ts              # Sigstore Rekor offline verification (632 lines):
                          # computeRekorLogIdHex (:66), verifyRekorReceipt (:549) — SET
                          # signature + signed checkpoint + inclusion proof, no network call
src/platform-pubkey.ts    # PLATFORM_PUBLIC_KEY_DER_B64 / PLATFORM_PUBLIC_KEY_FINGERPRINT —
                          # the compiled-in trust anchor (audit-verifier/README.md:530-534)
src/http-receipt.ts       # HTTP_RECEIPT_VERSION (:4), httpTargetKeyFingerprint (:32),
                          # httpRequestCommitment (:37), verifyHttpReceipt (:41) — verifies
                          # independently-pinned HTTP target receipts (README.md:877)
src/aibom.ts              # verifyAibomAttestation — be's attested AIBOM envelope
                          # (praesidia-aibom-attestation/v1), pinned tenant key (AV-0001)
src/index.ts              # package's public export surface
```

## Verification pipeline (high level)

`cli.ts:725`'s `main()` reads CLI flags, reads the bundle path, and calls into
`verify.ts:1189`'s `verifyBundle()`. That function is the load-bearing piece described in the
README's "What it verifies" section (`audit-verifier/README.md:116-411`): per-row signature
checks, Merkle root/inclusion proofs, chain-continuity checks, and (unless `--no-rekor`) Rekor
receipt verification via `rekor.ts:549`. `cli.ts:644`'s `mainVerifySet()` is the newer
cross-bundle continuity entrypoint (`verify-set`, SCAN2-004) that checks chain fields are present
across a *set* of bundles rather than one — it fails closed when chain fields are absent
(pinned by a dedicated test, `f13793e`).

Component statuses (`ComponentStatus`, `verify.ts`; README "Verdict shape"):

| status | meaning | top-level effect |
|---|---|---|
| `valid` | checked, all passed | — |
| `invalid` | a check failed | `invalid` |
| `incomplete` | evidence present but insufficient (e.g. redacted) | `incomplete` |
| `unsupported` | component does not apply to this manifest version | ignored |
| `not_present` | applies, but 0 items to check (AV-0008, `withEvidenceStatus`) | ignored, unless no evidence component is `valid` → `incomplete` |

## Byte-for-byte compatibility with `be`

This is the load-bearing correctness property of the whole package: its vendored crypto/JCS/zip
code must produce and check the **exact same bytes** `be` produces when it exports a bundle.
- `src/crypto.ts` ↔ `be`'s `CryptoUtilsService` (AGV-003) — same DER prefixes.
- `src/jcs-canonical.ts` ↔ `be`'s `canonicalJson` (AGV-030) — same key-ordering rules, including
  the `__proto__`-key edge case (SCAN-AV-02, pinned by `433ebef`).
- `src/aibom.ts` ↔ `be`'s `aibom-canonical.ts` + `aibom-attestation.ts` (BE-0155) — fixtures in
  `test-fixtures/aibom/` are real `be` exports from `scripts/make-aibom-fixtures.cts`. Envelope
  fields outside the signed `document` are `AIBOM_UNAUTHENTICATED_FIELDS` and are never reported
  as verified. BE-0738's `anchorReference`, `anchorStatus`, `anchoredAt` and `anchorReason`
  are unsigned. Since AV-0005 each must agree with BE-1255's `anchorProof`, which is checked
  offline with `be`'s A2-A10 procedure (`verifyAnchorProof` in `src/aibom.ts`, reusing
  `rekor.ts`'s `verifyRekorReceipt` with a pinned log key). The fixtures in
  `test-fixtures/aibom/anchored/` come from `scripts/make-aibom-anchor-fixtures.cts`, with `be`'s
  own verdicts in `be-verdicts.json`.
- Merkle root computation ↔ `be`'s `MerkleRootService` (AGV-033) — same RFC 6962
  domain-separation bytes.
- `src/zip.ts`'s reader ↔ `be`'s `BundleExporterService`'s `ZipStreamWriter` (AGV-035) — reads
  exactly the STORED-method entries that writer produces.

## Contract-drift gate

`scripts/contract-drift.mjs` — the CD-0002 cross-repo contract gate — checks this package's
expectations of `be`'s signable-row/bundle contract against `be`'s actual shape. Extended
(SCAN-AV-03, `2b965fe`) to also cover the audit-row contract, not just the bundle envelope. This
is the repo's other load-bearing piece beyond the CLI itself (per this ticket's own note) — a
drift here means the verifier could silently pass or fail against a bundle shape `be` no longer
produces.

## Trust-anchor operational scripts (`scripts/`)

```
assert-release-trust-anchor.mjs   # release-time check that the embedded pin matches the
                                   # operator-approved fingerprint (see below)
check-trust-anchor-ci.mjs          # CI-side check
trust-anchor-policy.mjs            # the policy itself (accepted curve, canonical-key checks)
trust-anchor-policy.selftest.mjs   # self-test for the policy script
```

`prepack` rejects a missing operator-approval value, a mismatch, a non-canonical key, or any EC
curve other than P-256 (`audit-verifier/README.md:547-550`) — this prevents a key and its
self-asserted fingerprint from being changed together and silently treated as approved.

See also `docs/design/platform-key-hierarchy.md` and `docs/trust-anchor-verification.md` for the
full key-ceremony design (the latter is explicitly incomplete pending MIL-0003, the production key
ceremony — see `docs/README.md`).
