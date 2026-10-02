# `@praesidia/audit-verifier` — architecture

Module map with `path:line` anchors. Each `src/` and `README.md` anchor is a path, line and quote
(`` `src/x.ts:N` `quote` ``). `src/__tests__/compatibility.spec.ts` fails when the quote is not on
exactly that line, or when an anchor has no quote.

## `src/` layout

- `src/cli.ts` — entrypoint and flag parsing. `runCli` dispatches on the first argument: to
  `src/cli.ts:1129` `async function main(` for one bundle (no subcommand, or `verify`), to
  `src/cli.ts:1058` `async function mainVerifySet(` for `verify-set`, or to `mainAibom` for `aibom`.
- `src/verify.ts` — `src/verify.ts:1465` `export async function verifyBundle(` is the bundle
  verification pipeline: signatures, Merkle proofs, chain continuity. `verifyChainBoundary` is the
  cross-bundle boundary rule that `verify-set` uses (SCAN2-004).
- `src/crypto.ts` — vendored Ed25519/ECDSA-P256 primitives, byte-for-byte compatible with be's
  CryptoUtilsService (AGV-003).
- `src/jcs-canonical.ts` — vendored JSON Canonicalization Scheme, compatible with be's
  canonicalJson (AGV-030), including the `__proto__`-key canonicalization pinned against be-core
  (SCAN-AV-02).
- `src/zip.ts` — PKZIP reader/writer: `src/zip.ts:101` `export function readZip(`,
  `src/zip.ts:589` `export function writeZip(`, `src/zip.ts:773` `export function gzipDeterministic(`.
  The archive/entry size caps `src/zip.ts:71-73` `export const MAX_ZIP_` reject oversized bundles
  before full decompression.
- `src/rekor.ts` — Sigstore Rekor offline verification:
  `src/rekor.ts:85` `export function computeRekorLogIdHex(`, and
  `src/rekor.ts:648` `export function verifyRekorReceipt(`, which checks the SET signature, the
  signed checkpoint and the inclusion proof, with no network call.
- `src/platform-pubkey.ts` — PLATFORM_PUBLIC_KEY_DER_B64 / PLATFORM_PUBLIC_KEY_FINGERPRINT, the
  compiled-in trust anchor (`README.md:1040` `The platform public key this build trusts is compiled into`).
- `src/http-receipt.ts` — `src/http-receipt.ts:4` `export const HTTP_RECEIPT_VERSION`,
  `src/http-receipt.ts:32` `export function httpTargetKeyFingerprint(`,
  `src/http-receipt.ts:37` `export function httpRequestCommitment(`,
  `src/http-receipt.ts:41` `export function verifyHttpReceipt(` — verifies independently-pinned
  HTTP target receipts (`README.md:1423` `### Independently pinned HTTP target receipts`).
- `src/aibom.ts` — verifyAibomAttestation: be's attested AIBOM envelope
  (praesidia-aibom-attestation/v1), pinned tenant key (AV-0001).
- `src/proofs.ts` — AV-0010: PROOF_COMPONENTS / deriveProofs / formatProofLines map components to
  six proof types (table below).
- `src/index.ts` — the package's public export surface.

## Verification pipeline (high level)

`src/cli.ts:1129` `async function main(` reads the CLI flags and the bundle file, and calls
`src/verify.ts:1465` `export async function verifyBundle(`. That function is the load-bearing
piece described in the README's "What it verifies" section (`README.md:505` `## What it verifies`):
per-row signature checks, Merkle root/inclusion proofs, chain-continuity checks, and (unless
`--no-rekor`) Rekor receipt verification via `src/rekor.ts:648` `export function verifyRekorReceipt(`.
`src/cli.ts:1058` `async function mainVerifySet(` is the newer cross-bundle continuity entrypoint
(`verify-set`, SCAN2-004) that checks chain fields are present across a *set* of bundles rather
than one — it fails closed when chain fields are absent (pinned by a dedicated test, `f13793e`).

Component statuses (`ComponentStatus`, `verify.ts`; README "Verdict shape"):

| status | meaning | top-level effect |
|---|---|---|
| `valid` | checked, all passed | — |
| `invalid` | a check failed | `invalid` |
| `incomplete` | evidence present but insufficient (e.g. redacted) | `incomplete` |
| `unsupported` | component does not apply to this manifest version | ignored |
| `not_present` | applies, but 0 items to check (AV-0008, `withEvidenceStatus`) | ignored, unless no evidence component is `valid` → `incomplete` |

### Proof summary (AV-0010, `src/proofs.ts`)

`VerifyReport.proofs` / the six leading CLI lines. Every component is in
exactly one row (pinned by a test), so `invalid` iff some proof is `fail`.
Reduction per row: any `invalid` → `fail`; else any `incomplete` →
`incomplete`; else any `valid` → `pass`; else `not_present`.

| proof | components |
|---|---|
| `signature` | `manifest`, `rowSignatures`, `rootSignatures`, `platformAttestation` (platform-key fingerprint pin), `keyBinding` |
| `hashChain` | `chain`, `inclusionProofs`, `rekor`, `completeness`, `rootCoverage`, `integrityCheckpoints` |
| `decisionReceipt` | `decisionReceipt` |
| `policyReference` | `policyReference` |
| `evidenceIntegrity` | audit package `verification.txt` receipt (packages only), `actionEventChain`, `permitBinding`, `requestBinding`, `dispatchIntegrity`, `callerResult`, `closureLegality`, `evidenceGrade`, `actionCompleteness` |
| `targetReceipt` | `targetAck` (HTTP target receipts + target-ack grade consistency) |

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
curve other than P-256 (`README.md:1088` `rejects a missing value, a mismatch, a non-canonical key, or any EC curve`) — this prevents a key and its
self-asserted fingerprint from being changed together and silently treated as approved.

See also `docs/design/platform-key-hierarchy.md` and `docs/trust-anchor-verification.md` for the
full key-ceremony design (the latter is explicitly incomplete pending MIL-0003, the production key
ceremony — see `docs/INDEX.md`).
