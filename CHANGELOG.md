# Changelog

All notable changes to `@praesidia/audit-verifier` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
No such convention previously existed in this repo, or in either sibling published
package (`sdk`, `sdk-python`) as of this entry — this file establishes it here first.
Versioning follows [Semantic Versioning](https://semver.org/); while the package is
`0.x`, a backward-compatible capability addition bumps the minor version.

## [0.11.0] — Unreleased

### Security
- **The embedded platform-key pin is checked, not trusted** (AV-2750, audit F02).
  With no key flag, the attestation's declared fingerprint was compared against the
  pinned `PLATFORM_PUBLIC_KEY_FINGERPRINT` constant, never recomputed from the pinned
  DER. A build whose DER bytes were swapped with the constant left intact therefore
  accepted a bundle forged under the swapped-in key. The fingerprint is now always
  `sha256(DER)`, and a pin whose DER does not hash to its constant fails closed:
  `invalid` (exit 1), reason `platform_key_pin_mismatch: ...`.
- **Small-order and non-canonical Ed25519 keys and signatures are rejected
  by the verifier itself** (AV-2701). On node v24.14.0 / OpenSSL 3.5.5 an
  all-zero Ed25519 public key with an all-zero signature verifies for roughly
  1 in 4 messages, so a bundle "signed" by the identity point could verify
  green. Before calling `crypto.verify`, the public key and the signature's
  `R` are now rejected when `y` (sign bit masked) is `>= p` (RFC 8032 §5.1.3)
  or is the `y` of one of the 8 small-order points (libsodium's
  `ed25519_ref10.c` blocklist). The outcome is the existing bad-signature
  result; no new reason string. Keys and signatures produced by an honest
  signer are never small-order or non-canonical, so no existing bundle changes
  verdict.
- **Rekor `integratedTime` is now bound to the root's own time window**
  (SEC-2026-09-12 MCPSDK-01). The log's signed integration time was previously
  used only to rebuild the SET payload and was never compared to anything, so a
  bundle forged under a compromised (since-REVOKED) tenant key could be anchored
  in public Rekor *today* while claiming an old period and verify green. A
  receipt whose `integratedTime` precedes `root.signedAt`, or exceeds the anchor
  time the bundle records, by more than a fixed 24h skew allowance now fails with
  `rekor_integrated_time_out_of_window`. Roots that carry a receipt but record no
  anchor time keep their (unbounded-above) legacy behaviour, so archives anchored
  by a later backfill run still verify.
- **The platform attestation is now bound to the export it vouches for**
  (SEC-2026-09-12 MCPSDK-01). `issuedAt` may not precede `manifest.generatedAt`
  by more than 24h (`attestation_predates_manifest`). Attestations carrying the
  new optional `manifestGeneratedAt` / `manifestDigest` fields (emitted by
  current `be` exporters; `manifestDigest` = sha256 hex over the manifest's
  canonical *signable* bytes) are verified against this manifest and fail closed
  on mismatch (`attestation_manifest_binding_mismatch`). Attestations without
  those fields remain **valid** but are flagged `attestation_unbound_legacy`,
  which the CLI surfaces as an explicit `NOTE:` — they attest the org key set,
  not this specific export.

### Added
- **Offline RFC 3161 timestamp verification on Merkle roots** (AV-0019). An
  `anchorReceipts` entry with `provider: 'rfc3161'` (base64 DER TimeStampToken,
  produced by be BE-1960) is now verified offline instead of failing as
  `unknown_provider`: strict DER, SHA-256 imprint = `rootHash`, CMS signature,
  ESS signer binding, critical timeStamping EKU, chain to a pinned QTSP or a
  `--tsa-cert` anchor valid at `genTime`, and `genTime` inside the root's time
  window. New `VerifyReport.rfc3161` per-root rows and `VerifyOptions.tsaTrustAnchorsPem`.
  No QTSP is pinned yet, so a token verifies only with `--tsa-cert`; without one
  it fails closed (`no_tsa_trust_anchor`).
- **Tenant signature format 2 and manifest v7** (AV-0018, ADR-0004 / DECISION-SEC-03, be BE-1957).
  Each signature slot (manifest, row, Merkle root, supersession link, integrity checkpoint,
  protected-action event, retention seal) verifies `signatureFormat: 2` signatures over
  `"praesidia:<purpose>:v2\n" || payload` with the slot's fixed purpose, so a signature minted
  for one purpose fails in every other slot. A v7 manifest signs `signatureFormat` and
  `signatureFormatCutoverAt`; a format-1 signature dated at or after the cutover fails
  (`signature_format_downgrade`), and any format other than 1 or 2 fails
  (`signature_format_unsupported`). A missing `signatureFormat` is 1, so v1–v6 bundles verify
  unchanged. The manifest ceiling is now 7.
- **`--trust-anchor <file>` and the `UNANCHORED` verdict** (AV-0017, be BE-1800). The CLI
  accepts a local copy of be's `/.well-known/praesidia-audit-keys.json`; the attestation's
  declared platform key must be listed (else `trust_anchor_key_not_found`) and valid at its
  `issuedAt` (else `trust_anchor_key_not_valid_at_issuedAt`), both exit 1. A malformed or
  self-inconsistent document, a URL (the CLI never fetches), or combining it with
  `--platform-key` is exit 2. Library: `parsePlatformTrustAnchor` + `VerifyOptions.platformTrustAnchor`.
  **Verdict change:** a bundle verified with no trust anchor at all (no build-time pin, no
  `--trust-anchor`, no `--platform-key`) was `invalid`/exit 1; it is now top-level
  `status: 'unanchored'` (`ok: false`), exit 5, with `platformAttestation` `incomplete` /
  `platform_key_not_pinned`; `verify-set` gains `bundle_unanchored` (exit 5). Never a pass;
  `invalid` still wins. Library callers that treated only `status === 'invalid'` as failure must
  check `ok` (always false here). A malformed attestation with no anchor is now reported as
  `malformed` (invalid) instead of `platform_key_not_pinned`.
- **Manifest v6: the declared evidence privacy mode** (AV-0013, be BE-1615).
  `MAX_SUPPORTED_MANIFEST_VERSION` 5 → 6. The signed `evidencePrivacy` timeline joins the
  manifest preimage (16 fields). New `report.evidencePrivacy`: per mode window, what the
  bundle proves and what it cannot, plus an annotation for every `payload: null` action
  event. No status changes: a declared reduced mode keeps `incomplete` as `incomplete` and
  only adds `reason: "evidence_privacy_mode:<MODE>"`. v1–v5 bundles verify exactly as
  before and read as `FULL (undeclared)`. A malformed or unknown-schema declaration is a
  bundle-format error.
- **Superseding Merkle roots** (AV-0016). New optional root fields `supersedesRootId`
  and `supersessionSignature`, the exported constant `ROOT_SUPERSESSION_VERSION`, and
  `ComponentResult.supersessions` on `rootCoverage` (all additive). A partial root
  plus a signed superseding root for the same hour now verifies, and both roots are
  reported. An unsigned, re-pointed, non-increasing, period-mismatched, branching or
  row-dropping link fails. Bundles without the fields verify exactly as before.
  Older verifiers fail such bundles closed. The wire contract is in README "Root
  coverage" and `.claude/backlog/AV-0016.md`.
- `docs/COMPATIBILITY.md` (AV-0012) — which verifier version reads which bundle
  manifest, audit package, decision disclosure, HTTP receipt and AIBOM formats, and
  its minimum Node version. Each current-row cell cites the code that decides it.
  `src/__tests__/compatibility.spec.ts` fails on drift. No verifier code change.
- `samples/` (AV-0011) — valid, corrupted and wrong-key audit packages plus the
  sample platform PUBLIC key, signed with TEST keys only (SAMPLE — NOT A PRAESIDIA
  KEY), generated deterministically by `scripts/make-sample-bundles.mjs`; README
  "Try it in 60 seconds". No verifier code change.
- `praesidia-verify aibom <file> --tenant-key-fingerprint <sha256hex>` and
  `verifyAibomAttestation()` (AV-0001) — offline verification of `be`'s attested
  AIBOM export (`praesidia-aibom-attestation/v1`) with `be`'s verdict set, plus three
  fail-closed checks `be`'s reference verifier does not make: the embedded key must
  match a caller-supplied pin (`untrusted_key`), envelope identity must match the
  signed document (`envelope_mismatch`), and the file must be the exact canonical
  export (`non_canonical_encoding`). New surface only; bundle verification unchanged.
- AIBOM pin from a verified bundle (AV-0002). `VerifyReport.bundle.attestedTenantKeys`
  (`keyVersion`, `status`, `fingerprint`, `attestedAt`) and a `tenant key v<n>:` line in the human report,
  present only when the platform attestation verified. `praesidia-verify aibom <file>
  --audit-bundle <bundle.zip> [bundle options]` and `aibomTrustFromBundle(report)` take the pin
  from a bundle only when its report is `valid` and platform-attested. They pin its non-REVOKED
  keys and require the AIBOM's signed `organizationId` to equal the bundle org. The new optional
  `AibomVerifyOptions.organizationId` enforces that as `untrusted_key`. Additive: existing
  bundles verify exactly as before, and an unset `organizationId` changes nothing.
- `--platform-key-fingerprint <sha256hex>` (SEC-2026-09-12 MCPSDK-03) — pins the
  `--platform-key` file to a digest obtained through a second channel; mismatch
  exits 2. The CLI now also prints a `WARNING:` line on every run that supplies
  `--platform-key`, since with a caller-supplied anchor the attestation's own
  fingerprint check is a tautology.
- `verifyHttpReceipt`, `httpRequestCommitment`, and `httpTargetKeyFingerprint`,
  exported from `src/http-receipt.ts` — offline Ed25519 verification of
  HTTP-receipt-backed protected-action evidence (the `commitments-only.v1`
  evidence shape), independent of Praesidia's servers.
- `src/jcs-canonical.ts` — RFC 8785-style JSON Canonicalization Scheme (JCS)
  implementation used by the new HTTP-receipt verification path.
- `verifiedHttpTarget` wiring in `src/verify.ts` so bundle verification now
  covers the new HTTP-receipt evidence type end-to-end, called from
  `verifyTargetAck`.
- `scripts/contract-drift.mjs` check [H] (AV-0003): fails CI when `be`'s
  `AibomAttestationEnvelope` / `AIBOM_SIGNING_DOMAIN` and `src/aibom.ts` disagree on
  the format or domain string, the envelope field set, or the `signingAlgorithm` set.
  `test-fixtures/aibom/` regenerated from `be` DOCS-0590 (9-step procedure; since then
  `be`'s reference verifier also makes the `untrusted_key` and `envelope_mismatch`
  checks). The previous 7-step exports are kept in `archive-7-step/` and still verify.
  Verification behaviour unchanged.
- `be`'s AIBOM anchor labels (AV-0004, be BE-0738): `anchorReference`, `anchorStatus`,
  `anchoredAt` and `anchorReason` are declared unauthenticated. They are the server-resolved
  anchor status, outside the signed document. They do not change the verdict, and no report
  field describes an AIBOM anchor. The `aibom` human output lists them among the unsigned fields
  and adds `NOTE: AIBOM anchoring was NOT checked`. Verification behaviour unchanged.
  Superseded in this release by AV-0005.
- Offline AIBOM anchor verification (AV-0005, be BE-1255). For a verified AIBOM,
  `anchorProof` is checked with `be`'s procedure A2-A10. The checks cover the signed
  anchor-request row, its Merkle inclusion proof and signed root (pinned tenant keys), and the
  root's Rekor receipt against a pinned log key. `AibomVerifyReport` gains `anchorStatus`
  (`verified_rekor` | `unverified`), `anchoredAt` (the log's signed `integratedTime`) and
  `anchorReason`, with verdicts and reasons equal to `be`'s. `AibomVerifyOptions` gains
  `rekorPublicKeysPem`, which defaults to the pinned Sigstore key. The four `anchor*` labels leave
  `AIBOM_UNAUTHENTICATED_FIELDS`: each must now agree with the proof. The `aibom` human output
  prints `anchor: verified_rekor at <time>` or `anchor: UNVERIFIED (<reason>)` instead of the
  NOTE. Exit codes are unchanged.

- **`not_present` component status (AV-0008).** A component that applies but found
  nothing to check (`ok` with `checked: 0`) now reports `status: 'not_present'` (CLI
  `[NOT_PRESENT]`) instead of `valid`, so `[VALID] target ack 0 checked` no longer
  claims evidence that is absent. `not_present` is excluded from the top-level
  reduction, except that a bundle where **no** evidence component is `valid` (zero
  rows, zero roots, no action events) is `incomplete` (exit 3), not `valid`.
  `manifest`, `completeness` and `keyBinding` never report it.
- **`praesidia-verify <audit-package.zip>` (AV-0007).** A zip with
  `evidence/audit-bundle.zip` and no `manifest.json` (be's audit package) is verified
  directly. The inner bundle's SHA-256 and byte count must match `verification.txt`
  (mismatch or an unparseable receipt → `invalid`, exit 1; receipt missing →
  `incomplete`, exit 3), then the inner bundle is verified exactly as a direct bundle.
  The report gains `package: {status, sha256Matches, byteCountMatches, reason?,
  sideArtifacts[]}` and a `package:` line; every other package entry is listed as an
  unsigned side artifact, never verified. Library: `verifyAuditPackage()`,
  `isAuditPackage()`. Additive: a direct bundle verifies byte-for-byte as before (the
  `verify-set` and `aibom --audit-bundle` inputs still take the inner bundle only).
- **Decision receipts and policy references (AV-0009).** New components
  `decisionReceipt` and `policyReference` over be BE-1585's unsigned
  `evidence/decision-receipts.ndjson`: each line must open the signed
  `detailsCommitment` of the bundle's `POLICY_DECISION`/`POLICY_VIOLATION` row it
  names (`invalid` on mismatch, a foreign row, an unknown version or an unparseable
  line; withheld rows counted; no file → `not_present`). Read from audit packages
  automatically (no longer listed as a side artifact), or `--disclosures <ndjson>`
  for a bare bundle; `--decision <id>` prints one verified decision (exit 1 unless
  disclosed and the report is `valid`). Library: `VerifyOptions.decisionDisclosures`,
  `VerifyReport.decisionReceipt` / `.policyReference` / `.decisionDisclosures?`,
  `findVerifiedDecision()`. Additive: every existing bundle and pre-BE-1585 package verifies
  with the same verdict (both components `not_present`).
- **Per-proof summary (AV-0010).** `VerifyReport.proofs` reduces the components into
  six auditor-facing proofs (`signature`, `hashChain`, `decisionReceipt`,
  `policyReference`, `evidenceIntegrity`, `targetReceipt`), each `pass` / `fail` /
  `not_present` / `incomplete`; every component maps to exactly one proof
  (docs/ARCHITECTURE.md), so `status: 'invalid'` iff some proof is `fail`. The human
  report now opens with six `PASS|FAIL|NOT_PRESENT|INCOMPLETE <proof>` lines ahead of
  the unchanged component detail; `--summary` prints only those lines, `RESULT:` and
  the caveats. Library: `formatProofLines()`, `PROOF_COMPONENTS`, `ProofType`,
  `ProofStatus`. No check, verdict, exit code, `RESULT:` line or `--quiet` output
  changed.

### Changed
- **`includeUnrooted=true` bundles verify as `incomplete` (exit 3), not `invalid`**
  (AV-0032, DECISION-AV-UNROOTED). The be exporter writes a `{ rowId, status:
  'not_yet_rooted' }` stub for each row in an hour it has not rooted yet, and the
  verifier failed every stub, so an honest export read as tampering. A stub is now
  accepted only for the **unrooted tail**, meaning rows signed at or after the latest bundled
  root's `periodEnd` (the root set is bound by the signed manifest's `rootCount`). It
  makes `inclusionProofs` `incomplete` with `failed: 0`, `firstFailure` = the first
  unrooted row, and reason `not_yet_rooted: N of M row(s) have no inclusion proof yet
  — …`. The top-level verdict is `incomplete` unless another component fails.
  `verify-set` reports `bundle_incomplete` (exit 3). These cases stay `invalid`: a
  stub on a row inside a published root's period, a stub in a rooting gap before a
  later root, a stub with fields beyond `rowId`/`status`, a stub for an absent row,
  a duplicate, any other status, and any row-signature or chain failure in the tail.
  No new status, exit code or export.

### Fixed
- **`praesidia-verify verify <bundle.zip>` now works** (AV-0006). It is the command
  every `be` audit package's `verification.txt` and the ui proof page tell the auditor
  to run, but the CLI only knew `<bundle.zip>`, `verify-set` and `aibom`, so it exited 2
  (`only one bundle path may be supplied`). A leading `verify` is now an exact alias of
  single-bundle mode (same checks, report and exit codes), which fixes every package
  already handed out. No verification check changed. A bundle file literally named
  `verify` in the working directory must now be passed as `./verify`.

### Packaging
- **Publish readiness** (INTEG-0054). `publishConfig.provenance: true` makes npm refuse a
  publish that cannot attach an OIDC provenance statement, so only the tagged CI workflow
  can release. The build no longer emits `.js.map` / `.d.ts.map` files: they pointed at
  `../src/*.ts`, which is not in the tarball, and were a third of its unpacked size. The README install section is now the post-publish command. No
  verification check, export or CLI behaviour changed.
- **Toolchain on latest** (AV-0030): TypeScript 7, Vitest 5, `@types/node` 22 (the
  `engines` floor, so typecheck rejects APIs newer than Node 22), Docker base
  `node:26.10.0-alpine3.24`, CI matrix Node 22/24/26. Emitted JavaScript is byte-identical
  to the TypeScript 5.9 build; `.d.ts` files differ only in quote style.
- **`gzipDeterministic` output is now identical on every OS** (AV-0030). zlib stamps the
  build OS in gzip header byte 9 (macOS 19, Linux 3), so `samples/` regenerated on Linux
  never matched the macOS-built files and the drift test failed there. The byte is now
  pinned to 3 and the three sample packages were regenerated. The verifier reads that
  byte nowhere; no verification check changed.
- **The test suite now builds `dist/` first** (AV-0031). Six specs run `dist/cli.js` and
  the samples drift test regenerates from `dist/*.js`, so after a source change without a
  rebuild they silently tested old code. `vitest.config.mjs` runs `tsc` as a globalSetup,
  and a compile error fails the run.
- **`check:release-fixture`** (AV-2750, audit F02): `scripts/assert-release-fixture.mjs`
  unpacks the `npm pack` tarball and runs its CLI with no key flag. The genuine production
  fixture (`PRAESIDIA_RELEASE_FIXTURE`) must exit 0 and a byte-flipped copy must exit
  non-zero. `publish.yml` runs it after `npm pack`; an unset fixture blocks the release.
  Not in `prepack`. Self-tested on a sample-pinned `npm pack` build.

### Compatibility
- AV-2750 tightens verification only for a build whose embedded DER and fingerprint
  disagree, which `check:trust-anchor-ci` and `prepack` already refuse to build. No bundle
  changes verdict under a consistent pin, `--platform-key` or `--trust-anchor`.
- AV-0032 is a **scoped strictness relaxation from `invalid` to `incomplete`**, never to
  `valid`. It applies only to well-formed `not_yet_rooted` stubs in the unrooted tail.
  Such a bundle moves from exit 1 to exit 3. Every bundle without stubs gets
  byte-identical results. Every other stub keeps failing, with a more specific reason
  for `not_yet_rooted` stubs outside the tail. Consumers that treat any non-zero exit
  as "not verified" are unaffected. Consumers that treat exit 1 as "the bundle was
  exported with includeUnrooted" must switch to exit 3 / `inclusionProofs.status ===
  'incomplete'`.
- AV-0010 changes no verification strictness. `VerifyReport.proofs` is a new required
  field: code that *builds* a `VerifyReport` must add it; readers are unaffected. The
  default human report gains six leading lines, so a parser keyed on line numbers (not
  on `RESULT:` or component labels) must adjust. `--quiet` still prints one word.
- AV-0008 is a **strictness increase** and a new enum value. JSON / library consumers that
  switch exhaustively on `ComponentStatus` must handle `'not_present'`; a 0-checked
  component's derived `ok` is now `false`. Top-level verdicts are unchanged for every bundle
  that carries any rows, roots or action events; a zero-evidence bundle moves from `valid`
  (exit 0) to `incomplete` (exit 3), and so does a `verify-set` containing one, and
  `aibomTrustFromBundle` no longer accepts one as a pin source.
- AV-0005 adds verification without weakening any. The anchor is informational: `valid`, the
  verdict and the exit status are computed exactly as before. An AIBOM without `anchorProof`
  (every export before BE-1255) verifies as before and reports `unverified` /
  `aibom_not_anchored`. `AibomVerifyReport.anchorStatus` is a new required field, so code that
  *builds* such a report object must add it. Code that only reads reports is unaffected.
- The two new time bindings above are a deliberate **strictness increase**. They
  are additive for every genuine bundle (a real anchor is integrated after the
  root is signed and at/near the recorded anchor time; a real attestation is
  issued for the export it accompanies), and the legacy shapes that cannot carry
  the evidence — receipts with no recorded anchor time, attestations with no
  manifest binding — are explicitly preserved rather than rejected. A bundle that
  now fails one of these checks was always evidence of a backdated artefact.
- Fully backward compatible. `src/verify.ts` branches on
  `proposal.payload.evidenceContent === 'commitments-only.v1'` for the new
  producer shape and keeps the pre-existing body-bearing shape in the `else`
  branch, requiring exact field matches and failing closed on any mismatch or
  exception. Existing (pre-HTTP-receipt) audit bundles continue to verify
  exactly as before — no migration is required to keep verifying archives
  produced before this change.
