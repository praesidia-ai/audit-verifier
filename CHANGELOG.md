# Changelog

All notable changes to `@praesidia/audit-verifier` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
No such convention previously existed in this repo, or in either sibling published
package (`sdk`, `sdk-python`) as of this entry — this file establishes it here first.
Versioning follows [Semantic Versioning](https://semver.org/); while the package is
`0.x`, a backward-compatible capability addition bumps the minor version.

## [0.11.0] — Unreleased

### Security
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

### Compatibility
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
