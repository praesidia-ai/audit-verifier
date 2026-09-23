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

### Compatibility
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
