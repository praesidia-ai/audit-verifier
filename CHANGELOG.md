# Changelog

All notable changes to `@praesidia/audit-verifier` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
No such convention previously existed in this repo, or in either sibling published
package (`sdk`, `sdk-python`) as of this entry — this file establishes it here first.
Versioning follows [Semantic Versioning](https://semver.org/); while the package is
`0.x`, a backward-compatible capability addition bumps the minor version.

## [0.11.0] — Unreleased

### Added
- `verifyHttpReceipt`, `httpRequestCommitment`, and `httpTargetKeyFingerprint`,
  exported from `src/http-receipt.ts` — offline Ed25519 verification of
  HTTP-receipt-backed protected-action evidence (the `commitments-only.v1`
  evidence shape), independent of Praesidia's servers.
- `src/jcs-canonical.ts` — RFC 8785-style JSON Canonicalization Scheme (JCS)
  implementation used by the new HTTP-receipt verification path.
- `verifiedHttpTarget` wiring in `src/verify.ts` so bundle verification now
  covers the new HTTP-receipt evidence type end-to-end, called from
  `verifyTargetAck`.

### Compatibility
- Fully backward compatible. `src/verify.ts` branches on
  `proposal.payload.evidenceContent === 'commitments-only.v1'` for the new
  producer shape and keeps the pre-existing body-bearing shape in the `else`
  branch, requiring exact field matches and failing closed on any mismatch or
  exception. Existing (pre-HTTP-receipt) audit bundles continue to verify
  exactly as before — no migration is required to keep verifying archives
  produced before this change.
