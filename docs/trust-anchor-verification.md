# Trust-anchor verification — confirming the CLI's embedded pin out-of-band

MIL-0002 item 5. This document is the fingerprint's **published location**: where an auditor
looks to confirm the platform public key compiled into this CLI is the real one, without taking
this package's own word for it. It exists because an npm-registry or CI-supply-chain compromise
of *this package* is exactly the attack a customer's second channel should catch — see
`README.md`'s "Trust anchor" section, which this file expands on.

## Where the pin lives in this CLI

- `src/platform-pubkey.ts` exports `PLATFORM_PUBLIC_KEY_DER_B64` and
  `PLATFORM_PUBLIC_KEY_FINGERPRINT` (SHA-256 hex of the DER bytes). These are compiled into the
  published `dist/platform-pubkey.js` — not fetched at verify time.
- `scripts/assert-release-trust-anchor.mjs` (the package's `prepack` hook) refuses to build a
  publishable artifact unless both constants are non-empty, the DER is one canonical P-256 SPKI
  public key, its SHA-256 fingerprint is canonical and internally consistent, and that fingerprint
  exactly matches the separately supplied operator approval. A different EC curve is not accepted.
- `.github/workflows/publish.yml` obtains that approval only from
  `PRODUCTION_PLATFORM_KEY_FINGERPRINT` in the `audit-verifier-production` GitHub Environment and
  passes it as `PRAESIDIA_RELEASE_APPROVED_PLATFORM_KEY_FINGERPRINT`. Configure the Environment
  with required reviewers. An absent, malformed, uppercase, stale, or mismatched value blocks both
  `npm pack` and `npm publish`; there is no source-code fallback.
- After `npm pack`, `publish.yml` runs `npm run check:release-fixture`
  (`scripts/assert-release-fixture.mjs`, shipped in the package). It runs the packed CLI with no
  key flag: the genuine production fixture, committed at
  `release-fixture/production-audit-package.zip` in the source repository, must exit 0, and the
  same bundle with its platform attestation re-signed under a foreign key must exit 1 with a
  `signature: ` reason. Otherwise the release stops before upload and publish. Set
  `PRODUCTION_RELEASE_FIXTURE_NO_REKOR=1` only if the fixture carries no Rekor anchor.
- At verify time the CLI recomputes the fingerprint from the embedded DER and fails closed
  (`platform_key_pin_mismatch`) if it differs from `PLATFORM_PUBLIC_KEY_FINGERPRINT`.
- `scripts/trust-anchor-policy.selftest.mjs` exercises the placeholder, partial-edit, malformed,
  wrong-curve, wrong-fingerprint, missing-approval, mismatch, and valid P-256 cases in ordinary CI.
- Confirm what shipped in a specific release with a registry query independent of `npm install`:
  `npm view @praesidia/audit-verifier@<version> --json | jq .dist` gives you the tarball hash;
  unpacking that tarball and inspecting `dist/platform-pubkey.js` gives you the exact bytes this
  build trusts.

## Second channel — where to compare it against

**Proposed, pending operator confirmation: the security contact in
`https://praesidia.ai/.well-known/security.txt`** (RFC 9116). An auditor emails it and asks for
the current production platform key fingerprint. A person answers, through a human-mediated
channel that is slower than a web page but harder for a single compromised system to spoof.

The other pre-listed option is a static page on infrastructure operated separately from both
items below (e.g. a security/trust-center subdomain with its own deploy credentials), stating
the current `PLATFORM_PUBLIC_KEY_FINGERPRINT` in plain text with its `validFrom` date. It is not
built. An operator confirms one, or both, and records the choice in this file and in
`README.md`'s "Trust anchor" section in the same commit.

A second channel must be:

1. **Not the npm registry** — the registry is one of the two things this channel exists to
   cross-check, so it cannot vouch for itself.
2. **Not `be-core`'s deploy pipeline** — the platform key and the application deploy share
   enough infrastructure that a deploy-pipeline compromise should not silently also compromise
   the channel meant to catch it. be's own `GET /.well-known/praesidia-audit-keys.json` is
   therefore **not** a second channel.

**Known limit of the proposed channel**, and the reason it is not yet confirmed: the praesidia.ai
website serves `security.txt`, and that website is deployed into the same AWS account as be.
Whoever controls that account controls the address the file lists, so the email answer meets
requirement 2 only if the auditor knows the address from somewhere else. The separately operated
page above does not have this limit.

## Production release handoff

The production key is pinned in `src/platform-pubkey.ts` since 0.11.0: the canonical base64 SPKI
bytes of the production P-256 KMS key, read with `kms:GetPublicKey`, and their lowercase SHA-256
fingerprint. Private key material stays inside KMS. What remains operator-owned before a release:

1. On a key rotation only: fetch the SPKI public bytes directly from the new production KMS key
   and put the canonical base64 bytes and their lowercase SHA-256 fingerprint in
   `src/platform-pubkey.ts`.
2. Confirm the fingerprint through the second channel above, once an operator has confirmed that
   channel. A second operator then enters
   that independently confirmed value into the protected `audit-verifier-production` Environment
   variable `PRODUCTION_PLATFORM_KEY_FINGERPRINT`. Do not derive or copy this approval value from
   the source diff under review; that would collapse two trust inputs back into one.
3. Require reviewers on that Environment and protect release tags with the repository ruleset.
   Repository configuration is operator-owned and cannot be made trustworthy by a file in the
   repository itself.
4. Commit the genuine production fixture at `release-fixture/production-audit-package.zip`
   (AV-2751) and configure the `NPM_TOKEN` secret.
5. Push a version tag only after the key-bearing commit and independent publication are approved.
   The tagged commit must be contained in `main`. The workflow builds and tests from that tag,
   runs the release assertion explicitly and again during both dry-run pack and publish, and
   publishes with npm provenance.

The ordinary PR check also accepts the documented pair of empty constants, the state before the
production key was pinned and of any build from source that empties it. That is not a release
bypass: `prepack` always runs the stricter policy, where the empty pair and a missing operator
approval both fail closed. Do not use `--ignore-scripts` for a release.

## What to actually compare

Byte-for-byte match `PLATFORM_PUBLIC_KEY_FINGERPRINT` from the installed tarball (see above)
against the fingerprint published on the second channel. A mismatch means one of the two is
compromised or you installed a tampered package — treat it as a security incident, not a bug
report against this tool.
