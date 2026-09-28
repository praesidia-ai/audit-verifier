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
- `scripts/trust-anchor-policy.selftest.mjs` exercises the placeholder, partial-edit, malformed,
  wrong-curve, wrong-fingerprint, missing-approval, mismatch, and valid P-256 cases in ordinary CI.
- Confirm what shipped in a specific release with a registry query independent of `npm install`:
  `npm view @praesidia/audit-verifier@<version> --json | jq .dist` gives you the tarball hash;
  unpacking that tarball and inspecting `dist/platform-pubkey.js` gives you the exact bytes this
  build trusts.

## Second channel — where to compare it against

**USER-OWED, pending the production key ceremony (MIL-0003).** As of this writing
`PLATFORM_PUBLIC_KEY_DER_B64` / `PLATFORM_PUBLIC_KEY_FINGERPRINT` are intentionally empty (the
verifier reports every bundle verified without `--trust-anchor`/`--platform-key` as `UNANCHORED`,
exit 5, reason `platform_key_not_pinned` — correct, not a bug) and
there is deliberately **no URL published here yet**: a customer-facing document must never point
an auditor at a channel that does not exist. Once the ceremony lands, publish the exact
fingerprint on infrastructure that is:

1. **Not the npm registry** — the registry is one of the two things this channel exists to
   cross-check, so it cannot vouch for itself.
2. **Not `be-core`'s deploy pipeline** — the platform key and the application deploy share
   enough infrastructure that a deploy-pipeline compromise should not silently also compromise
   the channel meant to catch it.

Two concrete candidates already scoped (pick one, or both, when the ceremony happens):

- A static page hosted on infrastructure operated separately from both of the above (e.g. a
  security/trust-center subdomain with its own deploy credentials), stating the current
  `PLATFORM_PUBLIC_KEY_FINGERPRINT` in plain text alongside its `validFrom` date.
- The `security.txt` contact response (RFC 9116) — an auditor emails the listed security
  contact and receives the fingerprint back through a human-mediated channel, which is slower
  but harder for a single compromised system to spoof.

Whichever is chosen, put its exact URL/contact **in this file and in `README.md`'s "Trust
anchor" section together**, in the same commit that pins the real key — never publish one
without the other, or the pin exists with nothing to check it against.

## Production release handoff

The remaining input is one operator-approved production P-256 public key; private key material
must stay inside KMS. The release operator must complete all of these views of that same input:

1. Fetch the SPKI public bytes directly from the production KMS key during the approved ceremony.
   Put the canonical base64 bytes and their lowercase SHA-256 fingerprint in
   `src/platform-pubkey.ts`.
2. Confirm the fingerprint through the independent channel above. A second operator then enters
   that independently confirmed value into the protected `audit-verifier-production` Environment
   variable `PRODUCTION_PLATFORM_KEY_FINGERPRINT`. Do not derive or copy this approval value from
   the source diff under review; that would collapse two trust inputs back into one.
3. Require reviewers on that Environment and protect release tags with the repository ruleset.
   Repository configuration is operator-owned and cannot be made trustworthy by a file in the
   repository itself.
4. Push a version tag only after the key-bearing commit and independent publication are approved.
   The tagged commit must be contained in `main`. The workflow builds and tests from that tag,
   runs the release assertion explicitly and again during both dry-run pack and publish, and
   publishes with npm provenance.

The ordinary PR check intentionally permits the documented pair of empty constants so development
can continue before the ceremony. That is not a release bypass: `prepack` always runs the stricter
policy, where the empty pair and a missing operator approval both fail closed. Do not use
`--ignore-scripts` for a release.

## What to actually compare

Byte-for-byte match `PLATFORM_PUBLIC_KEY_FINGERPRINT` from the installed tarball (see above)
against the fingerprint published on the second channel. A mismatch means one of the two is
compromised or you installed a tampered package — treat it as a security incident, not a bug
report against this tool.
