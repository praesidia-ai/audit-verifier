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
  publishable artifact unless both constants are non-empty, internally consistent (fingerprint
  matches DER bytes), and the key is EC — see that script for the exact checks.
- Confirm what shipped in a specific release with a registry query independent of `npm install`:
  `npm view @praesidia/audit-verifier@<version> --json | jq .dist` gives you the tarball hash;
  unpacking that tarball and inspecting `dist/platform-pubkey.js` gives you the exact bytes this
  build trusts.

## Second channel — where to compare it against

**USER-OWED, pending the production key ceremony (MIL-0003).** As of this writing
`PLATFORM_PUBLIC_KEY_DER_B64` / `PLATFORM_PUBLIC_KEY_FINGERPRINT` are intentionally empty (the
verifier fails closed with `platform_key_not_pinned` on every bundle — correct, not a bug) and
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

## What to actually compare

Byte-for-byte match `PLATFORM_PUBLIC_KEY_FINGERPRINT` from the installed tarball (see above)
against the fingerprint published on the second channel. A mismatch means one of the two is
compromised or you installed a tampered package — treat it as a security incident, not a bug
report against this tool.
