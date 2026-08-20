# DESIGN — platform key hierarchy (offline root + rotating operational keys)

MIL-0002 item 3. **Design only — not built.** This is the in-repo copy of record; the original
was drafted at `.claude/tickets/DESIGN-platform-key-hierarchy.md` (internal ticket tracking,
not part of this package's Git history) and is mirrored here so it ships with the source tree
an engineer would actually be looking at, survives ticket-tracking cleanup, and is visible to
anyone auditing the public repo — not just whoever has access to internal tickets. Keep both in
sync until DoD 3 sign-off; this file is authoritative if they ever diverge.

Building this is a two-repo change (`be` mints/rotates, `audit-verifier` pins/verifies) and
touches the bundle wire format, so it needs `backend-dev` + `audit-verifier-dev` sign-off before
implementation, and should land after MIL-0003 (platform key into KMS) rather than before — no
sense hardening rotation for a key that is still a plaintext env var.

## Problem this solves

Today (`src/platform-pubkey.ts`) there is exactly one platform public key pinned into the
verifier, hard-coded, with no expiry and no revocation path. Per that file's own docblock:
rotating the platform key means cutting a new `@praesidia/audit-verifier` release and every
auditor updating *before* verifying any bundle signed under the new key. There is no way to:

1. Rotate routinely (e.g. annual key hygiene) without a CLI release + universal auditor upgrade.
2. Revoke a *compromised* operational key in-band — an attacker who steals the platform signing
   key can mint attestations for every org, forever, until Praesidia ships a new CLI and every
   auditor in the world happens to upgrade before verifying the next bundle.
3. Distinguish "old bundle, signed under a since-rotated-but-not-compromised key" (should still
   verify) from "bundle signed under a revoked/compromised key" (should fail) — today there is
   only one key, so this distinction doesn't exist yet.

## Design: two-tier hierarchy, offline root cross-signs operational keys

```
Offline ROOT keypair (Ed25519 or P-256, air-gapped / HSM-backed, generated once)
   │
   │  cross-signs (root_signature over operational pubkey + validity window + keyId)
   ▼
Operational platform keypair(s) — 1 ACTIVE + up to N-1 ROTATED/REVOKED, KMS-held (MIL-0003)
   │
   │  signs
   ▼
platform-attestation.json (per-bundle, as today)
```

### New wire artifact: `platform-key-hierarchy.json` (bundled with the CLI, NOT the bundle)

Ships *inside the npm package* (like `platform-pubkey.ts` today), not inside each customer
bundle — the hierarchy is CLI-side trust configuration, refreshed by a CLI release, same
distribution model as today's single pin. Shape:

```ts
interface PlatformKeyHierarchy {
  rootPublicKeyDerB64: string;        // the ONE thing that never rotates without a corrigendum
  rootFingerprint: string;            // sha256 hex of rootPublicKeyDerB64
  operationalKeys: Array<{
    keyId: string;                    // e.g. "plat-2027-01"
    publicKeyDerB64: string;
    fingerprint: string;
    validFrom: string;                // ISO8601
    validUntil: string | null;        // null = still active
    status: 'ACTIVE' | 'ROTATED' | 'REVOKED';
    revokedAt: string | null;
    rootSignature: string;            // root's signature over
                                       // canonicalJson({keyId, publicKeyDerB64, validFrom, validUntil})
  }>;
}
```

### Verification rule (additive to today's `verifyPlatformAttestation`)

1. Resolve `platform-attestation.json`'s declared `keyId` (new field, additive — see Wire
   change below) to an entry in `operationalKeys`.
2. Verify `rootSignature` over that entry under `rootPublicKeyDerB64` — this is what makes the
   operational key trustworthy without the CLI having pinned it directly.
3. Verify the attestation's own signature under that operational key's `publicKeyDerB64` — same
   as today's single-key check.
4. Apply the SAME signed-before-revocation-window rule the tenant-key path already uses
   (`verifyKeyBinding`'s existing precedent, PROD15): an attestation signed while the
   operational key was `ACTIVE` and within `[validFrom, validUntil)` verifies even after later
   rotation; one signed after `revokedAt` (compromise, not routine rotation) fails closed
   unconditionally — mirrors `verifyManifest`'s existing REVOKED-key rule, no new precedent.
5. **Revocation is in-band, but only for auditors who have upgraded — this is the hard offline
   constraint, and it does not fully go away.** Publishing a new `platform-key-hierarchy.json`
   with an operational key's `status` flipped to `REVOKED` and cutting a CLI patch release
   closes the hole for anyone who installs that release. An offline verifier, by construction,
   cannot fetch a live CRL or an OCSP-style status check — there is no network call in the
   verification path, full stop (see repo-level rule). So an auditor running an
   **already-installed, not-yet-upgraded** CLI will still accept a bundle signed by a
   since-revoked operational key: the revocation is expressed entirely inside the *next*
   `platform-key-hierarchy.json` shipped with the *next* CLI release, not inside anything the
   already-running binary can see. **State this limitation to customers plainly, not
   hand-waved**: the guarantee this design buys is bounding the blast radius of an operational-key
   compromise to "every bundle signed with that key, verified by every CLI that hasn't updated
   yet" instead of today's "every bundle ever, forever, until a human hand-patches the single
   pin and republishes" — it does not achieve real-time revocation for an offline tool, because
   no offline tool can. The mitigations available are procedural, not cryptographic: (a) keep the
   window between compromise-detection and CLI-release short, (b) have `be`'s own live
   verification path (which IS online) refuse to mint anything under a key already marked
   `REVOKED` in this same hierarchy file, closing the hole for all *newly exported* bundles
   immediately even before the CLI ships, and (c) document the residual risk in the CLI's own
   `--version`/`RESULT: OK` output once built, so a customer's security reviewer sees "verified
   against key hierarchy dated X" rather than an unqualified pass.

### Wire change (additive, non-breaking — matches MIL-0003's own framing)

`platform-attestation.json`'s `PlatformAttestationBody` gains one optional field:

```ts
interface PlatformAttestationBody {
  // ...existing fields...
  keyId?: string; // NEW — selects the operationalKeys[] entry. Absent = legacy single-key path
                   // (today's PLATFORM_PUBLIC_KEY_DER_B64 pin), so old bundles keep verifying
                   // with no migration required.
}
```

`platformKeyVersion` (MIL-0003, messaged separately) is a DIFFERENT axis — it is the *tenant*
signing-key version already carried in `keyVersions[]`; `keyId` here is the *platform*
attestation key selector. They are independent fields and must not be conflated when MIL-0003's
shape lands; this design assumes `keyId` is added alongside whatever `platformKeyVersion` turns
out to be, and the two should be reviewed together when MIL-0003 messages the final attestation
shape.

### Why this design over the alternative (N pinned keys, no root)

Considered: just pin an *array* of currently-valid operational keys directly into the CLI,
skip the root entirely. Rejected — it doesn't solve the actual problem: adding a NEW
operational key still requires a CLI release either way, so the root buys nothing... **except**
it does: with a root, Praesidia can mint and start using a new operational key immediately
(signed by the root, which every CLI already trusts) and only needs a CLI release to
*revoke* a compromised one, not to *add* a routine one — routine rotation stops being a
forced-upgrade event, revocation still is (and arguably should be, since a revocation the
CLI doesn't know about yet is the residual risk any offline-pinned trust root has, spelled out
above rather than implied).

### Non-goals / explicitly out of scope for this design

- Does not change `verifyRowSignatures`/`verifyRootSignatures`/tenant key rotation — those
  already have a working per-tenant `status`/`revokedAt` model (PROD15); this design only adds
  the missing layer above the single platform key.
- Does not attempt a threshold/multi-sig root (M-of-N root signers) — a real improvement, but a
  separate hardware/ceremony decision for whoever runs the actual key ceremony, orthogonal to
  the wire format this design fixes.
- Does not touch RFC 9421 / SCITT interop (parked, `PLAN-milspec-nodrift.md`'s "not attempted"
  list) — this hierarchy is Praesidia-internal trust plumbing, not a standards-interop surface.
- Does not attempt real-time revocation for an already-installed CLI — see the hard limitation
  spelled out in step 5 above. No design can offer this for a tool with zero network calls; a
  design that implies otherwise would be lying to auditors about what "offline" costs.

## Rollout sequencing

1. MIL-0003 lands (platform key in KMS, `platformKeyVersion` messaged to `audit-verifier-dev`).
2. This design reviewed jointly by `backend-dev` + `audit-verifier-dev`, `keyId` finalized
   against whatever MIL-0003 actually shipped.
3. Generate the offline root (human key ceremony — same class of user-only action as pinning
   `PLATFORM_PUBLIC_KEY_DER_B64` itself; not autonomous).
4. `be` cross-signs the (now-KMS-held) operational key under the root, adds `keyId` to
   `platform-attestation.json`, and gains the live-side revocation check (mitigation (b) above).
5. `audit-verifier` ships `platform-key-hierarchy.json` + the additive verification rule above,
   still accepting legacy (no-`keyId`) attestations under the single pin for backward
   compatibility with bundles exported before this lands.
