# @praesidia/audit-verifier

> Offline verifier CLI for Praesidia compliance bundles. Zero runtime dependencies.

This package is a self-contained command-line tool an external auditor can
run to verify a Praesidia compliance bundle entirely offline. It does NOT
depend on `be-core` or any other Praesidia package — all required
cryptographic primitives (Ed25519, ECDSA-P256, RFC 6962 Merkle, JCS-style
canonical JSON, Rekor SET / inclusion-proof verification, PKZIP) are
vendored in `src/`.

Node.js 22.12 or newer is required.

## Install

```bash
npm install -g @praesidia/audit-verifier
praesidia-verify bundle.zip

# Or run once without installing
npx @praesidia/audit-verifier bundle.zip
```

Installing needs the network; verifying never does. Releases are published only
from the tagged CI workflow with npm provenance (`publishConfig.provenance`), so
a hand-run publish without an OIDC-backed provenance statement is refused. To
check the tarball you installed, see
[Trust anchor](#trust-anchor--verifying-the-clis-embedded-pin-out-of-band).

## Try it in 60 seconds

The package ships three sample audit packages in `samples/`, signed with
**TEST keys only** (SAMPLE — NOT A PRAESIDIA KEY; see
[`samples/README.md`](samples/README.md)). They carry no Rekor anchor, hence
`--no-rekor`; `--platform-key` is required because the CLI never trusts the
sample key on its own.

```bash
S=node_modules/@praesidia/audit-verifier/samples   # or ./samples in a checkout
npx praesidia-verify $S/audit-package.valid.zip     --platform-key $S/sample-platform-key.pem --no-rekor --summary
npx praesidia-verify $S/audit-package.corrupted.zip --platform-key $S/sample-platform-key.pem --no-rekor --summary
npx praesidia-verify $S/audit-package.wrong-key.zip --platform-key $S/sample-platform-key.pem --no-rekor --summary
```

Output of a real run (each also prints the `--no-rekor` NOTE and the
caller-supplied-key WARNING). Valid, exit 0:

```text
PASS signature
PASS hash chain
PASS decision receipt
PASS policy reference
PASS evidence integrity
NOT_PRESENT target receipt

RESULT: OK
```

Corrupted (one byte of one signed row flipped), exit 1:

```text
FAIL signature
FAIL hash chain
INCOMPLETE decision receipt
INCOMPLETE policy reference
PASS evidence integrity
NOT_PRESENT target receipt

RESULT: FAIL
```

Wrong key (platform attestation signed by another key), exit 1:

```text
FAIL signature
PASS hash chain
PASS decision receipt
PASS policy reference
PASS evidence integrity
NOT_PRESENT target receipt

RESULT: FAIL
```

## Usage

```bash
praesidia-verify <bundle.zip> [options]
praesidia-verify verify <bundle.zip> [options]   # alias of the form above
praesidia-verify <audit-package.zip> [options]   # be audit package, verified directly (AV-0007)
praesidia-verify aibom <aibom.attested.json> --tenant-key-fingerprint <sha256hex>
praesidia-verify aibom <aibom.attested.json> --audit-bundle <bundle.zip> [bundle options]
               # AIBOM attested export — see "AIBOM attestations" below

Options:
  --no-rekor   Skip the offline Sigstore Rekor receipt verification.
  --trust-anchor <file>
               A LOCAL copy of Praesidia's trust-anchor document
               (GET /.well-known/praesidia-audit-keys.json). The bundle's
               platform attestation must be signed by a key it lists, else
               FAIL (exit 1). Never fetched by the CLI; exclusive with
               --platform-key. See "Trust anchor" below.
  --platform-key <file>
               Trust this PEM or SPKI-DER platform public key. Prints a
               WARNING: the result is only as strong as that file's
               provenance.
  --platform-key-fingerprint <sha256hex>
               Require --platform-key's SPKI DER to hash to this digest,
               obtained from a channel independent of the bundle. Mismatch
               exits 2.
  --allow-legacy-unattested
               Explicitly accept a pre-attestation legacy bundle.
  --summary    Print only the six per-proof lines (see "Proof summary"),
               then RESULT and any caveat.
  --quiet      Print only the final status word (OK/FAIL/INCOMPLETE/UNANCHORED).
  --json       Print the full VerifyReport as stable machine-readable JSON
               (mutually exclusive with --quiet; --json wins if both given).
  --help       Show this help message.

Exit codes:
  0   status: valid   — all signatures, chain links, and proofs verified.
  1   status: invalid — a real verification failure.
  2   I/O or bundle-format error (malformed zip, missing file, etc.).
  3   status: incomplete — evidence present is insufficient to decide
      (distinct from a failure). Also returned for a bundle that carries no
      evidence at all (every evidence component NOT_PRESENT). The `targetAck`/`callerResult` components
      produce this when a piece of evidence was legitimately redacted
      (`payload: null` with a `payloadCommitment` present) rather than
      illegitimately stripped — see "Verdict shape" below.
  5   status: unanchored — no platform trust anchor at all (no build-time
      pin, no --trust-anchor, no --platform-key): the signing keys are the
      bundle's own claim, so origin is unproven. Never a pass; a real
      failure (exit 1) wins over it.
```

## Audit packages (AV-0007)

The audit package (`GET audit/packages/:id/download`) is an outer zip holding the
signed bundle at `evidence/audit-bundle.zip`, an unsigned `verification.txt`
receipt (its SHA-256 and byte count) and unsigned reports (PDF, JSON, CSV). Pass the
package itself: the verifier checks the receipt against the inner bundle's bytes
(mismatch or unparseable receipt → `invalid`, exit 1; receipt missing →
`incomplete`, exit 3), then verifies the inner bundle exactly as a direct bundle.
Only the inner bundle's signatures authenticate anything; every other entry is
listed under `package.sideArtifacts` as **not verified** — except
`evidence/decision-receipts.ndjson`, which is checked line by line (below).

## Decision receipts and policy references (AV-0009)

Post-cutover decision rows are signed over a `detailsCommitment`, not their
contents. The package's unsigned `evidence/decision-receipts.ndjson` (be BE-1585)
opens them: `decisionReceipt` requires each line's
`base64(sha256(salt || canonicalJson({details})))` to equal the signed
`detailsCommitment` of the `POLICY_DECISION`/`POLICY_VIOLATION` row it names
(mismatch, a row not in the bundle, an unknown version or an unparseable line →
`invalid`; withheld rows are counted, not failed; no file → `not_present`).
`policyReference` then checks each verified Decision Record's `policyId` /
`policyVersion` / `decision` (and the `approvalId` of an allow that consumed a
step-up approval) and reports the distinct policy references. It verifies the
reference only — the policy text is not in the package.

```bash
praesidia-verify audit-package.zip                          # read automatically
praesidia-verify bundle.zip --disclosures decision-receipts.ndjson
praesidia-verify audit-package.zip --decision <decisionId>  # exit 0 verified, 1 not
```

Report fields: `decisionReceipt`, `policyReference`, and `decisionDisclosures`
(`withheld`, `undisclosed`, `policyReferences[]`, `decisions[]`; present only when
`decisionReceipt` is `valid`). Contract: `docs/decision-disclosures.md`.

## Cross-bundle continuity (`verify-set`)

`be`'s exporter caps a single bundle at 90 days, so any org history longer
than that is necessarily several bundles. Verifying one bundle at a time
cannot tell you whether a whole bundle — an entire quarter — was left out
of the set an auditor was handed. `verify-set` closes that gap:

```bash
praesidia-verify verify-set <bundle1.zip> <bundle2.zip> [...] [options]
```

It sorts the given bundles by their manifest `from`, then asserts:

- the earliest bundle's chain head is a true genesis anchor (not an opaque
  range start) — otherwise either an earlier bundle is missing from the
  set, or the chain has been tampered with;
- every adjacent pair's date range is exactly contiguous — a gap or an
  overlap is reported as a named finding, never silently accepted;
- every adjacent pair's boundary is cryptographically continuous — the
  left bundle's newest-row hash-chain link must equal the right bundle's
  declared chain-head anchor, so a date-adjacent but forged/replaced
  bundle is still caught, not just a date gap.

A bundle that is itself invalid is reported as such and never downgraded
to "just a gap". Exit codes let a script tell the three outcomes apart:

```
0   status: continuous      — every bundle valid, no gap/overlap/mismatch.
1   status: bundle_invalid  — at least one bundle itself fails verification.
2   I/O or bundle-format error (including fewer than 2 bundles, or bundles
    that do not share one organizationId).
3   status: bundle_incomplete — no bundle invalid, no discontinuity found,
    but at least one bundle's own evidence was insufficient to decide.
4   status: discontinuous   — every bundle individually verifies, but the
    set has a named gap, overlap, forged boundary, or non-genesis first
    bundle.
5   status: bundle_unanchored — no bundle invalid, no discontinuity, but no
    platform trust anchor was available (see single-bundle exit 5).
```

`verify-set` accepts the same `--no-rekor` / `--trust-anchor` / `--platform-key` /
`--allow-legacy-unattested` / `--json` / `--quiet` options as single-bundle
mode, applied identically to every bundle in the set. It does not change
the single-bundle command's behaviour or exit codes in any way.

Detecting a **withheld** bundle (one never handed to the auditor at all,
as opposed to a gap visible across two bundles the auditor does have) is
out of scope for this mode — it needs a platform-side signed export ledger
to reconcile against, which is a separate, larger design.

## AIBOM attestations (`aibom`)

`be`'s `attested` AIBOM export (`GET /organizations/:orgId/ai-systems/:aiSystemId/aibom/:snapshotId/export?format=attested`,
envelope `praesidia-aibom-attestation/v1`) is verified offline, one file per run:

```bash
praesidia-verify aibom aibom-<aiSystemId>-v<n>.attested.json \
  --tenant-key-fingerprint <sha256hex> [--tenant-key-fingerprint <sha256hex> ...] [--json | --quiet]
```

It runs the procedure the envelope carries (canonical JSON of `document` → SHA-256 must
equal `digest`; Ed25519 or low-s ECDSA-P256 signature over `praesidia:aibom-snapshot:v1:<digest>`)
and enforces three fail-closed checks. `be` DOCS-0590 wrote the first two into the procedure
(7 steps became 9); the verifier already made them, so archived 7-step exports verify exactly as before:

- **The signing key must be pinned by you.** The envelope ships its own `publicKey`, so checking
  the signature against it proves integrity, never origin: anyone can edit the document, re-hash
  it and re-sign with their own key. `--tenant-key-fingerprint` is the lowercase sha256 hex of the
  tenant public-key bytes (raw 32 bytes for Ed25519, SPKI DER for P-256) — the value a compliance
  bundle's platform attestation lists as `keyVersions[].fingerprint`, so a bundle this CLI has
  verified for the same organization is a source independent of the AIBOM file. Repeat the flag
  to pin several key versions (rotation). A pin source is required; there is no unpinned mode.
- **The envelope's `organizationId` / `aiSystemId` must equal the signed document's own fields.**
- **The file must be the exact canonical export.** `be` emits canonical JSON and the UI downloads
  it untouched. A re-serialized file (whitespace, re-escaping, duplicate keys that other JSON
  readers may resolve differently than the digest did) fails.

| `reason` | Meaning | Exit |
|---|---|---|
| `verified` | All checks hold | 0 |
| `unsigned` | No signature (snapshot predates signing or the signer was down) — proves nothing about origin | 1 |
| `digest_mismatch` | The document was altered after signing | 1 |
| `envelope_mismatch` | Envelope identity differs from the signed document | 1 |
| `key_unavailable` | No public key in the envelope (key version revoked or unknown at export) | 1 |
| `untrusted_key` | The embedded key is not one you pinned, or (with `--audit-bundle`) the document names another org | 1 |
| `signature_invalid` | The signature does not verify under the pinned key | 1 |
| `non_canonical_encoding` | Bytes differ from the canonical encoding — re-serialized or edited | 1 |
| `unsupported_format` | Not a v1 envelope, unknown domain or algorithm, malformed field | 2 |

All but `non_canonical_encoding` are `be`'s own verdicts (`verifyAibomAttestation` in
`be/src/aibom/aibom-attestation.ts`); `non_canonical_encoding` is this verifier's addition. For
an unmodified export and a correct pin both verifiers agree. Not covered by the signature and never reported as verified: `snapshotId`, `version`,
`generatedAt`, `signedAt`, `signingKeyVersion`, `procedure`.

**AIBOM anchoring (AV-0005).** When anchoring is on, `be` adds the four `anchor*` labels
(BE-0738) and, since BE-1255, an `anchorProof`. The labels are unsigned. They are never taken
as the anchor: each must agree with the proof. For a bundle that verifies, the proof is checked
offline with the envelope's procedure A2-A10. The anchor-request audit row must be signed by a
pinned tenant key and bind this `digest` and `aiSystemId`. Its Merkle inclusion proof must fold
to a root signed by a pinned tenant key. That root's Rekor receipt must verify against a Rekor
log key you pinned (SET, signed checkpoint, inclusion proof, and a `hashedrekord` body naming
this root). No key or log the file ships is ever trusted. The report carries:

| `anchorStatus` | When |
|---|---|
| `verified_rekor` | Every step passed. `anchoredAt` is the log's SET-signed `integratedTime`, never a label |
| `unverified` | Anything else. `anchorReason` says why |

Reasons are `be`'s own. `aibom_not_anchored`: no `anchorProof` (never anchored, or exported
before BE-1255), or the bundle itself did not verify. `unsigned`: an unsigned bundle.
`not_yet_rooted` / `anchor_status_unavailable`: the exporting server had no proof yet.
`anchoring_pending`: no receipt. `s3_anchor_not_offline_verifiable`: object storage cannot be
checked offline. `legacy_receipt_unverified`: a `rekor:<index>` receipt. `unknown_log_id`: the
receipt's log is not pinned. `anchor_label_mismatch`, `anchor_row_unbound`,
`anchor_untrusted_key`, `anchor_row_signature_invalid`, `anchor_inclusion_invalid`,
`anchor_root_signature_invalid`, `anchor_proof_malformed`, or a Rekor receipt failure such as
`set_signature_invalid` or `body_root_mismatch`: a proof that does not hold. For a receipt that is
malformed or tampered inside, the Rekor failure name can differ from `be`'s, because this package's
Rekor verifier checks structure first. `unverified` is the same either way.

The anchor is informational. It never changes `valid` or the exit status. The human output prints
`anchor: verified_rekor at <time>` or `anchor: UNVERIFIED (<reason>)`. The CLI trusts only the
Sigstore public-good log key this package pins. Library use:
`verifyAibomAttestation(bytes, { trustedKeyFingerprints, rekorPublicKeysPem? })`. Omit
`rekorPublicKeysPem` to use that same pinned key, or pass the PEM keys of a private Rekor log. `[]`
trusts no log.

### Getting the pin from a verified compliance bundle (AV-0002)

Verifying a compliance bundle prints each tenant key its platform attestation vouches for
(`tenant key v<n>:  <status> sha256 <fingerprint> (platform-attested <issuedAt>)`; `--json`:
`bundle.attestedTenantKeys[]` with `keyVersion`, `status`, `fingerprint`, `attestedAt`). These appear only when
the platform attestation itself verified, never under `--allow-legacy-unattested`. Or let the CLI
do both steps:

```bash
praesidia-verify aibom aibom-<aiSystemId>-v<n>.attested.json --audit-bundle bundle.zip \
  [--no-rekor] [--platform-key <file> [--platform-key-fingerprint <sha256hex>]] [--target-keys <file>]
```

The bundle is verified first with the same trust options as the bundle command. It is a pin source
only if its whole report is `valid` and it carries a verified platform attestation; otherwise the
command exits 1 (`--audit-bundle is not a pin source` on stderr). Its attested ACTIVE and ROTATED
keys become the pins; REVOKED keys never do, because an AIBOM's signing time is not authenticated,
so a signature cannot be shown to predate the revocation. The signed document's `organizationId`
must equal the bundle's org (`untrusted_key` otherwise). Key status is as of the attestation's
platform-signed `issuedAt` (printed as `status as attested at`), not today: use a freshly exported
bundle, since a key revoked after that time still pins. `--audit-bundle` and `--tenant-key-fingerprint` are mutually
exclusive. Library use: `verifyAibomAttestation(bytes, aibomTrustFromBundle(await verifyBundle(zip)))`,
which throws on a bundle that is not a pin source.

## Verdict shape

Every component result (`report.manifest`, `report.rowSignatures`, ...) and
the top-level report both carry a `status: 'valid' | 'invalid' | 'incomplete'
| 'unsupported' | 'not_present'` field (`ok: boolean` is kept for backward compatibility,
always derived as `status === 'valid'`). The top-level `status` is a real
reduction, not "any component failed": `invalid` if any component is
`invalid`; else `unanchored` (top level only, AV-0017) when no platform
trust anchor existed — `platformAttestation` is then `incomplete` with reason
`platform_key_not_pinned`; else `incomplete` if any is `incomplete`; else
`valid`. A
component reporting `unsupported` — this bundle legitimately carries no
evidence for that check — is reported but never drags the overall verdict
down. The nine action-evidence components (invariants 13-21 below) report
`unsupported` on every bundle below `manifest.version: 5` (there is no
action-event evidence to check at all), and `targetAck`/`callerResult`
report `incomplete` when the relevant evidence event is legitimately
redacted.

A component that applies to the bundle but found nothing to check (a pass
with `checked: 0`) reports `not_present` (CLI `[NOT_PRESENT]`), never
`valid`: e.g. `targetAck` on a bundle with no `TARGET_ACKNOWLEDGED` event,
`chain` on a single-row bundle (no link to assert), `rekor` for unanchored
roots under `--no-rekor`, `integrityCheckpoints` below `manifest.version: 4`,
or `platformAttestation` absent under `--allow-legacy-unattested`. Like
`unsupported` it never drags the verdict down, but if **no** evidence
component is `valid` (a zero-row, zero-root bundle) the top level is
`incomplete` (exit 3), not `valid`. `manifest`, `completeness` and
`keyBinding` are mandatory and never report `not_present`. Neither
`unsupported` nor `not_present` appears at the top level.

### Proof summary (AV-0010)

`report.proofs` groups the components into six proofs an auditor can read, and
the human report opens with them:

```
PASS signature
PASS hash chain
PASS decision receipt
PASS policy reference
PASS evidence integrity
NOT_PRESENT target receipt
```

Each proof is `FAIL` if any of its components is `invalid`, else `INCOMPLETE`
if any is `incomplete`, else `PASS` if any is `valid`, else `NOT_PRESENT`
(every component `not_present`/`unsupported`). Every component belongs to
exactly one proof (table below; exported as `PROOF_COMPONENTS`), so `RESULT: FAIL` (exit 1)
always comes with at least one `FAIL` line. `RESULT: INCOMPLETE` can come with
no `INCOMPLETE` line: a bundle with no evidence at all has only
`PASS`/`NOT_PRESENT` lines. `--summary` drops the component detail;
`--quiet` is unchanged (one word).

| proof | components |
|---|---|
| `signature` | `manifest`, `rowSignatures`, `rootSignatures`, `platformAttestation`, `keyBinding` |
| `hashChain` | `chain`, `inclusionProofs`, `rekor`, `completeness`, `rootCoverage`, `integrityCheckpoints` |
| `decisionReceipt` | `decisionReceipt` |
| `policyReference` | `policyReference` |
| `evidenceIntegrity` | audit package `verification.txt` receipt (packages only), `actionEventChain`, `permitBinding`, `requestBinding`, `dispatchIntegrity`, `callerResult`, `closureLegality`, `evidenceGrade`, `actionCompleteness` |
| `targetReceipt` | `targetAck` |

### Evidence privacy mode (AV-0013, manifest v6)

A v6 manifest signs `evidencePrivacy: { modes: [{ mode, effectiveFrom }], schemaVersion }`,
the org's evidence privacy mode over `[from, to)` (`FULL | REDACTED | METADATA_ONLY |
ZERO_RETENTION`). `report.evidencePrivacy` (and the text report's `evidence privacy:` block)
states, per mode window, what this bundle proves and what it cannot:

| Mode | Proven | Not provable from this bundle |
|---|---|---|
| `FULL` (declared) | chain integrity, signatures, ordering, commitment binding, content equality, target-ack body | — |
| `REDACTED`, `METADATA_ONLY`, `ZERO_RETENTION` | chain integrity, signatures, ordering, commitment binding | content equality, target-ack body |
| `FULL (undeclared)` — manifest v1–v5 | chain integrity, signatures, ordering, commitment binding | content equality, target-ack body |

- A declared mode never changes a status. A component left `incomplete` by
  `payload: null` events that all fall in a declared reduced-mode window (by the event's
  `receivedAt`) keeps `incomplete` and gets `reason: "evidence_privacy_mode:<MODE>"`.
- Every `payload: null` event is listed in `evidencePrivacy.payloadAbsences`. One outside
  any declared reduced window is annotated `undeclared_payload_absence`. That is not a
  failure by itself: subject erasure is a legitimate cause.
- The declaration counts (`declared: true`) only when the manifest signature verified.
- Fail closed: an unknown mode, an unknown `schemaVersion` (upgrade the verifier), a
  timeline not starting at `manifest.from`, out of order, or reaching `manifest.to`, or
  any extra key, is a bundle-format error (exit 2). The field on a v1–v5 manifest, or its
  absence on v6, fails `manifest`.
- A pre-v6 bundle declares no mode, so the verifier does not claim its payloads are the
  unreduced originals.

## What it verifies

For a bundle produced by `BundleExporterService` (AGV-035) the verifier
checks every cryptographic invariant the bundle commits to:

1. **Manifest signature** — Ed25519 (or ECDSA-P256) signature over the
   canonical-JSON of the manifest fields, signed with the tenant's
   currently-active key. The signable field set is selected by the
   manifest's declared `version`, from a closed whitelist — never by
   inspecting which fields happen to be present on the received object.
   `version: 1`/`2` sign 9 fields; `version: 3` signs those 9 plus
   `chainSeqCeiling`/`chainSeqSnapshotAt` (the chainSeq snapshot a bundle
   export was bounded by). Either direction of mismatch — the two v3
   fields present on a `version: 1`/`2` manifest, or absent on a
   `version: 3` one — fails closed with its own distinct reason
   (`chainseq_fields_present_on_v{1,2}_manifest` /
   `chainseq_fields_missing_on_v3_manifest`) rather than a generic
   signature failure, so an auditor can tell version skew from tampering.
2. **Row signatures** — every row in `rows.ndjson.gz` is re-canonicalized
   from its signable fields and verified against the public key at
   `row.keyVersion` from `public-keys.json`. The signed preimage is
   `canonical_bytes || base64-decode(prev_row_hash)` — the row signature
   binds the row's chain position, byte-for-byte as the backend writer
   produces it. A row whose `prev_row_hash` is missing/malformed fails
   closed. `ipAddress` is included in the canonical preimage IFF the wire
   row object carries that key at all (present-with-`null` still counts as
   present) — this mirrors `be-core`'s own conditional signing of
   `ipAddress` only for rows produced at/after its
   `IP_ADDRESS_SIGNABLE_CUTOVER_AT` activation, with no cutover-date
   knowledge required in this verifier. `detailsCommitment` is handled the
   same presence-guarded way, but REPLACES `summary`/`details` rather than
   joining them: rows produced at/after `be-core`'s
   `AUDIT_DETAILS_COMMITMENT_CUTOVER_AT` activation sign `detailsCommitment`
   instead of raw `summary`/`details`, and this verifier reconstructs
   whichever shape the wire row actually carries.
3. **Chain integrity** — the true chain order is reconstructed from the
   cryptographic links themselves (each row's forward link vs. the next
   row's declared `prev_row_hash`), **not** from the bundle's on-disk row
   order. `rows.ndjson.gz` is exported ordered by `(signedAt, id)`, which
   does not always match the actual signing order when two rows in the
   same org share a `signedAt` millisecond (a same-transaction signing
   burst is the realistic case, not an edge case) — trusting file order in
   that case would report a false chain break on an honest bundle. Bundles
   are **date-ranged** (hard-capped at 90 days), so the ONE row with no
   in-bundle predecessor is accepted as an opaque anchor into the org's
   pre-range history, not required to be the all-zero genesis. Any other
   row missing an in-bundle predecessor, or two rows claiming the same
   predecessor (a fork), fails closed; leading truncation is caught by
   **completeness** (see 7) and per-period trailing truncation is caught
   by **root coverage** (see 10).
4. **Merkle root signatures** — every root in `roots.ndjson.gz` is
   re-canonicalized and verified.
5. **Inclusion proofs** — exactly one valid proof into a current root is
   required for every exported row (plus one per superseded root that
   committed it, see 10). Every proof is walked against the corresponding root via
   RFC 6962-style verification (leaf prefix `0x00`, internal prefix `0x01`),
   with index and path depth checked against the signed root row count.
   Diagnostic status markers are failures, not substitutes for proofs.
6. **Rekor receipt** — when `--no-rekor` is NOT passed, each root's
   Sigstore Rekor receipt is verified **cryptographically and offline**:
   its Signed Entry Timestamp (SET) is checked against the **pinned**
   Sigstore Rekor public key. The inclusion proof's C2SP signed checkpoint
   is verified under that same pin, its authenticated tree size/root must
   match the proof metadata, and the proof is then walked to that root. Its
   `hashedrekord` body must also contain the exact
   audit root hash and root signature from the bundle, preventing a genuine
   but unrelated receipt from being reattached. A receipt that is not a
   genuine, SET-signed, log-included entry (e.g. an empty `{}`) **fails**.
   The pinned key
   is baked in at build time (never fetched at verify time); a sovereign
   Rekor instance can pass its own key via `verifyBundle`'s
   `rekorPublicKeyPem` option.
   Legacy receipts that omit `inclusionProof.checkpoint` fail closed with
   `checkpoint_missing`; producers must persist the log's signed checkpoint,
   not only the unauthenticated `treeSize`/`rootHash` proof fields.
   The log's **signed `integratedTime` is bound to the root's own claimed
   time window**: it must not be earlier than `root.signedAt`, nor later
   than the anchor time the bundle records (`root.anchoredAt`, or the
   per-provider `anchorReceipts[].anchoredAt`), by more than a fixed **24h**
   skew allowance — otherwise `rekor_integrated_time_out_of_window`.
   `integratedTime` is the only clock in the artefact an attacker cannot
   backdate, so a freshly-anchored forgery claiming an old period fails
   here. A legacy root that carries a receipt but records **no** anchor time
   has no upper bound (a later backfill anchoring run is legitimate).
   - **A root with no anchor receipt at all still fails closed** — an
     unwitnessed root does not get the benefit of the doubt. The `reason`
     distinguishes two different situations rather than reporting them
     identically: `no_external_witness` means every root in the bundle is
     unanchored (consistent with a deployment that has never enabled
     Rekor/S3 anchoring); `anchor_missing_for_partially_anchored_bundle`
     means only SOME roots lack a receipt while others have one — a much
     narrower, more concerning gap (e.g. an anchoring outage or a deleted
     receipt). These are different findings; do not treat them the same.
   - `--no-rekor` skips Rekor receipts (`reason:
     'rekor_check_skipped_by_caller: ...'`) — this is a CALLER opt-out, not
     a verdict about whether Rekor anchoring exists. Other receipt providers
     (including S3) remain in scope and still fail closed unless their own
     verifier succeeds. `praesidia-verify` prints an explicit `NOTE:` line
     whenever this flag was used, so a skimmed `RESULT: OK` cannot be
     mistaken for "Rekor anchoring was verified".
7. **Completeness** — the number of rows / roots actually present must
   equal the SIGNED `manifest.rowCount` / `manifest.rootCount`. This
   fails closed on a whole-bundle trailing-truncation attack, where an
   attacker deletes the last N rows (and their proofs) and the manifest
   is NOT re-signed to match: the surviving prefix still chains and still
   proves, but the aggregate signed counts no longer match what was
   handed to the verifier. This does **not**, by itself, catch a
   suffix deleted before a HONEST re-export recomputes a smaller count —
   see **root coverage** (10).
8. **Platform key-binding attestation** — `platform-attestation.json` is
   checked against a trusted platform key. The current source distribution
   does not embed a deployment-specific key, so operators pass a trust anchor
   with `--trust-anchor` (library: `platformTrustAnchor`) or a single key with
   `--platform-key` (library: `platformPublicKeyDerB64`). A missing attestation,
   or an anchor/pin that does not contain the signing key, fails closed (exit 1);
   no trust anchor at all is `unanchored` (exit 5). Pre-attestation bundles are
   accepted only with explicit `--allow-legacy-unattested`. The attestation
   must cover every bundled key exactly once and binds its fingerprint,
   lifecycle status, and revocation timestamp.
   It is also bound to **this export**: `issuedAt` may not precede
   `manifest.generatedAt` by more than 24h (`attestation_predates_manifest`),
   and when the attestation carries the optional `manifestGeneratedAt` /
   `manifestDigest` fields (`manifestDigest` = sha256 hex over the manifest's
   canonical *signable* bytes — the same preimage the manifest signature
   covers) they must match this manifest exactly
   (`attestation_manifest_binding_mismatch`). An attestation carrying
   neither field is a pre-binding **legacy** one: still accepted, but the
   component reports `attestation_unbound_legacy` and the CLI prints a
   `NOTE:` — it vouches for the org's key set, not for this specific export,
   so a genuine older attestation can accompany a bundle it was never minted
   for. Upgrade the exporter to close that gap.
9. **Archive integrity and resource bounds** — duplicate filenames,
   local/central-header disagreement, invalid UTF-8 names, CRC mismatches,
   unsupported encryption, malformed ZIP64, and excessive decompression are
   rejected before bundle contents are trusted. Only the ten members defined
   by the supported bundle versions are accepted. The verifier caps the raw
   archive at 72 MiB, ZIP members at 32 MiB each / 68 MiB aggregate, static
   JSON/README members at 2 MiB each, nested-gzip output at 32 MiB each /
   64 MiB aggregate, NDJSON lines at 1 MiB, evidence records at 250,000 per
   member and 300,000 aggregate, public keys at 256, and anchor receipts at
   200,000. STORED members are zero-copy views and nested gzip/NDJSON is
   parsed incrementally under shared byte and record budgets; ZIP-layer
   DEFLATE is rejected. Library callers may lower
   (but not raise) configurable ceilings with `VerifyOptions.resourceLimits`;
   the CLI checks the file size through an already-open descriptor before
   allocating its buffer. Larger evidence ranges must be split into multiple
   bundles.
10. **Root coverage** — for every Merkle root whose full period lies
    inside the bundle's declared `[from, to)` date range, the number of
    bundle rows whose `signedAt` falls in that period, AND the number of
    proof entries pointing at that root, must both equal the root's own
    SIGNED `rowCount`. A Merkle root is signed and Rekor-anchored
    independently of the manifest, at anchor time — if rows are deleted
    from the underlying table AFTER a period's root was anchored but
    BEFORE the bundle is (re-)exported, the exporter's manifest honestly
    reflects the new (smaller) total and **completeness alone would
    pass**, while the untouched, already-anchored root still commits to
    the original, larger count. This component is what actually catches
    that class of deletion; a boundary root that only partially overlaps
    the bundle's date range is exempted (a genuine ranged export
    legitimately ships fewer rows for it, since rows outside `[from, to)`
    are never exported). A shrinkage (fewer rows/proofs than the root's
    own signed `rowCount`) is downgraded from a hard failure to a distinct
    `seal_exempted` pass — naming the responsible seal's `id` and
    `approvalId` — only when a VERIFIED entry in
    `sealed-purges.ndjson.gz` (invariant 12) names the exact same
    `(periodStart, periodEnd, rootHash)` and its signed `rowCount` equals
    both the root's committed count and the number of missing rows/proofs.
    A retention seal represents a full-period purge, so a partial count can
    never excuse an unrelated deletion. This closes `BE-0003`: a bundle
    spanning a legitimate,
    signed, two-person-approval-gated `AuditRetentionSeal` retention purge
    no longer reads as tampering. A shrinkage with no matching VERIFIED
    seal keeps failing exactly as before — this is a narrowing of the
    failure surface, never a widening; a period with MORE rows than its
    own signed root committed to is a different anomaly a purge record can
    never explain and always keeps failing regardless of any seal.

    **Superseding roots (AV-0016).** A root that committed to fewer rows
    than its hour holds is never rewritten. `be` appends a new root that
    carries `supersedesRootId` (the old root's `id`) and
    `supersessionSignature`: a signature, under the new root's own key,
    over the canonical JSON of `{version: "praesidia.root-supersession.v1",
    supersedes: <old rootHash>, rootHash, periodStart, periodEnd, rowCount}`.
    Both roots must ship in the bundle. The link is accepted only when the
    signature verifies, the old root is in the bundle with the same period
    and a strictly lower `rowCount`, and no other root supersedes it
    (chains are linear and acyclic). Each row proves once into its current
    root, and once more into each superseded root that committed it. The
    new root must prove every row of the old one. The superseded root
    keeps its own signature, inclusion-proof, proof-count and anchor
    checks. Only the rows-in-period count moves to its successor.
    `rootCoverage.supersessions` names both roots of every link, so the
    old root's Rekor receipt is never dropped silently. Any broken link
    fails `rootSignatures` or `rootCoverage`. Bundles without these fields
    verify exactly as before. Residual: a bundle that ships only the new
    root, with no link, still looks like an ordinary root. Offline, the
    verifier cannot know that an older root exists. `be` must export both.
11. **Integrity checkpoints** (`version: 4`+ only) — `be`'s
    `AuditIntegrityCheckpointService` periodically (hourly) signs and
    persists `{organizationId, chainHeadHash, cumulativeRowCount, asOf}`
    for every org, independent of any Merkle-root period or bundle export.
    When present, the verifier: (a) authenticates every checkpoint's own
    signature (REVOKED-key rejection, same as rows/roots); (b) requires
    `cumulativeRowCount` to be monotonically non-decreasing across
    checkpoints in `asOf` order; (c) independently recomputes each
    checkpoint's `chainHeadHash` from the bundle's OWN rows restricted to
    `signedAt <= asOf` and compares. A checkpoint whose window contains no
    bundled rows (a dormant org, or a historical ranged export ending
    before that instant) is a legitimate boundary case and is skipped, not
    asserted — mirroring root coverage's own boundary exemption — UNLESS
    the checkpoint claims the all-zero genesis hash, which is fully
    consistent with an empty window and IS checked. A `(b)` decrease or
    `(c)` mismatch between two checkpoints is downgraded to a
    `seal_exempted` pass — listing every contributing seal's `id` — when
    VERIFIED `sealed-purges.ndjson.gz` entries whose `deletedAt` falls
    strictly after the earlier checkpoint and at/before the later one
    (`(prev.asOf, cur.asOf]`) sum to at least the observed
    `cumulativeRowCount` decrease. A window with NO verified seal evidence
    at all — even when the arithmetic would otherwise be trivially
    satisfied — is never treated as reconciling; an empty seal window is
    the absence of evidence, not evidence. A decrease/mismatch the
    verified seals do not fully account for keeps failing closed, since
    that residual could still be genuine tampering on top of a legitimate
    purge.
12. **Sealed-purge evidence** (`sealed-purges.ndjson.gz`, wholly optional
    and never gated on `manifest.version`) — one entry per
    `AuditRetentionSeal` row whose purged period overlaps the bundle. Each
    entry carries its OWN signature, independent of the manifest and of
    every other entry, over `canonicalJson({organizationId, periodStart,
    periodEnd, rowCount, rootHash, rekorReceipt})` — the seal's existing
    envelope from `AuditRetentionSealService.purgeWithSeal`, re-emitted
    onto the bundle wire unchanged. Current producers sign `rowCount` as
    its canonical decimal string, matching the bundle wire; the verifier
    also accepts the legacy safe-integer numeric preimage emitted by older
    backend builds. This entry is deliberately **NOT**
    part of the signed manifest preimage (see the "Why this entry is
    unsigned" note below) — its own per-entry signature is what makes it
    trustworthy on its own, without needing a manifest-level count. An
    entry with a `null` signature (legacy backfilled rows), a
    `signingKeyVersion` absent from `public-keys.json`, a `REVOKED` key, or
    a signature that fails to verify is excluded from every downstream use
    (invariants 10 and 11) — it can never cause a NEW failure, only fail to
    help explain an existing one. A validly-signed entry that simply names
    a different period/root than the finding under evaluation is likewise
    not used — a near-miss is not evidence.

    **Why this entry is unsigned at the manifest level:** the shipped
    verifier's signable set (`verifyManifest`'s `signable` object) is a
    closed field-by-field whitelist keyed by `manifest.version` — an extra
    unknown key on `manifest.json` is silently excluded from the
    reconstructed preimage, so `be` could add an unsigned count today
    without breaking this verifier's signature check, but a genuine
    anti-suppression count (mirroring `rowCount`/`integrityCheckpointCount`)
    would need a coordinated `manifest.version` bump the same way v3→v4 was
    — a decision deliberately deferred, not made silently. Until then, each
    entry's OWN signature is the tamper-evidence: a holder of raw DB write
    access but not the tenant signing key cannot fabricate an entry that
    survives the authenticity gate above, so an attacker who deletes rows
    AND scrubs the matching seal entry from the wire only returns the
    affected finding to the pre-existing, conservative fail-closed state —
    never a forgery of a purge that did not happen. **This is why omission
    of this optional, unsigned file can never itself be a false `ok:
    true`** — the worst a missing/tampered/non-matching sealed-purge entry
    can do is leave `rootCoverage`/`integrityCheckpoints` failing closed
    exactly as they did before this entry existed.

13. **Action-event chain integrity** (`version: 5`+ only, `actionEventChain`)
    — every `protected_action_events` row in `action-events.ndjson.gz` is
    signature-verified (message = `canonicalJson(signable) ||
    prevEventCommitmentBytes`, mirroring the row-signature binding) and
    chained by an independently RECOMPUTED `sha256(canonical || sigBytes)`
    per `actionId`; the wire-declared `eventCommitment` must equal that
    recomputed digest and is never trusted as the chain source. `actionSeq`
    must be monotonic and gapless within the bundle for each `actionId`;
    the first event seen for an `actionId` is accepted as an opaque
    out-of-range anchor unless its `actionSeq` is `1`, in which case it
    must declare the genesis commitment (mirrors invariant 3's mid-range
    anchor rule). A `receivedAt` before `observedAt` is flagged as clock
    skew.
14. **Permit binding** (`permitBinding`) — `PERMIT_ISSUED`/`PERMIT_CONSUMED`
    within one `actionId` must agree on the request commitment and the
    permit identifier. Every consumed event must carry the same nonce in
    its signed top-level `permitNonce` and payload mirror, no nonce may be
    consumed more than once anywhere in the bundle, and one destination
    idempotency commitment may not map to distinct action IDs (the durable
    single-use and double-apply gates).
15. **Request binding** (`requestBinding`) — `DISPATCH_ATTEMPTED` and
    `PERMIT_CONSUMED` must agree on a well-formed `requestCommitment` for
    every dispatch attempt in the same `actionId`; a consumed event found
    only after dispatch is invalid. Observe-mode dispatches may omit a
    permit entirely — the authoritative-commitment-substitution defense.
16. **Dispatch integrity** (`dispatchIntegrity`) — every `DISPATCH_ATTEMPTED`
    event must carry `dispatched: true`; a post-dispatch closure requires
    one such event, a pre-dispatch-only closure must never have one.
17. **Target acknowledgment** (`targetAck`) — every `TARGET_ACKNOWLEDGED`
    event's claimed grade is independently re-checked structurally (grade A
    needs a target signature, grade B needs an authenticated edge
    attestation) rather than trusted.
18. **Caller result** (`callerResult`) — every `CALLER_RESULT_OBSERVED`
    event's `payload.success` must be boolean and any
    `payload.resultCommitment` well-formed. When present, `payload
    .outcomeClass` (`completed_success`/`completed_with_error`/
    `no_response_received`, PA-0033) must be a recognized value and
    consistent with `payload.success`.
19. **Closure legality** (`closureLegality`) — re-derives D7's frozen
    closure state machine independently (never trusts `be`'s own logic) and
    additionally requires an ACTUAL, POSITIVE `TARGET_ACKNOWLEDGED`/
    `CALLER_RESULT_OBSERVED` event for any closure that claims a determined
    outcome, regardless of the declared `reason` — presence of an
    evidencing-typed event is not by itself evidence (PA-0033, HIGH-1):
    `TARGET_ACKNOWLEDGED` is always positive, `CALLER_RESULT_OBSERVED` is
    positive only via `outcomeClass` (or `success: true` on bundles
    predating that field). **This is the check that makes a bundle claiming
    `FAILED_NO_EFFECT` justified only by a timeout — confirmed via
    `outcomeClass: 'no_response_received'`, or ambiguous pre-field
    `success: false` — verify as `invalid` or `incomplete`, never `valid`.**
20. **Evidence grade** (`evidenceGrade`) — derives a grade per closed action
    from the evidence actually present, requires the four declared grade
    buckets to total exactly the number of closed action streams, flags a
    declared strength that exceeds what the evidence supports, and rejects
    an `enforcementMode: 'enforce'` declaration contradicted by an
    `'observe'`-mode event.
21. **Action completeness** (`actionCompleteness`) — the signed
    `actionEventCount` must match the rows actually present in
    `action-events.ndjson.gz`.

S3 anchor receipts cannot be proven offline from their locator string alone.
The library therefore fails closed for S3 by default; callers can provide an
`anchorReceiptVerifier`. The hook receives the exact expected bundle root as
its second argument and must GET the immutable object version, compare the
stored root hash/signature and other available fields to that expected root,
and validate retention. A HEAD-only existence/lock check is insufficient.

`manifest.version` is checked against an explicit ceiling
(`MAX_SUPPORTED_MANIFEST_VERSION`, currently 6) — a bundle declaring a newer
version than this build implements is rejected as a bundle-format error
(exit code 2) rather than silently verified under the wrong (older) rules.
Never bump the ceiling without landing real support for the new version's
fields in the same change.

## What this verifier does — and does NOT — prove

**Does prove**, when it reports `ok: true` for a given bundle:

- Every row, root, and the manifest are validly signed by a key present in
  the bundle's own signed key set, and that key was not marked `REVOKED` at
  verification time. For the manifest, "validly signed" includes the
  version-keyed signable set matching the manifest's own declared version
  exactly (invariant 1) — a `chainSeqCeiling`/`chainSeqSnapshotAt` mismatch
  relative to the declared version fails closed before the signature is
  even computed.
- The rows form a single, internally consistent hash chain (order-independent
  reconstruction — see invariant 3) with no fork, no orphan, and no broken
  link, up to one accepted opaque anchor for a date-ranged export.
- No row or Merkle root has been added, removed from the middle, or had its
  content altered since it was signed.
- For every Merkle-root period fully inside the bundle's declared date
  range, the number of rows and proofs present matches what that root's own
  signature committed to at anchor time (invariant 10) — this is what lets
  the verifier catch a deleted trailing suffix, not just a truncated
  archive. A shrinkage explained by a VERIFIED `sealed-purges.ndjson.gz`
  entry naming the exact same period+root (invariant 12) is reported as a
  distinct, named `seal_exempted` pass instead — an UNEXPLAINED shrinkage
  (no matching verified seal) still fails closed exactly as before.
- For Rekor, unless skipped via `--no-rekor`, that the receipt is a genuine,
  cryptographically valid transparency-log entry bound to the exact root hash
  and signature in the bundle. For S3 or another provider, that the explicitly
  trusted caller hook accepted the receipt after receiving the expected root
  it must bind to.
- If `platform-attestation.json` is present (or `--allow-legacy-unattested`
  is NOT passed), that Praesidia's platform — not just the tenant — vouched
  for the key-to-org binding.
- For `version: 4`+ bundles, that the org's cumulative signed-row count and
  chain head at each checkpointed hour were not shrunk or rewritten after
  the fact — bounding an undetectable suffix deletion in the un-rooted
  tail, or a boundary period, to at most one checkpoint interval, in the
  common case where the bundle's own rows span up to (or past) the
  checkpoint's `asOf` (see invariant 11's boundary exemption and residual).
  An unexplained decrease/mismatch across a checkpoint window still fails
  closed; one fully accounted for by VERIFIED sealed-purge evidence in
  that exact window is reported as a distinct, named `seal_exempted` pass.

**Does NOT prove**, even on `ok: true`:

- **That every action was captured in the first place.** A signing outage
  (governance mode `off`, or a failed sign under `observe`) can produce an
  invisible hole: an unsigned row is invisible to the chain, the Merkle
  roots, the checkpoints, and the exported bundle alike, with no marker in
  the artifact. Two hours of signing downtime and two hours of deleted
  rows currently look identical to this verifier.
- **That a not-yet-anchored (or boundary/partially-anchored) period wasn't
  truncated — in full.** Root coverage (10) only binds a root's committed
  count once that root exists and its FULL period is inside the bundle's
  range. `version: 4`+ integrity checkpoints (11) now close PART of this:
  when the bundle's rows demonstrably extend up to a checkpoint's `asOf`,
  a suffix deletion after that instant is caught, bounding the
  undetectable window to at most one checkpoint interval (hourly) for both
  the un-rooted tail and a boundary period. The residual that remains
  open even on `ok: true`: (a) bundles on `version <= 3` (no checkpoint
  commitment at all — the original gap, unchanged); (b) a checkpoint whose
  `asOf` predates every bundled row is a legitimate boundary/dormant-org
  case and is deliberately NOT asserted, so a bundle whose ENTIRE checked
  range sits before its org's actual current head (a narrow historical
  export of a still-active org) gets no independent size commitment from
  checkpoints either, same as before; (c) a genuine, signed
  `AuditRetentionSeal` hard-purge is now reconciled — and downgraded to a
  named `seal_exempted` pass — ONLY when `sealed-purges.ndjson.gz` carries
  a VERIFIED entry whose `deletedAt` falls in the affected checkpoint
  window and whose summed `rowCount` accounts for the observed decrease
  (invariant 12). A purge with no corresponding sealed-purge entry in the
  bundle (e.g. an export produced by a `be` version that predates this
  wiring, or one where the entry was legitimately omitted/empty) still
  fails closed exactly as before — this closes the false-positive ONLY
  when the producer actually ships the matching evidence, it does not
  weaken the check for bundles that don't.
- **That Rekor anchoring exists at all when `--no-rekor` is used.** That flag
  permits roots without Rekor evidence but no longer bypasses S3 or other
  provider receipts that are present. Read the `rekor` component and the
  explicit CLI note, not just top-level `ok`, before treating a bundle as
  Rekor-witnessed.
- **That a REVOKED key's pre-revocation signatures are trustworthy.** This
  verifier rejects EVERY signature made under a revoked key, including ones
  that were genuinely signed before revocation — because `signedAt` is not
  itself part of the signed bytes, a backdated forgery and a genuine
  pre-revocation signature are indistinguishable without an external
  timestamp proof, which this verifier does not currently cross-check
  against Rekor's own inclusion timestamp. The practical effect: revoking a
  tenant signing key after a suspected compromise makes that key's entire
  history unverifiable going forward, including the legitimate part.
- **That privileged, non-audit-logged actions didn't happen.** This
  verifier can only attest to what is IN the bundle. Whether every
  security-relevant mutation in the product is actually written to
  `audit_logs` in the first place is a `be`-side coverage question, not
  something an offline bundle verifier can detect.
- **Anything about network reachability, uptime, or `be`'s live behavior.**
  This is a static, offline artifact check. It says nothing about whether
  the platform is currently signing correctly, whether retention jobs are
  about to destroy signed data, or any other live operational property.
- **That the bound `args` of a protected action were authorized BY A
  PRINCIPAL, only that they were not altered after policy ran.** On the
  agent-runtime dispatch path, the arguments a Permit binds are the
  model's own proposed arguments — a Permit proves byte-for-byte integrity
  from policy decision to dispatch, not that a human or an upstream
  authority chose those exact bytes. Prompt injection that steers an
  agent's proposed arguments yields a fully valid, fully signed Permit and
  a fully valid `closureLegality`/`evidenceGrade` verdict. This verifier
  (and every consumer of its report) must not present a valid verdict as
  "this exact action was authorized" without qualifying by whom
  (`PA01-DECISIONS.md` corrigendum C4).
- **That an unmediated dispatch path was covered at all.** A dispatch that
  never touches an instrumented Proof Edge (e.g. today's uninstrumented
  outbound-webhook path) produces ZERO bundle evidence — there is nothing
  in the artifact for this verifier to check, by construction. The signed
  `captureScopeDigest` makes the org's capture-scope REGISTRY
  tamper-evident, but detecting that a real dispatch bypassed the registry
  entirely requires comparing bundle evidence against live system activity,
  which is outside what an offline, single-bundle verifier can ever prove.

## Trust anchor — verifying the CLI's embedded pin out-of-band

The platform public key this build trusts is compiled into `src/platform-pubkey.ts`
as `PLATFORM_PUBLIC_KEY_DER_B64` / `PLATFORM_PUBLIC_KEY_FINGERPRINT` — **not** fetched
at verify time (that would reintroduce the exact network dependency this tool exists
to eliminate). Do not take the embedded bytes on faith: an npm-registry or CI-supply-chain
compromise of _this package_ is exactly the attack a customer's own second channel should
catch.

- **`--trust-anchor <file>` (AV-0017) checks the bundle against Praesidia's published
  trust-anchor document** — `GET https://<api-host>/.well-known/praesidia-audit-keys.json`,
  `{ "purpose": "audit-bundle-platform-attestation", "keys": [...] }`. The CLI **never fetches
  it**: download it yourself, over a channel independent of the bundle, and pass the local
  file (a URL is rejected, exit 2):

  ```bash
  curl -fsSo praesidia-audit-keys.json https://<api-host>/.well-known/praesidia-audit-keys.json
  praesidia-verify bundle.zip --trust-anchor praesidia-audit-keys.json
  ```

  Every listed key is self-checked first (PEM, JWK and `fingerprint` must be the same EC P-256
  key; `signatureAlgorithm` must be `ECDSA_P256_SHA256`) — any inconsistency is exit 2. The
  attestation's `platformSigningKeyFingerprint` selects the key; a document that does not list
  it fails `trust_anchor_key_not_found`, and an attestation `issuedAt` outside the key's
  `notBefore`/`notAfter` fails `trust_anchor_key_not_valid_at_issuedAt` (both exit 1). Retired
  keys stay listed so archived bundles keep verifying. Like `--platform-key`, the caller is the
  trust anchor, so every run prints a `WARNING:` line. Exclusive with `--platform-key`.
- **No trust anchor at all is `UNANCHORED` (exit 5)**, never OK and never a plain FAIL: with no
  build-time pin, no `--trust-anchor` and no `--platform-key`, the signing keys are the bundle's
  own claim. `platformAttestation` reports `incomplete` / `platform_key_not_pinned`; any real
  verification failure still wins (exit 1).
- **A caller-supplied `--platform-key` makes the caller the trust anchor.** The CLI cannot
  tell an operator-obtained key from one that arrived in the same email or ZIP as the bundle,
  and with a caller key the attestation's `platformSigningKeyFingerprint` check degenerates to
  hashing the key it was handed. Every run that uses the flag therefore prints a `WARNING:`
  line. Pair it with `--platform-key-fingerprint <sha256hex>`, taken from a *different*
  channel, so the key and its identity cannot both come from whoever produced the bundle; a
  mismatch is a hard exit-2 error, not a warning.
- **Confirm the pin against a second, independently-operated channel** before trusting a
  `RESULT: OK` for anything consequential — never take `PLATFORM_PUBLIC_KEY_FINGERPRINT`
  on the word of this package alone. Full detail on where the fingerprint lives, what the
  second channel must and must not share infrastructure with, and what to compare:
  `docs/trust-anchor-verification.md`. **USER-OWED, pending the production key ceremony
  (MIL-0003):** that document intentionally has no live channel URL yet — a customer-facing
  document must never point at a channel that does not exist. Once the ceremony lands, compare
  the published fingerprint, byte-for-byte, against `PLATFORM_PUBLIC_KEY_FINGERPRINT` in the
  exact tarball/commit you installed — `npm view @praesidia/audit-verifier@<version> --json |
  jq .dist` lets you confirm the tarball hash independently of `npm install`'s own trust.
- **The release workflow requires a separate operator approval value.** Its protected
  `audit-verifier-production` Environment supplies the independently confirmed lowercase
  fingerprint; `prepack` rejects a missing value, a mismatch, a non-canonical key, or any EC curve
  other than P-256. This prevents a key and its self-asserted fingerprint from being changed
  together and silently treated as approved. Setup and ceremony details are in
  `docs/trust-anchor-verification.md`, which is included in the published package.
- **`npm publish --provenance`** (MIL-0002 F4) means `npm view @praesidia/audit-verifier
  provenance` shows a SLSA attestation binding the published tarball to the exact GitHub
  Actions run, commit, and source repository that built it — a second, cryptographic check
  that what you installed is what this source tree actually produced, independent of trust
  in whoever holds the npm publish token.
- **Rotation does not (yet) avoid a CLI upgrade.** Today, rotating the platform key means
  cutting a new `@praesidia/audit-verifier` release and every auditor updating before
  verifying bundles signed under the new key — there is no in-band revocation for a
  compromised _platform_ key (as opposed to a per-tenant signing key, which already has
  one — see invariant 4). A key-hierarchy design that removes this constraint (an offline
  root that cross-signs rotating operational keys) is written up, not yet built:
  `docs/design/platform-key-hierarchy.md` — including the concrete, stated limit that an
  already-installed offline CLI cannot learn of a revocation before its next upgrade, which
  no purely offline design can avoid.
- **Until the production key ceremony lands** (the prod pin value is filled at release,
  AV-0015), this pin is intentionally empty and every bundle verified without
  `--trust-anchor`/`--platform-key` is `UNANCHORED` (exit 5, `platform_key_not_pinned`) — see
  "Platform key-binding attestation" above and `src/platform-pubkey.ts`'s own docblock. That
  verdict is correct; do not work around it with a trust anchor or key fetched from anywhere
  other than the second channel described above, or you have reintroduced the exact trust
  dependency this tool exists to remove.
- **The bundle-schema contract this verifier parses is itself gated against drift**:
  `scripts/contract-drift.mjs` (CI job `contract-drift`) diffs `be-core`'s bundle producer
  against this package's `BundleActionEvent`/`BundleManifest`/`signableActionEvent`/
  `verifyManifest` on every PR to either repository, specifically prioritizing the fields
  that enter the SIGNED preimage — the exact class of bug that made action-event
  signatures unverifiable for one release (`SEC-PA01-DISCOVERED-01`). Check [H] (AV-0003)
  diffs `be`'s AIBOM attestation envelope against `src/aibom.ts` the same way: format and
  domain strings, the envelope field set (each read or declared unauthenticated) and the
  `signingAlgorithm` set.

## Architecture

This package is intentionally **decoupled** from `be-core`:

- `package.json` `dependencies` is `{}` — zero runtime dependencies.
- `tsconfig.json` sets `rootDir: "src"` and an empty `paths` map; no
  imports can escape the package boundary.
- All crypto primitives are vendored under `src/crypto.ts`. They are
  byte-for-byte compatible with `be-core`'s
  `CryptoUtilsService` (AGV-003), `canonicalJson` (AGV-030), and
  `MerkleRootService` (AGV-033) — same DER prefixes, same RFC 6962
  domain-separation bytes, same key-ordering rules.
- The PKZIP reader in `src/zip.ts` reads STORED-method entries produced
  by `BundleExporterService`'s `ZipStreamWriter` (AGV-035).
- **No network calls at all** — the Rekor receipt is verified offline
  against a public key pinned into `src/rekor.ts` (SET signature + signed
  checkpoint + inclusion proof), so even the transparency-log check needs
  no network.
- No telemetry, no analytics, no payload logging — the verifier prints
  per-component pass/fail counts and the id of the first offending row.

## Changelog

### 0.10.0 (SCAN-AV-01 — `detailsCommitment` signable row field)

- **`detailsCommitment` is now a recognized (optional) signable row field**, the same additive,
  presence-guarded treatment `ipAddress` got in `0.4.0`: included in the canonical preimage IFF the
  wire row carries that key at all, with no cutover-date knowledge in this verifier. Unlike
  `ipAddress`, it REPLACES `summary`/`details` on the rows that carry it (`be-core`'s
  `AUDIT_DETAILS_COMMITMENT_CUTOVER_AT`), rather than joining them — rows produced today (the
  cutover is far-future by default in every known `be` deployment) are byte-for-byte unaffected.
  `MAX_SUPPORTED_MANIFEST_VERSION` is unchanged (still `5`): this is a row-level, self-describing
  field, not a manifest-level one, same as `ipAddress` never claiming its own manifest version.
- **Correctness fix: `canonicalJson` now omits an object key whose value is `undefined`**, instead
  of canonicalizing it as `"key":null`, matching `be-core`'s FROZEN, documented
  `canonical-json.ts` behavior byte-for-byte (confirmed by independently executing `be-core`'s real
  implementation, not by re-deriving the rule from this package's own code). This was a genuine,
  if previously unreachable-in-practice, divergence from this file's own "byte-for-byte identical
  to be-core's `canonicalJson`" claim — reachable the moment any signed object legitimately omits a
  key (exactly the shape `detailsCommitment` rows introduce for `summary`/`details`).
- **Verification-strictness change: none for any existing bundle.** Both changes are additive/
  corrective on a code path (an object key that is genuinely absent from the wire) no bundle
  produced by any shipped `be` version can exercise today; the full pre-existing 173-test suite
  passes unmodified alongside 4 new tests.
- **Known producer gap** (not a defect in this package, filed as `SCAN-BE-17` for `be-core`):
  `bundle-exporter.service.ts`'s `serializeRow` does not yet copy `detailsCommitment` onto the wire
  at all, so activating the cutover is still unsafe until that lands — this release is a
  prerequisite for activation, not by itself sufficient to make activation safe.

### 0.9.2 (MIL-0002 / CD-0002 — release-integrity hardening, no verification-strictness change)

- **`npm publish --provenance`**, `id-token: write` permission on the publish workflow — a
  customer can confirm the exact published tarball corresponds to a specific CI run/commit, not
  just trust an npm-token holder's say-so. The workflow's human gate is no longer a static
  `if: false`: it now triggers only on a protected `v*` tag whose value is checked against
  `package.json` and whose commit must be contained in `main` (a human still has to cut and push
  that tag), and `npm pack --dry-run` runs the
  `prepack` hook — `scripts/assert-release-trust-anchor.mjs` — before the publish step, so the
  job still cannot ship a tarball while `PLATFORM_PUBLIC_KEY_DER_B64`/`_FINGERPRINT` are empty.
- **`npm audit --audit-level=high`** added to CI (previously the only repo in the monorepo
  without one). The pre-existing critical/high `vitest`→`vite`→`esbuild` devDependency chain
  advisories are resolved by upgrading `vitest` `2.1.9` → `4.1.10` (all 152 tests still pass
  unmodified) — no `--omit=dev` scoping needed.
- **New `contract-drift` CI job** (`scripts/contract-drift.mjs`, CD-0002): diffs `be-core`'s
  bundle producer (`serializeActionEvent`, the manifest builder, `SignableProtectedActionEventRow`)
  against this package's consumer types (`BundleActionEvent`, `BundleManifest`,
  `signableActionEvent`, `verifyManifest`) on every PR, prioritizing the fields that enter the
  SIGNED preimage — the exact seam that broke once already (`SEC-PA01-DISCOVERED-01`) with no
  gate to catch it. Verified today: clean against the real `be` tree; fails with a specific
  field-level message when a field is added/removed on either side (proved against a scratch
  copy, never the real `be` tree).
- **`--allow-legacy-unattested` now prints a loud `WARNING:` line** (mirroring the existing
  `--no-rekor` `NOTE:`) whenever a bundle with no platform-attestation entry was accepted under
  that explicit opt-in — a skimmed `RESULT: OK` must never read as "Praesidia vouched for this
  bundle's signing keys" when that check was bypassed. The flag itself and its underlying
  fail-closed default were already correct and are unchanged.
- **No verification-strictness change**: every existing pass/fail verdict is unchanged for every
  existing bundle. `platform-pubkey.ts`'s empty trust-anchor pin and its fail-closed
  `platform_key_not_pinned` behavior are untouched and remain user-owed (production key
  ceremony, tracked with MIL-0003). A key-hierarchy design for in-band platform-key rotation is
  written up (`docs/design/platform-key-hierarchy.md`) but not built.

### 0.9.1 (PA-0033 — HIGH-1 security re-attack fix, `PA01-SEC-reattack.md`)

- **`closureLegality` now requires the evidencing event to carry a POSITIVE outcome, not merely
  exist.** A security re-attack found that `be` records a client-side timeout as
  `CALLER_RESULT_OBSERVED{success:false}` — the same wire shape a genuine negative tool result
  produces — so a bundle claiming `FAILED_NO_EFFECT`/`EVIDENCED` built on nothing but a timeout
  previously verified `valid`. Fixed via a new optional `CALLER_RESULT_OBSERVED.payload.outcomeClass`
  field (`completed_success` / `completed_with_error` / `no_response_received`, paired with `be`'s
  PA-0034): a confirmed `no_response_received` is `invalid`
  (`closure_evidencing_event_not_positive`, the HIGH-1 regression guard); `TARGET_ACKNOWLEDGED`
  remains unconditionally positive (D9: this event type has no "no answer" shape).
- **New `incomplete` case, not a silent `valid`.** A v5 bundle whose `CALLER_RESULT_OBSERVED` events
  predate the `outcomeClass` field (`success: false`, field absent) cannot be told apart from a
  timeout offline — this now verifies `status: 'incomplete'`
  (`closure_evidencing_event_ambiguous`), never `valid`. Scoped to `success: false` only:
  `success: true` (every existing happy-path bundle) is unaffected — a genuine completion can never
  be produced by a timeout, so it was never ambiguous.
- `callerResult` structurally validates `outcomeClass` when present: must be one of the three
  recognized values and consistent with `payload.success`.
- **Verification-strictness change: tightened, not weakened.** New failure/incomplete modes only; no
  previously-`invalid` bundle becomes `valid` or `incomplete`, and no previously-`valid`
  `success:true` bundle is affected.

### 0.9.0 (PA-0010 — manifest v5 action-event evidence, `PA01-CONTRACT-manifest-v5-actions.md`)

- **`manifest.version: 5` is now understood.** Adds `actionEventCount` /
  `captureScopeDigest` / `evidenceGradeSummary` inside the signed manifest
  preimage and a new REQUIRED-even-when-empty `action-events.ndjson.gz`
  entry. Same fail-closed-both-directions version negotiation as v3/v4
  (named reasons: `action_event_count_present_on_v{n}_manifest` /
  `_missing_on_v5_manifest`, etc.).
- **Nine new components** (see invariants 13-21 above):
  `actionEventChain`, `permitBinding`, `requestBinding`,
  `dispatchIntegrity`, `targetAck`, `callerResult`, `closureLegality`,
  `evidenceGrade`, `actionCompleteness`. All nine report `unsupported` on
  `manifest.version < 5`, never dragging the verdict down.
- **`evidenceGrade` DERIVES the grade, never trusts `be`'s declaration**
  (`PA01-DECISIONS.md` corrigendum C4) — a declared grade exceeding what
  the shipped evidence actually supports is `invalid`
  (`declared_grade_exceeds_derived_evidence`), and an `enforcementMode:
  'enforce'` declaration contradicted by an observe-mode event is
  `invalid` (`observe_mode_action_counted_as_enforced`).
- **`closureLegality` re-derives D7's frozen closure state machine
  independently** and requires an ACTUAL evidencing event for any closure
  claiming a determined outcome, regardless of the declared `reason` —
  this is what makes a bundle claiming `FAILED_NO_EFFECT` with only
  timeout evidence verify as `invalid`.
- **`targetAck`/`callerResult` can report `status: 'incomplete'`** — the
  first components in this package to use that state — when the relevant
  evidence event is legitimately redacted (`payload: null` with a present
  `payloadCommitment`).
- New `VerifyReport.bundle.actionEventsSeen` field (additive).
- **Known producer gap** (not a defect in this package): `be` commit
  `e9e39b88` omits six fields (`timeSource`, `permitNonce`, `edgeVersion`,
  `adapterVersion`, `externalReceiptRef`, `artifactStorageRef`) required
  to reconstruct the signed per-event preimage — a real `be` v5 bundle
  with non-empty action-event content is correctly rejected as a
  bundle-format error until `be`'s `PA-0027` lands.

### 0.7.0 (FIX01 audit-verifier2 — sealed-purge cross-check, `BE-0003`)

- **New, wholly optional bundle entry `sealed-purges.ndjson.gz`** (see
  invariant 12) — one independently-signed `AuditRetentionSeal` entry per
  legitimate retention purge overlapping the bundle. Deliberately **NOT**
  part of the signed manifest preimage (no `manifest.version` bump, no new
  signed count) — each entry's own signature is the sole tamper-evidence,
  by design (see the README's "Why this entry is unsigned" note).
- **`rootCoverage` no longer reports tampering on a legitimately sealed
  retention purge** (`BE-0003`, closed): a root-period shrinkage is
  downgraded to a named `seal_exempted` pass when a VERIFIED sealed-purge
  entry names the exact same `(periodStart, periodEnd, rootHash)`. An
  unexplained shrinkage — or one where the actual count EXCEEDS the
  committed count, which no purge can explain — still fails closed exactly
  as before.
- **`integrityCheckpoints`'s documented residual (a legitimate purge
  reading as tampering) is now closed the same way**: a
  `cumulative_row_count_decreased` or `chain_head_hash_mismatch` finding
  between two checkpoints is downgraded when VERIFIED sealed-purge entries
  whose `deletedAt` falls in that exact checkpoint window sum to at least
  the observed decrease. An empty seal window is NEVER treated as
  reconciling, even when the raw arithmetic would otherwise be trivially
  satisfied (e.g. a hash mismatch with no count change) — an exemption
  always names at least one real, verified seal.
- **Both downgrades are strictly a narrowing of the failure surface,
  never a widening** — a bundle with no sealed-purge evidence at all (or
  only unverifiable/non-matching entries) verifies byte-for-byte as
  before this release; confirmed by the full pre-existing 95-test suite
  passing unmodified alongside the new tests.
- New `ComponentResult.sealExemptions` field (additive) on `rootCoverage`
  and `integrityCheckpoints`, and new `VerifyReport.bundle.sealedPurgesSeen`
  / `sealedPurgesVerified` counters (additive). New CLI output lines.
- `rowCount` on `BundleSealedPurge` is bigint-as-string and is NEVER
  re-parsed as a `Number` anywhere in this verifier (the same discipline
  already applied to `cumulativeRowCount`/`chainSeqCeiling`) — only
  `BigInt(...)` comparisons and digit-string regex validation.

### 0.6.0 (FIX01 F5(b))

- **`manifest.version: 4` is now understood** (`PROD16-CONTRACT-manifest-v4-checkpoints.md`).
  Adds `integrityCheckpointCount` inside the signed manifest preimage and a
  new, conditionally-required bundle entry `integrity-checkpoints.ndjson.gz`
  carrying `be`'s `AuditIntegrityCheckpointService` rows
  (`{organizationId, chainHeadHash, cumulativeRowCount, asOf}`, each
  independently signed). Same both-directions version/field-presence rule
  as v3's `chainSeqCeiling`/`chainSeqSnapshotAt`
  (`integrity_checkpoint_count_present_on_v{1,2,3}_manifest` /
  `integrity_checkpoint_count_missing_on_v4_manifest`).
- **New `integrityCheckpoints` component** (see invariant 11 above):
  authenticates each checkpoint's signature, requires monotonic
  non-decreasing `cumulativeRowCount` across checkpoints, and cross-checks
  each checkpoint's `chainHeadHash` against the bundle's own reconstructed
  row chain as of that instant — closing PART of the previously-documented
  "un-rooted tail / boundary period has no independent size commitment"
  gap. See the "does NOT prove" section above for exactly which part
  remains open (pre-v4 bundles; a checkpoint whose window predates every
  bundled row; and a documented, explicit residual against the
  already-shipped `AuditRetentionSeal` hard-purge mechanism, which this
  verifier cannot yet distinguish from tampering).
- `MAX_SUPPORTED_MANIFEST_VERSION` raised from 3 to 4.
- `manifest.integrityCheckpointCount` (optional, additive) and
  `completeness` now also binds it to the number of checkpoints actually
  present, same anti-suppression rationale as `rowCount`/`rootCount`.
- New `VerifyReport.integrityCheckpoints` field (additive) and a new CLI
  output line. v1/v2/v3 bundles are completely unaffected — confirmed by
  the full pre-existing 84-test suite passing unmodified alongside 11 new
  tests built from `be`'s actual entity/service field set and signed
  preimage, not a hand-built guess of it.

### 0.5.0 (PROD16 §1b)

- **`manifest.version: 3` is now understood.** `be` commit `dc5b8a97` added
  `chainSeqCeiling`/`chainSeqSnapshotAt` INSIDE the signed manifest preimage
  and bumps the wire version to 3 for bundles carrying them
  (`PROD16-CONTRACT-manifest-v3.md`). Every bundle exported by that `be`
  version previously failed with a generic `manifest signature does not
  verify` because the verifier's signable whitelist was fixed at 9 fields
  regardless of declared version. The whitelist is now selected by
  `manifest.version` (9 fields for v1/v2, 9 + the two new fields for v3),
  still a closed selection — never reconstructed by stripping `signature`
  from the received object, which would let an attacker inject
  unsigned-looking fields into a signed payload.
- **Two new fail-closed reason codes**, one per direction of version/field
  mismatch: `chainseq_fields_present_on_v{1,2}_manifest` (the two v3 fields
  illegitimately present on an older-declared manifest — no genuine v1/v2
  producer ever emits them) and `chainseq_fields_missing_on_v3_manifest`
  (a `version: 3` manifest missing one or both — no genuine v3 producer
  ever omits them). Distinct from the generic signature-failure reason so
  an auditor can tell version skew from tampering.
- `MAX_SUPPORTED_MANIFEST_VERSION` raised from 2 to 3.
- No `VerifyReport` shape change. v1/v2 bundles (everything produced before
  `dc5b8a97`, and everything produced by `be` deployments that stay on v2)
  verify exactly as before — confirmed by the full pre-existing suite
  passing unmodified.

### 0.4.0 (PROD16)

- **New `rootCoverage` component** closes the suffix-deletion gap: a
  Merkle root's signed `rowCount` is now bound to the rows/proofs actually
  present in the bundle for every fully-contained period. Before this, a
  root anchored before rows were deleted (and never recomputed) would
  verify `ok:true` even though the rows it committed to no longer existed.
- **Chain verification (`chain`) no longer depends on the bundle's on-disk
  row order.** The true chain is now reconstructed from the cryptographic
  links themselves, closing a false-positive "chain break" that could fire
  on an honest bundle whenever two rows in the same org share a `signedAt`
  millisecond (the exporter orders by `(signedAt, id)`, not by the actual
  signing/chain order).
- **`manifest.version` now has an explicit ceiling.** A manifest declaring
  a version newer than this build implements is rejected as a bundle-format
  error instead of being silently verified under the wrong (older) rules.
- **`ipAddress` is now a recognized (optional) signable row field.** Rows
  produced under `be-core`'s `IP_ADDRESS_SIGNABLE_CUTOVER_AT` activation
  now verify correctly; rows without the field are unaffected.
- **Rekor "no receipt" messaging is now specific.** `no_external_witness`
  (no root in the bundle is anchored) and
  `anchor_missing_for_partially_anchored_bundle` (some roots are anchored,
  this one isn't) are now distinct reason codes instead of one generic
  `missing_anchor_receipt`. `--no-rekor` now prints an explicit CLI `NOTE:`
  line so a skimmed `RESULT: OK` cannot be mistaken for a verified anchor.
- New `VerifyReport.rootCoverage` field (additive).

### 0.3.0

- Platform attestation and trust-key absence now fail closed by default;
  explicit legacy opt-in and `--platform-key` are available for controlled
  migration.
- Rekor receipts are bound to the exact root hash and signature, S3 receipts
  require a real caller-supplied verifier, and proof coverage is complete.
- ZIP parsing now enforces unique names, CRC/header integrity, strict UTF-8,
  and decompression/resource limits.

- **Rekor receipts are now verified cryptographically (BUGHUNT-SDK-05).**
  The default Rekor check was previously `JSON.parse(receipt)` — it passed
  for any parseable JSON (even `{}`), so `rekor receipts OK` was false
  assurance. The verifier now checks the receipt's SET signature and signed
  checkpoint against the pinned Sigstore key and walks its inclusion proof
  to the checkpoint-authenticated `rootHash`
  (fully offline, `src/rekor.ts`); a non-genuine receipt now fails. New
  optional `verifyBundle` option `rekorPublicKeyPem` pins a sovereign
  Rekor key. `report.rekor.checked` still counts one per anchor entry.
- **Partial-range (non-genesis) bundles verify (BUGHUNT-SDK-02).** The
  chain check treated the first bundle row's `prev_row_hash` as an opaque
  anchor into the org's pre-range history instead of requiring the all-zero
  genesis, so a legitimate date-ranged export from an org older than 90
  days no longer falsely FAILS. Internal linkage for rows `[1..]` is still
  enforced; leading truncation is still caught by `completeness`.
  `report.chain.checked` now counts inter-row link assertions
  (`rows − 1`) rather than rows.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

### Independently pinned HTTP target receipts

Grade A now requires a verified `praesidia.http-receipt.v1` receipt with matching original request and observed result commitments. Signature presence alone is rejected. Supply `verifyBundle(zip, { targetPublicKeys: { "organizationId:targetId:keyId": ed25519PublicKeyPem } })`, or `--target-keys pins.json`. Obtain those pins separately from the bundle; platform attestation keys remain a separate trust input. Missing pins, changed request/result/closure, and invalid target signatures fail verification. A signed target assertion does not independently observe effects outside that target.
