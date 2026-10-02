# `@praesidia/audit-verifier` — operations

Condensed build/test/CLI-usage reference. Full CLI flag reference, verdict-shape JSON schema, and
trust-anchor ceremony detail live in the root `audit-verifier/README.md`.

## Requirements

Node.js `>=22.12` (`README.md:12` `Node.js 22.12 or newer is required.`). Zero runtime dependencies
(`package.json`'s `dependencies: {}`).

## Local development

```bash
cd core/audit-verifier
npm install
npm run build          # tsc -> dist/
npm run typecheck
npm run typecheck:spec
npm test                # vitest run
```

(The script list starts at `package.json:37` `"scripts": {`.)

## Running the CLI locally against a bundle

```bash
npm run build
node dist/cli.js <bundle.zip>                       # full verify
node dist/cli.js <bundle.zip> --json                 # machine-readable VerifyReport
node dist/cli.js <bundle.zip> --no-rekor             # skip offline Rekor receipt check
node dist/cli.js <bundle.zip> --platform-key <file>  # trust an alternate pinned key
node dist/cli.js <bundle.zip> --trust-anchor <file>  # local copy of /.well-known/praesidia-audit-keys.json (AV-0017)
node dist/cli.js verify-set <bundle1.zip> <bundle2.zip> ...   # cross-bundle continuity (SCAN2-004)
node dist/cli.js aibom <file.attested.json> --tenant-key-fingerprint <hex>  # AIBOM export (AV-0001)
```

Exit codes and the `--quiet`/`--allow-legacy-unattested` flags are documented in the
README's "Usage" section (`README.md:101` `## Usage`).

## Trust-anchor release gate

```bash
npm run check:release-trust-anchor   # node scripts/assert-release-trust-anchor.mjs
npm run check:trust-anchor-ci        # node scripts/check-trust-anchor-ci.mjs
npm run test:trust-anchor-policy     # node --test scripts/trust-anchor-policy.selftest.mjs
```

`prepack` (`package.json:39` `"prepack": "npm run build && npm run typecheck:spec && npm run check:release-trust-anchor"`)
runs build + `typecheck:spec` + `check:release-trust-anchor` automatically before packaging — a
release with a missing/mismatched/non-P-256 operator-approved fingerprint cannot be packed
(`README.md:1088` `rejects a missing value, a mismatch, a non-canonical key, or any EC curve`).

## Contract-drift gate

`scripts/contract-drift.mjs` (CD-0002/SCAN-AV-03) checks this package's assumptions about `be`'s
signable-row/bundle contract. Run it as documented in that script's own header/CI wiring; it
requires a sibling `be` checkout to diff against (this package has no runtime dependency on `be`
at execution time — only this drift check reads its source).

## Publishing (see `README.md`'s "Trust anchor" section for the full ceremony detail)

Not yet published — `npm view @praesidia/audit-verifier` → `404` (re-confirmed live 2026-09-12,
`.claude/tickets/CLOSE/TRIAGE-rest.md`'s `MKT-0002` row). `npm publish --provenance` (MIL-0002 F4)
is configured so that once published, `npm view @praesidia/audit-verifier provenance` will show a
SLSA attestation binding the tarball to the exact GitHub Actions run/commit that built it
(`README.md:1097` `(MIL-0002 F4) means`).

## Failure modes — what to check first

| Symptom | Likely cause | Where to look |
|---|---|---|
| Verify reports `INCOMPLETE` | Bundle missing an expected component (e.g. no chain-continuity fields, no Rekor receipt when one was expected) | `README.md:379` `## Verdict shape`, `src/verify.ts` |
| `verify-set` fails closed | One or more bundles in the set lack chain fields — by design (SCAN2-004) | `src/cli.ts:1058` `async function mainVerifySet(`; `f13793e` pins this behavior |
| Rekor check fails | Embedded/pinned key mismatch, or a genuinely tampered receipt — never a network issue, since this check is fully offline | `src/rekor.ts:685` `export function verifyRekorReceipt(` |
| `prepack` fails at release time | Operator-approved fingerprint missing/mismatched/wrong curve | `scripts/assert-release-trust-anchor.mjs`; `README.md:1088` `rejects a missing value, a mismatch, a non-canonical key, or any EC curve` |
| Bundle rejected before full read | Archive/entry size exceeds `MAX_ZIP_*_BYTES` caps | `src/zip.ts:71-73` `export const MAX_ZIP_` |

## `verify-set` limit: rows deleted from the end of the history

`verify-set` checks each bundle with rows against the next bundle with rows. The later bundle's
chain head must link back to the earlier bundle's newest row, through any empty bundles between
them (AV-2756). The newest bundle with rows has no later bundle to be checked against. So when a
set ends in one or more empty bundles, rows deleted from the end of the history, inside those
empty windows, break no chain link that the set can see. Each empty bundle's own checks still
apply: a Merkle root whose whole period lies in that bundle's window and committed to rows fails
the bundle (`rootCoverage`). Rows that no such root covers (the un-rooted tail, a boundary period,
or a period whose root was removed with them) leave nothing that the verifier checks. Offline, such a window cannot be told apart from
one in which nothing was logged, and `verify-set` reports no finding for it. This limit predates
AV-2756.

Exact verdicts (AV-2764). Take rows that were signed in the window of the newest bundle of a set,
then deleted from the database together with their Merkle roots before the export, with no
retention seal. The export of that window is a validly signed bundle with `rowCount` 0:

- **Manifest v5 or later:** the bundle is `valid` on its own (exit 0), because its signed zero
  action-event and evidence-grade counts verify (AV-0008). `verify-set` reports `continuous`
  (exit 0). Both reports are the same as for a window in which nothing was logged.
- **Manifest v1-v4:** the bundle is `incomplete` on its own, and the set is `bundle_incomplete`
  (exit 3). Exit 3 says that the window is unproven. It does not say that rows were deleted.

Offline, the deletion is caught only in one of these cases:

- A later bundle in the set has rows. Its chain head must link back across the window
  (`boundary_chain_mismatch`; see below).
- A Merkle root that committed to the rows is still in the bundle, and its whole period lies in
  the window (`rootCoverage`).
- Two integrity checkpoints in the bundle (manifest v4 or later) record the drop. One was signed
  while the rows existed, and a later one claims a lower `cumulativeRowCount`
  (`integrityCheckpoints`). `be` signs a checkpoint once an hour, so no such pair exists if the
  rows were deleted before the next checkpoint. Deleting those checkpoints as well also leaves no
  pair, because the signed `integrityCheckpointCount` counts the checkpoints left at export. A bundle with no rows
  has no rows to compare a checkpoint's `chainHeadHash` with, so that hash is not checked.

What an operator can do:

- **Treat the end of the set as unconfirmed.** A set that ends in an empty bundle proves nothing
  about rows after its newest bundle with rows. That holds even when the set reports
  `continuous`. In the `--json` report, check whether the last entries of `bundles[]` have
  `rowsSeen: 0`.
- **Verify again with a later export.** Once the next window holds rows, export it from the
  set's last `to`, add it to the set and run `verify-set` again. Its chain head must link back,
  across the empty bundles, to the last row before them. Rows deleted under the empty bundles
  then show up as a `boundary_chain_mismatch` that names them, unless a verified sealed purge
  bridges the gap.
- **Compare against an earlier export of the same window**, if one was archived. A window that
  held rows in an earlier export (`rowsSeen` in the `--json` report) and is empty in a later one,
  with no sealed purge for those rows, has lost rows.

## Verification limits

Commands verified against `package.json` and `README.md` this pass (2026-09-12); not
independently re-run against a live bundle export/verify round-trip in this session.
