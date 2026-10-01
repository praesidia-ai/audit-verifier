# Compatibility matrix

Which `@praesidia/audit-verifier` version reads which Praesidia artefact format.
Use the newest verifier: every row reads all the formats of the rows below it.
A verifier fails closed on a format it does not know. It never skips one.

| Verifier | Bundle manifest `version` | Audit package (AV-0007) | Decision disclosure v1 (AV-0009) | `praesidia.http-receipt.v1` | AIBOM attestation v1 | Superseding root (AV-0016) | Min Node |
|---|---|---|---|---|---|---|---|
| 0.11.0 (Unreleased) | 1–7 | yes | yes | yes | yes | yes | >=22.12.0 |
| 0.10.0 | 1–5 | — | — | — | — | — | >=22.12.0 |
| 0.9.0 – 0.9.2 | 1–5 | — | — | — | — | — | >=22.12.0 |
| 0.6.0 – 0.8.0 | 1–4 | — | — | — | — | — | >=22.12.0 |
| 0.5.0 | 1–3 | — | — | — | — | — | >=22.12.0 |
| 0.4.0 | 1–2 | — | — | — | — | — | >=22.12.0 |
| ≤ 0.3.0 (unsupported) | ≥ 1, no ceiling | — | — | — | — | — | >=18.0.0 |

`—` means that version has no code for the format. Do not use it to verify that artefact.
No version tag exists in this repository yet, so every row is a source-tree version.

## Where the code decides each cell (current row)

`src/__tests__/compatibility.spec.ts` checks every `path:line` citation below
against the quoted code, and checks the current row against `package.json` and
`src/verify.ts`. If a line number drifts, the test goes red.

- **Bundle manifest 1–7.** The ceiling is `src/verify.ts:1285` `const MAX_SUPPORTED_MANIFEST_VERSION = 7;`.
  The version gate at `src/verify.ts:5706` `manifest.version < 1 ||` and `src/verify.ts:5707` `manifest.version > MAX_SUPPORTED_MANIFEST_VERSION`
  rejects version 0 and anything newer than 7. A newer version throws a
  bundle-format error ("upgrade the verifier"), so the bundle does not verify.
- **Audit package.** The format has no version field. A zip counts as an audit package when it has
  `src/package.ts:18` `export const PACKAGE_BUNDLE_ENTRY = 'evidence/audit-bundle.zip';`
  and no top-level `manifest.json` (`src/package.ts:52` `!byName.has('manifest.json') && byName.has(PACKAGE_BUNDLE_ENTRY)`).
  The inner bundle then goes through the manifest gate above.
- **Decision disclosure v1.** The version string is `src/decision-disclosures.ts:14` `export const DECISION_DISCLOSURE_VERSION = 'praesidia.decision-disclosure.v1';`.
  Any other line version fails: `src/decision-disclosures.ts:170` `line.version !== DECISION_DISCLOSURE_VERSION`.
  The disclosed Decision Record must have `src/decision-disclosures.ts:221` `d.details.schemaVersion === 1`.
- **`praesidia.http-receipt.v1`.** The version string is `src/http-receipt.ts:4` `export const HTTP_RECEIPT_VERSION = 'praesidia.http-receipt.v1'`.
  Any other version is rejected: `src/http-receipt.ts:49` `s.version !== HTTP_RECEIPT_VERSION`.
  These receipts are read from manifest v5 action events: `src/verify.ts:3653` `return verifyHttpReceipt(payload.receipt`.
- **AIBOM attestation v1.** The format string is `src/aibom.ts:34` `export const AIBOM_ATTESTATION_FORMAT = 'praesidia-aibom-attestation/v1';`.
  Any other format gives `unsupported_format`: `src/aibom.ts:125` `env.attestationFormat !== AIBOM_ATTESTATION_FORMAT`.
- **Superseding root (AV-0016).** Optional root fields `supersedesRootId` and
  `supersessionSignature`. The signed envelope is versioned by
  `src/verify.ts:483` `export const ROOT_SUPERSESSION_VERSION = 'praesidia.root-supersession.v1';`.
  A link must name a root in the bundle with the same period and a lower row count
  (`src/verify.ts:526` `: old.rowCount >= root.rowCount`), otherwise `rootCoverage` fails.
  Roots without the fields take the old path unchanged (`src/verify.ts:519` `if (root.supersedesRootId === undefined) continue;`).
  Older verifiers have no code for the fields. They fail such a bundle closed, on the partial
  root's row count and on the second proof per row. They never pass it.
- **Evidence privacy (manifest v6, AV-0013).** The mode table version is
  `src/evidence-privacy.ts:17` `export const EVIDENCE_PRIVACY_SCHEMA_VERSION = 1;`. Any other
  `evidencePrivacy.schemaVersion` is a bundle-format error. Verifiers before 0.11.0 reject every v6 manifest.
- **Tenant signature format 2 (manifest v7, AV-0018, ADR-0004).** Format 2 signs
  `src/crypto.ts:443` `praesidia:${purpose}:v2\n` followed by the payload
  (the purpose is fixed by the slot being verified). Any `signatureFormat` other than 1 or 2 fails
  (`src/verify.ts:1910` `if (f !== 1 && f !== 2) {`); a format-1 signature dated at or after the signed
  v7 `signatureFormatCutoverAt` fails (`src/verify.ts:1913` `if (f === 1 && cutoverMs !== null) {`).
  An absent `signatureFormat` is 1, so v1–v6 bundles verify unchanged. Verifiers before 0.11.0
  reject every v7 manifest, and none of them can verify a format-2 signature.
- **Min Node.** From `package.json:34` `"node": ">=22.12.0"`.

## Where the code decided each older row

These are git citations (`<commit>:<path>`). The spec does not check them, because CI clones
with depth 1. Re-check one with `git grep -n MAX_SUPPORTED_MANIFEST_VERSION <commit> -- src/verify.ts`.

| Row | Commit | Deciding code |
|---|---|---|
| 0.10.0 | `ed151e1` | `src/verify.ts` `const MAX_SUPPORTED_MANIFEST_VERSION = 5;`. `src/package.ts`, `src/decision-disclosures.ts`, `src/http-receipt.ts` and `src/aibom.ts` do not exist yet. |
| 0.9.0 – 0.9.2 | `f473721`, `ffc1876` | `const MAX_SUPPORTED_MANIFEST_VERSION = 5;` (manifest v5 action events, PA-0010) |
| 0.6.0 – 0.8.0 | `b7658ba`, `358c3e9` | `const MAX_SUPPORTED_MANIFEST_VERSION = 4;` |
| 0.5.0 | `0834284` | `const MAX_SUPPORTED_MANIFEST_VERSION = 3;` |
| 0.4.0 | `debd710` | `const MAX_SUPPORTED_MANIFEST_VERSION = 2;` |
| ≤ 0.3.0 | `e62ae89` | only `manifest.version < 1` is rejected. A manifest newer than the build **was accepted** and checked against an older field set. The ceiling arrived in `007ba41`, which is still labelled 0.3.0. The Node floor rose to `>=22.12.0` at `f45ed07`. Do not use these builds. |

`src/http-receipt.ts` first appears at `bbf784c`, the same commit that set 0.11.0.
`src/aibom.ts` first appears at `972c170`, `src/package.ts` at `c1ebdb3` and
`src/decision-disclosures.ts` at `fc868d3`. All of these are 0.11.0.

## Keeping this file current

- When you bump `package.json` `version`, add a row, or the spec fails.
- When you raise `MAX_SUPPORTED_MANIFEST_VERSION`, update the current row's manifest cell and its citation.
- A new artefact format gets a new column, plus a `path:line` `quote` citation for the code that gates it.
