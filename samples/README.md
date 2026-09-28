# Sample audit packages (AV-0011) — TEST KEYS ONLY

**SAMPLE — NOT A PRAESIDIA KEY.** Every file here is signed with test keys
derived from public labels in `scripts/make-sample-bundles.mjs`, so their
private halves are public. A sample that verifies proves only that the
verifier works; it says nothing about Praesidia. No private key is committed.

| File | What it is |
| --- | --- |
| `audit-package.valid.zip` | An audit package: signed bundle (4 hash-chained rows, one signed Merkle root, a platform attestation), its `verification.txt` receipt, and decision disclosures for a decision → approval → outcome trio (STEP_UP on `send_email`, `approval.approved`, ALLOW with `approval_consumed`). |
| `audit-package.corrupted.zip` | The same package with ONE byte of the signed `approval.approved` row flipped. The unsigned receipt was recomputed, so only the signatures catch it. |
| `audit-package.wrong-key.zip` | A well-formed package whose platform attestation was signed by a different key than `sample-platform-key.pem`. |
| `sample-platform-key.pem` | PUBLIC half of the sample platform attestation test key (P-256, SPKI sha256 `fb4b6246b3670bbafd1c0b84b3025c0be8f486d008395fba755657e583fc7139`). |

The CLI never trusts this key on its own: without `--platform-key` (or a
`--trust-anchor` document listing it) the valid sample is `RESULT: UNANCHORED`,
exit 5 (`INCOMPLETE signature`), never OK. The samples carry no Rekor anchor (only
Sigstore can sign one), so they are verified with `--no-rekor`, and the CLI
says so on every run; without it they fail closed on `rekor receipts`.

## Run them

```bash
S=node_modules/@praesidia/audit-verifier/samples   # or ./samples in a checkout
npx praesidia-verify $S/audit-package.valid.zip     --platform-key $S/sample-platform-key.pem --no-rekor --summary
npx praesidia-verify $S/audit-package.corrupted.zip --platform-key $S/sample-platform-key.pem --no-rekor --summary
npx praesidia-verify $S/audit-package.wrong-key.zip --platform-key $S/sample-platform-key.pem --no-rekor --summary
```

Expected output (each run also prints the `--no-rekor` NOTE and the
caller-supplied-key WARNING after `RESULT`). Valid, exit 0:

```text
PASS signature
PASS hash chain
PASS decision receipt
PASS policy reference
PASS evidence integrity
NOT_PRESENT target receipt

RESULT: OK
```

Corrupted, exit 1. `FAIL signature` (row signature of `row-approval`) and
`FAIL hash chain` (the next row's link and the Merkle inclusion proof); the
decision disclosures open correctly but ride on rows that no longer verify,
so they are `INCOMPLETE`:

```text
FAIL signature
FAIL hash chain
INCOMPLETE decision receipt
INCOMPLETE policy reference
PASS evidence integrity
NOT_PRESENT target receipt

RESULT: FAIL
```

Wrong key, exit 1. `FAIL signature` (`platform attest.`: the attestation
does not verify under the key you supplied); add `--json` or drop
`--summary` to see the component detail:

```text
FAIL signature
PASS hash chain
PASS decision receipt
PASS policy reference
PASS evidence integrity
NOT_PRESENT target receipt

RESULT: FAIL
```

## Regenerate

`npm run build && node scripts/make-sample-bundles.mjs` — deterministic
(fixed keys, fixed 2026-09-01 timestamps, deterministic ECDSA nonce).
`src/__tests__/samples.spec.ts` fails if the committed bytes drift from the
generator or if any verdict above changes.
