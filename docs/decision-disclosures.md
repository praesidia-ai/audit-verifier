# Decision disclosures — `evidence/decision-receipts.ndjson` (AV-0009 ↔ be BE-1585)

Producer: `be/src/audit/decision-receipt.service.ts` (`collectDecisionDisclosures`,
`DecisionDisclosureLine`), written by `be/src/audit/services/audit-package.service.ts`
into the audit package next to `evidence/audit-bundle.zip`. Consumer:
`src/decision-disclosures.ts`. The file is **unsigned**; a line is trusted only
through the signed bundle row it opens.

## Line schema

UTF-8, one JSON object per `\n`-terminated line, no blank lines.

Disclosure line (exactly these keys):

```json
{"version":"praesidia.decision-disclosure.v1","rowId":"<audit_logs.id>","decisionId":"<string>|null","details":{...},"detailsSalt":"<base64>"}
```

Trailer (exactly one, always the last line):

```json
{"version":"praesidia.decision-disclosure.v1","withheld":<non-negative integer>}
```

`withheld` counts commitment-signed decision rows whose details were erased (or no
longer open their commitment); be never discloses substitute content for them.

## `decisionReceipt` (per disclosure line)

1. `rowId` names a row in `rows.ndjson.gz` (else `invalid`: not in the bundle).
2. That row's action is `POLICY_DECISION` or `POLICY_VIOLATION` and it carries a
   signed `detailsCommitment` string.
3. `base64(sha256(base64decode(detailsSalt) || canonicalJson({ details })))` equals
   that `detailsCommitment` — the formula of be
   `AuditCanonicalHelper.computeDetailsCommitment`, with the same canonicaliser the
   verifier already uses for row signatures (pinned against be's real output in
   `src/__tests__/decision-disclosures.spec.ts`).
4. `decisionId` equals `details.decisionId` when that is a string, else `null`.

Any failure, an unknown `version`, extra/missing keys, non-strict base64 salt, a
duplicate `rowId`, an unparseable line or a missing/misplaced trailer → `invalid`.
No file → `not_present`. Every opening matched but row signatures did not verify →
`incomplete`. The reason line reports opened / withheld / not-opened counts;
"not opened" (commitment-signed decision rows in the bundle with no line) is
reported, not failed: the trailer is unsigned, so omission cannot be proven offline.

## `policyReference` (per verified Decision Record v1 payload)

Payloads with `schemaVersion: 1` (be `decision-record.ts`) must carry:
`policyId` and `policyVersion` (present; non-empty string or `null`), `decision` in
`ALLOW|DENY|STEP_UP|OBSERVED`, a row action matching it (`DENY` ⇔
`POLICY_VIOLATION`), a `canonicalDecision` consistent with it when present, and —
for an `ALLOW` with `reasonCode: "approval_consumed"` (the allow that follows a
step-up approval) — a non-empty `approvalId`. Another `schemaVersion` → `invalid`.
Payloads with no `schemaVersion` predate Decision Record v1 and are counted as
carrying no reference. Distinct `(policyId, policyVersion)` pairs are reported.
The policy **text** is not in the package; only the reference is verified.

## `--decision <decisionId>`

Prints the verified fields of that decision (decision, policy reference, rule,
approvalId, actor, action/resource, tool = `details.fnName`, and the signed row's
`createdAt`). Exit 0 only when the decision is disclosed and the whole report is
`valid`; otherwise exit 1. Decision Record v1 has no approver field: approvals are
separate audit rows; on an approved dispatch the `actor` is the approving user.
