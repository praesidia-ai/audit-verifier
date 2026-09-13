#!/usr/bin/env node
/**
 * CD-0002 — cross-repo contract gate: `be`'s bundle producer vs this
 * package's bundle consumer.
 *
 * Why this exists
 * ----------------
 * `be/src/audit/services/bundle-exporter.service.ts` produces the compliance
 * bundle wire format (`serializeActionEvent`, the manifest builder).
 * `audit-verifier/src/verify.ts` (`BundleActionEvent`, `BundleManifest`,
 * `signableActionEvent`, `verifyManifest`) consumes it. No CI job anywhere
 * checked the two against each other, and the two sides agreed only because
 * a human traced every return site by hand (see `verify.ts:191-211`). That
 * silent-agreement-by-construction already broke for real:
 * SEC-PA01-DISCOVERED-01 — `serializeActionEvent` shipped 14 of 20 fields in
 * the signed preimage, making action-event signatures unverifiable offline
 * for every org with post-migration audit activity. A human caught it during
 * a research pass, not a gate. This script is that gate.
 *
 * Technique, reused from `gateway/scripts/contract-drift.py`
 * ------------------------------------------------------------
 * Dependency-free regex/brace-depth scraping of TS source — no TS parser
 * dependency needed in CI. `verify.ts` is itself TS, so the same shallow
 * "class/interface/object-literal body, depth-1 `key:` extraction" technique
 * that script uses for `export class *Dto` bodies applies directly to TS
 * `interface` bodies and object-literal return statements here.
 *
 * Seven checks, in priority order (signature-critical first — see the
 * CD-0002 ticket note: "if the script can only cover one thing well, cover
 * WHICH FIELDS ENTER THE SIGNATURE"):
 *
 *   A. Action-event SIGNED PREIMAGE — be's `SignableProtectedActionEventRow`
 *      (`protected-action-canonical.helper.ts`, the interface actually used
 *      to sign) vs this verifier's `signableActionEvent()` reconstruction
 *      (`verify.ts`). This is the exact seam SEC-PA01-DISCOVERED-01 broke.
 *   B. Manifest SIGNED PREIMAGE — be's `manifestSansSignature` fields plus
 *      `signatureAlgorithm` (the manifest's actual signed bytes,
 *      `bundle-exporter.service.ts`) vs this verifier's `signable`
 *      reconstruction in `manifestSignableBytes()` (called by
 *      `verifyManifest`, and by the platform attestation's `manifestDigest`
 *      binding) at the newest manifest version (`verify.ts`).
 *   C. Action-event WIRE shape — be's `serializeActionEvent` emitted fields
 *      vs `BundleActionEvent`'s declared fields (`verify.ts:212-235`).
 *   D. Manifest WIRE shape — be's manifest builder (`manifestSansSignature`
 *      plus the `signature`/`signatureKeyVersion` fields added on top) vs
 *      `BundleManifest`'s declared fields (`verify.ts:98-183`).
 *   E. Platform-attestation envelope — be's `attestBundle()` attestation
 *      body literal (`platform-attestation.service.ts`) vs this verifier's
 *      `PlatformAttestationBody` interface (`verify.ts:3859-3871`). UNLIKE
 *      A-D, this check is deliberately asymmetric (see below) — the
 *      attestation body is signature-safe under additive drift by
 *      construction (MIL-0003), so [E] must not cry wolf on that case.
 *   F. Audit-row SIGNED PREIMAGE — be's `SignableAuditRow`
 *      (`audit-canonical.helper.ts`, the interface `buildSignableRow`
 *      actually signs) vs this verifier's `signableRow()` reconstruction
 *      (`verify.ts`). SCAN-AV-03 — the row-level sibling of check A: this
 *      is the exact seam SCAN-AV-01 found silently drifted (missing
 *      `detailsCommitment` entirely), caught by a security-audit pass, not
 *      a gate, before this check existed.
 *   G. Audit-row WIRE shape — be's `serializeRow` emitted fields
 *      (`bundle-exporter.service.ts`) vs `BundleRow`'s declared fields
 *      (`verify.ts`). Optionality-aware like [E] (see below) — NOT a plain
 *      A-D-style symmetric diff.
 *
 * A-D and F fail on a field present on only one side, in EITHER direction —
 * a be-only field is unrecognized by every offline consumer (both
 * `signableActionEvent` and `signableRow` are TYPED reconstructions, unsafe
 * by omission on either side); a verifier-only required field is one no
 * producer will ever populate.
 *
 * [E] and [G] are asymmetric on purpose, for two DIFFERENT reasons:
 *
 * [E]: `verifyPlatformAttestation` (`verify.ts`) builds its signature
 * preimage with `canonicalJson(body)` over the PARSED JSON object, not a
 * typed reconstruction (contrast `signableActionEvent` in check A, which
 * DOES rebuild a typed object — that's exactly what made A blind to
 * SEC-PA01-DISCOVERED-01). A field `be` adds that this verifier's interface
 * doesn't know about still flows into the signed bytes correctly and the
 * signature still verifies — MIL-0003's `platformKeyVersion` is exactly
 * this case. So:
 *   - a `be`-only field (present in the attestation literal, absent from
 *     `PlatformAttestationBody` in EITHER its required or optional set) is
 *     a WARNING (interface is stale, but no bundle fails to verify because
 *     of it) — never a hard failure.
 *   - a `PlatformAttestationBody` field declared REQUIRED (no `?`) that
 *     `be` no longer emits IS a hard failure — `verifyPlatformAttestation`'s
 *     own structural `malformed` check (`verify.ts` ~:3989-3997) rejects
 *     every bundle missing it, so this is a real, signature-relevant break,
 *     not merely a stale-interface annoyance. A rename shows up as exactly
 *     this: the old required field disappears (hard failure) and a new
 *     field appears on the `be` side (warning).
 *   - a `PlatformAttestationBody` field declared OPTIONAL (`?`) that `be`
 *     doesn't emit is unremarkable (forward-declared or legitimately
 *     dropped) — no message.
 *
 * [G]: `BundleRow` is the CONSUMING declaration `signableRow()`'s
 * `'x' in row` guards are written against (unlike [E], the risk direction
 * is reversed: `serializeRow` is the typed PRODUCER, `BundleRow` the typed
 * CONSUMER, so an undeclared-on-BundleRow field `be` emits is real drift,
 * not signature-safe-by-construction the way [E]'s wholesale
 * canonicalization is — hard failure, both directions, EXCEPT one
 * deliberately safe case): `ipAddress` and `detailsCommitment` are each
 * declared OPTIONAL on `BundleRow` specifically so `signableRow()`'s guard
 * can tolerate a producer that has not started emitting them yet — the
 * verifier upgraded AHEAD of the producer on purpose (SCAN-AV-01, awaiting
 * SCAN-BE-17). So for [G] only:
 *   - a `BundleRow` field declared REQUIRED (no `?`) that `be`'s
 *     `serializeRow` never emits (unconditionally or guarded) IS a hard
 *     failure.
 *   - a `BundleRow` field declared OPTIONAL (`?`) that `be` doesn't emit at
 *     all yet is unremarkable (the intentional, coordinated-rollout state)
 *     — no message.
 *   - a field `be` emits (unconditionally or guarded) that `BundleRow`
 *     does not declare in EITHER category is a hard failure — unlike [E],
 *     there is no wholesale-canonicalization safety net here.
 *
 * Usage
 * -----
 *   node scripts/contract-drift.mjs <path-to-be-core-checkout>
 *
 * Exits non-zero, listing every offending field, when A-D disagree or when
 * [E] finds a hard failure. Warnings (safe [E] drift) print but do not
 * affect the exit code.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

/**
 * Depth-1 `key:` / `key?:` / `key =` extraction inside a balanced `{...}`
 * block, starting at `openBraceIndex` (which must point at the opening
 * `{`). Mirrors `gateway/scripts/contract-drift.py`'s `dto_properties`:
 * only captures identifiers at brace-depth 1 relative to the block's own
 * opening brace, so nested object types / nested object literals (e.g.
 * `BundleManifest.evidenceGradeSummary`'s inline `{A,B,C,D,enforcementMode}`
 * type, or the manifest builder's `keyVersions: Object.keys(...).map((v) =>
 * ({...}))`) do not leak their inner field names into the outer set.
 */
function extractDepth1Keys(source, openBraceIndex, { assignment = false, allowShorthand = true } = {}) {
  const keys = new Set();
  const propertyPattern = assignment
    ? /^([A-Za-z_]\w*)\s*=(?!=)/
    : /^([A-Za-z_]\w*)\s*[?!]?\s*:/;
  // ES6 shorthand object-literal properties (`orgId,` instead of
  // `orgId: orgId,`) carry no colon at all — only relevant for object
  // literals (be's producer code uses this liberally), never for TS
  // `interface` bodies, which always declare `name: Type`.
  const shorthandPattern = /^([A-Za-z_]\w*)\s*,/;
  let depth = 0;
  let index = openBraceIndex;
  let atLineStart = true;
  for (; index < source.length; index++) {
    const ch = source[index];
    if (ch === '{') {
      depth++;
      atLineStart = false;
      continue;
    }
    if (ch === '}') {
      depth--;
      if (depth === 0) break;
      atLineStart = false;
      continue;
    }
    if (depth === 1 && atLineStart) {
      const rest = source.slice(index);
      const match = propertyPattern.exec(rest);
      if (match) {
        keys.add(match[1]);
      } else if (allowShorthand) {
        const shorthandMatch = shorthandPattern.exec(rest);
        if (shorthandMatch) keys.add(shorthandMatch[1]);
      }
    }
    atLineStart = ch === '\n' || ch === ';' || (atLineStart && (ch === ' ' || ch === '\t'));
  }
  return keys;
}

/**
 * Same depth-1 walk as {@link extractDepth1Keys}, but returns
 * `Map<name, { optional: boolean }>` instead of a bare key set — needed by
 * check [E], which must distinguish a `PlatformAttestationBody` field
 * declared `name?: Type` (forward-compat-safe if `be` doesn't emit it) from
 * one declared `name: Type` (its absence breaks `verifyPlatformAttestation`'s
 * structural `malformed` check). Only used for TS `interface` bodies, which
 * never use ES6 object-literal shorthand, so there is no shorthand branch
 * here (unlike {@link extractDepth1Keys}).
 */
function extractDepth1PropertiesWithOptionality(source, openBraceIndex) {
  const props = new Map();
  const propertyPattern = /^([A-Za-z_]\w*)\s*(\?)?\s*:/;
  let depth = 0;
  let index = openBraceIndex;
  let atLineStart = true;
  for (; index < source.length; index++) {
    const ch = source[index];
    if (ch === '{') {
      depth++;
      atLineStart = false;
      continue;
    }
    if (ch === '}') {
      depth--;
      if (depth === 0) break;
      atLineStart = false;
      continue;
    }
    if (depth === 1 && atLineStart) {
      const match = propertyPattern.exec(source.slice(index));
      if (match) props.set(match[1], { optional: match[2] === '?' });
    }
    atLineStart = ch === '\n' || ch === ';' || (atLineStart && (ch === ' ' || ch === '\t'));
  }
  return props;
}

/** Finds `anchorRegex`, then the first `{` at/after the match end, and
 * returns the depth-1 keys of that balanced block — or, with
 * `{ entries: true }`, the `Map<name, {optional}>` form (see
 * {@link extractDepth1PropertiesWithOptionality}, used by check [E]). */
function keysAfterAnchor(source, anchorRegex, opts) {
  const match = anchorRegex.exec(source);
  if (!match) return null;
  const openBrace = source.indexOf('{', match.index + match[0].length - 1);
  if (openBrace === -1) return null;
  if (opts?.entries) {
    return extractDepth1PropertiesWithOptionality(source, openBrace);
  }
  return extractDepth1Keys(source, openBrace, opts);
}

/** Balanced-brace substring of the function whose declaration matches
 * `signatureRegex`, from its opening `{` to the matching `}` (inclusive). */
function extractFunctionBody(source, signatureRegex) {
  const match = signatureRegex.exec(source);
  if (!match) return null;
  const openBrace = source.indexOf('{', match.index);
  if (openBrace === -1) return null;
  let depth = 0;
  for (let index = openBrace; index < source.length; index++) {
    if (source[index] === '{') depth++;
    else if (source[index] === '}') {
      depth--;
      if (depth === 0) return source.slice(openBrace, index + 1);
    }
  }
  return null;
}

/** `identifier.field = ` assignments anywhere in `body`, e.g. the
 * version-gated `signable.actionEventCount = manifest.actionEventCount;`
 * lines in `manifestSignableBytes`. */
function extractDottedAssignments(body, identifier) {
  const keys = new Set();
  const re = new RegExp(`\\b${identifier}\\.([A-Za-z_]\\w*)\\s*=(?!=)`, 'g');
  let m;
  while ((m = re.exec(body))) keys.add(m[1]);
  return keys;
}

function diffSets(labelA, setA, labelB, setB) {
  const failures = [];
  for (const key of [...setA].sort()) {
    if (!setB.has(key)) {
      failures.push(`${key}: present in ${labelA}, absent from ${labelB}`);
    }
  }
  for (const key of [...setB].sort()) {
    if (!setA.has(key)) {
      failures.push(`${key}: present in ${labelB}, absent from ${labelA}`);
    }
  }
  return failures;
}

function main() {
  const beRootArg = process.argv[2];
  if (!beRootArg) {
    console.error('usage: node scripts/contract-drift.mjs <path-to-be-core-checkout>');
    return 2;
  }
  const beRoot = path.resolve(beRootArg);

  const bundleExporterPath = path.join(
    beRoot,
    'src/audit/services/bundle-exporter.service.ts',
  );
  const canonicalHelperPath = path.join(
    beRoot,
    'src/protected-actions/utils/protected-action-canonical.helper.ts',
  );
  const platformAttestationServicePath = path.join(
    beRoot,
    'src/common/security/services/platform-attestation.service.ts',
  );
  // SCAN-AV-03 — the row-level signed contract (`SignableAuditRow`,
  // `buildSignableRow`), distinct from `protected-action-canonical.helper.ts`'s
  // action-event contract already covered by check A.
  const auditCanonicalHelperPath = path.join(
    beRoot,
    'src/audit/audit-canonical.helper.ts',
  );
  const verifyTsPath = path.join(__dirname, '../src/verify.ts');

  let bundleExporterSrc,
    canonicalHelperSrc,
    platformAttestationSrc,
    auditCanonicalHelperSrc,
    verifyTsSrc;
  try {
    bundleExporterSrc = stripComments(readFileSync(bundleExporterPath, 'utf8'));
    canonicalHelperSrc = stripComments(readFileSync(canonicalHelperPath, 'utf8'));
    platformAttestationSrc = stripComments(readFileSync(platformAttestationServicePath, 'utf8'));
    auditCanonicalHelperSrc = stripComments(
      readFileSync(auditCanonicalHelperPath, 'utf8'),
    );
    verifyTsSrc = stripComments(readFileSync(verifyTsPath, 'utf8'));
  } catch (error) {
    console.error(`::error::could not read a required source file: ${error.message}`);
    return 2;
  }

  const failures = [];
  const warnings = [];

  // ── A. Action-event SIGNED PREIMAGE (signature-critical) ──────────────
  const signableRowFields = keysAfterAnchor(
    canonicalHelperSrc,
    /\binterface SignableProtectedActionEventRow\b[^{]*{/,
  );
  const signableActionEventFn = extractFunctionBody(
    verifyTsSrc,
    /function signableActionEvent\([^)]*\)[^{]*{/,
  );
  if (!signableRowFields) {
    failures.push(
      '[A] SignableProtectedActionEventRow interface not found in protected-action-canonical.helper.ts (renamed or moved?)',
    );
  } else if (!signableActionEventFn) {
    failures.push('[A] signableActionEvent() not found in verify.ts (renamed or moved?)');
  } else {
    const returnBrace = signableActionEventFn.indexOf('{', signableActionEventFn.indexOf('return'));
    const verifierFields = extractDepth1Keys(signableActionEventFn, returnBrace);
    for (const failure of diffSets(
      "be's SignableProtectedActionEventRow (the SIGNED fields)",
      signableRowFields,
      "verify.ts's signableActionEvent() reconstruction",
      verifierFields,
    )) {
      failures.push(`[A] ${failure}`);
    }
  }

  // ── B. Manifest SIGNED PREIMAGE (signature-critical) ───────────────────
  const manifestSansSignatureFields = keysAfterAnchor(
    bundleExporterSrc,
    /const manifestSansSignature\s*=\s*{/,
  );
  // SEC-2026-09-12 (MCPSDK-01) — the reconstruction moved OUT of
  // `verifyManifest` into `manifestSignableBytes()` so the platform
  // attestation's `manifestDigest` is computed over the identical preimage.
  // This check follows it; the contract it guards is unchanged.
  const manifestSignableFn = extractFunctionBody(
    verifyTsSrc,
    /function manifestSignableBytes\([^)]*\)[^{]*{/,
  );
  if (!manifestSansSignatureFields) {
    failures.push(
      '[B] manifestSansSignature literal not found in bundle-exporter.service.ts (renamed or moved?)',
    );
  } else if (!manifestSignableFn) {
    failures.push('[B] manifestSignableBytes() not found in verify.ts (renamed or moved?)');
  } else {
    const signableDeclMatch = /const signable:\s*Record<string,\s*unknown>\s*=\s*{/.exec(
      manifestSignableFn,
    );
    if (!signableDeclMatch) {
      failures.push("[B] manifestSignableBytes()'s `signable` reconstruction object not found");
    } else {
      const openBrace = manifestSignableFn.indexOf('{', signableDeclMatch.index + signableDeclMatch[0].length - 1);
      const baseSignableFields = extractDepth1Keys(manifestSignableFn, openBrace);
      const gatedSignableFields = extractDottedAssignments(manifestSignableFn, 'signable');
      const verifierSignableFields = new Set([...baseSignableFields, ...gatedSignableFields]);
      // be always builds the LATEST manifest version unconditionally (see
      // bundle-exporter.service.ts's own comment: "the manifest is always
      // version 5 going forward — there is no code path left that emits a
      // v3/v4 manifest"), so its signed preimage is
      // `manifestSansSignature` fields plus `signatureAlgorithm` (added at
      // sign time, canonicalJson({...manifestSansSignature,
      // signatureAlgorithm})) — the newest-version union the verifier's
      // version-gated `signable` object also converges to.
      const beSignableFields = new Set([...manifestSansSignatureFields, 'signatureAlgorithm']);
      for (const failure of diffSets(
        "be's manifest signed preimage (manifestSansSignature + signatureAlgorithm)",
        beSignableFields,
        "verify.ts's manifestSignableBytes() `signable` reconstruction (newest version)",
        verifierSignableFields,
      )) {
        failures.push(`[B] ${failure}`);
      }
    }
  }

  // ── C. Action-event WIRE shape ──────────────────────────────────────────
  const serializeActionEventFn = extractFunctionBody(
    bundleExporterSrc,
    /private serializeActionEvent\([^)]*\)\s*:\s*Record<string,\s*unknown>\s*{/,
  );
  const bundleActionEventFields = keysAfterAnchor(
    verifyTsSrc,
    /\binterface BundleActionEvent\b[^{]*{/,
  );
  if (!serializeActionEventFn) {
    failures.push('[C] serializeActionEvent() not found in bundle-exporter.service.ts (renamed or moved?)');
  } else if (!bundleActionEventFields) {
    failures.push('[C] BundleActionEvent interface not found in verify.ts (renamed or moved?)');
  } else {
    const returnBrace = serializeActionEventFn.indexOf(
      '{',
      serializeActionEventFn.indexOf('return'),
    );
    const producerFields = extractDepth1Keys(serializeActionEventFn, returnBrace);
    for (const failure of diffSets(
      "be's serializeActionEvent() wire output",
      producerFields,
      'BundleActionEvent (verify.ts)',
      bundleActionEventFields,
    )) {
      failures.push(`[C] ${failure}`);
    }
  }

  // ── D. Manifest WIRE shape ──────────────────────────────────────────────
  const bundleManifestFields = keysAfterAnchor(verifyTsSrc, /\binterface BundleManifest\b[^{]*{/);
  if (!manifestSansSignatureFields) {
    // Already reported in check B.
  } else if (!bundleManifestFields) {
    failures.push('[D] BundleManifest interface not found in verify.ts (renamed or moved?)');
  } else {
    const manifestLiteralMatch = /const manifest\s*=\s*{/.exec(bundleExporterSrc);
    let manifestExtraFields = new Set();
    if (manifestLiteralMatch) {
      const openBrace = bundleExporterSrc.indexOf(
        '{',
        manifestLiteralMatch.index + manifestLiteralMatch[0].length - 1,
      );
      manifestExtraFields = extractDepth1Keys(bundleExporterSrc, openBrace);
    }
    const producerManifestFields = new Set([
      ...manifestSansSignatureFields,
      ...manifestExtraFields,
    ]);
    for (const failure of diffSets(
      "be's manifest builder (manifestSansSignature + manifest wire literal)",
      producerManifestFields,
      'BundleManifest (verify.ts)',
      bundleManifestFields,
    )) {
      failures.push(`[D] ${failure}`);
    }
  }

  // ── E. Platform-attestation envelope (forward-compat-aware, MIL-0003) ──
  const attestationFields = keysAfterAnchor(platformAttestationSrc, /\bconst attestation\s*=\s*{/);
  const attestationBodyEntries = keysAfterAnchor(
    verifyTsSrc,
    /\binterface PlatformAttestationBody\b[^{]*{/,
    { entries: true },
  );
  if (!attestationFields) {
    failures.push(
      "[E] attestBundle()'s `attestation` literal not found in platform-attestation.service.ts (renamed or moved?)",
    );
  } else if (!attestationBodyEntries) {
    failures.push('[E] PlatformAttestationBody interface not found in verify.ts (renamed or moved?)');
  } else {
    const requiredVerifierFields = new Set(
      [...attestationBodyEntries].filter(([, v]) => !v.optional).map(([k]) => k),
    );
    const allVerifierFields = new Set(attestationBodyEntries.keys());
    // be-only field: signature-safe by construction (canonicalJson(body) is
    // over the PARSED object, so an unknown-to-the-interface field still
    // enters the signed bytes correctly) — warn, don't fail.
    for (const field of [...attestationFields].sort()) {
      if (!allVerifierFields.has(field)) {
        warnings.push(
          `[E] ${field}: present in be's attestBundle() attestation literal, absent from ` +
            'PlatformAttestationBody (verify.ts) — signature-safe (canonicalized as parsed, ' +
            'not typed-reconstructed) but the interface should be updated to reflect it',
        );
      }
    }
    // verifier-required field be no longer emits: hard failure —
    // `verifyPlatformAttestation`'s own structural `malformed` check
    // rejects every bundle missing it (verify.ts ~:3989-3997).
    for (const field of [...requiredVerifierFields].sort()) {
      if (!attestationFields.has(field)) {
        failures.push(
          `[E] ${field}: PlatformAttestationBody (verify.ts) declares this REQUIRED but be's ` +
            "attestBundle() no longer emits it — verifyPlatformAttestation's structural check " +
            'will reject every bundle as malformed',
        );
      }
    }
    // A verifier-OPTIONAL field be doesn't emit is unremarkable — no message.
  }

  // ── F. Audit-row SIGNED PREIMAGE (signature-critical) ──────────────────
  // SCAN-AV-03 — the exact seam SCAN-AV-01 found silently drifted
  // (`detailsCommitment` missing entirely from `signableRow()`). Plain
  // symmetric diff, same philosophy as [A]/[B]: `signableRow()` is a TYPED
  // rebuild, not a wholesale canonicalize like [E], so an unhandled field
  // on EITHER side is unsafe by omission — a be field marked optional
  // (cutover-gated) can start appearing in real signed bytes the moment an
  // operator flips the switch, and the verifier must already have a code
  // path for it (unconditional or `in`-guarded) or every such row fails
  // verification from that moment on.
  const signableAuditRowFields = keysAfterAnchor(
    auditCanonicalHelperSrc,
    /\binterface SignableAuditRow\b[^{]*{/,
  );
  const signableRowFn = extractFunctionBody(
    verifyTsSrc,
    /function signableRow\([^)]*\)[^{]*{/,
  );
  if (!signableAuditRowFields) {
    failures.push(
      '[F] SignableAuditRow interface not found in audit-canonical.helper.ts (renamed or moved?)',
    );
  } else if (!signableRowFn) {
    failures.push('[F] signableRow() not found in verify.ts (renamed or moved?)');
  } else {
    const signableDeclMatch = /const signable:\s*Record<string,\s*unknown>\s*=\s*{/.exec(
      signableRowFn,
    );
    if (!signableDeclMatch) {
      failures.push("[F] signableRow()'s `signable` reconstruction object not found");
    } else {
      const openBrace = signableRowFn.indexOf(
        '{',
        signableDeclMatch.index + signableDeclMatch[0].length - 1,
      );
      const baseSignableRowFields = extractDepth1Keys(signableRowFn, openBrace);
      const gatedSignableRowFields = extractDottedAssignments(signableRowFn, 'signable');
      const verifierRowFields = new Set([
        ...baseSignableRowFields,
        ...gatedSignableRowFields,
      ]);
      for (const failure of diffSets(
        "be's SignableAuditRow (the SIGNED audit-row fields)",
        signableAuditRowFields,
        "verify.ts's signableRow() reconstruction",
        verifierRowFields,
      )) {
        failures.push(`[F] ${failure}`);
      }
    }
  }

  // ── G. Audit-row WIRE shape (optionality-aware, mirrors [E]) ───────────
  // SCAN-AV-03 — unlike [F], `BundleRow` is the CONSUMING declaration
  // `signableRow()`'s `'x' in row` guards are written against, so a
  // `BundleRow`-OPTIONAL field be doesn't emit YET is the intentional,
  // coordinated-rollout state `ipAddress`/`detailsCommitment` are in right
  // now (verifier upgraded ahead of the producer — SCAN-AV-01, awaiting
  // SCAN-BE-17) — safe, not a failure. Everything else is a hard failure:
  // there is no [E]-style wholesale-canonicalization safety net for an
  // undeclared wire field here.
  const serializeRowFn = extractFunctionBody(
    bundleExporterSrc,
    /private serializeRow\([^)]*\)\s*:\s*Record<string,\s*unknown>\s*{/,
  );
  const bundleRowEntries = keysAfterAnchor(
    verifyTsSrc,
    /\binterface BundleRow\b[^{]*{/,
    { entries: true },
  );
  if (!serializeRowFn) {
    failures.push(
      '[G] serializeRow() not found in bundle-exporter.service.ts (renamed or moved?)',
    );
  } else if (!bundleRowEntries) {
    failures.push('[G] BundleRow interface not found in verify.ts (renamed or moved?)');
  } else {
    const wireDeclMatch = /const wire:\s*Record<string,\s*unknown>\s*=\s*{/.exec(
      serializeRowFn,
    );
    if (!wireDeclMatch) {
      failures.push("[G] serializeRow()'s `wire` object literal not found");
    } else {
      const openBrace = serializeRowFn.indexOf(
        '{',
        wireDeclMatch.index + wireDeclMatch[0].length - 1,
      );
      const baseWireFields = extractDepth1Keys(serializeRowFn, openBrace);
      const gatedWireFields = extractDottedAssignments(serializeRowFn, 'wire');
      const producerRowFields = new Set([...baseWireFields, ...gatedWireFields]);
      const requiredBundleRowFields = new Set(
        [...bundleRowEntries].filter(([, v]) => !v.optional).map(([k]) => k),
      );
      const allBundleRowFields = new Set(bundleRowEntries.keys());

      // be emits a field BundleRow doesn't declare in EITHER category —
      // undeclared wire drift, hard fail (no [E]-style safety net here).
      for (const field of [...producerRowFields].sort()) {
        if (!allBundleRowFields.has(field)) {
          failures.push(
            `[G] ${field}: present in be's serializeRow() wire output, absent from BundleRow (verify.ts)`,
          );
        }
      }
      // BundleRow requires a field be never emits (unconditionally or
      // guarded): hard failure.
      for (const field of [...requiredBundleRowFields].sort()) {
        if (!producerRowFields.has(field)) {
          failures.push(
            `[G] ${field}: BundleRow (verify.ts) declares this REQUIRED, but be's serializeRow() ` +
              'does not emit it under any condition',
          );
        }
      }
      // A BundleRow-OPTIONAL field be doesn't emit yet is unremarkable —
      // the intentional coordinated-rollout state — no message.
    }
  }

  if (failures.length > 0) {
    console.error('audit-verifier <-> be bundle-schema contract drift detected:\n');
    for (const failure of failures) {
      console.error(`::error::${failure}`);
    }
    for (const warning of warnings) {
      console.error(`::warning::${warning}`);
    }
    console.error(
      '\nUpdate `be`\'s serializer/manifest builder or this package\'s `BundleActionEvent` / ' +
        '`BundleManifest` / `signableActionEvent` / `verifyManifest` / `PlatformAttestationBody` / ' +
        '`BundleRow` / `signableRow` to match, then re-run. A field entering the SIGNED preimage ' +
        'on one side only ([A]/[B]/[F]) means signatures are unverifiable offline for the affected ' +
        'rows — see SEC-PA01-DISCOVERED-01 (action-events) and SCAN-AV-01 (audit rows). A [E]/[G] ' +
        'hard failure means a bundle every genuine producer emits will be rejected or mis-signed.',
    );
    return 1;
  }

  console.log('ok  [A] action-event signed-preimage fields match (SignableProtectedActionEventRow <-> signableActionEvent)');
  console.log('ok  [B] manifest signed-preimage fields match (manifestSansSignature+signatureAlgorithm <-> manifestSignableBytes signable)');
  console.log('ok  [C] action-event wire fields match (serializeActionEvent <-> BundleActionEvent)');
  console.log('ok  [D] manifest wire fields match (manifest builder <-> BundleManifest)');
  console.log('ok  [E] platform-attestation required fields match (no hard drift); additive fields, if any, warned below');
  console.log('ok  [F] audit-row signed-preimage fields match (SignableAuditRow <-> signableRow)');
  console.log('ok  [G] audit-row wire fields match (serializeRow <-> BundleRow); optional not-yet-emitted fields are not drift');
  for (const warning of warnings) {
    console.warn(`::warning::${warning}`);
  }
  console.log('\nno drift across the audit-verifier <-> be bundle-schema contract');
  return 0;
}

process.exit(main());
