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
 * Dependency-free regex/bracket-depth scraping of TS source — no TS parser
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
 * Producer fields emitted only under a condition count as emitted (AV-2793):
 * every object-literal branch of a depth-1 spread (be's
 * `...(x.signatureFormat === 2 ? { signatureFormat: 2 as const } : {})`), and,
 * for B/D, every literal branch of the `manifestUnsigned` assignment be signs
 * (the format-2 v7 manifest; AV-2794). A conditional field is checked like any
 * other one. A spread of anything else (`...helper(x)`, `...base`) hides the
 * fields it adds from this scraper, so it is reported as a warning (AV-2794).
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
 * [H] AIBOM attestation envelope (AV-0003; hard failure, both directions):
 * `be/src/aibom/aibom-attestation.ts` vs `src/aibom.ts` — the
 * `attestationFormat` literal and `AIBOM_SIGNING_DOMAIN` must be equal; every
 * `AibomAttestationEnvelope` key must be read by `verifyAibomAttestation` or
 * listed in `AIBOM_UNAUTHENTICATED_FIELDS`, and the verifier may know no key
 * be does not declare; the `signingAlgorithm` union must equal
 * `AIBOM_SIGNING_ALGORITHMS`.
 *
 * Usage
 * -----
 *   node scripts/contract-drift.mjs <path-to-be-core-checkout>
 *
 * Exits non-zero, listing every offending field, when A-D, F, G or H
 * disagree or when [E] finds a hard failure. Warnings (safe [E] drift, and spreads this
 * scraper cannot see into) print but do not affect the exit code.
 */

import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

/**
 * AV-2794 — the one balanced-bracket walk in this script: the index of the
 * bracket closing the `(`/`[`/`{` at `openIndex`, or -1. It counts all three
 * kinds, so a `,` or a line start inside a nested call or array is never taken
 * for one of the enclosing block's. Like the rest of this scraper it does not
 * know about string literals: a bracket inside one miscounts.
 */
function closingIndex(text, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < text.length; index++) {
    if ('([{'.includes(text[index])) depth++;
    else if (')]}'.includes(text[index]) && --depth === 0) return index;
  }
  return -1;
}

/**
 * Calls `visit(index)` for each character from `start` that is outside every
 * bracket opened at or after `start` (a nested block is skipped whole with
 * {@link closingIndex}; only its opener is visited). Returns the index where
 * `visit` returned true, else of the first unmatched closer (the end of the
 * enclosing block), else `text.length`.
 */
function scanTopLevel(text, start, visit) {
  for (let index = start; index < text.length; index++) {
    if (')]}'.includes(text[index]) || visit(index)) return index;
    if ('([{'.includes(text[index])) {
      index = closingIndex(text, index);
      if (index === -1) break;
    }
  }
  return text.length;
}

/** Index of the first character of each line (or `;`-separated member)
 * directly inside the block opened at `openIndex`. */
function depth1LineStarts(source, openIndex) {
  const starts = [];
  let atLineStart = false;
  scanTopLevel(source, openIndex + 1, (index) => {
    const ch = source[index];
    if (atLineStart && !' \t\n;'.includes(ch)) starts.push(index);
    atLineStart = ch === '\n' || ch === ';' || (atLineStart && (ch === ' ' || ch === '\t'));
    return false;
  });
  return starts;
}

/**
 * Depth-1 `key:` / `key?:` / `key =` extraction inside a balanced `{...}`
 * block, starting at `openBraceIndex` (which must point at the opening
 * `{`). Mirrors `gateway/scripts/contract-drift.py`'s `dto_properties`:
 * only captures identifiers at depth 1 relative to the block's own
 * opening brace, so nested object types / nested object literals (e.g.
 * `BundleManifest.evidenceGradeSummary`'s inline `{A,B,C,D,enforcementMode}`
 * type, or the manifest builder's `keyVersions: Object.keys(...).map((v) =>
 * ({...}))`) do not leak their inner field names into the outer set.
 * A depth-1 `...operand` spread adds what {@link spreadKeys} finds; a spread
 * this scraper cannot see into goes to `onOpaqueSpread` (AV-2794).
 */
export function extractDepth1Keys(
  source,
  openBraceIndex,
  { assignment = false, allowShorthand = true, onOpaqueSpread } = {},
) {
  const keys = new Set();
  const propertyPattern = assignment
    ? /^([A-Za-z_]\w*)\s*=(?!=)/
    : /^([A-Za-z_]\w*)\s*[?!]?\s*:/;
  // ES6 shorthand object-literal properties (`orgId,` instead of
  // `orgId: orgId,`) carry no colon at all — only relevant for object
  // literals (be's producer code uses this liberally), never for TS
  // `interface` bodies, which always declare `name: Type`.
  const shorthandPattern = /^([A-Za-z_]\w*)\s*,/;
  for (const index of depth1LineStarts(source, openBraceIndex)) {
    const rest = source.slice(index);
    const match = propertyPattern.exec(rest);
    if (match) {
      keys.add(match[1]);
    } else if (rest.startsWith('...')) {
      const end = scanTopLevel(source, index, (i) => source[i] === ',');
      spreadKeys(source.slice(index + 3, end), keys, onOpaqueSpread);
    } else if (allowShorthand) {
      const shorthandMatch = shorthandPattern.exec(rest);
      if (shorthandMatch) keys.add(shorthandMatch[1]);
    }
  }
  return keys;
}

/**
 * AV-2793 — adds to `keys` the keys of the object literal whose `{` is at
 * `openBraceIndex`, split on its top-level commas instead of line starts (the
 * literals a conditional spread or a manifest branch carries are often written
 * inline), recursing into spreads.
 */
function literalKeys(text, openBraceIndex, keys, onOpaqueSpread) {
  const close = closingIndex(text, openBraceIndex);
  for (let start = openBraceIndex + 1; close !== -1 && start < close; ) {
    const end = scanTopLevel(text, start, (i) => text[i] === ',');
    const entry = text.slice(start, end).trim();
    const key = /^([A-Za-z_]\w*)\s*(?:[?!]?\s*:|$)/.exec(entry);
    if (key) keys.add(key[1]);
    else if (entry.startsWith('...')) spreadKeys(entry.slice(3), keys, onOpaqueSpread);
    start = end + 1;
  }
}

/**
 * AV-2793 / AV-2794 — adds to `keys` what spreading `operand` contributes.
 * Every object literal in it counts, so every branch of be's
 * `...(row.signatureFormat === 2 ? { signatureFormat: 2 as const } : {})`
 * does: a field emitted under ANY condition is one the other side must know,
 * so it is checked, never skipped. A value branch that is not a literal
 * (`...helper(x)`, `...base`, `...(cond ? helper(x) : {})`,
 * `...(manifestUnsigned as T)`) adds fields this scraper cannot see; it goes to
 * `onOpaqueSpread` instead of contributing nothing silently.
 */
function spreadKeys(operand, keys, onOpaqueSpread) {
  for (let index = operand.indexOf('{'); index !== -1; index = operand.indexOf('{', index + 1)) {
    literalKeys(operand, index, keys, onOpaqueSpread);
    index = closingIndex(operand, index);
    if (index === -1) break;
  }
  for (const branch of opaqueBranches(operand)) onOpaqueSpread?.(branch);
}

const TRAILING_CAST = /\s+(?:as|satisfies)\s+[^()[\]{}]*$/;

/**
 * AV-2794 — the value branches of `expression` that are neither an object
 * literal nor `null`/`undefined`: the expression itself or, for a
 * `c ? x : y` chain, each arm, recursively. Parentheses and a trailing
 * `as T` are looked through.
 */
function opaqueBranches(expression) {
  let text = expression.trim().replace(TRAILING_CAST, '');
  while (text.startsWith('(') && closingIndex(text, 0) === text.length - 1) {
    text = text.slice(1, -1).trim().replace(TRAILING_CAST, '');
  }
  if (/^(?:null|undefined)$/.test(text)) return [];
  if (text.startsWith('{') && closingIndex(text, 0) === text.length - 1) return [];
  const isTernaryOperator = (i) =>
    text[i] === ':' || (text[i] === '?' && !'?.'.includes(text[i + 1]) && text[i - 1] !== '?');
  const arms = [];
  let end = -1;
  do {
    const start = end + 1;
    end = scanTopLevel(text, start, isTernaryOperator);
    // A segment followed by `?` is a condition, not a value.
    if (text[end] !== '?') arms.push(text.slice(start, end));
  } while (end < text.length);
  return arms.length === 1 ? [text] : arms.flatMap(opaqueBranches);
}

/**
 * AV-2794 — be's bindings that hold the newest manifest: spreading one adds
 * only fields {@link newestManifestFields} already counts, so no check warns
 * about it.
 */
const NEWEST_MANIFEST_BINDINGS = ['manifestSansSignature', 'manifestUnsigned'];

/**
 * AV-2793 / AV-2794 — be's manifest fields at the NEWEST version, anchored on
 * the value be signs. Since BE-1957 / AV-0018 be signs
 * `{ ...manifestUnsigned, signatureAlgorithm }` after
 * `manifestUnsigned = signatureFormat === 2 ? { ...manifestSansSignature,
 * version: 7, signatureFormat, signatureFormatCutoverAt } :
 * manifestSansSignature`: format 1 keeps the v6 manifest byte-for-byte,
 * format 2 signs v7. The newest fields are `manifestSansSignature`'s plus
 * those of every literal branch of that assignment (what spreading
 * `manifestUnsigned` contributes). Before BE-1957 (be 6b380bc9^) there is no
 * `manifestUnsigned` and be signs `manifestSansSignature` itself. Other
 * literals that spread `manifestSansSignature` — the wire `manifest`, which
 * adds `signature`/`signatureKeyVersion`, and the `canonicalJson` argument —
 * add nothing here. A non-literal branch or spread other than one of
 * {@link NEWEST_MANIFEST_BINDINGS} goes to `onOpaqueSpread`. Null when
 * `manifestSansSignature` is not found.
 */
export function newestManifestFields(source, onOpaqueSpread) {
  const report = (expression) => {
    if (!NEWEST_MANIFEST_BINDINGS.includes(expression)) onOpaqueSpread?.(expression);
  };
  const fields = keysAfterAnchor(source, /const manifestSansSignature\s*=\s*{/, {
    onOpaqueSpread: report,
  });
  if (!fields) return null;
  for (const m of source.matchAll(/\bmanifestUnsigned\s*=(?![=>])/g)) {
    const start = m.index + m[0].length;
    const end = scanTopLevel(source, start, (i) => source[i] === ';');
    spreadKeys(source.slice(start, end), fields, report);
  }
  return fields;
}

/**
 * Same depth-1 walk as {@link extractDepth1Keys}, but returns
 * `Map<name, { optional: boolean }>` instead of a bare key set — needed by
 * check [E], which must distinguish a `PlatformAttestationBody` field
 * declared `name?: Type` (forward-compat-safe if `be` doesn't emit it) from
 * one declared `name: Type` (its absence breaks `verifyPlatformAttestation`'s
 * structural `malformed` check). Only used for TS `interface` bodies, which
 * never use ES6 object-literal shorthand or spreads, so neither is handled
 * here (unlike {@link extractDepth1Keys}).
 */
function extractDepth1PropertiesWithOptionality(source, openBraceIndex) {
  const props = new Map();
  const propertyPattern = /^([A-Za-z_]\w*)\s*(\?)?\s*:/;
  for (const index of depth1LineStarts(source, openBraceIndex)) {
    const match = propertyPattern.exec(source.slice(index));
    if (match) props.set(match[1], { optional: match[2] === '?' });
  }
  return props;
}

/** Finds `anchorRegex`, then the first `{` at/after the match end, and
 * returns the depth-1 keys of that balanced block (`opts` as for
 * {@link extractDepth1Keys}) — or, with `{ entries: true }`, the
 * `Map<name, {optional}>` form (see
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

/** Balanced-bracket substring of the function whose declaration matches
 * `signatureRegex`, from its opening `{` to the matching `}` (inclusive). */
function extractFunctionBody(source, signatureRegex) {
  const match = signatureRegex.exec(source);
  if (!match) return null;
  const openBrace = source.indexOf('{', match.index);
  if (openBrace === -1) return null;
  const close = closingIndex(source, openBrace);
  return close === -1 ? null : source.slice(openBrace, close + 1);
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
  // AV-0003 — the AIBOM attestation envelope, a second producer/consumer pair.
  const beAibomAttestationPath = path.join(beRoot, 'src/aibom/aibom-attestation.ts');
  const aibomTsPath = path.join(__dirname, '../src/aibom.ts');

  let bundleExporterSrc,
    canonicalHelperSrc,
    platformAttestationSrc,
    auditCanonicalHelperSrc,
    verifyTsSrc,
    beAibomSrc,
    aibomTsSrc;
  try {
    bundleExporterSrc = stripComments(readFileSync(bundleExporterPath, 'utf8'));
    canonicalHelperSrc = stripComments(readFileSync(canonicalHelperPath, 'utf8'));
    platformAttestationSrc = stripComments(readFileSync(platformAttestationServicePath, 'utf8'));
    auditCanonicalHelperSrc = stripComments(
      readFileSync(auditCanonicalHelperPath, 'utf8'),
    );
    verifyTsSrc = stripComments(readFileSync(verifyTsPath, 'utf8'));
    beAibomSrc = stripComments(readFileSync(beAibomAttestationPath, 'utf8'));
    aibomTsSrc = stripComments(readFileSync(aibomTsPath, 'utf8'));
  } catch (error) {
    console.error(`::error::could not read a required source file: ${error.message}`);
    return 2;
  }

  const failures = [];
  const warnings = [];
  // AV-2794 — a spread this scraper cannot see into hides the fields it adds:
  // warn, naming it, instead of dropping it silently. `known` lists spreads the
  // check accounts for itself. A warning, not a failure: it marks a blind spot
  // of this scraper, not drift.
  const warnOpaque = (check, where, known = []) => (expression) => {
    if (known.includes(expression)) return;
    warnings.push(
      `[${check}] ${where} spreads \`${expression}\`, whose fields this check cannot see — ` +
        'write them as an object literal or teach scripts/contract-drift.mjs that shape',
    );
  };

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
    const verifierFields = extractDepth1Keys(signableActionEventFn, returnBrace, {
      onOpaqueSpread: warnOpaque('A', "verify.ts's signableActionEvent()"),
    });
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
  const beNewestManifestFields = newestManifestFields(
    bundleExporterSrc,
    warnOpaque('B', "be's newest manifest (manifestSansSignature / manifestUnsigned)"),
  );
  // SEC-2026-09-12 (MCPSDK-01) — the reconstruction moved OUT of
  // `verifyManifest` into `manifestSignableBytes()` so the platform
  // attestation's `manifestDigest` is computed over the identical preimage.
  // This check follows it; the contract it guards is unchanged.
  const manifestSignableFn = extractFunctionBody(
    verifyTsSrc,
    /function manifestSignableBytes\([^)]*\)[^{]*{/,
  );
  if (!beNewestManifestFields) {
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
      const baseSignableFields = extractDepth1Keys(manifestSignableFn, openBrace, {
        onOpaqueSpread: warnOpaque('B', "verify.ts's manifestSignableBytes() `signable`"),
      });
      const gatedSignableFields = extractDottedAssignments(manifestSignableFn, 'signable');
      const verifierSignableFields = new Set([...baseSignableFields, ...gatedSignableFields]);
      // be's newest manifest is `manifestSansSignature` (v6) or, for a
      // format-2 org, the v7 branch of `manifestUnsigned`, `{
      // ...manifestSansSignature, version: 7, signatureFormat,
      // signatureFormatCutoverAt }` (AV-2793/AV-2794, see
      // `newestManifestFields`). It signs canonicalJson({...that,
      // signatureAlgorithm}), so the signed preimage is the newest-version
      // union plus `signatureAlgorithm` — the union the verifier's
      // version-gated `signable` object also converges to.
      const beSignableFields = new Set([...beNewestManifestFields, 'signatureAlgorithm']);
      for (const failure of diffSets(
        "be's manifest signed preimage (manifestSansSignature + manifestUnsigned's literal branches + signatureAlgorithm)",
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
    const producerFields = extractDepth1Keys(serializeActionEventFn, returnBrace, {
      onOpaqueSpread: warnOpaque('C', "be's serializeActionEvent()"),
    });
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
  if (!beNewestManifestFields) {
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
      // Spreading `manifestUnsigned` / `manifestSansSignature` adds the newest
      // manifest fields, already counted above.
      manifestExtraFields = extractDepth1Keys(bundleExporterSrc, openBrace, {
        onOpaqueSpread: warnOpaque('D', "be's `manifest` wire literal", NEWEST_MANIFEST_BINDINGS),
      });
    }
    const producerManifestFields = new Set([
      ...beNewestManifestFields,
      ...manifestExtraFields,
    ]);
    for (const failure of diffSets(
      "be's manifest builder (newest manifest fields + manifest wire literal)",
      producerManifestFields,
      'BundleManifest (verify.ts)',
      bundleManifestFields,
    )) {
      failures.push(`[D] ${failure}`);
    }
  }

  // ── E. Platform-attestation envelope (forward-compat-aware, MIL-0003) ──
  const attestationFields = keysAfterAnchor(platformAttestationSrc, /\bconst attestation\s*=\s*{/, {
    onOpaqueSpread: warnOpaque('E', "be's attestBundle() `attestation` literal"),
  });
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
      const baseSignableRowFields = extractDepth1Keys(signableRowFn, openBrace, {
        onOpaqueSpread: warnOpaque('F', "verify.ts's signableRow() `signable`"),
      });
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
      const baseWireFields = extractDepth1Keys(serializeRowFn, openBrace, {
        onOpaqueSpread: warnOpaque('G', "be's serializeRow() `wire`"),
      });
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

  // ── H. AIBOM attestation envelope (AV-0003) ────────────────────────────
  // A second consumer, `src/aibom.ts`, verifies be's `attested` AIBOM
  // export. The envelope is JSON, not a signed preimage, but a renamed or
  // re-typed field makes every genuine export fail (or a new field go
  // unchecked), so all three parts are hard failures:
  //   - `attestationFormat` literal and `AIBOM_SIGNING_DOMAIN` equal;
  //   - every `AibomAttestationEnvelope` key is read by
  //     `verifyAibomAttestation` or listed in `AIBOM_UNAUTHENTICATED_FIELDS`,
  //     and the verifier knows no key be does not declare;
  //   - the `signingAlgorithm` union equals `AIBOM_SIGNING_ALGORITHMS`.
  const literals = (text) => new Set([...(text ?? '').matchAll(/'([^']*)'/g)].map((m) => m[1]));
  const envelopeBody = extractFunctionBody(beAibomSrc, /\binterface AibomAttestationEnvelope\b[^{]*{/);
  const verifyAibomBody = extractFunctionBody(aibomTsSrc, /\bexport function verifyAibomAttestation\(/);
  if (!envelopeBody) {
    failures.push('[H] AibomAttestationEnvelope interface not found in be/src/aibom/aibom-attestation.ts (renamed or moved?)');
  } else if (!verifyAibomBody) {
    failures.push('[H] verifyAibomAttestation() not found in src/aibom.ts (renamed or moved?)');
  } else {
    const constant = (src, name) => new RegExp(`\\bexport const ${name}\\b[^=]*=\\s*('[^']*'|\\[[^\\]]*\\])`).exec(src)?.[1] ?? null;
    const pairs = [
      ['attestationFormat', /\battestationFormat\s*:\s*('[^']*')\s*;/.exec(envelopeBody)?.[1], 'AIBOM_ATTESTATION_FORMAT', constant(aibomTsSrc, 'AIBOM_ATTESTATION_FORMAT')],
      ['AIBOM_SIGNING_DOMAIN', constant(beAibomSrc, 'AIBOM_SIGNING_DOMAIN'), 'AIBOM_SIGNING_DOMAIN', constant(aibomTsSrc, 'AIBOM_SIGNING_DOMAIN')],
    ];
    for (const [beName, beValue, avName, avValue] of pairs) {
      if (!beValue || !avValue || beValue !== avValue) {
        failures.push(`[H] be ${beName} = ${beValue ?? '(not found)'} but src/aibom.ts ${avName} = ${avValue ?? '(not found)'}`);
      }
    }

    // `readonly name: T` would otherwise hide `name` from the depth-1 walk.
    const envelopeKeys = extractDepth1Keys(envelopeBody.replace(/\breadonly\s+(?=\w+\s*[?!]?\s*:)/g, ''), 0, { allowShorthand: false });
    const destructured = /const\s*{([^}]*)}\s*=\s*env\s*;/.exec(verifyAibomBody)?.[1] ?? '';
    const verifierKeys = new Set([
      ...[...verifyAibomBody.matchAll(/(?<![\w.$])env\.([A-Za-z_]\w*)/g)].map((m) => m[1]),
      ...destructured.split(',').map((part) => part.split(/[:=]/)[0].trim()).filter(Boolean),
      ...literals(constant(aibomTsSrc, 'AIBOM_UNAUTHENTICATED_FIELDS')),
    ]);
    for (const failure of diffSets(
      "be's AibomAttestationEnvelope",
      envelopeKeys,
      'src/aibom.ts (fields verifyAibomAttestation reads + AIBOM_UNAUTHENTICATED_FIELDS)',
      verifierKeys,
    )) {
      failures.push(`[H] ${failure}`);
    }

    const union = /\bsigningAlgorithm\s*:\s*([^;]+);/.exec(envelopeBody)?.[1] ?? null;
    if (!union || union.replace(/'[^']*'|\bnull\b|\|/g, '').trim() !== '') {
      failures.push(`[H] be's signingAlgorithm is not an inline string-literal union (${union ?? 'not found'}); update this check`);
    } else {
      for (const failure of diffSets(
        "be's AibomAttestationEnvelope.signingAlgorithm",
        literals(union),
        "src/aibom.ts's AIBOM_SIGNING_ALGORITHMS",
        literals(constant(aibomTsSrc, 'AIBOM_SIGNING_ALGORITHMS')),
      )) {
        failures.push(`[H] ${failure}`);
      }
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
        'hard failure means a bundle every genuine producer emits will be rejected or mis-signed. ' +
        'A [H] failure means the AIBOM envelope (be `AibomAttestationEnvelope` / ' +
        '`AIBOM_SIGNING_DOMAIN` vs `src/aibom.ts`) drifted: update both, then refresh ' +
        '`test-fixtures/aibom/` with `scripts/make-aibom-fixtures.cts`.',
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
  console.log('ok  [H] AIBOM envelope matches (format, domain, AibomAttestationEnvelope keys, signingAlgorithm <-> src/aibom.ts)');
  for (const warning of warnings) {
    console.warn(`::warning::${warning}`);
  }
  console.log('\nno drift across the audit-verifier <-> be bundle-schema contract');
  return 0;
}

// Run as a CLI only when invoked directly; the spec imports the helpers.
// realpath both sides so a symlinked checkout cannot skip the gate silently,
// even when node keeps the symlink path (`--preserve-symlinks-main`). An
// argv[1] that is not a file (`node -e '…' arg`) is not this script.
function invokedDirectly() {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}
if (process.argv[1] && invokedDirectly()) {
  process.exit(main());
}
