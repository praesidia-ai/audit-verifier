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
 * Four checks, in priority order (signature-critical first — see the
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
 *      reconstruction in `verifyManifest` at the newest manifest version
 *      (`verify.ts`).
 *   C. Action-event WIRE shape — be's `serializeActionEvent` emitted fields
 *      vs `BundleActionEvent`'s declared fields (`verify.ts:212-235`).
 *   D. Manifest WIRE shape — be's manifest builder (`manifestSansSignature`
 *      plus the `signature`/`signatureKeyVersion` fields added on top) vs
 *      `BundleManifest`'s declared fields (`verify.ts:98-183`).
 *
 * Every check fails on a field present on only one side, in EITHER
 * direction — a be-only field is unrecognized by every offline consumer; a
 * verifier-only required field is one no producer will ever populate.
 *
 * Usage
 * -----
 *   node scripts/contract-drift.mjs <path-to-be-core-checkout>
 *
 * Exits non-zero, listing every offending field, on any of the four checks
 * disagreeing.
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

/** Finds `anchorRegex`, then the first `{` at/after the match end, and
 * returns the depth-1 keys of that balanced block. */
function keysAfterAnchor(source, anchorRegex, opts) {
  const match = anchorRegex.exec(source);
  if (!match) return null;
  const openBrace = source.indexOf('{', match.index + match[0].length - 1);
  if (openBrace === -1) return null;
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
 * lines in `verifyManifest`. */
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
  const verifyTsPath = path.join(__dirname, '../src/verify.ts');

  let bundleExporterSrc, canonicalHelperSrc, verifyTsSrc;
  try {
    bundleExporterSrc = stripComments(readFileSync(bundleExporterPath, 'utf8'));
    canonicalHelperSrc = stripComments(readFileSync(canonicalHelperPath, 'utf8'));
    verifyTsSrc = stripComments(readFileSync(verifyTsPath, 'utf8'));
  } catch (error) {
    console.error(`::error::could not read a required source file: ${error.message}`);
    return 2;
  }

  const failures = [];

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
  const verifyManifestFn = extractFunctionBody(
    verifyTsSrc,
    /function verifyManifest\([^)]*\)[^{]*{/,
  );
  if (!manifestSansSignatureFields) {
    failures.push(
      '[B] manifestSansSignature literal not found in bundle-exporter.service.ts (renamed or moved?)',
    );
  } else if (!verifyManifestFn) {
    failures.push('[B] verifyManifest() not found in verify.ts (renamed or moved?)');
  } else {
    const signableDeclMatch = /const signable:\s*Record<string,\s*unknown>\s*=\s*{/.exec(
      verifyManifestFn,
    );
    if (!signableDeclMatch) {
      failures.push("[B] verifyManifest()'s `signable` reconstruction object not found");
    } else {
      const openBrace = verifyManifestFn.indexOf('{', signableDeclMatch.index + signableDeclMatch[0].length - 1);
      const baseSignableFields = extractDepth1Keys(verifyManifestFn, openBrace);
      const gatedSignableFields = extractDottedAssignments(verifyManifestFn, 'signable');
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
        "verify.ts's verifyManifest() `signable` reconstruction (newest version)",
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

  if (failures.length > 0) {
    console.error('audit-verifier <-> be bundle-schema contract drift detected:\n');
    for (const failure of failures) {
      console.error(`::error::${failure}`);
    }
    console.error(
      '\nUpdate `be`\'s serializer/manifest builder or this package\'s `BundleActionEvent` / ' +
        '`BundleManifest` / `signableActionEvent` / `verifyManifest` to match, then re-run. ' +
        'A field entering the SIGNED preimage on one side only ([A]/[B]) means signatures are ' +
        'unverifiable offline for the affected rows — see SEC-PA01-DISCOVERED-01.',
    );
    return 1;
  }

  console.log('ok  [A] action-event signed-preimage fields match (SignableProtectedActionEventRow <-> signableActionEvent)');
  console.log('ok  [B] manifest signed-preimage fields match (manifestSansSignature+signatureAlgorithm <-> verifyManifest signable)');
  console.log('ok  [C] action-event wire fields match (serializeActionEvent <-> BundleActionEvent)');
  console.log('ok  [D] manifest wire fields match (manifest builder <-> BundleManifest)');
  console.log('\nno drift across the audit-verifier <-> be bundle-schema contract');
  return 0;
}

process.exit(main());
