import { createHash } from 'crypto';

/**
 * PA01 D2 (corrigendum C2, SEC-PA01-03) — RFC 8785 JSON Canonicalization
 * Scheme, a NEW module separately named from
 * `be/src/common/security/utils/canonical-json.ts`, which is FROZEN and
 * has 15 unrelated consumers. This module is used ONLY for the
 * ActionEnvelope / Permit request commitment (PA-0003/0005/0006).
 *
 * Why a hand-rolled implementation rather than an off-the-shelf
 * `canonicalize` package (SEC-PA01-11): several such packages read object
 * properties via `obj[k]`, which resolves `"__proto__"` through the
 * prototype chain instead of as an own data property — this repo has
 * already been bitten by exactly that trap once (TICKET-213, mirrored
 * here). A hand-rolled implementation lets us pin the exact behavior with
 * golden fixtures rather than trusting a dependency's edge-case handling.
 *
 * Deliberate design: THROW, never silently coerce. Unlike
 * `canonical-json.ts` (which treats `undefined` as omission/null so
 * server-controlled audit-row shapes never fail to sign),
 * this module is on an attacker-reachable path — commitment inputs are
 * `JSON.parse` output (MCP tool arguments) or explicitly-constructed
 * envelope objects, and per SEC-PA01-11 `undefined`/functions/symbols/
 * non-finite numbers/`Date`/`Buffer`/`BigInt` should never legitimately
 * appear there. Silently coercing an unexpected shape into "valid" bytes
 * on a security commitment is the wrong failure mode; a loud, named error
 * is. The absent-vs-null distinction PA-0003's DoD asks for falls out for
 * free: an object simply not carrying a key is not the same walk as
 * carrying it with an explicit `null`.
 *
 * RFC 8785 compliance notes (why so little custom logic is needed):
 *  - Number serialization: RFC 8785 §3.2.2.3 mandates the ECMAScript
 *    `Number::toString` algorithm, which is EXACTLY what V8's
 *    `JSON.stringify`/`String(number)` already implement (both call the
 *    same abstract operation). `-0` already stringifies to `"0"` under
 *    that algorithm. No custom number formatting is implemented here —
 *    doing so would risk DIVERGING from the spec, not conforming to it.
 *  - String escaping: RFC 8785 mandates the ECMA-262 `Quote` abstract
 *    operation, which is exactly what `JSON.stringify` already implements
 *    for strings (backslash/quote/control-char escaping; non-ASCII
 *    characters are NOT escaped).
 *  - Key ordering: RFC 8785 mandates UTF-16 code UNIT order, which is
 *    JavaScript's default `Array.prototype.sort()` string comparison —
 *    no locale-aware or code-point-aware comparator needed (those would
 *    be the ones that risk divergence, e.g. from a cross-language
 *    implementation that sorts by code point instead).
 *
 * Explicitly forbidden (throws `JcsCanonicalizationError`), and why:
 *  - `undefined` anywhere (top level, object value, array element) — see
 *    "deliberate design" above.
 *  - non-finite numbers (`NaN`/`Infinity`) — not legal JSON.
 *  - lone (unpaired) UTF-16 surrogates in strings — encoding one to UTF-8
 *    requires a lossy substitution (Node's `Buffer.from(str,'utf8')`
 *    silently replaces an unpaired surrogate with U+FFFD). TS and Python
 *    JSON encoders are documented to diverge on this exact case
 *    (SEC-PA01-11(b)); rather than risk the two implementations computing
 *    different bytes for the "same" logical request (a spurious
 *    commitment mismatch — an availability bug, not a security hole, but
 *    an avoidable one), this module refuses to commit to ill-formed text.
 *  - `Date` / `Buffer` / `BigInt` / functions / symbols — SEC-PA01-11(c):
 *    `canonical-json.ts` coerces these (Date→ISO string, Buffer→base64),
 *    which is non-injective (a `Buffer` and its own base64 string
 *    canonicalize identically). That is acceptable for server-controlled
 *    audit-row shapes; it is NOT acceptable on an attacker-reachable
 *    commitment input, where two different logical requests hashing to
 *    the same bytes is exactly the kind of collision this primitive
 *    exists to prevent.
 */
export class JcsCanonicalizationError extends Error {
  constructor(message: string) {
    super(`JCS canonicalization refused: ${message}`);
    this.name = 'JcsCanonicalizationError';
  }
}

/** A value producible by `JSON.parse`, and nothing else. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

function hasUnpairedSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const isHighSurrogate = code >= 0xd800 && code <= 0xdbff;
    const isLowSurrogate = code >= 0xdc00 && code <= 0xdfff;
    if (isHighSurrogate) {
      const next = s.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      i++; // consumed as a valid pair
    } else if (isLowSurrogate) {
      // A low surrogate not immediately preceded by a consumed high
      // surrogate is itself unpaired.
      return true;
    }
  }
  return false;
}

function canonicalize(v: JsonValue | undefined): string {
  if (v === undefined) {
    throw new JcsCanonicalizationError(
      'undefined is not a valid JSON value (top level, object value, or array element)',
    );
  }
  if (v === null) {
    return 'null';
  }
  if (typeof v === 'boolean') {
    return v ? 'true' : 'false';
  }
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) {
      throw new JcsCanonicalizationError(
        `non-finite number is not valid JSON: ${String(v)}`,
      );
    }
    // See module docstring — this already matches RFC 8785 §3.2.2.3
    // (ECMAScript Number::toString), including -0 -> "0".
    return JSON.stringify(v);
  }
  if (typeof v === 'string') {
    if (hasUnpairedSurrogate(v)) {
      throw new JcsCanonicalizationError(
        'string contains an unpaired UTF-16 surrogate, which cannot be ' +
          'encoded to well-formed UTF-8 without a lossy substitution',
      );
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    // Visit every index: Array.map skips holes, which could otherwise emit
    // invalid JSON or erase an absent element from the committed array.
    const parts: string[] = [];
    for (let i = 0; i < v.length; i++) {
      parts.push(canonicalize(v[i]));
    }
    return '[' + parts.join(',') + ']';
  }
  if (typeof v === 'object') {
    if (v instanceof Date) {
      throw new JcsCanonicalizationError(
        'Date is not a JSON value — pass an explicit ISO string instead',
      );
    }
    if (Buffer.isBuffer(v)) {
      throw new JcsCanonicalizationError(
        'Buffer is not a JSON value — pass an explicit base64 string instead',
      );
    }
    // TICKET-213 precedent (see canonical-json.ts) — copy into a
    // null-prototype accumulator via Object.assign so "__proto__" behaves
    // as an ordinary own string key instead of resolving through the
    // prototype chain.
    const own = Object.assign(
      Object.create(null) as Record<string, JsonValue>,
      v,
    );
    const keys = Object.keys(own).sort();
    const parts = keys.map((k) => {
      const val = own[k];
      if (val === undefined) {
        throw new JcsCanonicalizationError(
          `object key "${k}" has value undefined — omit the key entirely ` +
            'instead of setting it to undefined',
        );
      }
      // Property names are JSON strings too and must obey the same Unicode
      // constraints as string values.
      return canonicalize(k) + ':' + canonicalize(val);
    });
    return '{' + parts.join(',') + '}';
  }
  if (typeof v === 'bigint') {
    throw new JcsCanonicalizationError(
      'BigInt is not a JSON value — pass an explicit string instead',
    );
  }
  throw new JcsCanonicalizationError(
    `value of type ${typeof v} is not a valid JSON value`,
  );
}

/**
 * Returns the RFC 8785 canonical UTF-8 bytes for `value`. Throws
 * `JcsCanonicalizationError` on anything not representable as a strict
 * JSON value — see the module docstring for the full, deliberate list.
 */
export function jcsCanonicalize(value: JsonValue): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

/**
 * `sha256(JCS(value))`, hex, lowercase — the commitment primitive PA01 D2
 * specifies. This is the ONE shared helper; every write side and every
 * read side must call this function rather than re-deriving the digest
 * inline (mirrors the single-helper discipline in
 * `audit-canonical.helper.ts` that keeps the audit chain verifiable).
 */
export function jcsCommitment(value: JsonValue): string {
  return createHash('sha256').update(jcsCanonicalize(value)).digest('hex');
}
