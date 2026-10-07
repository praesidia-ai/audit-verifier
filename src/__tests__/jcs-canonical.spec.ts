import { describe, expect, it } from 'vitest';
import { JcsCanonicalizationError, jcsCanonicalize, type JsonValue } from '../jcs-canonical.js';

describe('JCS array serialization', () => {
  it('rejects missing array elements rather than omitting their positions', () => {
    const trailingHole: JsonValue[] = [1];
    trailingHole.length = 2;
    const leadingHole: JsonValue[] = [1, 2];
    delete leadingHole[0];

    for (const value of [Array<JsonValue>(1), leadingHole, trailingHole, { nested: leadingHole }]) {
      expect(() => jcsCanonicalize(value)).toThrow(JcsCanonicalizationError);
      expect(() => jcsCanonicalize(value)).toThrow(/undefined is not a valid JSON value/);
    }
  });

  it('preserves the order and explicit null elements of dense arrays', () => {
    const value: JsonValue = [null, 1, false, { z: 2, a: 'x' }, []];
    const serialized = jcsCanonicalize(value).toString('utf8');
    expect(serialized).toBe('[null,1,false,{"a":"x","z":2},[]]');
    expect(JSON.parse(serialized)).toEqual(value);
  });
});

describe('JCS object property names', () => {
  it('rejects unpaired surrogates in property names and values consistently', () => {
    for (const malformed of ['\ud800', '\udfff', 'before\ud800after']) {
      expect(() => jcsCanonicalize({ [malformed]: 'value' })).toThrow(/unpaired UTF-16 surrogate/);
      expect(() => jcsCanonicalize({ key: malformed })).toThrow(/unpaired UTF-16 surrogate/);
    }
  });

  it('preserves well-formed surrogate pairs in property names', () => {
    const value = { '\ud83d\ude00': 'smile', a: 1 };
    const serialized = jcsCanonicalize(value).toString('utf8');
    expect(serialized).toBe('{"a":1,"😀":"smile"}');
    expect(JSON.parse(serialized)).toEqual(value);
  });
});
