import { describe, expect, it } from 'vitest';
import { parseStrictJson } from '../src/public/strict-json.js';

describe('strict JSON members', () => {
  it.each([
    '{"enabled":true,"enabled":false}',
    '{"enabled":true,"\\u0065nabled":false}',
    '{"params":{"arguments":{"enabled":true,"enabled":false}}}',
    '{"items":[{"name":"a","name":"b"}]}',
    '{"__proto__":1,"__proto__":2}',
  ])('rejects duplicate members: %s', (raw) => {
    expect(() => parseStrictJson(raw)).toThrow('Duplicate JSON member.');
  });
  it.each([
    '{"enabled":false}',
    '{"a":{"name":"a"},"b":{"name":"b"}}',
    '{"items":[{"name":"a"},{"name":"b"}]}',
    JSON.stringify({ text: 'braces {} [] and "quotes"', enabled: true }),
    '{"\\u0065nabled":false}',
    'null',
    '[]',
    'true',
    '123',
  ])('preserves valid JSON: %s', (raw) => {
    expect(parseStrictJson(raw)).toEqual(JSON.parse(raw));
  });
  it.each(['', '{', '{} {}', '{"a":null,}', '{"a":undefined}'])(
    'rejects invalid syntax: %s',
    (raw) => {
      expect(() => parseStrictJson(raw)).toThrow();
    },
  );
});
