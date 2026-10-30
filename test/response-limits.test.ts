import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { createHmac } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { CHARACTER_LIMIT, TOOL_NAMES } from '../src/constants.js';
import { enforceCharacterLimit, enforceJsonLimit } from '../src/format.js';
import { respond } from '../src/tools/shared.js';
import { callTool, connect, fixture, textOf, type Connected } from './helpers.js';

let connected: Connected | undefined;

afterEach(async () => {
  await connected?.close();
  connected = undefined;
});

/** Text and structured content both fit; json text is exactly the structured content. */
function expectWithinLimits(result: CallToolResult, format: 'markdown' | 'json'): void {
  expect(result.isError, textOf(result).slice(0, 300)).toBeFalsy();
  const text = textOf(result);
  expect(text.length).toBeLessThanOrEqual(CHARACTER_LIMIT);
  expect(JSON.stringify(result.structuredContent).length).toBeLessThanOrEqual(CHARACTER_LIMIT);
  if (format === 'json') expect(JSON.parse(text)).toEqual(result.structuredContent);
}

describe('response size limits', () => {
  it('shorten explanations of pasted identifications with long values and many signals', async () => {
    connected = await connect({});
    const pasted = {
      identification_id: 'r'.repeat(5_000),
      risk_score: 100,
      connection_type: 'x'.repeat(5_000),
      signals: Array.from({ length: 60 }, (_, index) => ({
        name: `${index}${'n'.repeat(2_000)}`,
        weight: 15,
      })),
    };
    for (const format of ['markdown', 'json'] as const) {
      const result = await callTool(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: pasted,
        response_format: format,
      });
      expectWithinLimits(result, format);
      const explanation = result.structuredContent as any;
      expect(explanation.truncated).toBe(true);
      expect(explanation.truncation_message).toContain('names were cut to 100 characters');
      expect(explanation.truncation_message).toContain(
        'identification_id was cut to 100 characters',
      );
      expect(explanation.truncation_message).toContain('connection_type was cut to 100 characters');
      expect(explanation.identification_id).toHaveLength(100);
      if (format === 'markdown') expect(textOf(result)).toContain('Note: ');
    }
  });

  it('drop risk signals from an explanation until it fits, and say so', async () => {
    connected = await connect({});
    const many = {
      risk_score: 100,
      signals: Array.from({ length: 60 }, () => ({ name: 'antidetect_browser', weight: 60 })),
      detection_flags: Object.fromEntries(
        Object.keys(fixture('webhook-identification-scored.json').data.detection_flags).map(
          (flag) => [flag, true],
        ),
      ),
    };
    for (const format of ['markdown', 'json'] as const) {
      const result = await callTool(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: many,
        response_format: format,
      });
      expectWithinLimits(result, format);
      const explanation = result.structuredContent as any;
      expect(explanation.detection_flags.map((f: any) => f.flag)).toEqual(
        expect.arrayContaining(['private_relay', 'network_check_incomplete']),
      );
      expect(explanation.signals.length).toBeGreaterThan(10);
      expect(explanation.signals.length).toBeLessThan(60);
      expect(explanation.truncation_message).toMatch(
        /Only the first \d+ of 60 risk signals are explained to keep the response under 25,000 characters\./,
      );
    }
  });

  it('shorten the event summary of an authentic body with oversized fields', async () => {
    connected = await connect({});
    const body = JSON.stringify({
      event_type: 'e'.repeat(50_000),
      schema_version: 'v'.repeat(50_000),
      created_at: 't'.repeat(50_000),
    });
    const signature = `sha256=${createHmac('sha256', 'whsec_test').update(body).digest('hex')}`;
    for (const format of ['markdown', 'json'] as const) {
      const result = await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload: body,
        signature_header: signature,
        secret: 'whsec_test',
        response_format: format,
      });
      expectWithinLimits(result, format);
      const event = (result.structuredContent as any).event;
      expect(event.event_type).toBe(`${'e'.repeat(200)}... (50000 characters)`);
    }
  });
});

describe('last-resort limits', () => {
  it('replace oversized JSON with a small valid document that says what to ask for', () => {
    const json = enforceJsonLimit(
      JSON.stringify({ value: 'x'.repeat(30_000) }),
      'Use a smaller limit.',
    );
    expect(JSON.parse(json)).toEqual({
      truncated: true,
      truncation_message:
        'The JSON response has 30,012 characters, more than the limit of 25,000, so it was not returned. Use a smaller limit.',
    });
    expect(enforceJsonLimit('{"a":1}')).toBe('{"a":1}');
  });

  it('name the tool-specific hint when markdown is cut', () => {
    const cut = enforceCharacterLimit('y'.repeat(CHARACTER_LIMIT + 10), 'Use a smaller max_items.');
    expect(cut.length).toBeLessThanOrEqual(CHARACTER_LIMIT);
    expect(
      cut.endsWith('[Response truncated at 25,000 characters. Use a smaller max_items.]'),
    ).toBe(true);
  });

  it('keep json text parseable in respond()', () => {
    const structured = { value: 'x'.repeat(30_000) };
    const result = respond({ secrets: [] }, structured, 'short', 'json', 'Use a smaller limit.');
    const parsed = JSON.parse(textOf(result));
    expect(parsed.truncated).toBe(true);
    expect(parsed.truncation_message).toContain('Use a smaller limit.');
    expect(textOf(respond({ secrets: [] }, structured, 'short', 'markdown'))).toBe('short');
  });
});
