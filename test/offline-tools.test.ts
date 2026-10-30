import { afterEach, describe, expect, it } from 'vitest';
import { MOCK_PROFILE } from '../scripts/generate-mock-data.mjs';
import { TOOL_NAMES } from '../src/constants.js';
import { DIAGNOSE_MAX_BYTES, diagnoseChangedBody } from '../src/tools/verify-webhook.js';
import {
  callJson,
  callTool,
  connect,
  fixture,
  fixtureText,
  FULL_ENV,
  mockApiFetch,
  textOf,
  type Connected,
} from './helpers.js';

let connected: Connected | undefined;

afterEach(async () => {
  await connected?.close();
  connected = undefined;
});

const historyPage = fixture('history-page.json');
const scored = fixture('webhook-identification-scored.json');
const rateLimited = fixture('webhook-rate-limited.json');
const ping = fixture('webhook-ping.json');
const vectors = fixture<{ vectors: any[] }>('webhook-signature-vectors.json').vectors;

describe('shieldlabs_explain_risk_score', () => {
  it('explains a webhook event: band, weighted signals, flags, connection type', async () => {
    connected = await connect({});
    const event = structuredClone(scored);
    event.data.identification_id = event.data.request_id;
    delete event.data.request_id;
    const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: event,
    });
    expect(output).toMatchObject({
      identification_id: '02f1d973-84db-4156-a7f7-e799e6bf389b',
      risk_score: 80,
      risk_band: 'dangerous',
      band_range: '60-100',
      source: 'webhook',
    });
    expect(output.band_meaning).toContain('Strong risk signals.');
    expect(output.signals.map((s: any) => [s.name, s.weight, s.in_catalog])).toEqual([
      ['proxy', 10, true],
      ['datacenter_ip', 10, true],
      ['antidetect_browser', 60, true],
    ]);
    expect(output.signals[2]).toMatchObject({
      label: 'Anti-detect Browser',
      typical_weight: 60,
      related_flag: 'anti_detect_browser',
    });
    expect(output.detection_flags.map((f: any) => f.flag)).toEqual([
      'proxy',
      'anti_detect_browser',
      'ip_mismatch',
    ]);
    expect(output.detection_flags.find((f: any) => f.flag === 'ip_mismatch').scored).toBe(false);
    expect(output.connection_type).toMatchObject({ value: 'proxy', label: 'Proxy' });
    expect(output.notes.join(' ')).toContain('never add up weights yourself');
  });

  it('renders the explanation as markdown with a table', async () => {
    connected = await connect({});
    const text = textOf(
      await callTool(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: JSON.stringify(scored.data),
      }),
    );
    expect(text).toContain('# Risk Score 80: dangerous (60-100)');
    expect(text).toContain('| Anti-detect Browser (`antidetect_browser`) | +60 |');
    expect(text).toContain('- IP Mismatch (`ip_mismatch`, informational)');
    expect(text).toContain('## Connection type');
  });

  it('normalizes a raw History row with unknown and repeated signal names', async () => {
    connected = await connect({});
    const vpnRow = historyPage.data[2];
    const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: vpnRow,
    });
    expect(output.risk_score).toBe(45);
    expect(output.risk_band).toBe('suspicious');
    expect(output.source).toBe('history');
    expect(output.signals.map((s: any) => s.name)).toEqual([
      'vpn',
      'network_check_incomplete',
      'stun_late_correction',
      'stun_is_not_checked',
    ]);
    const unknown = output.signals[3];
    expect(unknown.in_catalog).toBe(false);
    expect(unknown.meaning).toContain('Not in this catalog');
    const notes = output.notes.join(' ');
    expect(notes).toContain('not in this server catalog');
    expect(output.detection_flags.map((f: any) => f.flag)).toContain('check_incomplete');
  });

  it('explains the rate-limit marker, crawlers and the all-zero device ID', async () => {
    connected = await connect({});
    const marker = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: rateLimited,
    });
    expect(marker.risk_band).toBe('banned_ip');
    expect(marker.band_range).toBe('above 100 (999)');
    expect(marker.band_meaning).toContain('not a Risk Score and not a band');
    expect(marker.notes.join(' ')).toContain('all-zero device ID');
    const markdown = textOf(
      await callTool(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: rateLimited,
      }),
    );
    expect(markdown).toContain('# Rate-limit marker 999 (not a Risk Score)');

    const crawler = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: historyPage.data[4],
    });
    expect(crawler.risk_score).toBe(0);
    expect(crawler.signals).toEqual([]);
    expect(crawler.notes.join(' ')).toContain('search-engine crawler');
    const crawlerText = textOf(
      await callTool(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: historyPage.data[4],
      }),
    );
    expect(crawlerText).toContain('Detailed signal weights are unavailable');
  });

  it('reads score_details when risk_score is set and signals are empty', async () => {
    connected = await connect({});
    const row = {
      ...historyPage.data[0],
      risk_score: 30,
      score: 30,
      signals: [],
      score_details: '[{"Value":30,"Description":"Is VPN"}]',
    };
    const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: row,
    });
    expect(output.risk_score).toBe(30);
    expect(output.risk_band).toBe('suspicious');
    expect(
      output.signals.map((signal: { name: string; weight: number }) => [
        signal.name,
        signal.weight,
      ]),
    ).toEqual([['vpn', 30]]);
    const markdown = textOf(
      await callTool(connected.client, TOOL_NAMES.explainRiskScore, { identification: row }),
    );
    expect(markdown).toContain('| VPN (`vpn`) | +30 |');
    expect(markdown).not.toContain('nothing added to the Risk Score');
    expect(markdown).not.toContain('Detailed signal weights are unavailable');
  });

  it('recovers score_details without requiring score or losing normalized context', async () => {
    connected = await connect({});
    const row = {
      identification_id: '33333333-3333-4333-8333-333333333333',
      risk_score: 30,
      signals: [],
      detection_flags: { vpn: true, proxy: false },
      connection_type: 'vpn',
      score_details: '[{"Value":30,"Description":"Is VPN"}]',
    };
    const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: row,
    });
    expect(output.risk_score).toBe(30);
    expect(
      output.signals.map((signal: { name: string; weight: number }) => [
        signal.name,
        signal.weight,
      ]),
    ).toEqual([['vpn', 30]]);
    expect(output.connection_type.value).toBe('vpn');
    const text = textOf(
      await callTool(connected.client, TOOL_NAMES.explainRiskScore, { identification: row }),
    );
    expect(text).toContain('| VPN (`vpn`) | +30 |');
    expect(text).not.toContain('nothing added to the Risk Score');
  });

  it('prefers supplied weighted signals, including zero weights, over score_details', async () => {
    connected = await connect({});
    for (const weight of [0, 30]) {
      const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: {
          risk_score: 30,
          signals: [{ name: 'proxy', weight }],
          score_details: '[{"Value":30,"Description":"Is VPN"}]',
        },
      });
      expect(
        output.signals.map((signal: { name: string; weight: number }) => [
          signal.name,
          signal.weight,
        ]),
      ).toEqual([['proxy', weight]]);
    }
  });

  it('keeps webhook origin when weights are recovered from score_details', async () => {
    connected = await connect({});
    const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: {
        event_type: 'identification.scored',
        data: {
          risk_score: 30,
          signals: [],
          score_details: '[{"Value":30,"Description":"Is VPN"}]',
        },
      },
    });
    expect(output.source).toBe('webhook');
    expect(output.signals[0].weight).toBe(30);
  });

  it('accepts the json output of shieldlabs_get_identification', async () => {
    connected = await connect(FULL_ENV, {
      apiFetch: mockApiFetch({ rows: historyPage.data, profile: MOCK_PROFILE }).fetch,
    });
    const found = await callJson(connected.client, TOOL_NAMES.getIdentification, {
      identification_id: '7c1e2f4a-3b6d-4e8f-9a0b-1c2d3e4f5a6b',
      domain: '11111111-1111-4111-8111-111111111111',
    });
    const fromOutput = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: found,
    });
    const fromApi = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification_id: '7c1e2f4a-3b6d-4e8f-9a0b-1c2d3e4f5a6b',
      domain: '11111111-1111-4111-8111-111111111111',
    });
    expect(fromOutput.signals).toEqual(fromApi.signals);
    expect(fromApi).toMatchObject({
      risk: { state: 'ok', score: 10, band: 'trusted' },
      weights_available: false,
    });
  });

  it('gives actionable errors for unusable input', async () => {
    connected = await connect({});
    const attempts: [Record<string, unknown>, string][] = [
      [{}, 'Give a pasted identification'],
      [
        { identification_id: '02f1d973-84db-4156-a7f7-e799e6bf389b', identification: {} },
        'Give a pasted identification',
      ],
      [
        {
          identification_id: '02f1d973-84db-4156-a7f7-e799e6bf389b',
          domain: '11111111-1111-4111-8111-111111111111',
        },
        'SHIELDLABS_API_KEY is not set',
      ],
      [{ identification: '{not json' }, 'not valid JSON'],
      [{ identification: '[1,2]' }, 'must be a JSON object'],
      [{ identification: ping }, 'carries no identification'],
      [{ identification: historyPage }, 'looks like a History API page'],
      [{ identification: { hello: 'world' } }, 'has no risk_score'],
      [
        { identification: { risk_score: 'high' } },
        'risk_score must be an integer from 0 to 100, or the 999 rate-limit marker; got a string.',
      ],
    ];
    for (const [args, message] of attempts) {
      const result = await callTool(connected.client, TOOL_NAMES.explainRiskScore, args);
      expect(result.isError, JSON.stringify(args)).toBe(true);
      expect(textOf(result)).toContain(message);
    }
  });

  it('refuses pasted scores and weights outside the valid values', async () => {
    connected = await connect({});
    const valid = 'must be an integer from 0 to 100, or the 999 rate-limit marker';
    const attempts: [Record<string, unknown>, string][] = [
      [{ risk_score: -5 }, `risk_score ${valid}; got -5.`],
      [{ risk_score: 1e20 }, `risk_score ${valid}; got 100000000000000000000.`],
      [{ risk_score: 45.5 }, `risk_score ${valid}; got 45.5.`],
      [{ risk_score: 150 }, `risk_score ${valid}; got 150.`],
      [{ risk_score: null }, `risk_score ${valid}; got null.`],
      [
        {
          risk_score: 30,
          signals: [
            { name: 'vpn', weight: 15 },
            { name: 'proxy', weight: 1e20 },
          ],
        },
        'signals[1].weight must be an integer; got 100000000000000000000.',
      ],
      [
        { risk_score: 30, signals: [{ name: 'vpn', weight: 15.5 }] },
        'signals[0].weight must be an integer; got 15.5.',
      ],
      [{ ...historyPage.data[0], score: -5 }, `score ${valid}; got -5.`],
      [
        { ...historyPage.data[0], score_details: '[{"Value":1e20,"Description":"Is VPN"}]' },
        'Every score_details Value must be an integer; got 100000000000000000000.',
      ],
      // A History row without its score is not a Risk Score of 0.
      [
        { score_details: '[{"Value":15,"Description":"Is VPN"}]' },
        'This History API row has score_details but no score. Paste the whole row, including score, or use identification_id.',
      ],
    ];
    for (const [identification, message] of attempts) {
      const result = await callTool(connected.client, TOOL_NAMES.explainRiskScore, {
        identification,
      });
      expect(result.isError, JSON.stringify(identification).slice(0, 200)).toBe(true);
      expect(textOf(result)).toContain(message);
      expect(textOf(result)).not.toContain('Output validation error');
    }
    for (const score of [0, 100, 999]) {
      const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: { risk_score: score },
      });
      expect(output.risk_score).toBe(score);
    }
  });

  it('tolerates partial objects: missing flags are false, invalid signals are skipped', async () => {
    connected = await connect({});
    const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: {
        risk_score: 35,
        signals: [
          { name: 'os_not_detected', weight: 30 },
          { name: 'bad' },
          'x',
          { name: 'mystery_signal', weight: 5 },
        ],
        detection_flags: { os_not_detected: true, vpn: 'yes' },
        connection_type: 'satellite',
      },
    });
    expect(output.risk_band).toBe('suspicious');
    expect(output.identification_id).toBeNull();
    expect(output.signals.map((s: any) => s.name)).toEqual(['os_not_detected', 'mystery_signal']);
    expect(output.detection_flags.map((f: any) => f.flag)).toEqual(['os_not_detected']);
    expect(output.connection_type).toMatchObject({
      value: 'satellite',
      meaning: expect.stringContaining('does not know'),
    });
    const many = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: {
        risk_score: 100,
        signals: Array.from({ length: 70 }, () => ({ name: 'vpn', weight: 15 })),
      },
    });
    expect(many.signals).toHaveLength(60);
    expect(many.notes.join(' ')).toContain('Only the first 60 of 70');
    expect(many.connection_type).toBeNull();
  });
});

describe('shieldlabs_verify_webhook_signature', () => {
  it('agrees with every shared signature vector', async () => {
    connected = await connect({});
    for (const vector of vectors) {
      // A list of secrets goes in as one comma-separated value.
      const secret: string = vector.secret ?? vector.secrets.join(',');
      if (secret === '') {
        const result = await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
          payload: vector.body,
          signature_header: vector.signature_header,
          secret,
        });
        expect(result.isError, vector.name).toBe(true);
        continue;
      }
      const output = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload: vector.body_base64,
        payload_encoding: 'base64',
        signature_header: vector.signature_header,
        secret,
      });
      expect(output.valid, vector.name).toBe(vector.valid);
      for (const key of secret.split(',')) expect(JSON.stringify(output)).not.toContain(key);
    }
  });

  it('verifies against a comma-separated list while a secret is rotated', async () => {
    const rotation = vectors.find((v) => v.name === 'valid_rotation_second_secret_matches');
    const [oldSecret, newSecret] = rotation.secrets as [string, string];
    // From the environment, with spaces around the comma.
    connected = await connect({ SHIELDLABS_WEBHOOK_SECRET: ` ${oldSecret} , ${newSecret} ` });
    const fromEnv = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: rotation.body,
      signature_header: rotation.signature_header,
    });
    expect(fromEnv).toMatchObject({
      valid: true,
      secret_source: 'environment',
      secrets_checked: 2,
      matched_secret: 2,
      hint: null,
    });
    expect(fromEnv.checks.find((c: any) => c.check === 'signature').detail).toContain(
      'with secret 2 of 2',
    );
    expect(fromEnv.checks.find((c: any) => c.check === 'secret_prefix')).toMatchObject({
      ok: true,
      detail: 'Each of the 2 secrets includes its whsec_ prefix.',
    });
    expect(fromEnv.event).toMatchObject({ event_type: expect.any(String) });
    for (const key of [oldSecret, newSecret]) expect(JSON.stringify(fromEnv)).not.toContain(key);

    // From the argument: no secret matches, and one of them lacks the whsec_ prefix.
    const none = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: rotation.body,
      signature_header: rotation.signature_header,
      secret: `${oldSecret},00112233445566778899aabbccddeeff`,
    });
    expect(none).toMatchObject({
      valid: false,
      secret_source: 'argument',
      secrets_checked: 2,
      matched_secret: null,
    });
    expect(none.checks.find((c: any) => c.check === 'signature').detail).toContain(
      'with any of the 2 secrets',
    );
    expect(none.checks.find((c: any) => c.check === 'secret_prefix')).toMatchObject({
      ok: false,
    });
    expect(none.checks.find((c: any) => c.check === 'secret_prefix').detail).toContain(
      'Secret 2 of 2 does not start with whsec_',
    );
    expect(none.hint).toContain('one of the secrets belongs to this endpoint');
    const unprefixed = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: rotation.body,
      signature_header: rotation.signature_header,
      secret: 'aaaa,whsec_x,bbbb',
    });
    expect(unprefixed.checks.find((c: any) => c.check === 'secret_prefix').detail).toContain(
      'Secrets 1 and 3 of 3 do not start with whsec_',
    );

    // A value with only commas and spaces holds no secret.
    const empty = await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: rotation.body,
      signature_header: rotation.signature_header,
      secret: ' , ',
    });
    expect(empty.isError).toBe(true);
    expect(textOf(empty)).toContain('no signing secret');
  });

  it('checks each secret of a rotation pair on its own', async () => {
    connected = await connect({});
    const rotation = vectors.find((v) => v.name === 'valid_rotation_second_secret_matches');
    const results = [];
    for (const secret of rotation.secrets) {
      const output = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload: rotation.body,
        signature_header: rotation.signature_header,
        secret,
      });
      results.push(output.valid);
    }
    expect(results).toEqual([false, true]);
  });

  it('verifies with SHIELDLABS_WEBHOOK_SECRET and summarizes the event', async () => {
    connected = await connect({
      SHIELDLABS_WEBHOOK_SECRET: 'whsec_00112233445566778899aabbccddeeff',
    });
    const output = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: fixtureText('webhook-ping.raw.txt'),
      signature_header: 'sha256=ea2685733d254f7028fb031c4214583b0650de01e6c8c93131236024edd9fdd8',
    });
    expect(output).toMatchObject({
      valid: true,
      secret_source: 'environment',
      secrets_checked: 1,
      matched_secret: 1,
      event: {
        event_type: 'webhook.ping',
        schema_version: '2026-06-01',
        identification_id: null,
        risk_score: null,
      },
      hint: null,
    });
    const scoredVector = vectors.find((v) => v.name === 'valid_scored_with_escaped_ampersand');
    const text = textOf(
      await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload: scoredVector.body,
        signature_header: scoredVector.signature_header,
      }),
    );
    expect(text).toContain('# Webhook signature: valid');
    expect(text).toContain('Event type: `identification.scored`');
    expect(text).toMatch(/Risk Score: \d+ \(/);
    expect(text).not.toContain('whsec_00112233445566778899aabbccddeeff');
  });

  it('names the body change that explains a mismatch', async () => {
    connected = await connect({
      SHIELDLABS_WEBHOOK_SECRET: 'whsec_00112233445566778899aabbccddeeff',
    });
    const header = 'sha256=ea2685733d254f7028fb031c4214583b0650de01e6c8c93131236024edd9fdd8';
    const raw = fixtureText('webhook-ping.raw.txt');
    const pretty = JSON.stringify(JSON.parse(raw), null, 2);
    const cases: [string, string][] = [
      [`${raw}\n`, 'removing trailing whitespace'],
      [pretty, 'compacting the JSON'],
    ];
    for (const [payload, change] of cases) {
      const output = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload,
        signature_header: header,
      });
      expect(output.valid).toBe(false);
      expect(output.hint).toContain(change);
    }
    const ampersand = vectors.find((v) => v.name === 'invalid_scored_unescaped_reserialization');
    const unescaped = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: ampersand.body,
      signature_header: ampersand.signature_header,
    });
    expect(unescaped.hint).toContain('escaping &');
    const crlf = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: pretty.replace(/\n/g, '\r\n'),
      signature_header: header,
    });
    expect(crlf.valid).toBe(false);
    expect(crlf.hint).toContain('compacting the JSON');
    const wrong = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: raw,
      signature_header: header,
      secret: '00112233445566778899aabbccddeeff',
    });
    expect(wrong.valid).toBe(false);
    expect(wrong.secret_source).toBe('argument');
    expect(wrong.checks.find((c: any) => c.check === 'secret_prefix').ok).toBe(false);
    expect(wrong.hint).toContain('belongs to this endpoint');
  });

  it('reports no Risk Score for an authentic event whose risk_score is not a valid value', async () => {
    connected = await connect({});
    const { createHmac } = await import('node:crypto');
    const sign = (body: string) =>
      `sha256=${createHmac('sha256', 'whsec_test').update(body).digest('hex')}`;
    const cases: [number, string][] = [
      [1e20, '100000000000000000000'],
      [1e300, '1e+300'],
      [-5, '-5'],
      [150, '150'],
      [998, '998'],
      [50.5, '50.5'],
    ];
    for (const [score, shown] of cases) {
      const body = JSON.stringify({ ...scored, data: { ...scored.data, risk_score: score } });
      for (const format of ['json', 'markdown'] as const) {
        const result = await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
          payload: body,
          signature_header: sign(body),
          secret: 'whsec_test',
          response_format: format,
        });
        expect(result.isError, textOf(result)).toBeFalsy();
        const output = result.structuredContent as any;
        expect(output.valid).toBe(true);
        expect(output.event).toMatchObject({
          event_type: 'identification.scored',
          identification_id: scored.data.request_id,
          risk_score: null,
          risk_band: null,
        });
        expect(output.checks.at(-1)).toMatchObject({ check: 'event', ok: false });
        expect(output.checks.at(-1).detail).toContain(
          `risk_score ${shown} is outside 0-100 and the 999 rate-limit marker`,
        );
        if (format === 'markdown') expect(textOf(result)).not.toContain('- Risk Score:');
      }
    }
    for (const score of [0, 100, 999]) {
      const body = JSON.stringify({ ...scored, data: { ...scored.data, risk_score: score } });
      const output = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload: body,
        signature_header: sign(body),
        secret: 'whsec_test',
      });
      expect(output.event.risk_score).toBe(score);
      expect(output.event.risk_band).toBe(
        score === 999 ? 'banned_ip' : score === 0 ? 'trusted' : 'dangerous',
      );
      expect(output.checks.map((c: any) => c.check)).toEqual([
        'header_format',
        'secret_prefix',
        'signature',
      ]);
    }
  });

  it('reminds of the delivery rules: one delivery today, idempotent handlers, History for reads', async () => {
    connected = await connect({});
    const text = textOf(
      await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload: '{}',
        signature_header: `sha256=${'0'.repeat(64)}`,
        secret: 'whsec_x',
      }),
    );
    expect(text).toContain('deduplicate on event_id');
    expect(text).toContain('hre.multi_account.changed');
    expect(text).toContain('Use the History API for the latest identification');
  });

  it('explains malformed headers, bad base64, missing secrets and inauthentic events', async () => {
    connected = await connect({});
    const malformed = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: '{}',
      signature_header: 'sha1=abc',
      secret: 'whsec_x',
    });
    expect(malformed.valid).toBe(false);
    expect(malformed.checks[0]).toMatchObject({ check: 'header_format', ok: false });
    expect(malformed.hint).toContain('unchanged');
    const noSecret = await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: '{}',
      signature_header: 'sha256=00',
    });
    expect(noSecret.isError).toBe(true);
    expect(textOf(noSecret)).toContain('SHIELDLABS_WEBHOOK_SECRET');
    const badBase64 = await callTool(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: '***',
      payload_encoding: 'base64',
      signature_header: 'sha256=00',
      secret: 'whsec_x',
    });
    expect(badBase64.isError).toBe(true);
    expect(textOf(badBase64)).toContain('not valid base64');

    // An authentic body that is not an event: signed with the vector secret over plain text.
    const { createHmac } = await import('node:crypto');
    const body = 'not an event';
    const signature = `sha256=${createHmac('sha256', 'whsec_test').update(body).digest('hex')}`;
    const notEvent = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: body,
      signature_header: signature,
      secret: 'whsec_test',
    });
    expect(notEvent.valid).toBe(true);
    expect(notEvent.event).toBeNull();
    expect(notEvent.checks.at(-1)).toMatchObject({ check: 'event', ok: false });
  });
});

describe('webhook body diagnostics', () => {
  const zeroHeader = `sha256=${'0'.repeat(64)}`;

  it('run in linear time on 1,000,000-character whitespace bodies', () => {
    const encoder = new TextEncoder();
    const bodies = [
      `${' '.repeat(1_000_000)}x`,
      `x${' '.repeat(1_000_000)}`,
      `${' \t\r\n'.repeat(250_000)}x`,
    ];
    for (const body of bodies) {
      const started = performance.now();
      expect(diagnoseChangedBody(encoder.encode(body), zeroHeader, 'whsec_x')).toBeUndefined();
      expect(performance.now() - started).toBeLessThan(1_000);
    }
  });

  it('answer a maximal whitespace payload with a wrong signature within a second', async () => {
    connected = await connect({});
    const started = performance.now();
    const large = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: `${' '.repeat(999_999)}x`,
      signature_header: zeroHeader,
      secret: 'whsec_x',
    });
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(large.valid).toBe(false);
    expect(large.hint).toContain('larger than 64 KB, so common body changes were not tested');

    // Just under the size cap the diagnostics run, and stay fast.
    const nearCapStarted = performance.now();
    const nearCap = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
      payload: `${' '.repeat(DIAGNOSE_MAX_BYTES - 1)}x`,
      signature_header: zeroHeader,
      secret: 'whsec_x',
    });
    expect(performance.now() - nearCapStarted).toBeLessThan(1_000);
    expect(nearCap.valid).toBe(false);
    expect(nearCap.hint).toContain('belongs to this endpoint');
  });
});

describe('shieldlabs_current_time', () => {
  it('returns UTC and a local time for an IANA zone', async () => {
    connected = await connect({}, { now: () => Date.parse('2026-09-30T12:34:56.789Z') });
    const utc = await callJson(connected.client, TOOL_NAMES.currentTime);
    expect(utc).toEqual({
      utc: '2026-09-30T12:34:56.789Z',
      unix_seconds: 1790771696,
      unix_ms: 1790771696789,
      timezone: null,
      local_time: null,
      utc_offset: null,
    });
    const berlin = await callJson(connected.client, TOOL_NAMES.currentTime, {
      timezone: 'Europe/Berlin',
    });
    expect(berlin).toMatchObject({ local_time: '2026-09-30 14:34:56', utc_offset: 'GMT+02:00' });
    const zero = await callJson(connected.client, TOOL_NAMES.currentTime, { timezone: 'UTC' });
    expect(zero.utc_offset).toBe('GMT+00:00');
    const text = textOf(
      await callTool(connected.client, TOOL_NAMES.currentTime, { timezone: 'Asia/Tokyo' }),
    );
    expect(text).toContain('Local time in Asia/Tokyo: 2026-09-30 21:34:56 (GMT+09:00)');
  });

  it('rejects an unknown time zone with examples', async () => {
    connected = await connect({});
    const result = await callTool(connected.client, TOOL_NAMES.currentTime, {
      timezone: 'Mars/Olympus',
    });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('Europe/Berlin');
  });
});

describe('entity recorded signal weights', () => {
  const id = '33333333-3333-4333-8333-333333333333',
    domain = '11111111-1111-4111-8111-111111111111';
  const weights = [
    { name: 'proxy', weight: 30 },
    { name: 'ip_mismatch', weight: 45 },
    { name: 'os_mismatch', weight: 60 },
    { name: 'incognito', weight: 0 },
    { name: 'correction', weight: -15 },
  ];
  const card = {
    type: 'identification',
    id,
    domain_id: domain,
    domain: 'example.com',
    risk: { state: 'ok', band: 'dangerous', score: 60, as_of: '2026-10-30T12:00:00Z' },
    signals: { state: 'ok', items: ['proxy', 'ip_mismatch', 'os_mismatch'] },
  };
  it('reads API weights and returns the same pairs through Get and Explain', async () => {
    const fetch = async (input: any) => {
      const u = new URL(String(input));
      return new Response(JSON.stringify({ data: { ...card, scored_signals: weights } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    connected = await connect(FULL_ENV, { apiFetch: fetch });
    const found = await callJson(connected.client, TOOL_NAMES.getIdentification, {
      domain,
      identification_id: id,
      response_format: 'json',
    });
    expect(found.identification.scored_signals).toEqual(weights);
    const output = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      domain,
      identification_id: id,
      response_format: 'json',
    });
    expect(output.weights_available).toBe(true);
    expect(output.scored_signals).toEqual(weights);
    expect(output.risk_score).toBe(60);
    expect(output.signals.map((s: any) => ({ name: s.name, weight: s.weight }))).toEqual(weights);
  });
  it('uses recorded weights in Markdown without summing them or substituting catalog weights', async () => {
    connected = await connect({});
    const text = textOf(
      await callTool(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: { ...card, scored_signals: weights },
        response_format: 'markdown',
      }),
    );
    expect(text).toContain('60');
    expect(text).toContain('45');
    expect(text).not.toContain('Detailed signal weights are unavailable');
  });
  it('distinguishes unavailable from known empty weights and preserves unknown risk', async () => {
    connected = await connect({});
    for (const weights of [undefined, null]) {
      const out = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
        identification: { ...card, scored_signals: weights },
      });
      expect(out.weights_available).toBe(false);
    }
    const empty = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: { ...card, scored_signals: [] },
    });
    expect(empty.weights_available).toBe(true);
    expect(empty.signals).toEqual([]);
    const unknown = await callJson(connected.client, TOOL_NAMES.explainRiskScore, {
      identification: {
        ...card,
        risk: { state: 'unavailable', band: null, as_of: null },
        scored_signals: weights,
      },
    });
    expect(unknown.weights_available).toBe(false);
    expect(unknown.risk_score).toBeUndefined();
  });
});
