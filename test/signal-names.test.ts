import { createHmac } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { CURRENT_DETECTION_FLAG_KEYS } from '../src/catalog/detection-flags.js';
import { CONNECTION_TYPE_CATALOG, connectionTypeInfo } from '../src/catalog/connection-types.js';
import { canonicalSignalName, riskSignalInfo } from '../src/catalog/risk-signals.js';
import { entityView, entityMarkdown } from '../src/entity-history.js';
import originalEntity from './fixtures/review-portal-entity.json';
import { currentFlags } from '../src/current-contract.js';
import { buildExplanation, normalizeHistoryRow, parseIdentificationInput } from '../src/explain.js';
import { IdentificationOutputSchema, toIdentificationOutput } from '../src/identification.js';
import { RISK_SIGNALS_REFERENCE } from '../src/resources/index.js';
import { WEBHOOK_EVENT_SCHEMA } from '../src/resources/schemas.js';
import { TOOL_NAMES } from '../src/constants.js';
import { callJson, connect, fixture } from './helpers.js';

const aliases = [
  ['privacy_relay', 'private_relay', 'Privacy Relay'],
  ['stun_not_checked', 'network_check_incomplete', 'Network Check Incomplete'],
  ['ws_tcp_latency', 'latency_test', 'Latency test'],
] as const;

describe('canonical public signal names', () => {
  it.each(aliases)(
    'accepts %s while projecting %s in JSON and Markdown',
    async (legacy, name, label) => {
      const input = {
        risk_score: 30,
        signals: [{ name: legacy, weight: 30 }],
        detection_flags: { [legacy]: true },
      };
      const before = JSON.stringify(input);
      const { explanation, markdown } = buildExplanation(parseIdentificationInput(input));
      expect(explanation.signals[0]).toMatchObject({
        name,
        label,
        related_flag: name,
        in_catalog: true,
      });
      expect(explanation.detection_flags).toContainEqual(
        expect.objectContaining({ flag: name, label }),
      );
      expect(markdown).toContain(`\`${name}\``);
      expect(markdown).not.toContain(`\`${legacy}\``);
      expect(JSON.stringify(input)).toBe(before);
    },
  );

  it.each(aliases)('prefers canonical false over conflicting %s=true', (legacy, name) => {
    const flags = currentFlags({ detection_flags: { [legacy]: true, [name]: false } });
    expect(flags[name]).toBe(false);
    expect(flags).not.toHaveProperty(legacy);
    expect(Object.keys(flags)).toHaveLength(20);
    expect(currentFlags({})[name]).toBeNull();
  });

  it.each(aliases)(
    'normalizes %s in identification outputs without changing raw input',
    async (legacy, name) => {
      const id = normalizeHistoryRow({
        score: 30,
        request_id: '00000000-0000-4000-8000-000000000042',
      });
      id.signals = [{ name: legacy, weight: 30, description: null }];
      id.raw = { detection_flags: { [legacy]: true } };
      const before = JSON.stringify(id);
      const output = toIdentificationOutput(id);
      expect(output.signals[0]?.name).toBe(name);
      expect(output.detection_flags[name]).toBe(true);
      expect(output.detection_flags).not.toHaveProperty(legacy);
      expect(IdentificationOutputSchema.safeParse(output).success).toBe(true);
      expect(JSON.stringify(id)).toBe(before);
    },
  );

  it('publishes only canonical renamed entries in the reference catalog', () => {
    for (const [legacy, name, label] of aliases) {
      expect(RISK_SIGNALS_REFERENCE.risk_signals).toContainEqual(
        expect.objectContaining({ slug: name, label }),
      );
      expect(RISK_SIGNALS_REFERENCE.risk_signals.some((s) => s.slug === legacy)).toBe(false);
      expect(RISK_SIGNALS_REFERENCE.detection_flags).toContainEqual(
        expect.objectContaining({ flag: name, label }),
      );
      expect(RISK_SIGNALS_REFERENCE.detection_flags.some((s) => String(s.flag) === legacy)).toBe(
        false,
      );
      expect(riskSignalInfo(legacy)?.slug).toBe(name);
    }
    expect(RISK_SIGNALS_REFERENCE.detection_flags).toHaveLength(20);
    expect(
      RISK_SIGNALS_REFERENCE.detection_flags.find((flag) => flag.flag === 'latency_test')?.scored,
    ).toBe(true);
    expect(canonicalSignalName('future_signal')).toBe('future_signal');
    expect(canonicalSignalName('toString')).toBe('toString');
    expect(riskSignalInfo('future_signal')).toBeUndefined();
  });

  it('explains current relay connections and retains the legacy connection value', () => {
    expect(CONNECTION_TYPE_CATALOG).toContainEqual(
      expect.objectContaining({ value: 'private_relay', label: 'Privacy Relay' }),
    );
    expect(connectionTypeInfo('private_relay').label).toBe('Privacy Relay');
    expect(connectionTypeInfo('privacy_relay')).toMatchObject({
      value: 'privacy_relay',
      label: 'Privacy Relay',
    });
  });

  it('keeps an explicit negative Banned IP flag even with the 999 marker', () => {
    expect(currentFlags({ risk_score: 999 }).banned_ip).toBe(true);
    expect(currentFlags({ risk_score: 999, detection_flags: { banned_ip: false } }).banned_ip).toBe(
      false,
    );
    expect(currentFlags({ is_banned_ip: true }).banned_ip).toBeNull();
    expect(currentFlags({ is_rate_limited: false }).banned_ip).toBeNull();
  });

  it('validates current 20-flag wire payloads and preserves signed bytes', async () => {
    const event = fixture<any>('webhook-identification-scored.json');
    event.schema_version = '2026-10-13';
    event.event_id = '00000000-0000-4000-8000-000000000043';
    event.data.hre = Object.fromEntries(
      ['account_sharing', 'account_takeover', 'impossible_travel'].map((name) => [
        name,
        { status: 'not_evaluated', level: null, reason: 'no_history', cluster_id: null },
      ]),
    );
    event.data.identification_id = event.data.request_id;
    delete event.data.request_id;
    event.data.detection_flags = Object.fromEntries(
      CURRENT_DETECTION_FLAG_KEYS.map((name) => [name, false]),
    );
    event.data.detection_flags.banned_ip = true;
    event.data.risk_score = 999;
    event.data.signals = [{ name: 'banned_ip', weight: 999 }];
    const validate = new Ajv2020({ strict: false, validateFormats: false }).compile(
      WEBHOOK_EVENT_SCHEMA,
    );
    expect(validate(event), JSON.stringify(validate.errors)).toBe(true);
    const secret = 'whsec_signal_names_test';
    const payload = JSON.stringify(event) + '\n';
    const signature_header = 'sha256=' + createHmac('sha256', secret).update(payload).digest('hex');
    const connected = await connect({});
    try {
      const result = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload,
        signature_header,
        secret,
      });
      expect(result.valid).toBe(true);
      expect(result.event.risk_band).toBe('banned_ip');
      const changed = await callJson(connected.client, TOOL_NAMES.verifyWebhookSignature, {
        payload: payload.trimEnd(),
        signature_header,
        secret,
      });
      expect(changed.valid).toBe(false);
    } finally {
      await connected.close();
    }
  });
});

describe('entity signal names', () => {
  it('projects legacy entity signals as canonical names without changing the source card', () => {
    const source = {
      ...originalEntity,
      signals: {
        state: 'ok',
        items: [
          'privacy_relay',
          'stun_not_checked',
          'ws_tcp_latency',
          'banned_ip',
          'future_signal',
        ],
      },
    };
    const before = JSON.stringify(source);
    const entity = entityView(source);
    expect(entity.signals.items).toEqual([
      'private_relay',
      'network_check_incomplete',
      'latency_test',
      'banned_ip',
      'future_signal',
    ]);
    expect(entityMarkdown(entity)).toContain('`private_relay`');
    expect(entityMarkdown(entity)).toContain('`banned_ip`');
    expect(entityMarkdown(entity)).not.toContain('`rate_limited`');
    expect(JSON.stringify(source)).toBe(before);
  });
});
