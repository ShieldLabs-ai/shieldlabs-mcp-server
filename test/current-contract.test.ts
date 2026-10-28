import { describe, expect, it } from 'vitest';
import { CURRENT_DETECTION_FLAG_KEYS } from '../src/catalog/detection-flags.js';
import { CHARACTER_LIMIT } from '../src/constants.js';
import { currentFlags, currentMetadata } from '../src/current-contract.js';
import { buildExplanation, fromIdentification, normalizeHistoryRow } from '../src/explain.js';
import { IdentificationOutputSchema, toIdentificationOutput } from '../src/identification.js';
import { summarize } from '../src/summarize.js';
import { fixture } from './helpers.js';

const hre = {
  account_sharing: { status: 'evaluated', level: 'medium', reason: 'device_count', devices: 4 },
  account_takeover: { status: 'not_evaluated', level: null, reason: 'no_history' },
  impossible_travel: { status: 'not_applicable', level: null, reason: 'anonymous' },
};
const identity = {
  availability: 'available',
  claims: [null, { provider_name: 'Claimed Provider', agent_name: 'Claimed Agent' }],
  verified: [
    null,
    { subject: 'provider', value_id: 'provider-id', evidence_ids: [null, 'proof-1'] },
  ],
  evidence: [{ id: 'proof-1', method: 'dns', covered_attributes: ['provider', null] }],
  unknown_future_field: 'secret-must-not-leak',
};

describe('entity history cards', () => {
  const id = '00000000-0000-4000-8000-000000000042';

  it('keeps the card id and a score of 30', async () => {
    const output = toIdentificationOutput(
      await normalizeHistoryRow({
        type: 'identification',
        id,
        risk: { state: 'ok', band: 'suspicious', score: 30 },
        signals: { state: 'unavailable', items: [] },
      }),
    );
    expect(output.identification_id).toBe(id);
    expect(output.risk_score).toBe(30);
    expect(output.risk_band).toBe('suspicious');
    expect(IdentificationOutputSchema.safeParse(output).success).toBe(true);
  });

  it('keeps an unavailable risk null instead of score 0', async () => {
    const output = toIdentificationOutput(
      await normalizeHistoryRow({
        type: 'identification',
        id,
        risk: { state: 'unavailable' },
        signals: { state: 'unavailable', items: [] },
      }),
    );
    expect(output.identification_id).toBe(id);
    expect(output.risk_score).toBeNull();
    expect(output.risk_band).toBeNull();
    const normalized = await normalizeHistoryRow({
      type: 'identification',
      id,
      risk: { state: 'unavailable' },
    });
    expect(() => fromIdentification(normalized)).toThrow(/unavailable/);
  });
});

describe('current public contract projection', () => {
  it('covers the canonical twenty flags and never defaults missing new signals to false', () => {
    expect(CURRENT_DETECTION_FLAG_KEYS).toHaveLength(20);
    const flags = currentFlags({
      detection_flags: { ai_bot: true, ai_browser: false, vpn: 'false' },
    });
    expect(flags).toMatchObject({ ai_bot: true, ai_browser: false, vpn: null, latency_test: null });
    expect(Object.keys(flags)).toHaveLength(20);
  });

  it('accepts legacy aliases, History fields and the 999 marker', () => {
    expect(currentFlags({ is_ai_bot: true, is_os_mismatch2: true, score: 999 })).toMatchObject({
      ai_bot: true,
      device_spoofing: null,
      os_mismatch: true,
      banned_ip: true,
    });
    expect(
      currentFlags({ detection_flags: { privacy_relay: true, stun_not_checked: false } }),
    ).toMatchObject({ private_relay: true, network_check_incomplete: false });
  });

  it('preserves nullable identity values and separates claims from scoped proof', () => {
    const result = currentMetadata(
      { hre, client_identity: identity },
      { truncated: [], escaped: [] },
    );
    expect(result.client_identity?.claims?.[0]).toBeNull();
    expect(result.client_identity?.verified?.[1]?.subject).toBe('provider');
    expect(result.hre?.account_takeover?.status).toBe('not_evaluated');
    expect(JSON.stringify(result)).not.toContain('secret-must-not-leak');
    expect(result.contract_warnings).toBeUndefined();
  });

  it('keeps missing, null and invalid metadata distinct and does not expose diagnostic bodies', () => {
    expect(currentMetadata({}, { truncated: [], escaped: [] })).toEqual({});
    expect(currentMetadata({ client_identity: null }, { truncated: [], escaped: [] })).toEqual({
      client_identity: null,
    });
    const invalid = currentMetadata(
      { hre: { account_sharing: 'sec_diagnostic' } },
      { truncated: [], escaped: [] },
    );
    expect(invalid.hre).toBeNull();
    expect(invalid.contract_warnings?.[0]).toContain('unavailable');
    expect(JSON.stringify(invalid)).not.toContain('sec_diagnostic');
  });

  it('marks shortened or escaped proof as incomplete even when used by explanations', () => {
    const changes = { truncated: [] as string[], escaped: [] as string[] };
    const projected = currentMetadata(
      {
        client_identity: {
          claims: Array.from({ length: 20 }, () => ({ agent_name: 'a'.repeat(500) + '\u0000' })),
        },
      },
      changes,
    );
    expect(projected.client_identity?.claims).toHaveLength(5);
    expect(changes.truncated.length).toBeGreaterThan(0);
    expect(projected.contract_warnings?.join(' ')).toContain('incomplete');
    expect(projected.contract_warnings?.join(' ')).toContain('escaped');
  });

  it('preserves current identifiers, HRE and identity through normalization, explanation and summary', async () => {
    const row = {
      ...fixture('history-page.json').data[0],
      hre,
      client_identity: identity,
      is_ai_bot: true,
    };
    const normalized = await normalizeHistoryRow(row);
    const output = toIdentificationOutput(normalized);
    expect(IdentificationOutputSchema.safeParse(output).success).toBe(true);
    expect(output.detection_flags.ai_bot).toBe(true);
    expect(output.hre).toEqual(hre);
    const explanation = buildExplanation(fromIdentification(normalized));
    expect(explanation.markdown).toContain('not_evaluated');
    expect(explanation.markdown).toContain('Claimed Agent');
    expect(explanation.markdown).toContain('does not prove an agent');
    const result = summarize([output, { ...output, client_identity: null }]);
    expect(result.high_risk_events?.snapshots_reported).toBe(2);
    expect(result.client_identity).toMatchObject({
      reported: 2,
      unavailable: 1,
      verified: [{ subject: 'provider', value_id: 'provider-id', count: 1 }],
    });
    expect(result.flags_unavailable).toEqual(
      expect.arrayContaining([{ flag: 'ai_browser', count: 2 }]),
    );
  });

  it('uses identification_id when the legacy SDK request_id is absent', async () => {
    const row = { ...fixture('history-page.json').data[0] };
    delete row.request_id;
    row.identification_id = '33333333-3333-4333-8333-333333333333';
    const normalized = await normalizeHistoryRow(row);
    expect(toIdentificationOutput(normalized).identification_id).toBe(row.identification_id);
    expect(fromIdentification(normalized).identification_id).toBe(row.identification_id);
  });

  it('keeps adversarial metadata within response limits for both renderings', async () => {
    const long = '\\'.repeat(300);
    const raw = {
      ...fixture('history-page.json').data[0],
      hre,
      client_identity: {
        claims: Array.from({ length: 25 }, () => ({
          provider_name: long,
          agent_name: long,
          purpose: long,
        })),
        evidence: Array.from({ length: 25 }, () => ({
          id: long,
          method: long,
          source_id: long,
          checked_at: long,
          covered_components: Array(25).fill(long),
          covered_attributes: Array(25).fill(long),
        })),
      },
    };
    const normalized = await normalizeHistoryRow(raw);
    const result = buildExplanation(fromIdentification(normalized));
    expect(result.markdown.length).toBeLessThanOrEqual(CHARACTER_LIMIT);
    expect(JSON.stringify(result.explanation).length).toBeLessThanOrEqual(CHARACTER_LIMIT);
    expect(result.explanation.contract_warnings?.join(' ')).toContain('incomplete');
  });
});
