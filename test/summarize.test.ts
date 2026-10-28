import { NIL_UUID } from '@shieldlabs-ai/node';
import { afterEach, describe, expect, it } from 'vitest';
import { toIdentificationOutput } from '../src/identification.js';
import { summarize } from '../src/summarize.js';
import { mockRows, type Connected } from './helpers.js';

let connected: Connected | undefined;

afterEach(async () => {
  await connected?.close();
  connected = undefined;
});

const rows = mockRows();

describe('summarize()', () => {
  it('skips the all-zero IDs, sentinel User HIDs and unparsable timestamps', () => {
    const base = toIdentificationOutput({
      identification_id: 'r1',
      visitor_id: NIL_UUID,
      device_id: NIL_UUID,
      session_id: NIL_UUID,
      cookie_id: NIL_UUID,
      user_hid: 'fail',
      domain: 'example.com',
      public_ip: { ip: '', country: '' },
      local_ip: { ip: '', country: '' },
      connection_type: '',
      os: 'Unknown',
      browser: 'Unknown',
      device_type: 'unknown',
      traffic_source: {
        channel: '',
        referrer_domain: '',
        landing_url: '',
        click_id_type: '',
        utm_source: '',
        utm_medium: '',
        utm_campaign: '',
        utm_content: '',
        utm_term: '',
      },
      risk_score: 40,
      signals: [
        { name: 'vpn', weight: 15, description: null },
        { name: 'vpn', weight: 15, description: null },
      ],
      detection_flags: Object.fromEntries(
        [
          'vpn',
          'privacy_relay',
          'browser_vpn_proxy',
          'tor',
          'proxy',
          'datacenter_ip',
          'abuser',
          'os_mismatch',
          'os_not_detected',
          'timezone_mismatch',
          'anti_detect_browser',
          'browser_automation',
          'ip_mismatch',
          'incognito',
          'search_bot',
          'suspicious_paid_click',
          'javascript_disabled',
          'stun_not_checked',
          'check_incomplete',
        ].map((flag) => [flag, false]),
      ) as any,
      observed_at: 'not a date',
      source: 'history',
      raw: {},
    });
    const summary = summarize([
      base,
      {
        ...base,
        identification_id: 'r2',
        user_hid: null,
        observed_at: null,
        risk_score: 10,
        risk_band: 'trusted',
      },
    ]);
    expect(summary.devices.distinct).toBe(0);
    expect(summary.visitors.distinct).toBe(0);
    expect(summary.users.distinct).toBe(0);
    expect(summary.identifications_without_account).toBe(2);
    expect(summary.identifications_without_device_signals).toBe(2);
    expect(summary.first_observed_at).toBeNull();
    expect(summary.signals_seen).toEqual([{ name: 'vpn', count: 2 }]);
    expect(summary.risk).toMatchObject({
      worst_band: 'suspicious',
      max_risk_score: 40,
      average_risk_score: 25,
    });
    expect(summary.connection_types.distinct).toBe(0);
  });

  it('lists at most ten values per dimension, most frequent first', () => {
    const items = rows.slice(0, 60).map((row) =>
      toIdentificationOutput({
        ...(row as any),
        identification_id: row.request_id,
        public_ip: { ip: row.ip, country: row.country },
        local_ip: { ip: '', country: '' },
        traffic_source: {
          channel: '',
          referrer_domain: '',
          landing_url: '',
          click_id_type: '',
          utm_source: '',
          utm_medium: '',
          utm_campaign: '',
          utm_content: '',
          utm_term: '',
        },
        risk_score: row.score,
        signals: [],
        detection_flags: {} as any,
        observed_at: null,
        source: 'history',
        raw: {},
      }),
    );
    const summary = summarize(items);
    expect(summary.ips.top.length).toBeLessThanOrEqual(10);
    const counts = summary.ips.top.map((entry) => entry.count);
    expect([...counts].sort((a, b) => b - a)).toEqual(counts);
  });
});
