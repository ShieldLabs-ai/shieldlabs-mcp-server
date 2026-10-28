import { afterEach, describe, expect, it } from 'vitest';
import { CURRENT_DETECTION_FLAG_KEYS } from '../src/catalog/detection-flags.js';
import { currentFlags } from '../src/current-contract.js';
import { TOOL_NAMES } from '../src/constants.js';
import { callTool, connect, fixture, FULL_ENV, type Connected, textOf } from './helpers.js';

let connected: Connected | undefined;
afterEach(async () => {
  await connected?.close();
  connected = undefined;
});
describe('current public History without diagnostics', () => {
  it('serves all four investigation tools with exactly 20 current flags and no invented weights', async () => {
    const row = fixture<Record<string, unknown>>('history-current-contract.json');
    connected = await connect(FULL_ENV, {
      apiFetch: async () => Response.json({ data: [row], total: 1 }),
    });
    for (const [name, args] of [
      [TOOL_NAMES.getIdentification, { request_id: row.identification_id }],
      [TOOL_NAMES.searchHistory, { type: 'user_hid', value: row.user_hid }],
      [TOOL_NAMES.explainRiskScore, { request_id: row.identification_id }],
      [TOOL_NAMES.summarizeEntity, { type: 'user_hid', value: row.user_hid, max_items: 1 }],
    ] as const) {
      const reply = await callTool(connected.client, name, { ...args, response_format: 'json' });
      expect(reply.isError, textOf(reply)).not.toBe(true);
      if (name === TOOL_NAMES.getIdentification) {
        const value = (reply.structuredContent as any).identification;
        expect(value.request_id).toBe(row.identification_id);
        expect(Object.keys(value.detection_flags).sort()).toEqual(
          [...CURRENT_DETECTION_FLAG_KEYS].sort(),
        );
        expect(value.detection_flags).toMatchObject({
          ip_mismatch: true,
          os_mismatch: true,
          device_spoofing: false,
          network_check_incomplete: false,
        });
        expect(value.signals).toEqual([]);
        expect(value.risk_score).toBe(row.score);
      }
    }
  });
  it('keeps OS detector two separate from device spoofing and does not turn browser VPN into proxy', () => {
    expect(currentFlags({ is_os_mismatch: false, is_os_mismatch2: true })).toMatchObject({
      os_mismatch: true,
      device_spoofing: null,
    });
    expect(
      currentFlags({ connection_type: 'browser_vpn_proxy', is_vpn: false, is_proxy: false }),
    ).toMatchObject({ vpn: true, proxy: false });
  });
});
