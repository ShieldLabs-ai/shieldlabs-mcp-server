import { afterEach, describe, expect, it } from 'vitest';
import { currentFlags } from '../src/current-contract.js';
import { type Connected } from './helpers.js';

let connected: Connected | undefined;
afterEach(async () => {
  await connected?.close();
  connected = undefined;
});
describe('current public History without diagnostics', () => {
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
