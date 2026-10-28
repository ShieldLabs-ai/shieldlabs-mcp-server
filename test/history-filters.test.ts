import type { FetchLike } from '@shieldlabs-ai/node';
import { afterEach, describe, expect, it } from 'vitest';
import { HistoryFilterShape, HISTORY_FLAG_PARAMS } from '../src/history-filters.js';
import { TOOL_NAMES } from '../src/constants.js';
import { callTool, connect, fixture, FULL_ENV, textOf, type Connected } from './helpers.js';

const base = fixture('history-page.json').data[0];
const ids = Array.from(
  { length: 103 },
  (_, i) => `33333333-3333-4333-8333-${String(i).padStart(12, '0')}`,
);
const connections: Connected[] = [];
afterEach(async () => {
  await Promise.all(connections.splice(0).map((c) => c.close()));
});
async function start(fetch: FetchLike) {
  const c = await connect(FULL_ENV, { apiFetch: fetch, maxRetries: 2 });
  connections.push(c);
  return c.client;
}
function backend(rows = [base], status = 200) {
  const urls: URL[] = [];
  const fetch: FetchLike = async (address) => {
    const url = new URL(address);
    urls.push(url);
    if (status !== 200)
      return Response.json({ code: 'invalid_request', error: 'invalid history input' }, { status });
    const q = url.searchParams;
    const matches = rows.filter(
      (row) =>
        (q.get('score_from') === null || row.score >= Number(q.get('score_from'))) &&
        (q.get('score_to') === null || row.score <= Number(q.get('score_to'))) &&
        (q.get('is_vpn') === null || row.is_vpn === (q.get('is_vpn') === 'true')) &&
        (q.get('is_incognito') === null ||
          (row.is_search_bot ? false : row.is_incognito) === (q.get('is_incognito') === 'true')),
    );
    const offset = Number(q.get('offset') ?? 0),
      limit = Number(q.get('limit') ?? 20);
    return Response.json({ data: matches.slice(offset, offset + limit), total: matches.length });
  };
  return { urls, fetch };
}
const args = { type: 'user_hid', value: 'test-account', response_format: 'json' };

describe('History filters through local MCP and SDK HTTP transport', () => {
  it('matches every filter name in the pinned public OpenAPI contract', () => {
    const contract = fixture<{ query_parameters: string[] }>('history-filter-contract.json');
    expect(Object.keys(HistoryFilterShape).sort()).toEqual(contract.query_parameters);
  });

  it('advertises every optional filter and preserves every explicit false and zero', async () => {
    const b = backend([]);
    const c = await start(b.fetch);
    const tools = (await c.listTools()).tools;
    for (const name of [TOOL_NAMES.searchHistory, TOOL_NAMES.summarizeEntity]) {
      const tool = tools.find((t) => t.name === name)!;
      expect(Object.keys(tool.inputSchema.properties!)).toEqual(
        expect.arrayContaining([...HISTORY_FLAG_PARAMS, 'from', 'to', 'score_from', 'score_to']),
      );
      expect(tool.inputSchema.required).not.toContain('is_vpn');
      const filters = {
        from: '2026-10-01',
        to: '2026-10-28 23:59:59.123456789',
        score_from: 0,
        score_to: 999,
        ...Object.fromEntries(HISTORY_FLAG_PARAMS.map((flag, i) => [flag, i % 2 === 0])),
      };
      const reply = await callTool(c, name, { ...args, ...filters });
      expect(reply.isError).not.toBe(true);
      expect(reply.structuredContent).toMatchObject({ filters });
      const url = b.urls.at(-1)!;
      expect(url.pathname).toBe('/api/v1/history/user_hid/test-account');
      for (const [key, value] of Object.entries(filters))
        expect(url.searchParams.get(key), key).toBe(String(value));
    }
  });
  it('ANDs raw-score and boolean conditions upstream; filtered total, paging, marker and empty scope stay truthful', async () => {
    const rows = [
      {
        ...base,
        request_id: ids[0],
        identification_id: ids[0],
        score: 0,
        is_vpn: true,
        is_incognito: false,
      },
      {
        ...base,
        request_id: ids[1],
        identification_id: ids[1],
        score: 80,
        is_vpn: true,
        is_incognito: false,
      },
      {
        ...base,
        request_id: ids[2],
        identification_id: ids[2],
        score: 999,
        is_vpn: true,
        is_incognito: false,
      },
      {
        ...base,
        request_id: ids[3],
        identification_id: ids[3],
        score: 80,
        is_vpn: false,
        is_incognito: false,
      },
      {
        ...base,
        request_id: ids[4],
        identification_id: ids[4],
        score: 80,
        is_vpn: true,
        is_incognito: true,
        is_search_bot: true,
      },
    ];
    const b = backend(rows);
    const c = await start(b.fetch);
    const filters = { score_from: 60, score_to: 100, is_vpn: true, is_incognito: false };
    const first = await callTool(c, TOOL_NAMES.searchHistory, { ...args, ...filters, limit: 1 });
    expect(first.isError).not.toBe(true);
    expect(first.structuredContent).toMatchObject({ total: 2, count: 1, next_offset: 1, filters });
    const second = await callTool(c, TOOL_NAMES.searchHistory, { ...args, ...filters, offset: 1 });
    expect(second.structuredContent).toMatchObject({ total: 2, count: 1, has_more: false });
    const summary = await callTool(c, TOOL_NAMES.summarizeEntity, { ...args, ...filters });
    expect(summary.structuredContent).toMatchObject({
      window: { total_matching: 2, identifications_analyzed: 2, complete: true },
      summary: { risk: { max_risk_score: 80, rate_limit_markers: 0 } },
    });
    const marker = await callTool(c, TOOL_NAMES.searchHistory, {
      ...args,
      score_from: 999,
      score_to: 999,
    });
    expect(marker.structuredContent).toMatchObject({
      total: 1,
      identifications: [{ risk_score: 999, risk_band: 'rate_limited' }],
    });
    const empty = await callTool(c, TOOL_NAMES.summarizeEntity, {
      ...args,
      score_from: 1,
      score_to: 2,
      response_format: 'markdown',
    });
    expect(empty.structuredContent).toMatchObject({
      filters: { score_from: 1, score_to: 2 },
      window: { total_matching: 0 },
    });
    expect(textOf(empty)).toContain('Filters (AND');
    expect(textOf(empty)).toContain('nothing to summarize in this history window');
  });
  it('keeps all filters on every summary page and across simultaneous conflicting requests', async () => {
    const rows = ids.map((id) => ({
      ...base,
      request_id: id,
      identification_id: id,
      score: 80,
      is_vpn: true,
    }));
    const b = backend(rows);
    const c = await start(b.fetch);
    const filters = {
      from: '2026-10-01',
      to: '2026-10-28',
      score_from: 0,
      is_vpn: true,
      is_proxy: false,
    };
    const summary = await callTool(c, TOOL_NAMES.summarizeEntity, {
      ...args,
      ...filters,
      max_items: 103,
    });
    expect(summary.isError).not.toBe(true);
    expect(summary.structuredContent).toMatchObject({
      filters,
      window: { identifications_analyzed: 103, total_matching: 103, complete: true },
    });
    expect(b.urls.map((u) => u.searchParams.get('offset'))).toEqual(['0', '100']);
    for (const url of b.urls)
      for (const [key, value] of Object.entries(filters))
        expect(url.searchParams.get(key)).toBe(String(value));
    const replies = await Promise.all(
      [true, false].map((is_vpn) => callTool(c, TOOL_NAMES.searchHistory, { ...args, is_vpn })),
    );
    expect(replies[0]!.structuredContent).toMatchObject({ total: 103, filters: { is_vpn: true } });
    expect(replies[1]!.structuredContent).toMatchObject({ total: 0, filters: { is_vpn: false } });
    const plain = await callTool(c, TOOL_NAMES.searchHistory, args);
    expect(plain.structuredContent).not.toHaveProperty('filters');
    expect([...b.urls.at(-1)!.searchParams.keys()].sort()).toEqual(['limit', 'offset']);
  });
  it.each([
    { from: '2026-02-30' },
    { from: '2026-10-28T00:00:00Z' },
    { from: '2026-10-28 24:00:00' },
    { from: '' },
    { from: '2026-10-29', to: '2026-10-28' },
    { from: '2026-10-28 00:00:00.000000002', to: '2026-10-28 00:00:00.000000001' },
    { score_from: -1 },
    { score_to: 1000 },
    { score_to: 0.5 },
    { score_from: 2, score_to: 1 },
    { is_vpn: 'false' },
    { is_proxy: null },
    { is_abuser: true },
    { is_stun_not_checked: true },
    { is_datacenter: false },
    { is_suspicious_paid_click: false },
    { country: 'DE' },
  ])('rejects invalid/unsupported input before an HTTP call: %j', async (filters) => {
    const b = backend([]);
    const c = await start(b.fetch);
    for (const name of [TOOL_NAMES.searchHistory, TOOL_NAMES.summarizeEntity]) {
      const reply = await callTool(c, name, { ...args, ...filters });
      expect(reply.isError).toBe(true);
    }
    expect(b.urls).toHaveLength(0);
  });
  it('surfaces backend 400 without retry or an empty-success fallback', async () => {
    const b = backend([], 400);
    const c = await start(b.fetch);
    const reply = await callTool(c, TOOL_NAMES.searchHistory, { ...args, is_vpn: true });
    expect(reply.isError).toBe(true);
    expect(b.urls).toHaveLength(1);
  });
});
