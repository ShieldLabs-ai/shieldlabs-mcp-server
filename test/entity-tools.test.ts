import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { describe, expect, it } from 'vitest';
import { handlePublicRequest } from '../src/public/handler.js';
import { TokenCache } from '../src/public/token.js';
import original from './fixtures/review-portal-entity.json';
import { FULL_ENV, connect as stdio } from './helpers.js';
import {
  DOMAIN_ID,
  HOSTED_TOKEN,
  operationsBackend,
  RAW_SECRET,
  REQUEST_ID,
  SIGNING_SECRET,
  UPSTREAM,
} from './operations-backend.js';
const card = { ...original, id: REQUEST_ID, domain_id: DOMAIN_ID };
type Reply = { status?: number; body: unknown };
async function run(
  mode: 'stdio' | 'hosted',
  reply: Reply,
  body: (client: Client, calls: string[], set: (r: Reply) => void) => Promise<void>,
) {
  const calls: string[] = [];
  let response = reply;
  let client: Client;
  let close: () => Promise<void>;
  if (mode === 'stdio') {
    const connection = await stdio(FULL_ENV, {
      maxRetries: 0,
      historyBudget: { maxConcurrent: 2, perSecond: 1000 },
      apiFetch: async (url) => {
        calls.push(String(url));
        return Response.json(response.body, { status: response.status ?? 200 });
      },
    });
    client = connection.client;
    close = () => connection.close();
  } else {
    const backend = operationsBackend();
    const config = {
      portalUrl: UPSTREAM,
      authIssuer: UPSTREAM,
      publicOrigin: 'https://dev.mcp.shieldlabs.ai',
      gatewayKey: { kid: 'k1', secret: SIGNING_SECRET },
    };
    const deps = {
      cache: new TokenCache(),
      fetch: async (
        url: Parameters<typeof backend.fetch>[0],
        init: Parameters<typeof backend.fetch>[1],
      ) => {
        if (String(url).includes('/history/')) {
          calls.push(String(url));
          backend.force({ status: response.status ?? 200, body: response.body });
        }
        return backend.fetch(url, init);
      },
    };
    client = new Client({ name: 'entity-client-contract', version: '1' });
    await client.connect(
      new StreamableHTTPClientTransport(new URL('https://dev.mcp.shieldlabs.ai/mcp'), {
        fetch: (input, init) => handlePublicRequest(new Request(input, init), config, deps),
        requestInit: { headers: { Authorization: `Bearer ${HOSTED_TOKEN}` } },
      }),
    );
    close = () => client.close();
  }
  try {
    await body(client, calls, (r) => {
      response = r;
    });
  } finally {
    await close();
  }
}
const get = {
  name: 'shieldlabs_get_identification',
  arguments: {
    domain: DOMAIN_ID,
    identification_id: REQUEST_ID,
    wait: false,
    response_format: 'json',
  },
};
for (const mode of ['stdio', 'hosted'] as const)
  describe(`${mode} current entity History`, () => {
    for (const score of [0, 30, 60, 100])
      it(`keeps score ${score} and the returned ID`, async () =>
        run(
          mode,
          {
            body: {
              data: {
                ...card,
                risk: {
                  state: 'ok',
                  band: score < 30 ? 'trusted' : score < 60 ? 'suspicious' : 'dangerous',
                  score,
                  as_of: card.risk.as_of,
                },
              },
            },
          },
          async (client, calls) => {
            const r = await client.callTool(get);
            expect(r.isError, JSON.stringify(r.content)).not.toBe(true);
            expect(r.structuredContent).toMatchObject({
              identification: { id: REQUEST_ID, risk: { score } },
            });
            expect(calls[0]).toContain(
              `/domains/${DOMAIN_ID}/history/identifications/${REQUEST_ID}`,
            );
          },
        ));
    it('keeps unavailable risk and nullable strings', async () =>
      run(
        mode,
        { body: { data: { ...card, risk: { state: 'unavailable', band: null, as_of: null } } } },
        async (client) => {
          const r = await client.callTool(get);
          expect(r.structuredContent).toMatchObject({
            identification: { risk: { state: 'unavailable', band: null }, browser: null },
          });
          expect(JSON.stringify(r.structuredContent)).not.toContain('"score":0');
        },
      ));
    it('reads detail cards with explicit null objects and public device identity', async () =>
      run(
        mode,
        {
          body: {
            data: {
              ...card,
              traffic: null,
              identity_risk: null,
              high_risk_events: null,
              device_identity: { state: 'available', hardware_id: REQUEST_ID },
            },
          },
        },
        async (client) => {
          const r = await client.callTool(get);
          expect(r.isError, JSON.stringify(r)).not.toBe(true);
          expect(r.structuredContent).toMatchObject({
            identification: {
              id: REQUEST_ID,
              identity_risk: null,
              high_risk_events: null,
              device_identity: { hardware_id: REQUEST_ID },
            },
          });
        },
      ));
    it('does not require the omitted self-count on an aggregate card', async () =>
      run(
        mode,
        {
          body: {
            data: {
              ...card,
              type: 'visitor',
              id: REQUEST_ID,
              related_counts: { devices: 1, users: 1, public_ips: 1, cookies: 1, sessions: 1 },
              band_split: null,
              device_identity: null,
            },
          },
        },
        async (client) => {
          const r = await client.callTool({
            name: 'shieldlabs_get_history',
            arguments: {
              domain: DOMAIN_ID,
              resource: 'visitor',
              resource_id: REQUEST_ID,
              response_format: 'json',
            },
          });
          expect(r.isError, JSON.stringify(r)).not.toBe(true);
          expect(r.structuredContent).toHaveProperty('entity.related_counts.devices', 1);
          expect(r.structuredContent).not.toHaveProperty('entity.related_counts.visitors');
        },
      ));
    for (const field of [
      'request_id',
      'offset',
      'score_from',
      'max_items',
      'filter',
      'include_total',
    ])
      it(`rejects retired input ${field} before IO`, async () =>
        run(mode, { body: { data: [card], next_page_token: null } }, async (client, calls) => {
          const r = await client.callTool({
            name: 'shieldlabs_list_history',
            arguments: {
              domain: DOMAIN_ID,
              resource: 'identifications',
              [field]:
                field === 'request_id'
                  ? REQUEST_ID
                  : field === 'filter'
                    ? { identification: {} }
                    : 1,
            },
          });
          expect(r.isError).toBe(true);
          expect(calls).toHaveLength(0);
        }));
    for (const input of [
      { rate_limited: true },
      { sort: 'created_at' },
      { chips: [{ dimension: 'browser', value: 'Chrome' }] },
      { hre_min_accounts: 2 },
      { hre_min_accounts: 100 },
      { hre_min_devices: 3 },
      { hre_min_devices: 100 },
      { device_id_source: 'legacy' },
      { ids: ['different-account'] },
      { type: 'identifications' },
    ])
      it(`rejects filters unsupported by the current reader ${JSON.stringify(input)} before IO`, async () =>
        run(mode, { body: { data: [card], next_page_token: null } }, async (client, calls) => {
          const result = await client.callTool({
            name: 'shieldlabs_list_history',
            arguments: { domain: DOMAIN_ID, resource: 'identifications', ...input },
          });
          expect(result.isError).toBe(true);
          expect(calls).toHaveLength(0);
        }));
    for (const domain of [undefined, 'example.com', 'all'])
      it(`requires a concrete domain UUID (${domain})`, async () =>
        run(mode, { body: { data: card } }, async (client, calls) => {
          const r = await client.callTool({ ...get, arguments: { ...get.arguments, domain } });
          expect(r.isError).toBe(true);
          expect(calls).toHaveLength(0);
        }));
    it('keeps opaque cursors, filter and window on subsequent requests', async () =>
      run(
        mode,
        { body: { data: [card], next_page_token: 'opaque+/=', total: 2 } },
        async (client, calls) => {
          const args = {
            domain: DOMAIN_ID,
            resource: 'identifications' as const,
            limit: 1,
            from: '2026-10-27T00:00:00Z',
            to: '2026-10-28T00:00:00Z',
            risk_bands: ['suspicious', 'dangerous'],
            hre_min_accounts: 3,
            hre_min_devices: 4,
            is_vpn: true,
            banned_ip: false,
            response_format: 'json' as const,
          };
          const a = await client.callTool({ name: 'shieldlabs_list_history', arguments: args });
          expect(a.isError).not.toBe(true);
          expect(a.structuredContent).toMatchObject({ next_page_token: 'opaque+/=' });
          expect(a.structuredContent).not.toHaveProperty('total');
          await client.callTool({
            name: 'shieldlabs_list_history',
            arguments: { ...args, page_token: 'opaque+/=' },
          });
          const url = new URL(calls[1]!);
          expect(url.searchParams.get('page_token')).toBe('opaque+/=');
          expect(url.searchParams.getAll('risk_bands')).toEqual(args.risk_bands);
          expect(url.searchParams.get('hre_min_accounts')).toBe('3');
          expect(url.searchParams.get('is_vpn')).toBe('true');
          expect(url.searchParams.get('banned_ip')).toBe('false');
          expect(url.searchParams.has('rate_limited')).toBe(false);
          expect(url.searchParams.has('filter')).toBe(false);
          expect(url.searchParams.get('from')).toBe(args.from);
        },
      ));
    it('forwards flat user filters without adding sort or a total', async () =>
      run(mode, { body: { data: [], next_page_token: null, total: 0 } }, async (client, calls) => {
        const r = await client.callTool({
          name: 'shieldlabs_list_history',
          arguments: {
            domain: DOMAIN_ID,
            resource: 'user',
            risk_bands: ['dangerous'],
            hre_min_accounts: 9,
            hre_min_devices: 9,
            ids: 'first',
            response_format: 'json',
          },
        });
        expect(r.isError, JSON.stringify(r)).not.toBe(true);
        expect(r.structuredContent).not.toHaveProperty('total');
        const url = new URL(calls[0]!);
        expect(url.pathname).toContain(`/domains/${DOMAIN_ID}/history/user`);
        expect(url.searchParams.getAll('risk_bands')).toEqual(['dangerous']);
        expect(url.searchParams.get('hre_min_accounts')).toBe('9');
        expect(url.searchParams.getAll('ids')).toEqual(['first']);
        expect(url.searchParams.has('include_total')).toBe(false);
        expect(url.searchParams.has('filter')).toBe(false);
        expect(url.searchParams.has('sort')).toBe(false);
      }));
    it('rejects more than one user id before IO', async () =>
      run(mode, { body: { data: [], next_page_token: null } }, async (client, calls) => {
        const result = await client.callTool({
          name: 'shieldlabs_list_history',
          arguments: { domain: DOMAIN_ID, resource: 'user', ids: ['first', 'second'] },
        });
        expect(result.isError).toBe(true);
        expect(calls).toHaveLength(0);
      }));
    it('does not invent a total for an empty page', async () =>
      run(mode, { body: { data: [], next_page_token: null } }, async (client) => {
        const r = await client.callTool({
          name: 'shieldlabs_list_history',
          arguments: { domain: DOMAIN_ID, resource: 'user', response_format: 'json' },
        });
        expect(r.isError).not.toBe(true);
        expect(r.structuredContent).not.toHaveProperty('total');
        expect(r.structuredContent).toMatchObject({ data: [], next_page_token: null });
      }));
    for (const type of ['user', 'visitor', 'device', 'ip'])
      it(`preserves ${type} aggregate and HRE availability with one GET`, async () => {
        const id = type === 'user' ? 'Exact+User %' : type === 'ip' ? '203.0.113.1' : REQUEST_ID;
        await run(
          mode,
          {
            body: {
              data: {
                ...card,
                type,
                id,
                identifications: 5,
                high_risk_events: { state: 'not_applicable', as_of: null, items: [] },
              },
            },
          },
          async (client, calls) => {
            const r = await client.callTool({
              name: 'shieldlabs_get_history',
              arguments: {
                domain: DOMAIN_ID,
                resource: type,
                resource_id: id,
                response_format: 'json',
              },
            });
            expect(r.isError, JSON.stringify(r.content)).not.toBe(true);
            expect(r.structuredContent).toMatchObject({
              entity: { id, identifications: 5, high_risk_events: { state: 'not_applicable' } },
            });
            expect(r.structuredContent).not.toHaveProperty('window');
            expect(calls).toHaveLength(1);
            expect(calls[0]).toContain(encodeURIComponent(id));
          },
        );
      });
    for (const replacement of [
      { id: '44444444-4444-4444-8444-444444444444' },
      { domain_id: '99999999-9999-4999-8999-999999999999' },
      { type: 'user' },
      { risk: { state: 'ok', band: 'trusted', score: 999, as_of: card.risk.as_of } },
      { risk: { state: 'unavailable', band: null, as_of: null, score: 0 } },
    ])
      it(`rejects an invalid or out-of-scope card ${JSON.stringify(replacement)}`, async () =>
        run(mode, { body: { data: { ...card, ...replacement } } }, async (client) => {
          expect((await client.callTool(get)).isError).toBe(true);
        }));
    it('escapes controls and masks key-shaped text in JSON and Markdown', async () =>
      run(
        mode,
        { body: { data: { ...card, user_hid: `line\n## injection\u202e ${RAW_SECRET}` } } },
        async (client) => {
          for (const response_format of ['json', 'markdown']) {
            const r = await client.callTool({
              ...get,
              arguments: { ...get.arguments, response_format },
            });
            expect(r.isError).not.toBe(true);
            const text = JSON.stringify(r);
            expect(text).not.toContain(RAW_SECRET);
            expect(text).not.toContain('injection\u202e');
            expect(text).toContain('\\u000a');
          }
        },
      ));
    it('drops unexpected private and diagnostic fields', async () =>
      run(
        mode,
        {
          body: {
            data: {
              ...card,
              debug: { password: 'private-db' },
              internal_owner: 'private-owner',
              score_details: 'private-trace',
            },
          },
        },
        async (client) => {
          const r = await client.callTool(get);
          expect(r.isError).not.toBe(true);
          expect(JSON.stringify(r)).not.toContain('private-');
        },
      ));
    it('bounds display strings without losing IDs or cursors', async () =>
      run(mode, { body: { data: { ...card, user_hid: 'u'.repeat(100000) } } }, async (client) => {
        const r = await client.callTool(get);
        expect(r.isError).not.toBe(true);
        expect(JSON.stringify(r).length).toBeLessThan(20000);
        expect(r.structuredContent).toMatchObject({ identification: { id: REQUEST_ID } });
      }));
    it('refuses oversized pages instead of skipping records behind a cursor', async () =>
      run(
        mode,
        {
          body: {
            data: Array.from({ length: 100 }, (_, i) => ({
              ...card,
              id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
              user_hid: 'u'.repeat(1000),
            })),
            next_page_token: 'next',
          },
        },
        async (client) => {
          const r = await client.callTool({
            name: 'shieldlabs_list_history',
            arguments: { domain: DOMAIN_ID, resource: 'identifications', limit: 100 },
          });
          expect(r.isError).toBe(true);
        },
      ));
    it('explains missing weights and preserves the risk state', async () =>
      run(mode, { body: { data: card } }, async (client) => {
        const r = await client.callTool({
          name: 'shieldlabs_explain_risk_score',
          arguments: {
            domain: DOMAIN_ID,
            identification_id: REQUEST_ID,
            response_format: 'markdown',
          },
        });
        expect(r.isError).not.toBe(true);
        expect(JSON.stringify(r.content)).toContain('Detailed signal weights are unavailable');
        expect(r.structuredContent).toMatchObject({
          risk: { score: 30 },
          weights_available: false,
        });
      }));
    it('returns a 404 once with wait=false, without an empty-success result', async () =>
      run(mode, { status: 404, body: { error: { code: 'not_found' } } }, async (client, calls) => {
        expect((await client.callTool(get)).isError).toBe(true);
        expect(calls).toHaveLength(1);
      }));
    it('resources use the domain-scoped API and the same states', async () =>
      run(mode, { body: { data: card } }, async (client, calls) => {
        const r = await client.readResource({
          uri: `shieldlabs://domains/${DOMAIN_ID}/identifications/${REQUEST_ID}`,
        });
        expect(JSON.stringify(r)).toContain(REQUEST_ID);
        expect(calls[0]).toContain(`/domains/${DOMAIN_ID}/history/identifications/${REQUEST_ID}`);
      }));
  });
