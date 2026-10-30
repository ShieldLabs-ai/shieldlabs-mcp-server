import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { expect, it } from 'vitest';
import { entityView } from '../src/entity-history.js';
import { handlePublicRequest } from '../src/public/handler.js';
import { TokenCache } from '../src/public/token.js';
import card from './fixtures/review-portal-entity.json';
import {
  DOMAIN_ID,
  HOSTED_TOKEN,
  operationsBackend,
  REQUEST_ID,
  SIGNING_SECRET,
  UPSTREAM,
} from './operations-backend.js';
async function hosted(
  body: unknown,
  run: (client: Client, backend: ReturnType<typeof operationsBackend>) => Promise<void>,
) {
  const backend = operationsBackend();
  backend.force({ status: 200, body });
  const config = {
    portalUrl: UPSTREAM,
    authIssuer: UPSTREAM,
    publicOrigin: 'https://dev.mcp.shieldlabs.ai',
    gatewayKey: { kid: 'k1', secret: SIGNING_SECRET },
  };
  const deps = { cache: new TokenCache(), fetch: backend.fetch };
  const client = new Client({ name: 'real-entity-contract-review', version: '1' });
  await client.connect(
    new StreamableHTTPClientTransport(new URL('https://dev.mcp.shieldlabs.ai/mcp'), {
      fetch: (input, init) => handlePublicRequest(new Request(input, init), config, deps),
      requestInit: { headers: { Authorization: `Bearer ${HOSTED_TOKEN}` } },
    }),
  );
  try {
    await run(client, backend);
  } finally {
    await client.close();
  }
}
const get = {
  name: 'shieldlabs_get_identification',
  arguments: {
    identification_id: REQUEST_ID,
    domain: DOMAIN_ID,
    wait: false,
    response_format: 'json',
  },
};
it('preserves the real entity identification id', async () =>
  hosted({ data: card }, async (client) => {
    const r = await client.callTool(get);
    expect(r.isError, JSON.stringify(r)).not.toBe(true);
    expect(r.structuredContent).toMatchObject({ identification: { id: REQUEST_ID } });
  }));
it('preserves nested Score 30', async () =>
  hosted({ data: card }, async (client) => {
    const r = await client.callTool(get);
    expect(r.structuredContent).toMatchObject({
      identification: { risk: { state: 'ok', score: 30 } },
    });
  }));
it('does not invent zero for unavailable risk', async () =>
  hosted(
    { data: { ...card, risk: { state: 'unavailable', band: null, as_of: null } } },
    async (client) => {
      const r = await client.callTool(get);
      expect(r.structuredContent).toMatchObject({
        identification: { risk: { state: 'unavailable', band: null } },
      });
      expect(JSON.stringify(r.structuredContent)).not.toContain('"score":0');
    },
  ));
it('lists without a card id and forwards page tokens', async () =>
  hosted({ data: [card], next_page_token: 'next+/=' }, async (client, backend) => {
    const r = await client.callTool({
      name: 'shieldlabs_list_history',
      arguments: {
        resource: 'identifications',
        domain: DOMAIN_ID,
        limit: 1,
        page_token: 'previous+/=',
        response_format: 'json',
      },
    });
    expect(r.isError, JSON.stringify(r)).not.toBe(true);
    expect(r.structuredContent).toMatchObject({
      data: [{ id: REQUEST_ID }],
      next_page_token: 'next+/=',
    });
    expect(backend.calls.at(-1)!.path).toContain(`/history/identifications?`);
    expect(
      new URL('https://fixture' + backend.calls.at(-1)!.path).searchParams.get('page_token'),
    ).toBe('previous+/=');
  }));
it('preserves API aggregate count without fake history analysis', async () =>
  hosted({ data: { ...card, type: 'user', id: 'qa-user', identifications: 5 } }, async (client) => {
    const r = await client.callTool({
      name: 'shieldlabs_get_history',
      arguments: {
        resource: 'user',
        resource_id: 'qa-user',
        domain: DOMAIN_ID,
        response_format: 'json',
      },
    });
    expect(r.isError, JSON.stringify(r)).not.toBe(true);
    expect(r.structuredContent).toMatchObject({
      entity: { id: 'qa-user', identifications: 5 },
    });
    expect(r.structuredContent).not.toHaveProperty('window');
  }));
it('refuses legacy offset instead of ignoring it', async () =>
  hosted({ data: card }, async (client, backend) => {
    const count = backend.calls.length;
    const r = await client.callTool({
      name: 'shieldlabs_list_history',
      arguments: {
        resource: 'identifications',
        domain: DOMAIN_ID,
        offset: 20,
        response_format: 'json',
      },
    });
    expect(r.isError).toBe(true);
    expect(backend.calls).toHaveLength(count);
  }));
it('explains unavailable weights and preserves score', async () =>
  hosted({ data: card }, async (client) => {
    const r = await client.callTool({
      name: 'shieldlabs_explain_risk_score',
      arguments: { identification_id: REQUEST_ID, domain: DOMAIN_ID, response_format: 'markdown' },
    });
    expect(r.isError, JSON.stringify(r)).not.toBe(true);
    expect(r.structuredContent).toMatchObject({ risk: { score: 30 }, weights_available: false });
    expect(JSON.stringify(r.content)).toContain('Detailed signal weights are unavailable');
  }));
it('does not expose backend rows from another domain', async () =>
  hosted(
    { data: { ...card, domain_id: '99999999-9999-4999-8999-999999999999' } },
    async (client) => {
      const r = await client.callTool(get);
      expect(r.isError).toBe(true);
    },
  ));

it('validates the Portal fixture directly', () => {
  expect(() => entityView(card)).not.toThrow();
});
