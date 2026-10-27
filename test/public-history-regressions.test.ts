import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { describe, expect, it } from 'vitest';
import { handlePublicRequest } from '../src/public/handler.js';
import { TokenCache } from '../src/public/token.js';
import history from './fixtures/history-page.json';
import {
  HOSTED_TOKEN,
  RAW_SECRET,
  REQUEST_ID,
  SIGNING_SECRET,
  UPSTREAM,
  operationsBackend,
} from './operations-backend.js';

function host(backend: ReturnType<typeof operationsBackend>) {
  const config = {
    portalUrl: UPSTREAM,
    authIssuer: UPSTREAM,
    publicOrigin: 'https://dev.mcp.shieldlabs.ai',
    gatewayKey: { kid: 'k1', secret: SIGNING_SECRET },
  };
  const deps = { cache: new TokenCache(), fetch: backend.fetch };
  return {
    fetch: (input: Parameters<typeof globalThis.fetch>[0], init?: RequestInit) =>
      handlePublicRequest(new Request(input, init), config, deps),
  };
}

async function connect(instance: ReturnType<typeof host>) {
  const client = new Client({ name: 'history-regression-test', version: '1' });
  await client.connect(
    new StreamableHTTPClientTransport(new URL('https://dev.mcp.shieldlabs.ai/mcp'), {
      fetch: instance.fetch,
      requestInit: { headers: { Authorization: `Bearer ${HOSTED_TOKEN}` } },
    }),
  );
  return client;
}

describe('hosted history output regressions', () => {
  for (const idField of ['request_id', 'identification_id'] as const) {
    it(`preserves ${idField} from History in identification, search and explanation`, async () => {
      const backend = operationsBackend();
      const row = { ...history.data[0], request_id: '', [idField]: REQUEST_ID };
      backend.force({ status: 200, body: { data: [row], total: 1 } });
      const client = await connect(host(backend));
      try {
        const get = await client.callTool({
          name: 'shieldlabs_get_identification',
          arguments: { request_id: REQUEST_ID, wait: false, response_format: 'json' },
        });
        expect(get.isError).not.toBe(true);
        expect(get.structuredContent).toMatchObject({
          found: true,
          identification: { request_id: REQUEST_ID },
        });
        const search = await client.callTool({
          name: 'shieldlabs_search_history',
          arguments: { type: 'request_id', value: REQUEST_ID, response_format: 'json' },
        });
        expect(search.isError).not.toBe(true);
        expect(JSON.stringify(search.structuredContent)).toContain(`"request_id":"${REQUEST_ID}"`);
        const explain = await client.callTool({
          name: 'shieldlabs_explain_risk_score',
          arguments: { request_id: REQUEST_ID, response_format: 'json' },
        });
        expect(explain.isError).not.toBe(true);
        expect(explain.structuredContent).toMatchObject({ request_id: REQUEST_ID });
      } finally {
        await client.close();
      }
    });
  }

  it('renders real Markdown for all history tools while escaping visitor controls and masking secrets', async () => {
    const backend = operationsBackend();
    backend.force({
      status: 200,
      body: {
        data: [
          {
            ...history.data[0],
            request_id: REQUEST_ID,
            user_hid: `visitor\n## injected\u202e ${RAW_SECRET}`,
          },
        ],
        total: 1,
      },
    });
    const client = await connect(host(backend));
    try {
      for (const [name, args] of [
        ['shieldlabs_get_identification', { request_id: REQUEST_ID, wait: false }],
        ['shieldlabs_search_history', { type: 'request_id', value: REQUEST_ID }],
        ['shieldlabs_explain_risk_score', { request_id: REQUEST_ID }],
        ['shieldlabs_summarize_entity', { type: 'user_hid', value: 'anonymous' }],
      ] as const) {
        const reply = await client.callTool({
          name,
          arguments: { ...args, response_format: 'markdown' },
        });
        expect(reply.isError, name).not.toBe(true);
        const content = reply.content as { type: string; text: string }[];
        const text = content.find((item) => item.type === 'text')!.text;
        expect(text, name).toMatch(/^#/);
        expect(text, name).toContain('\n');
        expect(text, name).not.toContain('\n## injected');
        expect(text, name).not.toContain('\u202e');
        expect(JSON.stringify(reply), name).not.toContain(RAW_SECRET);
        if (name !== 'shieldlabs_explain_risk_score') {
          expect(text, name).toContain('visitor\\u000a## injected\\u202e');
        }
        expect(reply.structuredContent, name).toBeDefined();
      }
    } finally {
      await client.close();
    }
  });
});
