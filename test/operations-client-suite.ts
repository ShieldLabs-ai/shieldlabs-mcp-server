import { describe, expect, it } from 'vitest';
import {
  MAX_BACKEND_BYTES,
  OperationError,
  OperationsClient,
} from '../src/public/operations-client.js';
import { identification } from '../src/public/operations.js';
import type { PortalFetch } from '../src/public/portal.js';
import card from './fixtures/review-portal-entity.json';
import {
  DOMAIN_ID,
  HOSTED_TOKEN,
  REQUEST_ID,
  SIGNING_SECRET,
  UPSTREAM,
} from './operations-backend.js';

function client(fetch: PortalFetch, signal?: AbortSignal) {
  return new OperationsClient({
    config: {
      publicOrigin: 'https://dev.mcp.shieldlabs.ai',
      authIssuer: UPSTREAM,
      portalUrl: UPSTREAM,
      gatewayKey: { kid: 'k1', secret: SIGNING_SECRET },
    },
    fetch,
    token: HOSTED_TOKEN,
    tokenHash: 'a'.repeat(64),
    now: Date.now,
    ...(signal === undefined ? {} : { signal }),
  });
}

export function operationsClientSuite() {
  describe('hosted request budgets and cancellation', () => {
    for (const code of [
      'snapshot_unavailable',
      'coverage_unavailable',
      'invalid_reader_scope',
      'temporarily_unavailable',
      'ambiguous_device_id',
    ])
      it(`preserves the controlled entity error code ${code} without leaking upstream text`, async () => {
        const api = client(async () =>
          Response.json({ error: { code, message: 'private-database-secret' } }, { status: 503 }),
        );
        await expect(
          api.request('GET', '/mcp/v1/domains/' + DOMAIN_ID + '/history/identifications'),
        ).rejects.toMatchObject({ code });
        await expect(
          api.request('GET', '/mcp/v1/domains/' + DOMAIN_ID + '/history/identifications'),
        ).rejects.not.toMatchObject({
          message: expect.stringContaining('private-database-secret'),
        });
      });

    it('immediately rethrows Retry-After 8 seconds when the total wait budget is 6 seconds', async () => {
      let calls = 0;
      const api = client(async () => {
        calls++;
        return Response.json(
          { error: 'rate_limited' },
          { status: 429, headers: { 'Retry-After': '8' } },
        );
      });
      const started = performance.now();
      await expect(
        identification(api, REQUEST_ID, DOMAIN_ID, true, new AbortController().signal, 6_000),
      ).rejects.toMatchObject({
        code: 'rate_limited',
        retryAfterMs: 8_000,
        message: 'Rate limit reached. ShieldLabs recommends waiting 8 seconds before retrying.',
      });
      expect(performance.now() - started).toBeLessThan(1000);
      expect(calls).toBe(1);
    });
    it('keeps the manual recommendation while capping a polling delay at 10 seconds', async () => {
      const api = client(async () =>
        Response.json({}, { status: 429, headers: { 'Retry-After': '30' } }),
      );
      await expect(api.request('GET', '/mcp/v1/domains')).rejects.toMatchObject({
        code: 'rate_limited',
        retryAfterMs: 10_000,
        message: 'Rate limit reached. ShieldLabs recommends waiting 30 seconds before retrying.',
      });
    });
    it('polls again after a non-JSON transient outage without surfacing its body', async () => {
      let calls = 0;
      const api = client(async () =>
        ++calls === 1
          ? new Response('<html>temporarily unavailable</html>', { status: 502 })
          : Response.json({ data: card }),
      );
      const found = await identification(
        api,
        REQUEST_ID,
        DOMAIN_ID,
        true,
        new AbortController().signal,
      );
      expect(found.id).toBe(REQUEST_ID);
      expect(calls).toBe(2);
    });
    it('does not forward an already-cancelled call or a call to another contour', async () => {
      let count = 0;
      const api = client(async () => {
        count++;
        return Response.json({});
      });
      const signal = AbortSignal.abort();
      await expect(
        api.request('POST', '/mcp/v1/domains', { domain: 'example.com' }, signal),
      ).rejects.toMatchObject({ code: 'cancelled' });
      await expect(api.request('GET', '/api/v1/history/user_hid/x')).rejects.toMatchObject({
        code: 'invalid_path',
      });
      await expect(
        api.request('GET', '/mcp/v1/../../api/v1/history/user_hid/x'),
      ).rejects.toMatchObject({ code: 'invalid_path' });
      expect(count).toBe(0);
    });

    it('cancels queued requests without forwarding and cleans delay listeners', async () => {
      let count = 0;
      const api = client(async () => {
        count++;
        return Response.json({ data: [], total: 0 });
      });
      await api.request('GET', '/mcp/v1/domains');
      const controller = new AbortController();
      const pending = api.request('GET', '/mcp/v1/domains', undefined, controller.signal);
      controller.abort();
      await expect(pending).rejects.toBeInstanceOf(OperationError);
      expect(count).toBe(1);
      const waiting = new AbortController();
      const poll = identification(
        client(async () => Response.json({ error: { code: 'not_found' } }, { status: 404 })),
        REQUEST_ID,
        DOMAIN_ID,
        true,
        waiting.signal,
      );
      setTimeout(() => waiting.abort(), 30);
      await expect(poll).rejects.toMatchObject({ code: 'cancelled' });
    });

    it('includes stalled fetch time in the entire identification wait deadline', async () => {
      let sentSignal: AbortSignal | undefined;
      const api = client((_url, init) => {
        sentSignal = init.signal;
        return new Promise(() => {});
      });
      const started = performance.now();
      await expect(
        identification(api, REQUEST_ID, DOMAIN_ID, true, new AbortController().signal, 50),
      ).rejects.toMatchObject({ code: 'timeout' });
      expect(performance.now() - started).toBeLessThan(1000);
      expect(sentSignal?.aborted).toBe(true);
    });

    it('bounds streamed backend responses and cancels the reader after overflow', async () => {
      let cancelled = false;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(MAX_BACKEND_BYTES + 1));
        },
        cancel() {
          cancelled = true;
        },
      });
      await expect(
        client(async () => new Response(stream)).request('GET', '/mcp/v1/domains'),
      ).rejects.toMatchObject({ code: 'response_too_large' });
      expect(cancelled).toBe(true);
    });

    it('bounds mutation bodies before signing or forwarding', async () => {
      let count = 0;
      const api = client(async () => {
        count++;
        return Response.json({});
      });
      await expect(
        api.request('POST', '/mcp/v1/domains', { domain: 'a'.repeat(MAX_BACKEND_BYTES) }),
      ).rejects.toMatchObject({ code: 'request_too_large' });
      expect(count).toBe(0);
    });

    it('does not let summaries or retries exceed 12 backend requests per MCP request', async () => {
      let count = 0;
      const api = client(async () => {
        count++;
        return Response.json({});
      });
      for (let index = 0; index < 12; index++) await api.request('GET', '/mcp/v1/domains');
      await expect(api.request('GET', '/mcp/v1/domains')).rejects.toMatchObject({
        code: 'budget_exceeded',
      });
      expect(count).toBe(12);
    });
  });
}
