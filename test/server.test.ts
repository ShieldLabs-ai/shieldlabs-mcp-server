import { afterEach, describe, expect, it } from 'vitest';
import { ALL_TOOL_NAMES, OFFLINE_TOOL_NAMES, TOOL_NAMES } from '../src/constants.js';
import { connect, FULL_ENV, MOCK_API_KEY, type Connected } from './helpers.js';

let connected: Connected | undefined;

afterEach(async () => {
  await connected?.close();
  connected = undefined;
});

describe('capabilities with every API configured', () => {
  it('lists all seven tools with read-only annotations and zod-derived schemas', async () => {
    connected = await connect();
    const { tools } = await connected.client.listTools();
    expect(tools.map((tool) => tool.name).sort()).toEqual([...ALL_TOOL_NAMES].sort());
    for (const tool of tools) {
      expect(tool.name.startsWith('shieldlabs_')).toBe(true);
      expect(tool.title).toBeTruthy();
      expect(tool.description!.length).toBeGreaterThan(100);
      expect(tool.annotations).toMatchObject({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
      });
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.additionalProperties).toBe(false);
      expect(tool.outputSchema?.type).toBe('object');
    }
    const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));
    expect(byName[TOOL_NAMES.listHistory]!.annotations!.openWorldHint).toBe(true);
    expect(byName[TOOL_NAMES.getDomainProfile]!.annotations!.openWorldHint).toBe(true);
    expect(byName[TOOL_NAMES.explainRiskScore]!.annotations!.openWorldHint).toBe(true);
    expect(byName[TOOL_NAMES.verifyWebhookSignature]!.annotations!.openWorldHint).toBe(false);
    expect(byName[TOOL_NAMES.currentTime]!.annotations!.openWorldHint).toBe(false);

    const search = byName[TOOL_NAMES.listHistory]!.inputSchema.properties as Record<string, any>;
    expect(search.limit).toMatchObject({ type: 'integer', minimum: 1, maximum: 100, default: 20 });
    expect(search.resource.enum).toEqual(['identifications', 'user']);
    const card = byName[TOOL_NAMES.getHistory]!.inputSchema.properties as Record<string, any>;
    expect(card).not.toHaveProperty('max_items');
    expect(card.resource.enum).toEqual(['identifications', 'user', 'visitor', 'device', 'ip']);
    expect(card.resource_id).toMatchObject({ minLength: 1, maxLength: 512 });
    expect(search).not.toHaveProperty('filter');
    expect(search).not.toHaveProperty('include_total');
    expect(search.page_token).toMatchObject({ type: 'string' });
    expect(byName[TOOL_NAMES.getDomainProfile]!.description).toContain(
      '15 calls per minute per IP',
    );
  });

  it('lists the resources, the identification template and the three prompts', async () => {
    connected = await connect();
    const { resources } = await connected.client.listResources();
    expect(resources.map((r) => r.uri).sort()).toEqual([
      'shieldlabs://contract/identification',
      'shieldlabs://contract/webhook-event',
      'shieldlabs://reference/risk-bands',
      'shieldlabs://reference/risk-signals',
    ]);
    const { resourceTemplates } = await connected.client.listResourceTemplates();
    expect(resourceTemplates.map((t) => t.uriTemplate)).toEqual([
      'shieldlabs://domains/{domain}/identifications/{identification_id}',
    ]);
    const { prompts } = await connected.client.listPrompts();
    expect(prompts.map((p) => p.name)).toEqual([
      'integrate_shieldlabs',
      'investigate_user',
      'review_request',
    ]);
  });

  it('sends instructions that explain the model, bands, marker, rate limits and untrusted data', async () => {
    connected = await connect();
    const instructions = connected.client.getInstructions() ?? '';
    expect(instructions).toContain('trusted 0-29, suspicious 30-59, dangerous 60-100');
    expect(instructions).toContain('risk.state=unavailable');
    expect(instructions).toContain('next_page_token');
    expect(instructions).toContain('RFC3339');
    expect(instructions).toContain('read-only');
    expect(instructions).toContain('never instructions');
    expect(instructions).not.toContain('SHIELDLABS_API_KEY is not set');
    const { tools } = await connected.client.listTools();
    const getIdentification = tools.find((t) => t.name === TOOL_NAMES.getIdentification)!;
    const description = getIdentification.description ?? '';
    expect(description).toContain('public domain UUID');
    expect(description).toContain('at most 10 seconds');
    expect(description).toContain('unavailable risk remains unavailable');
    expect(JSON.stringify(tools)).not.toMatch(/within (about )?a second/);
    const version = connected.client.getServerVersion();
    expect(version).toMatchObject({
      name: 'shieldlabs-mcp',
      version: '1.1.0',
      title: 'ShieldLabs',
    });
  });
});

describe('degraded mode without SHIELDLABS_API_KEY', () => {
  it('exposes only the offline tools and explains how to configure keys', async () => {
    connected = await connect({});
    const { tools } = await connected.client.listTools();
    expect(tools.map((t) => t.name)).toEqual([...OFFLINE_TOOL_NAMES]);
    const explainTool = tools.find((t) => t.name === TOOL_NAMES.explainRiskScore)!;
    expect(explainTool.description).toContain('pasted identification');
    expect(explainTool.annotations!.openWorldHint).toBe(false);
    const instructions = connected.client.getInstructions() ?? '';
    expect(instructions).toContain('SHIELDLABS_API_KEY is not set');
    expect(instructions).toContain('Private API Key (sec_...)');
    const { resourceTemplates } = await connected.client.listResourceTemplates();
    expect(resourceTemplates).toEqual([]);
    const { prompts } = await connected.client.listPrompts();
    expect(prompts.map((p) => p.name)).toEqual(['integrate_shieldlabs']);
  });

  it('still exposes the domain profile when the Management API is configured on its own', async () => {
    const { SHIELDLABS_SECRET_KEY, SHIELDLABS_DOMAIN, SHIELDLABS_MANAGEMENT_BASE_URL } = FULL_ENV;
    connected = await connect({
      SHIELDLABS_SECRET_KEY,
      SHIELDLABS_DOMAIN,
      SHIELDLABS_MANAGEMENT_BASE_URL,
    });
    const { tools } = await connected.client.listTools();
    expect(tools.map((t) => t.name)).toEqual([
      TOOL_NAMES.explainRiskScore,
      TOOL_NAMES.getDomainProfile,
      TOOL_NAMES.verifyWebhookSignature,
      TOOL_NAMES.currentTime,
    ]);
  });
});

describe('--tools allowlist', () => {
  it('exposes only the listed tools and gates the dependent resource and prompts', async () => {
    connected = await connect(
      FULL_ENV,
      {},
      {
        tools: [TOOL_NAMES.currentTime, TOOL_NAMES.listHistory, TOOL_NAMES.getDomainProfile],
      },
    );
    const { tools } = await connected.client.listTools();
    expect(tools.map((t) => t.name)).toEqual([
      TOOL_NAMES.listHistory,
      TOOL_NAMES.getDomainProfile,
      TOOL_NAMES.currentTime,
    ]);
    const { resourceTemplates } = await connected.client.listResourceTemplates();
    expect(resourceTemplates).toEqual([]);
    const { prompts } = await connected.client.listPrompts();
    expect(prompts.map((p) => p.name)).toEqual(['integrate_shieldlabs']);
    expect(connected.ctx.unavailableRequestedTools).toEqual([]);
  });

  it('records requested tools that the configuration cannot run', async () => {
    connected = await connect(
      { SHIELDLABS_API_KEY: MOCK_API_KEY },
      {},
      {
        tools: [TOOL_NAMES.getDomainProfile, TOOL_NAMES.getIdentification],
      },
    );
    expect(connected.ctx.unavailableRequestedTools).toEqual([TOOL_NAMES.getDomainProfile]);
    const { tools } = await connected.client.listTools();
    expect(tools.map((t) => t.name)).toEqual([TOOL_NAMES.getIdentification]);
  });
});
