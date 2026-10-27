import { fileURLToPath } from 'node:url';
import { unstable_readConfig } from 'wrangler';
import { describe, expect, it } from 'vitest';
import {
  parseGatewayKey,
  PublicConfigError,
  publicConfigFromEnv,
  type PublicEnv,
} from '../src/public/config.js';
import { protectedResourceMetadata } from '../src/public/metadata.js';

const SECRET = 'gateway-test-secret-0123456789abcdef';
const DEV: PublicEnv = {
  SHIELDLABS_PUBLIC_ORIGIN: 'https://dev.mcp.shieldlabs.ai',
  SHIELDLABS_AUTH_ISSUER: 'https://dev.account.shieldlabs.ai',
  SHIELDLABS_PORTAL_URL: 'https://dev.account.shieldlabs.ai',
  MCP_GATEWAY_KEY: `k1:${SECRET}`,
};

function refusal(env: PublicEnv): string {
  try {
    publicConfigFromEnv(env);
  } catch (error) {
    expect(error).toBeInstanceOf(PublicConfigError);
    return (error as Error).message;
  }
  throw new Error('expected a PublicConfigError');
}

describe('public-mode settings', () => {
  it('read the origins and the gateway key', () => {
    expect(publicConfigFromEnv(DEV)).toEqual({
      publicOrigin: 'https://dev.mcp.shieldlabs.ai',
      authIssuer: 'https://dev.account.shieldlabs.ai',
      portalUrl: 'https://dev.account.shieldlabs.ai',
      gatewayKey: { kid: 'k1', secret: SECRET },
    });
    expect(
      publicConfigFromEnv({
        ...DEV,
        SHIELDLABS_PUBLIC_ORIGIN: ' https://MCP.example.test/ ',
        SHIELDLABS_AUTH_ISSUER: '',
        SHIELDLABS_PORTAL_URL: 'http://localhost:8090',
      }),
    ).toMatchObject({
      publicOrigin: 'https://mcp.example.test',
      authIssuer: 'http://localhost:8090',
      portalUrl: 'http://localhost:8090',
    });
  });

  it('have no default origin, so an environment never falls back to another', () => {
    expect(refusal({ ...DEV, SHIELDLABS_PUBLIC_ORIGIN: undefined })).toContain(
      'SHIELDLABS_PUBLIC_ORIGIN is not set',
    );
    expect(refusal({ ...DEV, SHIELDLABS_PORTAL_URL: ' ' })).toContain(
      'SHIELDLABS_PORTAL_URL is not set',
    );
  });

  it('refuse plain http outside loopback hosts, paths and values that are not URLs', () => {
    expect(
      refusal({ ...DEV, SHIELDLABS_PORTAL_URL: 'http://dev.account.shieldlabs.ai' }),
    ).toContain('SHIELDLABS_PORTAL_URL must be an https URL');
    expect(refusal({ ...DEV, SHIELDLABS_PUBLIC_ORIGIN: 'https://mcp.example.test/mcp' })).toContain(
      'must be an origin without a path',
    );
    expect(refusal({ ...DEV, SHIELDLABS_AUTH_ISSUER: 'account' })).toContain(
      'SHIELDLABS_AUTH_ISSUER must be an absolute URL',
    );
  });

  it('refuse a gateway key the ShieldLabs API would refuse, without quoting it', () => {
    expect(refusal({ ...DEV, MCP_GATEWAY_KEY: undefined })).toContain('MCP_GATEWAY_KEY is not set');
    for (const value of [
      SECRET,
      `:${SECRET}`,
      `k 1:${SECRET}`,
      `${'k'.repeat(33)}:${SECRET}`,
      'k1:too-short-secret',
      `k1:${SECRET} with space`,
      `k1:${SECRET},k2:${SECRET}`,
    ]) {
      const message = refusal({ ...DEV, MCP_GATEWAY_KEY: value });
      expect(message, value).toContain('MCP_GATEWAY_KEY');
      expect(message).not.toContain(SECRET);
      expect(message).not.toContain('too-short-secret');
    }
    expect(parseGatewayKey(`key.2026-10_a:${SECRET}:with-colon`)).toEqual({
      kid: 'key.2026-10_a',
      secret: `${SECRET}:with-colon`,
    });
  });
});

describe('wrangler.jsonc', () => {
  const configPath = fileURLToPath(new URL('../wrangler.jsonc', import.meta.url));
  const read = (env: string | undefined) =>
    unstable_readConfig({ config: configPath, env }, { hideWarnings: true });

  it('ships only local example settings without production routes or a gateway key', () => {
    for (const config of [read(undefined), read('dev')]) {
      expect(config.name).toBe('shieldlabs-mcp-local');
      expect(config.routes ?? []).toEqual([]);
      expect(config.workers_dev).toBe(false);
      expect(config.vars).toEqual({
        SHIELDLABS_PUBLIC_ORIGIN: 'https://mcp.example.test',
        SHIELDLABS_AUTH_ISSUER: 'https://account.example.test',
        SHIELDLABS_PORTAL_URL: 'https://account.example.test',
      });
      expect(Object.keys(config.vars)).not.toContain('MCP_GATEWAY_KEY');
      expect(config.compatibility_flags).toEqual([]);
      expect(config.main).toMatch(/src\/worker\.ts$/);
      const rateLimits = config.ratelimits as { name: string; namespace_id: string }[];
      expect(rateLimits.map(({ name }) => name)).toEqual(['RL_TOKEN', 'RL_ANON', 'RL_TOKEN_CHECK']);
      expect(new Set(rateLimits.map(({ namespace_id }) => namespace_id)).size).toBe(3);
      const publicConfig = publicConfigFromEnv({
        ...(config.vars as PublicEnv),
        MCP_GATEWAY_KEY: `k1:${SECRET}`,
      });
      expect(protectedResourceMetadata(publicConfig)).toMatchObject({
        resource: 'https://mcp.example.test/mcp',
        authorization_servers: ['https://account.example.test'],
      });
    }
  });
});
