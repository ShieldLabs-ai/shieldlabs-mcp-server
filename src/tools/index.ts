import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { TOOL_NAMES, type ToolName } from '../constants.js';
import { redact, type ServerContext } from '../context.js';
import { registerEntityHistoryTools } from '../entity-history.js';
import { ToolInputError } from '../errors.js';
import { registerCurrentTime } from './current-time.js';
import { registerGetDomainProfile } from './domain-profile.js';
import { failure, respond } from './shared.js';
import { registerVerifyWebhookSignature } from './verify-webhook.js';

const REGISTRARS: Partial<Record<ToolName, (server: McpServer, ctx: ServerContext) => void>> = {
  [TOOL_NAMES.getDomainProfile]: registerGetDomainProfile,
  [TOOL_NAMES.verifyWebhookSignature]: registerVerifyWebhookSignature,
  [TOOL_NAMES.currentTime]: registerCurrentTime,
};

/** Registers every enabled tool, in a stable order. */
export function registerTools(server: McpServer, ctx: ServerContext): void {
  registerEntityHistoryTools(server, {
    reader: ctx.history?.entities ?? {
      list: () =>
        Promise.reject(
          new ToolInputError(
            'SHIELDLABS_API_KEY is not set. Paste an identification or configure the server key.',
          ),
        ),
      get: () =>
        Promise.reject(
          new ToolInputError(
            'SHIELDLABS_API_KEY is not set. Paste an identification or configure the server key.',
          ),
        ),
    },
    enabled: ctx.enabledTools,
    online: ctx.history !== undefined,
    waitTimeoutMs: ctx.waitTimeoutMs,
    respond: (data, format, markdown) =>
      respond(
        ctx,
        JSON.parse(redact(ctx, JSON.stringify(data))) as Record<string, unknown>,
        markdown,
        format,
      ),
    failure: (error) => failure(ctx, error),
  });
  for (const [name, register] of Object.entries(REGISTRARS) as [
    ToolName,
    typeof registerCurrentTime,
  ][]) {
    if (ctx.enabledTools.has(name) && register !== undefined) register(server, ctx);
  }
}
