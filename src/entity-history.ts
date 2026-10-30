import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  normalizeHistoryEntityId,
  parseEntityPage,
  parseHistoryEntity,
  type EntityListOptions,
  type EntityPage,
  type EntityReadOptions,
  type EntityWindow,
  type HistoryEntity,
  type HistoryResource,
} from '@shieldlabs-ai/node';
import { z } from 'zod';
import { CHARACTER_LIMIT, TOOL_NAMES, UUID_PATTERN } from './constants.js';
import { ToolInputError } from './errors.js';
import { canonicalSignalName } from './catalog/risk-signals.js';
import { buildExplanation, parseIdentificationInput } from './explain.js';
import { code, cutSerialized, escapeInvisible, UNTRUSTED_DATA_FIELD_NOTE } from './format.js';

const Band = z.enum(['trusted', 'suspicious', 'dangerous']);
export const EntityRiskSchema = z.union([
  z.object({
    state: z.literal('ok'),
    band: Band,
    score: z.number().int().min(0).max(100).optional(),
    as_of: z.string(),
  }),
  z.object({ state: z.literal('unavailable'), band: z.null(), as_of: z.null() }),
]);
const Signals = z.object({
  state: z.enum(['ok', 'unavailable']),
  items: z.array(z.string()).max(100),
});
const NullableText = z.string().nullable();
export const EntitySchema = z.object({
  type: z.enum(['identification', 'user', 'visitor', 'device', 'ip']),
  id: z.string().min(1).max(512),
  domain_id: z.string().regex(UUID_PATTERN),
  domain: z.string(),
  risk: EntityRiskSchema,
  signals: Signals,
  created_at: z.string().nullable().optional(),
  first_seen: z.string().nullable().optional(),
  last_seen: z.string().nullable().optional(),
  identifications: z.number().int().nonnegative().nullable().optional(),
  ...Object.fromEntries(
    [
      'visitor_id',
      'user_hid',
      'device_id',
      'device_id_source',
      'public_ip',
      'country',
      'browser',
      'os',
      'device_type',
      'connection_type',
      'session_id',
      'cookie_id',
      'local_ip',
      'local_country',
    ].map((k) => [k, z.string().nullable().optional()]),
  ),
  traffic: z
    .object(
      Object.fromEntries(
        [
          'channel',
          'referrer_domain',
          'entry_url',
          'click_id_type',
          'utm_source',
          'utm_medium',
          'utm_campaign',
          'utm_content',
          'utm_term',
        ].map((k) => [k, NullableText]),
      ),
    )
    .nullable()
    .optional(),
  identity_risk: z
    .object({
      visitor: EntityRiskSchema.nullable(),
      device: EntityRiskSchema.nullable(),
      user: EntityRiskSchema.nullable(),
      ip: EntityRiskSchema.nullable(),
    })
    .nullable()
    .optional(),
  high_risk_events: z
    .object({
      state: z.string(),
      as_of: NullableText,
      items: z.array(z.object({ code: z.string(), confidence: z.string() })).max(100),
    })
    .nullable()
    .optional(),
  related_counts: z
    .object({
      visitors: z.number().int().nonnegative().optional(),
      devices: z.number().int().nonnegative().optional(),
      users: z.number().int().nonnegative().optional(),
      public_ips: z.number().int().nonnegative().optional(),
      cookies: z.number().int().nonnegative(),
      sessions: z.number().int().nonnegative(),
    })
    .nullable()
    .optional(),
  attributes: z
    .object({
      countries: z.array(z.string()).max(100).nullable(),
      local_countries: z.array(z.string()).max(100).nullable(),
      browser: NullableText,
      os: NullableText,
      device_type: NullableText,
      connection_type: NullableText,
    })
    .nullable()
    .optional(),
  device_identity: z
    .object({
      hardware_id: z.string().nullable().optional(),
      legacy_device_id: z.string().nullable().optional(),
      hardware_ids: z.array(z.string()).max(100).optional(),
      legacy_device_ids: z.array(z.string()).max(100).optional(),
      record_ids: z.array(z.string()).max(100).optional(),
      state: z.string().optional(),
    })
    .nullable()
    .optional(),
  band_split: z
    .object({
      trusted: z.number().int().nonnegative(),
      suspicious: z.number().int().nonnegative(),
      dangerous: z.number().int().nonnegative(),
    })
    .nullable()
    .optional(),
});
const FLAG_NAMES = [
  'is_vpn',
  'is_tor',
  'is_proxy',
  'is_privacy_relay',
  'network_check_incomplete',
  'check_incomplete',
  'is_antidetect',
  'is_os_mismatch',
  'is_os_not_detected',
  'is_timezone_mismatch',
  'is_js_disabled',
  'is_browser_automation',
  'is_incognito',
  'is_search_bot',
  'ip_mismatch',
  'latency_test',
  'device_spoofing',
  'banned_ip',
  'ai_bot',
  'ai_browser',
] as const;
const FlagFields = Object.fromEntries(FLAG_NAMES.map((name) => [name, z.boolean().optional()]));
const FlatFilters = {
  snapshot: z.string().min(1).max(4096).optional(),
  risk_bands: z.array(Band).max(3).optional(),
  hre_min_accounts: z.number().int().min(3).max(99).optional(),
  hre_min_devices: z.number().int().min(4).max(99).optional(),
  ids: z.string().min(1).max(512).optional(),
  risk_signals: z.array(z.string().min(1).max(128)).max(32).optional(),
  source: z.array(z.string().min(1).max(512)).max(8).optional(),
  campaign: z.array(z.string().min(1).max(512)).max(8).optional(),
  ...FlagFields,
};
const Domain = z
  .string()
  .regex(UUID_PATTERN)
  .describe('Public domain UUID from shieldlabs_list_domains, not the hostname.');
const Format = z.enum(['markdown', 'json']).default('markdown');
const Window = {
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
};
const common = { domain: Domain, response_format: Format, ...Window };
function windowRange(
  v: { from?: string | undefined; to?: string | undefined },
  ctx: z.RefinementCtx,
) {
  if (
    (v.from === undefined) !== (v.to === undefined) ||
    (v.from !== undefined && v.to !== undefined && Date.parse(v.from) >= Date.parse(v.to))
  )
    ctx.addIssue({
      code: 'custom',
      message: 'Send both from and to in RFC3339, with from before to.',
    });
}
export interface EntityReader {
  list(
    domain: string,
    resource: 'identifications' | 'user',
    options: EntityListOptions,
  ): Promise<EntityPage>;
  get(
    domain: string,
    resource: HistoryResource,
    id: string,
    options: EntityReadOptions,
  ): Promise<HistoryEntity>;
}
interface Runtime {
  reader: EntityReader;
  respond: (
    data: Record<string, unknown>,
    format: 'markdown' | 'json',
    markdown: string,
  ) => CallToolResult;
  failure: (error: unknown) => CallToolResult;
  enabled?: ReadonlySet<string>;
  waitTimeoutMs?: number;
  online?: boolean;
}
/** Output only public schema fields. Browser text stays inert; opaque paging tokens are untouched. */
export function entityView(value: unknown): HistoryEntity {
  const parsed = EntitySchema.parse(parseHistoryEntity(value));
  parsed.signals.items = parsed.signals.items.map(canonicalSignalName);
  const safe = (v: unknown): unknown =>
    typeof v === 'string'
      ? cutSerialized(escapeInvisible(v), 1000)
      : Array.isArray(v)
        ? v.map(safe)
        : v !== null && typeof v === 'object'
          ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, safe(x)]))
          : v;
  return safe(parsed) as HistoryEntity;
}
export function entityMarkdown(entity: HistoryEntity): string {
  const risk = entity.risk;
  const label =
    risk.state === 'unavailable'
      ? 'Risk Score unavailable'
      : risk.score === undefined
        ? `Risk band ${risk.band}; exact score unavailable`
        : `Risk Score ${risk.score} (${risk.band})`;
  const lines = [
    `## ${label}`,
    `- ${entity.type === 'identification' ? 'Identification ID' : 'Entity ID'}: ${code(entity.id)}`,
    `- Domain: ${code(entity.domain)} (${code(entity.domain_id)})`,
  ];
  if (typeof entity.identifications === 'number')
    lines.push(`- Identifications reported by the API: ${entity.identifications}`);
  lines.push(
    entity.signals.state === 'unavailable'
      ? '- Risk signals unavailable in this response.'
      : `- Risk signals: ${entity.signals.items.length ? entity.signals.items.map((item) => code(item)).join(', ') : 'none reported'}`,
  );
  if (entity.high_risk_events)
    lines.push(`- High-Risk Events state: ${code(entity.high_risk_events.state)}`);
  return lines.join('\n');
}
function windowOptions(
  v: { from?: string | undefined; to?: string | undefined },
  signal: AbortSignal,
): EntityWindow {
  return {
    ...(v.from === undefined ? {} : { from: v.from }),
    ...(v.to === undefined ? {} : { to: v.to }),
    signal,
  };
}
function flatOptions(v: Record<string, unknown>): EntityListOptions {
  const out: Record<string, unknown> = {};
  for (const key of [
    'snapshot',
    'risk_bands',
    'hre_min_accounts',
    'hre_min_devices',
    'ids',
    'risk_signals',
    'source',
    'campaign',
    ...FLAG_NAMES,
  ])
    if (v[key] !== undefined) out[key] = v[key];
  return out;
}
export function registerEntityHistoryTools(server: McpServer, runtime: Runtime): void {
  const { reader } = runtime;
  const emit = (data: Record<string, unknown>, format: 'markdown' | 'json', markdown: string) => {
    if (
      JSON.stringify({ ...data, untrusted_data_note: UNTRUSTED_DATA_FIELD_NOTE }).length >
      CHARACTER_LIMIT
    )
      throw new ToolInputError(
        'History response exceeds the output limit. Request a smaller page.',
      );
    return runtime.respond(
      { ...data, untrusted_data_note: UNTRUSTED_DATA_FIELD_NOTE },
      format,
      markdown,
    );
  };
  const allowed = (name: string) => runtime.enabled === undefined || runtime.enabled.has(name);
  if (allowed(TOOL_NAMES.listHistory))
    server.registerTool(
      TOOL_NAMES.listHistory,
      {
        title: 'List History',
        description:
          'List identifications or users in one domain. domain is the public UUID from shieldlabs_list_domains. Repeat page_token with the same resource, window and flat filters. Filters are risk_bands, hre_min_accounts (3-99), hre_min_devices (4-99), ids (one user id on the user list), risk_signals, source, campaign and boolean flags. Dates are RFC3339 and the window is half-open. Nested filter, chips, offset, include_total and sort are rejected. visitor, device and ip have a card, not a list.',
        inputSchema: z
          .object({
            ...common,
            resource: z.enum(['identifications', 'user']),
            limit: z.number().int().min(1).max(100).default(20),
            page_token: z.string().min(1).max(4096).optional(),
            ...FlatFilters,
          })
          .strict()
          .superRefine(windowRange)
          .superRefine((v, ctx) => {
            if (v.resource !== 'user' && v.ids !== undefined)
              ctx.addIssue({ code: 'custom', message: 'ids is only valid for the user list.' });
            if ((v.source?.length ?? 0) + (v.campaign?.length ?? 0) > 8)
              ctx.addIssue({
                code: 'custom',
                message: 'source and campaign together accept at most 8 values.',
              });
          }),
        outputSchema: z.object({
          resource: z.enum(['identifications', 'user']),
          data: z.array(EntitySchema),
          next_page_token: z.string().nullable(),
          untrusted_data_note: z.string(),
        }),
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
      },
      async (args, extra) => {
        try {
          const { domain, resource, response_format, limit, page_token } = args;
          const page = await reader.list(domain, resource, {
            ...flatOptions(args),
            ...windowOptions(args, extra.signal),
            limit,
            ...(page_token === undefined ? {} : { page_token }),
          });
          const data = page.data.map(entityView);
          return emit(
            { resource, data, next_page_token: page.next_page_token },
            response_format,
            [
              '# History',
              ...data.map(entityMarkdown),
              page.next_page_token
                ? 'More records are available. Continue with next_page_token.'
                : 'End of this page sequence.',
            ].join('\n\n'),
          );
        } catch (e) {
          return runtime.failure(e);
        }
      },
    );
  if (allowed(TOOL_NAMES.getIdentification))
    server.registerTool(
      TOOL_NAMES.getIdentification,
      {
        title: 'Get identification',
        description:
          'Read one identification card by identification_id in a public domain UUID. wait polls missing results for at most 10 seconds; unavailable risk remains unavailable.',
        inputSchema: z
          .object({
            ...common,
            identification_id: z.string().regex(UUID_PATTERN),
            wait: z.boolean().default(true),
          })
          .strict()
          .superRefine(windowRange),
        outputSchema: z.object({
          found: z.literal(true),
          identification: EntitySchema,
          untrusted_data_note: z.string(),
        }),
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
      },
      async (args, extra) => {
        try {
          const entity = await readIdentificationEntity(
            reader,
            args.domain,
            args.identification_id,
            { ...windowOptions(args, extra.signal), wait: args.wait },
            runtime.waitTimeoutMs,
          );
          const view = entityView(entity);
          return emit(
            { found: true, identification: view },
            args.response_format,
            entityMarkdown(view),
          );
        } catch (e) {
          return runtime.failure(e);
        }
      },
    );
  if (allowed(TOOL_NAMES.getHistory))
    server.registerTool(
      TOOL_NAMES.getHistory,
      {
        title: 'Get History record',
        description:
          'Read one identification, user, visitor, device or ip card. domain is the public UUID and resource_id is the record id. The same flat list filters apply, plus device_id_source (legacy or fp21_record). relation, relation_limit and relation_page_token are not accepted. Nested filter, chips, offset and include_total are rejected.',
        inputSchema: z
          .object({
            ...common,
            resource: z.enum(['identifications', 'user', 'visitor', 'device', 'ip']),
            resource_id: z.string().min(1).max(512),
            device_id_source: z.enum(['legacy', 'fp21_record']).optional(),
            ...FlatFilters,
          })
          .strict()
          .superRefine(windowRange)
          .superRefine((v, ctx) => {
            if ((v.source?.length ?? 0) + (v.campaign?.length ?? 0) > 8)
              ctx.addIssue({
                code: 'custom',
                message: 'source and campaign together accept at most 8 values.',
              });
          }),
        outputSchema: z.object({
          resource: z.enum(['identifications', 'user', 'visitor', 'device', 'ip']),
          entity: EntitySchema,
          untrusted_data_note: z.string(),
        }),
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
      },
      async (args, extra) => {
        try {
          const entity = entityView(
            await reader.get(args.domain, args.resource, args.resource_id, {
              ...flatOptions(args),
              ...windowOptions(args, extra.signal),
              ...(args.device_id_source === undefined
                ? {}
                : { device_id_source: args.device_id_source }),
            }),
          );
          return emit(
            { resource: args.resource, entity },
            args.response_format,
            entityMarkdown(entity),
          );
        } catch (e) {
          return runtime.failure(e);
        }
      },
    );
  if (allowed(TOOL_NAMES.explainRiskScore))
    server.registerTool(
      TOOL_NAMES.explainRiskScore,
      {
        title: 'Explain Risk Score',
        description:
          'Read an identification card or explain a pasted identification. Missing signal weights are unavailable, never zero contribution. HRE confidence is separate from Risk Score.',
        inputSchema: z
          .object({
            domain: Domain.optional(),
            identification_id: z.string().regex(UUID_PATTERN).optional(),
            identification: z
              .union([z.record(z.string(), z.unknown()), z.string().max(500000)])
              .optional(),
            response_format: Format,
          })
          .strict()
          .superRefine((v, ctx) => {
            if (
              (v.identification_id === undefined) === (v.identification === undefined) ||
              (v.identification_id !== undefined && v.domain === undefined)
            )
              ctx.addIssue({
                code: 'custom',
                message: 'Give a pasted identification, or identification_id with domain UUID.',
              });
          }),
        outputSchema: z
          .object({
            identification_id: z.string().nullable(),
            risk: EntityRiskSchema.optional(),
            risk_score: z.number().int().optional(),
            weights_available: z.boolean().optional(),
            signals: z.union([Signals, z.array(z.record(z.string(), z.unknown()))]),
            untrusted_data_note: z.string(),
          })
          .passthrough(),
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: runtime.online ?? true,
        },
      },
      async (args, extra) => {
        try {
          let input = args.identification;
          if (args.identification_id !== undefined)
            input = {
              ...(await reader.get(args.domain!, 'identifications', args.identification_id, {
                signal: extra.signal,
              })),
            };
          if (typeof input === 'string') {
            try {
              input = JSON.parse(input) as Record<string, unknown>;
            } catch {
              throw new ToolInputError('identification is not valid JSON.');
            }
          }
          if (
            input !== null &&
            typeof input === 'object' &&
            typeof input.identification === 'object' &&
            input.identification !== null
          )
            input = input.identification as Record<string, unknown>;
          if (input !== null && typeof input === 'object' && input.type === 'identification') {
            const entity = entityView(input);
            const note = 'Detailed signal weights are unavailable in this response.';
            return emit(
              {
                identification_id: entity.id,
                risk: entity.risk,
                signals: entity.signals,
                weights_available: false,
              },
              args.response_format,
              `${entityMarkdown(entity)}\n\n${note}`,
            );
          }
          const built = buildExplanation(parseIdentificationInput(input!));
          return emit(built.explanation, args.response_format, built.markdown);
        } catch (e) {
          return runtime.failure(e);
        }
      },
    );
}
/** Poll the same ID only; respect cancellation, Retry-After and a total read deadline. */
export async function readIdentificationEntity(
  reader: EntityReader,
  domain: string,
  id: string,
  options: EntityWindow & { wait: boolean },
  timeoutMs = 10_000,
): Promise<HistoryEntity> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const deadline = Date.now() + (options.wait ? timeoutMs : 0);
  const timer = options.wait ? setTimeout(abort, timeoutMs) : undefined;
  try {
    for (;;) {
      try {
        return await reader.get(domain, 'identifications', id, {
          ...windowOptions(options, controller.signal),
        });
      } catch (e) {
        const failure = e as {
          status?: number;
          code?: string;
          retryAfterMs?: number;
          retryAfter?: number;
        };
        const retryable =
          failure.status === 404 ||
          (failure.status !== undefined && failure.status >= 500) ||
          ['not_found', 'unavailable', 'snapshot_unavailable', 'rate_limited'].includes(
            failure.code ?? '',
          );
        const pause =
          failure.retryAfterMs ??
          (failure.retryAfter === undefined ? 1000 : failure.retryAfter * 1000);
        if (
          !options.wait ||
          !retryable ||
          controller.signal.aborted ||
          Date.now() + pause >= deadline
        )
          throw e;
        await new Promise<void>((resolve, reject) => {
          const done = () => {
            controller.signal.removeEventListener('abort', cancel);
            resolve();
          };
          const delay = setTimeout(done, pause);
          const cancel = () => {
            clearTimeout(delay);
            controller.signal.removeEventListener('abort', cancel);
            reject(new ToolInputError('History read cancelled or timed out.'));
          };
          controller.signal.addEventListener('abort', cancel, { once: true });
          if (controller.signal.aborted) cancel();
        });
      }
    }
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    options.signal?.removeEventListener('abort', abort);
  }
}
/** Adapt the signed public MCP API, never the dashboard API. */
export function hostedEntityReader(
  request: (path: string, signal?: AbortSignal) => Promise<Record<string, unknown>>,
): EntityReader {
  const path = (domain: string, resource: HistoryResource) =>
    `/mcp/v1/domains/${domain.toLowerCase()}/history/${resource}`;
  const query = (options: EntityReadOptions) => {
    const q = new URLSearchParams();
    const add = (key: string, value: string) => q.append(key, value);
    for (const key of ['from', 'to', 'snapshot', 'page_token', 'device_id_source'] as const) {
      const value = options[key];
      if (value !== undefined) add(key, value);
    }
    for (const key of ['limit', 'hre_min_accounts', 'hre_min_devices'] as const) {
      const value = options[key];
      if (value !== undefined) add(key, String(value));
    }
    for (const key of ['risk_bands', 'risk_signals', 'source', 'campaign'] as const)
      for (const item of options[key] ?? []) add(key, item);
    const userID = options.ids as unknown;
    if (typeof userID === 'string') add('ids', userID);
    else if (Array.isArray(userID) && userID.length === 1 && typeof userID[0] === 'string')
      add('ids', userID[0]);
    for (const key of FLAG_NAMES) {
      const value = options[key];
      if (value !== undefined) add(key, value ? 'true' : 'false');
    }
    return q.size ? `?${q.toString()}` : '';
  };
  return {
    list: async (domain, resource, options) => {
      const page = parseEntityPage(
        await request(path(domain, resource) + query(options), options.signal),
      );
      if (
        page.data.some(
          (v) =>
            v.domain_id.toLowerCase() !== domain.toLowerCase() ||
            v.type !== (resource === 'identifications' ? 'identification' : resource),
        ) ||
        page.data.length > (options.limit ?? 20)
      )
        throw new ToolInputError('History returned records outside the requested scope or limit.');
      return page;
    },
    get: async (domain, resource, id, options) => {
      const key = normalizeHistoryEntityId(resource, id);
      const body = await request(
        `${path(domain, resource)}/${encodeURIComponent(key)}${query(options)}`,
        options.signal,
      );
      const entity = parseHistoryEntity(body.data);
      if (
        entity.id !== key ||
        entity.domain_id.toLowerCase() !== domain.toLowerCase() ||
        entity.type !== (resource === 'identifications' ? 'identification' : resource)
      )
        throw new ToolInputError('History returned the wrong entity or domain.');
      return entity;
    },
  };
}
