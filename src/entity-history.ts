import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  normalizeHistoryEntityId,
  parseEntityPage,
  parseHistoryEntity,
  type EntityListOptions,
  type EntityPage,
  type EntityWindow,
  type HistoryEntity,
  type HistoryResource,
} from '@shieldlabs-ai/node';
import { z } from 'zod';
import { CHARACTER_LIMIT, TOOL_NAMES, UUID_PATTERN } from './constants.js';
import { ToolInputError } from './errors.js';
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
const BandFilter = z.object({ risk_bands: z.array(Band).min(1).max(1) }).strict();
export const EntityFilterSchema = z
  .object({
    identification: BandFilter.optional(),
    entity: BandFilter.optional(),
  })
  .strict();
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
    options: EntityWindow,
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
  if (allowed(TOOL_NAMES.searchHistory))
    server.registerTool(
      TOOL_NAMES.searchHistory,
      {
        title: 'List History entities',
        description:
          'List identifications or users in one domain. Use page_token from the previous page, preserving the resource, window, filter, sort and limit. Dates are RFC3339 and the window is half-open. Old value/offset/boolean search fields are not accepted.',
        inputSchema: z
          .object({
            ...common,
            type: z.enum(['identifications', 'user']),
            limit: z.number().int().min(1).max(100).default(20),
            page_token: z.string().min(1).max(4096).optional(),
            include_total: z.boolean().optional(),
            sort: z.string().optional(),
            filter: EntityFilterSchema.optional(),
          })
          .strict()
          .superRefine(windowRange)
          .superRefine((v, ctx) => {
            if (
              v.sort !== undefined &&
              v.sort !== (v.type === 'identifications' ? '-created_at' : '-last_seen')
            )
              ctx.addIssue({
                code: 'custom',
                message: 'Only the default newest-first sort is supported.',
              });
            if (v.type === 'user' && v.include_total === true)
              ctx.addIssue({ code: 'custom', message: 'User list totals are unavailable.' });
            if (
              (v.type === 'identifications' && v.filter?.entity !== undefined) ||
              (v.type === 'user' && v.filter?.identification !== undefined)
            )
              ctx.addIssue({
                code: 'custom',
                message:
                  'Use identification risk_bands for identifications and entity risk_bands for users.',
              });
          }),
        outputSchema: z.object({
          resource: z.enum(['identifications', 'user']),
          data: z.array(EntitySchema),
          next_page_token: z.string().nullable(),
          total: z.number().int().nonnegative().optional(),
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
          const { domain, type, response_format, limit, page_token, include_total, sort, filter } =
            args;
          const page = await reader.list(domain, type, {
            ...windowOptions(args, extra.signal),
            limit,
            ...(page_token === undefined ? {} : { page_token }),
            ...(include_total === undefined ? {} : { include_total }),
            ...(sort === undefined ? {} : { sort }),
            ...(filter === undefined
              ? {}
              : { filter: filter as NonNullable<EntityListOptions['filter']> }),
          });
          const data = page.data.map(entityView);
          return emit(
            { resource: type, ...page, data },
            response_format,
            [
              '# History entities',
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
  if (allowed(TOOL_NAMES.summarizeEntity))
    server.registerTool(
      TOOL_NAMES.summarizeEntity,
      {
        title: 'Read entity summary',
        description:
          'Read the API aggregate card for a user, visitor, device or IP. Preserve reported counts, availability and HRE. This does not enumerate or analyze individual identifications.',
        inputSchema: z
          .object({
            ...common,
            type: z.enum(['user', 'visitor', 'device', 'ip']),
            value: z
              .string()
              .min(1)
              .max(512)
              .describe('Exact entity ID for user, visitor, device or IP.'),
          })
          .strict()
          .superRefine(windowRange),
        outputSchema: z.object({
          entity: EntitySchema,
          computed_from: z.literal('API entity card'),
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
            await reader.get(args.domain, args.type, args.value, windowOptions(args, extra.signal)),
          );
          return emit(
            { entity, computed_from: 'API entity card' },
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
          const built = buildExplanation(await parseIdentificationInput(input!));
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
  const query = (options: EntityListOptions) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(options)) {
      if (k !== 'signal' && v !== undefined)
        q.set(k, k === 'filter' ? JSON.stringify(v) : String(v));
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
