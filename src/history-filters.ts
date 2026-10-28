import type { FetchLike } from '@shieldlabs-ai/node';
import { z } from 'zod';

/** Public History query names, not the normalized detection_flags catalog. */
export const HISTORY_FLAG_PARAMS = [
  'is_vpn',
  'is_tor',
  'is_proxy',
  'is_datacenter',
  'is_abuser',
  'is_privacy_relay',
  'is_stun_not_checked',
  'check_incomplete',
  'is_antidetect',
  'is_os_mismatch',
  'is_os_not_detected',
  'is_timezone_mismatch',
  'is_js_disabled',
  'is_browser_automation',
  'is_incognito',
  'is_search_bot',
  'is_suspicious_paid_click',
] as const;

function validDate(value: string): boolean {
  const match = /^(\d{4}-\d{2}-\d{2})(?: (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?)?$/.exec(value);
  if (!match) return false;
  const day = new Date(`${match[1]}T00:00:00Z`);
  return (
    !Number.isNaN(day.getTime()) &&
    day.toISOString().slice(0, 10) === match[1] &&
    (match[2] === undefined ||
      (Number(match[2]) < 24 && Number(match[3]) < 60 && Number(match[4]) < 60))
  );
}

/** Compare at nanosecond precision without Date truncating fractional seconds. */
function instant(value: string, end: boolean): string {
  if (value.length === 10) return `${value} ${end ? '23:59:59.999000000' : '00:00:00.000000000'}`;
  const [seconds, fraction = ''] = value.split('.');
  return `${seconds}.${fraction.padEnd(9, '0')}`;
}

const date = z
  .string()
  .max(29)
  .refine(
    validDate,
    'Expected a real UTC date YYYY-MM-DD or YYYY-MM-DD HH:MM:SS with up to 9 fractional digits; no T, Z or timezone offset',
  );
const flags = Object.fromEntries(
  HISTORY_FLAG_PARAMS.map((name) => [
    name,
    z
      .boolean()
      .optional()
      .describe(
        `AND constraint on public History ${name}. Omit to leave unconstrained; false is explicit.${['check_incomplete', 'is_js_disabled', 'is_incognito'].includes(name) ? ' Always false for search bots, matching the API row.' : ''}`,
      ),
  ]),
) as Record<(typeof HISTORY_FLAG_PARAMS)[number], z.ZodOptional<z.ZodBoolean>>;

export const HistoryFilterShape = {
  from: date
    .optional()
    .describe(
      'Inclusive UTC start. Date-only means start of day; exact time uses a space, not T/Z.',
    ),
  to: date
    .optional()
    .describe(
      'Inclusive UTC end. Date-only means 23:59:59.999 of that day; exact time uses a space, not T/Z.',
    ),
  score_from: z
    .number()
    .int()
    .min(0)
    .max(999)
    .optional()
    .describe(
      'Inclusive minimum raw score, 0-999. 0 is a real bound; 999 is a rate-limit marker, not a Risk Score. For dangerous use 60-100.',
    ),
  score_to: z
    .number()
    .int()
    .min(0)
    .max(999)
    .optional()
    .describe('Inclusive maximum raw score, 0-999. Use 100 to exclude rate-limit marker 999.'),
  ...flags,
};
export const HistoryFiltersSchema = z.object(HistoryFilterShape).strict();
export type HistoryFilters = z.infer<typeof HistoryFiltersSchema>;

export function historyFilterRanges(value: HistoryFilters, ctx: z.RefinementCtx): void {
  if (
    value.from !== undefined &&
    value.to !== undefined &&
    validDate(value.from) &&
    validDate(value.to) &&
    instant(value.from, false) > instant(value.to, true)
  ) {
    ctx.addIssue({
      code: 'custom',
      path: ['to'],
      message: 'to must not be before from (inclusive UTC bounds)',
    });
  }
  if (
    value.score_from !== undefined &&
    value.score_to !== undefined &&
    value.score_from > value.score_to
  ) {
    ctx.addIssue({
      code: 'custom',
      path: ['score_to'],
      message: 'score_to must not be below score_from',
    });
  }
}

export function historyFilters(input: HistoryFilters): HistoryFilters {
  return Object.fromEntries(
    Object.keys(HistoryFilterShape).flatMap((key) => {
      const value = input[key as keyof HistoryFilters];
      return value === undefined ? [] : [[key, value]];
    }),
  );
}

export function appendHistoryFilters(query: URLSearchParams, filters: HistoryFilters): void {
  for (const [key, value] of Object.entries(historyFilters(filters))) query.set(key, String(value));
}

export function historyFilterNote(filters: HistoryFilters | undefined): string[] {
  return filters === undefined || Object.keys(filters).length === 0
    ? []
    : [
        `Filters (AND, within this identifier and domain): ${JSON.stringify(filters)}. Totals and aggregates describe this filtered history, not all activity.`,
        '',
      ];
}

/** SDK 1.0.1 drops unknown SearchOptions. Bind filters to a per-call client, never shared state. */
export function filteredHistoryFetch(fetch: FetchLike, filters: HistoryFilters): FetchLike {
  return (address, init) => {
    const url = new URL(address);
    if (url.pathname.startsWith('/api/v1/history/'))
      appendHistoryFilters(url.searchParams, filters);
    return fetch(url.toString(), init);
  };
}
