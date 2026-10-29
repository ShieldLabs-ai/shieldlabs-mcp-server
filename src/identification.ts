import { type Identification } from '@shieldlabs-ai/node';
import { z } from 'zod';
import { bandOf } from './catalog/bands.js';
import { canonicalSignalName } from './catalog/risk-signals.js';
import { CURRENT_DETECTION_FLAG_KEYS } from './catalog/detection-flags.js';
import { currentMetadata, CurrentMetadataShape, identificationFlags } from './current-contract.js';
import {
  cutSerialized,
  escapeInvisible,
  MAX_SIGNAL_NAME_LENGTH,
  MAX_VALUE_LENGTH,
} from './format.js';
import { nullableString } from './schema.js';

const IpInfoSchema = z.object({
  ip: z.string().describe('Dotted IPv4 address, or "" when none is known'),
  country: z.string().describe('English country name (for example "Germany"), or "" when unknown'),
});

const flagShape = Object.fromEntries(
  CURRENT_DETECTION_FLAG_KEYS.map((flag) => [
    flag,
    z
      .boolean()
      .nullable()
      .describe('null means unavailable in the returned public profile, not a negative result'),
  ]),
) as Record<(typeof CURRENT_DETECTION_FLAG_KEYS)[number], z.ZodNullable<z.ZodBoolean>>;

export const RiskBandSchema = z.enum(['trusted', 'suspicious', 'dangerous', 'rate_limited']);

/** More risk signals than this on one identification only come from a malformed payload. */
export const MAX_SIGNALS_PER_IDENTIFICATION = 50;

/**
 * Identification as returned by this server's tools: the normalized model without `raw`, with
 * `risk_band` added and `signals[].description` always null.
 */
export const IdentificationOutputSchema = z.object({
  identification_id: z.string(),
  visitor_id: z.string(),
  device_id: z.string(),
  session_id: z.string(),
  cookie_id: z.string(),
  user_hid: nullableString(
    'User HID as sent by the browser: "anonymous" for anonymous checks, null when it was empty',
  ),
  domain: z.string(),
  public_ip: IpInfoSchema,
  local_ip: IpInfoSchema,
  connection_type: z.string(),
  os: z.string(),
  browser: z.string(),
  device_type: z.string(),
  traffic_source: z.object({
    channel: z.string(),
    referrer_domain: z.string(),
    landing_url: z.string(),
    click_id_type: z.string(),
    utm_source: z.string(),
    utm_medium: z.string(),
    utm_campaign: z.string(),
    utm_content: z.string(),
    utm_term: z.string(),
  }),
  risk_score: z
    .number()
    .int()
    .nullable()
    .describe('Null when the History card says the risk is unavailable. That is not a score of 0.'),
  risk_band: RiskBandSchema.nullable().describe(
    'Null when risk_score is null. 0 is the trusted band, not an unknown score.',
  ),
  signals: z.array(
    z.object({
      name: z.string(),
      weight: z.number().int(),
      description: nullableString('Always null: internal score-detail text is not returned'),
    }),
  ),
  detection_flags: z.object(flagShape),
  ...CurrentMetadataShape,
  observed_at: nullableString(
    'When the identification was observed, RFC 3339 UTC with milliseconds',
  ),
  source: z.enum(['webhook', 'history']),
  truncated_fields: z
    .array(z.string())
    .optional()
    .describe(
      `Only present when this server shortened values: paths of the fields cut to ${MAX_VALUE_LENGTH} characters as serialized in JSON (${MAX_SIGNAL_NAME_LENGTH} for risk signal names), and "signals" when only the first ${MAX_SIGNALS_PER_IDENTIFICATION} risk signals are listed. A shortened value is a prefix of the stored one: do not search by it.`,
    ),
  escaped_fields: z
    .array(z.string())
    .optional()
    .describe(
      'Only present when a value contained invisible or control characters: paths of the fields where this server replaced them with visible \\uXXXX or \\u{XXXXX} escapes. Such a value differs from the stored one: do not search by it.',
    ),
});

export type IdentificationOutput = z.infer<typeof IdentificationOutputSchema>;

/** Where a value was changed for output: escaped characters, a cut, or both. */
interface Changes {
  truncated: string[];
  escaped: string[];
}

/**
 * A string value made safe to show: invisible and control characters become visible escapes, and
 * the result is cut to `max` characters as serialized in JSON. Changes are recorded under `path`.
 */
function boundValue(value: string, path: string, max: number, changes: Changes): string {
  const escaped = escapeInvisible(value);
  if (escaped !== value) changes.escaped.push(path);
  const cut = cutSerialized(escaped, max);
  if (cut !== escaped) changes.truncated.push(path);
  return cut;
}

/** Copies `obj`, bounding every string value (see boundValue) and recording the changed paths. */
function boundStrings<T extends object>(obj: T, prefix: string, max: number, changes: Changes): T {
  const copy = { ...obj } as Record<string, unknown>;
  for (const [key, value] of Object.entries(copy)) {
    if (typeof value === 'string') copy[key] = boundValue(value, `${prefix}${key}`, max, changes);
  }
  return copy as T;
}

/**
 * The tool view of an identification: every normalized field except `raw`, plus the band. Values
 * reported by browsers (User HID, landing URL, UTM values) can hold any text of any length, so
 * invisible and control characters are escaped (listed in `escaped_fields`) and long values are
 * cut (listed in `truncated_fields`): one identification always fits in a response and cannot
 * hide text from the person reading it.
 */
export function toIdentificationOutput(identification: Identification): IdentificationOutput {
  const { raw, identification_id: sdkRequestId, ...rest } = identification;
  const changes: Changes = { truncated: [], escaped: [] };
  const rawRisk =
    raw !== null && typeof raw === 'object' && 'risk' in raw && isRiskRecord(raw.risk)
      ? raw.risk
      : null;
  const scoreUnknown =
    rawRisk !== null &&
    (rawRisk.state === 'unavailable' || typeof rawRisk.score !== 'number') &&
    raw.type === 'identification';
  // A known integer stays. An entity card with unavailable risk stays null, not 0.
  const score = scoreUnknown
    ? null
    : Number.isFinite(rest.risk_score)
      ? Math.trunc(rest.risk_score)
      : 0;
  const signals = rest.signals.slice(0, MAX_SIGNALS_PER_IDENTIFICATION);
  const output: IdentificationOutput = {
    ...boundStrings(rest, '', MAX_VALUE_LENGTH, changes),
    public_ip: boundStrings(rest.public_ip, 'public_ip.', MAX_VALUE_LENGTH, changes),
    local_ip: boundStrings(rest.local_ip, 'local_ip.', MAX_VALUE_LENGTH, changes),
    traffic_source: boundStrings(rest.traffic_source, 'traffic_source.', MAX_VALUE_LENGTH, changes),
    identification_id: boundValue(
      (typeof raw.identification_id === 'string' ? raw.identification_id : '') ||
        (raw.type === 'identification' && typeof raw.id === 'string' ? raw.id : '') ||
        sdkRequestId,
      'identification_id',
      MAX_VALUE_LENGTH,
      changes,
    ),
    detection_flags: identificationFlags(identification),
    ...currentMetadata(identification.raw, changes),
    risk_score: score,
    risk_band: score === null ? null : bandOf(score),
    // History rows carry internal score-detail text in `description`; it is not meant to be
    // shown to users, so this server returns the slug and weight only (as webhooks do).
    signals: signals.map((signal, index) => ({
      name: boundValue(
        canonicalSignalName(signal.name),
        `signals[${index}].name`,
        MAX_SIGNAL_NAME_LENGTH,
        changes,
      ),
      weight: Math.trunc(signal.weight),
      description: null,
    })),
  };
  // Metadata adds optional evidence to already bounded legacy rows. Keep one projected row small
  // enough for get/search/resource responses, even when every upstream display field is oversized.
  if (JSON.stringify(output).length > 18_000) {
    for (const [key, value] of Object.entries(output)) {
      if (typeof value === 'string')
        Object.assign(output, { [key]: boundValue(value, key, 300, changes) });
    }
    output.public_ip = boundStrings(output.public_ip, 'public_ip.', 300, changes);
    output.local_ip = boundStrings(output.local_ip, 'local_ip.', 300, changes);
    output.traffic_source = boundStrings(output.traffic_source, 'traffic_source.', 300, changes);
  }
  if (signals.length < rest.signals.length) changes.truncated.push('signals');
  if (changes.truncated.length > 0) output.truncated_fields = [...new Set(changes.truncated)];
  if (changes.escaped.length > 0) output.escaped_fields = [...new Set(changes.escaped)];
  return output;
}

function isRiskRecord(value: unknown): value is { state?: unknown; score?: unknown } {
  return value !== null && typeof value === 'object';
}
