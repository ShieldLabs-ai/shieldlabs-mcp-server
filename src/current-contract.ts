import type { Identification } from '@shieldlabs-ai/node';
import { z } from 'zod';
import {
  CURRENT_DETECTION_FLAG_KEYS,
  type CurrentDetectionFlagKey,
} from './catalog/detection-flags.js';
import { cutSerialized, escapeInvisible } from './format.js';

/** Accept legacy input names; return canonical keys and null for unavailable signals. */
export function currentFlags(
  raw: Record<string, unknown>,
): Record<CurrentDetectionFlagKey, boolean | null> {
  const nested = record(raw.detection_flags);
  const history = nested === undefined;
  const values = nested ?? raw;
  const aliases: Record<CurrentDetectionFlagKey, string[]> = {
    vpn: ['is_vpn'],
    proxy: ['is_proxy'],
    private_relay: ['privacy_relay', 'is_privacy_relay', 'is_private_relay'],
    tor: ['is_tor'],
    check_incomplete: ['check_incomplete', 'is_check_incomplete'],
    network_check_incomplete: [
      'stun_not_checked',
      'is_stun_not_checked',
      'is_network_check_incomplete',
    ],
    os_not_detected: ['is_os_not_detected'],
    timezone_mismatch: ['is_timezone_mismatch'],
    javascript_disabled: ['is_js_disabled'],
    os_mismatch: ['is_os_mismatch'],
    ip_mismatch: ['is_ip_mismatch'],
    latency_test: ['is_latency_test', 'is_ws_tcp_latency', 'ws_tcp_latency'],
    anti_detect_browser: ['is_antidetect'],
    device_spoofing: ['is_device_spoof', 'is_device_spoofing'],
    banned_ip: [],
    incognito: ['is_incognito'],
    search_bot: ['is_search_bot'],
    ai_bot: ['is_ai_bot'],
    browser_automation: ['is_browser_automation'],
    ai_browser: ['is_ai_browser'],
  };
  const result = Object.fromEntries(
    CURRENT_DETECTION_FLAG_KEYS.map((key) => {
      for (const name of [key, ...aliases[key]]) {
        const value = own(values, name);
        if (typeof value === 'boolean') return [key, value];
      }
      return [key, null];
    }),
  ) as Record<CurrentDetectionFlagKey, boolean | null>;
  // These are documented derivations for the legacy History shape, not negative defaults.
  if (history && (raw.connection_type === 'browser_vpn_proxy' || raw.is_browser_vpn_proxy === true))
    result.vpn = true;
  if (history && raw.is_os_mismatch2 === true) result.os_mismatch = true;
  if (result.banned_ip === null && (raw.score === 999 || raw.risk_score === 999))
    result.banned_ip = true;
  return result;
}

export function identificationFlags(item: Identification) {
  const flags = currentFlags(item.raw);
  if (flags.ip_mismatch === null && item.source === 'history') {
    if (
      flags.search_bot === true ||
      flags.ai_bot === true ||
      flags.ai_browser === true ||
      flags.vpn === true ||
      item.connection_type === 'vpn'
    )
      flags.ip_mismatch = false;
    else {
      const row = item.raw;
      const leak =
        typeof row.webrtc_leak_source === 'string' &&
        row.webrtc_leak_source.trim() !== '' &&
        row.webrtc_leak_source.trim() !== 'none';
      const localCountry = leak ? row.webrtc_leak_country : row.web_rtc_country;
      const localIp = leak ? row.webrtc_leak_ip : row.web_rtc_ip;
      if (
        [row.ip, localIp, row.country, localCountry].every(
          (v) => typeof v === 'string' && v.trim() !== '' && v !== '0.0.0.0',
        )
      )
        flags.ip_mismatch =
          String(row.country).trim().toLowerCase() !== String(localCountry).trim().toLowerCase();
    }
  }
  return flags;
}

function own(value: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(value, key) ? value[key] : undefined;
}
function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

const text = z.string().nullable().optional();
const texts = z.array(z.string().nullable()).nullable().optional();
const HreResultSchema = z.object({
  status: z.string(),
  level: z.string().nullable(),
  reason: z.string(),
  devices: z.number().int().nonnegative().optional(),
  min_devices: z.number().int().positive().optional(),
  cluster_id: text,
});
export const HreSchema = z.object({
  rules_version: text,
  account_sharing: HreResultSchema.optional(),
  account_takeover: HreResultSchema.optional(),
  impossible_travel: HreResultSchema.optional(),
});
export const ClientIdentitySchema = z.object({
  schema_version: text,
  classification_revision: z.number().int().positive().nullable().optional(),
  classifier_version: text,
  registry_revision: text,
  availability: text,
  observed_at: text,
  decided_at: text,
  claims: z
    .array(
      z
        .object({
          profile_id: text,
          provider_id: text,
          provider_name: text,
          agent_name: text,
          client_kind: text,
          purpose: text,
          source: text,
        })
        .nullable(),
    )
    .nullable()
    .optional(),
  verified: z
    .array(z.object({ subject: text, value_id: text, evidence_ids: texts }).nullable())
    .nullable()
    .optional(),
  assessments: z
    .array(z.object({ candidate_profile_id: text, status: text, reason: text }).nullable())
    .nullable()
    .optional(),
  evidence: z
    .array(
      z
        .object({
          id: text,
          method: text,
          source_id: text,
          source_revision: text,
          checked_at: text,
          evaluated_at: text,
          covered_attributes: texts,
          covered_components: texts,
          request_binding: text,
          replay_policy: text,
        })
        .nullable(),
    )
    .nullable()
    .optional(),
});
export const CurrentMetadataShape = {
  hre: HreSchema.nullable().optional(),
  client_identity: ClientIdentitySchema.nullable().optional(),
  search_bot_owner: text,
  ai_bot_owner: text,
  ai_browser_owner: text,
  contract_warnings: z.array(z.string()).optional(),
};
export interface MetadataChanges {
  truncated: string[];
  escaped: string[];
}
export type CurrentMetadata = z.infer<z.ZodObject<typeof CurrentMetadataShape>>;

function bounded(value: unknown, path: string, changes: MetadataChanges): unknown {
  if (typeof value === 'string') {
    const escaped = escapeInvisible(value);
    if (escaped !== value) changes.escaped.push(path);
    const cut = cutSerialized(escaped, 160);
    if (cut !== escaped) changes.truncated.push(path);
    return cut;
  }
  if (Array.isArray(value)) {
    if (value.length > 5) changes.truncated.push(path);
    return value.slice(0, 5).map((v, i) => bounded(v, `${path}[${i}]`, changes));
  }
  const obj = record(value);
  if (obj)
    return Object.fromEntries(
      Object.entries(obj).map(([key, v]) => [key, bounded(v, `${path}.${key}`, changes)]),
    );
  return value;
}

/** Reduce projected arrays until the metadata budget fits; the cut paths are always reported. */
function fitBudget(value: unknown, path: string, changes: MetadataChanges, budget: number): void {
  const arrays: { values: unknown[]; path: string }[] = [];
  const visit = (v: unknown, p: string) => {
    if (Array.isArray(v)) {
      arrays.push({ values: v, path: p });
      v.forEach((entry, i) => visit(entry, `${p}[${i}]`));
    } else if (record(v))
      for (const [key, entry] of Object.entries(v as Record<string, unknown>))
        visit(entry, `${p}.${key}`);
  };
  visit(value, path);
  while (JSON.stringify(value).length > budget) {
    arrays.sort((a, b) => JSON.stringify(b.values).length - JSON.stringify(a.values).length);
    const target = arrays.find((a) => a.values.length > 0);
    if (!target) break;
    target.values.pop();
    if (!changes.truncated.includes(target.path)) changes.truncated.push(target.path);
  }
}

/** Allowlisted, bounded public projection. Never return arbitrary upstream or raw SDK fields. */
export function currentMetadata(
  raw: Record<string, unknown>,
  changes: MetadataChanges,
): CurrentMetadata {
  const result: CurrentMetadata = {};
  const warnings: string[] = [];
  for (const key of [
    'hre',
    'client_identity',
    'search_bot_owner',
    'ai_bot_owner',
    'ai_browser_owner',
  ] as const) {
    let value = own(raw, key);
    if (value === undefined) continue;
    if (value === null) {
      Object.assign(result, { [key]: null });
      continue;
    }
    if (
      (key === 'hre' || key === 'client_identity') &&
      typeof value === 'string' &&
      value.length <= 65_536
    ) {
      try {
        value = JSON.parse(value) as unknown;
      } catch {
        /* Report unavailable below. */
      }
    }
    const schema =
      key === 'hre' ? HreSchema : key === 'client_identity' ? ClientIdentitySchema : z.string();
    const parsed = schema.safeParse(value);
    if (!parsed.success) {
      Object.assign(result, { [key]: null });
      warnings.push(
        `${key} was present but did not match the supported public shape; unavailable, not a negative result.`,
      );
      continue;
    }
    const previousCuts = changes.truncated.length;
    const previousEscapes = changes.escaped.length;
    const safe = bounded(parsed.data, key, changes);
    fitBudget(safe, key, changes, key === 'hre' ? 3_000 : 6_000);
    Object.assign(result, { [key]: safe });
    if (changes.truncated.length > previousCuts)
      warnings.push(
        `${key} was shortened for display; this projection is incomplete. Read the verified original for decisions.`,
      );
    if (changes.escaped.length > previousEscapes)
      warnings.push(
        `${key} contained control or invisible characters; displayed values are escaped.`,
      );
  }
  if (warnings.length) result.contract_warnings = warnings;
  return result;
}
