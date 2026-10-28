import type { ToolName } from '../constants.js';
import {
  SETUP_SKILL_CACHE_MS,
  SETUP_SKILL_MAX_BYTES,
  SETUP_SKILL_TIMEOUT_MS,
  SETUP_SKILL_URL,
} from '../constants.js';
import type { GuideResponse, ServerContext } from '../context.js';

/** Concise integration guide used when the published setup skill cannot be fetched. */
export const BUILT_IN_SETUP_GUIDE = `# Integrate ShieldLabs (built-in guide)

Inspect the project and reuse existing configuration. Follow https://shieldlabs.ai/get-started.md
and the setup skill at https://github.com/ShieldLabs-ai/skills when available.

Show an evidence-based progress map before editing: account/MCP, domain coverage, browser SDK,
stored result and selected server/user-linking/HRE/webhook stages. Mark verified, needs check,
pending, not selected or blocked. On resume inspect current code and read state; do not repeat
verified work or mutations. Inventory production/staging/preview hostnames and inspect parent
allow_subdomains; separate keys are an isolation choice, not mandatory child registration.

## Guided stages

Ask whether the user has an account only when unknown and no authenticated connection exists.
State the proposed scope and reuse authorization already given; do not ask before each file or
package. A general install starts with browser identification and a verified first result. Then
ask what to do next, offering only unfinished server verification, signed webhooks, signed-in
user linking/account checks, or finish. Run only selected stages, verify each and return to the
remaining choices. Already selected later stages need no repeated question. Ask for a backend
repo path or an authorized webhook receiver only when missing. Stop after finish; resolve failed
verification before moving on. Browser-only identification does not prove server-side protection.

## 1. Account and domain

Use the managed OAuth MCP connection by default. Give the user the fresh authorization URL:
they sign in or create a ShieldLabs account and approve access in their browser. Wait for approval;
keep the flow in one browser and restart an expired flow. Never request passwords or OAuth codes.
If MCP is unavailable or the user chooses the dashboard, use https://app.shieldlabs.ai to sign in
or register and add or select the domain. Do one setup path, then continue.

Configure a Public Key for browser code and a Private API Key for the backend. Keep .env ignored
and secrets out of chat, logs and frontend bundles. OAuth authenticates MCP, while the app's SDK
uses its own domain keys. Do not automatically rotate an existing masked key.

## 2. Browser

Detect the framework and install its matching browser SDK. Verify the installed types before writing code.
Use the plain JavaScript package when no framework is present:

\`\`\`ts
import { load } from '@shieldlabs-ai/js';
// Call from the selected action handler; never await it at the top level.
async function identifyAction() {
  const agent = await load({ publicKey: publicKeyFromEnvironment });
  const { identificationId } = await agent.identify();
  return identificationId; // Pass with the action to your existing backend.
}
\`\`\`

The agent loads from https://cdn.shieldlabs.ai. Follow the documented CSP. Test on the registered
HTTPS hostname. A browser UUID alone does not prove that the identification was accepted.
Only add User HID linking when required; compute it on the server with the SDK helper.

For order or promo context, store server-authoritative action references in the application's
own database, scoped by tenant/domain and identification UUID. Reconcile either webhook/action
arrival order. Do not invent an SDK tag. Group HRE events have no identification UUID.

## 3. Existing backend

\`\`\`ts
// Run only on the backend. The domain is the public UUID from MCP or the dashboard.
const domainId = process.env.SHIELDLABS_DOMAIN_ID!;
const endpoint = new URL(
  '/api/v1/domains/' + encodeURIComponent(domainId) + '/history/identifications/' + encodeURIComponent(identificationId),
  'https://account.shieldlabs.ai',
);
const response = await fetch(endpoint, {
  headers: { Authorization: 'Bearer ' + process.env.SHIELDLABS_API_KEY! },
  signal: AbortSignal.timeout(5000), redirect: 'error', cache: 'no-store',
});
if (!response.ok) throw new Error('Identification could not be verified');
const { data: card } = await response.json();
if (card.id !== identificationId || card.domain_id !== domainId || card.type !== 'identification')
  throw new Error('Identification scope does not match');
// Atomically claim card.id for replay protection and check card.created_at freshness.
// Only use card.risk.score when card.risk.state === 'ok'.
// Keep signals/HRE availability as returned. An unavailable risk is unverified.
\`\`\`

Missing, stale or replayed results are unverified. Risk bands are Trusted 0-29, Suspicious 30-59
and Dangerous 60-100; 999 is a rate-limit marker. Never reconstruct the score by adding weights.
If no backend exists, install the browser integration and verify through MCP or the dashboard.
Do not invent a backend or put private keys in browser code.

## 4. Webhooks, when requested

Verify X-Shield-Signature against the original bytes with the server SDK before parsing.
Deduplicate using the verified envelope's opaque event_id; it is separate from the identification
UUID. Store privately or enqueue the verified event and respond promptly. Verify is a receiver
check; Test is a sample delivery. Neither proves that a real scored identification was delivered.

## 5. Verify

Trigger one fresh visit or protected action. Capture its actual browser identificationId and
read the same UUID through MCP (identification_id with wait=true) or the dashboard, and through the
backend when configured. Scoring is asynchronous: wait within the supported budget and retry
boundedly if still pending. Inspect Risk Score, flags, hostname and timestamps. Empty detailed
weights do not mean a zero score. Report each check as passed, failed or not configured; never
claim a sample Test event or a synthetic fixture proves a real integration.

## Optional backend HRE and client identity

Consume backend account_sharing/account_takeover/impossible_travel status, reason and level
when present; do not substitute a custom History count. Multi-account group transitions are
separate hre.multi_account.changed events without a Risk Score or identification UUID. If
selected, configure multiaccount through the current MCP schema, read it back and verify the
receiver plus real emission. Release profiles may disable this capability. Queue both scored
and group envelopes, deduplicate signed event_id atomically and compare group revisions as
UInt64 decimal strings within site/epoch/cluster scope. Keep resolved tombstones.

Keep client_identity claims distinct from verified subjects and evidence. Provider proof does
not prove an agent/service. Missing/null metadata is unknown, not human. The MCP projection is
bounded; warnings mean evidence may be incomplete. Retain route-specific access controls.

`;
export interface SetupGuide {
  text: string;
  /** Where the text came from: the skill URL, or "built-in". */
  source: string;
}

/** Remote guides must not instruct the client to call tools this server does not expose. */
function usesEnabledTools(text: string, ctx: ServerContext): boolean {
  const names = text.match(/\bshieldlabs_[a-z][a-z0-9_]*\b/g) ?? [];
  return names.every((name) => ctx.enabledTools.has(name as ToolName));
}

/**
 * The body as UTF-8 text, or undefined when it is larger than `maxBytes`. A streamed body is read
 * only up to the limit and then cancelled.
 */
export async function readCappedText(
  response: GuideResponse,
  maxBytes: number,
): Promise<string | undefined> {
  const body = response.body;
  if (body === undefined || body === null) {
    const text = await response.text();
    return Buffer.byteLength(text, 'utf8') > maxBytes ? undefined : text;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * The published setup skill, pinned to the skills release of this server version, fetched with a
 * short timeout and a size limit and cached for an hour. Falls back to the built-in guide when
 * offline mode is on (always over HTTP) or the fetch fails.
 */
export async function loadSetupGuide(ctx: ServerContext): Promise<SetupGuide> {
  const builtIn: SetupGuide = { text: BUILT_IN_SETUP_GUIDE, source: 'built-in' };
  if (ctx.config.offline || ctx.guideFetch === undefined) return builtIn;

  const now = ctx.now();
  if (ctx.guideCache !== undefined && now - ctx.guideCache.fetchedAt < SETUP_SKILL_CACHE_MS) {
    return usesEnabledTools(ctx.guideCache.value.text, ctx) ? ctx.guideCache.value : builtIn;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SETUP_SKILL_TIMEOUT_MS);
  try {
    const response = await ctx.guideFetch(SETUP_SKILL_URL, {
      signal: controller.signal,
      headers: { Accept: 'text/plain, text/markdown' },
    });
    if (!response.ok) return builtIn;
    const text = await readCappedText(response, SETUP_SKILL_MAX_BYTES);
    if (text === undefined || text.trim() === '') return builtIn;
    // Fall back as a whole: deleting arbitrary Markdown lines can damage a code sample or
    // leave an incomplete workflow. The built-in guide uses the SDK without requiring tools.
    if (!usesEnabledTools(text, ctx)) return builtIn;
    const guide = { text, source: SETUP_SKILL_URL };
    ctx.guideCache = { value: guide, fetchedAt: now };
    return guide;
  } catch {
    return builtIn;
  } finally {
    clearTimeout(timer);
  }
}
