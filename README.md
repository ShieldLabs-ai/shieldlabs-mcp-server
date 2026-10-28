# ShieldLabs MCP server

Identification, risk signals and risk scoring through hosted OAuth MCP or a local server.

## How it fits

The browser SDK returns an identification ID. Your backend or AI assistant reads the result through the public History API, or receives a signed webhook. A UUID by itself does not prove that ingest succeeded.

Hosted OAuth offers **21 tools** for domain setup, webhook management and History reads. Local stdio and single-tenant API-key HTTP mode remain read-only and expose seven tools when both API credentials are configured. The [hosted operations reference](HOSTED-OPERATIONS.md) describes every operation.

## Install

Use an MCP client with a remote streamable HTTP server and OAuth:

```text
https://mcp.shieldlabs.ai/mcp
```

Sign in or register in the browser and approve the connection. If the client does not load new tools automatically, restart that client and continue the same conversation. Keep OAuth approval in the browser that started it.

For local stdio:

```json
{
  "mcpServers": {
    "shieldlabs": {
      "command": "npx",
      "args": ["-y", "@shieldlabs-ai/mcp"],
      "env": { "SHIELDLABS_API_KEY": "sec_your_server_key" }
    }
  }
}
```

## Quick start

1. Check the hosted connection and call `shieldlabs_list_domains`.
2. Use the selected domain's public UUID for every History read. A hostname is not a History selector.
3. Capture an actual browser identification ID. Read it with `shieldlabs_get_identification`, using `domain`, `identification_id` and optionally `wait:true`.
4. Read the returned card's `id`, `domain_id`, `risk.state`, `risk.score` and `signals.state`. An unavailable risk remains unknown; it is never substituted with Score 0.

```json
{"domain":"11111111-1111-4111-8111-111111111111","identification_id":"33333333-3333-4333-8333-333333333333","wait":true,"response_format":"json"}
```

## Guide

### Review one identification

`shieldlabs_get_identification` returns `{found:true, identification:card}`. Cards use `type:"identification"`, `id` and nested `risk`, not the legacy row format. `wait:true` retries reads of the same ID within a ten-second total deadline. It never starts another browser identification. Retry-After and cancellation are respected.

`shieldlabs_explain_risk_score` accepts a domain UUID plus `identification_id`, or a pasted identification. It preserves unknown risk and says when detailed signal weights are unavailable. It also accepts scored webhook payloads for offline explanation. Missing weights do not establish that nothing contributed to a nonzero score.

### List entities

`shieldlabs_search_history` lists `identifications` or `user` in a domain. It does not require a card ID:

```json
{"domain":"11111111-1111-4111-8111-111111111111","type":"identifications","limit":20,"response_format":"json"}
```

The result contains `data`, `next_page_token` and an optional API-provided `total`. Preserve the same resource, window, filter, sort and limit when passing `next_page_token` as `page_token`. Tokens are opaque. The server can invalidate them after a restart; do not silently merge a fresh traversal into an earlier snapshot.

Optional `from` and `to` are paired RFC3339 timestamps. The window includes `from` and excludes `to`. `filter` accepts one risk band per request; use `identification.risk_bands` for identifications and `entity.risk_bands` for users. Lists use the default newest-first sort; totals are available for identification lists. Read an exact entity through get/summarize:

```json
{"domain":"11111111-1111-4111-8111-111111111111","type":"identifications","filter":{"identification":{"risk_bands":["dangerous"]}},"from":"2026-10-27T00:00:00Z","to":"2026-10-28T00:00:00Z"}
```

The old `value`, `offset`, `score_from`, `score_to` and boolean row-search fields are rejected. Visitor, device and IP resources have cards, not lists.

### Read an account, device, visitor or IP card

`shieldlabs_summarize_entity` reads the backend aggregate card:

```json
{"domain":"11111111-1111-4111-8111-111111111111","type":"user","value":"exact-user-hid","response_format":"json"}
```

The result is `{entity:card, computed_from:"API entity card"}`. It preserves the API's identification count, risk, related counts and High-Risk Events availability. One card is not one identification, and it does not enumerate the underlying history. No client-computed account counts or band split are invented.

### Webhooks and setup

Hosted tools can create and verify a receiver, send a signed test, read delivery status, opt into `multiaccount` events and rotate credentials with confirmation. A sample test does not prove real delivery. HRE confidence is separate from Risk Score; unknown metadata does not imply a negative result.

Use `integrate_shieldlabs` to inspect the project and choose installation stages. `investigate_user` and `review_request` require an explicit domain UUID and only mention enabled tools. Server-side integrations read the domain-scoped public History API. Keep the public browser key separate from server credentials.

## Reference

### Local configuration

| Variable | Purpose |
|---|---|
| `SHIELDLABS_API_KEY` | Server-only Private API Key for entity History |
| `SHIELDLABS_API_BASE_URL` | Public History origin, default `https://account.shieldlabs.ai` |
| `SHIELDLABS_SECRET_KEY` | Optional Management API credential |
| `SHIELDLABS_DOMAIN` | Registered hostname for the optional Management profile, separate from the History UUID |
| `SHIELDLABS_MANAGEMENT_BASE_URL` | Optional Management origin |
| `SHIELDLABS_WEBHOOK_SECRET` | Optional secret for offline signature verification |
| `SHIELDLABS_MCP_TOKEN` | Bearer protection for local HTTP mode |

History requests require `domain` in tool input. Browser code must never receive the server key or webhook secret. Run `npx -y @shieldlabs-ai/mcp --help` for transport and tool allowlist options.

### Local tools

| Tool | Purpose |
|---|---|
| `shieldlabs_get_identification` | Read an identification card by ID and domain UUID |
| `shieldlabs_search_history` | List identifications or users with opaque pagination |
| `shieldlabs_summarize_entity` | Read a user, visitor, device or IP aggregate card |
| `shieldlabs_explain_risk_score` | Explain reported risk and weight availability |
| `shieldlabs_get_domain_profile` | Read and cache the optional Management profile |
| `shieldlabs_verify_webhook_signature` | Verify original bytes before interpreting a webhook |
| `shieldlabs_current_time` | Read UTC time for freshness checks |

### Local resources

The identification template is `shieldlabs://domains/{domain}/identifications/{identification_id}`. It reads the same entity API once. Static contract/reference resources distinguish scored webhook identifications from entity History cards.

### Local prompts

- `integrate_shieldlabs`: inspect the stack and configure the selected installation stages.
- `investigate_user`: read the supplied User HID's API aggregate card in one domain.
- `review_request`: read and assess one identification in one domain.

## Security

- Hosted requests use the user's OAuth grant and signed public `/mcp/v1` calls. Private dashboard API routes are never exposed through MCP.
- Every operation applies account/domain ownership. Foreign-domain responses are rejected by the client as well.
- Destructive operations require `confirm:true`. One-time credentials are masked unless an installer explicitly uses `include_secret:true`; MCP transcripts can record them. Store privately and never repeat them in chat.
- Browser text is untrusted data. Invisible controls are escaped for display; private/debug fields are stripped, secret-shaped text is masked and output sizes are bounded.
- Oversized History pages fail with a smaller-page request instead of dropping records behind an opaque cursor.
- Signature checks use original webhook bytes. A valid signature is separate from the truth or availability of fields in the event.

## Errors and retries

A missing identification or `risk.state:"unavailable"` is unverified. Do not turn it into a zero score or infer a billing cause from a missing row. Preserve the backend error code in diagnostic reports.

Read polling respects the total wait deadline, Retry-After and cancellation. A 400, 401, 403 or 410 is not healed by polling. A 404 for a fresh identification may be retried with the same ID. Never automatically retry a mutation whose result may already have been committed.

### Troubleshooting

| Symptom | Action |
|---|---|
| Only offline tools are listed | Configure `SHIELDLABS_API_KEY` in the local client and restart that client |
| A History read rejects a hostname | Use the public UUID from the domain list |
| `endpoint_retired` | Update the client to the domain-scoped entity History API |
| Pagination token rejected | Recheck the original query; a restart can invalidate tokens |
| `snapshot_unavailable` | Treat the read as unavailable and retry within a bounded read budget |
| OAuth rejected | Reconnect using the client's OAuth flow |
| A webhook test passes but no real event arrives | Check actual source generation and real signed delivery separately |

## Compatibility

Node.js 20, 22 and 24 are tested in CI. Transports are stdio and streamable HTTP, with resources and prompts. The current Node SDK entity client is pinned by commit in CI. Scored webhook normalization remains separate from entity History; older row-search SDK methods do not represent the current API.

## Build from source

Use Node.js 20 or later and Git. The SDK is bundled from an immutable public source commit:

```sh
npm ci
npm run bootstrap:sdk
npm run build
```

## Development

The tests exercise tools, resources, prompts, tenant isolation, gateway signatures, malformed
payloads, secret masking and response formatting against synthetic backends.

```sh
npm run test:worker
npm run worker:check
npm pack --dry-run
```

Production deployment automation and secrets are maintained separately. Source publication is
separate from a managed-service deployment or an official client-directory listing.

## License

[MIT](LICENSE). ShieldLabs Inc. Support: contact@shieldlabs.ai.

