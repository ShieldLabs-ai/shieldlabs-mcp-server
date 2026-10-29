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

### List History

`shieldlabs_list_history` lists `identifications` or `user` in a domain. It does not require a card ID:

```json
{"domain":"11111111-1111-4111-8111-111111111111","resource":"identifications","limit":20,"response_format":"json"}
```

The result contains `data` and `next_page_token`. Preserve the same resource, window and flat filters when passing `next_page_token` as `page_token`. Tokens are opaque. The server can invalidate them after a restart; do not silently merge a fresh traversal into an earlier snapshot.

Optional `from` and `to` are paired RFC3339 timestamps. The window includes `from` and excludes `to`. Filters are flat fields: `risk_bands`, `hre_min_accounts` (3-99), `hre_min_devices` (4-99), `ids` on the user list, `risk_signals`, `source`, `campaign` and boolean flags such as `is_vpn`. Nested `filter`, `chips`, `offset`, `include_total` and `sort` are rejected.

```json
{"domain":"11111111-1111-4111-8111-111111111111","resource":"identifications","risk_bands":["dangerous"],"is_vpn":true,"from":"2026-10-27T00:00:00Z","to":"2026-10-28T00:00:00Z"}
```

Visitor, device and IP resources have cards, not lists.

### Read one History card

`shieldlabs_get_history` reads one identification, user, visitor, device or ip card:

```json
{"domain":"11111111-1111-4111-8111-111111111111","resource":"user","resource_id":"exact-user-hid","response_format":"json"}
```

The result is `{resource, entity}`. It preserves the API's identification count, risk, related counts and High-Risk Events availability. One card is not one identification, and it does not enumerate the underlying history. Card reads also accept `device_id_source`, `relation`, `relation_limit` and `relation_page_token`.

### Webhooks and setup

Hosted tools can create and verify a receiver, send a signed test, read delivery status, opt into `multiaccount` events and rotate credentials with confirmation. A sample test does not prove real delivery. HRE confidence is separate from Risk Score; unknown metadata does not imply a negative result.

Use `integrate_shieldlabs` to inspect the project and choose installation stages. `investigate_user` and `review_request` require an explicit domain UUID and only mention enabled tools. Server-side integrations use the Node SDK's current `entities` client. Keep the public browser key separate from server credentials.

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
| `shieldlabs_list_history` | List identifications or users with opaque pagination |
| `shieldlabs_get_history` | Read one identification, user, visitor, device or ip card |
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

## Deploy the hosted server

The hosted mode (`--mode public`) serves many users from one server: every request brings the
access token of its user's sign-in, which the ShieldLabs account API checks before the server
answers. A merge to `development` installs that process on the dev droplet. A merge to
`main` installs it on H3. It does not deploy a Cloudflare
Worker, and a tag does not publish the npm package or the container image. The public
`shieldlabs-mcp` repository owns those.

| Path | Answer |
|---|---|
| `POST /mcp` | MCP over streamable HTTP (stateless, JSON responses, one JSON-RPC message per request: a batch gets `400`). Without a token: `401` with `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource/mcp"`, which starts the sign-in. A token the account API refuses, or any credential that is not a ShieldLabs access token: `401` with `error="invalid_token"` added. Over the rate limits: `429`; when the token cannot be checked: `503`; when the account API refuses this server's signature: `500` |
| `GET /.well-known/oauth-protected-resource/mcp`, `GET /.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728): the resource `<origin>/mcp`, the authorization server, `bearer_methods_supported: ["header"]`. No scopes: the ShieldLabs authorization server has none |
| `GET /health` | `{"status":"ok","version":"..."}` without authentication and without a call to the account API |

How a token is checked: the server sends `GET /mcp/v1/ping` to the account API with the token and
an `X-Shield-Gateway: v1 kid=<key ID> t=<unix seconds> n=<nonce> sig=<signature>` header. The
signature is the unpadded base64url HMAC-SHA256, with the secret of the gateway key, of `v1`, the
time, the nonce, the method, the path with its query and the lowercase hex SHA-256 of the token,
one per line. The account API accepts it for 60 seconds either way and refuses a nonce it has
seen, so every request gets 16 fresh random bytes. A `200` lets the request through and is
remembered for 60 seconds under the SHA-256 of the token; refusals are never remembered. The
`shieldlabs_check_connection` always pings again, and every other operation independently
revalidates the live token and account ownership through its signed backend request.

| Variable | Default | Purpose |
|---|---|---|
| `SHIELDLABS_PUBLIC_ORIGIN` | required | Origin that clients connect to, for example `https://dev.mcp.shieldlabs.ai`. The resource, and the audience of the access tokens, is its `/mcp` path |
| `SHIELDLABS_PORTAL_URL` | required | Origin of the ShieldLabs account API that checks every token, for example `https://account.shieldlabs.ai`. It has no default, so that a server for one environment never asks another |
| `SHIELDLABS_AUTH_ISSUER` | `SHIELDLABS_PORTAL_URL` | Authorization server named in the metadata |
| `MCP_GATEWAY_KEY` | required, secret | `kid:secret`, the entry for this server in `MCP_GATEWAY_KEYS` of the account API of the same environment (a key ID of 1 to 32 letters, digits, `.`, `_` or `-`, and a secret of at least 32 bytes). Without it every request gets a `500` |

All URLs must use https, except on `localhost`, `127.0.0.1` and `[::1]`. The server never logs a
token, the gateway secret or a signature: every request writes one JSON line with the route, the
JSON-RPC method and tool name, the status, the duration, 8 hex characters of the token hash and
how the token was checked.

### Development droplet

[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) runs on a push to `development` and on a
manual rerun of that ref. It installs the built server on `dev-shield-admin-node-0`. The process listens on
`127.0.0.1:8787`. nginx serves `https://dev.mcp.shieldlabs.ai`. The gateway key is the GitHub
Environment secret `MCP_GATEWAY_KEY`, not a file in git.

### Production host

[`.github/workflows/production.yml`](.github/workflows/production.yml) runs on a push to `main`.
It builds the checksummed bundle and, in the `Production` environment, copies it to H3 and runs
`deploy/production/install.py`. The workflow does not receive the gateway key. The host must
already be `prod-shield-0` with `/etc/shieldlabs-mcp-production.env`, the `mcp.shieldlabs.ai`
certificate, and an accepted account backend. A pull request only builds the artifact.

`wrangler.jsonc` keeps local Worker settings and has no custom domain. Do not run `wrangler deploy`.
`npm run worker:check` only bundles the Worker and does not upload it.

Domain, History and webhook tools call the public `/mcp/v1` API. The connection probe uses
`GET /mcp/v1/ping`; reading a domain or a record is a separate verification step.

### Process

The droplet starts `node dist/index.js --transport http --mode public --host 127.0.0.1 --port 8787 --trust-proxy`.
It speaks plain HTTP. nginx terminates TLS and is the only proxy that can reach the port.
Rate limits are kept in memory per process, and request logs go to stdout, one JSON line per
request. This repository does not push a container image.

The per-address limits use the address of each TCP connection, which behind a proxy is the
proxy's for every client. Add `--trust-proxy` to take the client address from `CF-Connecting-IP`
instead: the proxy must then set that header on every request, replacing any value the client
sent. Cloudflare sets it; with nginx, use `proxy_set_header CF-Connecting-IP $remote_addr;`.

## Development

```bash
npm ci
# Until @shieldlabs-ai/node is published, build its tarball in a checkout of shieldlabs-node:
(cd ../shieldlabs-node && npm ci && npm pack)
npm install --no-save ../shieldlabs-node/shieldlabs-ai-node-1.0.0.tgz
npm run typecheck
npm run lint
npm test -- --coverage
npm run build
node dist/index.js --help
npm run smoke            # the built server over stdio against the fake History API
npm run test:worker      # the hosted mode in workerd (Node.js 22 or later)
npm run worker:check     # the Worker bundle: no Node.js built-in module, size limit
```

`@shieldlabs-ai/node` is bundled into `dist/` at build time, so the published package depends only on
`@modelcontextprotocol/sdk` and `zod`.

### Fake History API

`scripts/mock-history-api.mjs` serves a deterministic dataset (`test/mock-data/`, generated by
`scripts/generate-mock-data.mjs`) as a fake History API and Management API:

```bash
npm run build
node scripts/mock-history-api.mjs --port 8788
# in another terminal: the MCP Inspector CLI passes environment variables with -e
npx @modelcontextprotocol/inspector --cli node dist/index.js \
  -e SHIELDLABS_API_KEY=sec_evaldata-mockdata-00000001 \
  -e SHIELDLABS_API_BASE_URL=http://127.0.0.1:8788 \
  --method tools/list
```

`npm run smoke` does the same without extra downloads: it starts the fake API, runs the built
server over stdio with the MCP SDK client and calls its tools, resources and prompts.

See [CONTRIBUTING.md](CONTRIBUTING.md). Documentation: [docs.shieldlabs.ai](https://docs.shieldlabs.ai).
Support: [contact@shieldlabs.ai](mailto:contact@shieldlabs.ai).

## License

[MIT](LICENSE)

