# Hosted OAuth MCP operations

The hosted server exposes 21 tools. Source availability does not imply deployment: verify the deployed dev and production endpoints separately. Every operation uses the authenticated account and only public API routes.

## Tool inputs

Domain and webhook identifiers are public UUIDs. History `domain` is a UUID, not a hostname.

| Tool | Inputs |
|---|---|
| `shieldlabs_check_connection` | none |
| `shieldlabs_list_domains` | none |
| `shieldlabs_get_domain` | domain_id |
| `shieldlabs_add_domain` | domain hostname, optional allow_subdomains and include_secret |
| `shieldlabs_patch_domain` | domain_id, enabled and/or allow_subdomains; disabling requires confirm=true |
| `shieldlabs_delete_domain` | domain_id, confirm=true |
| `shieldlabs_rotate_server_key` | domain_id, confirm=true, optional include_secret |
| `shieldlabs_list_webhooks` | domain_id |
| `shieldlabs_get_webhook` | domain_id, webhook_id |
| `shieldlabs_create_webhook` | domain_id, name, url, optional multiaccount and include_secret |
| `shieldlabs_patch_webhook` | domain_id, webhook_id, name/url/multiaccount; URL change requires confirm=true |
| `shieldlabs_delete_webhook` | domain_id, webhook_id, confirm=true |
| `shieldlabs_enable_webhook` | domain_id, webhook_id |
| `shieldlabs_disable_webhook` | domain_id, webhook_id, confirm=true |
| `shieldlabs_rotate_webhook_secret` | domain_id, webhook_id, confirm=true, optional include_secret |
| `shieldlabs_verify_webhook` | domain_id, webhook_id |
| `shieldlabs_test_webhook` | domain_id, webhook_id |
| `shieldlabs_get_identification` | domain UUID, identification_id, optional wait and paired from/to |
| `shieldlabs_search_history` | domain UUID, type=identifications/user, optional limit, page_token, from/to, sort, include_total, filter |
| `shieldlabs_summarize_entity` | domain UUID, type=user/visitor/device/ip, value, optional paired from/to |
| `shieldlabs_explain_risk_score` | identification_id with domain UUID, or a pasted identification |

Webhook names are trimmed and bounded to 80 Unicode characters. URLs require public HTTPS without credentials and are bounded to 512 UTF-8 bytes. Omitted patch fields are preserved. A subscription-only patch does not change the endpoint. Pure IPv6 is refused locally; IPv4-mapped IPv6 is normalized to IPv4 for IP cards.

## History output

The list API is `/mcp/v1/domains/{domain}/history/{resource}`. It returns `data`, opaque `next_page_token` and an optional total. A card is `/mcp/v1/domains/{domain}/history/{resource}/{id}` and returns `data:card`. Cards contain `type`, `id`, `domain_id`, `domain`, `risk` and `signals`; other fields follow the public entity schema.

MCP get returns `{found:true, identification:card}`. List returns `{resource, data, next_page_token, total?}`. Summary returns `{entity:card, computed_from:"API entity card"}`. Explanation preserves `risk` and sets `weights_available:false` when a card does not include detailed signal weights. No aggregate is recomputed from a single card.

An available identification score is `risk.score` with `risk.state:"ok"`. `risk.state:"unavailable"` remains unknown, never 0. `signals.state` and `high_risk_events.state` remain as returned. HRE confidence is separate from Risk Score. Missing flags or client identity are not false/human evidence.

Lists support identifications and user only. Optional RFC3339 from/to must both be supplied; the window includes from and excludes to. Keep query fields unchanged while paging. Use page_token, never offset. Old value-based search and boolean row filters are rejected before requests. Filter by one risk band: `identification.risk_bands` for identifications or `entity.risk_bands` for users. Only the default newest-first sort is supported. Totals can be requested for identifications. Exact entity IDs are read with get/summarize.

## Resources and prompts

The domain-scoped identification resource uses the same validated card. `investigate_user` and `review_request` require a domain UUID. Setup guidance names only available operations and does not infer a backend verdict from a computed count.

## Credentials, retries and verification

Domain/server and webhook credentials are masked. An installer can explicitly opt in to one-time credentials; the client can record them in transcripts. Store privately and do not repeat them. Mutations are not automatically retried; verify state before manually repeating an uncertain write.

History reads preserve scope and returned IDs, reject malformed states, bound output and respect cancellation, Retry-After and a total read deadline. Oversized pages require a smaller limit rather than truncating rows while reusing an end-of-page cursor.

A signed sample test, verification ping and real event delivery are separate checks. A multiaccount subscription does not prove source generation. Validate real group delivery separately from ordinary scored events. The stdio/API-key server uses the same entity contract through `/api/v1`, without OAuth management operations.
