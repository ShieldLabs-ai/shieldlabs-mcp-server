# Current History contract validation

History uses public domain UUIDs and entity routes under /api/v1/domains/{domain}/history for API-key reads and /mcp/v1/domains/{domain}/history for hosted OAuth reads. Lists accept identifications and user; identification, user, visitor, device and ip cards require an ID.

## Inputs

- Filters are flat: risk_bands, hre_min_accounts, hre_min_devices, one User HID string in ids on the user list, risk_signals, source, campaign and the 20 boolean flags.
- from and to are paired RFC3339 timestamps with a half-open window. Pagination uses an opaque page_token with the same resource, window, filters and limit.
- Nested filter, chips, offset, include_total, sort and relation parameters are rejected before upstream I/O.
- banned_ip is the public signal. HTTP 429 retains its distinct rate_limited error code.
- The bundled published Node SDK is 1.3.2; its entity client forwards current query fields. Retired history.search methods are not used.

## Executable evidence

- test/entity-tools.test.ts exercises hosted and local paths, IDs, score bands, nullable fields, query forwarding, single ids validation, pagination and upstream failures.
- test/server.test.ts checks advertised tool schemas and exclusion of unsupported relation inputs.
- test/offline-tools.test.ts checks Explain behavior, including score_details when signals is empty.
- scripts/smoke-stdio.mjs checks the built executable against a deterministic fake API. SHIELDLABS_MCP_SMOKE_ENTRY selects an installed archive for the same smoke.
- Workers tests and the bundle check verify the public transport without deploying it.

Run the validation commands in CONTRIBUTING.md. Passing mocks proves client contract behavior; production ingestion and real webhook delivery require separate end-to-end checks.
