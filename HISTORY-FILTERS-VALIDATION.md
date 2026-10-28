# History filter validation

Date: 2026-10-28. Status: candidate implementation, not a production deployment.

## Contract

- Portal implementation: [development #771](https://github.com/ShieldLabs-ai/Shield.Portal.Admin/pull/771)
  and [main #772](https://github.com/ShieldLabs-ai/Shield.Portal.Admin/pull/772), merged.
- Public contract: [OpenAPI #31](https://github.com/ShieldLabs-ai/shieldlabs-openapi/pull/31), merged.
  The exact public parameter list is pinned in [the fixture](test/fixtures/history-filter-contract.json)
  and compared with the MCP schema in [tests](test/history-filters.test.ts).
- Candidate base is the existing `codex/current-contract-coverage` review branch. Review and merge
  its earlier contract changes first, then retarget this PR to main and review this delta.

## Behavior checked

Search and entity summary expose four optional date/score inputs plus 20 boolean flags.
Every predicate is AND-only inside one identifier and site. No filters preserves the previous
request and response shape. With filters, both response formats report the constraints.

The SDK 1.0.1 search method forwards only limit/offset and drops unknown options. The local
MCP therefore binds filters to an invocation-scoped HTTP fetch adapter. It reuses the same
budgeted fetch and SDK normalization/retry behavior; concurrent filter sets cannot leak.
Hosted requests include filters in the signed query without changing OAuth or the domain scope.

Tests cover every query name and true/false serialization, explicit zero, date/time formats,
invalid calendar days, nanosecond range comparison, inverted/out-of-bounds/fractional scores,
unsupported fields, combined score/flag predicates, filtered totals and empty results,
summary page propagation, simultaneous conflicting queries, unchanged unfiltered calls,
search-bot field semantics, marker 999, JSON/Markdown scope, and non-retried backend 400.
The signed-query cases run in Node and workerd against an independent signature verifier.

## Results

| Check | Result |
|---|---|
| Node tests with required coverage | 306 passed |
| Workers runtime tests | 31 passed |
| TypeScript, ESLint and formatting | Passed |
| Node build | Passed |
| Worker dry-run bundle | Passed; no Node built-in imports |
| Coverage, statements / branches / functions / lines | 95.54% / 91.03% / 95.90% / 96.57% |

New filter tests add 21 Node cases and 2 cases to the shared Workers suite. These are local
MCP-client and mock-upstream tests, not tests against production customer history.

## Errors found during this work

- SDK silently dropped filter options: handled by the scoped transport adapter, without
  claiming that application SDKs now support filters.
- Initial test compilation flagged possibly undefined entries in a test array; corrected.
- Initial documentation style check rejected en dashes; corrected.
- Sandboxed test runs could not bind local HTTP ports or write Wrangler logs. Full tests were
  rerun with loopback permission, and dry-run logs redirected to temporary files; passed.
- The package dry-run initially could not write the protected npm cache. It passed using a
  task-specific temporary cache, without changing global ownership or settings.

## Release and live acceptance still open

No merge, npm publication or deployment was performed. Production filtered reads are not
claimed: this candidate must first be reviewed, released and exercised on actual account data.
Use the client's normal OAuth flow for hosted acceptance, without extracting its credentials.
Compare unfiltered vs filtered total and rows for a known identifier on each selected domain;
check AND, false/zero, UTC boundaries, summary paging, search-bot and 999 where real rows exist.
Absent real examples do not count as exercised acceptance cases.

The contract still does not provide domain-wide enumeration, OR, country/campaign/HRE/identity
predicates, or every normalized output flag as a query field. Do not emulate them by scanning a
private dashboard endpoint, ignoring input, returning fake empty success, or labelling a
partial History window as complete site traffic.
