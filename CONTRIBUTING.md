# Contributing

Questions and bug reports: open an issue or write to contact@shieldlabs.ai.

## Set up and validate

Use Node.js 20 or newer (Node.js 22 or newer for Workers tests).

```bash
npm ci
npm run bootstrap:sdk
npm run typecheck
npm run lint
npm test -- --coverage
npm run test:worker
npm run worker:check
npm run build
npm run smoke
npm pack --ignore-scripts
```

The published Node SDK 1.3.2 is pinned in package.json and package-lock.json and bundled into dist. No sibling checkout or private repository token is required. CI tests Node.js 20, 22 and 24 and runs Workers checks separately. Worker bundle checks do not upload or deploy code.

## Guidelines

- Use only public API routes. Hosted OAuth exposes 21 tools; local API-key modes remain read-only. Keep all tool names prefixed with shieldlabs_.
- Give each tool strict bounded inputs, output schemas, annotations and actionable errors. Destructive operations require confirmation and are not retried automatically.
- Keep History reads domain-scoped. Preserve nullable fields and availability; do not invent risk, weights, counts or identity proof. RFC3339 windows are half-open; page tokens must retain the same query.
- Treat API strings as untrusted data, escape invisible characters and bound output sizes. Never log keys, OAuth codes or secrets; credentials are masked by default.
- Hosted requests use OAuth tokens and signed public /mcp/v1 calls. Keep gateway secrets in the deployment environment; do not expose private dashboard routes.
- Code reachable from src/worker.ts uses Web APIs instead of Node.js modules. The worker bundle check enforces this. Keep token-cache entries scoped to the token hash.
- Add tests using deterministic fixtures and the mock backend. Tests do not use customer keys or live mutations.
- Use plain technical English and the three Risk Score bands: Trusted 0-29, Suspicious 30-59, Dangerous 60-100. High-Risk Events confidence is a separate axis.
- Use conventional commit messages.

## Releases

A maintainer pushes a v* tag matching package.json after CI passes. The release workflow repeats checks, builds and packs, installs the actual archive and runs a stdio smoke test before npm publication with provenance. Its npm environment holds NPM_TOKEN. Existing npm versions are not overwritten. This workflow does not deploy the hosted service or publish a container image.

server.json describes the npm package and hosted remote endpoint. Registry listing is a separate action; a repository or npm release does not imply an MCP Registry listing.

The integrate_shieldlabs prompt fetches the setup skill from the immutable skills release selected by SETUP_SKILL_REF in src/constants.ts. Publish and check that release before updating the pin.
