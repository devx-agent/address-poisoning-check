# Changelog

## 1.1.0 (2026-10-30)

- The stdio MCP server (npm package, also what the Dockerfile runs) now registers its tools with `registerTool`, with a title, a longer description (what the tool does, when to use it and when not to, what it reads or sends, what it returns, limits), clearer parameter descriptions, a JSON output schema with `structuredContent`, and tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
- No change to the checks themselves, the hosted API, prices or payment flow. The remote MCP endpoint served by the Worker is unchanged in this release.
- `onchain_check_info` now describes the hosted check's chains as Ethereum and Base, with Avalanche optional, which matches the live API.

## 1.0.0 (2026-10-30)

- First release: CLI and stdio MCP server on npm (`devx-address-poisoning-check`), and the Cloudflare Worker behind the hosted API and remote MCP endpoint.
