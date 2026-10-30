# Address Poisoning Check

**Is this the address you meant?** Address poisoning plants a lookalike address (same first and last characters, different middle) in a wallet's history with a zero-value, dust or fake-token transfer, and waits for the owner (or their AI agent) to copy it. Bitquery counted about **$76M stolen on Ethereum alone in the 12 months to July 2026**.

This repo has three pieces, all read-only (we never ask for keys and never move funds):

| | What | Cost |
|---|---|---|
| **CLI / stdio MCP** `devx-address-poisoning-check` | Offline: is the recipient a lookalike of any address you trust? Is its EIP-55 checksum valid? Nothing leaves your machine. | free |
| **Remote MCP** `https://address-poisoning-check.nextill-pos.workers.dev/mcp` | Same offline check as a hosted MCP tool | free |
| **HTTP API** `GET /v1/check?from=<sender>&to=<recipient>` | On-chain: scans the sender's real transfer history (Ethereum + Base, optional Avalanche) and flags lookalikes of real counterparties, zero-value / dust / fake-token poisoning transfers (with tx hashes), recipients that only ever appeared through such transfers, and senders that were already poisoned. Returns `ok \| caution \| danger` and the address you probably meant. | 0.005 USDC via [x402](https://x402.org) on Base |

Live: https://address-poisoning-check.nextill-pos.workers.dev

## CLI

```sh
npx devx-address-poisoning-check 0xd9A1C3788D81257612E2581A6ea0aDa244853a91 --known 0xd9A1b0B1e1aE382DbDc898Ea68012FfcB2853a91
# DANGER: Looks like 0xd9a1...3a91 (same first 4 / last 6 hex chars) but is a different address. Classic address-poisoning lookalike.
```

Exit code `2` on danger, so it can gate scripts and agent payment flows.

## MCP

Claude Desktop / Cursor (stdio):

```json
{ "mcpServers": { "address-poisoning-check": { "command": "npx", "args": ["-y", "devx-address-poisoning-check", "mcp"] } } }
```

Or remote (streamable HTTP): `https://address-poisoning-check.nextill-pos.workers.dev/mcp`

Tools: `check_recipient_lookalike` (free), `onchain_check_info` (how to buy the on-chain check; does not pay).

## Paid on-chain check (x402)

```
GET https://address-poisoning-check.nextill-pos.workers.dev/v1/check?from=0x...&to=0x...[&chains=ethereum,base,avalanche]
```

* Answers `402` with an x402 v1 body (`X-PAYMENT`, network `base`) and a v2 `PAYMENT-REQUIRED` header (`PAYMENT-SIGNATURE`, `eip155:8453`). Both work.
* 5000 atomic USDC (0.005 USDC) to `0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247`, settled through the Coinbase CDP facilitator, listed in the CDP x402 Bazaar.
* Settled only **after** the report is produced; bad input or data-source errors are not charged.
* Data: Ethereum/Avalanche via the Routescan explorer API (last 300 token transfers + 150 transactions of the sender); Base via public RPC logs (about the last 4-5 days of USDC, USDbC, USDT, EURC, WETH, cbBTC transfers). It is a heuristic over a window of public data: always confirm the full address with the payee.

Example (the May 2024 $68M WBTC case): `from=0x1E227979f0b5BC691a70DEAed2e0F39a6F538FD5&to=0xd9A1C3788D81257612E2581A6ea0aDa244853a91` returns `danger` / `possibly_already_poisoned`: the victim did send real value to that address, but it first appeared in their history through a zero-value transfer.

OpenAPI: [/openapi.json](https://address-poisoning-check.nextill-pos.workers.dev/openapi.json) · Terms: [/terms](https://address-poisoning-check.nextill-pos.workers.dev/terms)

## Related DevX tools

* [7702 Sweeper Check](https://github.com/devx-agent/7702-sweeper-check): is an EIP-7702 sweeper delegation set on a wallet?
* [Crypto Link Check](https://github.com/devx-agent/crypto-link-check): is a crypto URL a phishing / drainer lookalike?
* [Repo Run Check](https://github.com/devx-agent/repo-run-check): is a GitHub repo safe to clone and run?

## Layout

* `cli/`: npm package `devx-address-poisoning-check` (CLI + stdio MCP), `npm test`
* `worker/`: the Cloudflare Worker behind the hosted API (`npm run build`)

MIT. Made by [DevX](https://madebydevx.com) · madebydevx@gmail.com
