import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkRecipient, DEFAULT_BASE } from "./index.js";
export const VERSION = "1.1.0";
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

export function createServer() {
  const server = new McpServer({ name: "devx-address-poisoning-check", version: VERSION }, {
    instructions: "Before an agent or user sends crypto to an address that was pasted, copied from history or taken from a message, call check_recipient_lookalike with that recipient and the addresses you trust. It catches address-poisoning lookalikes and mistyped checksums. It runs locally, sends nothing, never asks for keys and cannot move funds. onchain_check_info only describes the optional paid hosted check; it does not pay.",
  });

  server.registerTool("check_recipient_lookalike", {
    title: "Check a recipient for address poisoning",
    description: [
      "Compares the EVM address you are about to pay with addresses you trust and checks its EIP-55 checksum, to catch address-poisoning lookalikes before a transfer.",
      "Address poisoning: attackers send tiny or zero-value transfers from an address that shares the first and last hex characters with one of your real payees, hoping you copy it from your history. Use this tool before every transfer to an address that was pasted or copied, especially from wallet or explorer history.",
      "Offline and deterministic: nothing leaves the machine, no RPC calls, no keys, no signing.",
      "Rules: a lookalike shares at least 3 leading and 3 trailing hex characters with a trusted address (or 8 in total with at least 2 on each side) but is not identical. A mixed-case address whose EIP-55 checksum fails is treated as altered or mistyped. All-lowercase or all-uppercase input has no checksum (checksum_valid null).",
      "Returns: verdict (match = identical to a trusted address; danger = lookalike of a trusted address or invalid checksum: do not send; unknown = no match and no lookalike, which only means it is not similar to the addresses you supplied), a note, checksum_valid, compared, matches, lookalikes (address, shared_prefix, shared_suffix, shown_as) and onchain_check (URL of the paid history-based check).",
      "This tool only knows the addresses you pass in. To scan the sending wallet's real on-chain transfer history for poisoning transfers, see onchain_check_info.",
    ].join(" "),
    inputSchema: {
      to: z.string().regex(ADDR).describe("The recipient you are about to send to: 0x followed by 40 hex characters. Pass it exactly as copied, keeping its letter case, so the EIP-55 checksum can be checked."),
      known: z.array(z.string().regex(ADDR)).max(200).default([]).describe("Up to 200 addresses you trust, for example the address book and previous real payees, each 0x + 40 hex. With an empty list only the checksum is checked."),
    },
    outputSchema: {
      to: z.string().describe("recipient, lowercased"), checksum_valid: z.boolean().nullable().describe("true valid, false invalid, null when the input has no checksum (single case)"),
      compared: z.number().describe("number of trusted addresses compared"), matches: z.array(z.string()),
      lookalikes: z.array(z.object({ address: z.string(), shared_prefix: z.number(), shared_suffix: z.number(), shown_as: z.string() })),
      verdict: z.enum(["match", "danger", "unknown"]), note: z.string(), onchain_check: z.string(),
    },
    annotations: RO,
  }, async ({ to, known }) => {
    try { const r = checkRecipient(to, known); return { structuredContent: r, content: [{ type: "text", text: `Verdict: ${r.verdict}. ${r.note}\n\n${JSON.stringify(r)}` }] }; }
    catch (e) { return { isError: true, content: [{ type: "text", text: String(e.message || e) }] }; }
  });

  server.registerTool("onchain_check_info", {
    title: "How to buy the on-chain poisoning check",
    description: [
      "Returns the endpoint, price and payment method of the optional paid hosted check. It does not call the API and does not pay or sign anything.",
      "The paid check reads the sending wallet's real transfer history on Ethereum and Base (optionally Avalanche), finds poisoning transfers (zero-value, dust or fake-token transfers from lookalike addresses) and returns a verdict ok | caution | danger, the address you probably meant, and evidence transaction hashes. It costs 0.005 USDC on Base via x402.",
      "Use it when you have no trusted address list to pass to check_recipient_lookalike, or when check_recipient_lookalike returns unknown for a recipient copied from transaction history.",
      "Returns: method, url_template, price_usdc, network, asset, protocol, chains, settles and docs.",
    ].join(" "),
    inputSchema: {},
    outputSchema: { method: z.string(), url_template: z.string(), price_usdc: z.number(), network: z.string(), asset: z.string(), protocol: z.string(), chains: z.array(z.string()), settles: z.string(), docs: z.string() },
    annotations: RO,
  }, async () => {
    const info = { method: "GET", url_template: `${DEFAULT_BASE}/v1/check?from=<sending wallet>&to=<recipient>`, price_usdc: 0.005, network: "eip155:8453 (Base)", asset: "USDC", protocol: "x402 (HTTP 402 with a v1 JSON body and a v2 PAYMENT-REQUIRED header; any x402 client can pay)", chains: ["ethereum", "base", "avalanche (optional)"], settles: "only after the report is produced", docs: `${DEFAULT_BASE}/openapi.json` };
    return { structuredContent: info, content: [{ type: "text", text: JSON.stringify(info) }] };
  });
  return server;
}
