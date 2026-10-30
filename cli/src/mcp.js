import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkRecipient, DEFAULT_BASE } from "./index.js";
export function createServer() {
  const server = new McpServer({ name: "devx-address-poisoning-check", version: "1.0.0" }, { instructions: "Before sending crypto, check the recipient for address poisoning (lookalike of an address you trust, bad EIP-55 checksum). Runs offline; never asks for keys." });
  server.tool("check_recipient_lookalike", "Free, offline: is the recipient a lookalike (same first/last hex chars, different middle) of any trusted address, and is its EIP-55 checksum valid? Call before every transfer to a pasted or copied address.",
    { to: z.string().regex(/^0x[0-9a-fA-F]{40}$/).describe("recipient you are about to pay"), known: z.array(z.string().regex(/^0x[0-9a-fA-F]{40}$/)).max(200).default([]).describe("trusted addresses: address book, previous real payees") },
    async ({ to, known }) => { try { const r = checkRecipient(to, known); return { content: [{ type: "text", text: `Verdict: ${r.verdict}. ${r.note}\n\n${JSON.stringify(r)}` }] }; } catch (e) { return { isError: true, content: [{ type: "text", text: String(e.message || e) }] }; } });
  server.tool("onchain_check_info", "How to buy the hosted on-chain check that scans the sender's real transfer history (Ethereum, Base, Avalanche) for poisoning transfers and lookalikes: x402, 0.005 USDC on Base. Does not pay.", {},
    async () => ({ content: [{ type: "text", text: `GET ${DEFAULT_BASE}/v1/check?from=<sending wallet>&to=<recipient> returns HTTP 402 (x402 v1 body + v2 PAYMENT-REQUIRED header), 5000 units USDC on Base = 0.005 USDC. Settled only after the report is produced. Docs: ${DEFAULT_BASE}/openapi.json` }] }));
  return server;
}
