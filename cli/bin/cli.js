#!/usr/bin/env node
import { checkRecipient, onchainPrice } from "../src/index.js";
const args = process.argv.slice(2);
if (args[0] === "mcp") {
  const { createServer } = await import("../src/mcp.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  await createServer().connect(new StdioServerTransport());
} else if (!args.length || args[0] === "-h" || args[0] === "--help") {
  process.stdout.write(`Usage:
  devx-address-poisoning-check <recipient> --known 0xA,0xB [--json]   offline lookalike + checksum check
  devx-address-poisoning-check onchain <from> <to>                     price/URL of the hosted on-chain check (does not pay)
  devx-address-poisoning-check mcp                                     run as an MCP server (stdio)
Exit codes: 0 match/unknown, 2 danger, 1 error. Never asks for keys.
`);
} else if (args[0] === "onchain") {
  try { process.stdout.write(JSON.stringify(await onchainPrice(args[1], args[2]), null, 2) + "\n"); } catch (e) { process.stderr.write(e.message + "\n"); process.exitCode = 1; }
} else {
  const ki = args.indexOf("--known"); const known = ki >= 0 ? String(args[ki + 1] || "").split(/[\s,]+/).filter(Boolean) : [];
  const json = args.includes("--json");
  try { const r = checkRecipient(args[0], known); process.stdout.write(json ? JSON.stringify(r, null, 2) + "\n" : `${r.verdict.toUpperCase()}: ${r.note}\n${r.lookalikes.map((l) => "  lookalike of " + l.address).join("\n")}\n`); process.exitCode = r.verdict === "danger" ? 2 : 0; }
  catch (e) { process.stderr.write(e.message + "\n"); process.exitCode = 1; }
}
