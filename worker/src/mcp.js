// Minimal stateless MCP (Streamable HTTP, JSON responses) for the free check.
import { basic, isAddr } from "./core.js";
const TOOLS = [
  { name: "check_recipient_lookalike", description: "Free, offline, read-only: before sending crypto, check whether the recipient address is a lookalike (same first/last hex characters, different middle) of any address you trust, and whether its EIP-55 checksum is valid. Address poisoning stole $76M+ in 12 months by planting such lookalikes in wallet histories.",
    inputSchema: { type: "object", properties: { to: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$", description: "recipient you are about to pay" }, known: { type: "array", items: { type: "string" }, maxItems: 50, description: "addresses you trust (address book, previous real payees)" } }, required: ["to"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: "onchain_check_info", description: "How to buy the on-chain check (scans the sender's real transfer history on Ethereum/Base/Avalanche for poisoning transfers and lookalikes) via x402 for 0.005 USDC. Does not pay.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
];
const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
async function handle(m, origin) {
  const { id, method, params } = m || {};
  if (id === undefined || id === null) return null;
  if (method === "initialize") return ok(id, { protocolVersion: (params && params.protocolVersion) || "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "devx-address-poisoning-check", version: "1.0.0" }, instructions: "Address-poisoning check before sending crypto. Read-only; never asks for keys." });
  if (method === "ping") return ok(id, {});
  if (method === "tools/list") return ok(id, { tools: TOOLS });
  if (method === "tools/call") {
    const name = params && params.name, a = (params && params.arguments) || {};
    if (name === "onchain_check_info") return ok(id, { content: [{ type: "text", text: `GET ${origin}/v1/check?from=<sending wallet>&to=<recipient>[&chains=ethereum,base,avalanche] answers HTTP 402 (x402 v1 body + v2 PAYMENT-REQUIRED header): exact, Base USDC, 5000 units = 0.005 USDC. Settled only after the report is produced. Docs ${origin}/openapi.json` }] });
    if (name === "check_recipient_lookalike") {
      const to = String(a.to || "").trim(); const known = Array.isArray(a.known) ? a.known.map(String).slice(0, 50) : [];
      if (!isAddr(to)) return ok(id, { isError: true, content: [{ type: "text", text: "to must be 0x + 40 hex characters" }] });
      const bad = known.find((k) => !isAddr(k)); if (bad) return ok(id, { isError: true, content: [{ type: "text", text: "invalid known address" }] });
      const r = basic(to, known); r.onchain_check = `${origin}/v1/check?from=<your wallet>&to=${to.toLowerCase()}`;
      return ok(id, { content: [{ type: "text", text: `Verdict: ${r.verdict}. ${r.note}\n\n` + JSON.stringify(r) }], structuredContent: r });
    }
    return err(id, -32602, "unknown tool");
  }
  return err(id, -32601, "method not found");
}
export async function mcp(req, origin) {
  const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-expose-headers": "mcp-session-id" };
  if (req.method === "GET") return new Response(JSON.stringify({ name: "devx-address-poisoning-check", transport: "streamable-http (POST JSON-RPC)", tools: TOOLS.map((t) => t.name) }), { status: 200, headers: H });
  if (req.method !== "POST") return new Response(null, { status: 405, headers: H });
  let body; try { body = await req.json(); } catch { return new Response(JSON.stringify(err(null, -32700, "parse error")), { status: 400, headers: H }); }
  if (Array.isArray(body)) { const out = (await Promise.all(body.map((m) => handle(m, origin)))).filter(Boolean); return out.length ? new Response(JSON.stringify(out), { headers: H }) : new Response(null, { status: 202, headers: H }); }
  const r = await handle(body, origin);
  return r ? new Response(JSON.stringify(r), { headers: H }) : new Response(null, { status: 202, headers: H });
}
