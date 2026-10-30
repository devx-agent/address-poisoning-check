import { facilitate, facilitatorConfig } from "../shared/facilitator.js";
import { basic, full, isAddr, CHAINS } from "./core.js";
import PAGE from "./page.html";
import { mcp } from "./mcp.js";

const VERSION = "1.0.0";
const SERVICE = "DevX Address Poisoning Check";
const PAY_TO = "0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247";
const FACILITATOR = "Coinbase CDP facilitator (api.cdp.coinbase.com/platform/v2/x402)";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PRICE = "5000"; // 0.005 USDC per check
const ROUTE = "/v1/check";
const SITE = "https://address-poisoning-check.nextill-pos.workers.dev";
const DESC = "Address-poisoning check before an agent or wallet sends crypto: pass the sending wallet and recipient; we scan the sender's real on-chain history (Ethereum, Base, optional Avalanche) and flag lookalike recipients, zero-value/dust/fake-token poisoning transfers and bad EIP-55 checksums. Returns ok|caution|danger, the address you probably meant, and evidence tx hashes.";
const enc = new TextEncoder();
const b64 = (o) => btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))));
const unb64 = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0))));
const EXAMPLE = { from: "0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5", to: "0xd9a1c3788d81257612e2581a6ea0ada244853a91", verdict: "danger", findings: [{ level: "high", code: "possibly_already_poisoned", msg: "You already sent real value to this address, but it first appeared in your history via a zero-value transfer..." }], probably_meant: null, poisoning_attempts_on_sender: { count: 2, distinct_lookalikes: 2 } };

function requirements() { return { scheme: "exact", network: "eip155:8453", amount: PRICE, asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: "USD Coin", version: "2" } }; }
function advertised(resUrl) { return { ...requirements(), maxAmountRequired: PRICE, resource: resUrl, description: DESC, mimeType: "application/json" }; }
function paymentRequired(origin, error, resUrl) {
  resUrl = resUrl || origin + ROUTE;
  return { x402Version: 2, error: error || "PAYMENT-SIGNATURE header is required",
    resource: { url: resUrl, description: DESC, mimeType: "application/json", serviceName: SERVICE, tags: ["security", "address-poisoning", "wallet", "agents", "payments", "x402"] },
    accepts: [advertised(resUrl)],
    extensions: { bazaar: { info: { input: { type: "http", method: "GET", discoverable: true, queryParams: { from: EXAMPLE.from, to: EXAMPLE.to } }, output: { type: "json", example: EXAMPLE } },
      schema: { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object", properties: { input: { type: "object", properties: { type: { type: "string", const: "http" }, method: { type: "string", enum: ["GET"] }, discoverable: { type: "boolean" }, queryParams: { type: "object", properties: { from: { type: "string", description: "sending wallet 0x address" }, to: { type: "string", description: "intended recipient 0x address" }, chains: { type: "string", description: "comma list of ethereum,base,avalanche (default ethereum,base)" } }, required: ["from", "to"] } }, required: ["type", "method"] }, output: { type: "object" } }, required: ["input"] } } } };
}

// X402_COMPAT_V1: serve x402 v1 body (network "base") + v2 PAYMENT-REQUIRED header; accept v1 X-PAYMENT and v2 PAYMENT-SIGNATURE; accept POST JSON.
const POST_KEY = "to", POST_MODE = "join";
function v1Requirements(resUrl) { return { scheme: "exact", network: "base", maxAmountRequired: PRICE, resource: resUrl, description: DESC, mimeType: "application/json", payTo: PAY_TO, maxTimeoutSeconds: 120, asset: USDC_BASE, outputSchema: { input: { type: "http", method: "GET", discoverable: true, queryParams: { from: { type: "string", required: true, description: "sending wallet" }, to: { type: "string", required: true, description: "intended recipient" }, chains: { type: "string", required: false } } }, output: { type: "object" } }, extra: { name: "USD Coin", version: "2" } }; }
function v1Body(pr) { const resUrl = pr.resource.url; return { x402Version: 1, error: (pr.error && pr.error !== "PAYMENT-SIGNATURE header is required") ? pr.error : "X-PAYMENT header is required (x402 v1) or PAYMENT-SIGNATURE (x402 v2, see PAYMENT-REQUIRED header)", accepts: [v1Requirements(resUrl)], resource: pr.resource, extensions: pr.extensions }; }
function uaFamily(ua) { ua = (ua || "").toLowerCase(); for (const [k, re] of [["x402_sdk", /x402|coinbase|cdp|agentcash|payai/], ["monitor", /monitor|uptime|bot|crawl|spider|scan|probe|check/], ["axios", /axios/], ["python", /python|httpx|aiohttp/], ["curl", /curl|wget/], ["go", /go-http/], ["node", /node|undici/], ["browser", /mozilla/]]) if (re.test(ua)) return k; return ua ? "other" : "none"; }
async function postToParams(req, url) {
  if (req.method !== "POST") return null;
  let b; try { b = await req.json(); } catch { return { error: "POST body must be JSON, e.g. {\"from\": \"0x..\", \"to\": \"0x..\"}" }; }
  for (const [k, alts] of [["from", ["from", "wallet", "sender"]], ["to", ["to", "recipient", "address"]], ["chains", ["chains"]]]) { for (const a of alts) if (b && b[a] != null) { url.searchParams.set(k, Array.isArray(b[a]) ? b[a].join(",") : String(b[a])); break; } }
  return null;
}
const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE" };
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o, null, 2), { status, headers: { ...H, ...h } });
// CDP_SWITCH: Coinbase CDP facilitator when CDP_API_KEY_ID/SECRET secrets are set (lists in CDP x402 Bazaar), else PayAI.
let ENV = {};
async function facil(op, body) { const r = await facilitate(ENV, op, body); r._st = r._status; delete r._status; if (!r.isValid && !r.success) console.log(JSON.stringify({ ev: "facil_" + op, st: r._st, r: JSON.stringify(r).slice(0, 300) })); return r; }
function parseQ(url) {
  const from = (url.searchParams.get("from") || "").trim(), to = (url.searchParams.get("to") || "").trim();
  if (!isAddr(from) || !isAddr(to)) return { error: "from and to query parameters required (0x + 40 hex each)" };
  const chains = [...new Set((url.searchParams.get("chains") || "ethereum,base").toLowerCase().split(/[\s,]+/).filter(Boolean))];
  const bad = chains.find((c) => !CHAINS.includes(c)); if (bad) return { error: "unsupported chain: " + bad + " (use " + CHAINS.join(",") + ")" };
  return { from, to, chains };
}

const TERMS = `${SERVICE} - Terms of Service (v${VERSION}, effective 2026-10-30)
Operator: DevX / Made by DevX (madebydevx.com), contact madebydevx@gmail.com.
1. Service. Read-only analysis of public blockchain data. GET /api/basic?to=0x..&known=0x..,0x.. (free) compares a recipient with addresses you supply (lookalike + EIP-55 checksum, offline). GET ${ROUTE}?from=0x..&to=0x.. (paid) scans the sender's recent public transfer history (Ethereum and Avalanche via the Routescan explorer API: last 300 token transfers + 150 transactions; Base via public RPC: about the last 4-5 days of USDC, USDbC, USDT, EURC, WETH, cbBTC transfers) and reports lookalikes, zero-value/dust/fake-token poisoning transfers and a verdict. We never ask for keys and never move funds.
2. Price. 0.005 USDC per paid call, x402 "exact" on Base, paid to ${PAY_TO}, settled through ${FACILITATOR}.
3. Not charged on error. Payment is settled only after the report is produced. Invalid input or a data-source error returns an error and the authorization is not settled.
4. Refunds. If you were charged but got no report, email madebydevx@gmail.com with the Base tx hash within 30 days; verified cases are refunded in USDC on Base.
5. Not a guarantee. Heuristics over a limited window of public data. "ok" does not prove an address is right; always confirm the full address with the payee.
6. Data. We do not store queried addresses beyond Cloudflare's standard request logs.
7. Changes. Material changes bump the version; the price in the live 402 response is authoritative.`;

function docs(origin) {
  return { openapi: "3.1.0", info: { title: SERVICE, version: VERSION, description: DESC, termsOfService: origin + "/terms", contact: { name: "DevX", email: "madebydevx@gmail.com", url: "https://madebydevx.com" } },
    servers: [{ url: origin }],
    paths: {
      "/api/basic": { get: { summary: "Free, offline: is `to` a lookalike of any `known` address? Also EIP-55 checksum", parameters: [{ name: "to", in: "query", required: true, schema: { type: "string" } }, { name: "known", in: "query", required: false, schema: { type: "string" }, description: "comma-separated trusted addresses (max 50)" }], responses: { 200: { description: "result" } } } },
      [ROUTE]: { get: { summary: "Paid (0.005 USDC, x402): on-chain address-poisoning check of a recipient against the sender's real history", parameters: [{ name: "from", in: "query", required: true, schema: { type: "string" } }, { name: "to", in: "query", required: true, schema: { type: "string" } }, { name: "chains", in: "query", required: false, schema: { type: "string" }, description: "ethereum,base,avalanche (default ethereum,base)" }],
        "x-payment-info": { protocol: "x402", x402Version: 2, scheme: "exact", network: "eip155:8453", asset: USDC_BASE, amount: PRICE, price_usd: 0.005, payTo: PAY_TO, facilitator: FACILITATOR },
        responses: { 200: { description: "report" }, 402: { description: "Payment required (x402 v1 body + v2 PAYMENT-REQUIRED header)" } } } } } };
}

export default {
  async fetch(req, env) {
    ENV = env || {};
    const url = new URL(req.url), origin = url.origin, p = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { headers: { ...H, "access-control-allow-headers": "*", "access-control-allow-methods": "GET, HEAD, POST, OPTIONS" } });
    if (p === "/") return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" } });
    if (p === "/index.json") return J({ service: SERVICE, version: VERSION, by: "Made by DevX (madebydevx.com)", free: origin + "/api/basic?to=0x...&known=0x...,0x...", paid: origin + ROUTE + "?from=0x...&to=0x...", price_usdc: 0.005, protocol: "x402 (v1 X-PAYMENT and v2 PAYMENT-SIGNATURE), USDC on Base", payTo: PAY_TO, docs: origin + "/openapi.json", mcp: origin + "/mcp", terms: origin + "/terms", description: DESC });
    if (p === "/robots.txt") return new Response(`User-agent: *\nAllow: /\nSitemap: ${SITE}/sitemap.xml\n`, { headers: { "content-type": "text/plain" } });
    if (p === "/sitemap.xml") return new Response(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${SITE}/</loc><lastmod>2026-10-30</lastmod></url></urlset>`, { headers: { "content-type": "application/xml" } });
    if (p === "/llms.txt") return new Response(`# ${SERVICE}
> Before an agent or wallet sends crypto, check the recipient for address poisoning: lookalike of someone the sender really pays, planted by zero-value/dust/fake-token transfers. Free offline lookalike check; paid on-chain check 0.005 USDC via x402 on Base.
- Free API: GET /api/basic?to=0x...&known=0x...,0x...
- Paid API (x402): GET /v1/check?from=0x...&to=0x...[&chains=ethereum,base,avalanche]
- MCP: ${SITE}/mcp
- OpenAPI: /openapi.json
- Source: https://github.com/devx-agent/address-poisoning-check
- Related: https://sweeper-check.nextill-pos.workers.dev (EIP-7702 sweeper check), https://crypto-link-check.nextill-pos.workers.dev (phishing link check), https://tokencheck.madebydevx.com (token check)
`, { headers: { "content-type": "text/plain; charset=utf-8" } });
    if (p === "/terms") return new Response(TERMS, { headers: { "content-type": "text/plain; charset=utf-8", "access-control-allow-origin": "*" } });
    if (p === "/openapi.json") return J(docs(origin));
    if (p === "/.well-known/x402") return J({ version: 1, resources: [origin + ROUTE], description: SERVICE });
    if (p === "/.well-known/x402.json") return J({ x402Version: 2, name: SERVICE, provider: "Made by DevX (madebydevx.com)", resources: [{ url: origin + ROUTE, method: "GET", description: DESC, accepts: [requirements()] }] });
    if (p === "/mcp") return mcp(req, origin);
    if (p === "/.well-known/mcp.json" || p === "/.well-known/mcp/server-card.json") return J({ name: "devx-address-poisoning-check", description: "Address-poisoning / lookalike recipient check before sending crypto", url: origin + "/mcp", transport: "streamable-http", tools: ["check_recipient_lookalike", "onchain_check_info"], provider: "Made by DevX", repository: "https://github.com/devx-agent/address-poisoning-check" });
    if (p === "/health") return J({ ok: true, version: VERSION, facilitator: facilitatorConfig(ENV).name });
    if (p === "/api/basic") {
      const to = (url.searchParams.get("to") || url.searchParams.get("address") || "").trim();
      if (!isAddr(to)) return J({ error: "to must be a 0x 20-byte hex address" }, 400);
      const known = [...new Set((url.searchParams.get("known") || "").split(/[\s,]+/).filter(Boolean))];
      if (known.length > 50) return J({ error: "max 50 known addresses" }, 400);
      const badk = known.find((k) => !isAddr(k)); if (badk) return J({ error: "invalid known address: " + badk.slice(0, 60) }, 400);
      const r = basic(to, known); r.onchain_check = origin + ROUTE + "?from=<your wallet>&to=" + to.toLowerCase(); r.onchain_check_price_usdc = 0.005; return J(r);
    }
    if (p !== ROUTE) return J({ error: "not found", see: origin + "/index.json" }, 404);
    if (!["GET", "HEAD", "POST"].includes(req.method)) return J({ error: "use GET (or POST JSON)" }, 405);
    { const pe = await postToParams(req, url); if (pe && pe.error) return J({ error: pe.error }, 400); }
    const pr = paymentRequired(origin); // resource URL without query: buyer inputs must not end up in public Bazaar catalogs
    const parsed = parseQ(url);
    const sig = req.headers.get("PAYMENT-SIGNATURE") || req.headers.get("X-PAYMENT");
    console.log(JSON.stringify({ ev: "paid_route", m: req.method, pay: sig ? (req.headers.get("X-PAYMENT") ? "x-payment" : "payment-signature") : null, ua: uaFamily(req.headers.get("user-agent")) }));
    if (!sig) return J(v1Body(pr), 402, { "PAYMENT-REQUIRED": b64(pr) });
    if (parsed.error) return J({ error: parsed.error + " (you were not charged)" }, 400);
    let payload; try { payload = unb64(sig); } catch { return J({ ...pr, error: "malformed PAYMENT-SIGNATURE" }, 400, { "PAYMENT-REQUIRED": b64(pr) }); }
    const reqs = requirements(), isV1 = payload.x402Version === 1 || (!payload.accepted && !!payload.network);
    const acc = isV1 ? { network: (payload.network === "base" || payload.network === "eip155:8453") ? reqs.network : payload.network, payTo: payload.payload?.authorization?.to, amount: String(payload.payload?.authorization?.value ?? ""), asset: USDC_BASE } : (payload.accepted || {});
    const fReq = isV1 ? v1Requirements(pr.resource.url) : reqs, fPay = isV1 ? { ...payload, x402Version: 1, scheme: "exact", network: "base" } : payload, fv = isV1 ? 1 : 2;
    console.log(JSON.stringify({ ev: "pay_attempt", v: fv, ua: uaFamily(req.headers.get("user-agent")) }));
    if ((!isV1 && payload.x402Version !== 2) || acc.network !== reqs.network || acc.payTo?.toLowerCase() !== PAY_TO.toLowerCase() || acc.amount !== reqs.amount || acc.asset?.toLowerCase() !== USDC_BASE.toLowerCase())
      return J({ ...(isV1 ? v1Body(pr) : pr), error: "payment does not match requirements (exact, Base USDC " + PRICE + " atomic to " + PAY_TO + ")" }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    const v = await facil("verify", { x402Version: fv, paymentPayload: fPay, paymentRequirements: fReq });
    if (!v.isValid) { console.log(JSON.stringify({ ev: "pay_invalid", v: fv, r: v.invalidReason || "unknown" })); return J({ ...(isV1 ? v1Body(pr) : pr), error: "payment invalid: " + (v.invalidReason || v.errorMessage || v.message || v.error || ("facilitator status " + (v._st || "?"))) }, 402, { "PAYMENT-REQUIRED": b64(pr) }); }
    let report; try { report = await full(parsed.from, parsed.to, parsed.chains); } catch (e) { return J({ error: "data source error, you were not charged: " + String(e.message || e).slice(0, 120) }, 503); }
    const s = await facil("settle", { x402Version: fv, paymentPayload: fPay, paymentRequirements: fReq });
    const PRH = b64(isV1 ? { success: !!s.success, transaction: s.transaction || "", network: "base", payer: s.payer || payload.payload?.authorization?.from || "" } : s);
    console.log(JSON.stringify({ ev: s.success ? "paid" : "settle_fail", v: fv }));
    if (!s.success) return J({ ...pr, error: "settlement failed: " + (s.errorReason || "unknown") + " (report withheld, not charged)" }, 402, { "PAYMENT-REQUIRED": b64(pr), "PAYMENT-RESPONSE": PRH, "X-PAYMENT-RESPONSE": PRH });
    return J({ service: SERVICE, version: VERSION, report, payment: { tx: s.transaction || null, network: s.network || "eip155:8453", x402Version: fv } }, 200, { "PAYMENT-RESPONSE": PRH, "X-PAYMENT-RESPONSE": PRH });
  },
};
