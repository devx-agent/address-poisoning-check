// DevX Address Poisoning Check - core logic. Read-only, public data only.
export const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a || "").trim());
const lc = (a) => String(a || "").trim().toLowerCase();
const UA = { "user-agent": "devx-address-poisoning-check/1.0 (+https://madebydevx.com)", accept: "application/json" };
export const CHAINS = ["ethereum", "base", "avalanche"];

export function similarity(a, b) {
  a = lc(a).slice(2); b = lc(b).slice(2);
  let pre = 0; while (pre < 40 && a[pre] === b[pre]) pre++;
  let suf = 0; while (suf < 40 && a[39 - suf] === b[39 - suf]) suf++;
  return { prefix: pre, suffix: suf, identical: a === b };
}
export function isLookalike(a, b) {
  const s = similarity(a, b); if (s.identical) return false;
  return (s.prefix >= 3 && s.suffix >= 3) || (s.prefix + s.suffix >= 8 && Math.min(s.prefix, s.suffix) >= 2);
}
// EIP-55 checksum validity (mixed-case input only). Uses keccak from @noble/hashes.
import { keccak_256 } from "@noble/hashes/sha3";
export function checksumOk(a) {
  a = String(a).trim(); const h = a.slice(2);
  if (h === h.toLowerCase() || h === h.toUpperCase()) return null; // not checksummed
  const hash = Array.from(keccak_256(new TextEncoder().encode(h.toLowerCase())), (b) => b.toString(16).padStart(2, "0")).join("");
  for (let i = 0; i < 40; i++) { const c = h[i]; if (/[a-f]/i.test(c) && ((parseInt(hash[i], 16) >= 8) !== (c === c.toUpperCase()))) return false; }
  return true;
}
const short = (a) => lc(a).slice(0, 6) + "..." + lc(a).slice(-4);

// Free, offline: compare an intended recipient against addresses you trust.
export function basic(to, known = []) {
  const out = { to: lc(to), checksum_valid: checksumOk(to), compared: known.length, matches: [], lookalikes: [] };
  for (const k of known) {
    const s = similarity(to, k);
    if (s.identical) out.matches.push(lc(k));
    else if (isLookalike(to, k)) out.lookalikes.push({ address: lc(k), shared_prefix: s.prefix, shared_suffix: s.suffix, shown_as: short(k) });
  }
  out.verdict = out.checksum_valid === false ? "danger" : out.lookalikes.length && !out.matches.length ? "danger" : out.matches.length ? "match" : "unknown";
  out.note = out.verdict === "danger" ? (out.checksum_valid === false ? "Checksum is invalid: the address was mistyped or altered." : `Looks like ${out.lookalikes[0].shown_as} (same first ${out.lookalikes[0].shared_prefix} / last ${out.lookalikes[0].shared_suffix} hex chars) but is a different address. Classic address-poisoning lookalike.`)
    : out.verdict === "match" ? "Exactly matches an address you supplied." : "No lookalike among the supplied addresses. For an on-chain check of the sender's real history use the paid /v1/check.";
  return out;
}

const TOKENS = {
  ethereum: { "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ["USDC", 6], "0xdac17f958d2ee523a2206206994597c13d831ec7": ["USDT", 6], "0x6b175474e89094c44da98b954eedeac495271d0f": ["DAI", 18], "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ["WETH", 18], "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c": ["EURC", 6], "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": ["WBTC", 8], "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf": ["cbBTC", 8], "0x6c3ea9036406852006290770bedfcaba0e23a0e8": ["PYUSD", 6], "0x4c9edd5852cd905f086c759e8383e09bff1e68b3": ["USDe", 18], "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": ["stETH", 18], "0x7f39c581f595b53c5cb19bd0b3e8da6c935e2ca0": ["wstETH", 18], "0x514910771af9ca656af840dff83e8264ecf986ca": ["LINK", 18], "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": ["UNI", 18] },
  base: { "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": ["USDC", 6], "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca": ["USDbC", 6], "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2": ["USDT", 6], "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42": ["EURC", 6], "0x4200000000000000000000000000000000000006": ["WETH", 18], "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf": ["cbBTC", 8] },
  avalanche: { "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e": ["USDC", 6], "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7": ["USDT", 6], "0x49d5c2bdffac6ce2bfdb6640f4f80f226bc10bab": ["WETH.e", 18] },
};
const RS = { ethereum: 1, avalanche: 43114 };
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
import { cdpJwt } from "../shared/facilitator.js";
let CDP = null; // { id, secret } from Worker secrets; enables the Coinbase CDP SQL API (indexed Base data, ~0.5 s)
export function setDataEnv(env) { CDP = env && env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET ? { id: env.CDP_API_KEY_ID, secret: env.CDP_API_KEY_SECRET } : null; }
const SQL_PATH = "/platform/v2/data/query/run";
async function cdpSql(sql, ms) {
  const c = new AbortController(); const tm = setTimeout(() => c.abort(), ms);
  try { const r = await fetch("https://api.cdp.coinbase.com" + SQL_PATH, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + cdpJwt(CDP.id, CDP.secret, "POST", "api.cdp.coinbase.com", SQL_PATH) }, body: JSON.stringify({ sql }), signal: c.signal });
    const j = await r.json().catch(() => ({})); if (!r.ok || !(Array.isArray(j.result) || (j.result == null && j.metadata))) throw new Error("cdp sql " + r.status + " " + String(j.errorMessage || "").slice(0, 60)); return j.result || []; } finally { clearTimeout(tm); }
}
async function baseSql(A, deadline) {
  const key = `bs1/${A}`; const hit = await cget(key); if (hit) return { ...hit, cached: true };
  for (const days of [14, 7]) {
    const left = deadline - Date.now(); if (left < 500) break;
    const q = (col) => `SELECT transaction_hash AS h, block_number AS b, toUnixTimestamp(block_timestamp) AS ts, address AS k, parameters['from'] AS f, parameters['to'] AS o, toString(parameters['value']) AS v FROM base.events WHERE event_signature = 'Transfer(address,address,uint256)' AND block_timestamp > now() - INTERVAL ${days} DAY AND parameters['${col}'] = '${A}'`;
    try {
      const rows = await cdpSql(`${q("from")} UNION ALL ${q("to")} LIMIT 3000`, left);
      const ev = rows.map((l) => classify("base", { chain: "base", hash: l.h, ts: +l.ts, token: lc(l.k), from: lc(l.f), to: lc(l.o), value: /^\d+$/.test(String(l.v)) ? String(l.v) : "0", signed_by_sender: false }));
      const out = { events: ev, complete: rows.length < 3000, source: "Coinbase CDP SQL API (indexed Base)", window: `last ${days} days of ALL ERC-20 Transfer events (incl. unknown/fake tokens)` + (rows.length >= 3000 ? " - PARTIAL: capped at 3000 transfers" : "") };
      await cput(key, out, 120); return out;
    } catch (e) { if (!/scanned more data/.test(String(e.message))) break; }
  }
  return null;
}
const BASE_RPCS = ["https://base-rpc.publicnode.com", "https://base-rpc.polkachu.com", "https://base.rpc.blxrbdn.com"];
const SPAN = 10000;          // blocks per getLogs segment (~5.5 h on Base); aligned so finished segments are cacheable forever
const MAX_SEGS = 16;         // ~3.7 days max look-back on Base
const BUDGET_MS = 3500;      // hard time budget for data collection; partial results are labeled
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CACHE = typeof caches !== "undefined" ? caches.default : null;
async function cget(key) { if (!CACHE) return null; try { const r = await CACHE.match("https://cache.devx.internal/" + key); return r ? await r.json() : null; } catch { return null; } }
async function cput(key, val, ttl) { if (!CACHE) return; try { await CACHE.put("https://cache.devx.internal/" + key, new Response(JSON.stringify(val), { headers: { "content-type": "application/json", "cache-control": "public, max-age=" + ttl } })); } catch {} }
export const cache = { get: cget, put: cput };
async function getJson(url, init = {}, ms = 12000) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), ms);
  try { const r = await fetch(url, { ...init, headers: { ...UA, ...(init.headers || {}) }, signal: c.signal }); return await r.json(); } finally { clearTimeout(t); }
}
function classify(chain, ev) {
  const tok = TOKENS[chain][ev.token]; const canonical = ev.token === "native" || !!tok;
  const dec = tok ? tok[1] : ev.decimals; const v = BigInt(ev.value || "0");
  const stable = tok && /USD|EUR|DAI/.test(tok[0]);
  const zero = v === 0n;
  const dust = !zero && (stable ? v < 1000n * 10n ** BigInt(dec - 6) : false); // < 0.001 of a stablecoin
  const mimic = !canonical && /^(usdc|usdt|usd₮|weth|eth|dai|eurc|usdbc)$/i.test(String(ev.symbol || "").trim());
  return { ...ev, canonical, symbol: tok ? tok[0] : ev.symbol, zero, dust, fake_token: mimic };
}
async function routescan(chain, action, address, offset, deadline) {
  const u = `https://api.routescan.io/v2/network/mainnet/evm/${RS[chain]}/etherscan/api?module=account&action=${action}&address=${address}&page=1&offset=${offset}&sort=desc`;
  for (let i = 0; i < 2; i++) { const left = deadline - Date.now(); if (left < 300) break; try { const j = await getJson(u, {}, left); if (Array.isArray(j.result)) return j.result; } catch {} await sleep(250); }
  throw new Error(chain + " explorer unavailable within time budget");
}
async function rsEvents(chain, address, deadline, offset = 300) {
  const key = `rs1/${chain}/${address}`; const hit = await cget(key); if (hit) return { ...hit, cached: true };
  const [tt, tx] = await Promise.all([routescan(chain, "tokentx", address, offset, deadline), routescan(chain, "txlist", address, 150, deadline)]);
  const ev = tt.map((x) => classify(chain, { chain, hash: x.hash, ts: +x.timeStamp, token: lc(x.contractAddress), symbol: x.tokenSymbol, decimals: +x.tokenDecimal || 0, from: lc(x.from), to: lc(x.to), value: x.value, signed_by_sender: false }));
  for (const x of tx) if (x.isError !== "1" && x.to) ev.push({ chain, hash: x.hash, ts: +x.timeStamp, token: "native", symbol: chain === "avalanche" ? "AVAX" : "ETH", from: lc(x.from), to: lc(x.to), value: x.value, canonical: true, zero: x.value === "0", dust: false, fake_token: false, signed_by_sender: true });
  const out = { events: ev, window: "last " + offset + " token transfers + 150 transactions", complete: true };
  await cput(key, out, 300); return out;
}
let rr = 0;
async function rpc(method, params, ms, prefer) {
  const u = BASE_RPCS[(prefer ?? rr++) % BASE_RPCS.length];
  const j = await getJson(u, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }, ms);
  if (j.error) throw new Error(j.error.message); return j.result;
}
const pad = (a) => "0x" + "0".repeat(24) + lc(a).slice(2);
async function head(deadline) {
  const hit = await cget("basehead1"); if (hit && hit.t > Date.now() - 20000) return hit.h;
  const h = await Promise.any(BASE_RPCS.map((u, i) => rpc("eth_blockNumber", [], Math.max(300, Math.min(2000, deadline - Date.now())), i).then((x) => parseInt(x, 16))));
  await cput("basehead1", { h, t: Date.now() }, 30); return h;
}
async function baseEvents(address, deadline) {
  const A = lc(address);
  if (CDP && isAddr(A)) { const r = await baseSql(A, deadline); if (r) return r; } const addrs = Object.keys(TOKENS.base); const now = Date.now();
  const h = await head(deadline) - 2; // stay 2 blocks behind head (some RPCs lag)
  const top = Math.floor(h / SPAN) * SPAN; // segment k covers [top-(k-1)*SPAN, ...]; segment 0 is the live partial one
  const segs = [{ from: top, to: h, live: true }]; for (let k = 1; k < MAX_SEGS; k++) segs.push({ from: top - k * SPAN, to: top - (k - 1) * SPAN - 1, live: false });
  const jobs = []; for (const s of segs) for (const dir of ["out", "in"]) jobs.push({ s, dir });
  const res = new Array(jobs.length).fill(null); let next = 0, calls = 0;
  async function one(i) {
    const { s, dir } = jobs[i]; const key = `bl1/${A}/${dir}/${s.from}`;
    if (!s.live) { const hit = await cget(key); if (hit) { res[i] = hit; return; } }
    for (let t = 0; t < 2; t++) {
      const left = deadline - Date.now(); if (left < 400 || calls >= 40) return; calls++;
      try { const logs = await rpc("eth_getLogs", [{ fromBlock: "0x" + s.from.toString(16), toBlock: "0x" + s.to.toString(16), address: addrs, topics: dir === "out" ? [TRANSFER, pad(A)] : [TRANSFER, null, pad(A)] }], left, (i + t) % BASE_RPCS.length);
        res[i] = logs.map((l) => ({ h: l.transactionHash, b: parseInt(l.blockNumber, 16), k: lc(l.address), f: "0x" + l.topics[1].slice(26), o: "0x" + l.topics[2].slice(26), v: BigInt(l.data === "0x" ? 0 : l.data).toString() }));
        if (!s.live) await cput(key, res[i], 86400 * 7); return;
      } catch {}
    }
  }
  const worker = async () => { while (next < jobs.length && deadline - Date.now() > 400) await one(next++); };
  await Promise.all(Array.from({ length: 8 }, worker));
  // contiguous coverage from the head: a segment counts only if both directions succeeded
  let covered = 0; while (covered < segs.length && res[covered * 2] && res[covered * 2 + 1]) covered++;
  if (!covered) throw new Error("base rpc unavailable within time budget");
  const ev = [];
  for (let i = 0; i < covered * 2; i++) for (const l of res[i]) ev.push(classify("base", { chain: "base", hash: l.h, ts: Math.round(now / 1000 - (h - l.b) * 2), token: l.k, from: l.f, to: l.o, value: l.v, signed_by_sender: false }));
  const fromBlock = segs[covered - 1].from, hours = Math.round((h - fromBlock) * 2 / 3600);
  const complete = covered === segs.length;
  return { events: ev, complete, source: "public Base RPC eth_getLogs (fallback)", coverage: { from_block: fromBlock, to_block: h, approx_hours: hours },
    window: `Base blocks ${fromBlock}-${h} (~${hours} h) of USDC/USDbC/USDT/EURC/WETH/cbBTC transfers` + (complete ? "" : ` - PARTIAL: time budget reached, target was ~${Math.round(MAX_SEGS * SPAN * 2 / 86400 * 10) / 10} days`) };
}
async function events(chain, address, deadline) { return chain === "base" ? baseEvents(address, deadline) : rsEvents(chain, address, deadline); }

export async function full(fromAddr, toAddr, chains = ["ethereum", "base"]) {
  const W = lc(fromAddr), X = lc(toAddr);
  const report = { from: W, to: X, checksum_valid: checksumOk(toAddr), chains: [], findings: [] };
  const trusted = new Map(); const poisonEv = []; const seen = new Map(); let firstPoisonTsByAddr = new Map();
  const deadline = Date.now() + BUDGET_MS;
  const per = await Promise.all(chains.map(async (c) => { try { return { chain: c, ...(await events(c, W, deadline)) }; } catch (e) { return { chain: c, error: String(e.message || e) }; } }));
  for (const p of per) {
    const info = { chain: p.chain, window: p.window, complete: p.events ? !!p.complete : false, coverage: p.coverage, source: p.source || (p.chain === 'base' ? undefined : 'Routescan explorer API'), cached: p.cached || undefined, error: p.error, transfers_scanned: p.events ? p.events.length : 0 };
    report.chains.push(info); if (!p.events) continue;
    for (const e of p.events) {
      const other = e.from === W ? e.to : e.from; if (!other || other === W) continue;
      const s = seen.get(other) || { address: other, out_real: 0, in_real: 0, suspicious: 0, first_ts: e.ts, last_ts: e.ts, chains: new Set() };
      const suspicious = e.zero || e.dust || e.fake_token || !e.canonical;
      if (e.from === W && !suspicious) { s.out_real++; if (!trusted.has(other)) trusted.set(other, e.ts); trusted.set(other, Math.min(trusted.get(other), e.ts)); }
      else if (e.to === W && !suspicious) s.in_real++;
      else s.suspicious++;
      if (suspicious) firstPoisonTsByAddr.set(other, Math.min(firstPoisonTsByAddr.get(other) || Infinity, e.ts));
      s.first_ts = Math.min(s.first_ts, e.ts); s.last_ts = Math.max(s.last_ts, e.ts); s.chains.add(p.chain); seen.set(other, s);
      if (suspicious) poisonEv.push(e);
    }
  }
  if (report.chains.every((c) => c.error)) throw new Error("all data sources unavailable, try again");
  const trustedList = [...trusted.keys()];
  // Poisoning attempts against W: suspicious transfer whose counterparty looks like someone W really pays.
  const attempts = [];
  for (const e of poisonEv) { const other = e.from === W ? e.to : e.from; const target = trustedList.find((t) => t !== other && isLookalike(t, other)); if (target) attempts.push({ chain: e.chain, tx: e.hash, time: new Date(e.ts * 1000).toISOString(), lookalike: other, imitates: target, kind: e.fake_token ? "fake_token" : e.zero ? "zero_value" : e.dust ? "dust" : "unknown_token" }); }
  const poisoners = new Set(attempts.map((a) => a.lookalike));
  report.poisoning_attempts_on_sender = { count: attempts.length, distinct_lookalikes: poisoners.size, recent: attempts.sort((a, b) => b.time.localeCompare(a.time)).slice(0, 10) };
  const x = seen.get(X);
  report.history_with_recipient = x ? { real_sends_from_you: x.out_real, real_receipts: x.in_real, suspicious_transfers: x.suspicious, first_seen: new Date(x.first_ts * 1000).toISOString(), last_seen: new Date(x.last_ts * 1000).toISOString(), chains: [...x.chains] } : null;
  const tainted = new Set([...firstPoisonTsByAddr.keys()].filter((a) => poisoners.has(a) || !trusted.has(a) || firstPoisonTsByAddr.get(a) <= trusted.get(a)));
  const realParties = [...seen.values()].filter((s) => (s.out_real || s.in_real) && !tainted.has(s.address)).map((s) => s.address);
  const poisonTwins = [...tainted].filter((t) => t !== X && isLookalike(t, X));
  const imitates = realParties.filter((t) => t !== X && isLookalike(t, X)).map((t) => ({ address: t, ...similarity(t, X), your_real_sends: seen.get(t).out_real, your_real_receipts: seen.get(t).in_real })).sort((a, b) => b.your_real_sends - a.your_real_sends);
  const f = (level, code, msg) => report.findings.push({ level, code, msg });
  if (report.checksum_valid === false) f("high", "bad_checksum", "The recipient's EIP-55 checksum is invalid: it was mistyped or altered.");
  if (poisoners.has(X)) f("high", "recipient_is_poisoner", "This exact address sent you zero-value, dust or fake-token transfers that imitate an address you really pay. Do not send to it.");
  if (imitates.length && !(x && x.out_real && trusted.get(X) < (firstPoisonTsByAddr.get(X) || Infinity))) f("high", "lookalike_of_known_counterparty", `Recipient looks like ${short(imitates[0].address)} (same first ${imitates[0].prefix} / last ${imitates[0].suffix} hex chars), a different address you have really transacted with (${imitates[0].your_real_sends} send(s), ${imitates[0].your_real_receipts} receipt(s)). You probably meant ${imitates[0].address}.`);
  if (x && !x.out_real && !x.in_real && x.suspicious && !poisoners.has(X)) f("high", "only_seen_via_suspicious_transfers", `This address appears in your history only through ${x.suspicious} zero-value, dust or unverified-token transfer(s). That is how address poisoning plants a lookalike in your history. Do not copy it from there.`);
  if (x && x.out_real && firstPoisonTsByAddr.has(X) && firstPoisonTsByAddr.get(X) <= trusted.get(X)) f("high", "possibly_already_poisoned", "You already sent real value to this address, but it first appeared in your history via a zero-value/dust/fake-token transfer. You may have been poisoned before: verify this address out of band.");
  if (poisonTwins.length && !report.findings.some((z) => z.level === "high")) f("medium", "lookalike_of_poisoner", `A lookalike of this address (${poisonTwins[0]}) was planted in your history by suspicious transfers${(seen.get(poisonTwins[0]) || {}).out_real ? " and you have already sent real value to it" : ""}. Make sure the address you use came from the payee, character by character.`);
  if (!report.findings.some((z) => z.level !== "info")) {
    if (x && x.out_real) f("ok", "known_recipient", `You have sent real value to this exact address ${x.out_real} time(s) in the scanned window, and it was not first introduced by a suspicious transfer.`);
    else if (x && x.in_real) f("low", "known_counterparty", "This address has sent you real value, but you have not paid it in the scanned window. Confirm it is the right destination.");
    else f("medium", "new_recipient", "No history with this address in the scanned window. Not necessarily bad, but verify the FULL address with the payee through a separate channel, never from your transaction history.");
  }
  if (attempts.length) f("info", "sender_targeted", `Your wallet received ${attempts.length} poisoning-style transfer(s) from ${poisoners.size} lookalike address(es). Never copy addresses from transaction history.`);
  report.probably_meant = imitates.length ? imitates[0].address : null;
  const lv = report.findings.map((z) => z.level);
  report.verdict = lv.includes("high") ? "danger" : lv.includes("medium") ? "caution" : lv.includes("low") ? "caution" : "ok";
  report.advice = report.verdict === "danger" ? "Stop. Do not send. Get the address directly from the payee (or your own saved address book) and compare every character." : report.verdict === "caution" ? "Verify the full address with the payee out of band, or send a small test amount first." : "Recipient matches your real payment history.";
  report.partial = report.chains.some((c) => !c.complete);
  if (report.partial) report.partial_note = "Some data was not collected within the time budget (see chains[].window / error). Findings only cover the scanned window; treat ok/caution as weaker evidence and re-run later for a wider window (finished segments are cached).";
  report.checked_at = new Date().toISOString();
  return report;
}
