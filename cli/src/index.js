// devx-address-poisoning-check: offline lookalike + EIP-55 checks, and a client for the hosted on-chain check.
import { keccak_256 } from "@noble/hashes/sha3";
export const DEFAULT_BASE = "https://address-poisoning-check.nextill-pos.workers.dev";
export const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const lc = (a) => String(a || "").trim().toLowerCase();
export const isAddr = (a) => ADDR_RE.test(String(a || "").trim());

/** Shared leading / trailing hex characters (after 0x). */
export function similarity(a, b) {
  a = lc(a).slice(2); b = lc(b).slice(2);
  let prefix = 0; while (prefix < 40 && a[prefix] === b[prefix]) prefix++;
  let suffix = 0; while (suffix < 40 && a[39 - suffix] === b[39 - suffix]) suffix++;
  return { prefix, suffix, identical: a === b };
}
/** True when b looks like a (same first/last characters, different middle): the shape address poisoners generate. */
export function isLookalike(a, b) {
  const s = similarity(a, b); if (s.identical) return false;
  return (s.prefix >= 3 && s.suffix >= 3) || (s.prefix + s.suffix >= 8 && Math.min(s.prefix, s.suffix) >= 2);
}
/** EIP-55: true valid, false invalid, null when the address is all lower/upper case (no checksum). */
export function checksumOk(a) {
  a = String(a).trim(); const h = a.slice(2);
  if (h === h.toLowerCase() || h === h.toUpperCase()) return null;
  const hash = Array.from(keccak_256(new TextEncoder().encode(h.toLowerCase())), (x) => x.toString(16).padStart(2, "0")).join("");
  for (let i = 0; i < 40; i++) { const c = h[i]; if (/[a-f]/i.test(c) && ((parseInt(hash[i], 16) >= 8) !== (c === c.toUpperCase()))) return false; }
  return true;
}
const short = (a) => lc(a).slice(0, 6) + "..." + lc(a).slice(-4);

/** Offline check of a recipient against addresses you trust. Nothing leaves your machine. */
export function checkRecipient(to, known = []) {
  if (!isAddr(to)) throw new Error("to must be 0x + 40 hex characters");
  const bad = known.find((k) => !isAddr(k)); if (bad) throw new Error("invalid known address: " + bad);
  const out = { to: lc(to), checksum_valid: checksumOk(to), compared: known.length, matches: [], lookalikes: [] };
  for (const k of known) { const s = similarity(to, k); if (s.identical) out.matches.push(lc(k)); else if (isLookalike(to, k)) out.lookalikes.push({ address: lc(k), shared_prefix: s.prefix, shared_suffix: s.suffix, shown_as: short(k) }); }
  out.verdict = out.checksum_valid === false ? "danger" : out.lookalikes.length && !out.matches.length ? "danger" : out.matches.length ? "match" : "unknown";
  out.note = out.verdict === "danger" ? (out.checksum_valid === false ? "Checksum is invalid: the address was mistyped or altered." : `Looks like ${out.lookalikes[0].shown_as} (same first ${out.lookalikes[0].shared_prefix} / last ${out.lookalikes[0].shared_suffix} hex chars) but is a different address. Classic address-poisoning lookalike.`)
    : out.verdict === "match" ? "Exactly matches an address you supplied." : "No lookalike among the supplied addresses.";
  out.onchain_check = `${DEFAULT_BASE}/v1/check?from=<your wallet>&to=${lc(to)}`;
  return out;
}

/** Info for the paid on-chain check (x402). Fetches the 402 challenge, does not pay. */
export async function onchainPrice(from, to, { baseUrl = DEFAULT_BASE, fetch: f = globalThis.fetch } = {}) {
  if (!isAddr(from) || !isAddr(to)) throw new Error("from and to must be 0x + 40 hex characters");
  const url = `${baseUrl.replace(/\/$/, "")}/v1/check?from=${lc(from)}&to=${lc(to)}`;
  const r = await f(url, { headers: { accept: "application/json", "user-agent": "devx-address-poisoning-check" } });
  const body = await r.json(); const a = (body.accepts || [])[0] || {};
  return { url, status: r.status, price_usdc: Number(a.maxAmountRequired || a.amount || 0) / 1e6, payTo: a.payTo, network: a.network, note: "Pay with any x402 client (v1 X-PAYMENT or v2 PAYMENT-SIGNATURE). Settled only after the report is produced." };
}
