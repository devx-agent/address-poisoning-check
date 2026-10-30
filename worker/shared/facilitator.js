// Facilitator selection is configuration only:
//   - CDP_API_KEY_ID + CDP_API_KEY_SECRET (Worker secrets) present -> Coinbase CDP facilitator (settles + lists in the CDP x402 Bazaar)
//   - else FACILITATOR_URL (var) or the default PayAI facilitator (no key).
// Secrets are only used to sign short-lived JWTs; they are never logged or returned.
import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
const DEFAULT_FACILITATOR = 'https://facilitator.payai.network'; const CDP_FACILITATOR = 'https://api.cdp.coinbase.com/platform/v2/x402';

const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uJson = (o) => b64u(enc.encode(JSON.stringify(o)));
const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '')), (c) => c.charCodeAt(0));
const hexRand = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');

/** Extract the 32-byte P-256 private scalar from a PEM (SEC1 "EC PRIVATE KEY" or PKCS#8 "PRIVATE KEY"). */
export function p256KeyFromPem(pem) {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\\n/g, '').replace(/\s+/g, '');
  const der = fromB64(body);
  // SEC1: 30 .. 02 01 01 04 20 <32 bytes>. PKCS#8 wraps the SEC1 structure, so the same marker occurs inside it.
  for (let i = 0; i < der.length - 34; i++) if (der[i] === 0x02 && der[i + 1] === 0x01 && der[i + 2] === 0x01 && der[i + 3] === 0x04 && der[i + 4] === 0x20) return der.slice(i + 5, i + 37);
  throw new Error('unsupported EC key format');
}

/** CDP API JWT (same claims as @coinbase/cdp-sdk generateJwt): EdDSA for base64 Ed25519 keys, ES256 for PEM EC keys. */
export function cdpJwt(keyId, secret, method, host, path, now = Math.floor(Date.now() / 1000)) {
  const claims = { sub: keyId, iss: 'cdp', uris: [`${method} ${host}${path}`], iat: now, nbf: now, exp: now + 120 };
  const isPem = /BEGIN/.test(secret);
  const header = { alg: isPem ? 'ES256' : 'EdDSA', kid: keyId, typ: 'JWT', nonce: hexRand(16) };
  const signingInput = b64uJson(header) + '.' + b64uJson(claims);
  let sig;
  if (isPem) sig = p256.sign(sha256(enc.encode(signingInput)), p256KeyFromPem(secret)).toCompactRawBytes();
  else {
    const raw = fromB64(secret.trim());
    if (raw.length !== 64 && raw.length !== 32) throw new Error('CDP_API_KEY_SECRET: expected base64 Ed25519 key (64 bytes) or PEM EC key');
    sig = ed25519.sign(enc.encode(signingInput), raw.slice(0, 32));
  }
  return signingInput + '.' + b64u(sig);
}

export function facilitatorConfig(env = {}) {
  const id = env.CDP_API_KEY_ID, secret = env.CDP_API_KEY_SECRET;
  if (id && secret) return { name: 'coinbase-cdp', url: CDP_FACILITATOR, cdp: { id, secret }, bazaar: true };
  const url = (env.FACILITATOR_URL || DEFAULT_FACILITATOR).replace(/\/+$/, '');
  return { name: /payai/.test(url) ? 'payai' : 'custom', url, cdp: null, bazaar: /payai/.test(url) };
}

/** POST {url}/{op}. Returns parsed JSON ({} on parse failure) plus _status. Never throws on HTTP errors. */
export async function facilitate(env, op, body, fetchImpl = fetch) {
  const f = facilitatorConfig(env);
  const headers = { 'content-type': 'application/json' };
  if (f.cdp) {
    const u = new URL(f.url + '/' + op);
    headers.authorization = 'Bearer ' + cdpJwt(f.cdp.id, f.cdp.secret, 'POST', u.host, u.pathname);
    headers['Correlation-Context'] = 'sdk_version=1.29.0,sdk_language=typescript,source=x402,source_version=2.1.0';
  }
  try {
    const r = await fetchImpl(`${f.url}/${op}`, { method: 'POST', headers, body: JSON.stringify(body) });
    let j = {}; try { j = await r.json(); } catch {}
    return { ...j, _status: r.status };
  } catch (e) { return { _status: 0, errorReason: 'facilitator unreachable' }; }
}
