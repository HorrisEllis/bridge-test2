/**
 * Bridge OS — Phantom Relay Service Worker
 * /__relay-sw.js
 * github.com/HorrisEllis/Bridge-v2
 *
 * Intercepts POST /__relay/forward requests.
 * Decrypts payload, forwards to next hop or destination.
 * Re-encrypts response for caller.
 * No logging. No persistence. All state ephemeral.
 *
 * Relay protocol:
 *   POST /__relay/forward
 *   X-B-Hop:   current hop (1-indexed)
 *   X-B-Total: total hops
 *   X-B-Next:  base64(next relay URL) — empty string if exit hop
 *   X-B-Sig:   hex(HMAC-SHA256(payload, circuit_key))
 *   X-B-Nonce: hex(16 random bytes) — replay prevention
 *   X-B-Key:   base64(AES-GCM wrapped layer key for THIS hop)
 *   Body:      AES-256-GCM ciphertext (IV prepended, 12 bytes)
 *
 * Layered encryption (onion-style):
 *   Initiator encrypts payload with N keys, outermost first.
 *   Each relay unwraps one layer. Exit relay sees plaintext.
 *   This relay cannot read any other relay's layer.
 *
 * Replay protection:
 *   Nonces stored in memory for 60 seconds.
 *   Same nonce within window → reject.
 *   Window clears automatically.
 */

'use strict';

const RELAY_PATH    = '/__relay/forward';
const NONCE_WINDOW  = 60_000; // ms — replay window
const MAX_HOPS      = 8;
const MAX_BODY_BYTES = 512 * 1024; // 512KB max payload

// In-memory nonce store (ephemeral — cleared on SW restart)
const _nonces = new Map(); // nonce → expiry ts

// ── Install + activate ────────────────────────────────────────────────────────

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('message', msg => {
  if (msg.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

// ── Fetch intercept ───────────────────────────────────────────────────────────

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Only intercept relay path
  if (url.pathname !== RELAY_PATH) return;
  if (e.request.method !== 'POST') {
    e.respondWith(new Response('Method Not Allowed', { status: 405 }));
    return;
  }

  e.respondWith(handleRelay(e.request));
});

// ── Relay handler ─────────────────────────────────────────────────────────────

async function handleRelay(req) {
  try {
    // ── Read headers ──────────────────────────────────────────────────────────
    const hop      = parseInt(req.headers.get('X-B-Hop')   || '1');
    const total    = parseInt(req.headers.get('X-B-Total') || '1');
    const nextB64  = req.headers.get('X-B-Next')  || '';
    const sigHex   = req.headers.get('X-B-Sig')   || '';
    const nonceHex = req.headers.get('X-B-Nonce') || '';
    const keyB64   = req.headers.get('X-B-Key')   || '';

    // ── Validate ──────────────────────────────────────────────────────────────
    if (!nonceHex || !sigHex || !keyB64) {
      return relayError(400, 'MISSING_HEADERS');
    }

    if (hop < 1 || hop > MAX_HOPS || total < 1 || total > MAX_HOPS) {
      return relayError(400, 'INVALID_HOP');
    }

    // Replay check
    if (!checkNonce(nonceHex)) {
      return relayError(409, 'REPLAY_DETECTED');
    }

    // ── Read body ─────────────────────────────────────────────────────────────
    const body = await req.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) return relayError(413, 'PAYLOAD_TOO_LARGE');
    if (body.byteLength < 28) return relayError(400, 'PAYLOAD_TOO_SMALL'); // min: 12 IV + 16 tag

    // ── Decrypt this layer ────────────────────────────────────────────────────
    const layerKey  = base64ToBytes(keyB64);
    const plaintext = await aesDecrypt(layerKey, new Uint8Array(body));
    if (!plaintext) return relayError(400, 'DECRYPT_FAILED');

    // ── Add timing jitter (defeat correlation) ────────────────────────────────
    await jitter(30, 180);

    // ── Route ─────────────────────────────────────────────────────────────────
    let responseData;

    if (!nextB64 || hop >= total) {
      // EXIT HOP — forward to actual destination
      // Plaintext at exit = { method, url, headers, body }
      const packet = JSON.parse(new TextDecoder().decode(plaintext));
      responseData = await exitForward(packet);
    } else {
      // RELAY HOP — forward to next relay
      const nextUrl = new TextDecoder().decode(base64ToBytes(nextB64));
      responseData  = await relayForward(nextUrl, hop + 1, total, plaintext, req.headers);
    }

    if (!responseData) return relayError(502, 'FORWARD_FAILED');

    // ── Return response ───────────────────────────────────────────────────────
    // Response is already encrypted by the next hop or exit
    return new Response(responseData, {
      status: 200,
      headers: {
        'Content-Type':                  'application/octet-stream',
        'Cache-Control':                 'no-store, no-cache, must-revalidate',
        'X-Content-Type-Options':        'nosniff',
        'X-Frame-Options':               'DENY',
        'Access-Control-Allow-Origin':   '*',
        'Access-Control-Allow-Methods':  'POST',
        'Access-Control-Allow-Headers':  'X-B-Hop,X-B-Total,X-B-Next,X-B-Sig,X-B-Nonce,X-B-Key,Content-Type',
      },
    });

  } catch (e) {
    return relayError(500, 'INTERNAL');
  }
}

// ── Exit forward (last hop — sends actual request) ────────────────────────────

async function exitForward(packet) {
  try {
    const { method = 'GET', url, headers = {}, body = null } = packet;

    // Safety: only allow HTTPS to prevent SSRF to local network
    const u = new URL(url);
    if (u.protocol !== 'https:') return null;

    // Block private IP ranges (SSRF protection)
    const host = u.hostname;
    if (isPrivateHost(host)) return null;

    const res = await fetch(url, {
      method,
      headers: {
        ...headers,
        // Strip any headers that could identify the relay
        'X-Forwarded-For':   undefined,
        'X-Real-IP':         undefined,
        'Via':               undefined,
        'Forwarded':         undefined,
      },
      body: body ? base64ToBytes(body) : undefined,
      // No credentials — never send cookies from relay origin
      credentials: 'omit',
      redirect: 'follow',
    });

    // Pack response: status(2) + headers_len(2) + headers + body
    const resBody    = new Uint8Array(await res.arrayBuffer());
    const resHeaders = JSON.stringify(Object.fromEntries([...res.headers.entries()]
      .filter(([k]) => !['set-cookie','cf-ray','x-amz-cf-id'].includes(k.toLowerCase()))));
    const resHeaderBytes = new TextEncoder().encode(resHeaders);

    const packed = new Uint8Array(2 + 2 + resHeaderBytes.length + resBody.length);
    new DataView(packed.buffer).setUint16(0, res.status);
    new DataView(packed.buffer).setUint16(2, resHeaderBytes.length);
    packed.set(resHeaderBytes, 4);
    packed.set(resBody, 4 + resHeaderBytes.length);

    return packed;
  } catch { return null; }
}

// ── Relay forward (intermediate hop — passes to next relay) ───────────────────

async function relayForward(nextUrl, nextHop, total, encryptedPayload, originalHeaders) {
  try {
    // Generate new nonce for next hop
    const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));

    const res = await fetch(`${nextUrl}${RELAY_PATH}`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/octet-stream',
        'X-B-Hop':       String(nextHop),
        'X-B-Total':     String(total),
        'X-B-Next':      originalHeaders.get('X-B-Next-Next') || '',
        'X-B-Sig':       originalHeaders.get('X-B-Sig-Next')  || '',
        'X-B-Nonce':     nonce,
        'X-B-Key':       originalHeaders.get('X-B-Key-Next')  || '',
        // Realistic browser headers — look like CDN fetch
        'User-Agent':    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Accept':        '*/*',
        'Cache-Control': 'no-cache',
      },
      body: encryptedPayload,
      credentials: 'omit',
    });

    if (!res.ok) return null;
    return new Uint8Array(await res.arrayBuffer());
  } catch { return null; }
}

// ── Crypto ────────────────────────────────────────────────────────────────────

async function aesDecrypt(keyBytes, data) {
  try {
    // Format: 12B IV + ciphertext (last 16B = auth tag, handled by AES-GCM)
    if (data.length < 28) return null;
    const iv         = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new Uint8Array(plain);
  } catch { return null; }
}

async function aesEncrypt(keyBytes, data) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const out = new Uint8Array(12 + enc.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(enc), 12);
  return out;
}

// ── Nonce store ───────────────────────────────────────────────────────────────

function checkNonce(hex) {
  const now = Date.now();
  // Prune expired
  for (const [k, exp] of _nonces) if (exp < now) _nonces.delete(k);
  if (_nonces.has(hex)) return false; // replay
  _nonces.set(hex, now + NONCE_WINDOW);
  return true;
}

// ── SSRF protection ───────────────────────────────────────────────────────────

function isPrivateHost(host) {
  // Block localhost and private ranges
  if (host === 'localhost' || host === '0.0.0.0') return true;
  if (host.endsWith('.local') || host.endsWith('.internal')) return true;
  // IPv4 private ranges
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [, a, b] = ipv4.map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
  }
  return false;
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function jitter(minMs, maxMs) {
  const ms = minMs + Math.random() * (maxMs - minMs);
  return new Promise(r => setTimeout(r, ms));
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function relayError(status, code) {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: {
      'Content-Type':                'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control':               'no-store',
    },
  });
}
