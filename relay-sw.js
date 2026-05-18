/**
 * Bridge OS — Phantom Relay Service Worker
 * __relay-sw.js
 * github.com/HorrisEllis/Bridge-v2
 *
 * Intercepts POST /__relay/forward (or /<basePath>/__relay/forward).
 * Decrypts payload, forwards to next hop or destination.
 * Re-encrypts response for caller.
 * No logging. No persistence. All state ephemeral.
 */

'use strict';

// Relay path suffix — matched against the END of the URL pathname
// so it works whether served from / or /bridge-test2/
const RELAY_PATH_SUFFIX = '/__relay/forward';
const NONCE_WINDOW      = 60_000; // ms
const MAX_HOPS          = 8;
const MAX_BODY_BYTES    = 512 * 1024;

const _nonces = new Map();

// ── Install + activate ────────────────────────────────────────────────────────

self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message',  msg => {
  if (msg.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

// ── Fetch intercept ───────────────────────────────────────────────────────────

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Match relay path suffix — works at any subdirectory depth
  if (!url.pathname.endsWith(RELAY_PATH_SUFFIX)) return;

  if (e.request.method === 'OPTIONS') {
    e.respondWith(new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'X-B-Hop,X-B-Total,X-B-Next,X-B-Sig,X-B-Nonce,X-B-Key,Content-Type',
        'Access-Control-Max-Age':       '86400',
      },
    }));
    return;
  }

  if (e.request.method !== 'POST') {
    e.respondWith(new Response('Method Not Allowed', { status: 405 }));
    return;
  }

  e.respondWith(handleRelay(e.request));
});

// ── Relay handler ─────────────────────────────────────────────────────────────

async function handleRelay(req) {
  try {
    const hop      = parseInt(req.headers.get('X-B-Hop')   || '1');
    const total    = parseInt(req.headers.get('X-B-Total') || '1');
    const nextB64  = req.headers.get('X-B-Next')  || '';
    const sigHex   = req.headers.get('X-B-Sig')   || '';
    const nonceHex = req.headers.get('X-B-Nonce') || '';
    const keyB64   = req.headers.get('X-B-Key')   || '';

    if (!nonceHex || !sigHex || !keyB64) return relayError(400, 'MISSING_HEADERS');
    if (hop < 1 || hop > MAX_HOPS || total < 1 || total > MAX_HOPS) return relayError(400, 'INVALID_HOP');
    if (!checkNonce(nonceHex)) return relayError(409, 'REPLAY_DETECTED');

    const body = await req.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) return relayError(413, 'PAYLOAD_TOO_LARGE');
    if (body.byteLength < 28)             return relayError(400, 'PAYLOAD_TOO_SMALL');

    const layerKey  = base64ToBytes(keyB64);
    const plaintext = await aesDecrypt(layerKey, new Uint8Array(body));
    if (!plaintext) return relayError(400, 'DECRYPT_FAILED');

    await jitter(30, 180);

    let responseData;

    if (!nextB64 || hop >= total) {
      // EXIT HOP
      const packet = JSON.parse(new TextDecoder().decode(plaintext));
      responseData = await exitForward(packet);
    } else {
      // RELAY HOP
      const nextUrl = new TextDecoder().decode(base64ToBytes(nextB64));
      responseData  = await relayForward(nextUrl, hop + 1, total, plaintext, req.headers);
    }

    if (!responseData) return relayError(502, 'FORWARD_FAILED');

    return new Response(responseData, {
      status: 200,
      headers: {
        'Content-Type':                  'application/octet-stream',
        'Cache-Control':                 'no-store, no-cache, must-revalidate',
        'X-Content-Type-Options':        'nosniff',
        'Access-Control-Allow-Origin':   '*',
        'Access-Control-Allow-Methods':  'POST',
        'Access-Control-Allow-Headers':  'X-B-Hop,X-B-Total,X-B-Next,X-B-Sig,X-B-Nonce,X-B-Key,Content-Type',
      },
    });

  } catch (e) {
    return relayError(500, 'INTERNAL');
  }
}

// ── Exit forward ──────────────────────────────────────────────────────────────

async function exitForward(packet) {
  try {
    const { method = 'GET', url, headers = {}, body = null } = packet;
    const u = new URL(url);
    if (u.protocol !== 'https:') return null;
    if (isPrivateHost(u.hostname)) return null;

    const res = await fetch(url, {
      method,
      headers: {
        ...headers,
        'X-Forwarded-For': undefined,
        'X-Real-IP':       undefined,
        'Via':             undefined,
        'Forwarded':       undefined,
      },
      body:        body ? base64ToBytes(body) : undefined,
      credentials: 'omit',
      redirect:    'follow',
    });

    const resBody        = new Uint8Array(await res.arrayBuffer());
    const resHeadersStr  = JSON.stringify(Object.fromEntries(
      [...res.headers.entries()].filter(([k]) => !['set-cookie','cf-ray','x-amz-cf-id'].includes(k.toLowerCase()))
    ));
    const resHeaderBytes = new TextEncoder().encode(resHeadersStr);

    const packed = new Uint8Array(2 + 2 + resHeaderBytes.length + resBody.length);
    const dv     = new DataView(packed.buffer);
    dv.setUint16(0, res.status);
    dv.setUint16(2, resHeaderBytes.length);
    packed.set(resHeaderBytes, 4);
    packed.set(resBody, 4 + resHeaderBytes.length);
    return packed;
  } catch { return null; }
}

// ── Relay forward ─────────────────────────────────────────────────────────────

async function relayForward(nextUrl, nextHop, total, encryptedPayload, originalHeaders) {
  try {
    const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const res = await fetch(`${nextUrl}${RELAY_PATH_SUFFIX}`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/octet-stream',
        'X-B-Hop':       String(nextHop),
        'X-B-Total':     String(total),
        'X-B-Next':      originalHeaders.get('X-B-Next-Next') || '',
        'X-B-Sig':       originalHeaders.get('X-B-Sig-Next')  || '',
        'X-B-Nonce':     nonce,
        'X-B-Key':       originalHeaders.get('X-B-Key-Next')  || '',
        'User-Agent':    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Accept':        '*/*',
        'Cache-Control': 'no-cache',
      },
      body:        encryptedPayload,
      credentials: 'omit',
    });
    if (!res.ok) return null;
    return new Uint8Array(await res.arrayBuffer());
  } catch { return null; }
}

// ── Crypto ────────────────────────────────────────────────────────────────────

async function aesDecrypt(keyBytes, data) {
  try {
    if (data.length < 28) return null;
    const iv  = data.slice(0, 12);
    const ct  = data.slice(12);
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new Uint8Array(plain);
  } catch { return null; }
}

// ── Nonce store ───────────────────────────────────────────────────────────────

function checkNonce(hex) {
  const now = Date.now();
  for (const [k, exp] of _nonces) if (exp < now) _nonces.delete(k);
  if (_nonces.has(hex)) return false;
  _nonces.set(hex, now + NONCE_WINDOW);
  return true;
}

// ── SSRF protection ───────────────────────────────────────────────────────────

function isPrivateHost(host) {
  if (host === 'localhost' || host === '0.0.0.0') return true;
  if (host.endsWith('.local') || host.endsWith('.internal')) return true;
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
  return new Promise(r => setTimeout(r, minMs + Math.random() * (maxMs - minMs)));
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
