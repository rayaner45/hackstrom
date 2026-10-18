/**
 * HACKSTROM — Cloudflare Worker (hardened)
 *
 * Responsibilities:
 *  1. Serve the static site from the repository assets (binding: ASSETS).
 *  2. Protect /admin with a REAL server-side password gate:
 *       - SHA-256 verification of the password (hash stored as a secret).
 *       - Signed, HttpOnly, __Host- session cookie (HMAC-SHA256).
 *       - The admin HTML is never sent to unauthenticated visitors.
 *  3. Reject abusive / malformed / internal requests.
 *
 * Required secrets (set with `wrangler secret put`):
 *   ADMIN_PASSWORD_HASH : hex SHA-256 of the admin password
 *   SESSION_SECRET      : random string used to sign session tokens
 */

/* ------------------------- configuration ------------------------- */

const SESSION_COOKIE = "__Host-hs_admin"; // __Host- ⇒ Secure + Path=/ + no Domain
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// Server-side login throttling.
// State lives in the Cloudflare edge cache so it is shared across the many
// isolates that may serve consecutive requests (module memory is NOT shared).
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // observation window
const LOGIN_MAX_FAILS = 5; // failures allowed inside the window
const RL_ORIGIN = "https://hackstrom-ratelimit.internal"; // cache key namespace

/* ------------------------- crypto helpers ------------------------- */

function bytesToB64url(bytes) {
  let bin = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToB64url(sig);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      return decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return null;
}

async function isValidSession(request, env) {
  const raw = readCookie(request, SESSION_COOKIE);
  if (!raw) return false;
  const dot = raw.lastIndexOf(".");
  if (dot <= 0) return false;
  const payload = raw.slice(0, dot);
  const signature = raw.slice(dot + 1);
  if (!env.SESSION_SECRET) return false;
  const expected = await hmac(env.SESSION_SECRET, payload);
  if (!constantTimeEqual(signature, expected)) return false;
  const expiresAt = Number(payload);
  return Number.isFinite(expiresAt) && Date.now() < expiresAt;
}

/* ------------------------- login throttling ------------------------- */

function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "unknown"
  );
}

function rlCacheKey(ip) {
  return new Request(RL_ORIGIN + "/" + encodeURIComponent(ip));
}

const isolateFails = new Map(); // per-isolate mirror (tightens the throttle)

async function rlRead(ip) {
  let local = isolateFails.get(ip);
  if (local && Date.now() - local.windowStart > LOGIN_WINDOW_MS) {
    isolateFails.delete(ip);
    local = null;
  }
  let remote = null;
  try {
    const hit = await caches.default.match(rlCacheKey(ip));
    if (hit) {
      const data = await hit.json();
      if (data && typeof data.count === "number") remote = data;
    }
  } catch (e) {
    /* cache unavailable → fall back to the local mirror only */
  }
  if (!local) return remote;
  if (!remote) return local;
  return {
    count: Math.max(local.count || 0, remote.count || 0),
    windowStart: Math.max(local.windowStart || 0, remote.windowStart || 0),
    blockedUntil: Math.max(local.blockedUntil || 0, remote.blockedUntil || 0),
  };
}

async function rlWrite(ip, state) {
  const body = JSON.stringify({
    count: state.count,
    windowStart: state.windowStart,
    blockedUntil: state.blockedUntil,
  });
  try {
    await caches.default.put(
      rlCacheKey(ip),
      new Response(body, {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "max-age=" + Math.ceil(LOGIN_WINDOW_MS / 1000),
        },
      })
    );
  } catch (e) {
    /* ignore */
  }
}

async function rlClear(ip) {
  try {
    await caches.default.delete(rlCacheKey(ip));
  } catch (e) {
    /* ignore */
  }
}

/** Seconds the client must wait, or 0 when not blocked. */
async function loginRetryAfterSeconds(ip) {
  const s = await rlRead(ip);
  if (!s || !s.blockedUntil || s.blockedUntil <= Date.now()) return 0;
  return Math.max(1, Math.ceil((s.blockedUntil - Date.now()) / 1000));
}

async function recordLoginFailure(ip) {
  const now = Date.now();
  let s = await rlRead(ip);
  if (!s || !s.windowStart || now - s.windowStart > LOGIN_WINDOW_MS) {
    s = { count: 0, windowStart: now, blockedUntil: 0 };
  }
  s.count += 1;
  if (s.count >= LOGIN_MAX_FAILS) s.blockedUntil = now + LOGIN_WINDOW_MS;
  isolateFails.set(ip, s);
  if (isolateFails.size > 5000) isolateFails.clear();
  await rlWrite(ip, s);
}

async function clearLoginFailures(ip) {
  isolateFails.delete(ip);
  await rlClear(ip);
}

/* ------------------------- request guards ------------------------- */

/* Internal paths that must never be served, whatever the platform serves. */
function isInternalPath(path) {
  return (
    /^\/(?:src\/worker\.js|_worker\.js|_redirects|_headers|_routes\.json|\.assetsignore)$/i.test(path) ||
    /^\/(?:wrangler\.(?:toml|jsonc?)|package(?:-lock)?\.json)$/i.test(path) ||
    /^\/scripts\//i.test(path) ||
    /^\/\.(?:git|wrangler)(?:\/|$)/i.test(path) ||
    /\.(?:md|toml|ya?ml|lock|sh)$/i.test(path)
  );
}

function isUnsafePathName(rawPath) {
  if (rawPath.length > 2048) return true;
  if (rawPath.includes("\0")) return true;
  if (rawPath.includes("\\")) return true;
  if (/%2e%2e|%00|%5c|%2f%2e/i.test(rawPath)) return true;
  let decoded = rawPath;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch (e) {
    return true; // malformed percent-encoding
  }
  if (decoded.includes("\0") || decoded.includes("\\")) return true;
  if (/(^|\/)\.\.(\/|$)/.test(decoded)) return true;
  return false;
}

/* ------------------------- responses ------------------------- */

const DENY_HEADERS = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  "X-Robots-Tag": "noindex, nofollow",
};

const LOGIN_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

function loginPage(showError, retryAfter) {
  const errorBlock = showError
    ? '<div class="err">\u274c \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u0629</div>'
    : "";
  const lockBlock = retryAfter
    ? `<div class="err">\u26d4 \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u0643\u062b\u064a\u0631\u0629 \u2014 \u062d\u0627\u0648\u0644 \u0628\u0639\u062f ${retryAfter} \u062b\u0627\u0646\u064a\u0629</div>`
    : "";
  const html = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title>HACKSTROM \u2014 \u0627\u0644\u062f\u062e\u0648\u0644</title>
<style>
:root{--purple:#8b3dff;--cyan:#00d4ff;--text:#f2f2ff;--text3:#8a8ab0}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07070f;color:var(--text);
  font-family:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
.box{width:min(92vw,400px);padding:2.4rem 2rem;border-radius:22px;text-align:center;
  background:rgba(12,12,26,.75);border:1px solid rgba(139,61,255,.3);
  box-shadow:0 30px 90px -35px rgba(139,61,255,.75);backdrop-filter:blur(14px)}
.icon{width:64px;height:64px;margin:0 auto 1rem;border-radius:16px;display:grid;place-items:center;font-size:1.7rem;
  background:linear-gradient(135deg,var(--purple),var(--cyan));box-shadow:0 0 40px rgba(139,61,255,.6)}
h1{margin:0 0 .2rem;font-size:1.15rem;letter-spacing:.22em;font-weight:800}
.sub{font-size:.68rem;letter-spacing:.32em;text-transform:uppercase;color:var(--text3);margin-bottom:1.6rem}
label{display:block;text-align:right;font-size:.8rem;color:var(--text3);margin-bottom:.45rem}
input{width:100%;padding:.85rem 1rem;border-radius:12px;border:1px solid rgba(139,61,255,.35);
  background:rgba(7,7,15,.85);color:var(--text);font-size:1rem;outline:none}
input:focus{border-color:var(--purple);box-shadow:0 0 0 3px rgba(139,61,255,.18)}
button{width:100%;margin-top:1.1rem;padding:.9rem;border:none;border-radius:12px;cursor:pointer;
  font-size:.95rem;font-weight:800;color:#fff;background:linear-gradient(135deg,var(--purple),var(--cyan))}
.err{margin-top:1rem;font-size:.82rem;color:#ff6b8f}
.foot{margin-top:1.4rem;font-size:.7rem;color:var(--text3)}
</style>
</head>
<body>
  <form class="box" method="POST" action="/admin" autocomplete="off">
    <div class="icon">\ud83d\udee1\ufe0f</div>
    <h1>HACKSTROM</h1>
    <div class="sub">Admin Access</div>
    <label for="password">\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631</label>
    <input type="password" id="password" name="password" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" autocomplete="current-password" autofocus required maxlength="128">
    <button type="submit">\u062f\u062e\u0648\u0644</button>
    ${errorBlock}${lockBlock}
    <div class="foot">\u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0645\u062d\u0645\u064a\u0629 \u0639\u0644\u0649 \u0627\u0644\u062e\u0627\u062f\u0645 \ud83d\udd12</div>
  </form>
</body>
</html>`;
  return new Response(html, {
    status: retryAfter ? 429 : 401,
    headers: {
      ...DENY_HEADERS,
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": LOGIN_CSP,
      ...(retryAfter ? { "Retry-After": String(retryAfter) } : {}),
    },
  });
}

function methodNotAllowed(allow) {
  return new Response("405 Method Not Allowed", {
    status: 405,
    headers: { ...DENY_HEADERS, "Content-Type": "text/plain; charset=utf-8", Allow: allow },
  });
}

function badRequest() {
  return new Response("400 Bad Request", {
    status: 400,
    headers: { ...DENY_HEADERS, "Content-Type": "text/plain; charset=utf-8" },
  });
}

async function serveAsset404(env, url) {
  for (const path of ["/404", "/404.html"]) {
    try {
      const res = await env.ASSETS.fetch(new Request(url.origin + path, { method: "GET" }));
      if (res.status === 200) {
        const headers = new Headers(res.headers);
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(await res.text(), { status: 404, headers });
      }
    } catch (e) {
      /* fall through */
    }
  }
  return new Response("404 Not Found", {
    status: 404,
    headers: { ...DENY_HEADERS, "Content-Type": "text/plain; charset=utf-8" },
  });
}

async function serveAdmin(request, env, url) {
  const assetReq = new Request(url.origin + "/admin.html", { method: "GET" });
  const res = await env.ASSETS.fetch(assetReq);
  let html = await res.text();

  // Mark the page as server-authenticated so the client-side gate steps aside.
  html = html.replace("</head>", '<meta name="hs-server-auth" content="1"></head>');

  const headers = new Headers(res.headers);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate");
  headers.set("X-Robots-Tag", "noindex, nofollow");
  headers.set("Vary", "Cookie");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  return new Response(html, { status: 200, headers });
}

async function handleLogin(request, env, url) {
  const ip = clientIp(request);

  const retryAfter = await loginRetryAfterSeconds(ip);
  if (retryAfter) return loginPage(false, retryAfter);

  let password = "";
  try {
    const form = await request.formData();
    password = String(form.get("password") || "").slice(0, 256);
  } catch (e) {
    /* ignore malformed body */
  }

  const providedHash = await sha256Hex(password);
  const expectedHash = String(env.ADMIN_PASSWORD_HASH || "").toLowerCase();

  if (expectedHash && constantTimeEqual(providedHash, expectedHash)) {
    await clearLoginFailures(ip);
    const payload = String(Date.now() + SESSION_TTL_MS);
    const signature = await hmac(env.SESSION_SECRET, payload);
    const token = payload + "." + signature;
    return new Response(null, {
      status: 303,
      headers: {
        Location: "/admin",
        "Set-Cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(
          SESSION_TTL_MS / 1000
        )}`,
        ...DENY_HEADERS,
      },
    });
  }

  await recordLoginFailure(ip);
  await new Promise((r) => setTimeout(r, 350 + Math.floor(Math.random() * 250)));
  return loginPage(true, 0);
}

function logoutResponse() {
  return new Response(null, {
    status: 303,
    headers: {
      Location: "/admin",
      "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      ...DENY_HEADERS,
    },
  });
}

/* ------------------------- entry ------------------------- */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // Reject malformed / traversal / oversized paths outright.
    if (isUnsafePathName(path)) return badRequest();

    // Internal files are never readable, on any platform.
    if (isInternalPath(path)) return serveAsset404(env, url);

    // Never expose the raw admin HTML file directly.
    if (/\/admin\.html$/i.test(path)) return Response.redirect(url.origin + "/admin", 308);

    if (path === "/admin/logout") {
      if (method !== "GET" && method !== "HEAD" && method !== "POST") return methodNotAllowed("GET, POST");
      return logoutResponse();
    }

    if (path === "/admin" || path === "/admin/") {
      if (method === "POST") return handleLogin(request, env, url);
      if (method !== "GET" && method !== "HEAD") return methodNotAllowed("GET, POST");
      if (await isValidSession(request, env)) return serveAdmin(request, env, url);
      return loginPage(false, 0);
    }

    // Static assets are read-only.
    if (method !== "GET" && method !== "HEAD") return methodNotAllowed("GET, HEAD");

    return env.ASSETS.fetch(request);
  },
};
