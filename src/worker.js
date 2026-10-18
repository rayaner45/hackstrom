/**
 * HACKSTROM — Cloudflare Worker
 *
 * Responsibilities:
 *  1. Serve the static site from the repository assets (binding: ASSETS).
 *  2. Protect /admin with a REAL server-side password gate.
 *     - Password is verified on Cloudflare (SHA-256 hash stored as a secret).
 *     - On success a signed, HttpOnly session cookie is issued (HMAC-SHA256).
 *     - The admin HTML is never sent to unauthenticated visitors.
 *
 * Required secrets (set with `wrangler secret put`):
 *   ADMIN_PASSWORD_HASH : hex SHA-256 of the admin password
 *   SESSION_SECRET      : random string used to sign session tokens
 */

const SESSION_COOKIE = "hs_admin";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

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
  const expected = await hmac(env.SESSION_SECRET, payload);
  if (!constantTimeEqual(signature, expected)) return false;
  const expiresAt = Number(payload);
  return Number.isFinite(expiresAt) && Date.now() < expiresAt;
}

/* ------------------------- responses ------------------------- */

const DENY_HEADERS = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store, no-cache, must-revalidate",
  "X-Robots-Tag": "noindex, nofollow",
};

function loginPage(showError) {
  const errorBlock = showError
    ? '<div class="err">\u274c كلمة المرور غير صحيحة</div>'
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
:root{--purple:#8b3dff;--cyan:#00d4ff;--bg:#07070f;--text:#f0f0ff;--text3:rgba(160,164,220,.55)}
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);
  font-family:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
  background-image:radial-gradient(ellipse 60% 50% at 20% 0%,rgba(139,61,255,.18),transparent),radial-gradient(ellipse 50% 60% at 80% 100%,rgba(0,212,255,.12),transparent)}
.box{width:min(92vw,380px);padding:2.2rem 1.8rem;border-radius:20px;border:1px solid rgba(139,61,255,.3);
  background:rgba(14,14,32,.9);backdrop-filter:blur(16px);box-shadow:0 30px 80px -30px rgba(139,61,255,.6);text-align:center}
.icon{width:64px;height:64px;margin:0 auto 1rem;border-radius:16px;display:grid;place-items:center;font-size:1.7rem;
  background:linear-gradient(135deg,var(--purple),var(--cyan));box-shadow:0 0 40px rgba(139,61,255,.6)}
h1{font-size:1.15rem;letter-spacing:.22em;font-weight:800;margin-bottom:.15rem}
.sub{font-size:.68rem;letter-spacing:.32em;text-transform:uppercase;color:var(--text3);margin-bottom:1.6rem}
label{display:block;text-align:right;font-size:.8rem;color:var(--text3);margin-bottom:.45rem}
input{width:100%;padding:.85rem 1rem;border-radius:12px;border:1px solid rgba(139,61,255,.35);
  background:rgba(7,7,15,.85);color:var(--text);font-size:1rem;outline:none;transition:.25s}
input:focus{border-color:var(--purple);box-shadow:0 0 0 3px rgba(139,61,255,.18)}
button{width:100%;margin-top:1.1rem;padding:.9rem;border:none;border-radius:12px;cursor:pointer;
  font-size:.95rem;font-weight:800;color:#fff;background:linear-gradient(135deg,var(--purple),var(--cyan));
  box-shadow:0 14px 40px -16px rgba(139,61,255,.9);transition:.25s}
button:hover{transform:translateY(-2px)}
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
    ${errorBlock}
    <div class="foot">\u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629 \u0645\u062d\u0645\u064a\u0629 \u0639\u0644\u0649 \u0627\u0644\u062e\u0627\u062f\u0645 \ud83d\udd12</div>
  </form>
</body>
</html>`;
  return new Response(html, {
    status: 401,
    headers: {
      ...DENY_HEADERS,
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    },
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
  headers.set("Cache-Control", "private, no-store, max-age=0, must-revalidate");
  headers.set("X-Robots-Tag", "noindex, nofollow");
  headers.set("Vary", "Cookie");
  return new Response(html, { status: 200, headers });
}

async function handleLogin(request, env, url) {
  let password = "";
  try {
    const form = await request.formData();
    password = String(form.get("password") || "");
  } catch (e) {
    /* ignore malformed body */
  }

  const providedHash = await sha256Hex(password);
  const expectedHash = String(env.ADMIN_PASSWORD_HASH || "").toLowerCase();

  if (expectedHash && constantTimeEqual(providedHash, expectedHash)) {
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

  return loginPage(true);
}

/* ------------------------- entry ------------------------- */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Never expose the raw admin HTML file directly.
    if (/\/admin\.html$/i.test(path)) {
      return Response.redirect(url.origin + "/admin", 308);
    }

    if (path === "/admin/logout") {
      return new Response(null, {
        status: 303,
        headers: {
          Location: "/admin",
          "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
          ...DENY_HEADERS,
        },
      });
    }

    if (path === "/admin" || path === "/admin/") {
      if (request.method === "POST") return handleLogin(request, env, url);
      if (await isValidSession(request, env)) return serveAdmin(request, env, url);
      return loginPage(false);
    }

    // Everything else: static assets (with _headers rules applied).
    return env.ASSETS.fetch(request);
  },
};
