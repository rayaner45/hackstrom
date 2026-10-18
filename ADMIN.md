# HACKSTROM — Security & Admin

## Admin access
- **URL:** https://hackstrom.fahemrayane.workers.dev/admin
- Authentication is enforced **on the server** (Cloudflare Worker):
  - correct password → signed `HttpOnly; Secure; SameSite=Strict` session cookie (8 h),
  - the admin HTML is **never** sent to unauthenticated visitors (401 login page instead).
- The public mirror **https://hackstrom.pages.dev** does **not** contain the admin page.

## Public mirror (pages.dev)
`https://hackstrom.pages.dev` is a **static, admin-free** mirror.
Its upload contains a `_redirects` file that sends `/admin`, `/admin.html`
and `/admin/*` back to `/` (302). The admin page is **never** uploaded there.

Rebuild + deploy the mirror with:
```bash
rm -rf /tmp/hs-public
mkdir -p /tmp/hs-public/src/css /tmp/hs-public/src/js /tmp/hs-public/data
cp index.html robots.txt _headers /tmp/hs-public/
cp data/leaderboard.json /tmp/hs-public/data/
cp src/css/main.css /tmp/hs-public/src/css/
cp src/js/main.js src/js/loader.js /tmp/hs-public/src/js/
cp deploy/pages/admin.html /tmp/hs-public/admin.html   # harmless redirect page
cp deploy/pages/_redirects  /tmp/hs-public/_redirects
npx wrangler pages deploy /tmp/hs-public --project-name hackstrom --branch main
```

## Secrets (Cloudflare Worker)

| Secret | Purpose |
|---|---|
| `ADMIN_PASSWORD_HASH` | hex SHA‑256 of the admin password |
| `SESSION_SECRET`      | random key used to sign session cookies |

### Rotate the admin password
```bash
# 1) update the server-side hash
printf '%s' 'NEW_PASSWORD' | sha256sum | cut -d' ' -f1 \
  | npx wrangler secret put ADMIN_PASSWORD_HASH

# 2) update the client-side fallback (src/js/admin.js → PASS_SALT / PASS_KEY)
python3 -c "import os,hashlib; s=os.urandom(16).hex(); \
  print('PASS_SALT =', repr(s)); \
  print('PASS_KEY  =', repr(hashlib.pbkdf2_hmac('sha256', b'NEW_PASSWORD', s.encode(), 200000, 32).hex()))"
```

### Rotate the session-signing key
```bash
openssl rand -hex 32 | npx wrangler secret put SESSION_SECRET
```

## Hardening applied
- **Strict CSP** — `script-src 'self'` (no `'unsafe-inline'` for scripts).
- All inline scripts extracted to external files (`src/js/loader.js`, `src/js/admin.js`).
- **XSS fixes** — badge/name/avatar values are escaped (`esc`/`escAttr`); numbers coerced.
- **SRI** on the jsDelivr icon stylesheet.
- **Headers** — HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, `COOP`, `CORP`, `X-Permitted-Cross-Domain-Policies: none`.
- `robots.txt` disallows `/admin`.
- `.assetsignore` blocks `.git`, `.wrangler`, `wrangler.toml` and `src/worker.js`
  from ever being served as static assets.

## GitHub token
Use a **Fine-grained personal access token** limited to:
- Repository access → only `rayaner45/hackstrom`
- Permissions → Repository permissions → **Contents: Read and write** (nothing else).

Never commit a token or the admin password to the repository.
