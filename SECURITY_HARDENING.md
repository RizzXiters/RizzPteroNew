# Rizz Pterodactyl — Full Security Hardening

This build tightens the existing application while retaining the dashboard pages and main management APIs.

## Changes made

- Removed runtime dependency auto-installation. Install reviewed dependencies during deployment instead of allowing the app to install packages on startup.
- Removed the uploaded `.env` from the distribution and added `.env.example`; secrets must be configured on the host.
- Disabled Express `X-Powered-By`, retained Helmet and security headers, and added `Cache-Control: no-store`.
- CORS is same-origin by default. Cross-origin origins must be listed exactly in `CORS_ORIGINS`.
- Reduced JSON/form request limits and form parameter count.
- Session cookie is named `rizz.sid`, HttpOnly, SameSite=Lax, Secure by default; login regenerates and saves the session to reduce session fixation risk. Logout clears the cookie.
- Session secret must be at least 32 characters.
- API key authentication accepts only the `X-API-Key` header. Do not put API keys in URLs or request bodies; URLs can be retained in logs/history.
- Removed users' PTLA/PTLC values from the admin user-list response. API keys remain viewable only through the authenticated account's own key screen/API.
- Protected HTML pages are no longer directly served by the static middleware. Only `common.css` and `common.js` are public assets; dashboard HTML pages pass through authenticated routes.
- Added username/email/password input validation and tightened new/change password minimum to 12 characters.
- Added symlink-aware path validation for file operations, archive-entry checks, blocked archive symlinks, and disabled 7z/RAR/TAR.BZ2/TAR.XZ extraction until safe per-entry validation is available. ZIP and TAR.GZ/TGZ remain supported through the libraries.
- Reduced maximum upload size from 500 MiB to 100 MiB.
- Removed startup command text from rejected-command audit details to reduce accidental data leakage.
- Kept ngrok auth token out of the child process argument list.
- Added a generic HTTP error handler to avoid returning internal stack traces and paths.

## Deployment

1. Back up the existing application directory and database before replacing files.
2. Copy `.env.example` to `.env` on the server, then set a unique `INITIAL_OWNER_PASSWORD` (at least 12 characters) and a cryptographically random `SESSION_SECRET` (at least 32 characters). Do not use example values.
3. **Rotate credentials from the old `.env`**: it was included in the ZIP uploaded for review. Replace the ngrok token and any other credentials that may have been exposed. If the owner password or session secret were real, change them too. Changing the session secret invalidates existing sessions.
4. Run `npm ci` if a reviewed lockfile is available; otherwise run `npm install` on the server and review the generated lockfile. Then run `npm audit` and update vulnerable dependencies before exposing the app publicly.
5. Use HTTPS in production. Secure cookies are on by default. For local HTTP-only testing, set `COOKIE_SECURE=false`; do not use this on a public deployment.
6. If behind a trusted reverse proxy, set `TRUST_PROXY=1` only when the proxy is configured to overwrite forwarding headers. Otherwise leave it `0`.
7. Set `CORS_ORIGINS` only when an external browser origin is intentionally required, using exact origins such as `https://panel.example.com`, comma-separated. Leave empty for same-origin use.
8. Keep `database.json`, `.session_secret`, `sessions/`, logs, and `servers_data/` outside public/static directories and protect them with restrictive filesystem permissions.
9. Run the app as a non-root OS user. Do not expose the Node port directly if a TLS reverse proxy/firewall is available. Back up the database and server data regularly.

## Compatibility notes

- API integrations must send keys in the `X-API-Key` header; query/body API keys are intentionally rejected.
- The cookie is Secure by default. Local plain HTTP development requires `COOKIE_SECURE=false`.
- 7z, RAR, TAR.BZ2 and TAR.XZ extraction are intentionally disabled because this build cannot validate all their entry/link behaviors safely. ZIP and TAR.GZ/TGZ remain supported.
- Existing frontend uses inline scripts/styles, so the current CSP retains `unsafe-inline` for compatibility. A stronger CSP requires moving inline code to nonce/hash-based scripts/styles and testing the pages.

## Tests and limits

Run `npm run check` for JavaScript syntax checks and `npm test` for security helper smoke tests. These are not a full penetration test. A real deployment still needs dependency audit, HTTPS/proxy review, endpoint authorization testing, backup/restore testing, and external security review.


## Patch: same-origin CORS behind HTTPS proxy

Fixed the CORS middleware to allow requests whose Origin host matches the incoming Host, while continuing to reject other origins unless their exact origin is listed in `CORS_ORIGINS`. This addresses the erroneous `Origin not allowed` response for same-host dashboard/API requests behind HTTPS reverse proxies such as ngrok. This patch is not a full penetration test; verify routes after deployment.


## Patch: anti-DDoS / abuse protection (application layer)

Added without removing any feature or changing the UI:

- Per-IP flood limits (API 600/min, pages 120/min) applied before sessions/disk work; extra per-user limit for heavy actions (npm install, start/restart, upload, extract, compress).
- Auto-ban: sustained rate-limit violations ban the IP for 15 minutes; banned IPs get a cheap 429 before any other processing. Short bursts never cause a ban (max one strike per 10s). Loopback is never banned.
- Slowloris protection: header timeout 15s, request timeout, header count cap, max connection cap.
- Login no longer blocks the event loop (async bcrypt) and has a concurrent-login cap; unknown usernames take the same time as wrong passwords.
- `npm install` is now asynchronous (the panel no longer freezes while it runs), one per server, global cap of 2.
- Concurrent upload cap. `TRUST_PROXY` accepts 1-99 hops (e.g. 2 behind Cloudflare + tunnel).
- All limits are tunable via `.env` (see `.env.example`).

Limits: this cannot stop volumetric/network-layer floods. Put the panel behind Cloudflare (proxy on), and where possible only accept traffic from Cloudflare IPs at the firewall. Set `TRUST_PROXY` correctly or every visitor shares one IP and one rate-limit bucket.
