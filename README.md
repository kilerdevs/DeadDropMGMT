# DeadDropMGMT

[![CI](https://github.com/kilerdevs/DeadDropMGMT/actions/workflows/ci.yml/badge.svg)](https://github.com/kilerdevs/DeadDropMGMT/actions/workflows/ci.yml)

**A secure, bare-metal order management system for coordinating deliveries to dead-drop locations.**

Recipients look up an order by token, unlock an encrypted location with a password, and confirm receipt — all without ever exposing the underlying data. Built with zero external PHP dependencies; every security concern is addressed at the application layer, not bolted on with a framework.

![PHP](https://img.shields.io/badge/PHP-8.0%2B-777bb4?logo=php&logoColor=white)
![Database](https://img.shields.io/badge/DB-MySQL%20%2F%20MariaDB-4479A1?logo=mysql&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-zero%20(no%20Composer)-brightgreen)
![2FA](https://img.shields.io/badge/2FA-TOTP%20(RFC%206238)-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Disclaimer

This project was created **for educational purposes** — to demonstrate secure application design: encryption at rest, CSRF protection, rate limiting, two-factor authentication, and audit logging in a real, working PHP application.

The author provides this software **"as is," without warranty of any kind**, and assumes **no responsibility or liability for how it is used**, including but not limited to any illegal, unauthorized, or unintended use by any party. You are solely responsible for ensuring your use of this software complies with all applicable laws and regulations in your jurisdiction.

**By downloading, installing, deploying, or otherwise using this software, you acknowledge that you have read this disclaimer and agree to be bound by it.** If you do not agree, do not use this software.

---

## Contents

- [Disclaimer](#disclaimer)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Threat Model](#threat-model)
- [Docker](#docker)
- [Tests](#tests)
- [Third-Party Code & External Services](#third-party-code--external-services)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)
- [Elsewhere: Architecture Decision Records](docs/ADR.md)

---

## Features

### Public (recipient) flow
- Token-based order lookup — no account needed
- Password-protected location reveal (AES-256-GCM, decrypted server-side, never sent to client unencrypted)
- Live expiry countdown with redirect timer
- Photo gallery for reference images
- One-click links to Google Maps / Apple Maps
- Delivery confirmation endpoint

### Admin dashboard
- Role-based access: **Owner** (full control) and **Courier** (own orders only)
- Passwordless first login with enrollment secrets: accounts can be created without a password — the owner receives a single-use, 24-hour enrollment code (shown exactly once, stored only hashed), and the login form asks for that code instead of a password for unclaimed usernames. Knowing just the username gets an attacker nothing; claiming burns the code (5-minute setup window, race-guarded, audited). Presetting a password at creation still works
- Zero-config first run: on a fresh install (no accounts yet) the login page itself becomes a create-owner form — pick a username, set a password, done; no SQL or seed constants needed. The form disappears permanently once any account exists
- Create orders with an interactive Leaflet map picker
- Auto-generated memorable pickup passphrases (6 words + 4-digit number + symbol, ~64.6 bits) — shown **once** at creation, stored only as a bcrypt hash, replaceable but never recoverable
- Extend / close / delete orders with CSRF-protected actions
- Photo upload with automatic GD compression
- Configurable TTL — orders auto-expire and are securely wiped
- Two-factor authentication (TOTP) — self-service enroll/disable per account, QR + manual entry, works with any RFC 6238 authenticator app — see [recommended open-source apps](TOTP-APPS.md); mandatory for couriers, optional but strongly encouraged for the owner (with a "why" explainer on the enrollment page and a persistent warning banner on every admin page while it's off)
- Audit log — every write action recorded with actor, IP, and timestamp
- Analytics log: every lookup, unlock attempt, and confirmation recorded with IP + user-agent
- CSV export of the event log
- Panic mode (owner only)

### Operations
- IP-based rate limiting, configurable and togglable per surface (pickup guessing, admin login, 2FA codes)
- Pseudo-cron cleanup on each page visit (throttled to 1×/hour)
- Real cron endpoint (`cron/cleanup.php`) for server-side scheduling
- Secure file wipe: overwrites with null bytes before `unlink()`

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | PHP 8.0+ (strict types, procedural, no Composer) |
| Database | MySQL / MariaDB |
| Encryption | OpenSSL — AES-256-GCM (authenticated), random nonce per record |
| Auth | bcrypt cost=12, TOTP 2FA, CSRF tokens, session hardening |
| Frontend | Vanilla JS (ES5+), CSS Grid/Flexbox |
| Maps | Leaflet + OpenStreetMap |
| Webserver | Apache — mod_rewrite, mod_headers, .htaccess path protection |

---

## Threat Model

### 1. Attacker capabilities

The model assumes adversaries ranging from opportunistic to well-resourced:

| # | Adversary | Capabilities |
|---|---|---|
| A1 | Random internet scanner | Unauthenticated HTTP requests against public endpoints; automated exploitation tooling |
| A2 | Curious recipient / courier | Legitimate access to their own order data; attempts to read *other* orders or admin functions |
| A3 | Network observer | Passive traffic sniffing between client and server (mitigated externally by TLS — see Residual Risk) |
| A4 | Malicious DB reader | Read (not write) access to the MySQL database via SQL injection elsewhere on a shared host, stolen dump, or careless backups |
| A5 | Log/backup tamperer | Filesystem write access to `logs/` and `uploads/` through a path traversal bug or compromised cron — wants to erase traces of an intrusion |
| A6 | Host-level attacker | Full code execution on the server |

### 2. Assets

| # | Asset | Sensitivity |
|---|---|---|
| S1 | Drop locations (encrypted at rest) | Core secret — physical safety of the recipient depends on it |
| S2 | Pickup passwords | Gate location reveal |
| S3 | Order tokens (16-char lookup codes) | Capability URLs — possession grants lookup access |
| S4 | TOTP secrets | 2FA enrollment for owner/courier accounts |
| S5 | Admin sessions & credentials | Full panel control |
| S6 | Audit trail & application log integrity | Evidence — must survive tampering attempts (A5) |
| S7 | Availability | Delivered orders auto-expire; loss is by design but premature loss is not |

### 3. Trust boundaries

```
Browser ──[TLS, external]── Web server / PHP
                                │
        ┌───────────────────────┼──────────────────────┐
   Public zone             Admin zone               Server-local
   index.php               admin/* (session+CSRF    config.php
   receive.php             + role checks)           includes/
        │                        │                  logs/, uploads/
        └────────┬───────────────┘                        │
              MySQL (no trust in DB contents ←───────────┘
                                 
   Outbound: PHP → OSM/Nominatim (+ optional proxy pool)
   Embedded: Browser iframe → OSM tiles  ⚠ leaks visitor IP to OSM
```

- **Public ↔ PHP**: no session, only rate limiting and token entropy protect S3
- **Admin ↔ PHP**: session cookie + CSRF token + TOTP; owner vs courier role split
- **PHP ↔ MySQL**: prepared statements; the DB is *never* trusted to hold secrets in readable form (S1–S4 encrypted/hashed before insert)
- **PHP ↔ filesystem**: `.htaccess` denies direct web access to `includes/`, `logs/`, `config.php`
- **PHP ↔ OSM**: server-side proxies so admin IPs never leave the server; fail-closed proxy pool optional

### 4. Mitigations (capability → asset mapping)

| Threat | Mitigation | Protects | Against |
|---|---|---|---|
| SQL injection | PDO prepared statements throughout — zero string interpolation in SQL | S1–S5 | A1–A2 |
| Password storage | bcrypt cost=12 via `password_hash()` / `password_verify()` | S5 | A4 |
| Account takeover | TOTP 2FA (RFC 6238) — self-service per account, secret GCM-encrypted at rest. Passwordless accounts are claimed only with a single-use enrollment secret, never by username alone | S5 | A1, A2 |
| Location data at rest | AES-256-GCM (authenticated), random nonce per record; legacy CBC rows are rejected at runtime — migrate with `tools/migrate_cbc_to_gcm.php`. Key lives only in `config.php` or env (`DDMGMT_AES_KEY_HEX`), never in DB | S1, S4 | A4 |
| Pickup password guessing | Dual budget enforced together: IP-based limiter (**fail-closed**: if the limiter DB is down, pickup and login are denied, not waved through) **and** a per-session failure bucket — whoever trips either is blocked; ≥64-bit generated passphrases (6 words + 4-digit + symbol), hash-only at rest, equalized-cost responses for unknown tokens | S2 | A1 |
| Token enumeration | 16-char alphanumeric random tokens (~95 bits); unknown-token answers burn the same bcrypt cost and return the same body as wrong passwords when a credential was submitted; receipt requires the delivered state atomically | S3 | A1 |
| Session fixation / theft | `session_regenerate_id(true)` on login; `httponly`, `samesite=Strict`, `secure` when HTTPS | S5 | A1, A2 |
| CSRF | 64-byte random token in session, `hash_equals()` on every POST | S5, S7 | A2 |
| XSS | `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` on all user-derived output; strict CSP with nonces | S5 | A1, A2 |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, `nosniff`, HSTS | S5 | A1 |
| Error leakage | `display_errors=0`, exceptions caught and logged, generic user-facing messages | S1–S5 | A1 |
| Direct file access | `.htaccess` blocks `includes/`, `config.php`, `logs/`, `cron/` | all local assets | A1 |
| Log tampering | Structured JSONL log chained with HMAC-SHA256; one-click verification reports first broken entry. HMAC key derived from AES key with domain separation | S6 | A5 |
| Unaccountable writes | Every admin create/edit/delete/setting-change logged with actor, IP, timestamp | S6 | A2, A5 |
| Admin IP exposure to OSM | Tile/geocode requests proxied server-side; optional fail-closed anonymity proxy pool (manual or auto-discovered) | owner/courier privacy | A3 |

### 5. Residual risk

What remains after mitigations — stated plainly:

- **A6 wins by definition.** An attacker with code execution reads the AES key,
  the DB, and the log-HMAC key from the same host; the log chain detects
  tampering but cannot prevent it. The design goal is: everything short of
  full host compromise stays defensible.
- **TLS and WAF are external.** The app terminates neither; without HTTPS in
  front, A3 sees everything including pickup passwords. Deploy behind
  TLS (certbot, hosting certs, load balancer) and ideally a WAF/edge layer.
- **OSM embed iframe** sends the *recipient's* IP to OpenStreetMap when viewing
  a delivered order's location — browser-side, outside app control. Zero
  third-party contact requires a self-hosted tile server.
- **Legacy CBC rows are rejected at runtime.** Run
  `php tools/migrate_cbc_to_gcm.php` after upgrading (dry-run first); until
  you do, pre-GCM orders are unreadable by the app — loudly, not silently.
- **Pickup passwords are hash-only.** Generated credentials appear exactly
  once (creation flash message) and can be replaced in the order editor, but
  never displayed again. `php tools/purge_pickup_password_recovery.php`
  clears the encrypted copies older versions stored.
- **Panic mode destroys everything, evidence included** — orders, photos,
  event log, audit log and on-disk logs; only accounts and settings survive.
  Partial filesystem failures are reported honestly and the wipe is re-runnable (ADR-015).
- **Rate limiting is IP-based *plus* a per-session failure bucket**, which
  fixes both classic blind spots: strangers behind one NAT/VPN exit no longer
  lock each other out (separate session buckets), and an attacker must rotate
  IP *and* cookie per attempt. Still tunable in Settings; still no defense
  against truly industrial distributed guessing — the ≥64-bit passphrase and
  auto-expiry carry that.
- **Availability is best-effort**: pseudo-cron cleanup runs on page hits unless
  a real cron calls `cron/cleanup.php`; nothing protects against DDoS.

---

## Docker

Three interchangeable stacks — same app, different web server. Each boots
Apache/nginx/Caddy plus MariaDB 11, auto-loads `setup.sql` on first boot,
renders `config.php` from the committed template and (if no
`DDMGMT_AES_KEY_HEX` is provided) generates a key and persists it on the
`app-config` volume.

```bash
# Apache (mod_php), the default:
docker compose up -d --build

# nginx + PHP-FPM:
docker compose -f docker-compose.nginx.yml up -d --build

# Caddy + PHP-FPM (swap :80 for your hostname in docker/Caddyfile for auto-TLS):
docker compose -f docker-compose.caddy.yml up -d --build
```

The app is then on http://localhost:2137 (`APP_PORT` in `.env` to change).
Overrides live in `.env` (see `.env.example`) — DB password, port, AES key.
**Back up the `app-config` volume** if you let the key auto-generate: losing it
means losing all encrypted location data. TLS is never terminated by the app —
put certbot/LB/Caddy-with-hostname in front. CI builds both images and smoke
tests all three stacks end-to-end on every push.

---

## Tests

Zero-dependency PHP test suite — no PHPUnit, each file is a standalone script:

```bash
php tests/schema_loader.php   # loads setup.sql into an isolated deaddrops_test DB
php tests/run_all.php         # runs every tests/*Test.php, exits non-zero on failure
```

The suite never touches your real database: `tests/bootstrap.php` forces
`DDMGMT_DB_NAME=deaddrops_test` and points the app at TCP loopback unless you
say otherwise. Covered: AES-256-GCM roundtrip + tamper rejection + CBC
rejection/migration (`CryptoTest`), login/2FA/session-fixation/logout (`AuthTest`),
CSRF tokens (`CsrfTest`), RFC 4648 base32 + RFC 6238 vectors (`TotpTest`),
rate-limit budgets/scopes/window-expiry/kill-switch (`RateLimitTest`),
owner-vs-courier authorization (`AuthorizationTest`) and expiry cleanup with
photo-file shredding (`CleanupTest`), and an end-to-end public-flow suite
(`PublicFlowTest`) driving a real HTTP server: token lookup, password
unlock, PRG reveal, receipt confirmation, rate limiting and the per-session
failure bucket. Runs automatically in GitHub Actions
(`.github/workflows/ci.yml`, MariaDB 11 service container) across PHP
8.0–8.4, with smoke tests of all three Docker stacks.

**Coverage.** A separate CI job runs the suite under `pcov` and reports line
coverage over `includes/` — the security-critical library code (crypto,
auth, TOTP, rate limiting, logger, cleanup). The summary lands in the job
summary; a browsable HTML report is uploaded as an artifact for 14 days.
Locally: `composer install && php tests/coverage_runner.php` — Composer is
dev-only tooling, the application itself never touches it.

---

## Third-Party Code & External Services

The PHP backend has zero dependencies — no Composer, no framework. The browser, however, does load a few third-party pieces. Full disclosure:

### Vendored (bundled in this repo, served from your own domain — no CDN, works under the strict CSP)

| Asset | Version | License | Used for |
|---|---|---|---|
| [Leaflet](https://leafletjs.com/) | 1.9.4 | BSD-2-Clause | Interactive map picker (`admin/vendor/leaflet/`) |
| [QRCode.js](https://github.com/davidshimjs/qrcodejs) (davidshimjs, based on Kazuhiko Arase's original) | — | MIT | Renders the 2FA enrollment QR code client-side (`admin/vendor/qrcode/`) |
| [IBM Plex Mono](https://github.com/IBM/plex) | v20, latin + latin-ext subsets only | SIL OFL 1.1 | The site's monospace font (`fonts/ibm-plex-mono/`, ~56 KB for all 4 files) |

All three are unmodified upstream source, committed as static files — nothing is fetched over the network to load them. Google Fonts previously served IBM Plex Mono; it's now self-hosted, subset to just the Latin ranges this UI (Polish/English) actually uses to keep it light — the cyrillic/vietnamese subsets Google's CSS also served were dropped entirely.

### Proxied server-side (admin panel only)

The admin map picker (`admin/new_order.php`, `admin/edit.php`) never talks to OpenStreetMap directly. Tile requests go through `admin/tile_proxy.php` (validated `z`/`x`/`y`, disk-cached under `cache/osm_tiles/` for 7 days, so repeat views don't even leave the server) and address search goes through `admin/geocode_proxy.php` to Nominatim. Both require an authenticated admin session. The upshot: an owner/courier's real IP and search queries are never exposed to OpenStreetMap — only this server's IP is, and the CSP (`includes/auth.php`) reflects that (`img-src`/`connect-src` no longer allowlist any OSM host for the admin panel).

### Live external services (real network calls the browser still makes)

| Service | Called from | Purpose | Why it isn't bundled |
|---|---|---|---|
| OpenStreetMap embed (`www.openstreetmap.org`) | Public location-reveal page | Embedded `<iframe>` map showing the pickup pin | Rendered server-side per arbitrary coordinate on request — there's nothing static to bundle |
| Google Maps / Apple Maps | Public location-reveal page | Plain outbound `<a href>` links | Not a resource load at all — nothing is fetched or embedded, so there's nothing to bundle. Clicking just opens the respective site in a new tab |
| Public proxy lists — Proxifly, monosans, TheSpeedX, roosterkid (`raw.githubusercontent.com`) | Admin → Settings → proxy pool, only when the owner clicks **Auto-discover** | Candidate anonymity-focused proxies for the optional OSM proxy routing | Live, regularly-refreshed community lists — bundling them would be stale within days. Unrated HTTP candidates are additionally vetted through a live header-echo judge so only proxies that demonstrably do not leak the server's IP are kept |

These are exactly the hosts allowlisted in the public CSP (`includes/auth.php`) — nothing else can load. **Worth knowing:** the embedded map iframe sends the *customer's* IP to OSM when they view a delivered order's location — that's a request their own browser makes, and is in some tension with the "no tracking" claim shown on the public pages (that claim is about *this app* not tracking recipients, not about the third party it embeds a map from). If your threat model requires zero third-party contact even for that, the only remaining option is standing up your own tile server and pointing the public page at a self-hosted map instead of the OSM embed.

### Proxy auto-discovery sources (server-side, only on explicit owner action)

All fetched from GitHub raw by the server (never the browser) when the owner clicks **Auto-discover** in Settings → proxy pool. Candidates are probed against a real OSM tile; HTTP proxies from unrated sources must additionally pass a live anonymity check (below). Sources, and what each contributes (`includes/proxy.php` is the single place these are configured):

| Source | Repo | Provides | Anonymity metadata |
|---|---|---|---|
| Proxifly | `proxifly/free-proxy-list` | HTTP + SOCKS4/5 (structured JSON) | Yes — per-proxy rating; only anonymous/elite HTTP accepted |
| monosans | `monosans/proxy-list` | HTTP, SOCKS4, SOCKS5 (hourly pre-checked) | No — HTTP entries treated as unrated, SOCKS anonymous by protocol |
| TheSpeedX | `TheSpeedX/PROXY-LIST` | HTTP, SOCKS4, SOCKS5 (high volume) | No — HTTP entries treated as unrated |
| roosterkid | `roosterkid/openproxylist` | HTTPS (CONNECT-capable HTTP), SOCKS5 (curated) | No — HTTP entries treated as unrated |

**Anonymity judges.** HTTP proxies without a source-provided rating are verified live: the server fetches a header-echo page *through* the candidate proxy and rejects it if the echo contains the server's own IP in the origin or any forwarded header (`Via`, `X-Forwarded-For`, …). Judges used, in order: `httpbin.org/get`, `azenv.net/` (plain HTTP so the check also works through CONNECT-less proxies). If the server's own public IP cannot be determined first, all unrated HTTP candidates are dropped rather than trusted. SOCKS proxies are never header-injecting by protocol design and skip this check.

**What this means for your server's exposure:** clicking Auto-discover makes your server's IP visible to GitHub (list fetch, direct — not proxied), to every candidate proxy probed, and to the judge services. OSM itself is only contacted through accepted proxies while routing is enabled.

---

## Project Structure

```
DeadDropMGMT/
│
├── index.php                 Public order lookup & location reveal
├── receive.php               Delivery confirmation endpoint
├── public.js, gallery.js     Public-facing JS (lookup flow, photo gallery)
├── style.css                 Public CSS
├── favicon.svg               Green dead-drop pin on dark tile
├── error/                    Localized error pages (403 / 404 / 500 / 503)
├── config.php                DB credentials, AES key, admin hash   ← never commit
├── setup.sql                 Full DB schema — one file, fresh install or upgrade
├── .htaccess                 Blocks config.php, includes/, logs/ from web
├── fonts/                    Self-hosted IBM Plex Mono (no Google Fonts)
│
├── admin/                    Admin panel (owner + courier roles)
│   ├── index.php             Login wall
│   ├── login.php             Credential check → 2FA if enabled
│   ├── verify_2fa.php        TOTP code prompt (login step 2)
│   ├── set_lang.php          Per-account UI language switcher (AJAX)
│   ├── 2fa.php               Self-service 2FA enroll / disable (QR + manual)
│   ├── orders.php            Order list with courier filtering
│   ├── new_order.php         Order creation form (Leaflet map picker)
│   ├── create.php            Order creation handler
│   ├── edit.php              Edit order — status, location, password, photos
│   ├── delete.php            Order deletion (wipes sensitive columns first)
│   ├── order_close.php       Order close (immediate removal)
│   ├── order_remove.php      Order removal variant
│   ├── extend.php            Deadline extension
│   ├── mark_delivered.php    Status → delivered, starts TTL clock
│   ├── photo_delete.php      Photo removal
│   ├── save_setting.php      Settings auto-save endpoint
│   ├── log_verify.php         Log chain integrity verification (owner only)
│   ├── download_log.php      Error log export
│   ├── proxy_action.php      OSM proxy pool management (add / delete / discover)
│   ├── tile_proxy.php        Server-side OSM tile fetch (optional proxy routing)
│   ├── geocode_proxy.php     Server-side Nominatim address search
│   ├── osm_status.php        Badge feed: which proxy served the last OSM request
│   ├── osm_monit.php         Proxy status badge (map pages)
│   ├── users.php             Courier management (owner only)
│   ├── user_action.php       Courier create / delete / password / 2FA reset
│   ├── audit_log.php         Write-action audit trail (owner only)
│   ├── analytics.php         Event log viewer + CSV download
│   ├── panic.php             Emergency mode (owner only)
│   ├── settings.php          Configurable site parameters
│   ├── sidebar.php           Shared sidebar partial
│   ├── totp_banner.php       Shared disabled-2FA warning partial
│   ├── admin.js, style.css   Panel JS + CSS
│   └── vendor/               Leaflet + QRCode.js — vendored locally, no CDN
│
├── includes/                 Blocked from web via .htaccess
│   ├── db.php                PDO singleton
│   ├── auth.php              Session, CSRF, rate limiting, security headers
│   ├── crypto.php            AES-256-GCM encrypt/decrypt, bcrypt, 64-bit passphrase generator
│   ├── order_state.php       Atomic state machine: deliver / receive / delete / expiry
│   ├── totp.php              TOTP (RFC 6238) — base32, otpauth:// URI
│   ├── audit.php             Write-action audit logger
│   ├── settings.php          Settings cache (one DB query per page load)
│   ├── i18n.php              Translation engine (8 languages, CLDR plurals)
│   ├── proxy.php             OSM outbound proxy pool + free-proxy discovery
│   ├── analytics.php         Event logger
│   ├── logger.php            Structured JSONL log + tamper-evident hash chain
│   ├── cleanup.php           Expired order deletion (pseudo-cron + real cron)
│   └── lang/                 Translations: pl, en, de, ru, fr, es, uk, it
│
├── logs/                     Error log (blocked from web)
├── uploads/                  Order photos (blocked from web)
├── cache/                    OSM tile disk cache (blocked from web)
└── cron/
    └── cleanup.php           Server-side cron endpoint (call hourly)
```

---

## Setup

### 1. Database

One file, one command — works for a fresh install *and* for upgrading an existing database from any earlier version. Every statement is idempotent, so it's also safe to just re-run whenever you pull updates:

```bash
mysql -u root -p < setup.sql
```

### 2. AES-256 Key

```bash
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
```

Paste the 64-char hex output into `config.php` as `AES_KEY_HEX` — or better,
keep it out of the working tree entirely by exporting it as an environment
variable (`DDMGMT_AES_KEY_HEX`); `config.php` reads the environment first and
falls back to the literal value. DB credentials work the same way via
`DDMGMT_DB_USER` / `DDMGMT_DB_PASS`.
**Back this up.** Losing it means losing all encrypted location data.

#### Rotating the AES key

Rotate when the key may have been exposed (leaked backup, departed admin,
incident), or on a schedule you would defend to the people whose locations you
hold — yearly is a reasonable default. The bundled tool makes it mechanical:

```bash
# rehearse first: verifies every row decrypts with the old key, writes nothing
php tools/rotate_aes_key.php --old=<OLD_64HEX> --new=<NEW_64HEX> --dry-run

# apply: re-encrypts orders.locations, pickup passwords and TOTP secrets,
# verifies each row read-back under the new key, single transaction —
# any undecryptable row aborts and rolls everything back
php tools/rotate_aes_key.php --old=<OLD_64HEX> --new=<NEW_64HEX>
```

Procedure:

1. **Back up the database.**
2. **Verify the log chain** (Settings → *Verify log integrity*) and **archive
   `logs/app.log`** — the chain is HMAC-keyed with the AES key, so historical
   entries will not verify under the new key. The next entry starts a fresh
   genesis chain; keep the archived file together with the old key if you may
   ever need to re-prove it.
3. Pick a maintenance window — no writes while rotating.
4. Run the dry-run, then the real rotation.
5. Switch `DDMGMT_AES_KEY_HEX` to the new key everywhere it lives (env vars,
   `config.php`, backups of both) and restart the app.
6. Destroy every copy of the old key — otherwise nothing was gained.

Skipping rotation does not make data safer than rotating badly — but rotating
*only in the docs while never doing it* is how key compromise becomes total:
one leaked 64-char string decrypts the entire history.

### 3. Admin password hash

```bash
php -r "echo password_hash('your_password', PASSWORD_BCRYPT, ['cost' => 12]) . PHP_EOL;"
```

Paste the `$2y$12$...` string into `config.php` as `ADMIN_PASSWORD_HASH`.

### 4. config.php

```php
<?php
define('DB_HOST',    'localhost');
define('DB_PORT',    '3306');
define('DB_NAME',    'deaddrops');
define('DB_USER',    'dbuser');
define('DB_PASS',    'dbpassword');
define('DB_CHARSET', 'utf8mb4');

define('AES_KEY_HEX', 'aabbcc...(64 hex chars)');

define('ADMIN_USERNAME',      'admin');
define('ADMIN_PASSWORD_HASH', '$2y$12$...');

define('ERROR_LOG_PATH', __DIR__ . '/logs/error.log');
define('SESSION_NAME',     'ddmgmt');
define('SESSION_LIFETIME', 3600);
define('RATE_LIMIT_MAX',    10);
define('RATE_LIMIT_WINDOW', 900);

ini_set('display_errors', '0');
ini_set('log_errors',     '1');
ini_set('error_log',       ERROR_LOG_PATH);
```

### 5. Apache vhost

```apache
<VirtualHost *:443>
    DocumentRoot /var/www/deaddrops
    <Directory /var/www/deaddrops>
        Options -Indexes
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

Enable `mod_rewrite` and `mod_headers`. Set `AllowOverride All`.

### 6. Permissions

```bash
chmod 750 logs/ uploads/
chown www-data:www-data logs/ uploads/
```

### 7. Cron (optional but recommended)

```cron
0 * * * * curl -s https://yourdomain.com/cron/cleanup.php > /dev/null
```

### 8. Two-factor authentication (mandatory for couriers, self-service)

No server setup needed — log in, open **2FA** in the sidebar, scan the QR code with any RFC 6238 TOTP authenticator app (need one? see [TOTP-APPS.md](TOTP-APPS.md) for open-source picks per platform), and confirm with a code. Each account (owner or courier) enables/disables its own 2FA — 2FA is mandatory for couriers and strongly recommended (though optional) for the owner; the enrollment page explains why for each role, and a red banner nags every other admin page until it's on. The owner can force-reset a locked-out account's 2FA from **Users**.

---

## Requirements

- PHP 8.0+ with `pdo_mysql`, `openssl`, `gd` extensions
- MySQL 5.7+ or MariaDB 10.3+
- Apache 2.4+ with `mod_rewrite`, `mod_headers`

---

## Contributing

Bug fixes, security hardening, and documentation improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for coding conventions, how to submit changes, and — importantly — how to report a security vulnerability privately rather than through a public issue.

---

## License

MIT — see [LICENSE](LICENSE). The vendored third-party assets (Leaflet, QRCode.js, IBM Plex Mono) keep their own licenses; see [Third-Party Code & External Services](#third-party-code--external-services) for those.

This is separate from, and doesn't limit, the [Disclaimer](#disclaimer) above — the MIT license governs your rights to use, modify, and distribute the code, while the disclaimer addresses liability for how the software is used.
