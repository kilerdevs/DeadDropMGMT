# DeadDropMGMT

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
- [Security Model](#security-model)
- [Third-Party Code & External Services](#third-party-code--external-services)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Public (recipient) flow
- Token-based order lookup — no account needed
- Password-protected location reveal (AES-256-CBC, decrypted server-side, never sent to client unencrypted)
- Live expiry countdown with redirect timer
- Photo gallery for reference images
- One-click links to Google Maps / Apple Maps
- Delivery confirmation endpoint

### Admin dashboard
- Role-based access: **Owner** (full control) and **Courier** (own orders only)
- Create orders with an interactive Leaflet map picker
- Auto-generated memorable pickup passphrases (150-word list)
- Extend / close / delete orders with CSRF-protected actions
- Photo upload with automatic GD compression
- Configurable TTL — orders auto-expire and are securely wiped
- Two-factor authentication (TOTP) — self-service enroll/disable per account, QR + manual entry, works with Aegis and any RFC 6238 authenticator
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
| Encryption | OpenSSL — AES-256-CBC, random IV per record |
| Auth | bcrypt cost=12, TOTP 2FA, CSRF tokens, session hardening |
| Frontend | Vanilla JS (ES5+), CSS Grid/Flexbox |
| Maps | Leaflet + OpenStreetMap |
| Webserver | Apache — mod_rewrite, mod_headers, .htaccess path protection |

---

## Security Model

| Threat | Mitigation |
|---|---|
| SQL injection | PDO prepared statements throughout — zero string interpolation in SQL |
| Password storage | bcrypt cost=12 via `password_hash()` / `password_verify()` |
| Account takeover | TOTP 2FA (RFC 6238) — self-service per account, encrypted secret at rest |
| Location data at rest | AES-256-CBC, random IV per record, key lives only in `config.php` (never in DB) |
| Session fixation | `session_regenerate_id(true)` on login |
| CSRF | 64-byte random token in session, `hash_equals()` comparison on every POST |
| Brute-force | IP-based rate limiter, configurable and togglable — pickup guessing, admin login, 2FA codes |
| XSS | `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` on all user-derived output |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, strict CSP, HSTS |
| Error leakage | `display_errors=0`, all exceptions caught and logged, generic user-facing messages |
| Direct file access | `includes/`, `config.php`, `logs/`, `cron/` blocked via `.htaccess` |
| Cookie theft | `httponly`, `samesite=Strict`, `secure` (auto-enabled when HTTPS detected) |
| Unaccountable writes | Every admin create/edit/delete/setting-change logged with actor, IP, timestamp |
| Owner/courier IP exposure to third parties | Map tile and address-search requests from the admin panel are proxied server-side (`admin/tile_proxy.php`, `admin/geocode_proxy.php`) — neither an owner's nor a courier's real IP or search queries ever reach OpenStreetMap, only this server's does |

**Not included (configure externally):** TLS.

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

These are exactly the hosts allowlisted in the public CSP (`includes/auth.php`) — nothing else can load. **Worth knowing:** the embedded map iframe sends the *customer's* IP to OSM when they view a delivered order's location — that's a request their own browser makes, and is in some tension with the "no tracking" claim shown on the public pages (that claim is about *this app* not tracking recipients, not about the third party it embeds a map from). If your threat model requires zero third-party contact even for that, the only remaining option is standing up your own tile server and pointing the public page at a self-hosted map instead of the OSM embed.

---

## Project Structure

```
/
├── index.php               Public order lookup & location reveal
├── receive.php              Delivery confirmation endpoint
├── config.php               DB credentials, AES key, admin hash  ← never commit
├── setup.sql                 Full database schema — one file, fresh install or upgrade from any version
├── .htaccess                  Blocks config, includes/, logs/ from web
├── fonts/                      Self-hosted IBM Plex Mono (replaces Google Fonts)
│
├── admin/
│   ├── index.php             Login wall
│   ├── login.php              Credential check → 2FA if enabled
│   ├── verify_2fa.php          TOTP code prompt (login step 2)
│   ├── 2fa.php                 Self-service 2FA enroll / disable (QR + manual)
│   ├── orders.php             Order list with courier filtering
│   ├── new_order.php          Order creation form (Leaflet map picker)
│   ├── edit.php                Edit order — status, location, password, photos
│   ├── users.php               Courier management (owner only)
│   ├── audit_log.php            Write-action audit trail (owner only)
│   ├── analytics.php           Event log viewer + CSV download
│   ├── settings.php             Configurable site parameters
│   ├── panic.php                Emergency mode (owner only)
│   └── vendor/                  Leaflet + QRCode.js — vendored locally, no CDN
│
├── includes/                Blocked from web via .htaccess
│   ├── db.php                PDO singleton
│   ├── auth.php                Session, CSRF, rate limiting, security headers
│   ├── crypto.php               AES-256-CBC encrypt/decrypt, bcrypt, passphrase generator
│   ├── totp.php                  TOTP (RFC 6238) generate/verify, base32, otpauth:// URI
│   ├── audit.php                 Write-action audit logger
│   ├── settings.php              Settings cache (one DB query per page load)
│   ├── analytics.php              Event logger
│   └── cleanup.php                Expired order deletion (pseudo-cron + real cron)
│
└── cron/
    └── cleanup.php             Server-side cron endpoint (call hourly)
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

Paste the 64-char hex output into `config.php` as `AES_KEY_HEX`.
**Back this up.** Losing it means losing all encrypted location data.

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

### 8. Two-factor authentication (optional, self-service)

No server setup needed — log in, open **2FA** in the sidebar, scan the QR code with [Aegis](https://getaegis.app/) (or any RFC 6238 authenticator app), and confirm with a code. Each account (owner or courier) enables/disables its own 2FA; the owner can force-reset a locked-out account's 2FA from **Users**.

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
