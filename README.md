# DeadDropMGMT

A secure, bare-metal order management system for coordinating deliveries to dead-drop locations. Recipients look up orders by token, unlock an encrypted location with a password, and confirm receipt — all without ever exposing the underlying data.

Built with zero external PHP dependencies. Every security concern addressed at the application layer.

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
- Analytics log: every lookup, unlock attempt, and confirmation recorded with IP + user-agent
- CSV export of the event log
- Panic mode (owner only)

### Operations
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
| Auth | bcrypt cost=12, CSRF tokens, session hardening |
| Frontend | Vanilla JS (ES5+), CSS Grid/Flexbox |
| Maps | Leaflet + OpenStreetMap |
| Webserver | Apache — mod_rewrite, mod_headers, .htaccess path protection |

---

## Security Model

| Threat | Mitigation |
|---|---|
| SQL injection | PDO prepared statements throughout — zero string interpolation in SQL |
| Password storage | bcrypt cost=12 via `password_hash()` / `password_verify()` |
| Location data at rest | AES-256-CBC, random IV per record, key lives only in `config.php` (never in DB) |
| Session fixation | `session_regenerate_id(true)` on login |
| CSRF | 64-byte random token in session, `hash_equals()` comparison on every POST |
| Brute-force | Session-based rate limiter — 10 failed attempts per 15-min window |
| XSS | `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` on all user-derived output |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, strict CSP, HSTS |
| Error leakage | `display_errors=0`, all exceptions caught and logged, generic user-facing messages |
| Direct file access | `includes/`, `config.php`, `logs/`, `cron/` blocked via `.htaccess` |
| Cookie theft | `httponly`, `samesite=Strict`, `secure` (auto-enabled when HTTPS detected) |

**Not included (configure externally):** TLS, IP-based rate limiting, 2FA, audit log for writes.

---

## Project Structure

```
/
├── index.php            Public order lookup & location reveal
├── receive.php          Delivery confirmation endpoint
├── config.php           DB credentials, AES key, admin hash  ← never commit
├── setup.sql            Full database schema
├── .htaccess            Blocks config, includes/, logs/ from web
│
├── admin/
│   ├── index.php        Login wall + dashboard redirect
│   ├── orders.php       Order list with courier filtering
│   ├── new_order.php    Order creation form (Leaflet map picker)
│   ├── edit.php         Edit order — status, location, password, photos
│   ├── users.php        Courier management (owner only)
│   ├── analytics.php    Event log viewer + CSV download
│   ├── settings.php     Configurable site parameters
│   └── panic.php        Emergency mode (owner only)
│
├── includes/            Blocked from web via .htaccess
│   ├── db.php           PDO singleton
│   ├── auth.php         Session, CSRF, rate limiting, security headers
│   ├── crypto.php       AES-256-CBC encrypt/decrypt, bcrypt, passphrase generator
│   ├── settings.php     Settings cache (one DB query per page load)
│   ├── analytics.php    Event logger
│   └── cleanup.php      Expired order deletion (pseudo-cron + real cron)
│
└── cron/
    └── cleanup.php      Server-side cron endpoint (call hourly)
```

---

## Setup

### 1. Database

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

---

## Requirements

- PHP 8.0+ with `pdo_mysql`, `openssl`, `gd` extensions
- MySQL 5.7+ or MariaDB 10.3+
- Apache 2.4+ with `mod_rewrite`, `mod_headers`
