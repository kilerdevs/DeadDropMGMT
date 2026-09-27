<div align="center">

# Security Policy

[![Report a vulnerability](https://img.shields.io/badge/report-privately%20via%20GitHub-critical?style=flat&logo=github)](https://github.com/kilerdevs/DeadDropMGMT/security/advisories/new)
[![Acknowledgement](https://img.shields.io/badge/acknowledgement-48%20h-blue?style=flat)](#what-to-expect)
[![Fix target](https://img.shields.io/badge/fix%20target-30%20days-blue?style=flat)](#what-to-expect)
[![SAST](https://github.com/kilerdevs/DeadDropMGMT/actions/workflows/sast.yml/badge.svg)](https://github.com/kilerdevs/DeadDropMGMT/actions/workflows/sast.yml)

</div>

This is a security-focused application, so reports are taken seriously and handled in private. The design and its
limits are documented in the README's [threat model](README.md#threat-model) and in the
[architecture decision records](docs/ADR.md).

## Contents

- [Supported versions](#supported-versions)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [What to expect](#what-to-expect)
- [Scope](#scope)
- [Safe harbor](#safe-harbor)

---

## Supported versions

| Version | Supported |
|---|---|
| Latest tagged release and the current head of `master` | ✅ |
| Anything older | ❌ |

This project moves fast and does not maintain long-term release branches; fixes are developed on `dev` and land on
`master` with the next release. If you are running an older checkout, update before reporting an issue.

## Reporting a vulnerability

> [!IMPORTANT]
> **Please do not open a public GitHub issue for security problems.**

Preferred channel — GitHub Private Vulnerability Reporting:

> <https://github.com/kilerdevs/DeadDropMGMT/security/advisories/new>

This keeps details confidential until a fix ships, and lets us coordinate disclosure through the standard GitHub advisory
flow.

If you cannot use that channel, open a regular issue titled only `[security] please contact you privately` with no
technical detail and wait for the maintainer to reach out.

### What to include

- Affected file(s) / endpoint(s) and the code path involved
- Step-by-step reproduction or a proof of concept
- Impact assessment — what an attacker gains, under what preconditions
- Your environment (PHP version, web server, whether TLS is terminated in front, Docker stack if any)

## What to expect

| When | What happens |
|---|---|
| **48 hours** | Acknowledgement of your report |
| **7 days** | Initial assessment: confirmed / not a vulnerability / needs more info |
| **30 days** | Fix released or a documented mitigation, for confirmed issues |

We will credit you in the release notes and the advisory unless you prefer to remain anonymous. Please give us a
reasonable window (90 days is customary) to publish a fix before any public disclosure.

## Scope

### In scope

| Area | Examples |
|---|---|
| `index.php`, `receive.php` | Public order lookup, unlock, reveal and delivery-confirmation flows |
| `admin/*` | Authentication, session handling, CSRF, 2FA, authorization gaps between owner and courier roles, the `admin/dispatch.php` route envelope |
| `includes/crypto.php` | Encryption, key separation, hashing, the order-token index, ≥64-bit passphrase generation |
| `includes/order_state.php` | The atomic order state machine (deliver / receive / delete / expiry) |
| `includes/auth.php` | Rate limiting, security headers, session configuration |
| `includes/logger.php` | The tamper-evident log chain — ways to forge or rewrite history without detection |
| Self-hosted maps — `includes/maps.php`, `tiles/`, `admin/tile_proxy.php` | Access control on zone files, the pinned `pmtiles` CLI download and verification, the download worker, the tile/geocode proxies |
| Deployment files | `.htaccess`, `docker/nginx.conf`, `docker/Caddyfile`, `docker/entrypoint.sh` — e.g. a path that should be denied but is served, or key handling that leaks |
| Vulnerability classes | SQL injection, XSS, privilege escalation, insecure deserialization, path traversal, race conditions with security impact |

### Out of scope

- Vulnerabilities requiring a compromised host (root/shell on the server) — at that point the AES key, database and
  log-integrity HMAC key are all local and the game is over by definition
- Lack of TLS/WAF — explicitly documented as externally configured
- Clicking through the OSM embed iframe leaking the recipient IP to OpenStreetMap — disclosed in the README (the
  self-hosted map provider removes it)
- Published default passwords in the compose files and plain HTTP on the default port — the entrypoint warns; change them
  before exposing a stack
- Brute-force of pickup passphrases without rate-limit circumvention — the IP-based limiter (fail-closed) plus per-session
  bucket are the controls; demonstrate a *bypass* instead
- Guessing a generated pickup passphrase offline is bounded by ~64.6 bits of entropy and bcrypt cost 12; online guessing by
  the dual budget above
- Self-XSS, missing security headers on static error pages, or anything requiring social engineering rather than a flaw in
  the application
- Automated scanner output without a working demonstration

## Safe harbor

Good-faith research within this policy is welcome. We will not pursue legal action against anyone who avoids privacy
violations, data destruction, service degradation, and who reports findings through the channels above.
