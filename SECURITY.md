# Security Policy

## Supported versions

Only the latest commit on `master` is supported. This project moves fast and does
not maintain long-term release branches — if you are running an older checkout,
update before reporting an issue.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Preferred channel — GitHub Private Vulnerability Reporting:

> https://github.com/kilerdevs/DeadDropMGMT/security/advisories/new

This keeps details confidential until a fix ships, and lets us coordinate
disclosure through the standard GitHub advisory flow.

If you cannot use that channel, open a regular issue titled only
`[security] please contact you privately` with no technical detail and wait for
the maintainer to reach out.

### What to include

- Affected file(s) / endpoint(s) and the code path involved
- Step-by-step reproduction or a proof of concept
- Impact assessment — what an attacker gains, under what preconditions
- Your environment (PHP version, web server, whether TLS is terminated in front)

### What to expect

- **48 h** — acknowledgement of your report
- **7 days** — initial assessment: confirmed / not a vulnerability / needs more info
- **30 days** — fix released or a documented mitigation, for confirmed issues

We will credit you in the release notes and the advisory unless you prefer to
remain anonymous. Please give us a reasonable window (90 days is customary) to
publish a fix before any public disclosure.

## Scope

### In scope

- `index.php`, `receive.php` — public order lookup / delivery confirmation flows
- `admin/*` — authentication, session handling, CSRF, 2FA, authorization gaps
  between owner and courier roles
- `includes/crypto.php` — encryption, hashing, ≥64-bit passphrase generation
- `includes/order_state.php` — atomic order state machine (deliver/receive/delete/expiry)
- `includes/auth.php` — rate limiting, headers, session configuration
- SQL injection, XSS, privilege escalation, insecure deserialization,
  path traversal, race conditions with security impact
- The tamper-evident log chain (`includes/logger.php`) — e.g. ways to forge or
  rewrite history without detection

### Out of scope

- Vulnerabilities requiring a compromised host (root/shell on the server) — at
  that point the AES key, database and log-integrity HMAC key are all local and
  the game is over by definition
- Lack of TLS/WAF — explicitly documented as externally configured
- Clicking through the OSM embed iframe leaking the recipient IP to
  OpenStreetMap — disclosed in the README
- Brute-force of pickup passphrases without rate-limit circumvention — the
  IP-based limiter (fail-closed) plus per-session bucket are the controls;
  demonstrate a *bypass* instead
- Guessing a generated pickup passphrase offline is bounded by ~64.6 bits of
  entropy and bcrypt cost 12; online guessing by the dual budget above
- Self-XSS, missing security headers on static error pages, or anything
  requiring social engineering rather than a flaw in the application
- Automated scanner output without a working demonstration

## Safe harbor

Good-faith research within this policy is welcome. We will not pursue legal
action against anyone who avoids privacy violations, data destruction, service
degradation, and who reports findings through the channels above.
