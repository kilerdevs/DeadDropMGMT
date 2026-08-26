# Changelog

All notable changes to DeadDropMGMT are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semver.

## [Unreleased]

### Security
- CSRF tokens are single-use now: every successful verification mints a
  fresh value, so a token stolen by XSS or leakage cannot be replayed for
  further state-changing requests. Fetch-based endpoints return the next
  token in their JSON (`csrf` field); read-only probes (per-keystroke setup
  check, log verification) verify without consuming
- Fixed a dead end in the config-fallback owner login: `user_id = 0` failed
  the `!empty()` session check, kicking the bootstrap owner straight back to
  the login wall after one request
- The enrollment branch of `admin_login()` burns a dummy bcrypt verification
  on failure, so "account awaits first-login setup" is no longer reachable
  by timing the missing password check
- `admin/check_setup.php` is rate-limited under its own generous budget
  (30 / window), so the enrollment-state probe can no longer be polled at
  wire speed; the limiter runs before the CSRF check in `receive.php` too,
  making forged-request floods self-throttling
- Logout sends `Clear-Site-Data` ("cache", "cookies", "storage"), closing
  the shared-computer gap where bfcache could still render admin pages
- Photo upload re-sniffs the MIME of the GD re-encoded output and refuses
  (or renames) anything that is not a member of the allowed image map —
  malformed input can no longer smuggle surprising bytes onto disk
- Unparseable `DDMGMT_TRUSTED_PROXIES` entries are logged once per process
  instead of silently falling back to `REMOTE_ADDR`

### Changed
- `get_client_ip()` / `_ip_in_cidr()` moved from `config.php` to
  `includes/net.php` — hand-edited configs can no longer weaken proxy-header
  validation; config files stay constants-only
- Pseudo-cron cleanup gates its settings-table read behind a 1-in-100
  probability (tests pass an explicit chance); busy deployments should
  install real cron, which bypasses all gating

### Security
- Proxy-header trust is now bound to the connection peer: with
  `DDMGMT_TRUST_PROXY=1`, `CF-Connecting-IP` / `X-Forwarded-For` /
  `X-Real-IP` are honored only when `REMOTE_ADDR` matches
  `DDMGMT_TRUSTED_PROXIES` (default: loopback + RFC1918; explicit IP/CIDR
  list otherwise). Previously a single flipped env flag on an app reachable
  outside its proxy let any client rotate its rate-limit identity and poison
  the audit log at will
- Receipt confirmation is now bound to a verified pickup-password unlock:
  a correct password arms a single-use, AES-sealed receipt capability bound
  to that one token (600 s TTL); `receive.php` step 2 consumes it before any
  deletion. Possession of the order token alone — even with a valid CSRF
  token — can no longer destroy a delivered order. Cross-token use of a
  capability is rejected and still consumes it
- Fixed the tamper-evident log chain: `_log_last_hash()` read the file
  position right after `fopen('c+')` (always 0), so every entry anchored to
  the genesis hash and each write OVERWROTE the log from byte zero — history
  and tamper evidence were both lost. The chain now genuinely links and
  detects modification, truncation and forgery
- Fixed `osm_last_via_stage(null)` being a silent no-op (`!== null` guard),
  so staged proxy-badge info now actually clears on flush

### Changed
- `index.php` spends its rate-limit budget through one atomic check-and-
  consume (`rl_hit`) up front; non-failure outcomes refund the spend, so the
  budget keeps counting failed guesses while every decision stays race-free

### Added
- Five suites: `FailClosedTest` (fail-closed branches of guards, limiter,
  wipe, state machine, crypto, DB options), `I18nTest`, `LoggerTest`
  (chain integrity incl. forgery/truncation/legacy keys, audit, event log),
  `SettingsTest`, `ProxyClientTest` (outbound client vs local stub server);
  coverage floors raised to 85% per critical file and **80% overall**
- Coverage floors accept per-file overrides via
  `coverage_runner --min-file=name:pct`

### Changed
- `includes/db.php`: TLS options extracted into the pure, unit-tested
  `db_options()` factory; connection into `db_connect()` — removes the last
  PHPStan environment-dependent suppression

## [1.0.0] — 2026-08-24

First tagged release: the security-hardened core, fully gated by CI.

### Security
- Zero-runtime-dependency PHP app: AES-256-GCM at rest, bcrypt cost 12,
  TOTP 2FA (RFC 6238), CSRF tokens, strict CSP, tamper-evident JSONL log chain
- HKDF key separation (ADR-016): the master key never encrypts directly —
  locations, TOTP secrets, sealed reveals, capability MACs and the log chain
  each use their own subkey; `tools/separate_keys.php` migrates older installs
- Atomic order state machine (preparing → delivered → deleted) with row locks
  and a DB CHECK constraint; replays and races are harmless no-ops
- Pickup passwords: ≥64-bit generated passphrases, hash-only at rest, shown
  once; `tools/purge_pickup_password_recovery.php` clears legacy copies
- Rate limiting: dual IP + session budgets, fail-closed on limiter failure,
  atomic spend-and-decide (`rl_hit`), proxy headers only with explicit
  `DDMGMT_TRUST_PROXY=1`
- Enrollment secrets for passwordless first login (single-use, 256-bit,
  24 h expiry, burned on claim)
- Reveal flow: PRG with AES-sealed session payloads, 180 s capability TTL,
  constant-cost responses for unknown tokens
- Upload hardening: mandatory GD decode/re-encode, sniffed MIME only,
  decompression-bomb guard, server-generated filenames
- Panic wipe: destroys all data and evidence in one transaction, honest
  `files_failed` reporting, safe retries (ADR-015)
- Legacy CBC rows refused at runtime; `tools/migrate_cbc_to_gcm.php`

### CI / supply chain
- Test suite: 13 suites, ~560 assertions — crypto vectors, auth, CSRF, TOTP,
  rate limiting (incl. concurrency), state transitions, panic wipe, upload
  hardening, proxy anonymity gate, public end-to-end flow
- PHP 8.2–8.4 matrix + MySQL 8 job (MariaDB 11 primary), PHPStan level 5,
  coverage floors (includes/ ≥ 80%, security-critical ≥ 90%)
- Semgrep SAST with a custom request-echo taint rule; secret scanning +
  push protection enabled; CodeQL dropped upstream for PHP
- Docker: Apache / nginx+FPM / Caddy stacks, Trivy CVE gates on both images,
  CycloneDX SBOMs, HEALTHCHECKs, full-lifecycle journey inside the container
- Actions pinned by SHA, workflows read-only, Dependabot
  (actions + composer + docker)

### Added
- First-run owner creation through the UI (GET_LOCK guarded)
- Order analytics, OSM tile/geocode proxy pool with live anonymity judging
- `/healthz.php` liveness endpoint
- `tools/rotate_aes_key.php` — online key rotation with read-back
  verification

[1.0.0]: https://github.com/kilerdevs/DeadDropMGMT/releases/tag/v1.0.0
