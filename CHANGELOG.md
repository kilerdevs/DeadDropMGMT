# Changelog

All notable changes to DeadDropMGMT are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semver.
## [Unreleased]

### Changed
- Admin pages boot through a single service kernel
  (`includes/kernel.php`): the per-page 4–8 line require blocks (32 pages,
  169 lines) collapse to one require, and the service list lives in one
  manifest instead of being pasted across every entry script. Services stay
  plain functions with their own require guards, so tests, cron, and CLI
  entry points load them directly as before — zero behaviour change
- Automated formatting gate: `.php-cs-fixer.php` (conservative ruleset —
  whitespace, quotes, short arrays, strict-types; brace placement and line
  splitting deliberately out so the gate prevents drift without restyling
  history) enforced by a new CI `style` job running the version- and
  hash-pinned fixer phar in `--dry-run`
## [1.3.0] - 2026-09-16

### Security
- TOTP fails closed on weak secrets: an empty, undecodable, or truncated
  secret used to HMAC under the empty key — a publicly computable code, so
  a row with a damaged secret was a 2FA bypass for anyone computing the
  empty-key TOTP offline. Secrets decoding under 10 bytes now throw in
  `totp_code()` and deny in `totp_verify()`; absurd window/period/digits
  reject instead of hanging or dividing by zero
- Enrollment secrets with a NULL expiry no longer validate: every creation
  path stamps NOW() + 24h, so a missing expiry is a damaged row, not a
  perpetual claim credential
- Multi-hop `X-Forwarded-For` behind a trusted peer resolves to the
  peer-appended LAST hop: earlier entries are client-controlled under an
  appending proxy, and the old first-entry rule let a spoofed IP bypass
  per-IP rate limiting and poison audit IPs
- Proxy anonymity judging requires EVERY reachable judge clean: the first
  clean answer used to accept the proxy while a second judge could see the
  server IP leaking, storing a transparent proxy as `ok`
- Sealed reveal blobs are re-checked against the orders table on consume:
  an owner panic between unlock and the redirect GET no longer renders a
  deleted order for the 180 s window
- `admin/delete.php` routes through `order_delete_atomic()`: the legacy
  copy unlinked DB filenames with no path check (traversal to arbitrary
  file destroy), skipped `order_events`, and deleted files before the row
- `extend.php` only arms expiry on delivered orders, and the cleanup sweep
  only reaps delivered rows: a direct POST could previously schedule a
  never-delivered order for silent auto-deletion
- Panic wipe also destroys the rotated `app.log.1` generation, which
  carried the same IPs and tokens the panic exists to destroy
- `overwrite_and_unlink()` never follows symlinks: a planted link used to
  make the wipe zero its target outside uploads/logs
- DB client certificate/key without a CA now throws instead of silently
  falling back to a plaintext connection
- Logout is POST + CSRF only: a state-changing GET let any hostile page
  log the admin out with a single image tag
- Decryptors reject length-correct but non-hex IVs (`ctype_xdigit`):
  `hex2bin()` answers false there and `openssl_decrypt()` would TypeError
  instead of failing closed; invalid-UTF-8 payloads throw before reaching
  the ciphers; upload size is read from disk, not the client-supplied field
- Pseudo-cron dice fails toward cleanup on CSPRNG failure instead of
  500ing every page (injectable randomness keeps the arm test-covered)

### Fixed
- One-time passwords/flashes with `&` no longer display corrupted:
  `t()`/`tn()` output is HTML-safe by contract and sinks echo it raw;
  pre-escaping params or re-escaping output double-escaped them (a
  generated password containing `&` copied wrong and locked the recipient
  out). Contract documented on `t()`; all flash/error sinks converted
- `json_out()` always mints a fresh CSRF token instead of keeping a
  caller-supplied (just rotated, now invalid) one
- `admin_login()`/`admin_finish_login()` start the session themselves
  instead of depending on callers (an unstarted session silently lost the
  login and skipped fixation-protection rotation)
- Log rotation now serializes on a sidecar lock (concurrent rotators could
  delete each other's `.1` generation), verification reads under `LOCK_SH`,
  and the tail scan widens past single entries larger than 8 KiB (which
  used to anchor the next write to the wrong hash and alarm the chain)
- Transactional functions catch `Throwable`, not just `Exception`: an
  `Error` mid-transaction no longer escapes with the shared PDO handle
  holding an open transaction
- Panic report counts every table under guard (a raw `PDOException` with
  SQL text no longer escapes pre-transaction); routine cleanup deletions
  log at info level, not error
- Pagination clamps before querying (analytics recomputes the offset after
  clamping; audit log clamps at all); `save_setting` validates
  `extend_hours_options` as strict digits within extend's 1-720 range;
  client-side settings limits synced to the server ranges they mirror
- `download_log.php` omits `Content-Length` when `filesize()` fails;
  panic report counts render cast to int; all three key tools roll back
  their dry-run transaction before exiting; `edit.php` surfaces per-photo
  upload errors like `create.php`; `user_action` password/2FA changes
  report failure when no row matched; deliver TTL clamps to 1-720 h
- First-run screens: the intro paragraph keeps its spacing (the global
  reset had glued it to the first form label), and the one-time recovery
  enrollment code renders in an amber informational box instead of
  error-red — red means something failed, this is something to keep.
  The 64-char code also wraps instead of overflowing the column on
  narrow screens
- The enrollment code survives failed password attempts: it was consumed
  from the session on first render, so a too-short or mismatched password
  hid the only copy the creator would ever see. It now persists until the
  password is set (or the setup window lapses), and is consumed on claim
- Stale CSRF token on re-rendered setup/2FA forms: `verify_csrf()`
  rotates the session token on success, but `setup_password.php` and
  `verify_2fa.php` embedded the pre-rotation value captured at the top of
  the script — so the submit AFTER any failed attempt died with "Invalid
  CSRF token". Both re-capture the fresh token after a successful verify
- Form, settings, 2FA and panic panels center on the screen, not on the
  parent div (which sits right of center once the fixed sidebar takes its
  share): desktop-only relative offset of half the sidebar width.
  Relative, not transform, so `position:fixed` descendants stay
  viewport-anchored; mobile (drawer sidebar, full-width content) untouched

### Changed
- PHP 8.5 readiness: CI test matrix adds 8.5 (the shipped Docker images
  already run it); `curl_close()`/`imagedestroy()` calls removed (GC frees
  the handles), `$http_response_header` reads go through
  `http_get_last_response_headers()` where it exists, and
  `PDO::MYSQL_ATTR_*` resolves via `Pdo\Mysql::*` with legacy fallback
- Coverage `cleanup.php` pin 89 → 85: the proxy-revalidation hook added
  three load-time `require` lines that are structurally uncoverable (the
  bootstrap loads every include before recording starts) — the file is at
  100% of coverable lines
- FPM healthcheck runs `healthz.php` through the CLI SAPI (a broken
  docroot fails it; `kill -0 1` could never fail); `vendor/` and
  `composer.lock` no longer ship in images; `.dockerignore` re-includes
  `tests/schema_loader.php` with the portable `tests/*` pattern
- Semgrep custom rule gains `print` sinks and `$_SERVER`/`$_FILES`
  sources (validated live: fires on raw echoes, silent on escaped code);
  PHPStan keeps level 5 deliberately (level 8's bulk is dead
  `PDOStatement|false` arms under `ERRMODE_EXCEPTION`) and now also
  covers `docker/`
- `i18n_load()` whitelists its language argument; proxy discovery
  early-returns without cURL; `proxy_public_ip()` documents its direct
  clearnet trade-off; `schema_loader.php` replaces the database name only
  in `CREATE DATABASE`/`USE` position; stale version comments and ADR-010
  (superseded by the portable setup.sql + MySQL 8 CI job) corrected

## [1.2.0] - 2026-09-16

### Security
- Rate limiter fails closed on an unparseable `window_start`: `strtotime()`
  returning false used to read as "window started in 1970", silently
  resetting the budget so a damaged row could never block. Both the read
  path and the atomic spend path now deny (loudly) instead
- `tn()` HTML-escapes its parameters, matching `t()`: plural-string output
  renders into HTML, so request-derived values can no longer carry markup
  through it
- Photo pixel ceiling drops from 50 MP to 16 MP (4096x4096): a decoded
  32-bit buffer at the old cap was already ~200 MB, with GD holding several
  copies during resample — an OOM away from the 256 MB PHP limit
- Stale proxy pool entries are re-probed on cleanup passes (hourly
  pseudo-cron and real cron, 3 oldest-unchecked per pass): manually added
  proxies were only format-checked, and entries nobody exercised kept a
  stale 'ok'/'new' forever
- `X-Forwarded-Proto` is now covered by the same trusted-peer gate as the IP
  headers: `request_is_https()` moved to `includes/net.php` behind the shared
  `_proxy_peer_trusted()` check, so a forged proto from a direct connection
  can no longer plant a `secure` session cookie over plain HTTP
- Order event rows die with their order (same transaction, matched by id or
  token): lookup/unlock probes no longer accumulate IPs and user agents after
  the order is gone. A flow's own post-delete event (e.g. `received`) still
  lands afterwards as a single terminal row
- Panic wipe shreds the on-disk logs with `overwrite_and_unlink()` instead
  of truncating them, matching the photo-file treatment
- The log chain's `ip` field records the TCP peer directly instead of
  resolving through `get_client_ip()`: the logger no longer calls back into
  the function that logs through it (the old static once-guard was the only
  thing standing between that cycle and a stack overflow)

### Fixed
- `count(glob(...))` TypeError on PHP 8+ when the uploads directory is
  unreadable during order deletion — glob failure now degrades to "not empty"
- Misleading bootstrap error: losing the named-lock race while the users
  table is still empty now says "busy, retry" instead of "already initialized"
- Expiry sweep is bounded (200 rows per pass, repeat while full) instead of
  loading every expired order into one process

### Changed
- CI supply chain refreshed (checkout v7, setup-php 2.37.2,
  upload-artifact v7, ZAP baseline pin); Docker images run PHP 8.5,
  validated by the in-container lifecycle journey
- Trivy replaced by Grype (Anchore scan-action) + Syft SBOMs with identical
  gate semantics: HIGH/CRITICAL with a fix available fail the build
- Filesystem listings go through a shared `glob_list()` helper (bare
  `glob()` answers false on unreadable directories, and `count(false)` is a
  TypeError on PHP 8+); read-only CSRF checks use the named
  `verify_csrf_readonly()` wrapper instead of a bare `rotate: false` flag

## [1.1.0] - 2026-09-16

### Added
- Coverage climbs to ~88% overall across `includes/`: `net.php` hits 100%
  (CIDR/IP logic fully pinned), `cleanup.php` 89% (dice and sweep pass
  split into directly testable halves), `crypto.php` 93% (compressor reduce
  loops, undecodable-image and early-reject paths), `logger.php` 93%,
  `proxy.php` 63% (stub server doubles as a fake HTTP proxy for winner and
  judge paths). CI floors rise accordingly: 85% overall, per-file pins for
  net/logger/cleanup/proxy; the temporary `crypto.php` override is gone

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
  install real cron, which bypasses all gating. A lost die roll no longer
  consumes the process one-shot, and the dice (`_cleanup_roll`) plus the
  sweep pass (`_run_cleanup_pass`) are split out for direct testing

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
