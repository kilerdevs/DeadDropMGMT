# Changelog

All notable changes to DeadDropMGMT are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semver.

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
