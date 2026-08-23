# Architecture Decision Records

The threat model documents *what* protects what. These records capture *why*
each security-relevant choice was made the way it was — including the
alternatives that were rejected and the price we knowingly pay.

Format: lightweight ADR (Context / Decision / Consequences). Superseded
records stay here, marked as such.

---

## ADR-001 · Zero-dependency PHP application

**Context.** The app handles contraband-adjacent logistics for a tiny user
base; supply-chain surface must be near zero, hosting must work on cheap
shared PHP hosting.

**Decision.** No Composer, no framework, no runtime libraries. Everything is
hand-written PHP 8.0+ files. Dev-only tooling (code coverage) lives behind
`composer.json` but never ships in the image.

**Consequences.** Every dependency we *don't* have can't be compromised via
a transitive update (+). We re-implement small pieces (base32, TOTP) that a
library would provide, so those carry RFC test vectors in the suite (+/−).
Shared-hosting deployment stays `git clone` simple (+).

## ADR-002 · AES-256-GCM instead of CBC or XChaCha20-Poly1305

**Context.** Location records need authenticated encryption at rest.
Candidates: AES-256-CBC (what v1 shipped), AES-256-GCM, XChaCha20-Poly1305
via libsodium.

**Decision.** AES-256-GCM via OpenSSL: random 12-byte nonce per record,
16-byte tag appended to ciphertext, base64 storage.

**Why not CBC (v1).** Malleable — no integrity guarantee; a tampered row
decrypts to garbage or worse without any error. Padding-oracle class risks
move from theoretical to real the moment an attacker gets write access to the
ciphertext column.

**Why not XChaCha20-Poly1305.** Technically superior nonce discipline
(192-bit random nonces make collision odds negligible vs GCM's 96-bit, where
~2³² messages under one key already warrant concern) and constant-time by
design on any CPU. Rejected because libsodium's PECL build is absent from
most shared hosts this project explicitly targets, and polyfilling crypto
contradicts ADR-001 more than using OpenSSL's audited GCM does. GCM nonce
collisions are managed by construction: each record generates a fresh random
nonce and volumes are human-scale (~10² orders), putting collision probability
around 10⁻¹⁹ per record.

**Consequences.** Zero host requirements beyond ext-openssl (+). Nonce
randomness means uniqueness is probabilistic, not guaranteed (−); acceptable
at this volume, would need counter-based nonces at millions of records under
one key.

## ADR-003 · Legacy CBC rows decrypt transparently

**Context.** Pre-GCM rows exist in deployed databases; forcing migration
would break running installs on upgrade.

**Decision.** IV-length detection (24 hex = GCM nonce, 32 hex = legacy CBC
IV) with transparent CBC fallback; every record edited through the admin
panel re-encrypts to GCM automatically. An explicit one-shot rotation tool
(`tools/rotate_aes_key.php`) converts everything eagerly.

**Consequences.** Upgrades are drop-in (+). Two code paths in the crypto core
(−), mitigated by tests pinning both formats. CBC rows linger until touched
or migrated (−) — documented in Residual Risk.

## ADR-004 · bcrypt with cost 12

**Context.** Pickup passwords gate location reveals; admin passwords guard
everything. Hashing happens on every login/unlock attempt, inside request
handling.

**Decision.** bcrypt cost 12 via `password_hash()` — ~250 ms on 2020s
shared-hosting-class CPUs.

**Why not higher (13–15).** Each +1 doubles cost; cost 14 starts exceeding
1 s on weak shared CPUs, degrading UX for legitimate recipients and making
the login endpoint a trivial CPU-exhaustion DoS vector.

**Why not lower.** Pickup passphrases are machine-generated ~40-bit strings;
cost 12 stretches offline cracking of a stolen hash table from hours into
geological time even before rate limiting enters the picture.

**Why not argon2id.** Better memory-hardness, but availability on shared
hosts is spotty and bcrypt's 72-byte ceiling is irrelevant here (generated
passphrases are ≤40 chars, admin passwords policy-checked). Revisit if
hosting constraints change.

## ADR-005 · TOTP defaults: SHA-1 / 6 digits / 30 s

**Context.** 2FA secrets are scanned as QR codes by arbitrary authenticator
apps.

**Decision.** Exactly the RFC 6238 baseline every app assumes when enrolling
manually.

**Consequences.** Works with every TOTP app in existence (+). SHA-1-HMAC's
known weaknesses don't apply to HMAC preimage resistance in any practical
TOTP attack (−→+). Pinned against official RFC vectors in TotpTest.

## ADR-006 · Dual rate-limit budgets: IP + session cookie

**Context.** IP-based limiting alone locks strangers behind shared NAT out
of each other's way, while attackers rotate cheap IPv6 addresses.

**Decision.** Enforce whichever trips first: the DB-backed per-IP counter
*or* a server-side per-session failure bucket (the session cookie is the
bucket; clearing it yields a fresh zero-history session which the IP budget
still sees).

**Consequences.** NAT users keep independent buckets (+). Attacker cost per
attempt rises from "new IP" to "new IP + new cookie jar" (+). Server-side
storage means no client-trusted counters (+). A determined distributed
attacker is still not stopped — passphrase entropy and auto-expiry carry
that residual risk (documented).

## ADR-007 · Tamper-evident log: HMAC-chained JSONL

**Context.** Admin actions need an audit trail that survives attempts to
rewrite history (an intruder covering tracks). External append-only services
(WORM buckets, syslog hosts) violate ADR-001's hosting constraints.

**Decision.** JSONL entries where each carries `HMAC(prev_hash || entry)`,
keyed with a domain-separated derivative of the AES key. One-click chain
verification in Settings reports the first broken line.

**Consequences.** Any edit/delete of historical lines breaks every subsequent
hash (+). Detection, not prevention — an attacker with filesystem write access
can truncate the whole file or forge a full chain *if they also hold the AES
key*, which implies host compromise anyway (accepted, see Residual Risk).
Key reuse with domain separation means rotating the AES key invalidates old
chains — documented in the rotation procedure: archive logs before rotating.

## ADR-008 · PRG pattern for the location reveal

**Context.** After a correct password unlock, the decrypted location must
not be reachable via back-button/replay, nor live in URLs.

**Decision.** Unlock POST stores the reveal payload in the server-side
session, redirects (303-style GET) to `/`, the next GET consumes and clears
it. Fresh sessions see nothing.

**Consequences.** Location never appears in history/referrer/logs (+).
Reveal survives exactly one page load — refresh loses it by design
(communicated in UI copy). Session file briefly holds plaintext location
(+ accepted: same trust domain as the decryption code itself).

## ADR-009 · All third-party map traffic proxied server-side

**Context.** Owner/courier IPs must not leak to OpenStreetMap; public CSP is
strictly self-hosted except the recipient-facing OSM embed iframe.

**Decision.** Admin tile/geocode requests flow through authenticated server
proxies with caching; optional fail-closed proxy pool hides even the
server's IP. The public reveal embeds OSM directly (recipient's browser →
OSM), disclosed openly.

**Consequences.** No admin IP ever reaches OSM (+). Proxy pool dead = map
features stop, never silent direct fallback (+). Recipient IP still leaks to
OSM on delivered-order views — stated plainly in the README rather than
pretended away (− documented).

## ADR-010 · MariaDB-flavoured idempotent setup.sql

**Context.** Schema must install identically on fresh databases and decade-old
upgraded ones, from a single file.

**Decision.** `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ADD COLUMN IF NOT
EXISTS` + guarded FK checks. This syntax is MariaDB-specific; MySQL 8 lacks
`ADD COLUMN IF NOT EXISTS`.

**Consequences.** CI and Docker use MariaDB 11 (+). Pure-MySQL installs are
unsupported, stated in Requirements (− accepted).

## ADR-011 · Hand-rolled test harness instead of PHPUnit

**Context.** Tests exist to protect a zero-dependency codebase; adding
PHPUnit makes Composer a requirement to *contribute*, not just to run.

**Decision.** Standalone `tests/*Test.php` scripts with a ~50-line assertion
harness, one process per suite via `run_all.php`, plus one end-to-end suite
driving a real HTTP server.

**Consequences.** `php tests/run_all.php` works anywhere PHP works (+).
No data providers, no mocking library, assertions are plain (− accepted).
Coverage reporting needed dev-only Composer glue (see coverage job) — kept
out of the runtime path.

## ADR-012 · Three interchangeable container stacks

**Context.** Deployment targets range from "one VPS, keep it simple" to
"existing nginx/Caddy edge infrastructure".

**Decision.** Apache-all-in-one (default), nginx+FPM, Caddy+FPM — all from
two images sharing one entrypoint/config strategy; front configs mirror
every `.htaccess` protection.

**Consequences.** Whatever the web server, protections are equivalent and
CI smoke-tests each stack end-to-end (+). Three compose files to keep in
sync (−), mitigated by the shared FPM image doing all app-level work.
