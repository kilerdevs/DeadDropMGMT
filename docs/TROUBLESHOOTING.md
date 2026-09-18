# Troubleshooting

Symptom → cause → fix. For setup, see the [README](../README.md); for design decisions, see [`ADR.md`](ADR.md).

> [!TIP]
> Most problems leave a trace. Check `logs/error.log` (PHP errors and app errors) and `logs/app.log` (structured events)
> first — on Docker: `docker compose logs app` and the `app-logs` volume.

## Quick index

| Symptom | Section |
|---|---|
| Blank page or a 500 with no message | [Blank page](#blank-page--500-with-no-message) |
| Everyone locked out, or one account locked out | [Rate limiting](#rate-limited--logins-rejected) |
| "Invalid CSRF" | [Invalid CSRF](#invalid-csrf) |
| Suddenly logged out | [Session ended](#session-ended-or-expired) |
| Login fails while the database is down | [Database down](#login-fails-while-the-database-is-down) |
| AES key missing, invalid or lost | [AES key](#aes-key-missing-invalid-or-lost) |
| "Verify integrity" complaints | [Broken line](#verify-integrity-reports-a-broken-line-n) · [Continuity](#verify-integrity-continuity-says-truncated--rotated--none) · [Empty or key unavailable](#verify-integrity-says-nothing-to-verify-or-log-key-unavailable) |
| Expired orders are still listed | [Expiry](#expired-orders-never-disappear) |
| Photo upload rejected | [Photos](#photo-upload-rejected) |
| Courier forced to the 2FA page | [2FA](#courier-bounced-to-2faphprequired1) |
| Panic page restarts | [Panic](#panic-page-resets-to-step-1-with-an-error) |
| First-owner form asks for a token | [Setup token](#first-owner-form-asks-for-a-setup-token) |
| `config.php` fatals on first login | [config.php](#fresh-configphp-fatals-on-first-login) |
| Sensitive paths reachable on nginx/Caddy | [Web server denies](#manual-nginxcaddy-install-serves-sensitive-paths) |
| Self-hosted map: zones missing, stuck or failing | [Zones missing](#map-zones-vanished-after-a-rebuild) · [Zone download stuck](#a-zone-download-is-stuck-or-failed) · [CLI hash mismatch](#pmtiles-cli-hash-mismatch) |
| Developing locally | [Local quirks](#local-development-quirks) |
| Forwarding logs | [Shipping logs](#shipping-logs-to-a-central-system) |

---

## Blank page / 500 with no message

`display_errors` is intentionally `0` — fatals never reach the browser. Read `logs/error.log` (path: `ERROR_LOG_PATH` in
`config.php`). If the log itself is empty, check the web-server error log and directory permissions — the PHP user must
own the writable directories:

```bash
chown -R www-data:www-data logs uploads cache data tiles
chmod 750 logs uploads
```

## Rate-limited / logins rejected

Several independent budgets exist: the pickup, admin-login and 2FA-code surfaces each count per IP, login and 2FA also
count per *account*, and pickup adds a per-session failure bucket. The attempt count (3–10, default 5) and window
(5–60 min, default 15) live in **Settings → Security**; one switch turns the whole limiter on or off.

Work through the usual causes:

1. **Everyone shares one IP.** Behind a reverse proxy or CDN the app sees the proxy's address for every visitor, so one
   person's failures lock out everybody. Set `DDMGMT_TRUST_PROXY=1` and, if the proxy connects from public addresses,
   `DDMGMT_TRUSTED_PROXIES` (see the README's proxy-trust section). Only enable it when the proxy overwrites the forwarded
   headers.
2. **One account is locked.** Repeated wrong passwords or 2FA codes exhaust that account's own budget even from a fresh IP.
   Wait out the window, or clear the counters:

   ```sql
   DELETE FROM rate_limits;
   ```

3. **The budget itself is unusable.** Values are clamped (at least 1 attempt, at least a 1-minute window), but a mistaken
   `rate_limit_max` of `1` still locks people out after a single failure. Restore sane values:

   ```sql
   UPDATE settings SET value = '5'  WHERE key_name = 'rate_limit_max';
   UPDATE settings SET value = '15' WHERE key_name = 'rate_limit_window_min';
   ```

Emergency only — switch the limiter off, fix the cause, then switch it back on (the app fails closed on a broken limiter
database, it does not fail open):

```sql
UPDATE settings SET value = '0' WHERE key_name = 'rate_limit_enabled';   -- and '1' to re-enable
```

A failed guess counts for the whole window; a successful pickup or login gives back only its own attempt, not the
accumulated history.

## Invalid CSRF

CSRF tokens are single-use by design (ADR-018): every verified submission mints a fresh one. Admin pages fetch the live
token from `/admin/csrf_token.php` just before submitting, so two tabs and long-open pages normally just work. If you still
see it:

- **On the public unlock form:** the token rendered in another tab or before a back-button navigation was already spent.
  Reload the form and submit again.
- **In the admin panel:** JavaScript is blocked (the refresh hook cannot run), the session expired, or a proxy strips the
  `Sec-Fetch-Site` header the live-token endpoint checks (very old browsers do not send it).
- **In your own scripts:** adopt the fresh `csrf` value from every `json_out()` response, or read the live one from
  `/admin/csrf_token.php` with a same-origin request.

## Session ended or expired

The login page tells you why:

| Message | Cause |
|---|---|
| "Session expired" | Idle longer than the *admin session* setting (30 min – 5 h, default 4 h), or the hard 12-hour ceiling — every session ends after 12 hours regardless of activity |
| "…ended because the account logged in elsewhere" | An account has one active session; a newer login superseded this one. If that wasn't you, change the password |
| "…ended by the account owner" | The owner reset that account's password or 2FA, which ends its sessions |

## Login fails while the database is down

That is fail-closed and correct: pickup, login, and 2FA are denied when the limiter or user store is unreachable. There is no
bypass, by design — fix the database. (A legacy path exists for installs whose `config.php` still defines
`ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` and whose `users` table does not exist yet; the shipped `config.php.example`
defines neither.)

## AES key missing, invalid or lost

All location data, TOTP secrets, reveal payloads, and the log-chain HMAC key derive from the master key. **Losing it is
unrecoverable — there is no back door.** Restore from the key backup (you made one during setup, per the README), then
follow the rotation procedure there if the old key may have been exposed. Losing the key *and* having no backup means
re-installing with a fresh key and an empty database.

The key is looked up in this order: environment variable `DDMGMT_AES_KEY_HEX`, the file `/config/aes_key_hex`, then the
literal in `config.php`. Symptoms and fixes:

- **`AES_KEY_HEX is not a valid 64-hex-char key`** in the log, or the placeholder key still in `config.php`: the process never
  saw the key. A `docker exec` shell does not inherit variables from the container entrypoint — for CLI tools, pass
  `-e DDMGMT_AES_KEY_HEX=…` or rely on `/config/aes_key_hex`.
- **`[entrypoint] ERROR: no AES key (env or /config/aes_key_hex) for an existing install — not generating a new one`**: the
  `app-config` volume is gone or empty. The entrypoint refuses to invent a new key because that would make every stored
  location undecryptable. Restore the volume or set `DDMGMT_AES_KEY_HEX` from your backup.

## "Verify integrity" reports a broken line N

The log is a hash chain; verification reports the first entry that does not link up: `malformed entry` (not JSON / missing
fields), `broken chain linkage` (a line was deleted or reordered), or `hash mismatch` (a line was edited). Restore the
affected lines from backup — the log is append-only, so a healthy backup plus the surviving tail is the full repair. Note
the writer deliberately anchors *past* a corrupt tail on the next append, so logging keeps working while you investigate;
it refuses to write only when no intact anchor exists at all.

> [!NOTE]
> After an **AES key rotation**, entries written under the old key report `hash mismatch` at the first old entry until the
> log rotates out. That is expected: archive `logs/app.log` before rotating (see the README's rotation procedure).

## "Verify integrity" continuity says truncated / rotated / none

Next to chain validity the button reports a continuity verdict against the newest database checkpoint (written by the
cleanup pass, about hourly): `extends` is healthy; `truncated` means history ends before the anchor — tail entries were
deleted, or the file was swapped for an older copy. Restore from backup and investigate how the file was modified. `rotated`
is benign: the anchor aged out through legitimate log rotation. `none` means no anchor exists yet (fresh install, or the
`log_checkpoints` table predates your schema — re-run `setup.sql`). Deletions inside the ~hourly checkpoint interval cannot
be caught by design; that is the documented blind spot.

## "Verify integrity" says nothing to verify or log key unavailable

- **"Nothing to verify yet — the structured log is empty"**: the check covers the structured log (`logs/app.log`) only, not
  the error log. A fresh install or a log that was just wiped (panic mode, key rotation archive) has nothing to check.
- **"log key unavailable (AES_KEY_HEX invalid)"**: the chain key derives from the master key and the process cannot read a
  valid one — see [AES key](#aes-key-missing-invalid-or-lost). Logging refuses quietly (one warning) rather than writing
  entries it could never verify.

## Expired orders never disappear

Recipients never see an order past its expiry — lookups, unlocks and receipts treat it as gone the moment `expires_at`
passes — but the *row* is removed by a sweep. Expiry runs three ways: the Docker image's built-in loop (every 15 minutes),
real cron (`cron/cleanup.php`, hourly recommended), and pseudo-cron (every page visit checks an hourly stamp — see the
`last_cleanup` setting). On a quiet site without cron the sweep can lag until the next visit. If rows with a past
`expires_at` persist for days, run `php cron/cleanup.php` by hand and read its output plus `logs/error.log`. Only
`delivered` orders expire — `preparing` rows are never swept, even with an `expires_at` set.

## Photo upload rejected

Check in order: file must decode as JPEG/PNG/WebP/GIF (SVG, BMP, and MIME lies are rejected) and stay under 16 megapixels;
per-file size against `max_photo_mb` (Settings); at most `max_photos_per_order` files (default 10) per request — extras are
listed in the flash message, not silently dropped; and PHP's own limits (`upload_max_filesize`, `post_max_size`,
`max_file_uploads` — the Docker image raises them to 20M / 64M / 100). A bare `imagecreatetruecolor()` fatal means the PHP GD
extension is missing.

## Courier bounced to `2fa.php?required=1`

By design: 2FA is mandatory for couriers, optional for the owner. A courier who has never enrolled is sent to enrollment from
every page except logout and language settings. The owner sees the same banner until enrolling, but is never forced.

## Panic page resets to step 1 with an error

The per-step CSRF token expired (or the session lapsed) — the page now says so instead of silently restarting. Start the
sequence again from step 1. Step 3 is the point of no return: it wipes orders, photos, events, audit log, rate limits, the
tile cache and logs, then logs you out.

## First-owner form asks for a setup token

`DDMGMT_SETUP_TOKEN` is set, so creating the first owner requires it — that is the point: a fresh, network-reachable
instance cannot be claimed by whoever arrives first. Enter the token from your environment (`.env` on Docker). If it is unset
the form has no such field and the app logs a `bootstrap_unguarded` warning.

## Fresh `config.php` fatals on first login

The `DUMMY_AUTH_HASH` / `DUMMY_TOTP_SECRET` constants are required — a `config.php` written by hand (without them) will fatal.
Copy `config.php.example` whole instead — it also carries helpers such as `overwrite_and_unlink()`; the dummy values are
fixed by design, not secrets.

## Manual nginx/Caddy install serves sensitive paths

`.htaccess` is Apache-only. A non-Docker nginx/Caddy install MUST replicate every `deny all` / `respond 403` from
`docker/nginx.conf` / `docker/Caddyfile` (`includes/`, `logs/`, `cron/`, `tools/`, `tests/`, `data/`, `config.php`, PHP
execution under `uploads/`), or those paths are public. When in doubt, probe them: anything other than 403/404 on
`/includes/db.php` and `/config.php` is a misconfiguration.

## Map zones vanished after a rebuild

`data/` and `tiles/` are not Docker volumes, so rebuilding or recreating the container removes the downloaded zone files
(and the cached `pmtiles` CLI). The zone list survives in the database, so nothing is lost but the download: open
**Settings → Maps**, delete the affected zone and draw it again — the worker downloads it afresh. Mount volumes over those two
directories if you rebuild often.

## A zone download is stuck or failed

- **Nothing is moving:** downloads are done by `cron/maps_sync.php`, never by page visits. The Settings page kicks the worker
  after queueing when the platform allows; otherwise schedule it (`*/15 * * * * php /path/to/cron/maps_sync.php`).
- **Failed after a long silence:** the hourly steward marks jobs whose worker died as failed. Use **Retry** on the zone.
- **Failed immediately in proxy mode:** proxy mode is fail-closed — with no working pool proxy the job fails instead of
  silently going direct. Add proxies, or choose the direct route for that download.
- **Refused for size:** the worker dry-runs each zone and refuses it when it would not fit the free disk (512 MiB headroom is
  always kept). Free space or draw a smaller zone.

## pmtiles CLI hash mismatch

The bundled CLI version is verified against built-in SHA-256 pins before it is ever executed. A mismatch on a pinned build means
the download was corrupted or tampered with — the fetch is refused; retry, and investigate if it repeats. If you set
`DDMGMT_PMTILES_URL` or `DDMGMT_PMTILES_BIN`, or run an architecture without a pin, the app records the first hash it sees in
the `maps_cli_sha256` setting and compares against it afterwards; after deliberately replacing the binary, verify it yourself,
then clear that setting so the new hash is recorded.

## Local development quirks

- The test database (`deaddrops_test`) is shared between suites: suites pin and restore the limiter settings, but an
  interrupted run can leave `rate_limit_max` / `window_min` at unusable values — see [Rate-limited](#rate-limited--logins-rejected).
- HTTP suites bind `127.0.0.1` ports in the 87xx–89xx range; set `NO_PROXY=127.0.0.1,localhost,::1` or the requests route
  to a proxy.
- `UploadHardeningTest` (and photo uploads generally) need the GD extension; the suite documents the `PHP_INI_SCAN_DIR` flag
  for hosts where GD is opt-in.

## Shipping logs to a central system

There is no in-app syslog/webhook forwarding by design (the write path stays dependency-free) — but both logs are already
structured for collectors: `logs/app.log` is one JSON object per line (`ts`, `level`, `event`, `msg`, ...), and the PHP error
log is plain text. Point any forwarder (rsyslog `imfile`, Fluent Bit `tail`, Promtail, Filebeat) at those two files. Keep the
files themselves as the source of truth for `Verify integrity`: the HMAC chain is verified against the local lines, so
forward copies are for alerting/search, not for tamper evidence.
