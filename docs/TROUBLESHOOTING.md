# Troubleshooting

Symptom → cause → fix. For setup, see `README.md`; for design decisions,
see `docs/ADR.md`.

## Blank page / 500 with no message

`display_errors` is intentionally `0` — fatals never reach the browser.
Read `logs/error.log` (path: `ERROR_LOG_PATH` in `config.php`). If the log
itself is empty, check the web-server error log and directory permissions
(`chmod 750 logs/ uploads/`, owned by the PHP user).

## Everybody is suddenly rate-limited / logins always rejected

The limiter budget lives in `settings` (`rate_limit_max`,
`rate_limit_window_min`). If both read `0`, the budget is zero and every
attempt is denied. Reset to sane values directly in the database:

```sql
UPDATE settings SET value = '10' WHERE key_name = 'rate_limit_max';
UPDATE settings SET value = '15' WHERE key_name = 'rate_limit_window_min';
```

A successful login or pickup resets the caller's counter automatically
(`rl_reset()`); only a zeroed *budget* needs the manual fix above.

## "Invalid CSRF" after using two tabs or the back button

CSRF tokens are single-use by design: submitting tab A invalidates the token
already rendered in tab B. Reload the form (or re-open the page) and submit
again. API-style callers must adopt the fresh `csrf` value from every
`json_out()` response. Read-only probes (`check_setup`, log verify) never
rotate and are immune.

## Login fails while the database is down

That is fail-closed and correct: pickup, login, and 2FA are denied when the
limiter or user store is unreachable. The single exception is a *fresh
install* (no `users` table at all), where the config `ADMIN_*` credentials
work once. If the DB is merely unreachable, fix the database — there is no
bypass, by design.

## Lost AES key (`AES_KEY_HEX` / `DDMGMT_AES_KEY_HEX`)

All location data, TOTP secrets, reveal payloads, and the log-chain HMAC key
derive from the master key. **Losing it is unrecoverable — there is no
back door.** Restore from the key backup (you made one during setup, per
`README.md`), then follow the rotation procedure there if the old key may
have been exposed. Losing the key *and* having no backup means
re-installing with a fresh key and an empty database.

## "Verify integrity" reports a broken line N

The audit log is a hash chain; verification reports the first entry that
does not link up: `malformed entry` (not JSON / missing fields),
`broken chain linkage` (a line was deleted or reordered), or `hash mismatch`
(a line was edited). Restore the affected lines from backup — the log is
append-only, so a healthy backup plus the surviving tail is the full
repair. Note the writer deliberately anchors *past* a corrupt tail on the
next append, so logging keeps working while you investigate; it refuses to
write only when no intact anchor exists at all.

## "Verify integrity" continuity says truncated / rotated / none

Next to chain validity the button reports a continuity verdict against the
newest database checkpoint (written hourly by cleanup): `extends` is
healthy; `truncated` means history ends before the anchor — tail entries
were deleted, or the file was swapped for an older copy. Restore from
backup and investigate how the file was modified. `rotated` is benign: the
anchor aged out through legitimate log rotation. `none` means no anchor
exists yet (fresh install, or the `log_checkpoints` table predates your
schema — re-run `setup.sql`). Deletions inside the ~hourly checkpoint
interval cannot be caught by design; that is the documented blind spot.

## Expired orders never disappear

Expiry runs two ways: real cron (`cron/cleanup.php`, hourly recommended)
and pseudo-cron (a 1%-per-visit roll, at most once an hour — check the
`last_cleanup` setting). On a quiet site the sweep can lag by hours; on a
site with traffic but no cron it still runs. If rows with past `expires_at`
persist for days, run `php cron/cleanup.php` by hand and read its output
plus `logs/error.log`. Only `delivered` orders expire — `preparing` rows
are never swept, even with an `expires_at` set.

## Photo upload rejected

Check in order: file must decode as JPEG/PNG/WebP/GIF (SVG, BMP, and MIME
lies are rejected); per-file size against `max_photo_mb`; at most
`max_photos_per_order` files (default 10) per request — extras are listed in
the flash message, not silently dropped. A bare `imagecreatetruecolor()`
fatal means the PHP GD extension is missing.

## Courier bounced to `2fa.php?required=1`

By design: 2FA is mandatory for couriers, optional for the owner. A courier
who has never enrolled is sent to enrollment from every page except logout
and language settings. The owner sees the same banner until enrolling, but
is never forced.

## Panic page resets to step 1 with an error

The per-step CSRF token expired (or the session lapsed) — the page now says
so instead of silently restarting. Start the sequence again from step 1.
Step 3 is the point of no return: it wipes orders, photos, events, audit
log, rate limits, and logs, then logs you out.

## Fresh `config.php` fatals on first login

The `DUMMY_AUTH_HASH` / `DUMMY_TOTP_SECRET` constants are required — a
`config.php` written by hand (without them) will fatal. Copy
`config.php.example` whole instead — it also carries helpers such as
`overwrite_and_unlink()`; the dummy values are fixed by design, not secrets.

## Manual nginx/Caddy install serves sensitive paths

`.htaccess` is Apache-only. A non-Docker nginx/Caddy install MUST replicate
every `deny all` / `respond 403` from `docker/nginx.conf` /
`docker/Caddyfile` (`includes/`, `logs/`, `cron/`, `tools/`, `config.php`,
PHP execution under `uploads/`), or those paths are public. When in doubt,
probe them: anything other than 403/404 on `/includes/db.php` and
`/config.php` is a misconfiguration.

## Local development quirks

- The test database (`deaddrops_test`) is shared between suites: suites pin
  and restore the limiter settings, but an interrupted run can leave
  `rate_limit_max`/`window_min` at `0` — see "Everybody is suddenly
  rate-limited" above.
- HTTP suites bind `127.0.0.1` ports in the 87xx–89xx range; set
  `NO_PROXY=127.0.0.1,localhost,::1` or the requests route to a proxy.
- `UploadHardeningTest` (and photo uploads generally) need the GD
  extension; the suite documents the `PHP_INI_SCAN_DIR` flag for hosts
  where GD is opt-in.

## Shipping logs to a central system

There is no in-app syslog/webhook forwarding by design (the write path
stays dependency-free) — but both logs are already structured for
collectors: `logs/app.log` is one JSON object per line (`ts`, `level`,
`event`, `msg`, ...), and the PHP error log is plain text. Point any
forwarder (rsyslog `imfile`, Fluent Bit `tail`, Promtail, Filebeat) at
those two files. Keep the files themselves as the source of truth for
`Verify integrity`: the HMAC chain is verified against the local lines,
so forward copies are for alerting/search, not for tamper evidence.
