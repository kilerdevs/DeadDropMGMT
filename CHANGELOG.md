# Changelog

[![Keep a Changelog](https://img.shields.io/badge/changelog-Keep%20a%20Changelog-E05735?style=flat)](https://keepachangelog.com/en/1.1.0/)
[![SemVer](https://img.shields.io/badge/versioning-SemVer-3F4551?style=flat)](https://semver.org/spec/v2.0.0.html)
[![Latest tag](https://img.shields.io/github/v/tag/kilerdevs/DeadDropMGMT?style=flat&label=latest)](https://github.com/kilerdevs/DeadDropMGMT/tags)

All notable changes to DeadDropMGMT are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semver.

## [Unreleased]

### Changed
- Settings → Maps: **every zone has its own colour**, on the OSM zone map and
  as a swatch in the zone list, so a rectangle can be matched to its row at a
  glance (stable per zone; eight-colour palette, blue left for the rectangle
  being drawn). Ready zones are drawn solid; zones still queued, sizing,
  downloading or failed are dashed and lighter, with a hollow swatch, and the
  status text is coloured too (ready green, in progress amber, failed red).
- The OSM proxy status is a small caption **directly under the map** it
  describes (order pickers and the zone editor) instead of a fixed overlay at
  the top: it no longer covers page content, and a failover shows the skipped
  proxies on a second, muted, capped line.
- **OSM proxy routing is on by default** (new installs; existing installs keep
  their setting) and the pool is **discovered automatically on the first run**:
  an empty pool fails closed, so the same background job that replaces failed
  proxies seeds a first pool with exactly what the Auto-discover button would
  store (`proxy_seed` in the audit log) — started at container boot, by the
  first page visit or by the first OSM request. Until it finishes, OSM-backed
  maps answer 502 instead of leaking the server address. This makes the same
  outbound connections as the button, so it is opt-out: routing off in
  Settings, or `DDMGMT_PROXY_HEAL=0`.
- The pseudo-cron now runs from **any PHP page** (public, admin, receipt, JSON
  polls), not just the public index, and after the response has been sent, so
  an install used only through `/admin/` still gets its hourly maintenance and
  no visitor waits for a sweep. `healthz.php` stays code-free;
  `DDMGMT_PSEUDO_CRON=0` turns it off for installs with real cron.

### Added
- `ArrayInputTest`: a permanent guard for array-shaped input. Every entry
  point is sent every parameter name the code reads as `name[]=x`, GET and
  POST, as a logged-in owner, and the answer and the logs must stay clean —
  the class of bug behind the old `htmlspecialchars(): Argument #1 must be of
  type string, array given` error (fixed earlier via `post_string()` /
  `get_string()`). It fails on the pre-fix `index.php`.
- **Runs on free shared hosting** (no Docker, no cron, no exec, no CLI PHP, no
  way to set environment variables). A new capability layer
  (`includes/host.php`) is consulted by everything that used to assume them:
  the proxy pool upkeep runs **inline after the response** in a time-budgeted
  pass when no detached job can be started; discovery fetches its lists and the
  public-IP probe through cURL, so `allow_url_fopen` is not required; a host
  that can never find a working proxy has routing **switched off
  automatically after three empty discoveries** (audit + warning + Settings
  notice) instead of staying wedged fail-closed; without cURL routing is not
  applied and OSM requests go direct; map-zone **downloads** (which genuinely
  need `proc_open`, Linux and cURL) are refused up front with a clear message
  and a disabled Queue button. `DDMGMT_PSEUDO_CRON` / `DDMGMT_PROXY_HEAL` can be
  `define()`d in `config.php`. **Settings → Hosting** lists what the host
  allows and what each gap costs. A non-Docker install gets its version line
  from `tools/build_info.sh --write` (`build-info.json`, web-denied). New README
  section "Free shared hosting" and a troubleshooting entry.
- Failed proxies are replaced automatically. While OSM proxy routing is
  enabled, a discovered pool entry that fails is confirmed dead with a fresh
  probe, deleted and swapped for a newly discovered proxy chosen by exactly the
  Auto-discover criteria. Runs as a detached CLI job (`cron/proxy_heal.php`,
  also invoked by the cleanup cron) under a lock and a 10-minute cooldown,
  never inside a request. Nothing is deleted until a replacement exists (an
  outage cannot wipe the pool, which never shrinks), recovered proxies are
  kept, `manual` entries are never removed, each swap is audited
  (`proxy_replace`). It reuses discovery, so it makes the same outbound
  connections as the Auto-discover button — see the README privacy table.
- Settings shows the running version to owners: `vX.Y.Z` for a tagged release,
  or `vX.Y.Z+N` with a **BETA** badge and a one-line `hash · branch` for
  builds past the last release tag (builds from `dev`); commit messages are
  never recorded. The build host records
  it with `tools/build_info.sh --export` (the image has no `.git`); a plain
  build shows "unknown build". Not exposed on any public or unauthenticated
  page.

### Changed
- **Upgrade step required for existing installs:** after loading the new
  `setup.sql`, run `php tools/migrate_order_tokens.php` (dry-run first, back
  up the database — it drops the plaintext token columns). Until it has run,
  orders created before the upgrade cannot be found; new orders work. The
  hourly cleanup logs a `legacy_order_tokens` warning while any remain.
  Details in the README and the troubleshooting guide.
- The per-session failure bucket on the public unlock form now has its own
  fixed threshold (5 failures per window) instead of borrowing the IP
  limiter's attempt count, so retuning the IP budget (for example raising it
  for a busy NAT exit) no longer moves the per-cookie budget; the bucket
  still follows the limiter's window.
- `X-Forwarded-Proto` multi-hop lists now use the last entry, the same rule
  `X-Forwarded-For` already followed. A warning is logged when a list is seen.
- Documentation: the requirement to serve the app from the root of its own
  host (no sub-path) is documented, and the README, troubleshooting guide and
  ADR-006/016/019 describe the changes above.

### Fixed
- Map zone downloads no longer decide on stale file ages: the orphan sweep
  reads mtimes from disk instead of the process stat cache, so a steward that
  listed the tiles earlier cannot keep orphans forever — or mistake a live
  download for an aged file.
- The browser specs own the map queue deterministically again: the detached
  worker kick honours a `maps_worker_kick` switch (off in the e2e seed), so a
  refreshed zone cannot be failed by a worker racing the test — and
  queue-dependent specs skip cleanly on hosts that cannot run downloads
  (no Linux/exec/cURL) instead of timing out on the disabled button.
- PhotoCapTest probes for a free loopback port like MapsFetchTest instead of
  insisting on a fixed one, so a busy CI runner cannot fail the boot.
- Settings → Maps: queueing a zone without a name (or with the name not
  reaching the server) gave a toast naming a field that sits far above the
  button and vanished in seconds. The name is now checked in the browser: the
  field is scrolled into view, focused and marked, with the reason written next
  to it until you type. Every Settings POST (autosave, proxy and zone actions,
  the status poll) also goes through one queue that takes the rotated CSRF
  token from each reply and retries once with the live token on a 403, so two
  overlapping requests can no longer reject each other or restore a stale token.
- Notifications (the toasts on Settings and the order editor) no longer run off
  the screen: they wrap, are capped to the viewport width and height, and stay
  up longer the longer the message is. The "queued" message was one 100+
  character line that did not fit a phone.
- Settings → log viewer: **Verify integrity** checks the structured,
  hash-chained log, but the panel listed only PHP's raw error file — so "2
  entries verified" sat under "The log is empty". The viewer now shows the
  structured entries (newest 200, with time, level, event, message and context)
  above the raw error log, with Verify and the structured-log download next to
  them.
- Admin panel on phones: the menu button was missing on **New order** when the
  map provider is self-hosted (`admin.js` was only loaded on the Leaflet path,
  which also skipped the live-CSRF refresh on that form); the OSM proxy badge
  was always on screen because its `display:flex` overrode the `hidden`
  attribute, and is now only rendered for OSM maps with proxy routing enabled
  (and sits beside the menu button on narrow screens); **Settings** no longer
  scrolls sideways — the proxy pool and map zones render as cards instead of a
  580px-minimum table. `[hidden]` now always wins over component display rules.
- Settings → Maps zone editor now works on touch screens: drawing, corner
  resize and move use Pointer Events (finger drags never produced the mouse
  events it relied on), draw mode stops the page scrolling under the finger and
  the corner handles are fingertip-sized. Existing zone rectangles show their
  name as a permanent label and follow the live status poll. The OSM proxy
  badge now also appears on Settings while proxy routing is on (the editor's
  tiles and searches already went through the server-side proxy path).
- A crafted array-shaped field (`order_token[]=x`) with a valid CSRF token made
  `index.php` throw an uncaught `TypeError` while re-rendering the form. The
  public and admin pages now read form and query fields through
  `post_string()` / `get_string()` everywhere, so such input is an ordinary
  validation error.
- `receive.php` parsed `step` with an `(int)` cast, so `step[]=x` or `1abc`
  counted as step 1. Only the literal `1` and `2` are steps now.
- The admin console no longer reports `style-src` CSP violations: the last
  inline `style=""` attributes and every `element.style` write (copy-button
  scratch element, mobile menu toggle, zone-label colours, editor touch and
  cursor handling) are stylesheet classes now, so the fail-closed policy is
  satisfiable on every page.
- Settings is one aligned column again: the panel no longer sits 115px left
  of the version line (a viewport-centering offset that applied to some
  blocks but not others), the hosting list is the same width as the settings
  panel, and the version line is a single centered row. The admin stylesheet
  link carries its mtime, so a deploy is visible without a hard refresh.

### Security
- Order tokens are no longer stored in the clear (ADR-019). Lookups go through
  `orders.token_hmac`, an HMAC-SHA256 of the lower-cased token under its own
  HKDF subkey; the admin panel reads an AES-GCM copy (`token_enc` /
  `token_iv`) under a second subkey. `order_events` and `audit_log` keep only
  the index, so a database dump holds no usable token and cannot be used to
  test candidate tokens offline. `tools/migrate_order_tokens.php` migrates
  existing data, and `tools/rotate_aes_key.php` now re-encrypts and re-indexes
  tokens (event and audit rows of already-deleted orders lose their index).
  Token matching stays case-insensitive, as before.
- Sensitive flash messages (generated pickup passwords, enrollment secrets)
  are sealed under their own HKDF subkey (`deaddrop:flash-v1`) instead of the
  TOTP subkey, completing the purpose separation of ADR-016. Sessions are
  transient, so nothing needs migrating.

## [1.5.0] - 2026-09-18

### Added
- Self-hosted maps, Phase 1 (opt-in, OSM stays default): `map_provider`
  setting (`osm` | `selfhosted`, Settings → Maps), vendored MapLibre GL JS
  + PMTiles client, server-built dark style at `/tiles/style.php`
  (admin-gated), and a MapLibre picker on the new-order/edit pages with the
  same click-to-pin contract as Leaflet. With no zones downloaded yet the
  map chrome renders an empty-state overlay pointing at Settings → Maps.
  CSP gains `worker-src 'self' blob:` (both profiles) for MapLibre's WebGL
  workers. Pinned by `MapsTest` + a `maps-selfhosted` Playwright spec that
  renders a committed Warsaw fixture with zero third-party requests.
- Self-hosted maps, Phase 2 (zone downloads): `map_zones` manifest,
  `pmtiles` CLI auto-fetch (pinned v1.31.2, SHA-256-pinned per architecture), `cron/maps_sync.php`
  worker (system cron + detached kick, one-at-a-time lock), exact dry-run
  sizing with disk-budget enforcement, live speed/ETA progress, per-download
  proxy consent (fail-closed), Settings → Maps zone manager with polling,
  and a `maps-zones` Playwright spec for the hermetic UI paths. Page visits
  never download — the hourly steward only fails stalled jobs.
- Self-hosted maps, Phase 3 (zone editor): draw the download rectangle
  directly on an OSM canvas in Settings → Maps (same-origin tiles via
  tile_proxy.php, zero third-party contact) — drag to draw, drag the body
  to move, corners to resize, Clear to drop; every change syncs the
   numeric bbox inputs that the queue button reads. Overlapping drafts
   warn with the shared-tiles percentage (warning only), existing zones
   render in red, and a place search pans through the proxied Nominatim
   path. Pinned by a `maps-editor` Playwright spec (tile traffic aborted,
   queued zones deleted again).
- Self-hosted maps, Phase 4 (public reveal): with the self-hosted provider,
  a delivered order whose pin sits inside a ready zone renders the vendored
  MapLibre stack on the public reveal page (`reveal-map.js`, style inlined
  server-side — no new endpoint) instead of the OSM iframe, so the
  recipient's browser makes zero third-party requests. Only the covering
  zones' files are fetched (non-covering zones stay undisclosed); a pin
  outside every zone, or provider `osm`, keeps the OSM embed as the
  fallback. Pinned by `MapsTest` covering-zone arms plus a `maps-reveal`
  Playwright spec (rendered canvas + aborted-everything-else proof, and the
   osm-fallback path).
- Self-hosted maps, Phase 5 (zone freshness): ready zones remember the
  planet build they were cut from and show an *Update available* badge once
  the worker learns a newer build, with a Refresh button that re-queues
  them through the normal worker path (atomic republish — the old file
  serves until the new one lands). Freshness reads the cached build key
  only, so no page view ever fetches the build list. Pinned by `MapsTest`
  stale/refresh arms plus a `maps-zones` Playwright test that refreshes the
  seeded zone through the real settings UI.
- Map pin readouts show the reverse-geocoded place ("Country, State" via the
  proxied Nominatim reverse path) instead of raw coordinates: the order
  pickers (Leaflet + MapLibre) and the zone editor's draft label. Lat/lng
  stay in form fields and data attributes where the code needs them, but no
  owner-facing surface renders them anymore.
- Single active session per account: a login elsewhere supersedes the old
  one (`users.active_session_id`, set at every full login). The superseded
  browser is logged out to the login page with an explanatory notice
  (including a change-your-password nudge) instead of bouncing silently.
- Failed password and 2FA-code guesses are audited (`login_failed`,
  `2fa_failed`, attempted account + client IP, never secrets) — brute force
  is now visible in the existing audit-log viewer. Volume is bounded by the
  limiter, so it cannot become log spam.
- Real-browser E2E (`e2e/`, Playwright/Chromium, `e2e` CI job): the no-JS
  language-switcher path, inline-handler absence in a live DOM, the
  mid-reveal switcher hide, and full public/admin lifecycles through actual
  forms — the behaviours the raw-HTTP suites structurally cannot observe.
  Isolated `deaddrops_e2e` database, per-test browser contexts, 11 specs.
- TOTP replay resistance: each accepted counter is claimed at most once per
  user (`users.totp_last_counter`, atomic conditional UPDATE), so a code is
  good for its first presentation only — never for a replay inside the ±1
  window. Replayed codes answer exactly like wrong ones (no oracle).
- Last-resort error boundary in the kernel: an escaped Throwable is logged
  and answered with the localized 500 page (JSON for fetch callers) instead
  of the webserver's blank 500. CLI/cron keeps log + exit 1.
- `tests-tz` CI job runs the full battery under `TZ=Europe/Warsaw`, where
  UTC/local clock skews fail open instead of hiding.
- Public language switcher: recipients can change the site language from a
  selector on the pickup page (`?lang=`). The choice applies to the same
  request, persists in the session, and is remembered across visits in a
  year-long `ddmgmt_lang` cookie (HttpOnly, Lax). Unknown codes are ignored
  instead of erroring; the account preference still wins for logged-in
  staff, then the visitor choice, then the cookie, then the site default.
  `current_lang()` is no longer statically memoized so long-lived SAPIs
  can't pin the first request's language.
- Self-hosted maps, Phase 6 (readable, labelled map): the dark style is
  rebuilt for contrast and information density. Street names run along the
  roads (motorway/trunk refs included), house numbers appear at street
  zoom, and places are labelled by rank — city, town, village, hamlet, plus
  district and neighbourhood names in spaced capitals — with water and
  waterway names in italics. Points of interest are colour-coded by category
  (health, transit, education, nature, shops & food, civic, culture) in
  three prominence tiers so a dense block stays legible: major sites from
  z14 with a dot, common ones from z15.5, small shops and cafés from z17 as
  quiet text. Roads get a real hierarchy — casings, data-driven widths per
  class, warm motorways, dimmed tunnels, dashed footpaths, ticked rail —
  and buildings now paint *under* the roads (they used to sit on top,
  which turned the map into grey blobs). Only meaningful land is tinted
  (parks, woods, pitches, cemeteries, hospitals, campuses, water); housing
  stays the ground colour. Labels are drawn from vendored Noto Sans SDF
  glyphs (`fonts/glyphs/`, Latin, Latin Extended and Cyrillic — Polish,
  Ukrainian and Russian names render), served same-origin, so the zero
  third-party-request guarantee holds. With several zones, every zone's
  labels are stacked above every zone's ground. `MapsTest` pins unique
  layer ids, real basemap source layers, geometry-before-labels ordering
  and that each font the style names ships its glyph ranges.
- Community files: `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1, reports through
  GitHub's private form), issue forms for bug reports, feature requests and
  documentation problems (with a config that points security reports to private
  vulnerability reporting), and a pull request template with test, security and
  documentation checklists.
- `docs/ADR.md` gains an index and the missing ADR-016 (HKDF key separation —
  referenced from the code and README but never written down), ADR-017
  (self-hosted maps as an opt-in provider) and ADR-018 (single-use CSRF tokens
  with a live-token endpoint); records are now in numeric order.

### Changed
- The duplicate `order_remove` admin endpoint (route, handler and legacy shim)
  is gone: it was byte-for-byte `order_close`, and no page posted to either.
  `order_close` stays.
- Behaviour to know about: changing a password or resetting 2FA ends that
  account's other sessions; a failed guess counts against an account or IP for
  the whole window (successful logins no longer wipe it); zone files carry their
  token in the name, so anything that hard-coded `/tiles/zone_<id>.pmtiles` must
  read the URL from the style instead.
- Settings → Maps: the four coordinate fields (west/south/east/north) are
  gone from the "queue a new zone" form — the rectangle is drawn on the map,
  which was already the primary path. The values now travel in hidden inputs
  the editor writes and the queue button reads. **Clear** resets them (a
  stale rectangle can no longer be queued invisibly), and queueing with
  nothing drawn shows "Draw on the map" instead of a server-side "must be
  numbers". The four label strings are dropped from all eight languages; the
  e2e specs set the bbox through a `setZoneBbox` helper, with new specs for
  the hidden fields, Clear, and the nothing-drawn guard.
- Public language switcher restyled and relocated: a quiet footer row under
  the trust bar instead of a header control (plus `color-scheme: dark`, which
  is what actually keeps the native select out of the OS light theme). With
  JavaScript the choice auto-applies 500 ms after the last change
  (debounced, CSP-clean via `public.js`); without it a `<noscript>` Apply
  button remains the path. Switches spend from a dedicated IP budget
  (30 / 10 min, same-language requests free) — past it the switch is ignored
  and the page renders in the current language, never an error.

- README rewritten and audited against the code: centered header with status,
  stack, security and quality badges; overview with sequence, lifecycle and
  trust-boundary diagrams (Mermaid); quick start; configuration reference;
  Docker volume table (map zone files in `data/` / `tiles/` are not volumes and
  are lost on rebuild — now stated); test, coverage and mutation-probe sections
  brought up to date (30 suites, 7 browser specs, 16 mutants). Corrected: the
  manual `config.php` instructions (the old snippet lacked helpers the app
  calls, e.g. `overwrite_and_unlink()`; it now says to copy
  `config.php.example` whole), pseudo-cron behaviour, the public CSP claim,
  `.htaccess` coverage, per-surface rate-limit wording, the self-hosted maps
  file naming and `pmtiles` CLI pinning, requirements (`mbstring`, `curl`,
  WebP), permissions and cron lines, and the project tree. Stale wording
  fixed in `CONTRIBUTING.md`, `docs/TROUBLESHOOTING.md` and
  `e2e/fixtures/README.md`.
- Documentation audit against the code, beyond the README: `CONTRIBUTING.md`
  (default branch, CI matrix PHP 8.2–8.5, real coverage floors, the portable
  `setup.sql` pattern instead of `ADD COLUMN IF NOT EXISTS`, PHPStan / CS-Fixer /
  Playwright commands, i18n and CSP conventions), `SECURITY.md` (supported
  versions, maps and deployment files in scope, response-time table),
  `docs/TROUBLESHOOTING.md` (limiter clamping and per-account budgets, reverse
  proxy without `DDMGMT_TRUST_PROXY`, the current pseudo-cron behavior, session
  messages, AES key resolution, verify-log messages, map-zone problems),
  `THIRD-PARTY-NOTICES.md` (Leaflet copyright years, QRCode.js author and
  upstream notice, an index table) and `TOTP-APPS.md`. Documents gained badges,
  callouts and indexes where they help.
- `CHANGELOG.md` restructured: duplicate section headings merged into one per
  kind in every release, sections in Keep a Changelog order, version compare
  links added, date separators normalised. No entry was removed.

### Fixed
- Settings → Maps zones list no longer overflows the settings card. Eight
  table columns needed ~645 px inside a 600 px panel (long headers such as
  SZCZEGÓŁOWOŚĆ alone were wider than their values), pushing the action
  buttons past the border. Each zone is now a two-line card — name and
  actions on the first line, the facts (detail, status, size, speed, ETA,
  route, each prefixed with its column title) wrapping freely below — so it
  fits in every language and state. Empty speed/ETA/size cells are hidden
  instead of printing a column of dashes; the header row stays for screen
  readers.
- Queued zones sat on "Queued" forever under Apache: `maps_kick_worker()`
  launched the worker as `$PHP_BINARY cron/maps_sync.php &`, but under
  mod_php `PHP_BINARY` is empty (php-fpm: the fpm binary), so the detached
  command died silently while the UI announced the worker had started. It
  now resolves a real CLI (`maps_php_cli()`: the running binary under CLI,
  else `PHP_BINDIR/php`, `/usr/local/bin/php`, `/usr/bin/php`) and reports
  `false` — the honest "waits for cron" message — when none exists.
- Docker image: `data/` and `tiles/` shipped root-owned via `COPY` and were
  missing from the `chown`, so `www-data` could not write the downloaded
  `pmtiles` CLI or extracted zones and every zone download failed. Both are
  created and chowned at build time now.
- `it`, `pl`, `ru` and `uk` were missing the 84 strings added with the
  self-hosted maps UI (zone manager, editor, errors, pin status texts), so
  Settings → Maps rendered in English for those languages; translated, and
  the stale `admin.edit.current_pin` key dropped. `I18nTest` now fails when
  any language lacks a key that `en` has or keeps one it does not (pl/ru/uk
  pluralise with `.few`/`.many` in place of `.other`).
- `pmtiles` CLI version probe used a `--version` flag the real tool never
  had (it takes a `version` subcommand), so every freshly downloaded tool
  failed its check and all zone downloads died as `code:version_mismatch`.
  The probe now runs `pmtiles version` (whose `pmtiles 1.31.2, commit …`
  line still contains the pinned version); the test doubles mirror it.
- Admin language switch alerted "CSRF" (and logout silently did nothing) after
  any other request from the same page — an autosave, the zones poll, an AJAX
  save. `verify_csrf()` rotates the session token on every success, so the
  copy rendered into the sidebar (and into every form) went stale. New
  `GET /admin/csrf_token.php` (admin-only, GET-only, refuses cross-site
  fetches, no CORS, never rotates) returns the live token; the language switch
  and a global submit hook in `admin.js` take it right before any POST form
  goes out (a cancelled confirm still cancels; `formaction` submitters are
  preserved via `requestSubmit`). Settings' "Clear log" / "Clear analytics"
  forms had the same flaw. Pinned by a stale-token scenario in
  `AuthorizationHttpTest` (fails without the endpoint) and a Playwright spec.
- Coverage gate: the logger's new key-guard arms dipped `logger.php` under its
  92 % floor; the master-key text now flows through a test seam
  (`_log_key_hex()`), so `LoggerTest` covers the unusable-key paths in-process
  (the child-process probe stays for the no-warnings / untouched-file proof).
- Settings → Diagnostics: **Verify integrity** answered "Chain intact — 0
  entries verified" while the page listed 40 lines, because the check covers
  the structured (hash-chained) log, which was empty, not the PHP error log
  shown above it. An empty structured log now says so — "Nothing to verify
  yet … covers the structured log only, not the error log above" (eight
  languages) — instead of reading as a pass.
- CLI processes that never saw the container entrypoint's environment
  (`docker exec` shells, cron, `tools/*`) had no `DDMGMT_AES_KEY_HEX`, ran on
  the placeholder key and filled `error.log` with `hex2bin()` warnings.
  `config.php` now falls back to the key the entrypoint persisted at
  `/config/aes_key_hex` (the environment variable still wins). The
  structured logger refuses quietly when the key is unusable — one message per
  process, no empty `app.log`, no per-call warnings — and log verification
  names the cause; `aes_key_valid()` / `aes_key_problem()` let
  `separate_keys.php` and `migrate_cbc_to_gcm.php` check the key before any
  `hex2bin()` (`strlen(false)` was a TypeError). Pinned by a child-process
  probe in `LoggerTest` that fails on the old logger.
- `tools/mutation_probe.php` exits early with an explanation when it cannot
  write the source files (root-owned image, read-only checkout) instead of
  emitting a wall of `file_put_contents` warnings with meaningless verdicts;
  `docker/e2e_journey.php` refuses to run against a database that already holds
  users or orders and no longer reads columns from a row that was never created.
- **The AES key vanished on every container restart**: the entrypoint exported
  `DDMGMT_AES_KEY_HEX` only on first boot, so after `docker restart` or a host
  reboot (container filesystem — `config.php` — survives, shell exports do not)
  the app ran with the placeholder key and every location decrypt failed. The key
  is resolved on every start (env > config volume > first-boot generation) and an
  existing install without any key now refuses loudly instead of generating one.
- The container shipped without a `php.ini`, so PHP's defaults contradicted the
  app's own limits: `memory_limit` 128M against a 16-megapixel photo pipeline,
  `upload_max_filesize` 2M / `post_max_size` 8M against phone photos (an
  over-limit POST arrives empty and surfaces as "invalid CSRF token"), and
  `session.gc_maxlifetime` 1440 s ended admin sessions after ~24 min idle whatever
  `admin_session_hours` said. `docker/php-ddmgmt.ini` sets 256M / 20M / 64M /
  6 h and turns `display_errors` off (early-bootstrap fatals printed paths).
  `Dockerfile.fpm` also gains the `data/` and `tiles/` directories the map worker
  needs.
- Map worker lock was read-then-write, so two workers started together could
  both "acquire" it and extract into the same `.part`; it is a compare-and-swap
  now. A zone deleted mid-download is no longer published (orphan file no row
  would ever remove), and the steward sweeps orphan zone files.
- `receive.php` rendered the confirmation card for any well-formed token when
  `step` was neither 1 nor 2 (no existence or state check); it redirects now.
- `osm_reverse_url()` printed tiny coordinates in scientific notation
  (`1.0E-5`), which Nominatim rejects.
- The retired `require_delivered_reveal` setting (a toggle that never gated
  anything) is gone from Settings, `save_setting` and `setup.sql` (the leftover
  row is deleted on upgrade). `reveal_capability()` (unused) removed.
- Stale keystroke poll no longer logs freshly-logged-in admins out: the
  login form polls `check_setup.php` per keystroke, and a poll in flight
  across login's session-regenerate landed with a dead session id — a
  cookie-emitting start minted an empty session whose Set-Cookie clobbered
  the auth cookie. The endpoint now opens its session without ever sending
  cookies. Covered by a deterministic replay probe in
  `AuthorizationHttpTest`.
- `SettingsTest` restores the settings rows its hostile-value probes clobber
  (it left `rate_limit_max=0`, locking later standalone suites out of
  logins) — snapshot at start, restore at end, per the suite convention.
- Language switcher was dead under its own CSP: `script-src 'self'` + nonce
  never authorizes inline `on*` handlers, so the `onchange` submit did
  nothing with JS enabled. Plain submit button now, no inline handlers
  anywhere (the admin extend-expiry `onclick` had the same disease and is a
  real form now). A structural test scans rendered pages for `on*=` attrs.
- Switching language mid-reveal no longer eats the reveal: the selector is
  hidden while a single-use reveal (or preparing card) is on screen instead
  of discarding it via a fresh GET.
- Logger substitution fallback hashed default-flags encoding while the
  stored line (and verifier) used unescaped flags — every non-ASCII base
  field false-alarmed as "hash mismatch". Identical flags before hashing
  now; unencodable lines refuse loudly instead of appending a blank line
  the verifier would silently skip.
- Rate-limiter windows are UTC-anchored on read (`window_start` is stamped
  `UTC_TIMESTAMP()`): east of UTC budgets reset constantly (fail-open),
  west stayed sticky-blocked. New `RateLimitTzTest` pins verdicts across
  five timezones.
- Array-shaped inputs (`field[]=x`) no longer 500: `verify_csrf()` answers
  false for non-strings (covers all its call sites), new
  `post_string()`/`get_string()` bag readers guard public and auth inputs,
  and the kernel boundary localizes anything left.
- `receive.php` checks CSRF before spending limiter budget (same ordering
  as `index.php`): forged floods no longer burn the victim's IP budget.
  Covered by a no-spend probe in `PublicFlowTest`.
- Public language switcher did nothing while the same browser held an admin
  session: `current_lang()` let the admin account's saved language outrank the
  public `?lang=` choice, so every public switch was overridden on the next
  render. Public pages now honour the public choice (the admin area still uses
  the account language). Pinned by an HTTP scenario in `PublicLangTest` that
  logs in as a Polish-language admin and switches the public page to German.
- Docker stacks: `DDMGMT_AES_KEY_HEX` and the new optional `DDMGMT_SETUP_TOKEN`
  in `.env` now actually reach the container (all three compose files pass them
  through; `.env.example` documents them). Previously `.env.example` promised a
  key override that compose never forwarded.
- `.htaccess` now denies `cron/` like the nginx and Caddy configs always did
  (Apache answered 404 through the scripts' own CLI guard; it is 403 now, and
  `KernelTest` pins it for all three servers).
- `tools/rotate_aes_key.php` no longer claims the log chain stays verifiable
  across a rotation: entries written under the old key do not verify under the
  new one, so it now tells the operator to verify and archive `logs/app.log`
  first. README, tool and ADR-016 agree.
- `SetupPasswordTest` no longer fails the whole suite when its built-in server
  is slow or blocked: it takes a free port from the OS instead of a fixed one,
  waits up to 20 s, and prints the server's stderr when the boot fails (seen
  once on the MySQL 8 CI job with no diagnostics).

### Security
- Full code audit. Fixed below; deliberately left: the public "No tracking" wording
  vs. retained lookup events, the compose file's default DB passwords / plain HTTP
  (the entrypoint now warns), the base-image digest pin, and the config-fallback
  owner login.
  **CLI-only files were web-executable**: `tools/*`, `cron/*`, `docker/e2e_journey.php`,
  `e2e/seed.php` and the `tests/` harness carried no auth and the default Apache
  setup served them — `tools/mutation_probe.php` rewrites security code in place,
  `purge_pickup_password_recovery.php` and `separate_keys.php` mutate data. Every
  one now exits 404 unless `PHP_SAPI === 'cli'` (pinned over HTTP by
  `AuthorizationHttpTest` and structurally by `KernelTest`), and the root
  `.htaccess`, `docker/nginx.conf` and `docker/Caddyfile` deny `tools`, `tests`,
  `docker`, `e2e`, `data`, `backups`, `.semgrep`, `.github`, `setup.sql`,
  `composer.*`, `package*.json`, `auto-update.*` and friends.
- **Expiry is exact**: lookup, unlock, the reveal re-check and receipt
  confirmation refuse orders past `expires_at` (`ORDER_LIVE_SQL`) even before
  the sweep deletes the row. The pseudo-cron no longer rolls a 1-in-100 die
  (it made the sweep effectively daily on a quiet site — expired drops stayed
  retrievable for days), and the Docker entrypoint runs `cron/cleanup.php`
  every 15 minutes.
- **Rate limits cannot be laundered**: a status lookup or a successful unlock
  used to `rl_reset()` the whole per-IP counter, so guesses interleaved with
  free requests (or with a valid login of one's own — a courier account) were
  never throttled. They now `rl_refund()` exactly the one attempt spent, on the
  public page and in admin login alike. Admin login gains a per-account budget
  (20 failures / window, keyed on the submitted name whether or not it exists)
  and 2FA a per-account budget next to the per-IP one, so rotating addresses
  no longer buys unlimited guesses. Regression tests fail on the old code.
- **Sessions belong to live accounts**: `require_admin()` re-reads the user row
  every request — a deleted account is refused immediately, role and 2FA flag
  follow the row, and an owner-triggered revoke (password change, 2FA reset)
  ends every session of that account (the actor's own is kept). A 12-hour
  absolute lifetime caps sessions that activity would otherwise keep alive
  forever.
- **Map zone files are no longer enumerable**: they were public at
  `/tiles/zone_<id>.pmtiles`, so anyone could walk ids and learn which regions
  the operation covers. Files are now `zone_<id>_<128-bit token>.pmtiles`
  (`map_zones.file_token`); the name reaches a browser only inside a style the
  server chose to send (admins: all ready zones, a recipient: only the zones
  covering their pin) — the same bearer-name model as photo URLs. Existing
  zones are migrated on first touch (token minted, files renamed), the old
  names and `.part` files are denied by `tiles/.htaccess`, nginx and Caddy.
- The `pmtiles` binary is verified against a pinned SHA-256 per architecture —
  the archive before unpacking, the binary before it is ever executed — instead
  of trust-on-first-use (override env vars keep TOFU for tests).
- Owner bootstrap can be guarded with `DDMGMT_SETUP_TOKEN` (the first visitor
  otherwise claims a fresh instance); unguarded bootstraps log a warning.
- `auto-update.sh` deploys only tags signed by a key in `.allowed_signers`
  (`ALLOW_UNSIGNED_TAGS=1` to opt out) and writes its dumps private (`umask 077`).
- Panic wipe now also destroys the admin tile cache (it remembers every map area
  viewed — at street zoom, the drop). Cache misses are budgeted per admin (600 /
  min), only genuine PNGs are served or cached, and the hourly cleanup prunes the
  cache by age and size.
- Credentials no longer rest in the session store in plaintext: flashes carrying
  a generated pickup password or an enrollment secret are sealed (`flash_set()` /
  `flash_take()`). Passwords over bcrypt's 72 bytes are refused instead of being
  silently truncated.
- CSP gains `form-action 'self'` (both profiles); JSON endpoints send `nosniff` +
  `no-store`; `tiles/.htaccess` denies every PHP file but `style.php`; the docroot
  is mode 755 instead of the base image's world-writable 1777.
- Retention: events for tokens that never matched an order (nothing else ever
  deleted them) go after 30 days, audit rows after 365.
- Photo cap is per order, not per request; `audit()` cuts on a character boundary
  (a byte cut could make the INSERT fail and drop the row); zone retry is audited.

## [1.4.0] - 2026-09-17

### Added
- Audit follow-ups (external review, all claims verified before acting):
  order capability tokens use the full 62-symbol alphanumeric alphabet
  (16 chars, ~95 bits — previously hex-only 64 bits despite what the threat
  model promised; old tokens keep working), photo uploads are capped per
  request (`max_photos_per_order`, default 10, enforced in `create.php` and
  `edit.php` with over-cap files named in the flash), stale `rate_limits`
  rows are purged on every cleanup pass, and the session failure bucket
  follows the configured limiter window instead of a hardcoded 900 s
- Auth hardening from the same review: the fresh-install config-owner
  fallback now answers only for a genuinely absent `users` table (any other
  DB failure fails closed, so an outage can never downgrade a TOTP-enrolled
  owner to password-only login), and the admin session timeout is a sliding
  inactivity window instead of absolute-since-login
- Uploaded photo URLs hardened as bearer links: `Referrer-Policy:
  no-referrer` on both header profiles (nothing server-side reads the
  Referer) and `Cache-Control: private, no-store` on `/uploads/` across
  Apache (`uploads/.htaccess`, now force-tracked in git and un-ignored for
  Docker builds — it was silently absent from images), nginx, and Caddy
- `docs/TROUBLESHOOTING.md`: symptom → cause → fix for the failures
  operators actually hit (limiter lockouts, CSRF tab desync, DB-down
  behaviour, key loss, broken log chains, idle cleanup, upload rejects,
  2FA bounces, manual nginx/Caddy gaps)
- `tools/mutation_probe.php`: curated mutation probe (12 logic-weakening
  mutants over the security-critical code — CSRF, fail-closed limiter,
  login fallback scope, token entropy, sweep guards, log linkage, i18n
  escaping, session refresh, limiter purge, bucket window) that must all be
  killed by the suite; runs report-only in CI while the MSI baseline
  proves stable. Deliberately curated instead of infection/phpunit: the
  harness is custom, and destructive mutants (unlink bypass) are excluded
  by hand with reasons
- `tests/PhotoCapTest.php`: HTTP end-to-end for the photo cap (12 uploads
  leave exactly 10 rows)
- Operational follow-ups: `docs/TROUBLESHOOTING.md` is linked from the
  README; `uploads/.htaccess` is now force-tracked in git and re-included
  in `.dockerignore` (it was silently absent from Docker images and fresh
  clones, leaving the Apache variant without the uploads PHP-execution
  block)
- Automated formatting gate: `.php-cs-fixer.php` (conservative ruleset —
  whitespace, quotes, short arrays, strict-types; brace placement and line
  splitting deliberately out so the gate prevents drift without restyling
  history) enforced by a new CI `style` job running the version- and
  hash-pinned fixer phar in `--dry-run`
- Log tail-deletion detection (external review, verified): hash chains never
  caught pure tail truncation, so entries now carry a global monotonic `seq`
  (continues across rotation, backfilled by position for legacy tips) and the
  hourly cleanup pass anchors the tip in a new `log_checkpoints` table — a
  separate trust domain (db-data vs app-logs volume). `log_verify.php`
  reports a continuity verdict (`extends` / `truncated` / `rotated` /
  `none` / `error`) next to chain validity; `setup.sql` creates the table
  and is safe to re-run as the upgrade path
- Public unlock CSRF (external review, verified): the anonymous unlock form
  was the only state-affecting POST without a token, letting forged
  cross-site submits burn the victim's limiter budget and force reveals.
  The token is now verified before any budget is spent (both public forms
  embed it; rotation cannot desync a form re-rendered on every response)
- Session hardening: `use_strict_mode` / `use_only_cookies` /
  `use_trans_sid` set explicitly instead of trusting php.ini, and the
  pending TOTP secret + one-time enrollment note cross redirects sealed
  (TOTP subkey) rather than plaintext — the ADR-008 "ciphertext-only"
  wording is narrowed to the accurate "no plaintext secrets or credentials"
- Outbound response ceilings: `osm_fetch_via()` / `osm_fetch()` take a byte
  cap (default 2 MiB; 1 MiB tiles, 256 KiB geocode), enforced progressively
  via `CURLOPT_MAXFILESIZE` plus post-fetch length checks on every transport
  including the stream fallback and the direct discovery/IP-oracle reads
- Schema: `order_events(order_token)` and `rate_limits(window_start)`
  indexes (CREATE TABLE plus guarded ALTERs for existing installs, proven
  by strip-and-reload); CI loads the schema twice to prove the re-run
  no-op promise; `cache/` blocked from the web on all stacks (it was
  reachable, bypassing the tile auth gate) with CI 403 asserts;
  `docs/TROUBLESHOOTING.md` gains continuity-status and log-shipping notes
- README audited end to end: CSRF token size corrected (32 bytes, not 64),
  public-zone session reality, nginx/Caddy parity, PHP 8.2–8.5 matrix, new
  suites + mutation job listed, project tree updated, dead
  `SESSION_LIFETIME` knob removed from the template, cron recipe fixed to
  CLI (`cron/` is 403 from the web on every stack)
- Mutation probe grows to 16/16 killed (session ini, log seq, checkpoint
  write, continuity verdict); the probe itself caught a real test bug here
  (a stale anchor row letting a neutered writer pass)

### Changed
- Admin pages boot through a single service kernel
  (`includes/kernel.php`): the per-page 4–8 line require blocks (32 pages,
  169 lines) collapse to one require, and the service list lives in one
  manifest instead of being pasted across every entry script. Services stay
  plain functions with their own require guards, so tests, cron, and CLI
  entry points load them directly as before — zero behaviour change
- Kernel migration finished: the public pages (`index.php`, `receive.php`),
  `cron/cleanup.php`, the `tools/` one-shots, and `docker/e2e_journey.php`
  boot through the same manifest. `healthz.php` stays dependency-free on
  purpose (liveness must not depend on the stack it reports on), and the
  `KernelTest` header guard now covers all 40 entry points
- Thin admin dispatcher: the nine admin actions (`mark_delivered`,
  `order_close`, `order_remove`, `photo_delete`, `extend`, `save_setting`,
  `user_action`, `set_lang`, `logout`) run through one envelope
  (`admin/dispatch.php` + pure-data `admin/routes.php`) — headers, session,
  route-flag 2FA gate, method, auth, CSRF, ownership — while the legacy URLs
  stay as one-line shims, so bookmarks and forms keep working. The 2FA gate
  now consults the route's `2fa_exempt` flag instead of a script-basename
  allow-list, so shims and canonical URLs gate alike; handlers are
  moved-verbatim business logic guarded on their route name. Covered by
  `DispatchTest` (structural contract + HTTP shim/dispatch parity) and the
  `FailClosedTest` gate check, which now arms the route flag instead of a
  script name

## [1.3.0] - 2026-09-16

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

## [1.2.0] - 2026-09-16

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

### Fixed
- `count(glob(...))` TypeError on PHP 8+ when the uploads directory is
  unreadable during order deletion — glob failure now degrades to "not empty"
- Misleading bootstrap error: losing the named-lock race while the users
  table is still empty now says "busy, retry" instead of "already initialized"
- Expiry sweep is bounded (200 rows per pass, repeat while full) instead of
  loading every expired order into one process

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

## [1.1.0] - 2026-09-16

### Added
- Coverage climbs to ~88% overall across `includes/`: `net.php` hits 100%
  (CIDR/IP logic fully pinned), `cleanup.php` 89% (dice and sweep pass
  split into directly testable halves), `crypto.php` 93% (compressor reduce
  loops, undecodable-image and early-reject paths), `logger.php` 93%,
  `proxy.php` 63% (stub server doubles as a fake HTTP proxy for winner and
  judge paths). CI floors rise accordingly: 85% overall, per-file pins for
  net/logger/cleanup/proxy; the temporary `crypto.php` override is gone
- Five suites: `FailClosedTest` (fail-closed branches of guards, limiter,
  wipe, state machine, crypto, DB options), `I18nTest`, `LoggerTest`
  (chain integrity incl. forgery/truncation/legacy keys, audit, event log),
  `SettingsTest`, `ProxyClientTest` (outbound client vs local stub server);
  coverage floors raised to 85% per critical file and **80% overall**
- Coverage floors accept per-file overrides via
  `coverage_runner --min-file=name:pct`

### Changed
- `get_client_ip()` / `_ip_in_cidr()` moved from `config.php` to
  `includes/net.php` — hand-edited configs can no longer weaken proxy-header
  validation; config files stay constants-only
- Pseudo-cron cleanup gates its settings-table read behind a 1-in-100
  probability (tests pass an explicit chance); busy deployments should
  install real cron, which bypasses all gating. A lost die roll no longer
  consumes the process one-shot, and the dice (`_cleanup_roll`) plus the
  sweep pass (`_run_cleanup_pass`) are split out for direct testing
- `index.php` spends its rate-limit budget through one atomic check-and-
  consume (`rl_hit`) up front; non-failure outcomes refund the spend, so the
  budget keeps counting failed guesses while every decision stays race-free
- `includes/db.php`: TLS options extracted into the pure, unit-tested
  `db_options()` factory; connection into `db_connect()` — removes the last
  PHPStan environment-dependent suppression

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

## [1.0.0] - 2026-08-24

First tagged release: the security-hardened core, fully gated by CI.

### Added
- First-run owner creation through the UI (GET_LOCK guarded)
- Order analytics, OSM tile/geocode proxy pool with live anonymity judging
- `/healthz.php` liveness endpoint
- `tools/rotate_aes_key.php` — online key rotation with read-back
  verification

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

[Unreleased]: https://github.com/kilerdevs/DeadDropMGMT/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/kilerdevs/DeadDropMGMT/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/kilerdevs/DeadDropMGMT/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/kilerdevs/DeadDropMGMT/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/kilerdevs/DeadDropMGMT/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/kilerdevs/DeadDropMGMT/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kilerdevs/DeadDropMGMT/releases/tag/v1.0.0
