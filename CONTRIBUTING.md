<div align="center">

# Contributing to DeadDropMGMT

**Thanks for considering a contribution.** This project exists to demonstrate secure PHP application design in the open —
bug fixes, security hardening, documentation improvements and thoughtful features are all welcome.

[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat)](#pull-requests)
[![CI](https://github.com/kilerdevs/DeadDropMGMT/actions/workflows/ci.yml/badge.svg)](https://github.com/kilerdevs/DeadDropMGMT/actions/workflows/ci.yml)
[![Code of Conduct](https://img.shields.io/badge/code%20of%20conduct-Contributor%20Covenant%202.1-blueviolet?style=flat)](CODE_OF_CONDUCT.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat)](LICENSE)

</div>

---

## Contents

- [Before you start](#before-you-start)
- [Reporting a security vulnerability](#reporting-a-security-vulnerability)
- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Checks before you open a PR](#checks-before-you-open-a-pr)
- [Coding conventions](#coding-conventions)
- [Database changes](#database-changes)
- [Documentation](#documentation)
- [Pull requests](#pull-requests)
- [Code of conduct](#code-of-conduct)

---

## Before you start

Please read the [README](README.md) first, especially the **Disclaimer** and **Threat model** sections — this project was
built for educational purposes, and contributions are accepted under that same understanding. If you're not sure whether
an idea fits the project, open an issue to discuss it before writing code.

The project is [MIT licensed](LICENSE). By submitting a pull request, you agree your contribution is provided under the
same license.

---

## Reporting a security vulnerability

> [!CAUTION]
> **Please do not open a public issue for a security vulnerability.** This is a security-focused application; a public
> report gives potential attackers a head start before a fix ships.

Use GitHub's private reporting instead — the full policy, scope and response times are in [SECURITY.md](SECURITY.md):

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** to open a private security advisory.
3. Describe the issue, how to reproduce it, and its potential impact.

You'll get a response, and credit in the fix's changelog/commit if you'd like it. Ordinary bugs that aren't
security-sensitive (a broken layout, a wrong label, a logic error with no security impact) are fine as regular public
issues.

---

## Ways to contribute

| You want to… | Do this |
|---|---|
| **Fix a bug** — from a broken CSS class to a logic error | Open a [bug report](https://github.com/kilerdevs/DeadDropMGMT/issues/new?template=bug_report.yml), or go straight to a PR for small fixes |
| **Harden security** | Real vulnerabilities go through the [private channel](#reporting-a-security-vulnerability). Hardening *proposals* ("should we also rate-limit X?") are welcome as regular issues |
| **Improve the docs** | README, this file, `docs/`, or in-code comments where a non-obvious decision deserves one — see [Documentation](#documentation) |
| **Add a feature** | Open a [feature request](https://github.com/kilerdevs/DeadDropMGMT/issues/new?template=feature_request.yml) first for anything non-trivial. This project deliberately stays small and dependency-free; a feature that needs a framework or a runtime Composer dependency needs discussion before a PR, not after |
| **Translate** | The UI ships in eight languages (`includes/lang/`); fixes to wording are welcome — keep every language file's keys in sync |

---

## Development setup

Pick whichever path is quickest for you.

**Docker (fastest).** Builds the app and a MariaDB, loads `setup.sql` and starts on <http://localhost:2137>:

```bash
docker compose up -d --build
```

**Manual.** Follow the [Setup](README.md#setup) section in the README (PHP 8.2+, MySQL/MariaDB, Apache with
`mod_rewrite` / `mod_headers`). For quick iteration you can skip Apache and use PHP's built-in server — it doesn't enforce
`.htaccess` rules, so don't use it as your final check before opening a PR:

```bash
php -S localhost:8000
```

Then fork the repo, create a branch off `master`, make your change, and open a PR against `master`.

---

## Checks before you open a PR

CI runs all of this on every push and PR; run the relevant parts locally to fail faster.

| Check | Command | What CI enforces |
|---|---|---|
| Syntax | `php -l <file>` on every file you touched | lint on PHP 8.2 – 8.5 |
| PHP test suite | `php tests/schema_loader.php` (once, and after any `setup.sql` change) then `php tests/run_all.php` — must exit 0 | all suites on PHP 8.2 – 8.5, plus MySQL 8.0 |
| Static analysis | `php phpstan.phar analyse --no-progress` | PHPStan level 5 (`phpstan.neon`) |
| Code style | `php php-cs-fixer.phar fix --dry-run --diff` (drop `--dry-run` to apply) | PHP-CS-Fixer, read-only |
| Coverage | `composer install && php tests/coverage_runner.php` | ≥ 85 % overall and on every security-critical file, plus per-file pins (see the [README](README.md#coverage)) |
| Browser tests | `npm ci && npx playwright install chromium && npm run e2e` | Playwright specs in `e2e/tests/` |

The PHP suite never touches your real database: `tests/bootstrap.php` forces `deaddrops_test`. CI additionally builds and
smoke-tests all three Docker stacks, runs Semgrep, and runs a report-only [mutation probe](README.md#mutation-probe).

Beyond the automated gates:

- **Exercise the change for real.** Click through the affected flow in a browser against a real MySQL/MariaDB — a passing
  syntax check is not a test.
- **Write the test that would have caught it.** A new security guard needs a test that fails without it; a bug fix needs a
  regression test. Suites are plain scripts, see [`tests/`](tests/).
- **Touching `setup.sql`?** The suite's schema re-run already checks idempotence, but confirm locally by running the loader
  against a database that already has your change.
- **Touching `includes/`?** Watch the coverage job — regressions from the measured baseline fail the build.

---

## Coding conventions

This codebase is intentionally plain — procedural PHP, no framework, no runtime Composer. Match what's already there
(`.editorconfig` covers whitespace: UTF-8, LF, 4 spaces, no tabs).

**PHP**

- `declare(strict_types=1);` at the top of every PHP file.
- PDO prepared statements for every query — no string-interpolated SQL, ever.
- `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')` on every piece of user-derived output.
- `verify_csrf()` on every state-changing POST. New admin POST actions belong in the route table
  (`admin/routes.php` + `admin/actions/`) so headers, session, 2FA gate, method, auth, CSRF and ownership checks stay in one
  envelope (`admin/dispatch.php`) — `DispatchTest` pins the contract.
- Admin write actions call `audit()` (see `includes/audit.php`) so they show up in the audit log.
- POST → redirect → GET (PRG) for form submissions, to avoid resubmission on refresh.
- CLI-only scripts (`tools/`, `cron/`, test helpers) start with the `PHP_SAPI !== 'cli'` guard — `KernelTest` fails otherwise.
- Section comments use the existing `// ── Section ──...` divider style where a file is long enough to benefit from one —
  don't add them to short files.

**Front end**

- The CSP forbids inline scripts (other than nonce-bearing ones) and inline styles: no `onclick=` attributes, no `style=`
  attributes. Put behaviour in the `.js` files and styling in the `.css` files.
- User-visible text goes through `t('key')` and must exist in **all eight** language files under `includes/lang/` —
  `I18nTest` checks dictionary parity.

**Dependencies**

- No new Composer packages or JS frameworks. A new *vendored* client-side library (like Leaflet or QRCode.js) is fine if
  it's the actual, unmodified upstream source, kept as light as possible, and documented in the README's
  [Third-party code & external services](README.md#third-party-code--external-services) section and in
  [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

---

## Database changes

`setup.sql` is the **only** schema file, and it must stay safe to run against any starting state — a fresh empty database,
an existing install from any earlier version, or an already-current one. Don't add a separate migration file.

It uses a portable pattern that works on both MySQL and MariaDB (MySQL has no `ADD COLUMN IF NOT EXISTS`):

- Add new tables as `CREATE TABLE IF NOT EXISTS`.
- Add new columns with the `information_schema` guard + `PREPARE` / `EXECUTE` pattern already used throughout the file
  (count the column, then `ALTER TABLE ... ADD COLUMN` only when it is missing).
- Add new settings rows via the existing `INSERT ... ON DUPLICATE KEY UPDATE label = VALUES(label)` block.
- If you ever need a foreign key, name it explicitly and guard the `ALTER` the same way — see `fk_orders_created_by`.
- Test it: run the file against an empty database *and* against a database that already has your change applied. Both must
  succeed with no errors — on MariaDB and on MySQL 8.

---

## Documentation

- **README** — if your change alters behaviour, configuration, requirements or the project layout, update the README in the
  same PR; its claims are audited against the code.
- **CHANGELOG** — add a bullet under `## [Unreleased]` in the right section (Added / Changed / Fixed / Security), following
  [Keep a Changelog](https://keepachangelog.com/).
- **ADR** — a decision with trade-offs (crypto, auth, data model, deployment) gets a short record in
  [`docs/ADR.md`](docs/ADR.md): context, decision, consequences.
- **Troubleshooting** — a new failure mode an operator can hit belongs in [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
  as symptom → cause → fix.

---

## Pull requests

The [pull request template](.github/PULL_REQUEST_TEMPLATE.md) walks you through this; in short:

- Keep PRs focused — one logical change per PR is easier to review than five unrelated ones bundled together.
- Write commit messages that explain **why**, not just what changed (the diff already shows what): a short imperative subject
  line, then a body when the reason isn't obvious.
- Reference the issue number if there is one.
- Be ready to explain and adjust based on review feedback — this is a security-sensitive codebase, so scrutiny on anything
  touching auth, crypto or input handling should be expected.

---

## Code of conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). In short:
be respectful, and disagree on technical merits, not personalities. Conduct concerns can be reported privately — the
procedure is in the Code of Conduct.
