# Contributing to DeadDropMGMT

**Thanks for considering a contribution.** This project exists to demonstrate secure PHP application design in the open — bug fixes, security hardening, documentation improvements, and thoughtful feature additions are all welcome.

---

## Contents

- [Before You Start](#before-you-start)
- [Reporting a Security Vulnerability](#reporting-a-security-vulnerability)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Coding Conventions](#coding-conventions)
- [Database Changes](#database-changes)
- [Commit & Pull Request Guidelines](#commit--pull-request-guidelines)
- [Code of Conduct](#code-of-conduct)

---

## Before You Start

Please read the [README](README.md) first, especially the **Disclaimer** and **Security Model** sections — this project was built for educational purposes, and contributions are accepted under that same understanding. If you're not sure whether an idea fits the project, open an issue to discuss it before writing code.

The project is [MIT licensed](LICENSE). By submitting a pull request, you agree your contribution is provided under the same license.

---

## Reporting a Security Vulnerability

**Please do not open a public issue for a security vulnerability.** This is a security-focused application; a public report gives potential attackers a head start before a fix ships.

Instead, use GitHub's private reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** to open a private security advisory.
3. Describe the issue, how to reproduce it, and its potential impact.

You'll get a response, and credit in the fix's changelog/commit if you'd like it. Ordinary bugs that aren't security-sensitive (a broken layout, a wrong label, a logic error with no security impact) are fine as regular public issues.

---

## Ways to Contribute

- **Bug fixes** — anything from a broken CSS class to a logic error.
- **Security hardening** — see the reporting process above for actual vulnerabilities; hardening *proposals* (e.g. "should we also rate-limit X?") are welcome as regular issues.
- **Documentation** — the README, this file, or in-code comments where a non-obvious decision deserves one.
- **Features** — open an issue first for anything non-trivial. This project deliberately stays small and dependency-free; a feature that requires a framework or a Composer dependency needs discussion before a PR, not after.

---

## Development Setup

1. Follow the [Setup](README.md#setup) section in the README to get a local instance running (PHP 8.2+, MySQL/MariaDB, Apache with `mod_rewrite`/`mod_headers`).
2. For quick iteration you can skip Apache and use PHP's built-in server instead — it doesn't enforce `.htaccess` rules, so don't use it as your final check before opening a PR:
   ```bash
   php -S localhost:8000
   ```
3. Fork the repo, create a branch off `master`, make your change, and open a PR against `master`.

There **is** an automated test suite now, and CI runs it on every push and PR (PHP 8.2–8.4 + MySQL matrix, coverage floors, PHPStan, Docker smoke tests, Semgrep). Before opening a PR:

- Run the suite against an isolated test database — it never touches your real one (`tests/bootstrap.php` forces `deaddrops_test`):
  ```bash
  php tests/schema_loader.php   # once, and after any setup.sql change
  php tests/run_all.php         # must exit 0
  ```
- Run `php -l` on every file you touched (CI lints too, but fail faster locally).
- Actually exercise the change against a real MySQL/MariaDB instance — click through the affected flow in a browser, not just a syntax check.
- If you touched `setup.sql`, the suite's schema re-run (StateTransitionTest) already checks idempotence — but confirm locally as well: run the loader against a database that already has the schema.
- If your change touches `includes/`, watch the coverage job: overall `includes/` coverage must stay ≥ 80% and every security-critical file ≥ 90% (`tests/coverage_runner.php --min-overall=80 --min-critical=90`).

---

## Coding Conventions

This codebase is intentionally plain — procedural PHP, no framework, no Composer. Match what's already there:

- `declare(strict_types=1);` at the top of every PHP file.
- 4-space indentation, no tabs.
- PDO prepared statements for every query — no string-interpolated SQL, ever.
- `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')` on every piece of user-derived output.
- CSRF token (`verify_csrf()`) checked on every state-changing POST.
- Admin write actions call `audit()` (see `includes/audit.php`) so they show up in the audit log.
- POST → redirect → GET (PRG) for admin form submissions, to avoid resubmission on refresh.
- Section comments use the existing `// ── Section ──...` divider style where a file is long enough to benefit from one — don't add them to short files.
- No new Composer packages or JS frameworks. A new *vendored* client-side library (like Leaflet or QRCode.js) is fine if it's the actual, unmodified upstream source, kept as light as possible, and documented in the README's [Third-Party Code & External Services](README.md#third-party-code--external-services) section.

---

## Database Changes

`setup.sql` is the **only** schema file, and it must stay safe to run against any starting state — a fresh empty database, an existing install from any earlier version, or an already-current one. Don't add a separate migration file.

If your change touches the schema:
- Add new tables as `CREATE TABLE IF NOT EXISTS`.
- Add new columns as `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (MariaDB supports this; it's what the file already uses throughout).
- Add new settings rows via the existing `INSERT ... ON DUPLICATE KEY UPDATE label = VALUES(label)` block.
- If you ever need a foreign key, name it explicitly and note that MariaDB has **no** `ADD CONSTRAINT IF NOT EXISTS` — see the guarded `PREPARE`/`EXECUTE` pattern already in `setup.sql` for `fk_orders_created_by` and follow the same approach.
- Test it: run the file against an empty database *and* against a database that already has your change applied. Both must succeed with no errors.

---

## Commit & Pull Request Guidelines

- Keep PRs focused — one logical change per PR is easier to review than five unrelated ones bundled together.
- Write commit messages that explain **why**, not just what changed (the diff already shows what).
- Reference the issue number if there is one.
- Be ready to explain and adjust based on review feedback — this is a security-sensitive codebase, so scrutiny on anything touching auth, crypto, or input handling should be expected.

---

## Code of Conduct

Be respectful. Disagree on technical merits, not personalities. Reports of abusive behavior can go through the same private security-advisory channel described above if you'd rather not raise it publicly.
