<!--
Thanks for contributing! Fill in what applies and delete the rest.
Security vulnerability? Do NOT describe it here — use private reporting:
https://github.com/kilerdevs/DeadDropMGMT/security/advisories/new
-->

## Summary

<!-- What does this change, in a sentence or two? -->

## Why

<!-- The problem or motivation. Link the issue: Closes #123 -->

## Type of change

- [ ] Bug fix
- [ ] Security hardening
- [ ] New feature
- [ ] Refactor / cleanup (no behavior change)
- [ ] Documentation only
- [ ] Tests / CI / tooling

## How was this tested?

<!-- Commands you ran and what you clicked through. A passing syntax check is not enough. -->

- [ ] `php tests/schema_loader.php && php tests/run_all.php` passes
- [ ] Added or updated a test that fails without this change
- [ ] PHPStan (`php phpstan.phar analyse`) and PHP-CS-Fixer (`--dry-run --diff`) are clean
- [ ] Exercised the affected flow in a browser against a real MySQL/MariaDB
- [ ] Playwright specs pass (`npm run e2e`), if UI behavior changed

## Security checklist

<!-- Tick what applies; explain anything you skipped. -->

- [ ] No string-interpolated SQL — prepared statements only
- [ ] All user-derived output is escaped (`htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` or `t()`)
- [ ] State-changing POSTs verify CSRF and go through the admin dispatcher where applicable
- [ ] Admin write actions call `audit()`
- [ ] No new secrets, tokens or personal data are logged, stored in the clear or sent to third parties
- [ ] No inline scripts or `style=` attributes (the CSP forbids them)
- [ ] No new runtime dependency (Composer package or JS framework)
- [ ] Not applicable — this change does not touch auth, crypto, input handling or data storage

## Documentation

- [ ] README updated if behavior, configuration or requirements changed
- [ ] `CHANGELOG.md` entry added under **Unreleased**
- [ ] `docs/ADR.md` / `docs/TROUBLESHOOTING.md` updated if a decision or failure mode is new
- [ ] New UI text exists in all eight `includes/lang/` files
- [ ] `setup.sql` changes are idempotent (ran against an empty **and** an already-migrated database)

## Screenshots

<!-- UI changes: before / after. Redact any real data. -->

## Notes for the reviewer

<!-- Trade-offs, follow-ups, anything that deserves extra scrutiny. -->
