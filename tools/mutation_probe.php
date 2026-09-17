<?php
declare(strict_types=1);

// Entry-point rule (KernelTest): every tools/*.php boots through the kernel
// and pulls no service directly. The probe shells out to the suites and
// needs no services itself, but it honors the rule anyway — one line, and
// no exception mechanism to maintain or abuse.
require_once dirname(__DIR__) . '/includes/kernel.php';

// ── Curated mutation probe (report-only) ─────────────────────────────────────
// Line coverage cannot tell a tested guard from a dead one: this script
// applies a hand-picked set of logic-weakening mutants to the
// security-critical library code and checks that the existing suites FAIL
// without them (mutant KILLED) instead of staying green (SURVIVED — a real
// test gap). Run: php tools/mutation_probe.php
//
// Report-only by design: exit 0 unless the harness itself breaks (a mutant
// whose anchor text no longer matches means the code moved and the mutant
// needs maintenance — exit 2). CI runs this as a non-gating job and watches
// the score; gating (minimum MSI) only after the number proves stable.
//
// Mutants are CURATED, not generated, for two reasons:
//   1. The suites are a custom harness (no PHPUnit), so infection/phpunit
//      cannot drive them — and whole-suite-per-mutant runs stay in the
//      seconds range only because each mutant names one fast in-process
//      suite (no php -S suites here).
//   2. Equivalent or dangerous mutants are excluded BY HAND with a reason:
//      - unlink-path bypass (order_state): would overwrite REAL files —
//        excluded for safety, covered by review + the traversal test.
//      - token shortening: no fast killer (length is enforced at the HTTP
//        validators, covered by slow suites) — excluded, noted.
// Every mutant below must be killed; a SURVIVED line is a bug report
// against the test suite, not the application code.

$root = dirname(__DIR__);

// id, file, anchor (must occur exactly `count` times), weakened replacement,
// killer suite (fast, in-process), why it matters.
$mutants = [
    [
        'id'    => 'csrf-compare-removed',
        'file'  => 'includes/auth.php',
        'old'   => 'if (!hash_equals($_SESSION[\'csrf_token\'], $token)) {',
        'new'   => 'if (false) { // MUTANT: CSRF comparison removed',
        'suite' => 'CsrfTest',
        'why'   => 'any token accepted → cross-site state changes',
    ],
    [
        'id'    => 'csrf-rotation-removed',
        'file'  => 'includes/auth.php',
        'old'   => "    if (\$rotate) {\n        \$_SESSION['csrf_token'] = bin2hex(random_bytes(32));\n    }",
        'new'   => "    if (\$rotate) {\n        // MUTANT: rotation removed — tokens stay replayable\n    }",
        'suite' => 'CsrfTest',
        'why'   => 'stolen token replayable for further state changes',
    ],
    [
        'id'    => 'rate-status-fail-open',
        'file'  => 'includes/auth.php',
        'old'   => "log_err('Rate limit status failed (fail closed): ' . \$e->getMessage());\n        return ['blocked' => true, 'remaining' => \$window, 'count' => 0];",
        'new'   => "log_err('Rate limit status failed (fail closed): ' . \$e->getMessage());\n        return ['blocked' => false, 'remaining' => \$window, 'count' => 0]; // MUTANT: fail-open",
        'suite' => 'FailClosedTest',
        'why'   => 'limiter outage waves guessing traffic through',
    ],
    [
        'id'    => 'auth-fallback-guard-removed',
        'file'  => 'includes/auth.php',
        'old'   => 'if (_db_table_missing($e) && defined(\'ADMIN_USERNAME\') && defined(\'ADMIN_PASSWORD_HASH\') &&',
        'new'   => 'if (defined(\'ADMIN_USERNAME\') && defined(\'ADMIN_PASSWORD_HASH\') && // MUTANT: scope guard removed',
        'suite' => 'FailClosedTest',
        'why'   => 'any DB outage downgrades TOTP owners to password-only',
    ],
    [
        'id'    => 'auth-table-missing-always-true',
        'file'  => 'includes/auth.php',
        'old'   => 'return str_contains($msg, "doesn\'t exist") || str_contains($msg, \'no such table\');',
        'new'   => 'return true; // MUTANT: every DB error looks like a fresh install',
        'suite' => 'FailClosedTest',
        'why'   => 'same downgrade via the helper instead of the call site',
    ],
    [
        'id'    => 'token-alphabet-hex-only',
        'file'  => 'includes/crypto.php',
        'old'   => '$out .= $alphabet[random_int(0, 61)];',
        'new'   => '$out .= $alphabet[random_int(0, 15)]; // MUTANT: 95-bit token back to 64-bit hex',
        'suite' => 'CryptoTest',
        'why'   => 'capability-token entropy regression (B1 all over again)',
    ],
    [
        'id'    => 'cleanup-sweeps-preparing',
        'file'  => 'includes/order_state.php',
        // BOTH guards must fall: the candidate SELECT and the row lock
        // re-check the delivered status independently (defense in depth —
        // removing only one must NOT kill, which the probe verifies by
        // construction since a single-guard mutant would survive).
        'edits' => [
            [
                'old' => 'SELECT id FROM orders WHERE status = "delivered" AND expires_at IS NOT NULL',
                'new' => 'SELECT id FROM orders WHERE expires_at IS NOT NULL',
            ],
            [
                'old' => 'WHERE id = ? AND status = "delivered" AND expires_at IS NOT NULL',
                'new' => 'WHERE id = ? AND expires_at IS NOT NULL',
            ],
        ],
        'suite' => 'CleanupTest',
        'why'   => 'expiry sweep deletes undelivered orders',
    ],
    [
        'id'    => 'log-linkage-ignored',
        'file'  => 'includes/logger.php',
        'old'   => 'if (!hash_equals($prev, (string)$rec[\'prev\'])) {',
        'new'   => 'if (false) { // MUTANT: chain linkage unchecked',
        'suite' => 'LoggerTest',
        'why'   => 'reordered/deleted log entries verify clean',
    ],
    [
        'id'    => 'i18n-param-unescaped',
        'file'  => 'includes/i18n.php',
        'old'   => 'htmlspecialchars((string)$v, ENT_QUOTES, \'UTF-8\')',
        'new'   => '(string)$v // MUTANT: translation params unescaped',
        'suite' => 'I18nTest',
        'why'   => 'request data reflected unescaped (stored-XSS primitive)',
        'count' => 2,
        'all'   => true,
    ],
    [
        'id'    => 'session-refresh-removed',
        'file'  => 'includes/auth.php',
        'old'   => "    // revived by the very request that should kill it.\n    \$_SESSION['login_time'] = time();",
        'new'   => '    // MUTANT: sliding window removed — absolute-since-login timeout',
        'suite' => 'FailClosedTest',
        'why'   => 'idle sessions outlive the inactivity promise',
    ],
    [
        'id'    => 'rate-purge-skipped',
        'file'  => 'includes/cleanup.php',
        'old'   => '    _purge_stale_rate_limits();',
        'new'   => '    // MUTANT: stale rate-limit rows never swept',
        'suite' => 'CleanupTest',
        'why'   => 'rate_limits bloats forever (B7 all over again)',
    ],
    [
        'id'    => 'bucket-window-hardcoded',
        'file'  => 'includes/auth.php',
        'old'   => 'rl_window_seconds()',
        'new'   => '900 // MUTANT: bucket ignores the configured window',
        'suite' => 'FailClosedTest',
        'why'   => 'retuning the limiter silently diverges the two layers',
        'count' => 5,
        'all'   => true,
    ],
];

/** @var array<string,string> $backups path => original content, restored on shutdown */
$backups = [];
register_shutdown_function(static function () use (&$backups): void {
    foreach ($backups as $file => $content) {
        @file_put_contents($file, $content);
    }
});

// A mutant may need several coordinated edits (e.g. two independent guards
// for the same invariant — removing one must NOT kill, removing both must).
// Each edit carries its own anchor; 'all' replaces every occurrence.
$killed = [];
$survived = [];
$harnessErrors = [];

foreach ($mutants as $m) {
    $path = $root . '/' . $m['file'];
    $src = @file_get_contents($path);
    if (!is_string($src)) {
        $harnessErrors[] = $m['id'] . ': cannot read ' . $m['file'];
        continue;
    }
    // Anchor text below is authored with LF; the tree may check out CRLF —
    // match on normalized text and restore the original EOL on write.
    $eol = str_contains($src, "\r\n") ? "\r\n" : "\n";
    $norm = str_replace("\r\n", "\n", $src);
    $edits = $m['edits'] ?? [['old' => $m['old'], 'new' => $m['new'], 'count' => $m['count'] ?? 1, 'all' => $m['all'] ?? false]];
    $ok = true;
    foreach ($edits as $e) {
        $need = $e['count'] ?? 1;
        $found = substr_count($norm, $e['old']);
        if ($found !== $need) {
            $harnessErrors[] = $m['id'] . ": anchor found $found time(s), expected $need — code moved, mutant needs maintenance";
            $ok = false;
            break;
        }
        $norm = ($e['all'] ?? false)
            ? str_replace($e['old'], $e['new'], $norm)
            : preg_replace('/' . preg_quote($e['old'], '/') . '/', addcslashes($e['new'], '\\$'), $norm, 1);
    }
    if (!$ok) {
        continue;
    }
    if (!isset($backups[$path])) {
        $backups[$path] = $src;
    }
    file_put_contents($path, $eol === "\n" ? $norm : str_replace("\n", "\r\n", $norm));
    $t0 = microtime(true);
    $out = [];
    $code = 0;
    exec(
        escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/tests/' . $m['suite'] . '.php') . ' 2>&1',
        $out,
        $code
    );
    $dt = round(microtime(true) - $t0, 1);
    file_put_contents($path, $src);
    unset($backups[$path]);
    if ($code !== 0) {
        $killed[] = $m['id'] . " ({$dt}s)";
    } else {
        $survived[] = $m['id'] . ' — ' . $m['why'];
    }
}

$total = count($killed) + count($survived);
$msi = $total > 0 ? round(100 * count($killed) / $total, 1) : 0.0;
echo 'Mutation probe: ' . count($killed) . "/$total killed (MSI {$msi}%)\n";
foreach ($killed as $k) {
    echo "  KILLED   $k\n";
}
foreach ($survived as $s) {
    echo "  SURVIVED $s\n";
}
foreach ($harnessErrors as $e) {
    echo "  HARNESS  $e\n";
}
exit($harnessErrors !== [] ? 2 : 0);
