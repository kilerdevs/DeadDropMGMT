<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// ── One-time migration: plaintext order tokens → HMAC index (ADR-019) ─────────
// Older versions kept every order token in the clear (orders.order_token, and
// order_events / audit_log rows that referenced it). The runtime now looks
// tokens up through a keyed index (token_hmac) and keeps an AES-GCM copy on
// the order only for the admin panel. This tool moves the old values across
// and then DROPS the plaintext columns.
//
// Order of operations on an existing install:
//   1. back up the database (dropping the columns cannot be undone)
//   2. load the current setup.sql (adds the new columns, idempotent)
//   3. php tools/migrate_order_tokens.php --dry-run
//   4. php tools/migrate_order_tokens.php
//
// Until step 4 completes, orders created before the upgrade are unreachable
// by the app (new orders work); the hourly cleanup logs a warning naming this
// tool. Idempotent: with no plaintext column left it reports "nothing to do",
// and a half-finished earlier run is simply continued. Everything is one
// transaction — any failure changes nothing.
//
// Usage:  php tools/migrate_order_tokens.php [--dry-run] [--keep-legacy-columns]
//   --keep-legacy-columns  empty the plaintext columns but do not drop them

$options = getopt('', ['dry-run', 'keep-legacy-columns']);
$dry     = isset($options['dry-run']);
$keep    = isset($options['keep-legacy-columns']);

require_once dirname(__DIR__) . '/includes/kernel.php';

if (!aes_key_valid()) {
    fwrite(STDERR, aes_key_problem() . "\n");
    exit(1);
}

$db = get_db();

$has = static function (string $table, string $column) use ($db): bool {
    $st = $db->prepare(
        'SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?'
    );
    $st->execute([$table, $column]);
    return (int)$st->fetchColumn() > 0;
};

foreach ([['orders', 'token_hmac'], ['orders', 'token_enc'], ['orders', 'token_iv'],
          ['order_events', 'token_hmac'], ['audit_log', 'token_hmac']] as [$t, $c]) {
    if (!$has($t, $c)) {
        fwrite(STDERR, "Column $t.$c is missing — load the current setup.sql first (it is idempotent).\n");
        exit(1);
    }
}

$legacy = [];
foreach (['orders', 'order_events', 'audit_log'] as $t) {
    if ($has($t, 'order_token')) {
        $legacy[] = $t;
    }
}
if ($legacy === []) {
    echo "Nothing to do: no plaintext order_token column is left.\n";
    exit(0);
}

$db->beginTransaction();
$failed = 0;
$counts = ['orders' => 0, 'order_events' => 0, 'audit_log' => 0];

try {
    // ── orders: index + encrypted copy, plaintext blanked ──────────────────────
    if (in_array('orders', $legacy, true)) {
        $rows = $db->query('SELECT id, order_token, token_hmac FROM orders WHERE order_token IS NOT NULL')->fetchAll();
        $upd  = $db->prepare(
            'UPDATE orders SET token_hmac = ?, token_enc = ?, token_iv = ?, order_token = NULL WHERE id = ?'
        );
        $blank = $db->prepare('UPDATE orders SET order_token = NULL WHERE id = ?');
        foreach ($rows as $r) {
            $token = (string)$r['order_token'];
            if (preg_match('/^[0-9A-Za-z]{16}$/', $token) !== 1) {
                fwrite(STDERR, sprintf("FAIL orders#%d: token is not 16 alphanumeric characters — aborting\n", $r['id']));
                $failed++;
                continue;
            }
            $cols = token_columns($token);
            if ($r['token_hmac'] !== null) {
                // A previous run got this far: only the leftover plaintext remains,
                // and it must agree with the index already stored.
                if (!hash_equals((string)$r['token_hmac'], $cols['token_hmac'])) {
                    fwrite(STDERR, sprintf("FAIL orders#%d: stored index disagrees with the plaintext token — aborting\n", $r['id']));
                    $failed++;
                    continue;
                }
                $blank->execute([$r['id']]);
            } else {
                $upd->execute([$cols['token_hmac'], $cols['token_enc'], $cols['token_iv'], $r['id']]);
                // Read-back: the stored copy must open to the same token.
                $chk = $db->prepare('SELECT token_hmac, token_enc, token_iv FROM orders WHERE id = ?');
                $chk->execute([$r['id']]);
                $cur = $chk->fetch();
                if (!is_array($cur) || order_token_plain($cur) !== $token || $cur['token_hmac'] !== token_index($token)) {
                    fwrite(STDERR, sprintf("FAIL orders#%d: read-back verification failed\n", $r['id']));
                    $failed++;
                    continue;
                }
            }
            $counts['orders']++;
        }
    }

    // ── order_events: one UPDATE per distinct token (idx_order_token) ──────────
    if (in_array('order_events', $legacy, true)) {
        $tokens = $db->query('SELECT DISTINCT order_token FROM order_events WHERE order_token IS NOT NULL')
                     ->fetchAll(PDO::FETCH_COLUMN);
        $upd = $db->prepare('UPDATE order_events SET token_hmac = ?, order_token = NULL WHERE order_token = ?');
        foreach ($tokens as $token) {
            $upd->execute([token_index((string)$token), $token]);
            $counts['order_events'] += $upd->rowCount();
        }
    }

    // ── audit_log: by primary key (no index on the legacy column) ──────────────
    if (in_array('audit_log', $legacy, true)) {
        $rows = $db->query('SELECT id, order_token FROM audit_log WHERE order_token IS NOT NULL')->fetchAll();
        $upd  = $db->prepare('UPDATE audit_log SET token_hmac = ?, order_token = NULL WHERE id = ?');
        foreach ($rows as $r) {
            $upd->execute([token_index((string)$r['order_token']), $r['id']]);
            $counts['audit_log']++;
        }
    }

    // Nothing plaintext may survive in any legacy column.
    foreach ($legacy as $t) {
        $left = (int)$db->query("SELECT COUNT(*) FROM $t WHERE order_token IS NOT NULL")->fetchColumn();
        if ($left > 0) {
            fwrite(STDERR, "FAIL $t: $left plaintext value(s) still present after the pass\n");
            $failed++;
        }
    }
} catch (Throwable $e) {
    $failed++;
    fwrite(STDERR, 'ERROR: ' . $e->getMessage() . "\n");
}

if ($failed > 0) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    fwrite(STDERR, "\nABORTED: $failed problem(s) — transaction rolled back, nothing changed.\n");
    exit(1);
}

foreach ($counts as $t => $n) {
    printf("%s %-13s %d row(s)\n", $dry ? '[dry-run]' : 'migrated ', $t, $n);
}

if ($dry) {
    $db->rollBack();
    echo "\nDry run OK. Re-run without --dry-run to apply (back up the database first).\n";
    exit(0);
}
$db->commit();

// DDL commits implicitly, so it runs after the data is safely committed.
if (!$keep) {
    foreach ($legacy as $t) {
        $db->exec("ALTER TABLE $t DROP COLUMN order_token");
        echo "dropped   $t.order_token\n";
    }
}

echo "\nDone. Plaintext tokens are no longer stored in the database.\n";
echo "Older database dumps and backups still contain them — delete or re-create those.\n";
