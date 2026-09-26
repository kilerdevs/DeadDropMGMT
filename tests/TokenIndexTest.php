<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Order tokens are HMAC-indexed, never stored in the clear (ADR-019) ────────
// Covers the primitives, what actually lands in the tables, the one-time
// migration from the plaintext schema, and master-key rotation.

$db = get_db();
$php = escapeshellarg(PHP_BINARY);
$tool = static fn(string $name): string => escapeshellarg(dirname(__DIR__) . '/tools/' . $name);

// ── Primitives ───────────────────────────────────────────────────────────────
$tok = 'TixTokenAbCd0123';
$idx = token_index($tok);
T::ok('index is 64 lowercase hex', preg_match('/^[0-9a-f]{64}$/', $idx) === 1);
T::eq('index is deterministic', $idx, token_index($tok));
T::eq('index ignores case (the old column compared case-insensitively)', $idx, token_index(strtoupper($tok)));
T::ok('different tokens, different index', $idx !== token_index('TixTokenAbCd0124'));
T::ok('index is keyed: not a plain hash of the token', $idx !== hash('sha256', strtolower($tok)));
T::ok('index does not use the raw master key',
    $idx !== hash_hmac('sha256', strtolower($tok), (string)hex2bin(AES_KEY_HEX)));
T::eq('no token, no index (null)', null, token_index_or_null(null));
T::eq('no token, no index (empty)', null, token_index_or_null(''));

$enc = encrypt_token($tok);
T::eq('display copy roundtrips', $tok, decrypt_token($enc['ciphertext'], $enc['iv']));
T::ok('display copy is fresh per call (random nonce)', encrypt_token($tok)['iv'] !== $enc['iv']);
T::ok('token blob refused by the TOTP subkey', decrypt_secret($enc['ciphertext'], $enc['iv']) === false);
T::ok('token blob refused by the flash subkey', decrypt_flash($enc['ciphertext'], $enc['iv']) === false);
T::ok('token blob refused by the location subkey', decrypt_location($enc['ciphertext'], $enc['iv']) === false);
$fl = encrypt_flash($tok);
T::ok('flash blob refused by the token subkey', decrypt_token($fl['ciphertext'], $fl['iv']) === false);
T::ok('non-hex IV rejected', decrypt_token($enc['ciphertext'], str_repeat('g', 24)) === false);

$cols = token_columns($tok);
T::eq('token_columns carries the index', $idx, $cols['token_hmac']);
T::eq('token_columns carries a readable copy', $tok, order_token_plain($cols));
T::eq('unreadable copy answers null', null, order_token_plain(['token_enc' => 'AAAA', 'token_iv' => str_repeat('0', 24)]));
T::eq('missing copy answers null', null, order_token_plain([]));
T::eq('label prefers the readable token', $tok, token_label($tok, $idx));
T::eq('label falls back to an index prefix', '#' . substr($idx, 0, 8), token_label(null, $idx));
T::eq('label with nothing at all', '—', token_label(null, null));

// ── What the tables hold ─────────────────────────────────────────────────────
purge_orders_like($db, 'Tix');
$db->exec("DELETE FROM audit_log WHERE action = 't_tix'");
$db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES (?, ?, ?, 'x', 'ZQ==', 'abababababababababababab', 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute(tk($tok));
$oid = (int)$db->lastInsertId();
set_setting('analytics_enabled', '1');
log_event('t_tix', $oid, $tok);
audit('t_tix', $oid, $tok);

$dump = static function (string $sql) use ($db): string {
    $out = [];
    foreach ($db->query($sql)->fetchAll(PDO::FETCH_NUM) as $r) {
        foreach ($r as $cell) { $out[] = (string)$cell; }
    }
    return implode("\n", $out);
};
foreach (['orders' => "SELECT * FROM orders WHERE id = $oid",
          'order_events' => "SELECT * FROM order_events WHERE event_type = 't_tix'",
          'audit_log' => "SELECT * FROM audit_log WHERE action = 't_tix'"] as $table => $sql) {
    $d = $dump($sql);
    T::ok("$table row exists", $d !== '');
    T::ok("$table holds no plaintext token", stripos($d, $tok) === false);
}
T::eq('event row carries the index', $idx,
    $db->query("SELECT token_hmac FROM order_events WHERE event_type = 't_tix' ORDER BY id DESC LIMIT 1")->fetchColumn());
T::eq('audit row carries the index', $idx,
    $db->query("SELECT token_hmac FROM audit_log WHERE action = 't_tix' ORDER BY id DESC LIMIT 1")->fetchColumn());

audit('t_tix', $oid, 'not-a-token');
T::eq('a value that is not token-shaped is not indexed', 1,
    (int)$db->query("SELECT COUNT(*) FROM audit_log WHERE action = 't_tix' AND token_hmac IS NULL")->fetchColumn());

// Lookup by index, in any case; a near miss finds nothing.
T::eq('lookup finds the order', $oid, order_id_for($db, $tok));
T::eq('lookup ignores case', $oid, order_id_for($db, strtolower($tok)));
T::eq('near-miss token finds nothing', null, order_id_for($db, 'TixTokenAbCd0124'));

// The state machine works through the index, and deleting takes the events along.
T::ok('receive by token deletes the order', order_receive_atomic($tok));
T::ok('order is gone', !order_row_exists($db, $tok));
T::eq('its events went with it', 0, event_count_for($db, $tok));
T::ok('receive again fails harmlessly', !order_receive_atomic($tok));

// Admin delete returns the readable token for its audit entry.
$db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv, status)
     VALUES (?, ?, ?, 'x', 'ZQ==', 'abababababababababababab', 'preparing')"
)->execute(tk('TixTokenDelete01'));
$delId = (int)$db->lastInsertId();
$res = order_delete_atomic($delId);
T::eq('admin delete hands back the readable token', 'TixTokenDelete01', $res['token'] ?? null);

// A row whose copy cannot be opened still deletes, with an empty token.
$db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv, status)
     VALUES (?, 'AAAA', ?, 'x', 'ZQ==', 'abababababababababababab', 'preparing')"
)->execute([token_index('TixTokenBroken01'), str_repeat('0', 24)]);
$brokenId = (int)$db->lastInsertId();
$res = order_delete_atomic($brokenId);
T::ok('unreadable copy: order still deletes', $res !== null && $res['token'] === '');

// Two orders cannot share an index.
purge_orders($db, ['TixTokenDup00001']);
$ins = $db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv)
     VALUES (?, ?, ?, 'x', 'ZQ==', 'abababababababababababab')"
);
$ins->execute(tk('TixTokenDup00001'));
$threw = false;
try { $ins->execute(tk('tixtokendup00001')); } catch (PDOException) { $threw = true; }
T::ok('the index is unique (case variants collide)', $threw);
purge_orders($db, ['TixTokenDup00001']);

// ── Migration from the plaintext schema ──────────────────────────────────────
// Rebuild the old shape (plaintext columns, some rows), run the tool, expect the
// columns to be gone and every token reachable through the index.
$addLegacy = static function () use ($db): void {
    // The old shape: orders had NOT NULL UNIQUE order_token (+ idx_token),
    // events and audit rows a nullable one.
    $has = static fn(string $t): bool => (int)$db->query("SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '$t' AND COLUMN_NAME = 'order_token'")->fetchColumn() > 0;
    if (!$has('orders')) {
        $db->exec('DELETE FROM orders');
        $db->exec('ALTER TABLE orders ADD COLUMN order_token CHAR(16) NOT NULL, ADD UNIQUE KEY order_token (order_token), ADD INDEX idx_token (order_token)');
    }
    foreach (['order_events', 'audit_log'] as $t) {
        if (!$has($t)) {
            $db->exec("ALTER TABLE $t ADD COLUMN order_token CHAR(16) DEFAULT NULL");
        }
    }
    // The documented upgrade order: load setup.sql first. It must relax the
    // NOT NULL so new-style inserts (and the tool's blanking) work.
    shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/schema_loader.php') . ' 2>&1');
};
$dropLegacy = static function () use ($db): void {
    foreach (['orders', 'order_events', 'audit_log'] as $t) {
        $has = (int)$db->query("SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '$t' AND COLUMN_NAME = 'order_token'")->fetchColumn();
        if ($has > 0) {
            $db->exec("ALTER TABLE $t DROP COLUMN order_token");
        }
    }
};

$dropLegacy(); // a crashed earlier run must not poison this one
$out = (string)shell_exec("$php " . $tool('migrate_order_tokens.php') . ' 2>&1');
T::ok('nothing to migrate on the current schema', str_contains($out, 'Nothing to do'));

$db->exec('DELETE FROM orders');
$db->exec("DELETE FROM order_events WHERE event_type LIKE 't\\_mig%'");
$db->exec("DELETE FROM audit_log WHERE action = 't_mig'");
$addLegacy();
$legacyIns = $db->prepare(
    "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status)
     VALUES (?, 'x', 'ZQ==', 'abababababababababababab', 'preparing')"
);
$legacyIns->execute(['MigTokenAAAA0001']); $mig1 = (int)$db->lastInsertId();
$legacyIns->execute(['MigTokenBBBB0002']); $mig2 = (int)$db->lastInsertId();
$db->prepare("INSERT INTO order_events (order_id, order_token, event_type, ip_address) VALUES (?, ?, 't_mig_ev', '198.51.100.1')")
   ->execute([$mig1, 'MigTokenAAAA0001']);
$db->prepare("INSERT INTO order_events (order_id, order_token, event_type, ip_address) VALUES (NULL, ?, 't_mig_ev', '198.51.100.1')")
   ->execute(['MigTokenUnknown1']);
$db->prepare("INSERT INTO audit_log (username, action, order_id, order_token, ip_address) VALUES ('t', 't_mig', ?, ?, '198.51.100.1')")
   ->execute([$mig2, 'MigTokenBBBB0002']);

T::eq('before migration the app cannot find a legacy order', null, order_id_for($db, 'MigTokenAAAA0001'));
T::eq('setup.sql relaxed the old NOT NULL so new orders can be inserted', 'YES', (string)$db->query(
    "SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()
     AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'order_token'")->fetchColumn());

$out = (string)shell_exec("$php " . $tool('migrate_order_tokens.php') . ' --dry-run 2>&1');
T::ok('dry run reports success', str_contains($out, 'Dry run OK'));
T::eq('dry run changes nothing', 2, (int)$db->query('SELECT COUNT(*) FROM orders WHERE order_token IS NOT NULL AND token_hmac IS NULL')->fetchColumn());

_warn_legacy_tokens(); // must answer (with a logged warning), not throw
T::ok('legacy warning does not throw', true);

$lines = []; $code = -1;
exec("$php " . $tool('migrate_order_tokens.php') . ' 2>&1', $lines, $code);
$out = implode("\n", $lines);
T::ok('migration reports success', str_contains($out, 'Done') && $code === 0);
foreach (['orders', 'order_events', 'audit_log'] as $t) {
    T::eq("$t.order_token is gone", 0, (int)$db->query("SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '$t' AND COLUMN_NAME = 'order_token'")->fetchColumn());
}
T::eq('migrated order is found through the index', $mig1, order_id_for($db, 'MigTokenAAAA0001'));
T::eq('the other one too', $mig2, order_id_for($db, 'migtokenbbbb0002'));
$row = $db->query("SELECT token_hmac, token_enc, token_iv FROM orders WHERE id = $mig1")->fetch();
T::eq('the display copy opens to the original token', 'MigTokenAAAA0001', order_token_plain($row));
T::eq('the linked event now carries the index', 1, event_count_for($db, 'MigTokenAAAA0001'));
T::eq('the token-only event was converted too', 1, event_count_for($db, 'MigTokenUnknown1'));
T::eq('the audit row was converted', token_index('MigTokenBBBB0002'),
    $db->query("SELECT token_hmac FROM audit_log WHERE action = 't_mig'")->fetchColumn());

$out = (string)shell_exec("$php " . $tool('migrate_order_tokens.php') . ' 2>&1');
T::ok('second run is a clean no-op', str_contains($out, 'Nothing to do'));

// A token that is not 16 alphanumerics aborts the whole run, changing nothing.
$addLegacy();
$db->exec("INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status)
           VALUES ('bad token!', 'x', 'ZQ==', 'abababababababababababab', 'preparing')");
$lines = []; $code = -1;
exec("$php " . $tool('migrate_order_tokens.php') . ' 2>&1', $lines, $code);
$out = implode("\n", $lines);
T::ok('a malformed legacy token aborts the migration', str_contains($out, 'ABORTED') && $code !== 0);
T::ok('the abort left the plaintext column in place', (int)$db->query(
    "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()
     AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'order_token'")->fetchColumn() === 1);
$db->exec("DELETE FROM orders WHERE order_token = 'bad token!'");

// --keep-legacy-columns blanks the plaintext but leaves the column.
$legacyIns->execute(['MigTokenKeep0003']);
$out = (string)shell_exec("$php " . $tool('migrate_order_tokens.php') . ' --keep-legacy-columns 2>&1');
T::ok('--keep-legacy-columns migrates', str_contains($out, 'Done'));
T::eq('…and keeps the (now empty) column', 0, (int)$db->query('SELECT COUNT(*) FROM orders WHERE order_token IS NOT NULL')->fetchColumn());
T::ok('…with the row reachable through the index', order_row_exists($db, 'MigTokenKeep0003'));
$dropLegacy();
$db->exec('DELETE FROM orders');
$db->exec("DELETE FROM order_events WHERE event_type LIKE 't\\_mig%'");
$db->exec("DELETE FROM audit_log WHERE action = 't_mig'");

// ── Master-key rotation re-indexes tokens ─────────────────────────────────────
$oldHex = AES_KEY_HEX;
$newHex = bin2hex(random_bytes(32));
$db->exec('DELETE FROM orders');
$db->exec('UPDATE users SET totp_secret_enc = NULL, totp_secret_iv = NULL WHERE totp_secret_enc IS NOT NULL');
$db->exec("DELETE FROM order_events WHERE event_type LIKE 't\\_rot%'");
$db->exec("DELETE FROM audit_log WHERE action = 't_rot'");

$enc = encrypt_location_data(['text' => 'rotation drop']);
$rotIns = $db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv, status)
     VALUES (?, ?, ?, 'x', ?, ?, 'preparing')"
);
$rotIns->execute([...tk('RotTokenAAAA0001'), $enc['ciphertext'], $enc['iv']]);
$rotId = (int)$db->lastInsertId();
$db->prepare("INSERT INTO order_events (order_id, token_hmac, event_type, ip_address) VALUES (?, ?, 't_rot_live', '198.51.100.2')")
   ->execute([$rotId, token_index('RotTokenAAAA0001')]);
$db->prepare("INSERT INTO order_events (order_id, token_hmac, event_type, ip_address) VALUES (NULL, ?, 't_rot_orphan', '198.51.100.2')")
   ->execute([token_index('RotTokenGone00001')]);
$db->prepare("INSERT INTO audit_log (username, action, order_id, token_hmac, ip_address) VALUES ('t', 't_rot', ?, ?, '198.51.100.2')")
   ->execute([$rotId, token_index('RotTokenAAAA0001')]);
$before = (string)$db->query("SELECT token_hmac FROM orders WHERE id = $rotId")->fetchColumn();

$rot = static function (string $from, string $to, string $extra = '') use ($php, $tool): array {
    $lines = []; $code = -1;
    exec("$php " . $tool('rotate_aes_key.php') . ' --old=' . escapeshellarg($from) . ' --new=' . escapeshellarg($to) . " $extra 2>&1", $lines, $code);
    return [implode("\n", $lines), $code];
};

[$out, $code] = $rot($oldHex, $newHex, '--dry-run');
T::ok('rotation dry run succeeds', str_contains($out, 'Dry run OK') && $code === 0);
T::eq('dry run leaves the index alone', $before, (string)$db->query("SELECT token_hmac FROM orders WHERE id = $rotId")->fetchColumn());

[$out, $code] = $rot($oldHex, $newHex);
T::ok('rotation succeeds', str_contains($out, 'Done') && $code === 0);
$after = (string)$db->query("SELECT token_hmac FROM orders WHERE id = $rotId")->fetchColumn();
T::ok('the index changed with the master key', $after !== $before && preg_match('/^[0-9a-f]{64}$/', $after) === 1);
T::eq('the live event followed the order to the new index', $after,
    (string)$db->query("SELECT token_hmac FROM order_events WHERE event_type = 't_rot_live'")->fetchColumn());
T::eq('the audit row followed too', $after,
    (string)$db->query("SELECT token_hmac FROM audit_log WHERE action = 't_rot'")->fetchColumn());
T::eq('an event whose order is gone loses its index', null,
    $db->query("SELECT token_hmac FROM order_events WHERE event_type = 't_rot_orphan'")->fetchColumn() ?: null);
T::ok('the app (still on the old key) can no longer find it — as expected', order_id_for($db, 'RotTokenAAAA0001') === null);

// Rotate back: everything lines up with the original key again.
[$out, $code] = $rot($newHex, $oldHex);
T::ok('rotation back succeeds', str_contains($out, 'Done') && $code === 0);
T::eq('original index restored', $before, (string)$db->query("SELECT token_hmac FROM orders WHERE id = $rotId")->fetchColumn());
T::eq('the token is reachable again', $rotId, order_id_for($db, 'RotTokenAAAA0001'));
$row = $db->query("SELECT token_hmac, token_enc, token_iv FROM orders WHERE id = $rotId")->fetch();
T::eq('and its display copy still opens', 'RotTokenAAAA0001', order_token_plain($row));
T::eq('the location survived both rotations', 'rotation drop', decrypt_location_data(
    (string)$db->query("SELECT location_encrypted FROM orders WHERE id = $rotId")->fetchColumn(),
    (string)$db->query("SELECT location_iv FROM orders WHERE id = $rotId")->fetchColumn())['text'] ?? null);

// Rotation refuses to run while plaintext token columns exist.
$addLegacy();
[$out, $code] = $rot($oldHex, $newHex, '--dry-run');
T::ok('rotation refuses while plaintext tokens exist', str_contains($out, 'migrate_order_tokens.php') && $code !== 0);
$dropLegacy();

$db->exec('DELETE FROM orders');
$db->exec("DELETE FROM order_events WHERE event_type LIKE 't\\_rot%' OR event_type = 't_tix'");
$db->exec("DELETE FROM audit_log WHERE action IN ('t_rot', 't_tix')");
exit(T::done());
