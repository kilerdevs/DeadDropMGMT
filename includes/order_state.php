<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/crypto.php';

// ── Atomic order state machine ────────────────────────────────────────────────
// Single source of truth for every destructive state change:
//
//     preparing ──deliver──> delivered ──receive/close/expiry──> deleted
//
// Every function here uses conditional UPDATE/DELETE + affected-row checks or
// row locks (SELECT ... FOR UPDATE) inside a transaction, so concurrent
// requests can never double-execute a transition and invalid/replayed ones
// are harmless no-ops. File deletion happens AFTER the DB transaction commits:
// the database is authoritative, and an orphaned file is merely cosmetic —
// never an order that vanished while its row survived.

// An order whose lifetime has run out is gone as far as recipients are
// concerned, whether or not the cleanup sweep has physically deleted the row
// yet (the sweep is periodic — this predicate makes expiry exact). Preparing
// orders carry no expiry and stay live. Public lookups, unlocks and receipt
// confirmation all filter through it.
const ORDER_LIVE_SQL = '(expires_at IS NULL OR expires_at > NOW())';

// preparing → delivered. Returns false if the order was already delivered,
// deleted, or never existed — replaying is safe. TTL is clamped to 1–720 h
// like the admin UI: an unbounded value overflows DATE_ADD and fails.
function order_deliver_atomic(int $id, int $ttl_hours): bool {
    try {
        $db   = get_db();
        $stmt = $db->prepare(
            'UPDATE orders
             SET status = "delivered", delivered_at = NOW(),
                 expires_at = DATE_ADD(NOW(), INTERVAL ? HOUR)
             WHERE id = ? AND status = "preparing"'
        );
        $stmt->execute([min(720, max(1, $ttl_hours)), $id]);
        return $stmt->rowCount() > 0;
    } catch (Throwable $e) {
        log_err('Deliver transition failed: ' . $e->getMessage());
        return false;
    }
}

// delivered → received (row deleted). The whole destructive step is one
// transaction guarded by both the token and the terminal state, so a valid
// token alone can NOT receive an order that was never delivered, and a
// second receipt finds no row and fails harmlessly. Photo filenames are read
// under the row lock and unlinked only after commit.
function order_receive_atomic(string $token): bool {
    $db = get_db();
    $db->beginTransaction();
    try {
        $stmt = $db->prepare(
            'SELECT id FROM orders WHERE token_hmac = ? AND status = "delivered" LIMIT 1 FOR UPDATE'
        );
        $index = token_index($token);
        $stmt->execute([$index]);
        $order = $stmt->fetch();

        if (!$order) {
            $db->rollBack();
            return false;
        }

        $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
        $photos->execute([(int)$order['id']]);
        $files = $photos->fetchAll(PDO::FETCH_COLUMN);

        $del = $db->prepare('DELETE FROM orders WHERE id = ? AND status = "delivered"');
        $del->execute([(int)$order['id']]);
        if ($del->rowCount() !== 1) {
            $db->rollBack();
            return false;
        }
        _delete_order_events($db, (int)$order['id'], $index);

        $db->commit();
        _unlink_order_files((int)$order['id'], $files);
        return true;
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        log_err('Receive transition failed: ' . $e->getMessage());
        return false;
    }
}

// Admin close/remove → deleted, same guarantees as receiving but keyed by id.
// Returns [token, files] on success, null when nothing was deleted. The
// token is the plaintext display copy ('' if it cannot be opened): callers
// use it for their audit entry, which re-indexes it.
function order_delete_atomic(int $id): ?array {
    $db = get_db();
    $db->beginTransaction();
    try {
        $stmt = $db->prepare('SELECT token_hmac, token_enc, token_iv FROM orders WHERE id = ? LIMIT 1 FOR UPDATE');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) {
            $db->rollBack();
            return null;
        }
        $index = is_string($row['token_hmac'] ?? null) ? $row['token_hmac'] : null;
        $token = order_token_plain($row) ?? '';

        $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
        $photos->execute([$id]);
        $files = $photos->fetchAll(PDO::FETCH_COLUMN);

        $del = $db->prepare('DELETE FROM orders WHERE id = ?');
        $del->execute([$id]);
        if ($del->rowCount() !== 1) {
            $db->rollBack();
            return null;
        }
        _delete_order_events($db, $id, $index);

        $db->commit();
        _unlink_order_files($id, $files);
        return ['token' => $token, 'files' => $files];
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        log_err('Delete transition failed: ' . $e->getMessage());
        return null;
    }
}

// Expired → deleted, per order, under a row lock so cleanup can safely run
// concurrently with itself, with receiving, or with revealing. Idempotent:
// re-running deletes nothing extra and never resurrects partial failures.
// Bounded: one pass handles at most $batch rows (default 200), then the
// caller repeats while the previous pass was full — a backlog after days
// without cron stays a series of small transactions instead of one giant
// SELECT + unbounded loop that max_execution_time kills halfway.
function cleanup_expired_orders(int $batch = 200): int {
    $db      = get_db();
    $deleted = 0;
    do {
        // Defense in depth: only delivered orders expire. Expiry is armed by
        // delivery (and guarded extension); a preparing row must never be
        // swept even if an expires_at leaked onto it.
        $expired = $db->query(
            'SELECT id FROM orders WHERE status = "delivered" AND expires_at IS NOT NULL AND expires_at <= NOW() LIMIT ' . max(1, $batch)
        )->fetchAll();

        foreach ($expired as $row) {
            $oid = (int)$row['id'];
            $db->beginTransaction();
            try {
                $lock = $db->prepare(
                    'SELECT id, token_hmac FROM orders WHERE id = ? AND status = "delivered" AND expires_at IS NOT NULL AND expires_at <= NOW() LIMIT 1 FOR UPDATE'
                );
                $lock->execute([$oid]);
                $locked = $lock->fetch();
                if (!$locked) {
                    $db->rollBack(); // someone else got it first — fine
                    continue;
                }

                $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
                $photos->execute([$oid]);
                $files = $photos->fetchAll(PDO::FETCH_COLUMN);

                $db->prepare('DELETE FROM orders WHERE id = ?')->execute([$oid]);
                _delete_order_events($db, $oid, is_string($locked['token_hmac'] ?? null) ? $locked['token_hmac'] : null);
                $db->commit();

                _unlink_order_files($oid, $files);
                log_info('cleanup_deleted', ['msg' => 'Cleanup: deleted expired order #' . $oid]);
                $deleted++;
            } catch (Throwable $e) {
                if ($db->inTransaction()) {
                    $db->rollBack();
                }
                log_err('Cleanup error on order #' . $oid . ': ' . $e->getMessage());
            }
        }
    } while (count($expired) === max(1, $batch));

    return $deleted;
}

// The order's own event rows die with it, in the same transaction: lookup /
// unlock / reveal probes carry IPs and user agents, and keeping them after
// the order is gone is a privacy liability with no operational value. Both
// keys are matched — analytics rows sometimes carry only the token index (no
// id). $token_index is the order's token_hmac, never the token itself.
// A flow's own post-delete log_event() (e.g. 'received') lands AFTERWARDS,
// so the deletion itself stays on record as a single terminal row.
function _delete_order_events(PDO $db, int $order_id, ?string $token_index): void {
    $db->prepare('DELETE FROM order_events WHERE order_id = ? OR token_hmac = ?')
       ->execute([$order_id, $token_index]);
}

// Best-effort filesystem sweep AFTER the DB rows are gone. Filenames come
// from our own DB column and are additionally pattern-checked before any
// unlink, so a tampered row can never point outside uploads/<id>/<hex>.<ext>.
function _unlink_order_files(int $order_id, array $files): void {
    $base = dirname(__DIR__) . '/uploads/';
    foreach ($files as $fn) {
        if (is_string($fn) && preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $fn)) {
            overwrite_and_unlink($base . $fn);
            // The DB row is already gone (commit-then-sweep, by design), so a
            // file that survives the sweep would sit orphaned forever with no
            // row pointing at it — log it so the next admin log review shows
            // a stub filename to remove by hand.
            if (is_file($base . $fn)) {
                log_err("Orphaned photo after order {$order_id} delete: {$fn}");
            }
        }
    }
    $dir = dirname(__DIR__) . '/uploads/' . $order_id . '/';
    // glob_list(): a bare glob() answers false on unreadable dirs, and
    // count(false) is a TypeError on PHP 8+, crashing the whole deletion.
    if (is_dir($dir) && count(glob_list($dir . '*')) === 0) {
        @rmdir($dir);
    }
}
