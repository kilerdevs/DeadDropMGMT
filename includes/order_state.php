<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';

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

// preparing → delivered. Returns false if the order was already delivered,
// deleted, or never existed — replaying is safe.
function order_deliver_atomic(int $id, int $ttl_hours): bool {
    try {
        $db   = get_db();
        $stmt = $db->prepare(
            'UPDATE orders
             SET status = "delivered", delivered_at = NOW(),
                 expires_at = DATE_ADD(NOW(), INTERVAL ? HOUR)
             WHERE id = ? AND status = "preparing"'
        );
        $stmt->execute([max(1, $ttl_hours), $id]);
        return $stmt->rowCount() > 0;
    } catch (Exception $e) {
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
            'SELECT id FROM orders WHERE order_token = ? AND status = "delivered" LIMIT 1 FOR UPDATE'
        );
        $stmt->execute([$token]);
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

        $db->commit();
        _unlink_order_files((int)$order['id'], $files);
        return true;
    } catch (Exception $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        log_err('Receive transition failed: ' . $e->getMessage());
        return false;
    }
}

// Admin close/remove → deleted, same guarantees as receiving but keyed by id.
// Returns [token, files] on success, null when nothing was deleted.
function order_delete_atomic(int $id): ?array {
    $db = get_db();
    $db->beginTransaction();
    try {
        $stmt = $db->prepare('SELECT order_token FROM orders WHERE id = ? LIMIT 1 FOR UPDATE');
        $stmt->execute([$id]);
        $token = $stmt->fetchColumn();
        if ($token === false || $token === null) {
            $db->rollBack();
            return null;
        }

        $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
        $photos->execute([$id]);
        $files = $photos->fetchAll(PDO::FETCH_COLUMN);

        $del = $db->prepare('DELETE FROM orders WHERE id = ?');
        $del->execute([$id]);
        if ($del->rowCount() !== 1) {
            $db->rollBack();
            return null;
        }

        $db->commit();
        _unlink_order_files($id, $files);
        return ['token' => (string)$token, 'files' => $files];
    } catch (Exception $e) {
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
function cleanup_expired_orders(): int {
    $db      = get_db();
    $expired = $db->query(
        'SELECT id FROM orders WHERE expires_at IS NOT NULL AND expires_at <= NOW()'
    )->fetchAll();

    $deleted = 0;
    foreach ($expired as $row) {
        $oid = (int)$row['id'];
        $db->beginTransaction();
        try {
            $lock = $db->prepare(
                'SELECT id FROM orders WHERE id = ? AND expires_at IS NOT NULL AND expires_at <= NOW() LIMIT 1 FOR UPDATE'
            );
            $lock->execute([$oid]);
            if (!$lock->fetch()) {
                $db->rollBack(); // someone else got it first — fine
                continue;
            }

            $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
            $photos->execute([$oid]);
            $files = $photos->fetchAll(PDO::FETCH_COLUMN);

            $db->prepare('DELETE FROM orders WHERE id = ?')->execute([$oid]);
            $db->commit();

            _unlink_order_files($oid, $files);
            log_err('Cleanup: deleted expired order #' . $oid);
            $deleted++;
        } catch (Exception $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            log_err('Cleanup error on order #' . $oid . ': ' . $e->getMessage());
        }
    }

    return $deleted;
}

// Best-effort filesystem sweep AFTER the DB rows are gone. Filenames come
// from our own DB column and are additionally pattern-checked before any
// unlink, so a tampered row can never point outside uploads/<id>/<hex>.<ext>.
function _unlink_order_files(int $order_id, array $files): void {
    foreach ($files as $fn) {
        if (is_string($fn) && preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $fn)) {
            overwrite_and_unlink(dirname(__DIR__) . '/uploads/' . $fn);
        }
    }
    $dir = dirname(__DIR__) . '/uploads/' . $order_id . '/';
    if (is_dir($dir) && count(glob($dir . '*')) === 0) {
        @rmdir($dir);
    }
}
