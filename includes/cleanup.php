<?php
declare(strict_types=1);

// Core deletion logic — single source of truth used by both pseudo-cron and CLI cron.
function do_cleanup(): int {
    $db      = get_db();
    $expired = $db->query(
        "SELECT id FROM orders WHERE expires_at IS NOT NULL AND expires_at <= NOW()"
    )->fetchAll();

    $deleted = 0;
    foreach ($expired as $row) {
        $oid = (int)$row['id'];

        $pq = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
        $pq->execute([$oid]);
        foreach ($pq->fetchAll() as $ph) {
            if (preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $ph['filename'])) {
                secure_unlink(dirname(__DIR__) . '/uploads/' . $ph['filename']);
            }
        }

        $dir = dirname(__DIR__) . '/uploads/' . $oid . '/';
        if (is_dir($dir)) {
            @rmdir($dir);
        }

        $db->prepare('DELETE FROM orders WHERE id = ?')->execute([$oid]);
        log_err('Cleanup: deleted expired order #' . $oid);
        $deleted++;
    }

    return $deleted;
}

// Pseudo-cron wrapper — throttled to at most once per hour, called on each page visit.
function run_cleanup_if_due(): void {
    static $ran = false;
    if ($ran) return;
    $ran = true;

    try {
        $last = (int)get_setting('last_cleanup', '0');
        if ((time() - $last) < 3600) return;

        // Stamp before work to block concurrent duplicate runs
        set_setting('last_cleanup', (string)time());
        do_cleanup();
    } catch (Throwable $e) {
        log_err('Cleanup error: ' . $e->getMessage());
    }
}
