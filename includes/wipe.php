<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';

// ── Panic wipe ────────────────────────────────────────────────────────────────
// Semantics (explicit product decision, documented in ADR-015):
//  - Panic destroys EVERYTHING it can reach: orders, photos, event log,
//    audit log, rate-limit rows and on-disk logs. No evidence survives —
//    including the record of the wipe itself.
//  - What deliberately survives: the schema itself, user accounts and the
//    settings table, so the installation keeps working afterwards instead
//    of becoming a brick.
//  - The DB side runs in one transaction: either every table is emptied or
//    nothing changed and the caller can retry.
//  - Files are swept AFTER the commit, every failure counted. The function
//    never reports success it did not achieve: files_failed > 0 means the
//    caller must surface that and allow a retry.
//  - Re-running is always safe: missing rows/files are simply skipped.
function do_panic_wipe(): array {
    $db = get_db();

    $report = [
        'orders'       => (int)$db->query('SELECT COUNT(*) FROM orders')->fetchColumn(),
        'photos'       => (int)$db->query('SELECT COUNT(*) FROM order_photos')->fetchColumn(),
        'events'       => (int)$db->query('SELECT COUNT(*) FROM order_events')->fetchColumn(),
        'audit'        => 0,
        'files'        => 0,
        'files_failed' => 0,
    ];

    try {
        $report['audit'] = (int)$db->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
    } catch (Exception $e) {
        $report['audit'] = -1; // table unreadable — count unknown, still wiped below if possible
    }

    // Collect filenames while the FK chain still exists.
    try {
        $files = $db->query('SELECT filename FROM order_photos')->fetchAll(PDO::FETCH_COLUMN);
    } catch (Exception $e) {
        $files = [];
    }

    // DB side: one transaction over every evidence-bearing table. DELETE (not
    // TRUNCATE) so a failure rolls back cleanly instead of leaving some tables
    // empty and others full; the ON DELETE CASCADE takes care of photos.
    $db->beginTransaction();
    try {
        $db->prepare('DELETE FROM orders')->execute();
        $db->prepare('DELETE FROM order_events')->execute();
        $db->prepare('DELETE FROM audit_log')->execute();
        $db->prepare('DELETE FROM rate_limits')->execute();
        $db->commit();
    } catch (Exception $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw new RuntimeException('DB wipe failed, nothing destroyed: ' . $e->getMessage(), 0, $e);
    }

    // Filesystem side: after the DB is authoritative-zero. Pattern-checked
    // paths plus a directory sweep catch orphans from earlier partial runs.
    foreach ($files as $fn) {
        if (is_string($fn) && preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $fn)) {
            _panic_unlink(dirname(__DIR__) . '/uploads/' . $fn, $report);
        }
    }
    foreach (glob(dirname(__DIR__) . '/uploads/*', GLOB_ONLYDIR) ?: [] as $dir) {
        foreach (glob($dir . '/*') ?: [] as $f) {
            _panic_unlink($f, $report);
        }
        @rmdir($dir);
    }

    // On-disk logs carry IPs and tokens — destroyed along with everything else.
    foreach ([ERROR_LOG_PATH, APP_LOG_PATH] as $log_path) {
        if (is_file($log_path)) {
            @file_put_contents($log_path, '');
        }
    }

    return $report;
}

function _panic_unlink(string $path, array &$report): void {
    if (!is_file($path)) {
        return; // already gone — retry runs stay quiet about it
    }
    secure_unlink($path);
    // file_exists (not is_file): the earlier is_file() call would otherwise be
    // assumed by static analysis to hold for the whole function body — the
    // unlink inside secure_unlink() is best-effort and may genuinely fail.
    if (@file_exists($path)) {
        $report['files_failed']++;
    } else {
        $report['files']++;
    }
}
