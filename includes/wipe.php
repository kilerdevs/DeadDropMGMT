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

    // Every count is guarded: an unreadable table must surface as -1 in the
    // report (still wiped below if possible), never as a raw PDOException
    // escaping before the transaction with SQL text attached.
    $report = ['orders' => -1, 'photos' => -1, 'events' => -1, 'audit' => -1, 'files' => 0, 'files_failed' => 0];
    foreach (['orders' => 'orders', 'photos' => 'order_photos', 'events' => 'order_events', 'audit' => 'audit_log'] as $k => $table) {
        try {
            $report[$k] = (int)$db->query("SELECT COUNT(*) FROM {$table}")->fetchColumn();
        } catch (Exception $e) {
            $report[$k] = -1; // table unreadable — count unknown, still wiped below if possible
        }
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
    } catch (Throwable $e) {
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
    foreach (glob_list(dirname(__DIR__) . '/uploads/*', GLOB_ONLYDIR) as $dir) {
        _panic_sweep_dir($dir, $report);
        @rmdir($dir);
    }

    // On-disk logs carry IPs and tokens — destroyed along with everything
    // else. Same overwrite treatment as photo files (finding: truncation
    // alone leaves the old blocks recoverable); both daemons reopen their
    // logs per write, so unlinking under them is safe. The rotated .1
    // generation carries the same history and must die too.
    foreach ([ERROR_LOG_PATH, APP_LOG_PATH, APP_LOG_PATH . '.1'] as $log_path) {
        if (is_file($log_path) || is_link($log_path)) {
            overwrite_and_unlink($log_path);
        }
    }

    return $report;
}

// Recursive sweep: only one level was walked before, so a nested directory
// under uploads/<id>/ survived (with @rmdir then failing silently on top).
function _panic_sweep_dir(string $dir, array &$report): void {
    foreach (glob_list($dir . '/*') as $f) {
        if (is_dir($f) && !is_link($f)) {
            _panic_sweep_dir($f, $report);
            @rmdir($f);
        } else {
            _panic_unlink($f, $report);
        }
    }
}

function _panic_unlink(string $path, array &$report): void {
    // is_file() is false for symlinks — but those must still be removed
    // (overwrite_and_unlink() unlinks them without following).
    if (!is_file($path) && !is_link($path)) {
        return; // already gone — retry runs stay quiet about it
    }
    overwrite_and_unlink($path);
    // file_exists (not is_file): the earlier is_file() call would otherwise be
    // assumed by static analysis to hold for the whole function body — the
    // unlink inside overwrite_and_unlink() is best-effort and may genuinely fail.
    if (@file_exists($path)) {
        $report['files_failed']++;
    } else {
        $report['files']++;
    }
}
