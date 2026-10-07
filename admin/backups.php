<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

// Owner backups: manual create / download / delete / restore. Destructive
// half (restore) additionally demands the owner's password — a stolen
// session alone must not be able to replace every row — and every failure
// answers quiet codes (invalid, restore_failed), never paths or SQL. Long
// operations run with the session lock released (create checksums hundreds
// of MiB) and client disconnects ignored, panic.php idiom.
start_secure_session();
$csp_nonce = set_security_headers(true);
require_owner();

$notice = '';
$warning = '';
$error = '';
$rows = backup_supported() ? backup_list() : [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = t('admin.common.invalid_csrf');
    } else {
        $action = post_string('action');
        if ($action === 'create') {
            // Hours of photos must not hold the session lock (every other
            // owner request, tiles included, would queue behind the backup)
            // nor die with a closed browser tab.
            session_write_close();
            ignore_user_abort(true);
            if (function_exists('set_time_limit')) {
                @set_time_limit(0);
            }
            $res = backup_create(get_db());
            start_secure_session();
            if (($res['ok'] ?? false) === true) {
                audit('backup_create', null, null, 'file=' . ($res['file'] ?? '?'));
                $notice = t('admin.backup.flash.created', [
                    'file' => (string)($res['file'] ?? '?'),
                    'rows' => (int)($res['rows'] ?? 0),
                    'files' => (int)($res['files'] ?? 0),
                ]);
                $rows = backup_list();
            } else {
                log_err('backup create failed from admin: ' . ($res['code'] ?? '?'));
                $error = t('admin.backup.flash.create_failed');
            }
        } elseif ($action === 'delete') {
            $name = post_string('file');
            if (backup_delete($name)) {
                audit('backup_delete', null, null, 'file=' . $name);
                $notice = t('admin.backup.flash.deleted', ['file' => $name]);
                $rows = backup_list();
            } else {
                $error = t('admin.backup.flash.invalid');
            }
        } elseif ($action === 'restore') {
            // Password re-auth FIRST (before touching any file): no oracle
            // for whether the backup itself is valid.
            $uid = current_user_id();
            $st = get_db()->prepare('SELECT password_hash FROM users WHERE id = ? LIMIT 1');
            $st->execute([$uid]);
            $hash = (string)($st->fetchColumn() ?: '');
            $pw = is_string($_POST['password'] ?? null) ? (string)$_POST['password'] : '';
            if ($hash === '' || $pw === '' || !verify_password($pw, $hash)) {
                $error = t('admin.backup.flash.reauth_failed');
            } else {
                // Staged under a dot-name that never lists and never matches
                // the finished-backup regex, then unlinked either way.
                $stage = null;
                $source = post_string('source');
                if ($source === 'upload') {
                    $file = $_FILES['backupfile'] ?? null;
                    if (!is_array($file)) {
                        // post_max_size overflow voids the whole body: no
                        // POST fields, no file — host limits are the answer.
                        $error = t('admin.backup.flash.upload_ini');
                    } else {
                        // UPLOAD_ERR_* arrives int (or numeric string);
                        // anything else (array-shaped input included) is "no
                        // file", never a cast warning.
                        $errRaw = $file['error'] ?? null;
                        $err = is_scalar($errRaw) ? (int)$errRaw : UPLOAD_ERR_NO_FILE;
                        if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) {
                            $error = t('admin.backup.flash.upload_ini');
                        } elseif ($err !== UPLOAD_ERR_OK
                            || !is_string($file['tmp_name'] ?? null)
                            || !is_uploaded_file($file['tmp_name'])
                        ) {
                            $error = t('admin.backup.flash.upload_invalid');
                        } else {
                            $stage = backup_dir() . '/.restore-' . bin2hex(random_bytes(8)) . '.part';
                            if (!@move_uploaded_file($file['tmp_name'], $stage)) {
                                $stage = null;
                                $error = t('admin.backup.flash.restore_failed');
                            }
                        }
                    }
                } elseif ($source === 'stored' && preg_match(BACKUP_NAME_RE, post_string('file')) === 1) {
                    $cand = backup_dir() . '/' . post_string('file');
                    if (is_file($cand)) {
                        $stage = $cand;
                    } else {
                        $error = t('admin.backup.flash.invalid');
                    }
                } else {
                    $error = t('admin.backup.flash.invalid');
                }
                if ($error === '' && is_string($stage)) {
                    $isUpload = str_ends_with($stage, '.part');
                    session_write_close();
                    ignore_user_abort(true);
                    if (function_exists('set_time_limit')) {
                        @set_time_limit(0);
                    }
                    $ver = backup_verify($stage);
                    if (($ver['ok'] ?? false) === true) {
                        $res = backup_restore(get_db(), $stage, $ver['manifest']);
                    } else {
                        $res = ['ok' => false];
                    }
                    start_secure_session();
                    if ($isUpload) {
                        @unlink($stage);
                    }
                    if (($res['ok'] ?? false) === true) {
                        // The client filename is request-derived: only a
                        // string ever reaches the notice (t() escapes it).
                        $clientName = $_FILES['backupfile']['name'] ?? null;
                        $shown = is_string($clientName) && $clientName !== '' ? basename($clientName) : 'upload';
                        audit('backup_restore', null, null, 'source=' . ($isUpload ? 'upload' : basename($stage)));
                        $notice = t('admin.backup.flash.restored', ['file' => $isUpload ? $shown : basename($stage)]);
                        if (($res['key_mismatch'] ?? false) === true) {
                            $warning = t('admin.backup.flash.key_mismatch');
                        } elseif (($res['files_partial'] ?? false) === true) {
                            $warning = t('admin.backup.flash.files_partial');
                        }
                        $rows = backup_list();
                    } else {
                        // Quiet on purpose (A5 backup tamperer): the detail
                        // went to the log inside the core. One exception: a
                        // size refusal is actionable (re-create as zip, or
                        // restore on a bigger host) and tells an attacker
                        // nothing they did not already know — they supplied
                        // the file — so it gets its own message.
                        $code = (string)($ver['code'] ?? $res['code'] ?? '?');
                        log_err('backup restore refused from admin: ' . $code);
                        $error = $code === 'too_large'
                            ? t('admin.backup.flash.too_large')
                            : t('admin.backup.flash.invalid');
                    }
                }
            }
            // The password must not outlive the request in any form.
            unset($pw);
        }
    }
}

function backup_human_bytes(int $b): string {
    if ($b >= 1073741824) {
        return number_format($b / 1073741824, 1) . ' GB';
    }
    if ($b >= 1048576) {
        return number_format($b / 1048576, 1) . ' MB';
    }
    return number_format(max(0, $b) / 1024, 0) . ' KB';
}

$csrf = generate_csrf();
$_active = 'backups';
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.backup.title') ?></title><link rel="stylesheet" href="/admin/style.css?v=<?= admin_css_ver() ?>">
</head>
<body>
<div class="shell">

    <?php require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading"><?= t('admin.backup.title') ?></div>
        <p class="td-muted"><?= t('admin.backup.lead') ?></p>

        <?php if ($error): ?><div class="flash"><?= $error ?></div><?php endif; ?>
        <?php if ($warning): ?><div class="flash flash-warn"><?= $warning ?></div><?php endif; ?>
        <?php if ($notice): ?><div class="flash flash-ok"><?= $notice ?></div><?php endif; ?>
        <!-- $error/$warning/$notice are t()-built (HTML-safe); raw echo.
             Filenames below are strict-regex names; escaped anyway. -->

        <?php if (!backup_supported()): ?>
        <div class="flash"><?= t('admin.backup.flash.unsupported') ?></div>
        <?php else: ?>
        <form method="POST" action="/admin/backups.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="action" value="create">
            <button type="submit" class="btn btn-neutral"><?= t('admin.backup.create_button') ?></button>
            <span class="td-muted"><?= backup_zip_supported() ? t('admin.backup.format_zip') : t('admin.backup.format_json') ?></span>
        </form>
        <?php endif; ?>

        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th><?= t('admin.backup.col_file') ?></th>
                    <th><?= t('admin.backup.col_format') ?></th>
                    <th><?= t('admin.backup.col_size') ?></th>
                    <th><?= t('admin.backup.col_date') ?></th>
                    <th></th>
                </tr></thead>
                <tbody>
                <?php if ($rows === []): ?>
                    <tr><td colspan="5" class="td-muted"><?= t('admin.backup.empty') ?></td></tr>
                <?php endif; ?>
                <?php foreach ($rows as $r): ?>
                    <tr>
                        <td><span class="token"><?= htmlspecialchars($r['name'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td class="td-muted"><?= htmlspecialchars($r['format'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td class="td-muted"><?= backup_human_bytes((int)$r['size']) ?></td>
                        <td class="td-muted"><?= htmlspecialchars(date('Y-m-d H:i', (int)$r['mtime']), ENT_QUOTES, 'UTF-8') ?></td>
                        <td>
                            <a href="/admin/download_backup.php?file=<?= rawurlencode($r['name']) ?>"><?= t('admin.backup.download') ?></a>
                            <form method="POST" action="/admin/backups.php" style="display:inline" onsubmit="return confirm(<?= htmlspecialchars(json_encode(t('admin.backup.delete_confirm')), ENT_QUOTES, 'UTF-8') ?>)">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="file" value="<?= htmlspecialchars($r['name'], ENT_QUOTES, 'UTF-8') ?>">
                                <button type="submit" class="btn-cancel"><?= t('admin.backup.delete') ?></button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if (backup_supported()): ?>
        <div class="panic-wrap">
            <div class="panic-step"><?= t('admin.backup.restore_title') ?></div>
            <div class="panic-body"><?= t('admin.backup.restore_hint') ?></div>
            <form method="POST" action="/admin/backups.php" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="restore">
                <label><input type="radio" name="source" value="upload" checked> <?= t('admin.backup.file_label') ?>
                    <input type="file" name="backupfile" accept=".zip,.json,.gz">
                </label>
                <?php if ($rows !== []): ?>
                <label><input type="radio" name="source" value="stored"> <?= t('admin.backup.stored_label') ?>
                <select name="file">
                    <?php foreach ($rows as $r): ?>
                    <option value="<?= htmlspecialchars($r['name'], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($r['name'], ENT_QUOTES, 'UTF-8') ?></option>
                    <?php endforeach; ?>
                </select>
                </label>
                <?php endif; ?>
                <label><?= t('admin.backup.password_label') ?>
                    <input type="password" name="password" autocomplete="current-password">
                </label>
                <div class="form-actions">
                    <button type="submit" class="btn btn-panic" name="restore_btn" value="upload">&#9888; <?= t('admin.backup.restore_button') ?></button>
                </div>
            </form>
        </div>
        <?php endif; ?>
    </main>
</div>
<script src="/admin/admin.js?v=<?= asset_ver('/admin/admin.js') ?>"></script>
</body>
</html>
