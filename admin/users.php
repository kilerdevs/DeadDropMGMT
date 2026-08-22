<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

start_secure_session();
require_owner();
$csp_nonce = set_security_headers(true);

$flash    = $_SESSION['flash']    ?? '';
$flash_ok = $_SESSION['flash_ok'] ?? false;
unset($_SESSION['flash'], $_SESSION['flash_ok']);

try {
    $db = get_db();
    $owner = $db->query('SELECT id, username, created_at, totp_enabled FROM users WHERE role = "owner" LIMIT 1')->fetch();
    $couriers = $db->query(
        'SELECT u.id, u.username, u.created_at, u.totp_enabled, COUNT(o.id) AS order_count
         FROM users u
         LEFT JOIN orders o ON o.created_by = u.id
         WHERE u.role = "courier"
         GROUP BY u.id ORDER BY u.username'
    )->fetchAll();
} catch (Exception $e) {
    log_err('Users page: ' . $e->getMessage());
    $owner = null; $couriers = [];
}

$csrf    = generate_csrf();
$_active = 'users';
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Użytkownicy</title><link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading">Użytkownicy</div>

        <?php if ($flash): ?>
        <div class="flash <?= $flash_ok ? 'ok' : '' ?>"><?= htmlspecialchars($flash, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <!-- ── Owner ──────────────────────────────────────────────────────── -->
        <div class="section-label">Właściciel</div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Nazwa użytkownika</th><th>Konto od</th><th>Akcje</th></tr></thead>
                <tbody>
                <?php if ($owner): ?>
                <tr>
                    <td>
                        <span class="token"><?= htmlspecialchars($owner['username'], ENT_QUOTES, 'UTF-8') ?></span>
                        <?php if ((int)$owner['id'] === current_user_id()): ?>
                        <span class="role-badge role-owner">Ty</span>
                        <?php endif; ?>
                        <span class="role-badge <?= $owner['totp_enabled'] ? 'role-owner' : 'role-courier' ?>">
                            <?= $owner['totp_enabled'] ? '2FA WŁĄCZONE' : '2FA WYŁĄCZONE' ?>
                        </span>
                    </td>
                    <td class="meta td-muted"><?= htmlspecialchars($owner['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td>
                        <div class="order-actions">
                            <button class="action-btn" data-toggle="pw-owner-<?= (int)$owner['id'] ?>">Zmień hasło</button>
                            <?php if ($owner['totp_enabled']): ?>
                            <form class="inline-form" method="POST" action="/admin/user_action.php"
                                  data-confirm="Wyłączyć 2FA dla konta <?= htmlspecialchars($owner['username'], ENT_QUOTES, 'UTF-8') ?>?">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="action" value="reset_2fa">
                                <input type="hidden" name="user_id" value="<?= (int)$owner['id'] ?>">
                                <button class="action-btn action-btn--danger">Wyłącz 2FA</button>
                            </form>
                            <?php endif; ?>
                        </div>
                        <div id="pw-owner-<?= (int)$owner['id'] ?>" class="pw-form-panel">
                            <form method="POST" action="/admin/user_action.php" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="action" value="change_password">
                                <input type="hidden" name="user_id" value="<?= (int)$owner['id'] ?>">
                                <div class="inline-pw-form">
                                    <input type="password" name="new_password" placeholder="Nowe hasło (min. 8 znaków)" autocomplete="new-password">
                                    <button type="submit" class="action-btn">Zapisz</button>
                                </div>
                            </form>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <tr class="empty-row"><td colspan="3">BRAK DANYCH</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- ── Couriers ───────────────────────────────────────────────────── -->
        <div class="divider"></div>
        <div class="section-label">Kurierzy (<?= count($couriers) ?>)</div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr><th>Nazwa użytkownika</th><th>Zamówienia</th><th>Konto od</th><th>Akcje</th></tr>
                </thead>
                <tbody>
                <?php if (empty($couriers)): ?>
                    <tr class="empty-row"><td colspan="4">BRAK KURIERÓW</td></tr>
                <?php else: foreach ($couriers as $c): ?>
                <tr>
                    <td>
                        <span class="token"><?= htmlspecialchars($c['username'], ENT_QUOTES, 'UTF-8') ?></span>
                        <span class="role-badge <?= $c['totp_enabled'] ? 'role-owner' : 'role-courier' ?>">
                            <?= $c['totp_enabled'] ? '2FA WŁĄCZONE' : '2FA WYŁĄCZONE' ?>
                        </span>
                    </td>
                    <td class="td-muted"><?= (int)$c['order_count'] ?></td>
                    <td class="meta td-muted"><?= htmlspecialchars($c['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td>
                        <div class="order-actions">
                            <button class="action-btn" data-toggle="pw-c-<?= (int)$c['id'] ?>">Zmień hasło</button>
                            <?php if ($c['totp_enabled']): ?>
                            <form class="inline-form" method="POST" action="/admin/user_action.php"
                                  data-confirm="Wyłączyć 2FA dla konta <?= htmlspecialchars($c['username'], ENT_QUOTES, 'UTF-8') ?>?">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="action" value="reset_2fa">
                                <input type="hidden" name="user_id" value="<?= (int)$c['id'] ?>">
                                <button class="action-btn action-btn--danger">Wyłącz 2FA</button>
                            </form>
                            <?php endif; ?>
                            <form class="inline-form" method="POST" action="/admin/user_action.php"
                                  data-confirm="Usunąć konto kuriera <?= htmlspecialchars($c['username'], ENT_QUOTES, 'UTF-8') ?>? Jego zamówienia pozostaną w systemie.">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="action" value="delete_courier">
                                <input type="hidden" name="user_id" value="<?= (int)$c['id'] ?>">
                                <button class="action-btn action-btn--danger">Usuń</button>
                            </form>
                        </div>
                        <div id="pw-c-<?= (int)$c['id'] ?>" class="pw-form-panel">
                            <form method="POST" action="/admin/user_action.php" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="action" value="change_password">
                                <input type="hidden" name="user_id" value="<?= (int)$c['id'] ?>">
                                <div class="inline-pw-form">
                                    <input type="password" name="new_password" placeholder="Nowe hasło (min. 8 znaków)" autocomplete="new-password">
                                    <button type="submit" class="action-btn">Zapisz</button>
                                </div>
                            </form>
                        </div>
                    </td>
                </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>

        <!-- ── Add courier ────────────────────────────────────────────────── -->
        <div class="divider"></div>
        <div class="section-label">Dodaj kuriera</div>
        <div class="form-panel users-add-panel">
            <form method="POST" action="/admin/user_action.php" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="create_courier">
                <div class="form-group">
                    <label for="new_username">Nazwa użytkownika</label>
                    <input type="text" id="new_username" name="username" autocomplete="off" spellcheck="false">
                </div>
                <div class="form-group">
                    <label for="new_pw">Hasło <span class="hint">min. 8 znaków</span></label>
                    <input type="password" id="new_pw" name="password" autocomplete="new-password">
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn">Utwórz konto kuriera</button>
                </div>
            </form>
        </div>
    </main>
</div>

<script src="/admin/admin.js"></script>
<script nonce="<?= htmlspecialchars($csp_nonce, ENT_QUOTES, 'UTF-8') ?>">
(function () {
    // Hide all pw-form-panels initially
    document.querySelectorAll('.pw-form-panel').forEach(function (el) {
        el.style.display = 'none';
    });
    // Toggle password forms
    document.querySelectorAll('[data-toggle]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var t = document.getElementById(btn.dataset.toggle);
            if (!t) return;
            t.style.display = t.style.display === 'none' ? 'block' : 'none';
        });
    });
})();
</script>
</body>
</html>
