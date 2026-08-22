<?php
// Shared sidebar partial.
// Set $_active before requiring: 'orders' | 'new_order' | 'analytics' | 'settings' | 'users' | 'panic' | 'edit'
require_once dirname(__DIR__) . '/includes/i18n.php';
$_active    = $_active ?? '';
$_is_owner  = is_owner();
$_user_name = current_user_name();
$_lang_csrf = generate_csrf();
?>
<aside class="sidebar" id="sidebar">
    <div class="sidebar-wordmark"><?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?> // ADMIN</div>
    <nav class="sidebar-nav">
        <div class="nav-section-label"><?= t('admin.sidebar.nav_label') ?></div>
        <a class="nav-item <?= $_active === 'orders'    ? 'active' : '' ?>" href="/admin/orders.php"><?= t('admin.sidebar.orders') ?></a>
        <a class="nav-item <?= $_active === 'new_order' ? 'active' : '' ?>" href="/admin/new_order.php"><?= t('admin.sidebar.new_order') ?></a>
        <?php if ($_active === 'edit'): ?>
        <a class="nav-item active" href="#"><?= t('admin.sidebar.edit_order') ?></a>
        <?php endif; ?>
        <?php if ($_is_owner): ?>
        <?php if (analytics_enabled()): ?>
        <a class="nav-item <?= $_active === 'analytics' ? 'active' : '' ?>" href="/admin/analytics.php"><?= t('admin.sidebar.analytics') ?></a>
        <?php endif; ?>
        <a class="nav-item <?= $_active === 'users'     ? 'active' : '' ?>" href="/admin/users.php"><?= t('admin.sidebar.users') ?></a>
        <a class="nav-item <?= $_active === 'audit'     ? 'active' : '' ?>" href="/admin/audit_log.php"><?= t('admin.sidebar.audit_log') ?></a>
        <a class="nav-item <?= $_active === 'settings'  ? 'active' : '' ?>" href="/admin/settings.php"><?= t('admin.sidebar.settings') ?></a>
        <?php endif; ?>
        <a class="nav-item <?= $_active === '2fa'       ? 'active' : '' ?>" href="/admin/2fa.php">2FA</a>
    </nav>
    <div class="sidebar-footer">
        <?php if ($_is_owner): ?>
        <a class="nav-item-danger <?= $_active === 'panic' ? 'active' : '' ?>" href="/admin/panic.php">&#9888; <?= t('admin.sidebar.panic') ?></a>
        <?php endif; ?>
        <a class="sidebar-logout" href="/admin/logout.php"><?= t('admin.sidebar.logout') ?></a>
        <div class="sidebar-user">
            <span class="sidebar-username"><?= htmlspecialchars($_user_name, ENT_QUOTES, 'UTF-8') ?></span>
            <span class="role-badge role-<?= $_is_owner ? 'owner' : 'courier' ?>">
                <?= $_is_owner ? t('admin.role.owner') : t('admin.role.courier') ?>
            </span>
        </div>
        <select class="sidebar-lang" id="sidebar-lang-select" aria-label="<?= htmlspecialchars(t('admin.sidebar.lang_label'), ENT_QUOTES, 'UTF-8') ?>">
            <?php foreach (i18n_lang_names() as $_code => $_name): ?>
            <option value="<?= htmlspecialchars($_code, ENT_QUOTES, 'UTF-8') ?>" <?= current_lang() === $_code ? 'selected' : '' ?>><?= htmlspecialchars($_name, ENT_QUOTES, 'UTF-8') ?></option>
            <?php endforeach; ?>
        </select>
        <div class="sidebar-sec">AES-256 &middot; BCRYPT &middot; CSRF &middot; CSP</div>
    </div>
</aside>
<script nonce="<?= htmlspecialchars($csp_nonce ?? '', ENT_QUOTES, 'UTF-8') ?>">
window.I18N = <?= json_encode([
    'expired'         => t('common.expired'),
    'copied'          => t('admin.2fa.copied'),
    'copy_link_label' => t('admin.js.copy_link_label'),
    'copy_password_label' => t('admin.js.copy_password_label'),
    'copy_no_password'    => t('admin.js.copy_no_password'),
    'copy_warning' => t('admin.js.copy_warning', ['ttl' => order_ttl_hours()]),
    'menu_aria' => t('admin.js.menu_aria'),
]) ?>;
document.getElementById('sidebar-lang-select').addEventListener('change', function () {
    var fd = new FormData();
    fd.append('csrf_token', <?= json_encode($_lang_csrf) ?>);
    fd.append('lang', this.value);
    fetch('/admin/set_lang.php', { method: 'POST', body: fd })
        .then(function () { location.reload(); });
});
</script>
