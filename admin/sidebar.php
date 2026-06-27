<?php
// Shared sidebar partial.
// Set $_active before requiring: 'orders' | 'new_order' | 'analytics' | 'settings' | 'users' | 'panic' | 'edit'
$_active    = $_active ?? '';
$_is_owner  = is_owner();
$_user_name = current_user_name();
?>
<aside class="sidebar" id="sidebar">
    <div class="sidebar-wordmark"><?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?> // ADMIN</div>
    <nav class="sidebar-nav">
        <div class="nav-section-label">Nawigacja</div>
        <a class="nav-item <?= $_active === 'orders'    ? 'active' : '' ?>" href="/admin/orders.php">Zamówienia</a>
        <a class="nav-item <?= $_active === 'new_order' ? 'active' : '' ?>" href="/admin/new_order.php">Nowe zamówienie</a>
        <?php if ($_active === 'edit'): ?>
        <a class="nav-item active" href="#">Edycja zamówienia</a>
        <?php endif; ?>
        <?php if ($_is_owner): ?>
        <?php if (analytics_enabled()): ?>
        <a class="nav-item <?= $_active === 'analytics' ? 'active' : '' ?>" href="/admin/analytics.php">Analityka</a>
        <?php endif; ?>
        <a class="nav-item <?= $_active === 'users'     ? 'active' : '' ?>" href="/admin/users.php">Użytkownicy</a>
        <a class="nav-item <?= $_active === 'settings'  ? 'active' : '' ?>" href="/admin/settings.php">Ustawienia</a>
        <?php endif; ?>
    </nav>
    <div class="sidebar-footer">
        <?php if ($_is_owner): ?>
        <a class="nav-item-danger <?= $_active === 'panic' ? 'active' : '' ?>" href="/admin/panic.php">&#9888; Tryb awaryjny</a>
        <?php endif; ?>
        <a class="sidebar-logout" href="/admin/logout.php">Wyloguj</a>
        <div class="sidebar-user">
            <span class="sidebar-username"><?= htmlspecialchars($_user_name, ENT_QUOTES, 'UTF-8') ?></span>
            <span class="role-badge role-<?= $_is_owner ? 'owner' : 'courier' ?>">
                <?= $_is_owner ? 'Właściciel' : 'Kurier' ?>
            </span>
        </div>
        <div class="sidebar-sec">AES-256 &middot; BCRYPT &middot; CSRF &middot; CSP</div>
    </div>
</aside>
