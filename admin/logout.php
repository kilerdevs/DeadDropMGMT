<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

set_security_headers();
start_secure_session();

// POST-only: a state-changing GET lets any hostile page log the admin out
// with a single <img> tag. GETs (and CSRF failures) redirect without touching
// the session.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && verify_csrf($_POST['csrf_token'] ?? '')) {
    admin_logout();
}

header('Location: /admin/index.php');
exit;
