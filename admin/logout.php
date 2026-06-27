<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/auth.php';

set_security_headers();
start_secure_session();
admin_logout();

header('Location: /admin/index.php');
exit;
