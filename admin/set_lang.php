<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

header('Content-Type: application/json');
start_secure_session();
require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    echo json_encode(['error' => 'CSRF']);
    exit;
}

$lang = $_POST['lang'] ?? '';
if (!in_array($lang, i18n_supported_langs(), true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid language']);
    exit;
}

try {
    get_db()->prepare('UPDATE users SET lang = ? WHERE id = ?')->execute([$lang, current_user_id()]);
    $_SESSION['user_lang'] = $lang;
    echo json_encode(['ok' => true]);
} catch (Exception $e) {
    log_err('Set language: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Save failed']);
}
exit;
