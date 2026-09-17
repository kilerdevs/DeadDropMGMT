<?php
declare(strict_types=1);

// Handler for the set_lang dispatch route. Runs INSIDE the dispatcher
// envelope (JSON headers, session, admin auth, POST, CSRF) — direct
// requests are refused. 2FA-exempt by route flag: couriers pending
// enrollment must still reach their own language preference.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'set_lang') {
    http_response_code(404);
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
