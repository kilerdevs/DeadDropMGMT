<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

// First-run owner creation. Only reachable while the users table is empty:
// the visitor picks a username, gets routed to the set-password step, and
// the instance is claimed.
set_security_headers(false);
start_secure_session();

function _bootstrap_back(string $msg): void {
    $_SESSION['login_error'] = $msg;
    header('Location: /admin/index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/index.php');
    exit;
}
if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    _bootstrap_back(t('admin.common.invalid_csrf'));
}

$rl = rl_status('admin_login');
if ($rl['blocked']) {
    _bootstrap_back(t('admin.login.error.rate_limited', ['min' => (int)ceil($rl['remaining'] / 60)]));
}

// Optional claim guard: when DDMGMT_SETUP_TOKEN is set, only someone who
// knows it can create the first owner — a fresh instance reachable from the
// network is otherwise claimed by whoever asks first.
$setupToken = _secret('DDMGMT_SETUP_TOKEN', '');
if ($setupToken !== '' && !hash_equals($setupToken, trim(post_string('setup_token')))) {
    rl_increment('admin_login');
    _bootstrap_back(t('admin.bootstrap.error.bad_token'));
}
if ($setupToken === '') {
    log_warn('bootstrap_unguarded', ['msg' => 'Owner bootstrap without DDMGMT_SETUP_TOKEN: the first visitor claims this instance']);
}

$username   = trim(post_string('username'));
$enrollment   = ''; // set inside the lock; keeps analysis honest about the flash below
$new_user_id  = 0;

try {
    $db = get_db();
    // Named lock makes the empty-table check + insert atomic across concurrent
    // requests — two simultaneous claimants can no longer both observe zero
    // users and both proceed to INSERT.
    if (!$db->query("SELECT GET_LOCK('deaddrop_owner_bootstrap', 5)")->fetchColumn()) {
        // Lost the race for the lock — but that does NOT mean the instance
        // is claimed. A second claimant timing out here used to be told
        // "already initialized" while the table was still empty; check.
        $claimed = (int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn() !== 0;
        _bootstrap_back(t($claimed ? 'admin.bootstrap.error.initialized'
                                   : 'admin.bootstrap.error.busy'));
    }
    try {
        if ((int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn() !== 0) {
            _bootstrap_back(t('admin.bootstrap.error.initialized'));
        }

        if (strlen($username) < 3 || strlen($username) > 64) {
            rl_increment('admin_login');
            _bootstrap_back(t('admin.users.flash.username_length'));
        }
        if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $username)) {
            rl_increment('admin_login');
            _bootstrap_back(t('admin.users.flash.username_chars'));
        }

        // The owner's own enrollment secret: shown once on the next screen as
        // the recovery credential should this setup session be lost. Without
        // it, nobody can reach the password step for this account.
        $enrollment = enrollment_secret_generate();
        $db->prepare('INSERT INTO users (username, password_hash, role, enrollment_hash, enrollment_expires)
                      VALUES (?, "", "owner", ?, NOW() + INTERVAL 24 HOUR)')
               ->execute([$username, enrollment_secret_hash($enrollment)]);
        // Capture the id NOW: audit() below inserts into audit_log and would
        // clobber lastInsertId, pointing the setup step at the wrong row.
        $new_user_id = (int)$db->lastInsertId();
    } finally {
        $db->exec("DO RELEASE_LOCK('deaddrop_owner_bootstrap')");
    }
} catch (Exception $e) {
    if (str_contains($e->getMessage(), 'Duplicate')) {
        _bootstrap_back(t('admin.bootstrap.error.taken'));
    }
    log_err('Owner bootstrap: ' . $e->getMessage());
    _bootstrap_back(t('admin.bootstrap.error.create_failed'));
}

audit('owner_bootstrap', null, null, $username);

// One-time display of the enrollment secret on the set-password screen,
// sealed like any flash message (single-use credential crossing a
// redirect via the session — never plaintext at rest).
$_SESSION['enrollment_flash'] = encrypt_flash(t('admin.bootstrap.enrollment_note', ['secret' => $enrollment]));

session_regenerate_id(true);
$_SESSION['pending_setup_user_id'] = $new_user_id;
$_SESSION['pending_setup_time']    = time();
unset($_SESSION['csrf_token']);
rl_reset('admin_login');

header('Location: /admin/setup_password.php');
exit;
