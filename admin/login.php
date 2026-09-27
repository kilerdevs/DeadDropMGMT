<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';
set_security_headers(false);
start_secure_session();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/index.php');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    $_SESSION['login_error'] = t('admin.login.error.bad_request');
    header('Location: /admin/index.php');
    exit;
}

$username = trim(post_string('username'));
$password = post_string('password');

// Second budget, per ACCOUNT: the IP limiter alone is beaten by rotating
// addresses. The threshold is deliberately looser than the IP one (an
// attacker can spend it to lock a victim out for one window, so it must not
// bite on a handful of typos), and it is keyed on the submitted name whether
// or not the account exists (admin_login() refuses names outside the account
// charset, so collation-equal spellings cannot mint fresh budgets).
const LOGIN_ACCOUNT_MAX = 20;
$acct = rl_account_subject('l:', $username);

// ── Rate limit (IP-based, configurable in Ustawienia) ────────────────────────
// Spend BEFORE the password check, atomically (rl_hit): a check-then-count
// flow lets a burst of parallel requests all read the same count during the
// bcrypt window and slip past the limit together.
$hit = rl_hit('admin_login');
$acctHit = rl_hit('admin_login_acct', LOGIN_ACCOUNT_MAX, null, $acct);
if ($hit['blocked'] || $acctHit['blocked']) {
    $rem = $hit['blocked'] ? $hit['remaining'] : $acctHit['remaining'];
    $_SESSION['login_error'] = t('admin.login.error.rate_limited', ['min' => (int)ceil($rem / 60)]);
    header('Location: /admin/index.php');
    exit;
}

// Successful steps do NOT reset the IP budget: a valid credential of one's
// own (a courier account, say) would otherwise wipe the counter between
// guesses against the owner and the limiter would never bite. They only give
// back this request's own attempt; failed attempts age out with the window.
switch (admin_login($username, $password)) {
    case 'ok':
        rl_refund('admin_login');
        rl_reset('admin_login_acct', $acct);
        header('Location: /admin/orders.php');
        exit;
    case 'need_2fa':
        rl_refund('admin_login');
        rl_reset('admin_login_acct', $acct);
        header('Location: /admin/verify_2fa.php');
        exit;
    case 'need_setup':
        rl_refund('admin_login');
        rl_refund('admin_login_acct', $acct);
        header('Location: /admin/setup_password.php');
        exit;
}

// Brute-force visibility: every rejected password lands in the audit trail
// (attempted username, never the password) next to the IP the audit row
// always carries. Volume is inherently bounded — the limiter above caps
// attempts per IP, so this cannot be turned into log spam.
audit('login_failed', null, null, $username);
$_SESSION['login_error'] = t('admin.login.error.bad_credentials');
header('Location: /admin/index.php');
exit;
