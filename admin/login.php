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

// ── Rate limit failed attempts (IP-based, configurable in Ustawienia) ────────
$rl = rl_status('admin_login');
if ($rl['blocked']) {
    $_SESSION['login_error'] = t('admin.login.error.rate_limited', ['min' => (int)ceil($rl['remaining'] / 60)]);
    header('Location: /admin/index.php');
    exit;
}

$username = trim(post_string('username'));
$password = post_string('password');

// Second budget, per ACCOUNT: the IP limiter alone is beaten by rotating
// addresses. The threshold is deliberately looser than the IP one (an
// attacker can spend it to lock a victim out for one window, so it must not
// bite on a handful of typos), and it is keyed on the submitted name whether
// or not the account exists.
const LOGIN_ACCOUNT_MAX = 20;
$acct = rl_account_subject('l:', $username);
$acctRl = rl_status('admin_login_acct', $acct);
// (rl_status()'s own 'blocked' trips at the IP threshold — only a fail-closed
// verdict, which carries count 0, or the account threshold itself denies here.)
if ($acctRl['count'] >= LOGIN_ACCOUNT_MAX || ($acctRl['blocked'] && $acctRl['count'] === 0)) {
    $_SESSION['login_error'] = t('admin.login.error.rate_limited', ['min' => (int)ceil($acctRl['remaining'] / 60)]);
    header('Location: /admin/index.php');
    exit;
}

// Successful steps do NOT reset the IP budget: a valid credential of one's
// own (a courier account, say) would otherwise wipe the counter between
// guesses against the owner and the limiter would never bite. Failed
// attempts age out with the window.
switch (admin_login($username, $password)) {
    case 'ok':
        rl_reset('admin_login_acct', $acct);
        header('Location: /admin/orders.php');
        exit;
    case 'need_2fa':
        rl_reset('admin_login_acct', $acct);
        header('Location: /admin/verify_2fa.php');
        exit;
    case 'need_setup':
        header('Location: /admin/setup_password.php');
        exit;
}

// One atomic spend + verdict: a budget that fills with this very attempt
// denies it immediately instead of leaking one extra try to a race.
$hit = rl_hit('admin_login');
rl_hit('admin_login_acct', LOGIN_ACCOUNT_MAX, null, $acct);
// Brute-force visibility: every rejected password lands in the audit trail
// (attempted username, never the password) next to the IP the audit row
// always carries. Volume is inherently bounded — the limiter above caps
// attempts per IP, so this cannot be turned into log spam.
audit('login_failed', null, null, $username);
$_SESSION['login_error'] = $hit['blocked']
    ? t('admin.login.error.rate_limited', ['min' => (int)ceil($hit['remaining'] / 60)])
    : t('admin.login.error.bad_credentials');
header('Location: /admin/index.php');
exit;
