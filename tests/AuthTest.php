<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Login flow, session fixation, 2FA gating state, logout ───────────────────

$db = get_db();
$db->exec("DELETE FROM users WHERE username IN ('t_auth_owner','t_auth_courier2fa')");
$hash = password_hash('CorrectHorse1!', PASSWORD_BCRYPT);
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_auth_owner', ?, 'owner')")->execute([$hash]);
$ownerId = (int)$db->lastInsertId();
$db->prepare("INSERT INTO users (username, password_hash, role, totp_enabled) VALUES ('t_auth_courier2fa', ?, 'courier', 1)")->execute([$hash]);
$courierId = (int)$db->lastInsertId();

// Successful login
$_SESSION = [];
start_secure_session();
T::eq('valid login returns ok', 'ok', admin_login('t_auth_owner', 'CorrectHorse1!'));
T::ok('session marked logged in', is_admin_logged_in());
T::eq('role stored', 'owner', $_SESSION['user_role']);
T::ok('is_owner true', is_owner());
T::ok('is_courier false', !is_courier());
T::eq('user id stored', $ownerId, current_user_id());
T::eq('user name stored', 't_auth_owner', current_user_name());
T::ok('login_time stamped', isset($_SESSION['login_time']) && abs(time() - $_SESSION['login_time']) < 5);

// Sliding inactivity expiry (pure predicate — require_admin() exits, so the
// comparison itself is unit-tested here, not through the guard).
$now = 1000000;
T::ok('fresh login not expired', !admin_login_expired(3600, $now - 10, $now));
T::ok('exact window edge not expired', !admin_login_expired(3600, $now - 3600, $now));
T::ok('past the window expired', admin_login_expired(3600, $now - 3601, $now));
T::ok('disabled timeout never expires', !admin_login_expired(0, $now - 999999, $now));
T::ok('missing stamp never expires here', !admin_login_expired(3600, null, $now));
T::ok('non-integer stamp never expires here', !admin_login_expired(3600, 'yesterday', $now));

// Missing-table detection answers by SQLSTATE, not by message wording: a
// 42S02 with an unfamiliar message is still "no table yet" (fresh-install
// fallback), while any other failure fails closed.
$missingCode = new class('unfamiliar driver message') extends PDOException {
    /** @var int|string */
    protected $code = '42S02';
};
T::ok('42S02 by code is a missing table', _db_table_missing($missingCode));
T::ok('other failures are not', !_db_table_missing(new PDOException('Connection lost')));

// Absolute lifetime (12 h wall clock, not sliding): the edge itself still
// belongs to the session; one second past it does not.
$abs = ADMIN_SESSION_ABSOLUTE_SECONDS;
T::ok('newborn session alive', !admin_session_absolute_expired($now, $now));
T::ok('edge of lifetime alive', !admin_session_absolute_expired($now - $abs, $now));
T::ok('past lifetime expired', admin_session_absolute_expired($now - $abs - 1, $now));
T::ok('unstamped session never expires here (caller stamps it)', !admin_session_absolute_expired(0, $now));

// Failed logins leave no session
$_SESSION = [];
T::eq('wrong password returns fail', 'fail', admin_login('t_auth_owner', 'wrong-password'));
T::ok('failed login leaves session empty', empty($_SESSION['user_id']));
T::eq('unknown user returns fail', 'fail', admin_login('no_such_user', 'CorrectHorse1!'));
// Non-ASCII input can MATCH a row under utf8mb4_unicode_ci ("ówner" ==
// "owner") while hashing to a fresh rate-limit key — guaranteed miss here,
// with the dummy-hash verify so timing reveals nothing.
T::eq('non-ASCII username is a guaranteed miss', 'fail', admin_login('ówner', 'CorrectHorse1!'));

// Session fixation: id must change on login
$_SESSION = [];
start_secure_session();
generate_csrf();
$pre_id = session_id();
admin_login('t_auth_owner', 'CorrectHorse1!');
T::ok('session id regenerated on login', session_id() !== $pre_id);

// 2FA-enabled account: password alone must not grant a session
$_SESSION = [];
T::eq('totp account returns need_2fa', 'need_2fa', admin_login('t_auth_courier2fa', 'CorrectHorse1!'));
T::ok('pending 2FA user recorded', (int)$_SESSION['pending_2fa_user_id'] === $courierId);
T::ok('full session NOT granted by password alone', !is_admin_logged_in());

// Completing login clears pending state and carries the flag
admin_finish_login($courierId, 'courier', 't_auth_courier2fa', true);
T::ok('finish_login clears pending 2FA', !isset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_time']));
T::ok('totp_enabled carried into session', $_SESSION['totp_enabled'] === true);

// Logout destroys the session
admin_logout();
T::eq('session destroyed on logout', PHP_SESSION_NONE, session_status());

// ── Session hardening invariants ─────────────────────────────────────────────
$params = session_get_cookie_params();
T::ok('session cookie is HttpOnly', $params['httponly'] === true);
T::ok('session cookie is SameSite=Strict', ($params['samesite'] ?? '') === 'Strict');
T::eq('session cookie is session-scoped', 0, $params['lifetime']);
T::ok('session name is app-specific', SESSION_NAME === 'ddmgmt');

// Logout must invalidate sensitive state: a reveal armed before logout is
// unreachable afterwards.
$_SESSION = [];
start_secure_session();
$_SESSION['reveal'] = ['type' => 'preparing', 'ts' => time()];
generate_csrf();
admin_logout();
start_secure_session();
T::ok('logout wipes any pending reveal state', empty($_SESSION['reveal']));
T::ok('logout wipes the CSRF token', empty($_SESSION['csrf_token']));
admin_logout();

// ── Passwordless account: username alone must NOT reach the setup step ──────
$_SESSION = [];
start_secure_session(); // logout above destroyed the session
$db->prepare("DELETE FROM users WHERE username = 't_auth_pending'")->execute();
$db->prepare("INSERT INTO users (username, password_hash, role, enrollment_hash, enrollment_expires)
              VALUES ('t_auth_pending', '', 'courier', ?, NOW() + INTERVAL 24 HOUR)")
   ->execute([enrollment_secret_hash('ENROLL-CODE-123')]);
$pendingId = (int)$db->lastInsertId();

$_SESSION = [];
$_POST = ['enrollment' => 'WRONG-CODE'];
T::eq('wrong enrollment secret fails', 'fail', admin_login('t_auth_pending', ''));
T::ok('failed claim leaves no pending setup', empty($_SESSION['pending_setup_user_id']));

$_POST = [];
T::eq('missing enrollment secret fails', 'fail', admin_login('t_auth_pending', ''));
T::eq('non-empty password on unclaimed account fails', 'fail', admin_login('t_auth_pending', 'whatever'));

$_POST = ['enrollment' => 'ENROLL-CODE-123'];
T::eq('valid enrollment secret arms setup', 'need_setup', admin_login('t_auth_pending', ''));
T::eq('pending setup user recorded', $pendingId, (int)$_SESSION['pending_setup_user_id']);

// Expired secret is worthless even if it matches
$db->prepare('UPDATE users SET enrollment_expires = NOW() - INTERVAL 1 HOUR WHERE id = ?')->execute([$pendingId]);
$_SESSION = [];
T::eq('expired enrollment secret fails', 'fail', admin_login('t_auth_pending', ''));

// ── Single active session ───────────────────────────────────────────────────
$db->prepare("DELETE FROM users WHERE username = 't_auth_sess'")->execute();
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_auth_sess', ?, 'owner')")->execute([$hash]);
$sessId = (int)$db->lastInsertId();

$_SESSION = [];
start_secure_session();
T::eq('first login ok', 'ok', admin_login('t_auth_sess', 'CorrectHorse1!'));
$s1 = session_id();
T::eq('login records the session id', $s1,
    $db->query("SELECT active_session_id FROM users WHERE id = $sessId")->fetchColumn());

T::eq('second login ok', 'ok', admin_login('t_auth_sess', 'CorrectHorse1!'));
$s2 = session_id();
T::ok('second login rotates the session id', $s2 !== $s1);
T::eq('record follows the latest login', $s2,
    $db->query("SELECT active_session_id FROM users WHERE id = $sessId")->fetchColumn());

// Predicate: the live session matches the record — not superseded.
T::ok('current session not superseded', !admin_session_superseded());
// A newer login elsewhere moves the record forward; this session is stale.
$db->prepare('UPDATE users SET active_session_id = ? WHERE id = ?')->execute(['elsewhere-sid', $sessId]);
T::ok('stale record reads as superseded', admin_session_superseded());
// Pre-rollout NULL rows and the config-fallback owner never trip it.
$db->prepare('UPDATE users SET active_session_id = NULL WHERE id = ?')->execute([$sessId]);
T::ok('NULL record never superseded', !admin_session_superseded());
$_SESSION['user_id'] = 0;
T::ok('config-fallback owner never superseded', !admin_session_superseded());
$_SESSION = [];
$db->prepare('DELETE FROM users WHERE id = ?')->execute([$sessId]);

// ── Account state behind a session ──────────────────────────────────────────
// A session is only as good as the account it was issued to: role and 2FA
// flag come from the row on every request, a deleted account is refused, and
// the owner can revoke every session of an account at once.
$db->prepare("DELETE FROM users WHERE username = 't_auth_state'")->execute();
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_auth_state', ?, 'courier')")->execute([$hash]);
$stId = (int)$db->lastInsertId();
$_SESSION = [];
start_secure_session();
$_SESSION['user_id']      = $stId;
$_SESSION['user_role']    = 'owner';   // a stale/forged cookie value
$_SESSION['totp_enabled'] = true;
T::eq('live account reads ok', 'ok', admin_session_status());
T::eq('role follows the account row, not the session copy', 'courier', $_SESSION['user_role']);
T::ok('2FA flag follows the account row', $_SESSION['totp_enabled'] === false);

admin_revoke_sessions($stId); // acting on one's OWN account keeps this session
T::eq('own revoke keeps the acting session', 'ok', admin_session_status());
$_SESSION['user_id'] = 0;      // now act as someone else revoking $stId
admin_revoke_sessions($stId);
$_SESSION['user_id'] = $stId;
T::eq('revoked account is refused', 'revoked', admin_session_status());
T::ok('revoked counts as superseded', admin_session_superseded());
T::eq('revoke ignores non-positive ids', null, admin_revoke_sessions(0));

$db->prepare('DELETE FROM users WHERE id = ?')->execute([$stId]);
T::eq('deleted account is gone', 'gone', admin_session_status());
T::ok('gone is not "superseded" (require_admin acts on it separately)', !admin_session_superseded());
$_SESSION['user_id'] = 0;
T::eq('config-fallback owner reads ok', 'ok', admin_session_status());
$_SESSION = [];

// ── Flash messages: credentials are sealed at rest ─────────────────────────
start_secure_session();
flash_set('plain notice', false);
T::eq('plain flash round-trips', ['plain notice', false], flash_take());
flash_set('Password: SeCr3t&Pass!', true, true);
T::ok('sensitive flash never rests in plaintext', !str_contains(json_encode($_SESSION), 'SeCr3t'));
T::eq('sealed flash round-trips', ['Password: SeCr3t&Pass!', true], flash_take());
T::eq('flash is consumed', ['', false], flash_take());
$_SESSION = [];

T::ok('72-byte password is accepted', password_length_ok(str_repeat('a', 72)));
T::ok('73-byte password is refused (bcrypt would truncate)', !password_length_ok(str_repeat('a', 73)));

// Self-service changes re-prove the current password (hijacked owner session
// must not strip 2FA / swap the password); other accounts need no re-auth.
$db->prepare("DELETE FROM rate_limits WHERE scope = 'admin_reauth'")->execute();
$_SESSION = ['user_id' => $ownerId, 'user_role' => 'owner'];
T::ok('own account: wrong current password refused', !admin_self_reauth_ok($ownerId, 'wrong'));
T::ok('own account: missing current password refused', !admin_self_reauth_ok($ownerId, ''));
T::ok('own account: correct current password accepted', admin_self_reauth_ok($ownerId, 'CorrectHorse1!'));
T::ok('another account: owner recovery path needs no re-auth', admin_self_reauth_ok($courierId, ''));
$db->prepare("DELETE FROM rate_limits WHERE scope = 'admin_reauth'")->execute();
$_SESSION = [];
// The IP-limiting switch only covers public budgets; authentication ones stay.
T::ok('rate-limit switch covers the public budget', rl_scope_switchable('public'));
T::ok('rate-limit switch never disables 2FA budgets', !rl_scope_switchable('admin_2fa_acct'));

// Cleanup
$_POST = [];
$db->prepare('DELETE FROM users WHERE id = ?')->execute([$pendingId]);
$db->prepare('DELETE FROM users WHERE id IN (?, ?)')->execute([$ownerId, $courierId]);

// ── Session fallback dir: uncreatable means hands off ─────────────────────
// When the effective session path is unusable (a file squats here, so it is
// settable but never a directory) AND the app-local fallback cannot be
// created either, the helper must leave the configured path alone instead
// of pointing sessions at a file.
$localDir = dirname(__DIR__) . '/cache/sessions';
if (!is_dir($localDir)) {
    // Fallback dir missing anyway: nothing to squat (the helper would just
    // create it — covered by the setup suite's session tests).
    T::ok('fallback squat skipped (no dir to block)', true);
} else {
    $prevSavePath = (string)@ini_get('session.save_path');
    $probeFile = sys_get_temp_dir() . '/ddmgmt_sesprobe_' . getmypid();
    file_put_contents($probeFile, 'x');
    rename($localDir, $localDir . '.probe_bak');
    file_put_contents($localDir, 'squat');
    // A live session locks save_path: close it so the probe path is settable
    // (nothing below needs the session — only cleanup queries remain).
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    try {
        @ini_set('session.save_path', $probeFile);
        session_save_path_ensure();
        T::eq('uncreatable fallback leaves save_path alone',
            $probeFile, (string)@ini_get('session.save_path'));
    } finally {
        @ini_set('session.save_path', $prevSavePath);
        @unlink($localDir);
        rename($localDir . '.probe_bak', $localDir);
        @unlink($probeFile);
    }
}

// ── Admin guard: no session means exit, never fall-through ─────────────────
// (Child process: the guard exits, exactly like the next request would.)
$devnull = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
$guardOut = shell_exec(
    escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/_admin_guard.php') . " 2>$devnull"
) ?: '';
T::eq('logged-out admin never passes the guard', '', $guardOut);

exit(T::done());
