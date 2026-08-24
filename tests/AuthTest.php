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

// Failed logins leave no session
$_SESSION = [];
T::eq('wrong password returns fail', 'fail', admin_login('t_auth_owner', 'wrong-password'));
T::ok('failed login leaves session empty', empty($_SESSION['user_id']));
T::eq('unknown user returns fail', 'fail', admin_login('no_such_user', 'CorrectHorse1!'));

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

// Cleanup
$_POST = [];
$db->prepare('DELETE FROM users WHERE id = ?')->execute([$pendingId]);
$db->prepare('DELETE FROM users WHERE id IN (?, ?)')->execute([$ownerId, $courierId]);

exit(T::done());
