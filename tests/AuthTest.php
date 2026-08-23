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

// Cleanup
$db->prepare('DELETE FROM users WHERE id IN (?, ?)')->execute([$ownerId, $courierId]);

exit(T::done());
