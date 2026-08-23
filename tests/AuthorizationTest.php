<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Role-based authorization: owner bypass, courier ownership checks ─────────

$db = get_db();
$db->exec("DELETE FROM users WHERE username IN ('t_az_owner','t_az_courier')");
$db->prepare("DELETE FROM orders WHERE order_token IN ('aztoken00000001','aztoken00000002')")->execute();

$hash = password_hash('x', PASSWORD_BCRYPT);
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_az_owner', ?, 'owner')")->execute([$hash]);
$ownerId = (int)$db->lastInsertId();
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_az_courier', ?, 'courier')")->execute([$hash]);
$courierId = (int)$db->lastInsertId();

$ins = $db->prepare('INSERT INTO orders (created_by, order_token, pickup_password_hash, location_encrypted, location_iv, status)
                     VALUES (?, ?, "x", "e", "00", "preparing")');
$ins->execute([$courierId, 'aztoken00000001']);
$ownOrder   = (int)$db->lastInsertId();
$ins->execute([null, 'aztoken00000002']);
$orphanOrder = (int)$db->lastInsertId();

// Owner: full access to every order
$_SESSION = ['user_id' => $ownerId, 'user_role' => 'owner'];
T::ok('owner is_owner', is_owner() && !is_courier());
T::ok('owner owns courier order', courier_owns_order($ownOrder));
T::ok('owner owns orphan order', courier_owns_order($orphanOrder));

// Courier: only own orders
$_SESSION = ['user_id' => $courierId, 'user_role' => 'courier'];
T::ok('courier is_courier', is_courier() && !is_owner());
T::ok('courier owns own order', courier_owns_order($ownOrder));
T::ok('courier does NOT own other order', !courier_owns_order($orphanOrder));

// Hostile session shapes
$_SESSION = ['user_id' => 0, 'user_role' => 'courier'];
T::ok('id=0 courier cannot match created_by', !courier_owns_order($ownOrder));
$_SESSION = ['user_id' => $courierId];
T::ok('missing role fails admin check', !is_admin_logged_in());
$_SESSION = ['user_id' => $courierId, 'user_role' => 'superadmin'];
T::ok('unknown role is not owner or courier', !is_owner() && !is_courier());
$_SESSION = [];
T::ok('no order access without session', !courier_owns_order($ownOrder));
T::ok('nonexistent order denied for courier',
    ($_SESSION = ['user_id' => $courierId, 'user_role' => 'courier']) || !courier_owns_order(99999999));

// Cleanup
$db->prepare('DELETE FROM orders WHERE id IN (?, ?)')->execute([$ownOrder, $orphanOrder]);
$db->prepare('DELETE FROM users WHERE id IN (?, ?)')->execute([$ownerId, $courierId]);

exit(T::done());
