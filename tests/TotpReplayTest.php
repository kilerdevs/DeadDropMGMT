<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── TOTP counters burn once ───────────────────────────────────────────────────
// A code stays valid ~90 s for its FIRST presentation only: the conditional
// UPDATE is the atomic test-and-set, so a replay (or a concurrent double
// submit) claims nothing. Older counters never come back either.

$db = get_db();
$name = 'totpreplay_' . getmypid();
$db->prepare('DELETE FROM users WHERE username = ?')->execute([$name]);
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, '', 'courier')")->execute([$name]);
$uid = (int)$db->lastInsertId();
T::ok('replay-test user created', $uid > 0);

$C = intdiv(time(), 30);
T::eq('first claim accepted', true, totp_claim_counter($uid, $C));
T::eq('immediate replay rejected', false, totp_claim_counter($uid, $C));
T::eq('older counter rejected', false, totp_claim_counter($uid, $C - 1));
T::eq('next counter accepted', true, totp_claim_counter($uid, $C + 1));
$stored = $db->query('SELECT totp_last_counter FROM users WHERE id = ' . $uid)->fetchColumn();
T::eq('newest counter persisted', $C + 1, (int)$stored);
T::eq('unknown user claims nothing', false, totp_claim_counter(2147483647, $C));

// The primitive reports WHICH step matched, null when none does.
$secret = totp_generate_secret();
T::eq('current code reports current counter',
    intdiv(time(), 30), totp_verify_counter($secret, totp_code($secret)));
T::eq('wrong code reports null', null, totp_verify_counter($secret, '999999999'));
T::eq('far-step code reports null (outside ±1 window)',
    null, totp_verify_counter($secret, totp_code($secret, time() - 300)));
T::eq('plain verify still accepts the current code', true, totp_verify($secret, totp_code($secret)));

$db->prepare('DELETE FROM users WHERE id = ?')->execute([$uid]);

exit(T::done());
