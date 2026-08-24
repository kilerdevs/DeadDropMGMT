<?php
declare(strict_types=1);

// ── Full-lifecycle journey against a RUNNING stack (CI docker job) ────────────
//   boot → schema → first-run owner creation → password setup → create order →
//   deliver → public lookup → password unlock → receipt confirmation →
//   assert every trace wiped
//
// Runs INSIDE the app container (docker compose exec app php docker/e2e_journey.php)
// or against any local php -S instance pointed at a scratch database:
//   JOURNEY_BASE_URL=http://127.0.0.1:8931 php docker/e2e_journey.php
// The HTTP assertions are what a real browser would see; the wipe assertions
// read the storage truth behind it.

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';

$base = getenv('JOURNEY_BASE_URL') ?: 'http://127.0.0.1';
if (substr($base, -1) === '/') {
    $base = substr($base, 0, -1);
}

// ── tiny HTTP helpers (cookie-aware, redirects NOT followed) ─────────────────
function _j(string $method, string $url, ?array $fields, string $cookie): array {
    $opts = ['http' => [
        'method'          => $method,
        'ignore_errors'   => true,
        'follow_location' => 0,
        'timeout'         => 15,
        'header'          => ($fields !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '')
                           . ($cookie !== '' ? "Cookie: $cookie\r\n" : ''),
    ]];
    if ($fields !== null) {
        $opts['http']['content'] = http_build_query($fields);
    }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0;
    $setCookie = '';
    foreach ($http_response_header ?? [] as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
        if (stripos($h, 'Set-Cookie:') === 0) {
            $pair = trim(explode(';', trim(substr($h, 11)))[0]);
            if ($pair !== '' && str_contains($pair, '=')) { $setCookie = $pair; }
        }
    }
    return [$status, $body === false ? '' : $body, $setCookie ?: $cookie];
}
function _j_get(string $url, string $cookie = ''): array            { return _j('GET', $url, null, $cookie); }
function _j_post(string $url, array $f, string $cookie = ''): array { return _j('POST', $url, $f, $cookie); }
function _j_csrf(string $body): string {
    preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $body, $m);
    return $m[1] ?? '';
}

$fail = 0;
function T(bool $cond, string $what): void {
    global $fail;
    echo ($cond ? '  ok  ' : '  FAIL') . " $what\n";
    if (!$cond) { $fail++; }
}

echo "=== DeadDropMGMT container journey ===\n";

// ── 0. boot: the public page must render ─────────────────────────────────────
[$st, $html] = _j_get("$base/");
T($st === 200 && str_contains($html, '<!DOCTYPE'), 'container serves the public page');

// ── 1. DB migration: re-running the shipped schema must be a harmless no-op
// on THIS database, in THIS container (compose loads setup.sql on first boot).
putenv('DDMGMT_TEST_DB=' . DB_NAME);
exec(
    escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/tests/schema_loader.php') . ' 2>&1',
    $migOut, $migrated
);
T($migrated === 0, 'schema re-run (migration) is idempotent here');

// ── 2. first-run owner creation ───────────────────────────────────────────────
[$st, $html, $ck] = _j_get("$base/admin/index.php");
$hasBootstrapForm = str_contains($html, 'name="username"') && !str_contains($html, 'name="password"');
T($hasBootstrapForm, 'fresh install shows the create-owner form');
$csrf = _j_csrf($html);
T($csrf !== '', 'first-run form carries a CSRF token');

$ownerName = 'journey_owner';
$ownerPass = 'JourneyOwner1!';
[$st,, $ck] = _j_post("$base/admin/bootstrap.php",
    ['csrf_token' => $csrf, 'username' => $ownerName], $ck);
T($st === 302, 'owner creation redirects to the password step');

// ── 3. finish setup: choose the password ─────────────────────────────────────
[$st, $html, $ck] = _j_get("$base/admin/setup_password.php", $ck);
$csrf = _j_csrf($html);
T($csrf !== '', 'password step reachable and armed');
[$st,, $ck] = _j_post("$base/admin/setup_password.php",
    ['csrf_token' => $csrf, 'password' => $ownerPass, 'password2' => $ownerPass], $ck);
[$st, $html, $ck] = _j_get("$base/admin/orders.php", $ck);
T($st === 200, 'login works: orders page renders');

// ── 4. create an order (explicit password, no photos) ────────────────────────
[$st, $html, $ck] = _j_get("$base/admin/new_order.php", $ck);
$csrf = _j_csrf($html);
T($csrf !== '', 'new-order form reachable');
$orderPass = 'Recipient9!';
[$st,, $ck] = _j_post("$base/admin/create.php", [
    'csrf_token'      => $csrf,
    'location'        => 'Journey drop: bench behind the station, north side',
    'lat'             => '52.2297',
    'lng'             => '21.0122',
    'instructions'    => 'under the loose plank',
    'notes'           => 'journey test order',
    'pickup_password' => $orderPass,
], $ck);
$row = get_db()->query('SELECT id, order_token, status FROM orders ORDER BY id DESC LIMIT 1')->fetch();
$token   = (string)$row['order_token'];
$orderId = (int)$row['id'];
T(strlen($token) === 16, "order created with token $token");

// ── 5. deliver the order through the admin UI ────────────────────────────────
[$st, $html, $ck] = _j_get("$base/admin/edit.php?id=$orderId", $ck);
$csrf = _j_csrf($html);
[$st,, $ck] = _j_post("$base/admin/edit.php?id=$orderId", [
    'csrf_token'   => $csrf,
    'id'           => $orderId,
    'status'       => 'delivered',
    'location'     => 'Journey drop: bench behind the station, north side',
    'lat'          => '52.2297',
    'lng'          => '21.0122',
    'instructions' => 'under the loose plank',
    'notes'        => 'journey test order',
    'new_password' => '',
], $ck);
$row = get_db()->query("SELECT status FROM orders WHERE order_token = '$token'")->fetch();
T($row !== null && $row['status'] === 'delivered', 'order delivered through the admin UI');

// ── 6. public lookup (no password) ───────────────────────────────────────────
[$st, $html, $pubCookie] = _j_post("$base/", ['order_token' => $token], '');
T($st === 200 && str_contains($html, 'status-badge delivered'), 'recipient sees the delivered badge');

// ── 7. password unlock → reveal ──────────────────────────────────────────────
[$st,, $pubCookie] = _j_post("$base/",
    ['order_token' => $token, 'pickup_password' => $orderPass], $pubCookie);
T($st === 302, 'correct pickup password redirects (PRG)');
[$st, $html] = _j_get("$base/", $pubCookie);
T(str_contains($html, 'Journey drop: bench behind the station'), 'reveal shows the decrypted location');
$rcsrf = _j_csrf($html);
T($rcsrf !== '', 'reveal page offers the receipt confirmation form');

// ── 8. receipt confirmation (step 1 + step 2) ────────────────────────────────
[$st, $html, $pubCookie] = _j_post("$base/receive.php",
    ['csrf_token' => $rcsrf, 'order_token' => $token, 'step' => '1'], $pubCookie);
T(str_contains($html, $token), 'confirmation page names the token');
$rcsrf2 = _j_csrf($html);
[$st, $html] = _j_post("$base/receive.php",
    ['csrf_token' => $rcsrf2, 'order_token' => $token, 'step' => '2'], $pubCookie);
T(str_contains($html, 'delivered'), 'receipt confirmed (done page)');

// ── 9. assert wiped: the receipt must leave NOTHING behind ───────────────────
$db = get_db();
T((int)$db->query("SELECT COUNT(*) FROM orders WHERE order_token = '$token'")->fetchColumn() === 0,
    'order row gone');
T((int)$db->query("SELECT COUNT(*) FROM order_photos WHERE order_id = '$orderId'")->fetchColumn() === 0,
    'photo rows gone');
T((int)$db->query("SELECT COUNT(*) FROM order_events WHERE order_token = '$token'")->fetchColumn() >= 1,
    'event log recorded the lifecycle');
$uploadsDir = dirname(__DIR__) . '/uploads/' . $orderId;
T(!is_dir($uploadsDir) || count(glob($uploadsDir . '/*')) === 0, 'no orphaned upload files');
[$st, $html] = _j_post("$base/", ['order_token' => $token], '');
T(str_contains($html, 'class="alert"'), 'public lookup now reports the order unknown');

// Reveal cannot be replayed from the same session either.
[$st, $html] = _j_get("$base/", $pubCookie);
T(!str_contains($html, 'Journey drop: bench behind the station'), 'reveal does not survive the receipt');

echo $fail === 0 ? "\nJourney complete — all assertions passed.\n" : "\nJourney FAILED: $fail assertion(s).\n";
exit($fail === 0 ? 0 : 1);
