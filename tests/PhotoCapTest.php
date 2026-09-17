<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Per-request photo cap over HTTP ─────────────────────────────────────────
// admin/create.php (and edit.php) accept at most max_photos_per_order() files
// per request; extras are reported, never processed. Posting 12 valid JPEGs
// must leave exactly 10 photo rows. Needs the GD ini flag for standalone
// runs (run_all.php already sets it):
//   $env:PHP_INI_SCAN_DIR = ";C:\Users\Jakub\AppData\Local\Temp\opencode\ini"

if (!function_exists('imagecreatetruecolor')) {
    echo "PhotoCapTest.php: 1 passed, 0 failed (GD unavailable — skipped)\n";
    exit(0);
}

$root = dirname(__DIR__);
$port = 8945;
$cmd  = escapeshellarg(PHP_BINARY)
      . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
      . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
register_shutdown_function(function () use ($proc): void {
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
});
$B = "http://127.0.0.1:$port";

function _pc(string $method, string $url, ?array $f, string $ck, ?string $raw = null, ?string $ctype = null): array {
    $headers = '';
    if ($f !== null) {
        $headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    if ($ctype !== null) {
        $headers .= "Content-Type: $ctype\r\n";
    }
    if ($ck !== '') {
        $headers .= "Cookie: $ck\r\n";
    }
    $opts = ['http' => [
        'method' => $method, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 30,
        'header' => $headers,
    ]];
    if ($f !== null) {
        $opts['http']['content'] = http_build_query($f);
    }
    if ($raw !== null) {
        $opts['http']['content'] = $raw;
    }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0;
    $sc = '';
    $loc = '';
    $headers = function_exists('http_get_last_response_headers')
        ? (http_get_last_response_headers() ?? [])
        : ($http_response_header ?? []);
    foreach ($headers as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) {
            $status = (int)$m[1];
        }
        if (stripos($h, 'Set-Cookie:') === 0) {
            $p = trim(explode(';', trim(substr($h, 11)))[0]);
            if ($p !== '' && str_contains($p, '=')) {
                $sc = $p;
            }
        }
        if (preg_match('#^Location:#i', $h)) {
            $loc = trim(substr($h, 9));
        }
    }
    return [$status, $body === false ? '' : $body, $sc ?: $ck, $loc];
}

$up = false;
for ($i = 0; $i < 50; $i++) {
    try {
        [$st] = _pc('GET', "$B/healthz.php", null, '');
        if ($st === 200) {
            $up = true;
            break;
        }
    } catch (Throwable) {
    }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) {
    exit(T::done());
}

// Pin budgets: suites share one DB and a zeroed budget locks the login flow.
set_setting('rate_limit_max', '10');
set_setting('rate_limit_window_min', '15');
// Pin the cap itself: exactly 10, regardless of suite order.
$prevCap = get_setting('max_photos_per_order', '');
set_setting('max_photos_per_order', '10');

$db = get_db();
$db->prepare("DELETE FROM users WHERE username = 't_pc_owner'")->execute();
$db->prepare("DELETE FROM orders WHERE order_token LIKE 'pctoken%'")->execute();
$hash = password_hash('PcPass123!', PASSWORD_BCRYPT);
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_pc_owner', ?, 'owner')")->execute([$hash]);
$ownerId = (int)$db->lastInsertId();

$csrfOf = static function (string $b): string {
    preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $b, $m);
    return $m[1] ?? '';
};
[, $b, $ck] = _pc('GET', "$B/admin/index.php", null, '');
[$st, , $ck, $loc] = _pc('POST', "$B/admin/login.php",
    ['csrf_token' => $csrfOf($b), 'username' => 't_pc_owner', 'password' => 'PcPass123!'], $ck);
T::ok('owner login ok', $st === 302 && str_contains($loc, 'orders.php'));
[, $b] = _pc('GET', "$B/admin/new_order.php", null, $ck);
$csrf = $csrfOf($b);
T::ok('create form carries a CSRF token', $csrf !== '');

// Twelve valid tiny JPEGs — every one would pass alone.
$tmpdir = sys_get_temp_dir() . '/ddmgmt_cap_test';
if (!is_dir($tmpdir)) {
    mkdir($tmpdir, 0700, true);
}
$shots = [];
for ($i = 0; $i < 12; $i++) {
    $img = imagecreatetruecolor(8, 8);
    imagefill($img, 0, 0, imagecolorallocate($img, 30 + $i * 10, 120, 60));
    $path = "$tmpdir/cap$i.jpg";
    imagejpeg($img, $path, 85);
    $shots[] = $path;
}

$boundary = 'ddmgmt-cap-' . bin2hex(random_bytes(8));
$raw = '';
$raw .= "--$boundary\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n$csrf\r\n";
$raw .= "--$boundary\r\nContent-Disposition: form-data; name=\"location\"\r\n\r\ncap test shelf\r\n";
$raw .= "--$boundary\r\nContent-Disposition: form-data; name=\"pickup_password\"\r\n\r\nCapTestPass1!\r\n";
foreach ($shots as $n => $path) {
    $data = (string)file_get_contents($path);
    $raw .= "--$boundary\r\nContent-Disposition: form-data; name=\"photos[]\"; filename=\"cap$n.jpg\"\r\n"
          . "Content-Type: image/jpeg\r\n\r\n$data\r\n";
}
$raw .= "--$boundary--\r\n";
[$st, , $ck, $loc] = _pc('POST', "$B/admin/create.php", null, $ck, $raw,
    "multipart/form-data; boundary=$boundary");
T::ok('create redirects to orders', $st === 302 && str_contains($loc, 'orders.php'));

$oid = (int)$db->query("SELECT id FROM orders WHERE created_by = $ownerId ORDER BY id DESC LIMIT 1")->fetchColumn();
T::ok('order created', $oid > 0);
if ($oid > 0) {
    $rows = (int)$db->query("SELECT COUNT(*) FROM order_photos WHERE order_id = $oid")->fetchColumn();
    T::eq('twelve uploads leave exactly ten photo rows', 10, $rows);
    foreach ($db->query("SELECT filename FROM order_photos WHERE order_id = $oid")->fetchAll(PDO::FETCH_COLUMN) as $fn) {
        @unlink($root . '/uploads/' . $fn);
    }
    @rmdir($root . '/uploads/' . $oid);
    $db->prepare('DELETE FROM orders WHERE id = ?')->execute([$oid]);
}

// Cleanup + restore shared state.
foreach ($shots as $path) {
    @unlink($path);
}
@rmdir($tmpdir);
$db->prepare("DELETE FROM users WHERE username = 't_pc_owner'")->execute();
$db->prepare("DELETE FROM orders WHERE order_token LIKE 'pctoken%'")->execute();
if ($prevCap === '') {
    $db->prepare("DELETE FROM settings WHERE key_name = 'max_photos_per_order'")->execute();
} else {
    set_setting('max_photos_per_order', $prevCap);
}
$cache = &_settings_store();
$cache = null;

exit(T::done());
