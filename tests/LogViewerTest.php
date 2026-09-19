<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Settings log viewer ───────────────────────────────────────────────────────
// "Verify integrity" checks the structured, hash-chained log — but the viewer
// used to show only PHP's raw error file, so a passing check over "2 entries"
// sat under a panel that said the log was empty. The viewer now lists the
// structured entries (the ones the check covers) and keeps the raw error file
// as a second section.

// ── unit: summary + reader ───────────────────────────────────────────────────
T::eq('summary: event, message, then context', 'proxy_replaced  replaced 2 of 2  replaced=2  dead=2',
      log_entry_summary(['ts' => 'x', 'level' => 'info', 'event' => 'proxy_replaced', 'msg' => 'replaced 2 of 2',
                         'ip' => null, 'user' => null, 'req' => 'cli', 'replaced' => 2, 'dead' => 2, 'prev' => 'p', 'seq' => 9, 'hash' => 'h']));
T::ok('summary: chain fields and empties are hidden',
      !str_contains(log_entry_summary(['event' => 'e', 'msg' => '', 'prev' => 'abc', 'hash' => 'def', 'seq' => 1, 'ip' => null]), 'abc'));
T::ok('summary: long values are cut', mb_strlen(log_entry_summary(['event' => 'e', 'blob' => str_repeat('z', 900)])) <= 400);

$tmp = sys_get_temp_dir() . '/ddmgmt_viewer_' . getmypid() . '.log';
$rows = [];
for ($i = 1; $i <= 5; $i++) {
    $rows[] = json_encode(['ts' => "2026-09-19T09:0$i:00.000Z", 'level' => $i === 3 ? 'error' : 'info',
                           'event' => "ev$i", 'msg' => "m$i", 'seq' => $i, 'hash' => 'h', 'prev' => 'p']);
}
$rows[] = 'this is not json';
file_put_contents($tmp, implode("\n", $rows) . "\n");
$v = log_recent_entries(4, $tmp);
T::eq('reader: total counts every line', 6, $v['total']);
T::eq('reader: limit applies', 4, count($v['entries']));
T::eq('reader: newest first (non-JSON line shown raw, not hidden)', 'raw', $v['entries'][0]['level']);
T::eq('reader: then the newest record', 5, $v['entries'][1]['seq']);
T::eq('reader: timestamp made readable', '2026-09-19 09:05:00', $v['entries'][1]['ts']);
T::eq('reader: level kept', 'error', log_recent_entries(6, $tmp)['entries'][3]['level']);
T::eq('reader: missing file', ['total' => 0, 'entries' => []], log_recent_entries(10, $tmp . '.nope'));
@unlink($tmp);

// ── HTTP: what the owner actually sees ───────────────────────────────────────
$probe = stream_socket_server('tcp://127.0.0.1:0');
$port = (int)explode(':', (string)stream_socket_get_name($probe, false))[1];
fclose($probe);
$cmd = escapeshellarg(PHP_BINARY)
    . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
    . " -S 127.0.0.1:$port -t " . escapeshellarg(dirname(__DIR__));
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
$prevShow = get_setting('show_error_log', '0');
$teardown = t_teardown(function () use ($proc, $prevShow): void {
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
    $db = get_db();
    $db->prepare("DELETE FROM users WHERE username = 't_lv_owner'")->execute();
    set_setting('show_error_log', $prevShow);
});
$B = "http://127.0.0.1:$port";

function _lv(string $method, string $url, ?array $f, string $ck): array {
    $opts = ['http' => [
        'method' => $method, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 15,
        'header' => ($f !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '')
                  . ($ck !== '' ? "Cookie: $ck\r\n" : ''),
    ]];
    if ($f !== null) { $opts['http']['content'] = http_build_query($f); }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0; $sc = '';
    $headers = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
    foreach ($headers as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
        if (stripos($h, 'Set-Cookie:') === 0) {
            $c = trim(explode(';', trim(substr($h, 11)))[0]);
            if ($c !== '' && str_contains($c, '=')) { $sc = $c; }
        }
    }
    return [$status, $body === false ? '' : $body, $sc ?: $ck];
}

$up = false;
for ($i = 0; $i < 50; $i++) {
    [$st] = _lv('GET', "$B/healthz.php", null, '');
    if ($st === 200) { $up = true; break; }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) { $teardown(); exit(T::done()); }

$db = get_db();
$db->prepare("DELETE FROM users WHERE username = 't_lv_owner'")->execute();
$db->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
   ->execute(['t_lv_owner', password_hash('LvPass123!', PASSWORD_BCRYPT), 'owner']);
[, $b, $ck] = _lv('GET', "$B/admin/index.php", null, '');
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $b, $m);
[$st, , $ck] = _lv('POST', "$B/admin/login.php", ['csrf_token' => $m[1] ?? '', 'username' => 't_lv_owner', 'password' => 'LvPass123!'], $ck);
T::eq('owner logged in', 302, $st);

set_setting('show_error_log', '1');
log_warn('viewer_probe', ['msg' => 'hello <b>x</b>', 'k' => 'v']);
[$valid, $checked] = verify_log_chain();
T::ok('the chain verifies and covers at least the entry just written', $valid && $checked >= 1);

[$st, $html] = _lv('GET', "$B/admin/settings.php", null, $ck);
T::eq('settings renders', 200, $st);
T::ok('structured entries are listed', str_contains($html, 'viewer_probe'));
T::ok('entry text is escaped', str_contains($html, 'hello &lt;b&gt;x&lt;/b&gt;') && !str_contains($html, 'hello <b>x</b>'));
T::ok('context shown as key=value', str_contains($html, 'k=v'));
T::ok('level styled', str_contains($html, 'log-line--warn'));
T::ok('the verify button sits with the structured log, before the raw error log',
      strpos($html, 'id="verify-log-btn"') !== false
      && strpos($html, 'id="verify-log-btn"') < strpos($html, 'value="clear_log"'));
T::ok('the raw PHP error log stays a separate section, after the structured one',
      strpos($html, 'app-log-view') < strpos($html, 'value="clear_log"'));
T::ok('the structured log can be downloaded', str_contains($html, 'download_log.php?file=app'));

set_setting('show_error_log', '0');
[, $html] = _lv('GET', "$B/admin/settings.php", null, $ck);
T::ok('viewer is hidden when the setting is off', !str_contains($html, 'app-log-view') && !str_contains($html, 'id="verify-log-btn"'));
$teardown();
exit(T::done());
