<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Build provenance: interpretation and who gets to see it ───────────────────
// A build is a release only when it sits exactly on a v* tag with a clean
// tree; commits after the tag (a build from dev), a dirty tree, or no tag to
// compare against make it a beta. No provenance file means "unknown" — no
// claim either way. The line is shown to owners on Settings and nowhere
// else. The file's text is untrusted: validated on read, escaped on output.

$doc = static fn(array $o): string => (string)json_encode($o);
$sha = '610eff73772a939d6304a9c8316103d586aa2d2b';

// ── parse ────────────────────────────────────────────────────────────────────
$rel = build_info_parse($doc(['describe' => 'v1.5.0-0-g610eff7', 'commit' => $sha, 'branch' => '', 'dirty' => false]));
T::ok('exact tag + clean tree is a release', $rel['known'] && $rel['release'] && !$rel['beta']);
T::eq('release version', '1.5.0', $rel['version']);
T::eq('release ahead count', 0, $rel['ahead']);

$dev = build_info_parse($doc(['describe' => 'v1.5.0-8-g610eff7', 'commit' => $sha, 'branch' => 'dev', 'subject' => 'Fix things', 'dirty' => false]));
T::ok('a commit message in the file is ignored, never surfaced', !in_array('Fix things', $dev, true) && !array_key_exists('subject', $dev));
T::ok('commits after the tag are a beta', $dev['known'] && $dev['beta'] && !$dev['release']);
T::eq('beta keeps the base version', '1.5.0', $dev['version']);
T::eq('beta ahead count', 8, $dev['ahead']);
T::eq('short commit name', '610eff7', $dev['commit']);
T::eq('branch kept', 'dev', $dev['branch']);

$dirty = build_info_parse($doc(['describe' => 'v1.5.0-0-g610eff7', 'commit' => $sha, 'dirty' => true]));
T::ok('a dirty tree on a tag is a beta', $dirty['beta'] && $dirty['dirty'] && !$dirty['release']);

$notag = build_info_parse($doc(['describe' => '610eff7', 'commit' => $sha, 'branch' => 'dev']));
T::ok('no tag to compare against: beta with no version', $notag['known'] && $notag['beta'] && $notag['version'] === null);

foreach (['' => 'empty', 'not json' => 'garbage', '[]' => 'empty list', '{"describe":"v1.5.0-0-g1"}' => 'sha too short'] as $raw => $what) {
    $u = build_info_parse((string)$raw);
    T::ok("unusable file ($what) is unknown, not a claim", !$u['known'] && !$u['beta'] && !$u['release']);
}

$hostile = build_info_parse($doc([
    'describe' => 'v1.5.0-3-g610eff7', 'commit' => $sha,
    'branch'   => 'dev"><script>alert(1)</script>',
]));
T::eq('unsafe branch name is dropped', null, $hostile['branch']);

// ── rendering + audience (HTTP) ──────────────────────────────────────────────
$file = sys_get_temp_dir() . '/ddmgmt_build_' . getmypid() . '.json';
putenv('DDMGMT_BUILD_INFO_FILE=' . $file); // inherited by the server process below
// A free port, not a fixed one: a stale server from an earlier run would keep
// answering with ITS environment (and its build-info file) instead of ours.
$probe = stream_socket_server('tcp://127.0.0.1:0');
$port = (int)explode(':', (string)stream_socket_get_name($probe, false))[1];
fclose($probe);
$root = dirname(__DIR__);
$cmd  = escapeshellarg(PHP_BINARY)
      . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
      . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
register_shutdown_function(function () use ($proc, $file): void {
    @unlink($file);
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
    get_db()->prepare("DELETE FROM users WHERE username = 't_ver_owner'")->execute();
});
$B = "http://127.0.0.1:$port";

function _vr(string $method, string $url, ?array $f, string $ck): array {
    $opts = ['http' => [
        'method' => $method, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 15,
        'header' => ($f !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '')
                  . ($ck !== '' ? "Cookie: $ck\r\n" : ''),
    ]];
    if ($f !== null) { $opts['http']['content'] = http_build_query($f); }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0; $sc = '';
    $headers = function_exists('http_get_last_response_headers')
        ? (http_get_last_response_headers() ?? [])
        : ($http_response_header ?? []);
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
    try { [$st] = _vr('GET', "$B/healthz.php", null, ''); if ($st === 200) { $up = true; break; } }
    catch (Throwable) { }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) { exit(T::done()); }

$db = get_db();
$db->prepare("DELETE FROM users WHERE username = 't_ver_owner'")->execute();
$db->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
   ->execute(['t_ver_owner', password_hash('VerPass123!', PASSWORD_BCRYPT), 'owner']);
[, $b, $ck] = _vr('GET', "$B/admin/index.php", null, '');
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $b, $m);
[$st, , $ck] = _vr('POST', "$B/admin/login.php",
    ['csrf_token' => $m[1] ?? '', 'username' => 't_ver_owner', 'password' => 'VerPass123!'], $ck);
T::eq('owner logged in', 302, $st);

$settings = static function () use ($B, &$ck): string {
    [$st, $body, $ck] = _vr('GET', "$B/admin/settings.php", null, $ck);
    return $st === 200 ? $body : '';
};

file_put_contents($file, $doc(['describe' => 'v1.5.0-8-g610eff7', 'commit' => $sha, 'branch' => 'dev',
    'subject' => 'Tricky <b>subject</b> & "quotes"', 'dirty' => true]));
$html = $settings();
T::ok('beta build: version line rendered with the offset', str_contains($html, 'v1.5.0+8'));
T::ok('beta build: BETA badge shown', str_contains($html, 'class="beta-badge"'));
T::ok('beta build: commit hash shown', str_contains($html, '<code>610eff7</code>'));
T::ok('beta build: commit message not displayed', !str_contains($html, 'Tricky') && !str_contains($html, 'subject</b>'));
preg_match('#<span class="version-commit">(.*?)</span>\s*</div>#s', $html, $vc);
$line = trim(preg_replace('/\s+/', ' ', html_entity_decode(strip_tags($vc[1] ?? ''), ENT_QUOTES, 'UTF-8')));
T::eq('beta build: hash, branch and local-changes note on ONE line', '610eff7 · dev · local changes', $line);
T::ok('beta build: that line contains no line break', !str_contains($vc[1] ?? "\n", "\n"));

file_put_contents($file, $doc(['describe' => 'v1.5.0-0-g610eff7', 'commit' => $sha, 'branch' => '', 'dirty' => false]));
$html = $settings();
T::ok('release build: plain version', str_contains($html, '>v1.5.0<'));
T::ok('release build: no BETA badge', !str_contains($html, 'class="beta-badge"'));
T::ok('release build: no commit line', !str_contains($html, 'class="version-commit"'));

@unlink($file);
$html = $settings();
T::ok('no provenance file: says unknown, no badge', str_contains($html, 'class="version-muted"') && !str_contains($html, 'class="beta-badge"'));

// Audience: never on a public or unauthenticated surface.
file_put_contents($file, $doc(['describe' => 'v1.5.0-8-g610eff7', 'commit' => $sha, 'branch' => 'dev']));
foreach (['/', '/healthz.php', '/admin/index.php', '/receive.php'] as $path) {
    [, $body] = _vr('GET', "$B$path", null, '');
    T::ok("$path does not disclose the build", !str_contains($body, '610eff7') && !str_contains($body, 'beta-badge'));
}
[$st, $body] = _vr('GET', "$B/admin/settings.php", null, '');
T::ok('settings without a session redirects, discloses nothing', $st === 302 && !str_contains($body, '610eff7'));

exit(T::done());
