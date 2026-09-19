<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Admin shell contract that the mobile layout depends on ────────────────────
// Three regressions this pins, all invisible to a desktop render:
//   1. admin.js builds the mobile menu button. new_order.php loaded it only on
//      the Leaflet (OSM) path, so a self-hosted-map install had no menu on
//      phones at all — and no live-CSRF refresh on the create form either.
//   2. The OSM proxy badge sets display:flex, which beat the [hidden]
//      attribute, so it was always on screen. It must not even be rendered
//      unless the map is OSM and proxy routing is enabled.
//   3. style.css must let [hidden] win, and the proxy/zone lists must not keep
//      the blanket 580px table min-width that turned .main into a sideways
//      scroller on the settings page.

$port = 8946;
$root = dirname(__DIR__);
$cmd  = escapeshellarg(PHP_BINARY)
      . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
      . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
$stopServer = t_teardown(function () use ($proc): void {
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

function _am(string $method, string $url, ?array $f, string $ck): array {
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
    try { [$st] = _am('GET', "$B/healthz.php", null, ''); if ($st === 200) { $up = true; break; } }
    catch (Throwable) { }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) { $stopServer(); exit(T::done()); }

$db = get_db();
$db->prepare("DELETE FROM users WHERE username = 't_am_owner'")->execute();
$db->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
    ->execute(['t_am_owner', password_hash('AmPass123!', PASSWORD_BCRYPT), 'owner']);

$saved = [
    'map_provider'      => get_setting('map_provider', 'osm'),
    'osm_proxy_enabled' => get_setting('osm_proxy_enabled', '0'),
];
$restoreSettings = t_teardown(static function () use ($saved): void {
    foreach ($saved as $k => $v) { set_setting($k, $v); }
});

[, $b, $ck] = _am('GET', "$B/admin/index.php", null, '');
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $b, $m);
[$st, , $ck] = _am('POST', "$B/admin/login.php",
    ['csrf_token' => $m[1] ?? '', 'username' => 't_am_owner', 'password' => 'AmPass123!'], $ck);
T::eq('owner logged in', 302, $st);

$page = static function (string $provider, string $proxy, string $path) use ($B, &$ck): string {
    set_setting('map_provider', $provider);
    set_setting('osm_proxy_enabled', $proxy);
    [$st, $body, $ck] = _am('GET', "$B$path", null, $ck);
    return $st === 200 ? $body : '';
};

foreach (['/admin/new_order.php'] as $path) {
    foreach ([['selfhosted', '0'], ['selfhosted', '1'], ['osm', '0'], ['osm', '1']] as [$prov, $px]) {
        $html = $page($prov, $px, $path);
        $tag  = "$path $prov proxy=$px";
        T::ok("$tag renders", str_contains($html, '</html>'));
        T::ok("$tag loads admin.js (mobile menu button)", str_contains($html, 'src="/admin/admin.js"'));
        $wantBadge = $prov === 'osm' && $px === '1';
        T::eq("$tag OSM badge " . ($wantBadge ? 'rendered' : 'absent'),
              $wantBadge, str_contains($html, 'id="osm-monit"'));
    }
}

// Settings: the zone editor's OSM tiles and searches always go through the
// server (tile_proxy.php / geocode_proxy.php), so the badge that shows which
// pool proxy served them must follow the proxy toggle alone.
foreach (['0', '1'] as $px) {
    $html = $page('osm', $px, '/admin/settings.php');
    T::ok("settings proxy=$px renders", str_contains($html, '</html>'));
    T::eq("settings proxy=$px OSM badge " . ($px === '1' ? 'rendered' : 'absent'),
          $px === '1', str_contains($html, 'id="osm-monit"'));
}

// edit.php needs a real order id; reuse the same rule via the partial guard.
$src = (string)file_get_contents($root . '/admin/edit.php');
T::ok('edit.php guards the badge on provider and proxy toggle',
      str_contains($src, 'map_provider() === MAP_PROVIDER_OSM && osm_proxy_enabled()'));
$src = (string)file_get_contents($root . '/admin/new_order.php');
T::eq('new_order.php includes admin.js exactly once', 1, substr_count($src, '/admin/admin.js'));

// Zone editor gestures: mouse events never fire for a finger drag, so the
// editor must ride Pointer Events (mouse, touch and pen alike) — and the
// existing zone rectangles carry their name as a permanent label.
$set = (string)file_get_contents($root . '/admin/settings.php');
T::ok('zone editor draws with pointer events', str_contains($set, "addEventListener('pointerdown'"));
T::ok('zone editor no longer relies on Leaflet mouse events',
      !preg_match("/mzMap\.on\('mouse(down|move|up)'/", $set) && !str_contains($set, "h.on('mousedown'"));
T::ok('existing zone rectangles get a permanent name label',
      str_contains($set, 'bindTooltip(b.name, { permanent: true') && str_contains($set, "className: 'mz-zone-label'"));
T::ok('zone labels re-sync after the status poll re-renders rows',
      str_contains($set, "typeof mzSyncZoneLayers === 'function'"));

$css = (string)file_get_contents($root . '/admin/style.css');
// The OSM status strip must never be an overlay again: a fixed badge covered
// the heading and forms, and on failover (several lines) covered more.
T::ok('style.css: the OSM status strip is in the page flow, not fixed or layered',
      preg_match('/\.osm-monit\s*\{[^}]*\}/', $css, $mm) === 1
      && !preg_match('/position:\s*(fixed|absolute|sticky)|z-index/', $mm[0]));
T::ok('style.css: ...and the phone override does not turn it back into an overlay',
      preg_match('/@media \(max-width: 780px\)\s*\{\s*\.osm-monit\s*\{[^}]*\}/', $css, $mp) === 1
      && !preg_match('/position:|z-index|top:|left:|right:/', $mp[0]));
$mon = (string)file_get_contents($root . '/admin/osm_monit.php');
T::ok('failover detail sits on its own capped line', str_contains($mon, 'osm-monit-detail') && str_contains($mon, 'sk.slice(0, 3)'));
T::ok('style.css: draw mode blocks browser touch panning',
      (bool)preg_match('/\.maps-editor-map\.mz-drawing\s*\{[^}]*touch-action:\s*none/', $css));
T::ok('style.css: zone labels styled', str_contains($css, '.leaflet-tooltip.mz-zone-label'));
T::ok('style.css: [hidden] overrides component display', (bool)preg_match('/\[hidden\]\s*\{\s*display:\s*none\s*!important/', $css));
T::ok('style.css: proxy/zone lists drop the 580px table min-width on phones',
      (bool)preg_match('/@media \(max-width: 780px\).*?\.proxies-table\s*\{\s*min-width:\s*0/s', $css));

$db->prepare("DELETE FROM users WHERE username = 't_am_owner'")->execute();
$stopServer();
$restoreSettings();
exit(T::done());
