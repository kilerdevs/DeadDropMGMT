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
T::ok('style.css: ...and no phone override turns it back into an overlay',
      !preg_match('/@media[^{]*\{\s*\.osm-monit\s*\{[^}]*(position:|z-index|top:|left:|right:)/', $css));
// It is a caption for the map: included directly under it, never at the top.
foreach ([
    '/admin/new_order.php' => ['id="map-picker"', 'osm_monit.php', 'id="coords-display"'],
    '/admin/edit.php'      => ['id="map-picker"', 'osm_monit.php', 'id="coords-display"'],
    '/admin/settings.php'  => ['id="mz-map"', 'osm_monit.php', 'id="mz-overlap"'],
] as $file => [$map, $inc, $next]) {
    $src = (string)file_get_contents($root . $file);
    $pm = strpos($src, $map); $pi = strpos($src, $inc); $pn = strpos($src, $next);
    T::ok("$file: the OSM strip sits directly under the map", $pm !== false && $pi !== false && $pn !== false
        && $pm < $pi && $pi < $pn && substr_count($src, 'osm_monit.php') === 1);
}
$mon = (string)file_get_contents($root . '/admin/osm_monit.php');
T::ok('failover detail sits on its own capped line', str_contains($mon, 'osm-monit-detail') && str_contains($mon, 'sk.slice(0, 3)'));
// Zone colours: the palette the PHP constant, the CSS swatch classes and the
// map layers all use must agree, or a row and its rectangle would differ.
foreach (MAPS_ZONE_COLORS as $i => $hex) {
    T::ok("style.css: .mz-c$i carries the palette colour $hex",
          preg_match('/\.mz-c' . $i . '\s*\{\s*--zc:\s*' . preg_quote($hex, '/') . '\s*;/', $css) === 1);
}
T::ok('style.css: swatches and status text are coloured from data attributes, not inline styles',
      str_contains($css, '.mz-swatch') && str_contains($css, 'tr[data-status="ready"] .mz-status')
      && str_contains($css, 'tr[data-status]:not([data-status="ready"]) .mz-swatch'));
T::ok('settings: rows carry the colour class and a swatch (server-rendered and re-rendered by the poll)',
      str_contains($set, 'class="mz-c<?= maps_zone_color_index(') && substr_count($set, 'mz-swatch') >= 2
      && str_contains($set, "tr.className = 'mz-c' + (z.id % MZ_PALETTE.length)"));
T::ok('settings: map layers take the zone colour and dash the zones that are not ready',
      str_contains($set, 'var MZ_PALETTE = <?= json_encode(MAPS_ZONE_COLORS) ?>;')
      && str_contains($set, "dashArray: ready ? null : '6 4'") && str_contains($set, 'MZ_PALETTE[b.id % MZ_PALETTE.length]'));
// Notifications must fit any screen: they wrap and are capped to the viewport
// (a one-line, nowrap toast ran off a phone's edge), and long ones stay up
// long enough to read.
T::ok('style.css: .save-popup wraps and is capped to the viewport',
      preg_match('/\.save-popup\s*\{[^}]*\}/', $css, $sp) === 1
      && !str_contains($sp[0], 'nowrap') && preg_match('/white-space:\s*normal/', $sp[0]) === 1
      && preg_match('/max-width:\s*92vw/', $sp[0]) === 1 && preg_match('/max-height:\s*80vh/', $sp[0]) === 1
      && preg_match('/overflow-wrap:\s*anywhere/', $sp[0]) === 1);
foreach (['/admin/settings.php', '/admin/edit.php'] as $f) {
    T::ok("$f: popup time scales with message length",
          str_contains((string)file_get_contents($root . $f), 'msg.length * 55')
          || str_contains((string)file_get_contents($root . $f), 'String(msg).length * 55'));
}
// Settings POSTs: ONE queue, token-safe. Direct fetches would let two requests
// race the rotating CSRF token (one rejected, a late reply restoring a stale one).
T::eq('settings: no page request bypasses the shared POST queue', 0,
      preg_match_all("#fetch\\('/admin/(save_setting|proxy_action|maps_action)\\.php'#", $set));
T::ok('settings: save, proxy and zone actions all go through postForm()',
      substr_count($set, "postForm('/admin/") === 3 && str_contains($set, 'window.ddmgmtFreshCsrf().then(send)'));
T::ok('settings: an empty zone name is caught in the browser and points at the field',
      str_contains($set, 'mzNameProblem(I.mz_name_required)') && str_contains($set, 'id="mz-name-error"')
      && str_contains($set, "el.scrollIntoView({ block: 'center'"));
T::ok('style.css: the marked field and its message are styled',
      str_contains($css, '.mz-field-error') && str_contains($css, 'input.mz-invalid'));
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
