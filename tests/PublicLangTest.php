<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Public language choice: ?lang= → session → year-cookie → default ───────
// In-process precedence and handler rules, then end-to-end over a live PHP
// built-in server (session persistence, cookie persistence, unknown ignored).

// ── In-process: handler ────────────────────────────────────────────────────
start_secure_session();

$_GET['lang'] = 'de';
$_SESSION = [];
i18n_handle_public_lang_param();
T::eq('handler stores allowlisted code in session', 'de', $_SESSION['public_lang'] ?? null);

$_GET['lang'] = 'xx';
unset($_SESSION['public_lang']);
i18n_handle_public_lang_param();
T::ok('handler ignores unknown code', !isset($_SESSION['public_lang']));

unset($_GET['lang']);
i18n_handle_public_lang_param();
T::ok('handler ignores missing param', !isset($_SESSION['public_lang']));

$_GET['lang'] = ['de'];
i18n_handle_public_lang_param();
T::ok('handler ignores non-string param', !isset($_SESSION['public_lang']));
unset($_GET['lang']);

// ── In-process: precedence ─────────────────────────────────────────────────
$_SESSION = [];
$_COOKIE = [];
$orig_default = get_setting('default_lang', 'en');

$_SESSION['user_lang'] = 'pl';
$_SESSION['public_lang'] = 'de';
$_COOKIE[i18n_public_lang_cookie()] = 'fr';
set_setting('default_lang', 'es');
T::eq('account preference beats everything', 'pl', current_lang());

unset($_SESSION['user_lang']);
T::eq('public session beats cookie and default', 'de', current_lang());

unset($_SESSION['public_lang']);
T::eq('cookie beats site default', 'fr', current_lang());

unset($_COOKIE[i18n_public_lang_cookie()]);
T::eq('site default used when nothing chosen', 'es', current_lang());

set_setting('default_lang', 'xx');
T::eq('garbage site default collapses to en', 'en', current_lang());
set_setting('default_lang', $orig_default);

// t() renders in the chosen language.
$_SESSION = ['public_lang' => 'de'];
$_COOKIE = [];
T::eq('page strings render in chosen language',
    i18n_load('de')['public.index.title'], t('public.index.title'));
$_SESSION = [];

// ── HTTP: persistence across requests and visits ───────────────────────────
$port = 8300 + (int)(getmypid() % 400);
$root = dirname(__DIR__);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$cmd  = escapeshellarg(PHP_BINARY)
    . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
    . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $pipes);
if (!is_resource($proc)) {
    fwrite(STDERR, "cannot spawn built-in server\n");
    exit(1);
}
register_shutdown_function(static function () use ($proc): void {
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

$up = false;
for ($i = 0; $i < 30; $i++) {
    try { [$st] = _pl_get("http://127.0.0.1:$port/"); }
    catch (Throwable) { $st = 0; usleep(200000); continue; }
    if ($st === 200) { $up = true; break; }
    usleep(200000);
}
T::ok('built-in server booted', $up);
if (!$up) { exit(T::done()); }

$base = "http://127.0.0.1:$port";
$deTitle = i18n_load('de')['public.index.title'];

// Explicit choice renders immediately and plants the preference cookie.
[$st, $body, $jar, $headers] = _pl_get("$base/?lang=de");
T::eq('lang choice answers 200', 200, $st);
T::ok('choice renders in German',
    str_contains($body, '<html lang="de">') && str_contains($body, $deTitle));
$setCookies = array_values(array_filter(
    $headers, static fn (string $h): bool => stripos($h, 'Set-Cookie:') === 0));
$hasPref = false;
$prefHttpOnly = false;
$prefLax = false;
foreach ($setCookies as $h) {
    if (str_contains($h, i18n_public_lang_cookie() . '=de')) {
        $hasPref = true;
        $prefHttpOnly = stripos($h, 'httponly') !== false;
        $prefLax = stripos($h, 'samesite=lax') !== false;
    }
}
T::ok('preference cookie planted', $hasPref);
T::ok('preference cookie httponly', $prefHttpOnly);
T::ok('preference cookie samesite=lax', $prefLax);

// Same visitor, no param: the session choice persists.
[, $body2] = _pl_get("$base/", $jar);
T::ok('session keeps the choice', str_contains((string)$body2, '<html lang="de">'));

// New visitor presenting only the cookie: still German.
[, $body3] = _pl_get("$base/", i18n_public_lang_cookie() . '=de');
T::ok('cookie keeps the choice across sessions', str_contains((string)$body3, '<html lang="de">'));

// Unknown code: ignored, site default renders.
$def = default_lang();
[, $body4] = _pl_get("$base/?lang=xx");
T::ok('unknown code falls back to site default',
    str_contains((string)$body4, '<html lang="' . $def . '">')
    && !str_contains((string)$body4, '<html lang="de">'));

// Switcher control is on the page with every supported language.
[, $body5] = _pl_get($base);
T::ok('switcher select present', str_contains((string)$body5, 'name="lang"'));
$allOptions = true;
foreach (i18n_supported_langs() as $code) {
    if (!str_contains((string)$body5, 'value="' . $code . '"')) { $allOptions = false; break; }
}
T::ok('switcher offers all supported languages', $allOptions);
T::ok('switcher labels every language natively',
    str_contains((string)$body5, i18n_lang_names()['de']));

// A ?token= arrival keeps its token through the language form.
[, $body6] = _pl_get("$base/?token=DeliveredToken01XY&lang=en");
T::ok('token survives language switch', str_contains((string)$body6, 'name="token"'));

exit(T::done());

// ── tiny HTTP helpers (multi-cookie jar, no redirects followed) ─────────────

function _pl_get(string $url, string $jar = ''): array {
    return _pl_req($url, $jar);
}

function _pl_req(string $url, string $jar): array {
    $opts = [
        'http' => [
            'method'          => 'GET',
            'ignore_errors'   => true,
            'follow_location' => 0,
            'timeout'         => 15,
            'header'          => $jar !== '' ? "Cookie: $jar\r\n" : '',
        ],
        'ssl' => ['verify_peer' => false],
    ];
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0;
    $headers = function_exists('http_get_last_response_headers')
        ? (http_get_last_response_headers() ?? [])
        : ($http_response_header ?? []);
    foreach ($headers as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
    }
    return [$status, $body === false ? '' : $body, _pl_jar_merge($jar, $headers), $headers];
}

function _pl_jar_merge(string $jar, array $headers): string {
    $pairs = [];
    foreach (explode('; ', $jar) as $p) {
        if (!str_contains($p, '=')) { continue; }
        [$k, $v] = explode('=', $p, 2);
        $pairs[trim($k)] = trim($v);
    }
    foreach ($headers as $h) {
        if (stripos($h, 'Set-Cookie:') !== 0) { continue; }
        $pair = trim(explode(';', trim(substr($h, 11)))[0]);
        if (!str_contains($pair, '=')) { continue; }
        [$k, $v] = explode('=', $pair, 2);
        $pairs[trim($k)] = trim($v);
    }
    $out = [];
    foreach ($pairs as $k => $v) { $out[] = "$k=$v"; }
    return implode('; ', $out);
}
