<?php
// DeadDropMGMT web installer — ONE file. Upload to empty (or existing) hosting
// dir, open in browser, follow the wizard. Downloads the app from GitHub
// releases, extracts it, writes config.php, creates storage dirs and imports
// the schema. No sessions, no dependencies, CSS+JS embedded. Delete when done.
declare(strict_types=1);

const INST_VERSION = '1.0.0';
const INST_MASTER_ZIP = 'https://github.com/kilerdevs/DeadDropMGMT/archive/refs/heads/master.zip';
const INST_TAGS_API = 'https://api.github.com/repos/kilerdevs/DeadDropMGMT/tags';
const INST_TABLES = ['users','orders','order_photos','osm_proxies','map_zones','order_events','rate_limits','audit_log','settings','log_checkpoints'];
const INST_DIRS = ['logs','cache','cache/osm_tiles','cache/sessions','tiles','data/maps','uploads'];

// Cheap hosts disableini_set/ini_get/disk_free_space via disable_functions —
// and on PHP 8 calling one throws Error, which @ cannot suppress. So every
// such call below goes through a function_exists-guarded wrapper; the check
// step then reports "unknown" instead of white-screening.
if (function_exists('ini_set')) { @ini_set('display_errors', '0'); }
if (function_exists('error_reporting')) { @error_reporting(E_ALL & ~E_DEPRECATED); }
function eini(string $k): string { return function_exists('ini_get') ? (string)@ini_get($k) : ''; }
function edisk(string $p) { return function_exists('disk_free_space') ? @disk_free_space($p) : false; }
function pver(string $e): string { return function_exists('phpversion') ? (string)@phpversion($e) : 'unknown'; }

// String helpers are PHP 8+: polyfill so a PHP 7 host gets the readable
// "needs PHP 8.2" row instead of a parse-error blank page. (No other 8.x-only
// syntax is used in this file for the same reason.)
if (!function_exists('str_contains')) {
    function str_contains(string $h, string $n): bool { return $n === '' || strpos($h, $n) !== false; }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $h, string $n): bool { return strncmp($h, $n, strlen($n)) === 0; }
}
// php.ini shorthand ("8M", "512K", "-1") → bytes; -1/empty = unlimited.
function shorthand_bytes(string $v): int {
    $v = trim($v);
    if ($v === '' || $v === '-1') return PHP_INT_MAX;
    $u = strtolower(substr($v, -1));
    $n = (int)$v;
    if ($u === 'g') $n *= 1073741824;
    elseif ($u === 'm') $n *= 1048576;
    elseif ($u === 'k') $n *= 1024;
    return $n;
}

// ── tiny helpers ─────────────────────────────────────────────────────────────
function jout(array $d): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($d, JSON_UNESCAPED_SLASHES);
    exit;
}
function jer(string $msg, array $extra = []): void { jout(['ok' => false, 'error' => $msg] + $extra); }
function row(string $id, string $label, string $st, string $detail = ''): array {
    return ['id' => $id, 'label' => $label, 'status' => $st, 'detail' => $detail];
}
function unlimit(): void {
    if (function_exists('set_time_limit')) { try { @set_time_limit(60); } catch (Throwable) {} }
}
function base(): string { return rtrim(str_replace('\\', '/', __DIR__), '/'); }
function dl_paths(): array {
    $b = base();
    return [$b . '/.__install_dl.zip', $b . '/.__install_src'];
}
function pq(string $v): string { // php-quote for config patching
    return str_replace(['\\', "'"], ['\\\\', "\\'"], $v);
}

// ── HTTP fetch with optional proxy + manual redirect loop ────────────────────
// Transports: cURL (anything incl. SOCKS5 with remote DNS) or streams (direct
// or HTTP proxy; HTTPS-through-proxy needs cURL). Returns
// [status, headers, body] or ['error' => msg].
function http_fetch(string $url, array $proxy, string $method = 'GET'): array {
    $hops = 0;
    $headersOut = [];
    while ($hops < 8) {
        $hops++;
        $r = ($proxy['type'] === 'socks5' || ($proxy['type'] === 'http' && str_starts_with($url, 'https:')))
            && function_exists('curl_init')
            ? curl_hop($url, $proxy, $method)
            : stream_hop($url, $proxy, $method);
        if (isset($r['error'])) return $r;
        [$code, $hdrs, $body] = [$r[0], $r[1], $r[2]];
        $headersOut = $hdrs;
        if ($code >= 300 && $code < 400 && isset($hdrs['location'])) {
            $url = rel_url($url, $hdrs['location']);
            continue;
        }
        return [$code, $headersOut, $body];
    }
    return ['error' => 'too many redirects (8) — proxy loop?'];
}
function rel_url(string $base, string $loc): string {
    if (preg_match('#^https?://#i', $loc)) return $loc;
    $p = parse_url($base);
    $root = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    return str_starts_with($loc, '/') ? $root . $loc : $root . '/' . $loc;
}
function hdrs_parse(string $raw): array {
    $out = [];
    foreach (explode("\r\n", $raw) as $ln) {
        $pos = strpos($ln, ':');
        if ($pos !== false) $out[strtolower(trim(substr($ln, 0, $pos)))] = trim(substr($ln, $pos + 1));
    }
    return $out;
}
function curl_hop(string $url, array $proxy, string $method): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 25,
        CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_USERAGENT => 'DeadDropMGMT-installer/' . INST_VERSION,
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_HTTPHEADER => ['Accept: */*'],
    ]);
    if ($method === 'HEAD') curl_setopt($ch, CURLOPT_NOBODY, true);
    if ($proxy['type'] === 'http') {
        curl_setopt($ch, CURLOPT_PROXY, $proxy['host'] . ':' . $proxy['port']);
        curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    } elseif ($proxy['type'] === 'socks5') {
        curl_setopt($ch, CURLOPT_PROXY, $proxy['host'] . ':' . $proxy['port']);
        curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME); // remote DNS: no leak
    }
    if ($proxy['user'] !== '') curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxy['user'] . ':' . $proxy['pass']);
    $raw = curl_exec($ch);
    if ($raw === false) { $e = curl_error($ch); curl_close($ch); return ['error' => 'cURL: ' . $e]; }
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsz = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return [$code, hdrs_parse(substr($raw, 0, $hsz)), substr($raw, $hsz)];
}
function stream_hop(string $url, array $proxy, string $method): array {
    if ($proxy['type'] === 'socks5') return ['error' => 'SOCKS5 needs the cURL extension (missing here) — use an HTTP proxy or no proxy.'];
    if ($proxy['type'] === 'http' && str_starts_with($url, 'https:'))
        return ['error' => 'HTTPS via HTTP proxy needs cURL (missing here) — try no proxy.'];
    $h = ['User-Agent: DeadDropMGMT-installer/' . INST_VERSION, 'Accept: */*', 'Connection: close'];
    $opt = ['http' => ['method' => $method, 'header' => implode("\r\n", $h), 'timeout' => 25,
        'ignore_errors' => true, 'follow_location' => 0, 'protocol_version' => 1.1]];
    if ($proxy['type'] === 'http') {
        $opt['http']['proxy'] = 'tcp://' . $proxy['host'] . ':' . $proxy['port'];
        $opt['http']['request_fulluri'] = true;
        if ($proxy['user'] !== '') $opt['http']['header'] .= "\r\nProxy-Authorization: Basic " . base64_encode($proxy['user'] . ':' . $proxy['pass']);
    }
    $ctx = stream_context_create($opt);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false || empty($http_response_header)) return ['error' => 'connection failed (DNS / firewall / allow_url_fopen?)'];
    $code = 0;
    if (preg_match('#HTTP/\S+\s+(\d+)#', (string)$http_response_header[0], $m)) $code = (int)$m[1];
    if ($method === 'HEAD') $body = '';
    return [$code, hdrs_parse(implode("\r\n", $http_response_header)), (string)$body];
}
function read_proxy(): array {
    $t = strtolower(trim((string)($_REQUEST['proxy_type'] ?? 'none')));
    if (!in_array($t, ['none', 'http', 'socks5'], true)) $t = 'none';
    $host = trim((string)($_REQUEST['proxy_host'] ?? ''));
    $port = max(1, min(65535, (int)($_REQUEST['proxy_port'] ?? 0)));
    if ($t !== 'none' && ($host === '' || $port === 0))
        jer('proxy selected but host/port missing');
    return ['type' => $t, 'host' => $host, 'port' => $port ?: 1080,
        'user' => (string)($_REQUEST['proxy_user'] ?? ''), 'pass' => (string)($_REQUEST['proxy_pass'] ?? '')];
}

// ── capability check (mirrors includes/setup_check.php rows, standalone) ─────
function cap_checks(): array {
    $out = [];
    $out[] = version_compare(PHP_VERSION, '8.2.0', '>=')
        ? row('php', 'PHP ' . PHP_VERSION, 'ok')
        : row('php', 'PHP ' . PHP_VERSION, 'fail', 'DeadDropMGMT needs PHP 8.2+. Ask the host to switch the PHP version for this domain.');
    foreach (['pdo_mysql' => 'fail', 'mbstring' => 'fail', 'openssl' => 'warn', 'zlib' => 'warn'] as $ext => $lvl) {
        $out[] = extension_loaded($ext)
            ? row('ext_' . $ext, $ext . ' ' . pver($ext), 'ok')
            : row('ext_' . $ext, $ext . ($lvl === 'fail' ? ' MISSING' : ' missing'), $lvl,
                $lvl === 'fail' ? "Required. Enable $ext in the panel (Select PHP Version / extensions)."
                    : "Optional: without $ext some features degrade (updates need zlib).");
    }
    $hasCurl = function_exists('curl_init');
    $out[] = $hasCurl ? row('ext_curl', 'curl ' . pver('curl'), 'ok')
        : row('ext_curl', 'curl missing', 'info', 'Optional. Without cURL: no SOCKS proxy, no HTTPS-via-proxy; direct downloads use streams.');
    $fopen = filter_var(eini('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN);
    $tls = $hasCurl || ($fopen && function_exists('stream_socket_client') && extension_loaded('openssl'));
    $out[] = $tls ? row('tls', 'HTTPS transport', 'ok')
        : row('tls', 'HTTPS transport', 'fail', 'Neither cURL nor (allow_url_fopen + openssl) available — GitHub downloads are impossible. Enable cURL.');
    $out[] = $fopen ? row('fopen', 'allow_url_fopen on', 'ok')
        : row('fopen', 'allow_url_fopen off', $hasCurl ? 'info' : 'fail',
            $hasCurl ? 'Fine — cURL covers downloads.' : 'With cURL also missing, downloads cannot work.');
    $out[] = class_exists('ZipArchive') ? row('zip', 'ZipArchive', 'ok')
        : row('zip', 'ZipArchive MISSING', 'fail', 'Required to unpack the release. Enable the zip extension in the panel.');
    $w = is_writable(base());
    $out[] = $w ? row('writedir', 'directory writable', 'ok')
        : row('writedir', 'directory NOT writable', 'fail', 'The installer cannot write here. Fix ownership/permissions (755/775) or pick another dir.');
    $free = edisk(base());
    $out[] = $free === false ? row('disk', 'disk space unknown', 'info')
        : ($free > 32 * 1048576 ? row('disk', 'disk free: ' . round($free / 1048576) . ' MB', 'ok')
            : row('disk', 'disk free: ' . round($free / 1048576) . ' MB', 'fail', 'Release needs ~5 MB + room for tiles/maps. Free space first.'));
    // Upload fallback viability: the release zip is ~4 MB and panel PHP
    // builds often cap uploads at 2 MB — know BEFORE downloading fails.
    $upMax = shorthand_bytes(eini('upload_max_filesize'));
    $postMax = shorthand_bytes(eini('post_max_size'));
    $upCap = min($upMax, $postMax);
    $out[] = $upCap === PHP_INT_MAX ? row('upload', 'upload limit: unlimited', 'ok')
        : ($upCap >= 5 * 1048576 ? row('upload', 'upload limit: ' . round($upCap / 1048576) . ' MB', 'ok')
            : row('upload', 'upload limit: ' . round($upCap / 1048576) . ' MB', 'warn',
                'The ~4 MB release zip may not fit a manual upload — prefer direct download on this host.'));
    $met = eini('max_execution_time');
    $out[] = row('max_time', 'max_execution_time=' . ($met !== '' ? $met : '?'),
        ($met !== '' && (int)$met > 0 && (int)$met < 20) ? 'warn' : 'info',
        'The package downloads in one request (~4 MB); under ~20 s limits a slow link can time out — retry or upload the zip manually.');
    $out[] = function_exists('set_time_limit') ? row('set_time_limit', 'set_time_limit', 'ok')
        : row('set_time_limit', 'set_time_limit disabled', 'warn', 'Long steps run in small chunks anyway — slower but fine.');
    $out[] = function_exists('proc_open') ? row('proc_open', 'proc_open', 'ok')
        : row('proc_open', 'proc_open disabled', 'info', 'Fine — the app runs its pure-PHP maps pipeline instead.');
    $sp = eini('session.save_path');
    $out[] = ($sp === '' || is_writable($sp)) ? row('sessions', 'session path' . ($sp !== '' ? ': ' . $sp : ''), 'ok')
        : row('sessions', 'session path not writable', 'warn', 'The installer pre-creates cache/sessions and the app falls back to it automatically.');
    $sw = (string)($_SERVER['SERVER_SOFTWARE'] ?? '');
    $out[] = stripos($sw, 'apache') !== false ? row('server', $sw, 'ok')
        : row('server', $sw !== '' ? $sw : 'web server', 'warn', 'Only Apache honors .htaccess. On nginx apply docs/nginx-deaddrop.conf after install.');
    $ob = eini('open_basedir');
    if ($ob !== '') $out[] = row('open_basedir', 'open_basedir=' . $ob, 'info', 'May block temp paths outside this dir — the installer keeps everything local.');
    $out[] = row('memory', 'memory_limit=' . (eini('memory_limit') !== '' ? eini('memory_limit') : '?'), 'info');
    return $out;
}

// ── schema splitter/apply (same rules as includes/setup_check.php) ───────────
function schema_statements(string $sql, bool $keepCreate = false): array {
    $out = [];
    foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
        $body = implode("\n", array_filter(explode("\n", $stmt),
            function (string $l): bool {
                return trim($l) !== '' && !str_starts_with(ltrim($l), '--');
            }));
        if ($body === '' || preg_match('/^USE\s+/i', $body) === 1) continue;
        if (str_starts_with($body, 'CREATE DATABASE') && !$keepCreate) continue;
        $out[] = $body;
    }
    return $out;
}
function schema_apply(PDO $pdo, array $stmts): array {
    $n = 0;
    foreach ($stmts as $body) {
        try {
            $st = $pdo->query($body);
            if ($st instanceof PDOStatement) { while ($st->nextRowset()) {} $st->closeCursor(); }
            $n++;
        } catch (PDOException $e) {
            return ['applied' => $n, 'error' => $e->getMessage(), 'statement' => $body];
        }
    }
    return ['applied' => $n, 'error' => '', 'statement' => ''];
}

// ── action dispatch ──────────────────────────────────────────────────────────
$action = (string)($_GET['action'] ?? $_POST['action'] ?? '');
if ($action !== '') {
    unlimit();
    if ($action === 'check') {
        $rows = cap_checks();
        $fails = 0;
        foreach ($rows as $r) if ($r['status'] === 'fail') $fails++;
        jout(['ok' => true, 'rows' => $rows, 'fails' => $fails]);
    }
    if ($action === 'tags') {
        $proxy = read_proxy();
        $r = http_fetch(INST_TAGS_API, $proxy);
        if (isset($r['error'])) jer('version list failed: ' . $r['error']);
        if ($r[0] !== 200) jer('GitHub API answered HTTP ' . $r[0] . ' — proxy/auth issue? You can still paste a zip URL manually.');
        $tags = json_decode($r[2], true);
        if (!is_array($tags)) jer('GitHub API returned garbage — paste a zip URL manually.');
        $out = [];
        foreach ($tags as $t) {
            if (!isset($t['name'], $t['zipball_url'])) continue;
            $out[] = ['tag' => (string)$t['name'], 'zip' => (string)$t['zipball_url']];
            if (count($out) >= 15) break;
        }
        jout(['ok' => true, 'tags' => $out]);
    }
    if ($action === 'tree') { // already-extracted app present?
        jout(['ok' => true, 'present' => is_file(base() . '/setup.sql') && is_file(base() . '/includes/kernel.php'),
            'has_config' => is_file(base() . '/config.php')]);
    }
    if ($action === 'download') {
        // One single request: GitHub's archive endpoint (codeload) ignores
        // Range, so resume/chunking is impossible there — but the package is
        // only a few MB and hosts that cannot reach GitHub at all get the
        // manual-upload button instead. Partial files never resume: a stale
        // .part from an interrupted run is deleted, not appended to.
        $proxy = read_proxy();
        $url = trim((string)($_POST['url'] ?? ''));
        if (!preg_match('#^https?://#i', $url)) jer('not an http(s) URL');
        [$zip] = dl_paths();
        @unlink($zip);
        $r = http_fetch($url, $proxy);
        if (isset($r['error'])) jer($r['error']);
        [$code, $hdrs, $body] = [$r[0], $r[1], $r[2]];
        if ($code !== 200) jer('GitHub answered HTTP ' . $code . ' — wrong URL, or the proxy blocks it?');
        $ct = strtolower($hdrs['content-type'] ?? '');
        if ($body === '' || (!str_contains($ct, 'zip') && !str_contains($ct, 'octet-stream') && substr($body, 0, 2) !== 'PK'))
            jer('that URL did not return a zip (HTTP ' . $code . ', ' . ($ct !== '' ? $ct : 'no content-type') . ') — check the version/URL.');
        if (@file_put_contents($zip, $body) === false) jer('cannot write ' . basename($zip) . ' — directory not writable?');
        $size = filesize($zip);
        jout(['ok' => true, 'size' => $size, 'total' => $size, 'done' => true,
            'log' => 'download complete: ' . number_format($size) . ' B']);
    }
    if ($action === 'upload') {
        if (!class_exists('ZipArchive')) jer('ZipArchive missing — enable the zip extension in the panel first.');
        if (empty($_FILES['zip']['tmp_name']) || !is_uploaded_file($_FILES['zip']['tmp_name'])) jer('no file received');
        [$zip] = dl_paths();
        if (!@move_uploaded_file($_FILES['zip']['tmp_name'], $zip)) jer('cannot store upload — directory not writable?');
        $z = new ZipArchive();
        if ($z->open($zip) !== true) { @unlink($zip); jer('not a valid zip archive'); }
        $n = $z->numFiles; $z->close();
        jout(['ok' => true, 'size' => filesize($zip), 'files' => $n,
            'log' => 'upload received: ' . number_format((int)filesize($zip)) . ' B, ' . $n . ' entries']);
    }
    if ($action === 'extract') {
        if (!class_exists('ZipArchive')) jer('ZipArchive missing — enable the zip extension.');
        [$zip, $src] = dl_paths();
        if (!is_file($zip)) jer('no package yet — download or upload the release zip first');
        $z = new ZipArchive();
        if ($z->open($zip) !== true) jer('cannot open zip — re-download (interrupted transfer?)');
        $first = (string)$z->getNameIndex(0);
        $prefix = str_contains($first, '/') ? substr($first, 0, strpos($first, '/') + 1) : '';
        $n = $z->numFiles;
        @mkdir($src, 0755, true);
        if (!$z->extractTo($src)) { $z->close(); jer('extract failed — disk full or permissions?'); }
        $z->close();
        $from = $src . '/' . $prefix;
        if (!is_dir($from)) { rmdir_r($src); jer('unexpected zip layout (no top folder)'); }
        $keepCfg = !empty($_POST['keep_config']) && is_file(base() . '/config.php');
        $moved = 0; $skipped = 0;
        foreach (scandir($from) as $e) {
            if ($e === '.' || $e === '..') continue;
            if ($keepCfg && $e === 'config.php') { $skipped++; continue; }
            if ($e === basename(__FILE__)) { $skipped++; continue; } // never overwrite the running installer
            $dst = base() . '/' . $e;
            rmdir_r($dst);
            if (!@rename($from . '/' . $e, $dst)) { rmdir_r($src); jer('cannot move ' . $e . ' into place — permissions?'); }
            $moved++;
        }
        rmdir_r($src); @unlink($zip);
        jout(['ok' => true, 'moved' => $moved, 'entries' => $n, 'kept_config' => $keepCfg,
            'log' => "extracted $n entries, placed $moved top-level items" . ($keepCfg ? ' (existing config.php kept)' : '')]);
    }
    if ($action === 'dbtest' || $action === 'setup') {
        $h = trim((string)($_POST['db_host'] ?? 'localhost'));
        $port = max(1, min(65535, (int)($_POST['db_port'] ?? 3306)));
        $name = trim((string)($_POST['db_name'] ?? ''));
        $user = trim((string)($_POST['db_user'] ?? ''));
        $pass = (string)($_POST['db_pass'] ?? '');
        if ($name === '' || $user === '') jer('database name and user are required');
        if (!preg_match('/^[0-9A-Za-z_$]+$/', $name)) jer('database name must be plain [A-Za-z0-9_$] (panel-prefixed names are fine)');
        try {
            $pdo = new PDO("mysql:host=$h;port=$port;dbname=$name;charset=utf8mb4", $user, $pass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 10]);
        } catch (PDOException $e) {
            jer('connect failed: ' . $e->getMessage() . ' — create the database + user in the panel first (the installer has no CREATE DATABASE privilege there).');
        }
        $ver = (string)$pdo->query('SELECT VERSION()')->fetchColumn();
        if ($action === 'dbtest') {
            $have = [];
            try {
                foreach ($pdo->query('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()')->fetchAll(PDO::FETCH_COLUMN) as $t) $have[] = $t;
            } catch (Throwable) {}
            jout(['ok' => true, 'version' => $ver,
                'tables' => count(array_intersect(INST_TABLES, $have)) . '/' . count(INST_TABLES),
                'log' => "connected: MySQL $ver, schema tables present: " . count(array_intersect(INST_TABLES, $have)) . '/' . count(INST_TABLES)]);
        }
        // — full setup —
        $log = ["connected: MySQL $ver"];
        if (!is_file(base() . '/config.php.example') || !is_file(base() . '/setup.sql'))
            jer('app files missing — extract the release first (config.php.example / setup.sql not found).');
        // 1. storage dirs
        foreach (INST_DIRS as $d) {
            $p = base() . '/' . $d;
            if (!is_dir($p) && !@mkdir($p, 0755, true)) jer('cannot create ' . $d . ' — permissions?');
            $probe = $p . '/.__w';
            if (@file_put_contents($probe, '1') === false || !@unlink($probe)) jer($d . ' is not writable — permissions?');
            $log[] = 'dir ok: ' . $d;
        }
        // 2. config.php (patch the shipped example so future options stay in sync)
        $tpl = (string)file_get_contents(base() . '/config.php.example');
        $key = bin2hex(random_bytes(32));
        $rep = [
            "_secret('DDMGMT_DB_HOST', 'localhost')" => "_secret('DDMGMT_DB_HOST', '" . pq($h) . "')",
            "_secret('DDMGMT_DB_PORT', '3306')" => "_secret('DDMGMT_DB_PORT', '" . $port . "')",
            "_secret('DDMGMT_DB_NAME', 'deaddrops')" => "_secret('DDMGMT_DB_NAME', '" . pq($name) . "')",
            "_secret('DDMGMT_DB_USER', 'root')" => "_secret('DDMGMT_DB_USER', '" . pq($user) . "')",
            "_secret('DDMGMT_DB_PASS', '')" => "_secret('DDMGMT_DB_PASS', '" . pq($pass) . "')",
            'REPLACE_WITH_64_HEX_CHARS_FROM_PHP_R_ABOVE__________' => $key,
        ];
        foreach ($rep as $from => $to) {
            if (!str_contains($tpl, $from)) jer('config template changed upstream (anchor missing: ' . substr($from, 0, 40) . '…) — update the installer.');
            $tpl = str_replace($from, $to, $tpl);
        }
        $cfgHead = "<?php\n// Generated by DeadDropMGMT web installer " . INST_VERSION . ' on ' . gmdate('Y-m-d H:i:s') . " UTC.\n";
        if (@file_put_contents(base() . '/config.php', $cfgHead . substr($tpl, 5)) === false)
            jer('cannot write config.php — directory not writable?');
        $log[] = 'config.php written (AES key generated fresh)';
        // 3. schema
        $stmts = schema_statements((string)file_get_contents(base() . '/setup.sql'));
        $res = schema_apply($pdo, $stmts);
        $log[] = 'schema: ' . $res['applied'] . '/' . count($stmts) . ' statements applied';
        if ($res['error'] !== '') jer('schema failed after ' . $res['applied'] . ' statements: ' . $res['error'] . ' — statement: ' . substr($res['statement'], 0, 200));
        // 4. verify
        $have = [];
        $engines = [];
        try {
            foreach ($pdo->query('SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()')->fetchAll() as $r) {
                $have[] = $r['TABLE_NAME']; $engines[$r['TABLE_NAME']] = strtoupper((string)$r['ENGINE']);
            }
        } catch (Throwable) {}
        $missing = array_values(array_diff(INST_TABLES, $have));
        if ($missing !== []) jer('schema applied but tables missing: ' . implode(', ', $missing));
        $log[] = 'schema verified: ' . count(INST_TABLES) . '/' . count(INST_TABLES) . ' tables';
        $badEng = [];
        foreach (INST_TABLES as $t) if (($engines[$t] ?? 'INNODB') !== 'INNODB') $badEng[] = $t . ':' . $engines[$t];
        if ($badEng !== []) $log[] = 'WARNING non-InnoDB tables: ' . implode(', ', $badEng) . ' (ask host to default to InnoDB)';
        // 5. session fallback dir + server note
    $sp = eini('session.save_path');
        $log[] = ($sp === '' || is_writable($sp)) ? 'sessions: default path usable'
            : 'sessions: default NOT writable — app auto-falls back to cache/sessions (pre-created)';
        $sw = (string)($_SERVER['SERVER_SOFTWARE'] ?? '');
        if (stripos($sw, 'apache') === false)
            $log[] = 'NOTE non-Apache server (' . ($sw !== '' ? $sw : 'unknown') . '): apply docs/nginx-deaddrop.conf manually';
        elseif (!is_file(base() . '/.htaccess'))
            $log[] = 'WARNING .htaccess missing from package — protection rules absent!';
        else $log[] = 'server: Apache + .htaccess present';
        jout(['ok' => true, 'log' => $log, 'applied' => $res['applied']]);
    }
    if ($action === 'remove') {
        $me = __FILE__;
        if (@unlink($me)) jout(['ok' => true]);
        jer('could not delete itself — remove ' . basename($me) . ' via FTP/file manager.');
    }
    jer('unknown action');
}
function rmdir_r(string $p): void {
    if (is_link($p) || is_file($p)) { @unlink($p); return; }
    if (!is_dir($p)) return;
    foreach (scandir($p) as $e) {
        if ($e === '.' || $e === '..') continue;
        rmdir_r($p . '/' . $e);
    }
    @rmdir($p);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeadDropMGMT installer</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#e6edf3;--dim:#8b949e;--ok:#3fb950;--fail:#f85149;--warn:#d29922;--info:#58a6ff;--btn:#238636}
*{box-sizing:border-box}body{background:var(--bg);color:var(--txt);font:14px/1.5 system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;padding:0 12px 60px}
.wrap{max-width:760px;margin:24px auto}h1{font-size:22px;margin:0 0 4px}.sub{color:var(--dim);margin:0 0 16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin:0 0 12px}
.steps{display:flex;gap:6px;margin:0 0 12px;flex-wrap:wrap}.step{flex:1;min-width:90px;text-align:center;font-size:12px;color:var(--dim);padding:6px 4px;border:1px solid var(--line);border-radius:6px}
.step.on{color:var(--txt);border-color:var(--info)}.step.done{color:var(--ok);border-color:var(--ok)}
label{display:block;margin:8px 0 2px;color:var(--dim);font-size:13px}
input[type=text],input[type=password],input[type=number],select{width:100%;background:#0d1117;border:1px solid var(--line);color:var(--txt);border-radius:6px;padding:8px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}.grid3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:0 12px}
button{background:var(--btn);color:#fff;border:0;border-radius:6px;padding:9px 16px;font-size:14px;cursor:pointer;margin:8px 8px 0 0}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}button:disabled{opacity:.45;cursor:default}
.row{display:flex;gap:8px;align-items:baseline;padding:5px 0;border-top:1px solid var(--line);font-size:13px}
.dot{flex:0 0 10px;height:10px;border-radius:50%;margin-top:5px}.ok{background:var(--ok)}.fail{background:var(--fail)}.warn{background:var(--warn)}.info{background:var(--info)}
.det{color:var(--dim);font-size:12px}.bar{height:8px;background:#0d1117;border:1px solid var(--line);border-radius:4px;margin:8px 0}.bar>i{display:block;height:100%;background:var(--info);border-radius:4px;width:0}
#log{background:#010409;border:1px solid var(--line);border-radius:8px;padding:10px;height:220px;overflow-y:auto;font:12px/1.6 Consolas,monospace;white-space:pre-wrap}
#log .t{color:var(--dim)}#log .ok{color:var(--ok)}#log .fail{color:var(--fail)}#log .warn{color:var(--warn)}#log .info{color:var(--info)}
.hint{font-size:12px;color:var(--dim)}a{color:var(--info)}.hidden{display:none}.sec{font-weight:700;margin:12px 0 2px}
code{background:#0d1117;padding:1px 5px;border-radius:4px;font-size:12px}
</style>
</head>
<body>
<div class="wrap">
<h1>DeadDropMGMT installer <span class="hint">v<?= INST_VERSION ?></span></h1>
<p class="sub">Upload this one file to your hosting directory, then follow the steps. Everything is logged below — copy it if you need help.</p>
<div class="steps" id="steps">
<div class="step" data-s="0">1. Server check</div><div class="step" data-s="1">2. Package</div><div class="step" data-s="2">3. Database</div><div class="step" data-s="3">4. Finish</div>
</div>

<div class="card" id="p0">
<div class="sec">Server capability check</div>
<p class="hint">Same checks as the app's own setup_check: PHP, extensions, HTTPS transport, zip support, writability, disk space.</p>
<div id="checks"><p class="hint">Running…</p></div>
<label><input type="checkbox" id="override"> Continue despite failures (I know what I'm doing)</label>
<div><button id="b0" disabled>Continue →</button><button class="ghost" id="recheck">Re-check</button></div>
</div>

<div class="card hidden" id="p1">
<div class="sec">App package</div>
<div id="treeinfo"></div>
<label>Version</label><select id="ver"><option value="">Loading versions from GitHub…</option></select>
<label>…or paste a release zip URL manually</label><input type="text" id="url" placeholder="https://github.com/…/archive/refs/tags/v1.5.0.zip">
<div class="sec">Proxy (optional)</div>
<p class="hint">If this host cannot reach github.com directly, route the download through your proxy. SOCKS5 uses remote DNS (no leak) but needs cURL; plain HTTP proxy also works without it for direct HTTP.</p>
<div class="grid3">
<div><label>Type</label><select id="pt"><option value="none">none (direct)</option><option value="http">HTTP</option><option value="socks5">SOCKS5</option></select></div>
<div><label>Host</label><input type="text" id="ph" placeholder="127.0.0.1"></div>
<div><label>Port</label><input type="number" id="pp" placeholder="1080"></div>
</div>
<div class="grid2">
<div><label>User (optional)</label><input type="text" id="pu"></div>
<div><label>Password (optional)</label><input type="password" id="pw"></div>
</div>
<div class="bar"><i id="dbar"></i></div><div class="hint" id="dtxt"></div>
<div><button id="bdl">Download</button><button class="ghost" id="bup">Upload a zip instead…</button><input type="file" id="fup" accept=".zip" class="hidden"></div>
<div id="dlbtns" class="hidden"><label><input type="checkbox" id="keepcfg" checked> Keep existing config.php (upgrade mode)</label><br><button id="bex">Extract into this directory</button></div>
<div><button id="b1" class="hidden">Continue →</button></div>
</div>

<div class="card hidden" id="p2">
<div class="sec">Database + site setup</div>
<p class="hint">Create the database and user in your hosting panel first (the installer has no such privilege there), then enter them here. Writes <code>config.php</code>, creates storage dirs, imports the schema.</p>
<div class="grid2">
<div><label>Host</label><input type="text" id="dh" value="localhost"></div>
<div><label>Port</label><input type="number" id="dp" value="3306"></div>
<div><label>Database name</label><input type="text" id="dn" placeholder="user_deaddrops"></div>
<div><label>User</label><input type="text" id="du" placeholder="user_ddmgmt"></div>
</div>
<label>Password</label><input type="password" id="dk">
<div><button class="ghost" id="btest">Test connection</button><button id="b2">Install now</button></div>
<div id="setuprows"></div>
</div>

<div class="card hidden" id="p3">
<div class="sec">Done 🎉</div>
<div id="finlinks"></div>
<div class="sec">Maintenance</div>
<p class="hint">No cron needed: hourly cleanup runs from page visits (pseudo-cron, on by default). Map sync advances from the admin UI. If your panel offers real cron, <code>php /path/to/cron/cleanup.php</code> hourly lets you turn pseudo-cron off.</p>
<div><button id="bdel">Delete this installer</button></div>
</div>

<div class="card"><div class="sec">Log <button class="ghost" id="copylog" style="margin:0 0 0 8px;padding:3px 10px;font-size:12px">Copy</button></div><div id="log"></div></div>
</div>
<script>
(function(){
"use strict";
var $=function(id){return document.getElementById(id)};
var step=0;
function stamp(){var d=new Date();return d.toISOString().substr(11,8)}
function log(msg,cls){var el=$("log");var s=document.createElement("span");s.innerHTML='<span class="t">['+stamp()+'] </span><span class="'+(cls||"info")+'"></span>';s.lastChild.textContent=msg;el.appendChild(s);el.appendChild(document.createTextNode("\n"));el.scrollTop=el.scrollHeight}
function go(n){step=n;["p0","p1","p2","p3"].forEach(function(id,i){$(id).classList.toggle("hidden",i!==n)});
var st=document.querySelectorAll("#steps .step");st.forEach(function(e,i){e.classList.toggle("on",i===n);e.classList.toggle("done",i<n)});window.scrollTo(0,0)}
function fd(o){var f=new FormData();for(var k in o)f.append(k,o[k]);return f}
function api(action,data,files){
var f=files||fd(data||{});f.append("action",action);
return fetch("?action="+encodeURIComponent(action),{method:"POST",body:f}).then(function(r){return r.json()}).catch(function(e){return {ok:false,error:"request failed: "+e}});
}
function get(action,qs){return fetch("?action="+encodeURIComponent(action)+(qs||""),{method:"GET"}).then(function(r){return r.json()}).catch(function(e){return {ok:false,error:"request failed: "+e}})}
function proxyQS(){return "&proxy_type="+encodeURIComponent($("pt").value)+"&proxy_host="+encodeURIComponent($("ph").value)+"&proxy_port="+encodeURIComponent($("pp").value)+"&proxy_user="+encodeURIComponent($("pu").value)+"&proxy_pass="+encodeURIComponent($("pw").value)}
function proxyObj(){return {proxy_type:$("pt").value,proxy_host:$("ph").value,proxy_port:$("pp").value,proxy_user:$("pu").value,proxy_pass:$("pw").value}}
var dotc={ok:"ok",fail:"fail",warn:"warn",info:"info"};

/* step 0 */
function runCheck(){
$("checks").innerHTML="<p class='hint'>Running…</p>";$("b0").disabled=true;
get("check").then(function(r){
if(!r.ok){$("checks").innerHTML="<p class='hint'>check failed: "+r.error+"</p>";return}
var h="",fails=r.fails||0;
r.rows.forEach(function(x){h+='<div class="row"><span class="dot '+dotc[x.status]+'"></span><span><b>'+x.label+'</b>'+(x.detail?'<br><span class="det">'+x.detail+'</span>':"")+"</span></div>";log(x.label+(x.detail?" — "+x.detail:""),x.status)});
$("checks").innerHTML=h;
$("b0").disabled=fails>0&&!$("override").checked;
log("capability check: "+r.rows.length+" rows, "+fails+" blocking failure(s)",fails>0?"fail":"ok");
});
}
$("recheck").onclick=runCheck;$("override").onchange=runCheck;
$("b0").onclick=function(){go(1);loadTree();loadTags()};

/* step 1 */
function loadTree(){
get("tree").then(function(r){
if(!r.ok)return;
$("treeinfo").innerHTML=r.present
?'<p class="hint">App files already present in this directory'+(r.has_config?" <b>and config.php exists</b> (upgrade mode — your config is kept).":" (no config.php yet).")+" You may skip straight to extraction or setup.</p>"
:'<p class="hint">No app files here yet — download the release package below.</p>';
if(r.present){$("dlbtns").classList.remove("hidden");$("b1").classList.remove("hidden")}
log("tree probe: app files "+(r.present?"present":"absent")+", config.php "+(r.has_config?"present":"absent"),"info");
});
}
function loadTags(){
api("tags",proxyObj()).then(function(r){
var s=$("ver");
if(!r.ok||!r.tags||!r.tags.length){s.innerHTML='<option value="">version list failed — paste URL manually</option>';log("version list failed: "+(r.error||"empty"),"warn");return}
s.innerHTML="";r.tags.forEach(function(t,i){var o=document.createElement("option");o.value=t.zip;o.textContent=t.tag+(i===0?" (latest)":"");s.appendChild(o)});
var m=document.createElement("option");m.value="MASTER";m.textContent="master (bleeding edge)";s.appendChild(m);
log("versions: "+r.tags.map(function(t){return t.tag}).join(", "),"ok");
});
}
$("pt").onchange=$("ph").onchange=function(){/* proxy applies to next download/tags call */};
$("bup").onclick=function(){$("fup").click()};
$("fup").onchange=function(){
if(!$("fup").files.length)return;
log("uploading "+$("fup").files[0].name+"…","info");
var f=new FormData();f.append("zip",$("fup").files[0]);
api("upload",null,f).then(function(r){
if(!r.ok){log("upload failed: "+r.error,"fail");return}
log(r.log,"ok");$("dtxt").textContent="upload complete: "+r.size+" B";
$("dlbtns").classList.remove("hidden");
});
};
$("bdl").onclick=function(){
var url=$("url").value.trim();
if(!url){if(!$("ver").value){log("pick a version or paste a URL","warn");return}
url=$("ver").value==="MASTER"?"<?= INST_MASTER_ZIP ?>":$("ver").value}
log("downloading "+url+" (one request, a few MB)…","info");$("bdl").disabled=true;$("dtxt").textContent="downloading…";
var d=Object.assign({url:url},proxyObj());
api("download",d).then(function(r){
$("bdl").disabled=false;
if(!r.ok){log("download failed: "+r.error,"fail");$("dtxt").textContent="failed";return}
$("dbar").style.width="100%";$("dtxt").textContent=Math.round(r.size/1024)+" KB";
log(r.log,"ok");$("dlbtns").classList.remove("hidden");
});
};
$("bex").onclick=function(){
log("extracting…","info");$("bex").disabled=true;
api("extract",{keep_config:$("keepcfg").checked?"1":""}).then(function(r){
$("bex").disabled=false;
if(!r.ok){log("extract failed: "+r.error,"fail");return}
log(r.log,"ok");$("b1").classList.remove("hidden");
});
};
$("b1").onclick=function(){go(2)};

/* step 2 */
function dbObj(){return {db_host:$("dh").value,db_port:$("dp").value,db_name:$("dn").value.trim(),db_user:$("du").value.trim(),db_pass:$("dk").value}}
$("btest").onclick=function(){
var d=dbObj();if(!d.db_name||!d.db_user){log("enter database name + user first","warn");return}
log("testing connection to "+d.db_user+"@"+d.db_host+"/"+d.db_name+"…","info");
api("dbtest",d).then(function(r){
if(!r.ok){log("DB: "+r.error,"fail");return}
log("DB: "+r.log,"ok");
});
};
$("b2").onclick=function(){
var d=dbObj();if(!d.db_name||!d.db_user){log("enter database name + user first","warn");return}
log("installing: config → dirs → schema → verify","info");$("b2").disabled=true;
api("setup",d).then(function(r){
$("b2").disabled=false;
if(!r.ok){log("SETUP FAILED: "+r.error,"fail");return}
(r.log||[]).forEach(function(m){log(m,/^warn|not |non-/i.test(m)?"warn":"ok")});
$("setuprows").innerHTML='<div class="row"><span class="dot ok"></span><span><b>Setup complete</b><br><span class="det">'+r.applied+' schema statements, all checks passed.</span></span></div>';
var base=location.href.split("?")[0].replace(/\/[^\/]*$/,"/");
$("finlinks").innerHTML='<p>1. Open <a href="'+base+'admin/">admin/</a> — with zero accounts it shows the <b>create-owner form</b>.<br>2. Then run the full diagnostics at <a href="'+base+'admin/setup_check.php">admin/setup_check.php</a>.<br>3. Delete this installer (button below).</p>';
log("setup complete — create the owner at admin/","ok");go(3);
});
};

/* step 3 */
$("bdel").onclick=function(){
if(!confirm("Delete the installer file?"))return;
api("remove",{}).then(function(r){
log(r.ok?"installer deleted. Installation finished.":"DELETE FAILED: "+r.error,r.ok?"ok":"fail");
if(r.ok)$("bdel").disabled=true;
});
};
$("copylog").onclick=function(){
var t=$("log").innerText;
if(navigator.clipboard)navigator.clipboard.writeText(t).then(function(){log("log copied to clipboard","info")});
};
log("installer <?= INST_VERSION ?> ready — checking this server…","info");
runCheck();
})();
</script>
</body>
</html>
