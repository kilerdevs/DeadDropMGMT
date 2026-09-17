<?php
declare(strict_types=1);
require_once __DIR__ . '/settings.php';

function i18n_supported_langs(): array {
    return ['pl', 'en', 'de', 'ru', 'fr', 'es', 'uk', 'it'];
}

function i18n_lang_names(): array {
    return [
        'pl' => 'Polski', 'en' => 'English', 'de' => 'Deutsch', 'ru' => 'Русский',
        'fr' => 'Français', 'es' => 'Español', 'uk' => 'Українська', 'it' => 'Italiano',
    ];
}

function i18n_load(string $lang): array {
    static $cache = [];
    if (isset($cache[$lang])) return $cache[$lang];
    // Belt and braces: the path below interpolates $lang into a require, so
    // only allowlisted codes ever reach it — a future caller passing request
    // data must fail closed, not LFI.
    if (!in_array($lang, i18n_supported_langs(), true)) {
        return [];
    }
    $file = __DIR__ . "/lang/{$lang}.php";
    $cache[$lang] = is_file($file) ? require $file : [];
    return $cache[$lang];
}

// Admin accounts carry their own language in session (set at login); public
// visitors have no account, so they pick their own: an explicit ?lang=
// choice (session, first visit) wins, then the year-long preference cookie
// from an earlier visit, then the owner-configured site default.
//
// Deliberately NOT statically memoized: under long-lived SAPIs (php -S,
// FrankenPHP, workers) statics survive across requests, so a memoized first
// request would pin the language for every later one. get_settings() already
// caches the settings row and i18n_load() caches dictionaries — the per-call
// cost left is a session/cookie read plus allowlist checks.
function current_lang(): string {
    $supported = i18n_supported_langs();
    if (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['user_lang'])) {
        // An account preference, corrupt or not, decides for its owner: an
        // invalid stored code collapses to English (the guaranteed-complete
        // dictionary), never to a visitor-level fallback.
        return in_array($_SESSION['user_lang'], $supported, true) ? $_SESSION['user_lang'] : 'en';
    }
    if (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['public_lang'])
        && in_array($_SESSION['public_lang'], $supported, true)) {
        return $_SESSION['public_lang'];
    }
    $cookie = $_COOKIE[i18n_public_lang_cookie()] ?? '';
    if (is_string($cookie) && in_array($cookie, $supported, true)) {
        return $cookie;
    }
    $candidate = default_lang();
    return in_array($candidate, $supported, true) ? $candidate : 'en';
}

// Preference-cookie name for the public language choice. A cookie (not just
// the session) so a returning recipient keeps their language across visits.
function i18n_public_lang_cookie(): string {
    return 'ddmgmt_lang';
}

// Honors an explicit public language choice (?lang=) on public pages: an
// allowlisted code is stored in the session AND in the preference cookie;
// anything else (missing, unknown, non-string) is silently ignored — a
// recipient following a stale or hand-typed link keeps their current
// language instead of meeting an error page.
//
// Call BEFORE the first t()/current_lang() on the page (the choice must be
// visible to this same request) and AFTER start_secure_session() (it writes
// the session and must emit Set-Cookie before any output).
function i18n_handle_public_lang_param(): void {
    $raw = $_GET['lang'] ?? null;
    if (!is_string($raw) || !in_array($raw, i18n_supported_langs(), true)) {
        return;
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['public_lang'] = $raw;
    }
    setcookie(i18n_public_lang_cookie(), $raw, [
        'expires'  => time() + 31536000,
        'path'     => '/',
        'secure'   => request_is_https(),
        'httponly' => true,
        'samesite' => 'Lax', // Strict would drop it on arrival from a chat-app link
    ]);
}

function t(string $key, array $params = []): string {
    // CONTRACT: the return value is fully HTML-safe (static trusted text +
    // escaped params) — echo it raw. Never htmlspecialchars() t()/tn() output
    // at the display site, and never pre-escape values passed as $params:
    // either mistake double-escapes (a generated password containing & once
    // rendered as &amp;amp;, locking the recipient out).
    $lang = current_lang();
    $str  = i18n_load($lang)[$key] ?? i18n_load('en')[$key] ?? $key;
    foreach ($params as $k => $v) {
        // Substitutions are HTML-escaped at the sink: translation strings
        // render into HTML, so a request-derived parameter must never be
        // able to carry markup through t(). Static message text (including
        // intentional <br> in some strings) is untouched — only params.
        $str = str_replace('{' . $k . '}', htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'), $str);
    }
    return $str;
}

// pl/ru/uk need 3 plural forms (one/few/many); every other supported
// language only ever uses one/other.
function plural_category(int $n, ?string $lang = null): string {
    $lang = $lang ?? current_lang();
    $n    = abs($n);
    if (in_array($lang, ['pl', 'ru', 'uk'], true)) {
        $mod10  = $n % 10;
        $mod100 = $n % 100;
        if ($mod10 === 1 && $mod100 !== 11) return 'one';
        if ($mod10 >= 2 && $mod10 <= 4 && !($mod100 >= 12 && $mod100 <= 14)) return 'few';
        return 'many';
    }
    return $n === 1 ? 'one' : 'other';
}

function tn(string $key, int $n, array $params = []): string {
    $lang    = current_lang();
    $cat     = plural_category($n, $lang);
    $dict    = i18n_load($lang);
    $enDict  = i18n_load('en');
    $str     = $dict["{$key}.{$cat}"] ?? $dict["{$key}.other"]
             ?? $enDict["{$key}.{$cat}"] ?? $enDict["{$key}.other"] ?? $key;
    $params['n'] = $params['n'] ?? $n;
    foreach ($params as $k => $v) {
        // Same sink-escaping as t(): tn() output renders into HTML, so a
        // request-derived parameter must never carry markup through it.
        $str = str_replace('{' . $k . '}', htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'), $str);
    }
    return $str;
}
