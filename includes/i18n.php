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
    $file = __DIR__ . "/lang/{$lang}.php";
    $cache[$lang] = is_file($file) ? require $file : [];
    return $cache[$lang];
}

// Admin accounts carry their own language in session (set at login); public
// visitors have no account, so they get the owner-configured site default.
function current_lang(): string {
    static $lang = null;
    if ($lang !== null) return $lang;
    $candidate = (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['user_lang']))
        ? $_SESSION['user_lang']
        : default_lang();
    $lang = in_array($candidate, i18n_supported_langs(), true) ? $candidate : 'en';
    return $lang;
}

function t(string $key, array $params = []): string {
    $lang = current_lang();
    $str  = i18n_load($lang)[$key] ?? i18n_load('en')[$key] ?? $key;
    foreach ($params as $k => $v) {
        $str = str_replace('{' . $k . '}', (string)$v, $str);
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
        $str = str_replace('{' . $k . '}', (string)$v, $str);
    }
    return $str;
}
