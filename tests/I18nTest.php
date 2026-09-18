<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

// ── i18n engine: dictionaries, fallbacks, escaping at substitution, plurals ──
// current_lang() is deliberately unmemoized (long-lived SAPIs would pin the
// first request's language), so cases below may switch languages freely.

T::eq('eight supported languages', 8, count(i18n_supported_langs()));
T::ok('language names complete', count(i18n_lang_names()) === count(i18n_supported_langs()));

// Dictionary loading + caching
$en = i18n_load('en');
T::ok('english dictionary loaded', count($en) > 100);
T::eq('dictionary load is cached', $en, i18n_load('en'));
T::eq('unknown language falls back to empty dict', [], i18n_load('xx'));

// current_lang: unsupported session value collapses to English.
$_SESSION = [];
start_secure_session();
$_SESSION['user_lang'] = 'klingon';
T::eq('unsupported session lang falls back to en', 'en', current_lang());

// t(): key resolution order lang → en → literal key
set_setting('site_name', '');
T::ok('existing english key resolves',
      t('public.receive.title.done') === ($en['public.receive.title.done']));
T::eq('missing everywhere yields the key itself', 'totally.missing.key', t('totally.missing.key'));

// Params are HTML-escaped AT THE SINK — request data can never carry markup
$out = t('public.receive.rate_limited', ['min' => '<script>alert(1)</script>']);
T::ok('param injection is escaped', str_contains($out, '&lt;script&gt;') && !str_contains($out, '<script>'));

// Plural categories: Slavic one/few/many rules vs one/other
T::eq('pl one (1)',    'one',  plural_category(1, 'pl'));
T::eq('pl many (11)',  'many', plural_category(11, 'pl'));
T::eq('pl few (2)',    'few',  plural_category(2, 'pl'));
T::eq('pl few (4)',    'few',  plural_category(4, 'pl'));
T::eq('pl many (12)',  'many', plural_category(12, 'pl'));
T::eq('pl one (21)',   'one',  plural_category(21, 'pl'));
T::eq('pl many (14)',  'many', plural_category(14, 'pl'));
T::eq('ru many (111)', 'many', plural_category(111, 'ru'));
T::eq('uk few (23)',   'few',  plural_category(23, 'uk'));
T::eq('en one (1)',    'one',  plural_category(1, 'en'));
T::eq('en other (2)',  'other', plural_category(2, 'en'));
T::eq('negative counts use absolute value', 'one', plural_category(-1, 'pl'));

// tn(): category-keyed lookup with {n} substitution and en-dict fallback
$probeKey = 'test.plural.probe';
// tn() against missing keys degrades to the bare key without exploding
T::eq('tn missing key yields key', $probeKey, tn($probeKey, 5));

// tn() escapes params exactly like t() — request data through a plural
// string must never carry markup into the page.
$tout = tn('admin.settings.log_line', 3, ['n' => '<b>3</b>']);
T::ok('tn param injection is escaped',
      str_contains($tout, '&lt;b&gt;') && !str_contains($tout, '<b>'));

// i18n_load() never reaches the filesystem for non-allowlisted codes —
// a future caller passing request data fails closed, not LFI.
T::eq('unlisted language loads nothing', [], i18n_load('../config'));
T::eq('empty language loads nothing', [], i18n_load(''));

// Dictionary parity: a key missing from a language silently renders English,
// and a key left behind after a removal is dead weight. pl/ru/uk pluralise
// with .few/.many instead of .other (see plural_category()), so those replace
// the English .other of a .one/.other pair.
foreach (i18n_supported_langs() as $lang) {
    if ($lang === 'en') {
        continue;
    }
    $dict = i18n_load($lang);
    $slavic = in_array($lang, ['pl', 'ru', 'uk'], true);
    $missing = [];
    foreach (array_keys($en) as $key) {
        if (isset($dict[$key])) {
            continue;
        }
        $base = substr($key, 0, -6);
        if ($slavic && str_ends_with($key, '.other') && isset($en[$base . '.one'])
            && isset($dict[$base . '.few'], $dict[$base . '.many'])) {
            continue;
        }
        $missing[] = $key;
    }
    $stale = array_values(array_filter(
        array_diff(array_keys($dict), array_keys($en)),
        static fn (string $key): bool => !($slavic && preg_match('/\.(few|many)$/', $key) === 1),
    ));
    T::eq("{$lang} has every en key", [], $missing);
    T::eq("{$lang} has no keys absent from en", [], $stale);
}

exit(T::done());
