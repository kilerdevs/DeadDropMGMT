<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

// ── i18n engine: dictionaries, fallbacks, escaping at substitution, plurals ──
// This suite must stay the FIRST in-process caller of current_lang() (the
// result is statically cached per process); suites are run alphabetically
// and nothing before I18nTest translates in-process.

T::eq('eight supported languages', 8, count(i18n_supported_langs()));
T::ok('language names complete', count(i18n_lang_names()) === count(i18n_supported_langs()));

// Dictionary loading + caching
$en = i18n_load('en');
T::ok('english dictionary loaded', count($en) > 100);
T::eq('dictionary load is cached', $en, i18n_load('en'));
T::eq('unknown language falls back to empty dict', [], i18n_load('xx'));

// current_lang: unsupported session value collapses to English.
// (Static cache: this first call fixes the language for this process.)
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

exit(T::done());
