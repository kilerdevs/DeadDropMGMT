<?php
declare(strict_types=1);

// Minified-installer builder: tools/install.php → tools/install.min.php.
// The .min file is what gets uploaded to shared hosting (one small file);
// it is AUTO-GENERATED — never edited by hand — and CI rebuilds +
// commits it after every push that touches the source.
//
// Usage: php tools/build_installer_min.php [--check]
//   default: write tools/install.min.php (LF endings, deterministic: no
//            timestamps — the header pins the source sha256 instead).
//   --check: exit 0 when the committed file is in sync, 1 with a diff
//            hint otherwise (the InstallerMinTest freshness gate uses this).
//
// Minification strategy, in order of risk:
//   PHP: token-based (token_get_all) — comments and redundant whitespace go,
//        every other byte is verbatim, so semantics cannot shift. Open/close
//        tags are emitted verbatim; only the source's first open tag is
//        replaced by the generated header.
//   CSS: comment strip + whitespace collapse (the installer CSS holds no
//        strings or url() — the builder aborts if one ever appears).
//   JS:  quote-aware comment strip + per-line trim (no string/regex content
//        is ever touched). Fail-closed tripwire below: after stripping, any
//        leftover // or /* outside strings means a regex literal grew one,
//        and the build aborts instead of shipping corrupted script.
//   HTML: whitespace runs collapse to one space outside style/script blocks
//        (no <pre>/<textarea> in the installer — aborted if added).

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

const BIM_SRC = __DIR__ . '/install.php';
const BIM_DST = __DIR__ . '/install.min.php';

function bim_is_word(string $c): bool {
    return ctype_alnum($c) || $c === '_';
}

// Quote-aware pass over JS: returns the code with '...'/"..." removed
// (escapes honored). Used by the tripwire — never by the minifier itself.
function bim_js_code_only(string $js): string {
    $n = strlen($js);
    $out = '';
    $i = 0;
    $q = '';
    $esc = false;
    while ($i < $n) {
        $c = $js[$i];
        if ($q !== '') {
            if ($esc) {
                $esc = false;
            } elseif ($c === '\\') {
                $esc = true;
            } elseif ($c === $q) {
                $q = '';
            }
            $i++;
            continue;
        }
        if ($c === "'" || $c === '"') {
            $q = $c;
            $i++;
            continue;
        }
        $out .= $c;
        $i++;
    }
    if ($q !== '') {
        throw new RuntimeException('unterminated string in installer JS');
    }
    return $out;
}

function bim_minify_css(string $css): string {
    // Quoted spans (font names) are stashed behind placeholders so the
    // whitespace/quote-agnostic collapsing below can never touch them.
    $kept = [];
    $css = preg_replace_callback('/("[^"\\\\]*(?:\\\\.[^"\\\\]*)*"|\'[^\'\\\\]*(?:\\\\.[^\'\\\\]*)*\')/s',
        static function (array $m) use (&$kept): string {
            $kept[] = $m[0];
            return "\x00" . (count($kept) - 1) . "\x00";
        }, $css) ?? '';
    $css = preg_replace('#/\*.*?\*/#s', '', $css) ?? '';
    $css = preg_replace('/\s+/', ' ', $css) ?? '';
    $css = preg_replace('/\s*([{};:,>+~])\s*/', '$1', $css) ?? '';
    $css = str_replace(';}', '}', $css);
    $css = preg_replace_callback('/\x00(\d+)\x00/', static function (array $m) use ($kept): string {
        return $kept[(int)$m[1]] ?? '';
    }, trim($css)) ?? '';
    return $css;
}

function bim_minify_js(string $js): string {
    if (stripos($js, '</script') !== false) {
        throw new RuntimeException('installer JS contains </script — cannot stay embedded');
    }
    $n = strlen($js);
    $out = '';
    $i = 0;
    $q = '';
    $esc = false;
    while ($i < $n) {
        $c = $js[$i];
        if ($q !== '') {
            $out .= $c;
            if ($esc) {
                $esc = false;
            } elseif ($c === '\\') {
                $esc = true;
            } elseif ($c === $q) {
                $q = '';
            }
            $i++;
            continue;
        }
        if ($c === "'" || $c === '"') {
            $q = $c;
            $out .= $c;
            $i++;
            continue;
        }
        if ($c === '/' && $i + 1 < $n && $js[$i + 1] === '/') {
            $j = strpos($js, "\n", $i);
            $i = $j === false ? $n : $j;
            continue;
        }
        if ($c === '/' && $i + 1 < $n && $js[$i + 1] === '*') {
            $j = strpos($js, '*/', $i + 2);
            if ($j === false) {
                throw new RuntimeException('unterminated block comment in installer JS');
            }
            $i = $j + 2;
            continue;
        }
        $out .= $c;
        $i++;
    }
    if ($q !== '') {
        throw new RuntimeException('unterminated string in installer JS');
    }
    // Fail-closed tripwire: a // or /* surviving outside strings can only
    // come from a regex literal — stripping it would corrupt the script.
    $code = bim_js_code_only($out);
    if (str_contains($code, '//') || str_contains($code, '/*')) {
        throw new RuntimeException('installer JS grew a comment-like regex — review minifier safety');
    }
    $lines = [];
    foreach (explode("\n", $out) as $line) {
        $line = trim($line);
        if ($line !== '') {
            $lines[] = $line;
        }
    }
    return implode("\n", $lines);
}

function bim_minify_html(string $html): string {
    if (stripos($html, '<pre') !== false || stripos($html, '<textarea') !== false) {
        throw new RuntimeException('installer HTML grew <pre>/<textarea> — review minifier safety');
    }
    $html = preg_replace_callback('#<style>(.*?)</style>#s', static function (array $m): string {
        return '<style>' . bim_minify_css($m[1]) . '</style>';
    }, $html) ?? '';
    $html = preg_replace_callback('#<script>(.*?)</script>#s', static function (array $m): string {
        return '<script>' . bim_minify_js($m[1]) . '</script>';
    }, $html) ?? '';
    $html = preg_replace('#<!--.*?-->#s', '', $html) ?? '';
    $html = preg_replace('/\s+/', ' ', $html) ?? '';
    return trim($html);
}

function bim_build(string $src): string {
    $sha = hash('sha256', $src);
    $out = '';
    $prevLast = '';
    $pending = false;
    $first = true;
    foreach (token_get_all($src) as $tok) {
        if (is_array($tok)) {
            $id = $tok[0];
            $text = $tok[1];
            if ($id === T_OPEN_TAG) {
                if ($first) {
                    // Replaced by the generated header below.
                    $first = false;
                    continue;
                }
                $out .= $text;
                $prevLast = $text !== '' ? substr($text, -1) : '';
                $pending = false;
                continue;
            }
            $first = false;
            if ($id === T_COMMENT || $id === T_DOC_COMMENT || $id === T_WHITESPACE) {
                $pending = true;
                continue;
            }
            if ($id === T_INLINE_HTML) {
                $out .= bim_minify_html($text);
                $prevLast = '';
                $pending = false;
                continue;
            }
            if ($pending && $prevLast !== '' && $text !== ''
                && bim_is_word($prevLast) && bim_is_word($text[0])) {
                $out .= ' ';
            }
            $out .= $text;
            $prevLast = $text !== '' ? substr($text, -1) : '';
            $pending = false;
            continue;
        }
        $first = false;
        if ($pending && $prevLast !== '' && bim_is_word($prevLast) && bim_is_word($tok)) {
            $out .= ' ';
        }
        $out .= $tok;
        $prevLast = $tok;
        $pending = false;
    }
    $header = '<?php // AUTO-GENERATED from tools/install.php — do not edit.'
        . ' Source sha256: ' . $sha . '. Rebuild: php tools/build_installer_min.php' . "\n";
    return $header . $out;
}

function bim_main(array $argv): int {
    $check = in_array('--check', $argv, true);
    $raw = file_get_contents(BIM_SRC);
    if (!is_string($raw)) {
        fwrite(STDERR, "cannot read " . BIM_SRC . "\n");
        return 2;
    }
    $src = str_replace(["\r\n", "\r"], "\n", $raw);
    try {
        $out = bim_build($src);
    } catch (RuntimeException $e) {
        fwrite(STDERR, 'build failed: ' . $e->getMessage() . "\n");
        return 1;
    }
    if ($check) {
        $have = file_get_contents(BIM_DST);
        $haveNorm = is_string($have) ? str_replace(["\r\n", "\r"], "\n", $have) : '';
        if ($haveNorm !== $out) {
            fwrite(STDERR, "tools/install.min.php is stale — run: php tools/build_installer_min.php\n");
            return 1;
        }
        fwrite(STDOUT, "install.min.php in sync (" . strlen($out) . " bytes)\n");
        return 0;
    }
    if (file_put_contents(BIM_DST, $out) === false) {
        fwrite(STDERR, 'cannot write ' . BIM_DST . "\n");
        return 1;
    }
    fwrite(STDOUT, 'install.min.php: ' . strlen($out) . ' bytes ('
        . (int)round(100 * strlen($out) / max(1, strlen($src))) . '% of install.php ' . strlen($src) . " bytes)\n");
    return 0;
}

exit(bim_main($argv));
