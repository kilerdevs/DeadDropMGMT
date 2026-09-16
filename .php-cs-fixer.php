<?php
// PHP-CS-Fixer configuration — automated code formatting gate.
//
// Local:  php php-cs-fixer.phar fix   (writes changes)
// CI:     php php-cs-fixer.phar fix --dry-run --diff   (fails the build)
//
// The ruleset is deliberately conservative: it covers the
// whitespace/quote/array basics plus explicit no-op-today rules
// (declare_strict_types, unused/ordered imports) that lock the style new
// code is already written in. Anything that would RESTYLE the tree (brace
// placement, operator alignment, line splitting) is deliberately out: the
// gate prevents drift, it does not reformat history.

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__)
    // vendor + coverage-html are generated; fromftp/ is an untracked local
    // deployment mirror, not repo source.
    ->exclude(['vendor', 'coverage-html', 'fromftp'])
    ->name('*.php');

// declare_strict_types is classified "risky" by the fixer (it touches the
// token stream), so the allowance below is explicit — and it is the ONLY
// risky rule enabled. Everything else stays non-risky: formatting must
// never change behaviour.
return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setUsingCache(true)
    ->setCacheFile(sys_get_temp_dir() . '/.php-cs-fixer-' . md5(__DIR__) . '.cache')
    ->setFinder($finder)
    ->setRules([
        'encoding' => true,
        'single_quote' => true,
        'array_syntax' => ['syntax' => 'short'],
        'no_trailing_whitespace' => true,
        'no_trailing_whitespace_in_comment' => true,
        'single_blank_line_at_eof' => true,
        'indentation_type' => true,
        'spaces_inside_parentheses' => true,
        'no_spaces_after_function_name' => true,
        'elseif' => true,
        // NOTE: no single_blank_line_at_eof — it demands a lone LF at EOF,
        // which fails every Windows (CRLF) checkout and writes mixed endings
        // into CRLF files. EOL shape is the checkout's business, not the
        // gate's; everything above is EOL-agnostic and stable cross-platform.
        'declare_strict_types' => true,
        'no_unused_imports' => true,
        'ordered_imports' => ['sort_algorithm' => 'alpha'],
        // The tree is edited on Windows (CRLF working copies, git autocrlf);
        // enforcing LF would rewrite every file and fight the local setup.
        // EOL normalization is git's job (.gitattributes), not the formatter's.
        'line_ending' => false,
    ]);
