import re

with open('D:/MyWare/DeadDropMGMT/includes/auth.php', 'r') as f:
    content = f.read()

# Find exact old content using regex pattern
pattern = r'\n\n// window_start is written by MySQL UTC_TIMESTAMP\(\) — a bare DATETIME with\n// no zone\. Parsing it with plain strtotime\(\) interprets it in PHP\'s\n// default timezone, skewing every window by the UTC offset: east of UTC\n// \(Europe/Warsaw\) windows expire hours early and budgets reset constantly\n// \(fail-open for guessing\); west of UTC they never roll and visitors stay\n// sticky-blocked with absurd cooldowns\. Anchoring the parse to UTC keeps\n// the read side on the same clock the write side used\. Returns false for\n// values the database should never hold \(fail-closed callers decide\)\.\nfunction _rl_parse_window_start\(string \\): int\|false \{\n    \ = trim\(\\);\n    if \(\ === \'\'\) \{\n        return false;\n    \}\n    return strtotime\(\ \. \' UTC\'\);\n\}'

new_func = '''

// window_start is written by MySQL UTC_TIMESTAMP() — a bare DATETIME with
// no zone. Parsing it with plain strtotime() interprets it in PHP's
// default timezone, skewing every window by the UTC offset: east of UTC
// (Europe/Warsaw) windows expire hours early and budgets reset constantly
// (fail-open for guessing); west of UTC they never roll and visitors stay
// sticky-blocked with absurd cooldowns. Anchoring the parse to UTC keeps
// the read side on the same clock the write side used. Returns false for
// values the database should never hold (fail-closed callers decide).
function _rl_parse_window_start(string \): int|false {
    \ = trim(\);
    if (\ === '') {
        return false;
    }

    // Try multiple parsing strategies for different database datetime formats:
    // 1. MySQL: 'YYYY-MM-DD HH:MM:SS' (UTC_TIMESTAMP) -- bare datetime, assume UTC
    // 2. PostgreSQL: 'YYYY-MM-DD HH:MM:SS+00' or with timezone offset
    // 3. SQLite: 'YYYY-MM-DD HH:MM:SS' (UTC) -- bare datetime, assume UTC
    // 4. ISO 8601: 'YYYY-MM-DDTHH:MM:SSZ' or 'YYYY-MM-DDTHH:MM:SS+00:00'
    //
    // Strategy: Try each format in order, return first success. Fail closed (return false)
    // if all strategies fail.

    // Strategy 1: ISO 8601 with explicit timezone (DateTime::ISO8601 / RFC3339)
    // Handles: 'YYYY-MM-DDTHH:MM:SSZ', 'YYYY-MM-DDTHH:MM:SS+00:00', 'YYYY-MM-DDTHH:MM:SS-05:00'
    if (preg_match('/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:Z|[+-]\\d{2}:?\\d{2})$/', \)) {
        try {
            \ = new DateTime(\, new DateTimeZone('UTC'));
            return \->getTimestamp();
        } catch (Exception) {
            // fall through to next strategy
        }
    }

    // Strategy 2: PostgreSQL with timezone offset (space separator)
    // Handles: 'YYYY-MM-DD HH:MM:SS+00', 'YYYY-MM-DD HH:MM:SS-05', 'YYYY-MM-DD HH:MM:SS+00:00'
    if (preg_match('/^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}[+-]\\d{2}:?\\d{2}$/', \)) {
        try {
            \ = new DateTime(\, new DateTimeZone('UTC'));
            return \->getTimestamp();
        } catch (Exception) {
            // fall through to next strategy
        }
    }

    // Strategy 3: Bare datetime (MySQL UTC_TIMESTAMP, SQLite) -- assume UTC
    // Handles: 'YYYY-MM-DD HH:MM:SS'
    if (preg_match('/^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}$/', \)) {
        try {
            \ = new DateTime(\, new DateTimeZone('UTC'));
            return \->getTimestamp();
        } catch (Exception) {
            // fall through to next strategy
        }
    }

    // Strategy 4: Bare ISO date only (unlikely but safe)
    // Handles: 'YYYY-MM-DD'
    if (preg_match('/^\\d{4}-\\d{2}-\\d{2}$/', \)) {
        try {
            \ = new DateTime(\, new DateTimeZone('UTC'));
            return \->getTimestamp();
        } catch (Exception) {
            // fall through
        }
    }

    // Strategy 5: Fallback to strtotime with explicit UTC (legacy behavior)
    // This catches any format strtotime() understands when anchored to UTC
    \ = strtotime(\ . ' UTC');
    if (\ !== false && \ > 0) {
        return \;
    }

    // All strategies failed -- fail closed
    return false;
}'''

new_content = re.sub(pattern, new_func, content, flags=re.DOTALL)

if new_content != content:
    with open('D:/MyWare/DeadDropMGMT/includes/auth.php', 'w') as f:
        f.write(new_content)
    print('Replacement done successfully')
else:
    print('Pattern not matched')

