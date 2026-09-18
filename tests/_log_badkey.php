<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Child probe for LoggerTest: run with DDMGMT_AES_KEY_HEX set to garbage, it
// proves the structured log refuses to write WITHOUT side effects — no empty
// app.log, no hex2bin() warnings — and that verification says why.
// Prints three fields joined by pipes: app_log's return (1/0), whether app.log
// was left untouched, and the verify verdict. (No question mark before a
// closing angle bracket in comments: that sequence ends PHP mode.)
require_once __DIR__ . '/bootstrap.php';

$before = is_file(APP_LOG_PATH) ? (int)filesize(APP_LOG_PATH) : -1;

// bootstrap's error handler turns any warning into an exception — a stray
// hex2bin() warning would surface here as a crash, which is the point.
$wrote = app_log('info', 'probe', ['msg' => 'should not be written']);
clearstatcache();
$after = is_file(APP_LOG_PATH) ? (int)filesize(APP_LOG_PATH) : -1;

// Verification of an existing (even dummy) file must name the cause.
$tmp = sys_get_temp_dir() . '/ddmgmt_badkey_' . getmypid() . '.log';
file_put_contents($tmp, "{}\n");
[$valid, , , $reason] = verify_log_chain($tmp);
@unlink($tmp);

echo ($wrote ? '1' : '0') . '|' . ($before === $after ? 'untouched' : 'modified') . '|' . ($valid ? 'valid' : (string)$reason);
