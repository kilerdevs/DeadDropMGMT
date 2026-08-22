<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/i18n.php';
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>500 — <?= t('error.500.title') ?></title><link rel="stylesheet" href="/style.css">
<style>.error-code{font-family:'IBM Plex Mono',monospace;font-size:80px;font-weight:500;color:#222;letter-spacing:.04em;line-height:1;margin:32px 0 4px}</style>
</head>
<body>
<main>
    <div class="wordmark">DEAD DROP // SYSTEM</div>
    <div class="error-code">500</div>
    <h1><?= t('error.500.title') ?></h1>
    <p class="form-footnote"><?= t('error.500.body') ?></p>
    <a href="/" class="btn"><?= t('common.home') ?></a>
    <div class="compliance-note" style="margin-top:48px"><?= t('common.compliance_note') ?></div>
</main>
</body>
</html>
