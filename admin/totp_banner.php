<?php
$totp_banner_show_link = $totp_banner_show_link ?? true;
if (empty($_SESSION['totp_enabled'])):
?>
<div class="totp-banner">
    <span class="totp-banner-icon">&#9888;</span>
    <span class="totp-banner-text"><strong><?= t('admin.totp_banner.strong') ?></strong> <?= t('admin.totp_banner.text') ?></span>
    <?php if ($totp_banner_show_link): ?>
    <a class="totp-banner-cta" href="/admin/2fa.php"><?= t('admin.totp_banner.cta') ?> &rarr;</a>
    <?php endif; ?>
</div>
<?php endif; ?>
