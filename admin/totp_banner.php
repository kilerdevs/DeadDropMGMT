<?php
if (empty($_SESSION['totp_enabled'])):
?>
<div class="totp-banner">
    <span class="totp-banner-icon">&#9888;</span>
    <span class="totp-banner-text"><strong>2FA jest wyłączone.</strong> Twoje konto nie jest chronione weryfikacją dwuetapową.</span>
    <a class="totp-banner-cta" href="/admin/2fa.php">Włącz teraz &rarr;</a>
</div>
<?php endif; ?>
