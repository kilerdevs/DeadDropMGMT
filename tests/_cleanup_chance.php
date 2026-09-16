<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// Child probe for SettingsTest: prints 1 when run_cleanup_if_due() honored
// the probability gate and did NOT touch the settings table even though the
// hourly stamp was stale.
set_setting('last_cleanup', '12345');
run_cleanup_if_due(0.0);
echo (int)(get_setting('last_cleanup', '0') === '12345');
