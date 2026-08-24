#!/bin/sh
# First-boot configuration for the DeadDrop container.
# Runs as root (both apache2-foreground and php-fpm expect that), renders
# config.php from the committed template if absent, generates + persists an
# AES key when none was supplied via env, fixes runtime dir permissions,
# then execs the real server process.

DOCROOT=/var/www/html
CONFIG="$DOCROOT/config.php"
TEMPLATE=/usr/local/share/config.php.template

if [ ! -f "$CONFIG" ]; then
    echo "[entrypoint] rendering config.php from template"
    cp "$TEMPLATE" "$CONFIG"

    # Key priority: explicit DDMGMT_AES_KEY_HEX env > value persisted on the
    # config volume from a previous first boot > generate a fresh one.
    if [ -z "${DDMGMT_AES_KEY_HEX:-}" ]; then
        if [ -s /config/aes_key_hex ]; then
            echo "[entrypoint] reusing AES key persisted on the config volume"
            DDMGMT_AES_KEY_HEX="$(cat /config/aes_key_hex)"
        else
            echo "[entrypoint] no DDMGMT_AES_KEY_HEX set — generating one and storing it on the config volume"
            DDMGMT_AES_KEY_HEX="$(php -r 'echo bin2hex(random_bytes(32));')"
            printf '%s' "$DDMGMT_AES_KEY_HEX" > /config/aes_key_hex
            chmod 600 /config/aes_key_hex
            echo "[entrypoint] NOTE: losing the config volume means losing all encrypted location data"
        fi
        export DDMGMT_AES_KEY_HEX
    fi
fi

# ZAP 10037: PHP must not advertise itself in X-Powered-By. expose_php is
# PHP_INI_SYSTEM - it can only be set here, never at runtime.
printf 'expose_php = Off\n' > /usr/local/etc/php/conf.d/zz-ddmgmt-hardening.ini

mkdir -p "$DOCROOT/logs" "$DOCROOT/uploads" "$DOCROOT/cache/osm_tiles"
chown -R www-data:www-data "$DOCROOT/logs" "$DOCROOT/uploads" "$DOCROOT/cache" /config

exec "$@"
