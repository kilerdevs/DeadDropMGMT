#!/bin/sh
# First-boot configuration for the DeadDrop container.
# Runs as root (both apache2-foreground and php-fpm expect that), renders
# config.php from the committed template if absent, generates + persists an
# AES key when none was supplied via env, fixes runtime dir permissions,
# then execs the real server process.

DOCROOT=/var/www/html
CONFIG="$DOCROOT/config.php"
TEMPLATE=/usr/local/share/config.php.template

# FPM stacks (nginx/Caddy) keep the docroot in a named volume shared with the
# web container. Docker seeds a named volume from the image only while it is
# EMPTY, so after `up --build` FPM would keep running the old code — security
# fixes included — forever. Refresh the code from the image's pristine copy on
# every start; runtime state (config.php, uploads, logs, cache, tiles, data,
# backups) is left alone. The Apache image has no such copy and skips this.
if [ -d /usr/src/ddmgmt ]; then
    echo "[entrypoint] refreshing application code in the shared docroot"
    find "$DOCROOT" -mindepth 1 -maxdepth 1 \
        ! -name config.php ! -name uploads ! -name logs ! -name cache \
        ! -name tiles ! -name data ! -name backups \
        -exec rm -rf {} +
    cp -a /usr/src/ddmgmt/. "$DOCROOT/"
fi

FIRST_BOOT=0
if [ ! -f "$CONFIG" ]; then
    echo "[entrypoint] rendering config.php from template"
    cp "$TEMPLATE" "$CONFIG"
    FIRST_BOOT=1
fi

# The AES key is resolved on EVERY start, not only the first: config.php reads
# it from the environment, and an environment variable exported in one run of
# this script is gone after `docker restart` / a host reboot (the container
# filesystem — config.php included — survives, the shell's exports do not).
# Skipping this on later boots left the app with the placeholder key.
# Priority: explicit DDMGMT_AES_KEY_HEX env > value persisted on the config
# volume > (first boot only) a freshly generated one.
if [ -z "${DDMGMT_AES_KEY_HEX:-}" ]; then
    if [ -s /config/aes_key_hex ]; then
        echo "[entrypoint] reusing AES key persisted on the config volume"
        DDMGMT_AES_KEY_HEX="$(cat /config/aes_key_hex)"
        export DDMGMT_AES_KEY_HEX
    elif [ "$FIRST_BOOT" = "1" ]; then
        echo "[entrypoint] no DDMGMT_AES_KEY_HEX set — generating one and storing it on the config volume"
        DDMGMT_AES_KEY_HEX="$(php -r 'echo bin2hex(random_bytes(32));')"
        printf '%s' "$DDMGMT_AES_KEY_HEX" > /config/aes_key_hex
        chmod 600 /config/aes_key_hex
        echo "[entrypoint] NOTE: losing the config volume means losing all encrypted location data"
        export DDMGMT_AES_KEY_HEX
    else
        # Existing config, no key anywhere: generating a new one would make
        # every stored location undecryptable. Refuse loudly instead.
        echo "[entrypoint] ERROR: no AES key (env or /config/aes_key_hex) for an existing install — not generating a new one" >&2
    fi
fi

# ZAP 10037: PHP must not advertise itself in X-Powered-By. expose_php is
# PHP_INI_SYSTEM - it can only be set here, never at runtime.
printf 'expose_php = Off\n' > /usr/local/etc/php/conf.d/zz-ddmgmt-hardening.ini

mkdir -p "$DOCROOT/logs" "$DOCROOT/uploads" "$DOCROOT/cache/osm_tiles"
# The logs volume predates logs/.htaccess on existing stacks; seed it so the
# folder is denied per-directory (and Setup check stays green).
[ -f "$DOCROOT/logs/.htaccess" ] || printf 'Require all denied\n' > "$DOCROOT/logs/.htaccess"
chown -R www-data:www-data "$DOCROOT/logs" "$DOCROOT/uploads" "$DOCROOT/cache" /config

if [ "${DDMGMT_DB_PASS:-}" = "deaddrop-db" ]; then
    echo "[entrypoint] WARNING: DDMGMT_DB_PASS is the published default — set DB_PASS in .env before exposing this stack" >&2
fi

# When the owner has turned OSM proxy routing on (it is off by default) and
# the pool is empty (fails closed), discover a first pool now instead of
# waiting for the first page visit or the 15-minute timer below. Detached,
# Throwable-guarded and a one-SELECT no-op when routing is off or the pool
# already exists.
# DDMGMT_PROXY_HEAL=0 turns automatic discovery off.
(
    sleep 20
    runuser -u www-data -- php "$DOCROOT/cron/proxy_heal.php" >/dev/null 2>&1 || true
) &

# Real maintenance timer. The page-visit pseudo-cron is only a fallback: this
# loop deletes expired orders, prunes rate-limit rows, the tile cache and old
# records every 15 minutes even when nobody visits. Runs as www-data so log and
# upload ownership stay intact; failures are logged by the script itself.
(
    sleep 90
    while true; do
        runuser -u www-data -- php "$DOCROOT/cron/cleanup.php" >/dev/null 2>&1 || true
        sleep 900
    done
) &

exec "$@"
