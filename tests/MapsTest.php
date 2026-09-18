<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Self-hosted map provider: accessors, fail-back, style builder ────────────

$db = get_db();

// Snapshot shared settings (see SettingsTest): provider probes below write
// real rows and must not poison later suites.
$prevSettings = [];
foreach ($db->query('SELECT key_name, value FROM settings')->fetchAll() as $r) {
    $prevSettings[$r['key_name']] = $r['value'];
}

// Missing row answers the historic default (OSM path, untouched behaviour).
$db->prepare("DELETE FROM settings WHERE key_name = 'map_provider'")->execute();
$cache = &_settings_store();
$cache = null;
T::eq('missing provider defaults to osm', MAP_PROVIDER_OSM, map_provider());

set_setting('map_provider', MAP_PROVIDER_SELFHOSTED);
T::eq('selfhosted provider reads back', MAP_PROVIDER_SELFHOSTED, map_provider());

// Unknown/corrupt values fail back to OSM, never to a broken map.
set_setting('map_provider', 'tiles.example.com');
T::eq('garbage provider fails back to osm', MAP_PROVIDER_OSM, map_provider());

// Phase 1: no zones exist yet — the stub answers empty, the style carries
// no sources, pages render the map chrome + empty-state overlay.
T::eq('phase 1 has no ready zones', [], maps_ready_zones());

$empty = maps_style([]);
T::eq('empty style is v8', 8, $empty['version']);
T::eq('empty style has no sources', [], $empty['sources']);
T::eq('empty style is background-only', ['background'], array_column($empty['layers'], 'id'));

$one = maps_style([['id' => 'zone_7', 'file' => 'zone_7.pmtiles']]);
T::ok('zone source registered', isset($one['sources']['zone_7']));
T::eq('zone source is pmtiles vector',
    ['type' => 'vector', 'url' => 'pmtiles:///tiles/zone_7.pmtiles',
     'maxzoom' => MAPS_SOURCE_MAXZOOM,
     'attribution' => '© OpenStreetMap contributors'],
    $one['sources']['zone_7']);
$layerIds = array_column($one['layers'], 'id');
T::eq('one zone adds the six-layer stack', 7, count($layerIds));
foreach ($one['layers'] as $layer) {
    if ($layer['id'] === 'background') {
        continue;
    }
    T::ok("layer {$layer['id']} binds the zone source",
        ($layer['source'] ?? '') === 'zone_7');
    T::ok("layer {$layer['id']} names a real basemap layer",
        in_array($layer['source-layer'] ?? '', ['earth', 'landuse', 'water', 'roads', 'buildings', 'boundaries'], true));
}

// The style endpoint json_encodes this array — it must survive the round trip.
$rt = json_decode(json_encode($one, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), true);
T::eq('style survives JSON round trip', $one, $rt);

// Pinned vendored builds (drift here means /maplibre/ was updated without
// the constants — cache-busting and notices depend on them).
T::ok('maplibre version pinned', MAPLIBRE_VERSION !== '');
T::ok('pmtiles js version pinned', PMTILES_JS_VERSION !== '');

// Restore every row the probes above touched so later suites inherit sanity.
foreach ($prevSettings as $k => $v) {
    set_setting($k, $v);
}
if (!array_key_exists('map_provider', $prevSettings)) {
    $db->prepare("DELETE FROM settings WHERE key_name = 'map_provider'")->execute();
}
$cache = &_settings_store();
$cache = null;

exit(T::done());
