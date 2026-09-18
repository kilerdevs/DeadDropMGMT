<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/settings.php';

// ── Self-hosted map provider (PMTiles + MapLibre GL JS) ──────────────────────
// Dual-provider design: 'osm' (default, current tile_proxy/embed path,
// untouched) vs 'selfhosted' (same-origin PMTiles zones rendered by vendored
// MapLibre in /maplibre/). Nothing here touches the network: the style is
// built from zone files on local disk, fonts/glyphs/JS are vendored.
//
// Phase 1: no zones exist yet — maps_ready_zones() returns [] and the style
// carries no sources (pages render the map chrome + an empty-state overlay).
// Phase 2/3 replace the stub with the map_zones table read.

const MAP_PROVIDER_OSM = 'osm';
const MAP_PROVIDER_SELFHOSTED = 'selfhosted';

// Pinned vendored builds in /maplibre/ (see THIRD-PARTY-NOTICES.md).
const MAPLIBRE_VERSION = '5.13.0';
const PMTILES_JS_VERSION = '4.5.0';

// MapLibre renders vector tiles with WebGL workers built from Blob URLs,
// which the default CSP (script-src 'self' + nonce, no worker-src) blocks.
// Both CSP profiles therefore carry worker-src 'self' blob: (see auth.php).
// The glyph path below is reserved for Phase 3 (labels); the Phase 1 style
// deliberately has no symbol layers so it renders with zero font files.
const MAPS_GLYPHS_URL = '/fonts/glyphs/{fontstack}/{range}.pbf';

// Native detail of our extracts; the client overzooms crisply beyond it.
const MAPS_SOURCE_MAXZOOM = 14;

// Which tile backend renders maps. Unknown/corrupt values fail back to OSM
// (the historic behaviour) rather than to a broken map.
function map_provider(): string {
    $v = get_setting('map_provider', MAP_PROVIDER_OSM);
    return $v === MAP_PROVIDER_SELFHOSTED ? MAP_PROVIDER_SELFHOSTED : MAP_PROVIDER_OSM;
}

// Ready-to-render zones: each ['id' => 'zone_<n>', 'file' => '<name>.pmtiles'].
// Phase 1 stub — the map_zones table and downloader land in Phase 2.
/** @return array<int,array{id:string,file:string}> */
function maps_ready_zones(): array {
    return [];
}

// Build a MapLibre v8 style array for the given zones. One vector source per
// zone file; the dark layer stack is emitted per source (later zones paint
// over earlier ones where they overlap — the zone list warns about that).
/** @param array<int,array{id:string,file:string}> $zones */
function maps_style(array $zones): array {
    $style = [
        'version' => 8,
        'sources' => [],
        'layers'  => [
            [
                'id'    => 'background',
                'type'  => 'background',
                'paint' => ['background-color' => '#111418'],
            ],
        ],
    ];
    foreach ($zones as $zone) {
        $src = (string)$zone['id'];
        $style['sources'][$src] = [
            'type'        => 'vector',
            'url'         => 'pmtiles:///tiles/' . (string)$zone['file'],
            'maxzoom'     => MAPS_SOURCE_MAXZOOM,
            'attribution' => '© OpenStreetMap contributors',
        ];
        foreach (maps_layer_stack($src) as $layer) {
            $style['layers'][] = $layer;
        }
    }
    return $style;
}

// The dark layer stack for one source. Geometry only (fill/line) — symbol/
// text layers wait for vendored glyphs in Phase 3.
/** @return array<int,array<string,mixed>> */
function maps_layer_stack(string $source): array {
    $s = $source;
    return [
        [
            'id' => "earth_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'earth',
            'paint' => ['fill-color' => '#1a1e24'],
        ],
        [
            'id' => "landuse_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'landuse',
            'paint' => ['fill-color' => '#1e242c'],
        ],
        [
            'id' => "water_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'water',
            'paint' => ['fill-color' => '#0e2a3f'],
        ],
        [
            'id' => "roads_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'roads',
            'paint' => [
                'line-color' => '#5a636e',
                'line-width' => ['interpolate', ['linear'], ['zoom'], 8, 0.5, 14, 3],
            ],
        ],
        [
            'id' => "buildings_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'buildings',
            'paint' => ['fill-color' => '#2a2f37'],
        ],
        [
            'id' => "boundaries_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'boundaries',
            'paint' => [
                'line-color'   => '#3a4552',
                'line-width'   => 1,
                'line-dasharray' => [3, 2],
            ],
        ],
    ];
}
