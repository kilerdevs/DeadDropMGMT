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
// Label glyphs are vendored SDF fonts (Noto Sans, OFL — see
// THIRD-PARTY-NOTICES.md), served same-origin so labels cost zero third-party
// requests. A font named in a symbol layer must exist under fonts/glyphs/
// (MapsTest walks the style and checks).
const MAPS_GLYPHS_URL = '/fonts/glyphs/{fontstack}/{range}.pbf';
const MAPS_FONT_REGULAR = 'Noto Sans Regular';
const MAPS_FONT_MEDIUM  = 'Noto Sans Medium';
const MAPS_FONT_ITALIC  = 'Noto Sans Italic';

// Native detail of our extracts; the client overzooms crisply beyond it.
const MAPS_SOURCE_MAXZOOM = 14;

// Which tile backend renders maps. Unknown/corrupt values fail back to OSM
// (the historic behaviour) rather than to a broken map.
function map_provider(): string {
    $v = get_setting('map_provider', MAP_PROVIDER_OSM);
    return $v === MAP_PROVIDER_SELFHOSTED ? MAP_PROVIDER_SELFHOSTED : MAP_PROVIDER_OSM;
}

// ── Zone file names ─────────────────────────────────────────────────────────
// Zone files are served straight from /tiles/ so browsers can Range-fetch
// them, and the public reveal page loads them anonymously — no session can
// gate that. What CAN be kept private is the name: every zone file is
// zone_<id>_<token>.pmtiles with a random 128-bit token in map_zones.file_token,
// so files cannot be enumerated (or their coverage discovered) by walking ids.
// The token reaches a browser only inside a style the server chose to send:
// admins get every ready zone, a recipient only the zones covering their pin.
// Same bearer-name model as the photo URLs.

function maps_zone_valid_token(mixed $t): bool {
    return is_string($t) && preg_match('/^[0-9a-f]{32}$/', $t) === 1;
}

function maps_zone_file_base(int $id, string $token): string {
    return 'zone_' . $id . '_' . $token;
}

// The zone's secret file token, minted on first use for rows that predate the
// column (their legacy zone_<id>.pmtiles / .part files are renamed to match,
// so nothing stays reachable under the old guessable name). Race-safe: the
// UPDATE only lands on a NULL token and the winner's value is what is read
// back. Null when the row does not exist or the store is unreadable.
function maps_zone_ensure_token(int $id): ?string {
    try {
        $db = get_db();
        $st = $db->prepare('SELECT file_token FROM map_zones WHERE id = ? LIMIT 1');
        $st->execute([$id]);
        $tok = $st->fetchColumn();
        if ($tok === false) {
            return null;
        }
        if (!maps_zone_valid_token($tok)) {
            $db->prepare('UPDATE map_zones SET file_token = ? WHERE id = ? AND (file_token IS NULL OR file_token = "")')
               ->execute([bin2hex(random_bytes(16)), $id]);
            $st->execute([$id]);
            $tok = $st->fetchColumn();
            if (!maps_zone_valid_token($tok)) {
                return null;
            }
        }
    } catch (Throwable $e) {
        log_err('Zone token: ' . $e->getMessage());
        return null;
    }
    foreach (['pmtiles', 'part'] as $ext) {
        $legacy = maps_tiles_dir() . '/zone_' . $id . '.' . $ext;
        $named  = maps_tiles_dir() . '/' . maps_zone_file_base($id, $tok) . '.' . $ext;
        if (is_file($legacy) && !is_file($named)) {
            @rename($legacy, $named);
        }
    }
    return $tok;
}

// Absolute path of a zone's published file / in-flight download. Never
// touches disk beyond the token lookup; unknown zones answer a path that
// cannot exist (nothing is served, nothing is deleted).
function maps_zone_path(int $id, bool $part = false): string {
    $tok = maps_zone_ensure_token($id);
    $base = $tok === null ? 'zone_' . $id . '_missing' : maps_zone_file_base($id, $tok);
    return maps_tiles_dir() . '/' . $base . ($part ? '.part' : '.pmtiles');
}

// Ready-to-render zones: each ['id' => 'zone_<n>', 'file' => '<name>.pmtiles'].
/** @return array<int,array{id:string,file:string}> */
function maps_ready_zones(): array {
    try {
        $rows = get_db()->query(
            "SELECT id, file_token FROM map_zones WHERE status = 'ready' ORDER BY id ASC"
        )->fetchAll();
    } catch (Throwable) {
        return []; // table missing (setup.sql not re-run) — no zones, no crash
    }
    return maps_zone_entries($rows);
}

// Shared row → style-entry mapping for the two listings above and below.
/**
 * @param array<int,array<string,mixed>> $rows
 * @return array<int,array{id:string,file:string}>
 */
function maps_zone_entries(array $rows): array {
    $out = [];
    foreach ($rows as $r) {
        $id = (int)$r['id'];
        $tok = maps_zone_valid_token($r['file_token'] ?? null) ? (string)$r['file_token'] : maps_zone_ensure_token($id);
        if ($tok === null) {
            continue; // no usable name — better no zone than a guessable one
        }
        $out[] = ['id' => 'zone_' . $id, 'file' => maps_zone_file_base($id, $tok) . '.pmtiles'];
    }
    return $out;
}

// Ready zones whose bbox contains the point (inclusive edges), same shape
// as maps_ready_zones(). The public reveal style is built from this list
// only: zones elsewhere stay undisclosed to the recipient, and a point
// outside every zone falls back to the OSM embed instead of rendering an
// empty canvas. Non-finite coordinates match nothing (fail-closed).
/** @return array<int,array{id:string,file:string}> */
function maps_covering_zones(float $lat, float $lng): array {
    if (!is_finite($lat) || !is_finite($lng)) {
        return [];
    }
    try {
        $st = get_db()->prepare(
            "SELECT id, file_token FROM map_zones WHERE status = 'ready'
             AND min_lon <= ? AND min_lat <= ? AND max_lon >= ? AND max_lat >= ?
             ORDER BY id ASC"
        );
        $st->execute([$lng, $lat, $lng, $lat]);
        $rows = $st->fetchAll();
    } catch (Throwable) {
        return []; // table missing (setup.sql not re-run) — no zones, no crash
    }
    return maps_zone_entries($rows);
}

// Build a MapLibre v8 style array for the given zones. One vector source per
// zone file. Geometry for every zone is emitted first and every zone's labels
// after it, so a later zone's ground never paints over an earlier zone's
// street names where the two overlap (the zone list still warns about the
// shared tiles). Dark theme, tuned for contrast: a road hierarchy with
// casings, buildings under the roads, and street/place/POI labels.
/** @param array<int,array{id:string,file:string}> $zones */
function maps_style(array $zones): array {
    $style = [
        'version' => 8,
        'glyphs'  => MAPS_GLYPHS_URL,
        'sources' => [],
        'layers'  => [
            [
                'id'    => 'background',
                'type'  => 'background',
                'paint' => ['background-color' => '#161a20'],
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
        foreach (maps_base_layers($src) as $layer) {
            $style['layers'][] = $layer;
        }
    }
    foreach ($zones as $zone) {
        foreach (maps_label_layers((string)$zone['id']) as $layer) {
            $style['layers'][] = $layer;
        }
    }
    return $style;
}

// Road classes by Protomaps `kind_detail`: [fill colour, width in px at z14].
// Widths scale with zoom in maps_road_width(); casing colour is shared.
const MAPS_ROAD_CLASSES = [
    'motorway'       => ['#c79a52', 6.0],
    'motorway_link'  => ['#c79a52', 3.0],
    'trunk'          => ['#bd9660', 5.2],
    'trunk_link'     => ['#bd9660', 2.8],
    'primary'        => ['#93a0af', 5.0],
    'primary_link'   => ['#93a0af', 2.6],
    'secondary'      => ['#7b8795', 4.2],
    'secondary_link' => ['#7b8795', 2.4],
    'tertiary'       => ['#687482', 3.4],
    'tertiary_link'  => ['#687482', 2.2],
    'residential'    => ['#556170', 2.5],
    'unclassified'   => ['#556170', 2.5],
    'living_street'  => ['#556170', 2.2],
    'pedestrian'     => ['#4d5865', 2.0],
    'service'        => ['#414b58', 1.4],
    'taxiway'        => ['#414b58', 2.4],
    'runway'         => ['#414b58', 5.0],
];
const MAPS_ROAD_FALLBACK = ['#556170', 2.0];
const MAPS_ROAD_CASING   = '#0d1014';

// Zoom → width multiplier relative to the z14 base of MAPS_ROAD_CLASSES.
const MAPS_ROAD_ZOOM_SCALE = [8 => 0.1, 11 => 0.3, 14 => 1.0, 16 => 1.9, 19 => 5.6];

// json_encode() writes a whole float such as 3.0 as `3`, so the style would
// not survive its own JSON round trip. Emit whole numbers as ints up front.
function maps_num(float $v): int|float {
    return floor($v) === $v ? (int)$v : $v;
}

/** Data-driven width: a `match` on kind_detail per zoom stop, interpolated. */
function maps_road_width(float $extra = 0.0): array {
    $expr = ['interpolate', ['exponential', 1.4], ['zoom']];
    foreach (MAPS_ROAD_ZOOM_SCALE as $zoom => $scale) {
        $match = ['match', ['get', 'kind_detail']];
        foreach (MAPS_ROAD_CLASSES as $detail => [, $w]) {
            $match[] = $detail;
            $match[] = maps_num(round($w * $scale + $extra, 2));
        }
        $match[] = maps_num(round(MAPS_ROAD_FALLBACK[1] * $scale + $extra, 2));
        $expr[] = $zoom;
        $expr[] = $match;
    }
    return $expr;
}

function maps_road_color(): array {
    $match = ['match', ['get', 'kind_detail']];
    foreach (MAPS_ROAD_CLASSES as $detail => [$color]) {
        $match[] = $detail;
        $match[] = $color;
    }
    $match[] = MAPS_ROAD_FALLBACK[0];
    return $match;
}

// Membership filter. to-string turns a missing property into '' — a bare
// null needle would make the whole filter error out and drop the feature.
/** @param array<int,string> $values */
function maps_in(string $prop, array $values): array {
    return ['in', ['to-string', ['get', $prop]], ['literal', $values]];
}

// Ground, water, buildings, roads, rails, boundaries — no text.
/** @return array<int,array<string,mixed>> */
function maps_base_layers(string $source): array {
    $s = $source;
    $hidden = ['platform', 'driveway', 'crossing', 'sidewalk', 'corridor', 'pier'];
    return [
        [
            'id' => "earth_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'earth',
            'paint' => ['fill-color' => '#161a20'],
        ],
        [
            // Only present up to z7 — carries the ground at country scale.
            'id' => "landcover_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'landcover', 'maxzoom' => 8,
            'paint' => ['fill-color' => ['match', ['get', 'kind'],
                'forest', '#15221c', 'grassland', '#171f1a', 'scrub', '#171f1a',
                'farmland', '#191f19', 'barren', '#1c2027', 'glacier', '#202730',
                '#181c22']],
        ],
        [
            // Residential / commercial stay earth-coloured on purpose: only
            // land with a meaning of its own (green, water, campus, hospital)
            // is tinted, so the map reads as places, not as noise.
            'id' => "landuse_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'landuse',
            'filter' => ['!', maps_in('kind', ['residential', 'commercial', 'retail', 'kindergarten', 'pedestrian', 'platform', 'railway', 'construction', 'brownfield'])],
            'layout' => ['fill-sort-key' => ['coalesce', ['get', 'sort_rank'], 0]],
            'paint' => ['fill-color' => ['match', ['get', 'kind'],
                ['park', 'nature_reserve', 'national_park', 'protected_area', 'garden', 'dog_park', 'recreation_ground', 'grass', 'meadow', 'grassland'], '#1a2b22',
                ['wood', 'forest', 'scrub'], '#16251c',
                ['pitch', 'playground'], '#1c2e26',
                ['farmland', 'allotments'], '#1c221b',
                'cemetery', '#1b2420',
                'wetland', '#15252a',
                ['sand', 'beach'], '#282b28',
                'hospital', '#2b2029',
                ['school', 'university', 'college'], '#29261c',
                ['industrial', 'military'], '#1b1f26',
                '#181c22']],
        ],
        [
            'id' => "water_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'water',
            'filter' => ['==', ['geometry-type'], 'Polygon'],
            'paint' => ['fill-color' => '#0f2b40'],
        ],
        [
            'id' => "waterway_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'water',
            'filter' => ['==', ['geometry-type'], 'LineString'],
            'layout' => ['line-cap' => 'round', 'line-join' => 'round'],
            'paint' => [
                'line-color' => '#174463',
                'line-width' => ['interpolate', ['linear'], ['zoom'],
                    9, ['match', ['get', 'kind'], ['river', 'canal'], 0.7, 0.3],
                    14, ['match', ['get', 'kind'], ['river', 'canal'], 3, 1],
                    18, ['match', ['get', 'kind'], ['river', 'canal'], 12, 4]],
            ],
        ],
        [
            'id' => "buildings_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'buildings', 'minzoom' => 12,
            'filter' => ['==', ['get', 'kind'], 'building'],
            'paint' => [
                'fill-color' => ['interpolate', ['linear'], ['zoom'], 13, '#1c2128', 17, '#262d36'],
                'fill-outline-color' => ['interpolate', ['linear'], ['zoom'], 14, '#1c2128', 16, '#36404c'],
            ],
        ],
        [
            'id' => "rail_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'roads', 'minzoom' => 10,
            'filter' => ['==', ['get', 'kind'], 'rail'],
            'paint' => [
                'line-color' => '#56606c',
                'line-opacity' => ['match', ['get', 'kind_detail'], 'subway', 0.35, 1],
                'line-width' => ['interpolate', ['linear'], ['zoom'], 10, 0.5, 14, 1.3, 18, 3.2],
            ],
        ],
        [
            'id' => "rail_ties_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'roads', 'minzoom' => 14.5,
            'filter' => ['all', ['==', ['get', 'kind'], 'rail'], ['!=', ['get', 'kind_detail'], 'subway']],
            'paint' => [
                'line-color' => '#6d7885',
                'line-dasharray' => [1.5, 2.5],
                'line-width' => ['interpolate', ['linear'], ['zoom'], 14, 0.9, 18, 2.2],
            ],
        ],
        [
            'id' => "paths_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'roads', 'minzoom' => 15,
            'filter' => ['all', ['==', ['get', 'kind'], 'path'], ['!', maps_in('kind_detail', $hidden)]],
            'layout' => ['line-cap' => 'round'],
            'paint' => [
                'line-color' => '#76838f',
                'line-dasharray' => [1.2, 1.6],
                'line-width' => ['interpolate', ['linear'], ['zoom'], 15, 0.8, 18, 2.2],
            ],
        ],
        [
            'id' => "road_casing_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'roads', 'minzoom' => 6,
            'filter' => ['all', maps_in('kind', ['highway', 'major_road', 'minor_road', 'other', 'aeroway']),
                ['!', maps_in('kind_detail', $hidden)]],
            'layout' => ['line-cap' => 'round', 'line-join' => 'round',
                'line-sort-key' => ['coalesce', ['get', 'sort_rank'], 0]],
            'paint' => [
                'line-color' => MAPS_ROAD_CASING,
                'line-opacity' => ['case', ['==', ['get', 'is_tunnel'], true], 0.4, 1],
                'line-width' => maps_road_width(1.2),
            ],
        ],
        [
            'id' => "road_fill_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'roads', 'minzoom' => 6,
            'filter' => ['all', maps_in('kind', ['highway', 'major_road', 'minor_road', 'other', 'aeroway']),
                ['!', maps_in('kind_detail', $hidden)]],
            'layout' => ['line-cap' => 'round', 'line-join' => 'round',
                'line-sort-key' => ['coalesce', ['get', 'sort_rank'], 0]],
            'paint' => [
                'line-color' => maps_road_color(),
                'line-opacity' => ['case', ['==', ['get', 'is_tunnel'], true], 0.45, 1],
                'line-width' => maps_road_width(),
            ],
        ],
        [
            'id' => "boundaries_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'boundaries',
            'paint' => [
                'line-color'     => ['match', ['get', 'kind'], 'country', '#6b7290', '#3d4658'],
                'line-width'     => ['match', ['get', 'kind'], 'country', 1.2, 0.8],
                'line-dasharray' => [3, 2],
            ],
        ],
    ];
}

// POI kinds by prominence and category. Tier A is drawn from z14 with a dot,
// tier B from z15.5 with a dot, tier C from z17 as a small label only — the
// same collision-checked layers stack, so a crowded block never turns to soup.
const MAPS_POI_TIER_A = ['hospital', 'university', 'college', 'station', 'aerodrome', 'museum',
    'castle', 'attraction', 'stadium', 'mall', 'townhall', 'zoo', 'park', 'nature_reserve'];
const MAPS_POI_TIER_B = ['place_of_worship', 'library', 'police', 'fire_station', 'marketplace',
    'supermarket', 'hotel', 'cinema', 'theatre', 'arts_centre', 'sports_centre', 'fuel',
    'clinic', 'school', 'garden', 'cemetery', 'recreation_ground', 'courthouse', 'embassy',
    'community_centre'];
const MAPS_POI_TIER_C = ['restaurant', 'cafe', 'fast_food', 'bar', 'pub', 'convenience',
    'doctors', 'pharmacy', 'dentist', 'kindergarten', 'bank', 'car_repair', 'bakery', 'hairdresser',
    'post_office'];

/** Category colour for a POI kind: health, transit, education, nature, shops & food, civic, culture. */
function maps_poi_color(): array {
    return ['match', ['get', 'kind'],
        ['hospital', 'clinic', 'doctors', 'pharmacy', 'dentist'], '#e5787a',
        ['station', 'aerodrome', 'railway'], '#5fa8e8',
        ['university', 'college', 'school', 'kindergarten', 'library'], '#e3b04b',
        ['park', 'nature_reserve', 'garden', 'cemetery', 'recreation_ground', 'zoo'], '#78b978',
        ['supermarket', 'mall', 'marketplace', 'convenience', 'restaurant', 'cafe', 'fast_food',
            'bar', 'pub', 'bakery', 'hairdresser', 'hotel', 'fuel'], '#e58f5c',
        ['police', 'fire_station', 'townhall', 'post_office', 'courthouse', 'embassy', 'bank'], '#9aa5dd',
        ['museum', 'theatre', 'cinema', 'attraction', 'castle', 'arts_centre', 'stadium',
            'sports_centre', 'place_of_worship', 'community_centre'], '#c690d8',
        '#9aa4b1'];
}

// Text-only layers, all placed above every zone's geometry. Later layers win
// label collisions, so the order is: minor roads, roads, water, POIs, places.
/** @return array<int,array<string,mixed>> */
function maps_label_layers(string $source): array {
    $s = $source;
    $text = static fn (array $font, array $size, array $extra = []): array => array_merge([
        'text-font'      => $font,
        'text-size'      => $size,
        'text-max-width' => 8,
    ], $extra);
    $roadSize = ['interpolate', ['linear'], ['zoom'], 13, 9, 15, 11, 17, 13, 19, 15];
    $hasName = ['has', 'name'];
    $roadName = ['coalesce', ['get', 'name'], ['get', 'ref']];
    $roadHalo = ['text-color' => '#c3cbd6', 'text-halo-color' => '#11151a', 'text-halo-width' => 1.6];

    $poiLayers = static function (string $id, array $kinds, int|float $minzoom, bool $dot) use ($s, $text): array {
        $filter = maps_in('kind', $kinds);
        $out = [];
        if ($dot) {
            $out[] = [
                'id' => "{$id}_dot_$s", 'type' => 'circle', 'source' => $s,
                'source-layer' => 'pois', 'minzoom' => $minzoom,
                'filter' => ['all', ['has', 'name'], $filter],
                'paint' => [
                    'circle-color' => maps_poi_color(),
                    'circle-radius' => ['interpolate', ['linear'], ['zoom'], 14, 2.6, 18, 4.5],
                    'circle-stroke-color' => '#0d1014',
                    'circle-stroke-width' => 1,
                ],
            ];
        }
        $out[] = [
            'id' => "{$id}_label_$s", 'type' => 'symbol', 'source' => $s,
            'source-layer' => 'pois', 'minzoom' => $minzoom,
            'filter' => ['all', ['has', 'name'], $filter],
            'layout' => $text([MAPS_FONT_REGULAR],
                ['interpolate', ['linear'], ['zoom'], 14, 10, 18, 12.5],
                [
                    'text-field'  => ['get', 'name'],
                    'text-anchor' => $dot ? 'top' : 'center',
                    'text-offset' => $dot ? [0, 0.55] : [0, 0],
                    'text-max-width' => 7,
                    'text-padding' => 3,
                ]),
            'paint' => [
                'text-color' => maps_poi_color(),
                'text-halo-color' => '#0d1014',
                'text-halo-width' => 1.5,
            ],
        ];
        return $out;
    };

    $place = static fn (string $id, array $filter, array $minmax, array $size, string $color, array $font = [MAPS_FONT_MEDIUM], array $extra = []): array => [
        'id' => "{$id}_$s", 'type' => 'symbol', 'source' => $s,
        'source-layer' => 'places'] + $minmax + [
        'filter' => $filter,
        'layout' => $text($font, $size, array_merge([
            'text-field' => ['get', 'name'],
            'symbol-sort-key' => ['-', ['coalesce', ['get', 'population_rank'], 0]],
        ], $extra)),
        'paint' => ['text-color' => $color, 'text-halo-color' => '#0d1014', 'text-halo-width' => 1.8],
    ];
    $upper = ['text-transform' => 'uppercase', 'text-letter-spacing' => 0.12];

    return array_merge(
        [
            [
                'id' => "road_label_minor_$s", 'type' => 'symbol', 'source' => $s,
                'source-layer' => 'roads', 'minzoom' => 14.5,
                'filter' => ['all', $hasName, maps_in('kind', ['minor_road', 'other']),
                    ['!', maps_in('kind_detail', ['platform', 'driveway', 'service'])]],
                'layout' => $text([MAPS_FONT_REGULAR], $roadSize, [
                    'symbol-placement' => 'line', 'text-field' => ['get', 'name'],
                    'symbol-spacing' => 260, 'text-max-angle' => 35, 'text-padding' => 8,
                ]),
                'paint' => ['text-color' => '#a8b1bd', 'text-halo-color' => '#11151a', 'text-halo-width' => 1.5],
            ],
            [
                'id' => "road_label_$s", 'type' => 'symbol', 'source' => $s,
                'source-layer' => 'roads', 'minzoom' => 12.5,
                'filter' => ['all', ['any', $hasName, ['has', 'ref']],
                    maps_in('kind', ['highway', 'major_road'])],
                'layout' => $text([MAPS_FONT_MEDIUM], $roadSize, [
                    'symbol-placement' => 'line', 'text-field' => $roadName,
                    'symbol-spacing' => 300, 'text-max-angle' => 35, 'text-padding' => 8,
                    'symbol-sort-key' => ['match', ['get', 'kind'], 'highway', 0, 1],
                ]),
                'paint' => $roadHalo,
            ],
            [
                'id' => "water_line_label_$s", 'type' => 'symbol', 'source' => $s,
                'source-layer' => 'water', 'minzoom' => 12,
                'filter' => ['all', $hasName, ['==', ['geometry-type'], 'LineString']],
                'layout' => $text([MAPS_FONT_ITALIC], ['interpolate', ['linear'], ['zoom'], 12, 10, 17, 13], [
                    'symbol-placement' => 'line', 'text-field' => ['get', 'name'],
                    'symbol-spacing' => 350, 'text-letter-spacing' => 0.1,
                ]),
                'paint' => ['text-color' => '#6f9dc4', 'text-halo-color' => '#0c2233', 'text-halo-width' => 1.4],
            ],
            [
                'id' => "water_label_$s", 'type' => 'symbol', 'source' => $s,
                'source-layer' => 'water', 'minzoom' => 11,
                'filter' => ['all', $hasName, ['==', ['geometry-type'], 'Polygon'],
                    ['!', maps_in('kind', ['swimming_pool', 'fountain'])]],
                'layout' => $text([MAPS_FONT_ITALIC], ['interpolate', ['linear'], ['zoom'], 11, 10, 16, 14], [
                    'text-field' => ['get', 'name'], 'text-letter-spacing' => 0.08,
                ]),
                'paint' => ['text-color' => '#6f9dc4', 'text-halo-color' => '#0c2233', 'text-halo-width' => 1.4],
            ],
            [
                // Street numbers on buildings once the map is zoomed to street level.
                'id' => "housenumber_$s", 'type' => 'symbol', 'source' => $s,
                'source-layer' => 'buildings', 'minzoom' => 17,
                'filter' => ['has', 'addr_housenumber'],
                'layout' => $text([MAPS_FONT_REGULAR], ['interpolate', ['linear'], ['zoom'], 17, 9, 19, 12], [
                    'text-field' => ['get', 'addr_housenumber'], 'text-max-width' => 4,
                ]),
                'paint' => ['text-color' => '#8a94a1', 'text-halo-color' => '#141920', 'text-halo-width' => 1.2],
            ],
            [
                // Named residential estates: quiet italic area labels.
                'id' => "area_label_$s", 'type' => 'symbol', 'source' => $s,
                'source-layer' => 'pois', 'minzoom' => 15.5,
                'filter' => ['all', $hasName, maps_in('kind', ['residential'])],
                'layout' => $text([MAPS_FONT_ITALIC], ['interpolate', ['linear'], ['zoom'], 15.5, 9.5, 18, 12], [
                    'text-field' => ['get', 'name'], 'text-max-width' => 6,
                ]),
                'paint' => ['text-color' => '#7f8896', 'text-halo-color' => '#0d1014', 'text-halo-width' => 1.4],
            ],
        ],
        $poiLayers('poi_c', MAPS_POI_TIER_C, 17, false),
        $poiLayers('poi_b', MAPS_POI_TIER_B, 15.5, true),
        $poiLayers('poi_a', MAPS_POI_TIER_A, 14, true),
        [
            $place('place_neighbourhood',
                ['all', ['==', ['get', 'kind'], 'neighbourhood']],
                ['minzoom' => 13.5, 'maxzoom' => 18],
                ['interpolate', ['linear'], ['zoom'], 13.5, 9.5, 16, 12], '#7f8a99', [MAPS_FONT_MEDIUM], $upper),
            $place('place_district',
                ['==', ['get', 'kind'], 'macrohood'],
                ['minzoom' => 10.5, 'maxzoom' => 15],
                ['interpolate', ['linear'], ['zoom'], 10.5, 10, 14, 13], '#9aa5b5', [MAPS_FONT_MEDIUM], $upper),
            $place('place_hamlet',
                ['all', ['==', ['get', 'kind'], 'locality'], ['==', ['get', 'kind_detail'], 'hamlet']],
                ['minzoom' => 12],
                ['interpolate', ['linear'], ['zoom'], 12, 10, 16, 13], '#aab3c0', [MAPS_FONT_REGULAR]),
            $place('place_village',
                ['all', ['==', ['get', 'kind'], 'locality'], ['==', ['get', 'kind_detail'], 'village']],
                ['minzoom' => 9.5],
                ['interpolate', ['linear'], ['zoom'], 9.5, 10.5, 15, 15], '#c2c9d4'),
            $place('place_town',
                ['all', ['==', ['get', 'kind'], 'locality'], ['==', ['get', 'kind_detail'], 'town']],
                ['minzoom' => 7],
                ['interpolate', ['linear'], ['zoom'], 7, 11, 13, 17], '#d6dbe3'),
            $place('place_city',
                ['all', ['==', ['get', 'kind'], 'locality'], ['==', ['get', 'kind_detail'], 'city']],
                ['minzoom' => 3],
                ['interpolate', ['linear'], ['zoom'], 3, 11, 8, 16, 13, 24], '#eef1f6'),
            $place('place_region',
                ['==', ['get', 'kind'], 'region'],
                ['minzoom' => 4, 'maxzoom' => 9],
                ['interpolate', ['linear'], ['zoom'], 4, 10, 8, 13], '#7c8698', [MAPS_FONT_REGULAR], $upper),
            $place('place_country',
                ['==', ['get', 'kind'], 'country'],
                ['minzoom' => 1, 'maxzoom' => 8],
                ['interpolate', ['linear'], ['zoom'], 1, 10, 6, 16], '#a6afbe', [MAPS_FONT_MEDIUM], $upper),
        ],
    );
}

// ── Phase 2: zone downloads ─────────────────────────────────────────────────
// The worker (cron/maps_sync.php, detached or via system cron) advances queued
// zones: ensure CLI → resolve planet build → dry-run sizing → disk check →
// extract with live progress → verify → atomic publish. Extracts cannot
// resume, so page visits NEVER run them — the pseudo-cron steward only fails
// stalled jobs. Proxy consent is per zone (via_proxy): proxy path is
// fail-closed (no working pool proxy = failed job, never silent direct).

const PMTILES_CLI_VERSION = '1.31.2';
const MAPS_PLANET_BUILDS_URL = 'https://build-metadata.protomaps.dev/builds.json';
const MAPS_PLANET_FILE_URL = 'https://build.protomaps.com/';
const MAPS_BUILD_CACHE_TTL = 86400;
const MAPS_WORKER_STALL_SECS = 2700; // 45 min without progress = dead
const MAPS_HEADROOM_MIN = 536870912; // 512 MiB always kept free

function maps_tiles_dir(): string {
    return dirname(__DIR__) . '/tiles';
}

function maps_data_dir(): string {
    return dirname(__DIR__) . '/data/maps';
}

// CLI asset triplet for this host, or null when the worker cannot run here
// (non-Linux, unknown arch — the admin UI says so instead of failing oddly).
function maps_arch(): ?string {
    if (PHP_OS_FAMILY !== 'Linux') {
        return null;
    }
    $m = php_uname('m');
    if ($m === 'x86_64') {
        return 'Linux_x86_64';
    }
    if ($m === 'aarch64') {
        return 'Linux_arm64';
    }
    return null;
}

// SHA-256 pins for the release v1.31.2 assets: the .tar.gz as downloaded and
// the `pmtiles` binary inside it (both computed from the upstream release and
// cross-checked against the binary a live install fetched on its own). The
// binary runs as the web user, so it is never trusted on first use where a
// pin exists. Bumping PMTILES_CLI_VERSION means re-pinning here.
const PMTILES_CLI_PINS = [
    'Linux_x86_64' => [
        'tgz' => '3ed7dbf4ec2e6dfe5e25b6f70d1ffc932729f93c86db353bf514dd71010a312f',
        'bin' => 'a7e9ae10184d109c83f456ccdf6df4f3e2a64ba6cf69d9ed0f9f1840305055c1',
    ],
    'Linux_arm64' => [
        'tgz' => 'f8bd47e7ea866863489cad588fbaf2f31f42e5821f7a03f009b3769f05801cb1',
        'bin' => '8cd0affde1ba5380b7cea6de0f94c674f88e4f586c77ae5820ea9652862691f4',
    ],
];

// The pin for this host, or null when none applies: unsupported arch, or a
// test/operator override (DDMGMT_PMTILES_URL / DDMGMT_PMTILES_BIN) that
// deliberately points somewhere else — those keep the trust-on-first-use
// record below.
/** @return ?array{tgz:string,bin:string} */
function maps_cli_pin(): ?array {
    foreach (['DDMGMT_PMTILES_URL', 'DDMGMT_PMTILES_BIN'] as $override) {
        $env = getenv($override);
        if (is_string($env) && $env !== '') {
            return null;
        }
    }
    $arch = maps_arch();
    return $arch !== null ? (PMTILES_CLI_PINS[$arch] ?? null) : null;
}

function maps_cli_asset(): ?string {
    $arch = maps_arch();
    if ($arch === null) {
        return null;
    }
    return 'go-pmtiles_' . PMTILES_CLI_VERSION . '_' . $arch . '.tar.gz';
}

function maps_cli_url(): ?string {
    // DDMGMT_PMTILES_URL overrides for tests (local stub server).
    $env = getenv('DDMGMT_PMTILES_URL');
    if (is_string($env) && $env !== '') {
        return $env;
    }
    $asset = maps_cli_asset();
    if ($asset === null) {
        return null;
    }
    return 'https://github.com/protomaps/go-pmtiles/releases/download/v'
        . PMTILES_CLI_VERSION . '/' . $asset;
}

// Test seam (see _cleanup_roll precedent): unit tests inject a stub runner;
// production always uses proc_open through maps_cli_exec(). Pass $clear to
// uninstall the stub (suites must not leak it into later files).
function maps_cli_runner(?callable $fn = null, bool $clear = false): ?callable {
    static $runner = null;
    if ($clear) {
        $runner = null;
        return null;
    }
    if ($fn !== null) {
        $runner = $fn;
    }
    return $runner;
}

/** @return array{bool,string} [ok, output-or-error] */
function maps_cli_exec(array $args, ?array $env = null, ?callable $onChunk = null): array {
    $runner = maps_cli_runner();
    if ($runner !== null) {
        return $runner($args, $env, $onChunk);
    }
    $bin = maps_cli_bin();
    $cmd = escapeshellarg($bin);
    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg((string)$a);
    }
    $base = ['PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'TMPDIR' => sys_get_temp_dir()];
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes, null, $env !== null ? $env + $base : null);
    if (!is_resource($proc)) {
        return [false, 'could not spawn pmtiles CLI'];
    }
    fclose($pipes[2]); // progress + logs both arrive on stdout; drop stderr
    $out = '';
    while (!feof($pipes[1])) {
        $chunk = fread($pipes[1], 65536);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $out .= $chunk;
        if ($onChunk !== null) {
            $onChunk($chunk);
        }
    }
    fclose($pipes[1]);
    $code = proc_close($proc);
    if ($code !== 0) {
        return [false, 'pmtiles exit ' . $code . ': ' . substr($out, -500)];
    }
    return [true, $out];
}

// Binary path. DDMGMT_PMTILES_BIN overrides for tests (stub executable).
function maps_cli_bin(): string {
    $env = getenv('DDMGMT_PMTILES_BIN');
    if (is_string($env) && $env !== '') {
        return $env;
    }
    return maps_data_dir() . '/pmtiles';
}

/** @return array{bool,string} [ok, error] */
function maps_ensure_cli(bool $viaProxy, ?string $proxy): array {
    if (!function_exists('curl_init')) {
        return [false, 'code:no_curl'];
    }
    $bin = maps_cli_bin();
    // Pin first, execute second: an installed binary that is not the pinned
    // release is deleted BEFORE the version probe would run it, and the
    // fetch below replaces it.
    $pin = maps_cli_pin();
    if ($pin !== null && is_file($bin) && !hash_equals($pin['bin'], (string)hash_file('sha256', $bin))) {
        @unlink($bin);
    }
    // A test runner installed via maps_cli_runner() answers the version
    // probe below, so the file check is skipped in that case — hermetic
    // suites must never reach the network for a CLI download.
    if ((is_file($bin) && is_executable($bin)) || maps_cli_runner() !== null) {
        // The real CLI takes a `version` subcommand (no --version flag).
        [$ok, $out] = maps_cli_exec(['version']);
        if ($ok && str_contains($out, PMTILES_CLI_VERSION)) {
            if (!is_file($bin)) {
                return [true, '']; // stubbed CLI under test
            }
            // Pinned builds were verified against their pin before the probe
            // above ran; without a pin (override / other arch) the hash
            // recorded at first use is the reference instead.
            if ($pin !== null) {
                return [true, ''];
            }
            $hash = hash_file('sha256', $bin);
            $known = get_setting('maps_cli_sha256', '');
            if ($known === '') {
                set_setting('maps_cli_sha256', (string)$hash);
                audit('maps_cli_fetch', null, null, 'v' . PMTILES_CLI_VERSION . ' sha256=' . substr((string)$hash, 0, 16) . '…');
            } elseif (!hash_equals($known, (string)$hash)) {
                return [false, 'code:hash_mismatch'];
            }
            return [true, ''];
        }
        // Stale or broken binary — fall through to re-fetch.
    }
    $url = maps_cli_url();
    if ($url === null) {
        return [false, 'code:no_build'];
    }
    if ($viaProxy && $proxy === null) {
        return [false, 'code:proxy_empty'];
    }
    $dir = maps_data_dir();
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
        return [false, 'code:mkdir'];
    }
    $tmp = $dir . '/pmtiles.tgz';
    [$ok, $err] = maps_fetch_file($url, $tmp, $viaProxy ? $proxy : null);
    if (!$ok) {
        return [false, 'code:fetch_failed|' . $err];
    }
    // Verify the archive against its pin BEFORE anything is unpacked: the
    // download may have crossed a public pool proxy.
    if ($pin !== null && !hash_equals($pin['tgz'], (string)hash_file('sha256', $tmp))) {
        @unlink($tmp);
        return [false, 'code:hash_mismatch'];
    }
    try {
        $phar = new PharData($tmp);
        $phar->extractTo($dir, 'pmtiles', true);
    } catch (Throwable $e) {
        @unlink($tmp);
        return [false, 'code:bad_archive'];
    }
    @unlink($tmp);
    @chmod($bin, 0750);
    [$ok, $out] = maps_cli_exec(['version']);
    if (!$ok || !str_contains($out, PMTILES_CLI_VERSION)) {
        return [false, 'code:version_mismatch'];
    }
    $hash = hash_file('sha256', $bin);
    if ($pin !== null) {
        if (!hash_equals($pin['bin'], (string)$hash)) {
            @unlink($bin);
            return [false, 'code:hash_mismatch'];
        }
        audit('maps_cli_fetch', null, null, 'v' . PMTILES_CLI_VERSION . ' sha256=' . substr((string)$hash, 0, 16) . '… (pinned)');
        return [true, ''];
    }
    $known = get_setting('maps_cli_sha256', '');
    if ($known === '') {
        set_setting('maps_cli_sha256', (string)$hash);
        audit('maps_cli_fetch', null, null, 'v' . PMTILES_CLI_VERSION . ' sha256=' . substr((string)$hash, 0, 16) . '…');
    } elseif (!hash_equals($known, (string)$hash)) {
        return [false, 'code:hash_mismatch'];
    }
    return [true, ''];
}

// Stream a URL to disk with resume (Range) across calls. Proxy failures are
// returned, never silently retried direct — the caller owns fail-closed.
/** @return array{bool,string} [ok, error] */
function maps_fetch_file(string $url, string $dest, ?string $proxy): array {
    $ch = curl_init($url);
    if ($ch === false) {
        return [false, 'could not start download'];
    }
    $have = is_file($dest) ? filesize($dest) : 0;
    // @: an unwritable path warns — the false branch below owns the error.
    $fh = @fopen($dest, $have > 0 ? 'ab' : 'wb');
    if ($fh === false) {
        unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit
        return [false, 'cannot write download file'];
    }
    curl_setopt($ch, CURLOPT_FILE, $fh);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
    curl_setopt($ch, CURLOPT_TIMEOUT, 600);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    if ($have > 0) {
        curl_setopt($ch, CURLOPT_RANGE, $have . '-');
    }
    if ($proxy !== null) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
    }
    $ok = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit
    fclose($fh);
    if ($ok && ($code === 200 || ($have > 0 && $code === 206))) {
        return [true, ''];
    }
    return [false, $proxy !== null
        ? 'download failed through proxy (HTTP ' . $code . ($err !== '' ? ': ' . $err : '') . ')'
        : 'download failed (HTTP ' . $code . ($err !== '' ? ': ' . $err : '') . ')'];
}

// Latest planet build key (e.g. 20260918), cached a day. Reuses osm_fetch so
// the global proxy toggle + pool apply exactly like every other OSM fetch.
/** @return array{?string,string} [key-or-null, error] */
function maps_latest_build(): array {
    $cached = get_setting('maps_build_key', '');
    $at = (int)get_setting('maps_build_at', '0');
    if ($cached !== '' && (time() - $at) < MAPS_BUILD_CACHE_TTL) {
        return [$cached, ''];
    }
    $body = osm_fetch(MAPS_PLANET_BUILDS_URL, 1048576);
    if ($body === false) {
        return [null, 'code:build_list_unreachable'];
    }
    try {
        $list = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return [null, 'code:build_list_invalid'];
    }
    $best = null;
    foreach (is_array($list) ? $list : [] as $entry) {
        $key = is_array($entry) ? ($entry['key'] ?? '') : '';
        if (is_string($key) && str_ends_with($key, '.pmtiles')
            && ($best === null || $key > $best)) {
            $best = $key;
        }
    }
    if ($best === null) {
        return [null, 'code:build_list_empty'];
    }
    $key = substr($best, 0, -8);
    set_setting('maps_build_key', $key);
    set_setting('maps_build_at', (string)time());
    return [$key, ''];
}

// Validate a zone bbox. Numbers arrive pre-cast; this enforces geography:
// lon ±180, lat ±85 (WebMercator wall), ordered, non-degenerate, and no
// antimeridian crossing in Phase 2 (the CLI supports it, our overlap and
// budget math does not — unlock later).
/** @return array{bool,string} [ok, error] */
function maps_validate_bbox(float $minLon, float $minLat, float $maxLon, float $maxLat): array {
    foreach (['min_lon' => $minLon, 'max_lon' => $maxLon] as $k => $v) {
        if (!is_finite($v) || $v < -180.0 || $v > 180.0) {
            return [false, 'code:lon_range'];
        }
    }
    foreach (['min_lat' => $minLat, 'max_lat' => $maxLat] as $k => $v) {
        if (!is_finite($v) || $v < -85.0 || $v > 85.0) {
            return [false, 'code:lat_range'];
        }
    }
    if ($minLon >= $maxLon || $minLat >= $maxLat) {
        return [false, 'code:unordered'];
    }
    if (($maxLon - $minLon) < 0.0001 || ($maxLat - $minLat) < 0.0001) {
        return [false, 'code:tiny'];
    }
    return [true, ''];
}

/** @return array{?int,string} [id-or-null, error] */
function maps_zone_add(string $name, float $minLon, float $minLat, float $maxLon, float $maxLat, int $maxzoom, bool $viaProxy): array {
    $name = trim($name);
    if ($name === '' || mb_strlen($name) > 64) {
        return [null, 'code:bad_name'];
    }
    [$ok, $err] = maps_validate_bbox($minLon, $minLat, $maxLon, $maxLat);
    if (!$ok) {
        return [null, $err];
    }
    if ($maxzoom !== 14 && $maxzoom !== 15) {
        return [null, 'code:bad_zoom'];
    }
    if (maps_disk_free() < MAPS_HEADROOM_MIN) {
        return [null, 'code:disk_full_queue'];
    }
    try {
        $db = get_db();
        $db->prepare(
            'INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, maxzoom, via_proxy, file_token)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        )->execute([$name, $minLon, $minLat, $maxLon, $maxLat, $maxzoom, $viaProxy ? 1 : 0, bin2hex(random_bytes(16))]);
        $id = (int)$db->lastInsertId();
    } catch (Throwable $e) {
        log_err('Zone add: ' . $e->getMessage());
        return [null, 'code:save_failed'];
    }
    audit('maps_zone_add', null, null, "id={$id} name={$name}");
    return [$id, ''];
}

/** @return array<int,array<string,mixed>> */
function maps_zone_list(): array {
    try {
        return get_db()->query('SELECT * FROM map_zones ORDER BY id ASC')->fetchAll();
    } catch (Throwable) {
        return [];
    }
}

// Whether the zone's row still exists. A zone deleted while its download runs
// must not be published afterwards (an orphan file no row would ever remove).
// Unreadable store answers true: never destroy work on a transient DB error.
// It reads live state, so two calls in one pass may differ (row deleted in
// between) — hence impure for static analysis.
/** @phpstan-impure */
function maps_zone_exists(int $id): bool {
    try {
        $st = get_db()->prepare('SELECT 1 FROM map_zones WHERE id = ? LIMIT 1');
        $st->execute([$id]);
        return (bool)$st->fetchColumn();
    } catch (Throwable) {
        return true;
    }
}

// Removes zone files no row claims any more (deleted mid-download, crashed
// publish). Only files older than an hour go: a fresh .part may belong to a
// worker that has not written its row state yet.
function maps_sweep_orphan_files(): int {
    $removed = 0;
    foreach (glob_list(maps_tiles_dir() . '/zone_*') as $f) {
        if (!preg_match('/^zone_(\d+)(?:_([0-9a-f]{32}))?\.(pmtiles|part)$/', basename($f), $m)) {
            continue;
        }
        if ((time() - (int)@filemtime($f)) < 3600) {
            continue;
        }
        // Kept only while a row claims THIS name: a live zone's own file (or
        // its legacy name, which the token lookup renames on first touch).
        if (maps_zone_exists((int)$m[1])) {
            $tok = $m[2] === '' ? null : $m[2];
            $current = maps_zone_ensure_token((int)$m[1]);
            if ($tok === null || $current === null || $tok === $current) {
                continue;
            }
        }
        if (@unlink($f)) {
            $removed++;
        }
    }
    return $removed;
}

function maps_zone_delete(int $id): bool {
    if ($id <= 0) {
        return false;
    }
    // Resolve the file names while the row (and its token) still exists.
    $final = maps_zone_path($id);
    $part  = maps_zone_path($id, true);
    try {
        get_db()->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$id]);
    } catch (Throwable $e) {
        log_err('Zone delete: ' . $e->getMessage());
        return false;
    }
    @unlink($final);
    @unlink($part);
    audit('maps_zone_delete', null, null, "id={$id}");
    return true;
}

function maps_zone_retry(int $id): bool {
    if ($id <= 0) {
        return false;
    }
    try {
        $st = get_db()->prepare(
            "UPDATE map_zones SET status = 'queued', error = NULL,
             bytes_expected = NULL, bytes_done = 0, speed_bps = NULL, eta_secs = NULL
             WHERE id = ? AND status = 'failed'"
        );
        $st->execute([$id]);
        return $st->rowCount() === 1;
    } catch (Throwable $e) {
        log_err('Zone retry: ' . $e->getMessage());
        return false;
    }
}

// Freshness: a ready zone is stale once the cached planet build key moves
// past the zone's own build_key (daily planet builds). Only the CACHED key
// is consulted — page views never fetch the build list; the worker refreshes
// the cache whenever it sizes. Unknown cache ('') means unknown freshness:
// not stale. A NULL row key (pre-freshness rows) never equals a known
// build, so it reads stale — the safe direction (re-download, not silence).
function maps_zone_is_stale(array $row): bool {
    if (($row['status'] ?? '') !== 'ready') {
        return false;
    }
    $latest = get_setting('maps_build_key', '');
    if ($latest === '') {
        return false;
    }
    return (string)($row['build_key'] ?? '') !== $latest;
}

// Re-queue a ready or failed zone (new planet build, or a manual nudge):
// same reset as retry; the worker re-sizes, re-downloads, verifies, and
// republishes atomically. In-flight rows are left alone (rowCount 0).
function maps_zone_refresh(int $id): bool {
    if ($id <= 0) {
        return false;
    }
    try {
        $st = get_db()->prepare(
            "UPDATE map_zones SET status = 'queued', error = NULL,
             bytes_expected = NULL, bytes_done = 0, speed_bps = NULL, eta_secs = NULL
             WHERE id = ? AND status IN ('ready', 'failed')"
        );
        $st->execute([$id]);
        return $st->rowCount() === 1;
    } catch (Throwable $e) {
        log_err('Zone refresh: ' . $e->getMessage());
        return false;
    }
}

// Best pool proxy URL for a long download (same ok → new → dead ordering as
// osm_fetch), or null when none is usable. Never falls back to direct here.
function maps_pick_proxy(): ?string {
    $pool = osm_proxy_pool();
    if (!$pool) {
        return null;
    }
    usort($pool, function ($a, $b) {
        $rank = static fn($p) => match ($p['last_status'] ?? '') {
            'ok'   => 0,
            'new'  => 1,
            default => 2,
        };
        $ra = $rank($a);
        if ($ra !== ($rb = $rank($b))) {
            return $ra <=> $rb;
        }
        return ((int)($a['latency_ms'] ?? PHP_INT_MAX)) <=> ((int)($b['latency_ms'] ?? PHP_INT_MAX));
    });
    foreach ($pool as $px) {
        if (($px['last_status'] ?? '') !== 'fail') {
            return (string)$px['url'];
        }
    }
    return null;
}

function maps_disk_free(): int {
    $free = @disk_free_space(maps_tiles_dir());
    return $free === false ? 0 : (int)$free;
}

// Refuse a download unless the exact sized bytes plus headroom fit.
function maps_disk_ok(int $needBytes): bool {
    return maps_disk_free() >= $needBytes + MAPS_HEADROOM_MIN
        && maps_disk_free() >= MAPS_HEADROOM_MIN;
}

// Fraction of $b covered by $a (0–1): the UI warns on overlapping zones
// because each zone file carries its own copy of shared tiles.
/** @param array{min_lon:float,min_lat:float,max_lon:float,max_lat:float} $a $b */
function maps_overlap_frac(array $a, array $b): float {
    $w = max(0.0, min($a['max_lon'], $b['max_lon']) - max($a['min_lon'], $b['min_lon']));
    $h = max(0.0, min($a['max_lat'], $b['max_lat']) - max($a['min_lat'], $b['min_lat']));
    $areaB = max(0.0, ($b['max_lon'] - $b['min_lon']) * ($b['max_lat'] - $b['min_lat']));
    if ($areaB <= 0.0) {
        return 0.0;
    }
    return min(1.0, ($w * $h) / $areaB);
}

// Parse one CLI progress line:
//   fetching chunks  42% |███| (1.4/32 MB, 1.1 MB/s) [3s:24s]
// Done-bytes without a unit inherit the total's (the CLI prints "1.4/32 MB").
// The opening (0 B/32 MB, no speed yet) and closing (100%, no ETA) lines lack
// a group each — both are optional, missing values answer 0.
/** @return ?array{pct:int,done:int,total:int,speed:int,eta:int} */
function maps_parse_progress(string $line): ?array {
    if (!str_contains($line, 'fetching chunks')) {
        return null;
    }
    if (!preg_match('/(\d+)%/', $line, $pm)) {
        return null;
    }
    if (!preg_match('/\(\s*([\d.]+)\s*([KMGT]?B)?\s*\/\s*([\d.]+)\s*([KMGT]?B)\s*(?:,\s*([\d.]+)\s*([KMGT]?B)\/s\s*)?\)/i', $line, $m)) {
        return null;
    }
    $done = maps_parse_bytes($m[1], $m[2] !== '' ? $m[2] : $m[4]);
    $total = maps_parse_bytes($m[3], $m[4]);
    $speed = isset($m[5], $m[6]) && $m[5] !== '' ? maps_parse_bytes($m[5], $m[6]) : 0;
    if ($done === null || $total === null || $speed === null) {
        return null;
    }
    $eta = 0;
    if (preg_match('/\[\s*[^:\]]+\s*:\s*([^\]]+)\s*\]/', $line, $t)) {
        $eta = maps_parse_dur($t[1]);
    }
    return [
        'pct'   => min(100, (int)$pm[1]),
        'done'  => $done,
        'total' => $total,
        'speed' => $speed,
        'eta'   => $eta,
    ];
}

function maps_parse_bytes(string $num, string $unit): ?int {
    $n = (float)$num;
    if (!is_finite($n) || $n < 0) {
        return null;
    }
    $mult = match (strtoupper($unit)) {
        'B' => 1, 'KB' => 1024, 'MB' => 1048576,
        'GB' => 1073741824, 'TB' => 1099511627776,
        default => null,
    };
    if ($mult === null) {
        return null;
    }
    return (int)round($n * $mult);
}

// CLI durations: 24s, 10m55s, 1h2m3s, 0s.
function maps_parse_dur(string $s): int {
    if (!preg_match('/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/', trim($s), $m)) {
        return 0;
    }
    if ($m[0] === '') {
        return 0;
    }
    return ((int)($m[1] ?? 0)) * 3600 + ((int)($m[2] ?? 0)) * 60 + ((int)($m[3] ?? 0));
}

// Worker lock (settings rows, no new table): one extractor at a time.
// A lock older than the stall window belongs to a dead process — stealable.
/** @return array{bool,string} [acquired, holder-or-error] */
function maps_worker_lock(): array {
    $mine = json_encode(['by' => php_uname('n') . ':' . getmypid(), 'at' => time()]);
    try {
        $db = get_db();
        // Read the row itself (never the per-process settings cache) and win
        // it with a compare-and-swap: the INSERT / UPDATE succeeds for exactly
        // one of any number of workers started at the same instant — a plain
        // read-then-write let two of them both "acquire" and extract the same
        // zone into the same .part file.
        $st = $db->query("SELECT value FROM settings WHERE key_name = 'maps_worker_lock' LIMIT 1");
        $raw = $st === false ? false : $st->fetchColumn();
        if ($raw === false) {
            $win = $db->prepare("INSERT IGNORE INTO settings (key_name, value, label) VALUES ('maps_worker_lock', ?, '')");
            $win->execute([$mine]);
        } else {
            $raw = (string)$raw;
            if ($raw !== '') {
                try {
                    $lock = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
                    if (is_array($lock) && (time() - (int)($lock['at'] ?? 0)) < MAPS_WORKER_STALL_SECS) {
                        return [false, 'worker already running (' . substr((string)($lock['by'] ?? '?'), 0, 32) . ')'];
                    }
                } catch (Throwable) {
                    // Corrupt lock — stealable like a stale one.
                }
            }
            $win = $db->prepare("UPDATE settings SET value = ? WHERE key_name = 'maps_worker_lock' AND value = ?");
            $win->execute([$mine, $raw]);
        }
        if ($win->rowCount() !== 1) {
            return [false, 'worker already running (lock taken a moment ago)'];
        }
    } catch (Throwable $e) {
        log_err('Maps worker lock: ' . $e->getMessage());
        return [false, 'lock store unavailable'];
    }
    // Keep this process's settings cache coherent with what it just wrote.
    $cache = &_settings_store();
    if ($cache !== null) {
        $cache['maps_worker_lock'] = (string)$mine;
    }
    return [true, ''];
}

function maps_worker_touch(): void {
    set_setting('maps_worker_lock', json_encode(['by' => php_uname('n') . ':' . getmypid(), 'at' => time()]));
}

function maps_worker_unlock(): void {
    $db = get_db();
    try {
        $db->prepare("DELETE FROM settings WHERE key_name = 'maps_worker_lock'")->execute();
    } catch (Throwable) {
    }
    $cache = &_settings_store();
    $cache = null;
}

// Hourly steward (called from the pseudo-cron slot): fail jobs whose CLI
// died without a word, release the lock behind them. Never downloads.
function maps_steward(): void {
    maps_sweep_orphan_files();
    try {
        $db = get_db();
        $cutoff = gmdate('Y-m-d H:i:s', time() - MAPS_WORKER_STALL_SECS);
        $st = $db->prepare(
            "UPDATE map_zones SET status = 'failed', error = 'code:stalled'
             WHERE status IN ('sizing','downloading') AND updated_at < ?"
        );
        $st->execute([$cutoff]);
        if ($st->rowCount() > 0) {
            log_err('Maps steward failed ' . $st->rowCount() . ' stalled zone(s)');
            maps_worker_unlock();
        }
    } catch (Throwable $e) {
        log_err('Maps steward: ' . $e->getMessage());
    }
}

// Throttled wrapper for page visits: a dice roll first (same rationale as
// _cleanup_roll — no DB touch on most visits), then an hourly timestamp.
function maps_steward_if_due(float $chance = 1.0): void {
    static $ran = false;
    if ($ran) {
        return;
    }
    if ($chance < 1.0) {
        try {
            if (random_int(1, max(1, (int)round(1 / $chance))) !== 1) {
                return;
            }
        } catch (Throwable) {
            // Dead CSPRNG — run the (cheap, guarded) steward rather than skip.
        }
    }
    $ran = true;
    try {
        $last = (int)get_setting('maps_steward_at', '0');
        if ((time() - $last) < 3600) {
            return;
        }
        set_setting('maps_steward_at', (string)time());
        maps_steward();
    } catch (Throwable $e) {
        log_err('Maps steward slot: ' . $e->getMessage());
    }
}

// A php the worker can run under. PHP_BINARY is only runnable from the CLI
// SAPI: under mod_php it is empty (or the Apache binary) and under FPM it is
// php-fpm, so a detached `$PHP_BINARY script &` would die silently while the
// admin is told the worker started. Fall back to the CLI next to the install.
function maps_php_cli(): ?string {
    return host_php_cli(); // probing lives in includes/host.php with the other capability checks
}

// Zone downloads run the external pmtiles binary from a long-lived worker
// (cron/maps_sync.php): that needs process execution, Linux, cURL for the
// one-time CLI download and a writable data directory. Free shared hosting
// usually has none of it — the feature is then refused up front with a clear
// message instead of leaving zones queued forever. The OSM map provider, the
// default, needs none of this.
function maps_downloads_supported(): bool {
    return host_is_linux() && host_can_proc_open() && host_has_curl() && host_dir_writable(maps_data_dir());
}

// Detached kick after queueing (Linux + exec only): the worker then runs
// without holding any request. False = admin waits for system cron.
function maps_kick_worker(): bool {
    if (!host_can_detach()) {
        return false;
    }
    $cli = maps_php_cli();
    if ($cli === null) {
        return false;
    }
    $php = escapeshellarg($cli);
    $script = escapeshellarg(dirname(__DIR__) . '/cron/maps_sync.php');
    @exec($php . ' ' . $script . ' > /dev/null 2>&1 &');
    return true;
}

// Full pipeline for one zone. Every state change hits the DB so the UI (and
// a killed worker's successor) always sees the truth.
/** @return array{bool,string} [ok, error] */
function maps_process_one(array $zone): array {
    $id = (int)$zone['id'];
    $db = get_db();
    $mark = static function (string $status, array $extra = []) use ($db, $id): void {
        $sets = 'status = ?';
        $params = [$status];
        foreach ($extra as $k => $v) {
            $sets .= ", {$k} = ?";
            $params[] = $v;
        }
        $params[] = $id;
        try {
            $db->prepare("UPDATE map_zones SET {$sets} WHERE id = ?")->execute($params);
        } catch (Throwable) {
        }
    };

    $viaProxy = ((int)($zone['via_proxy'] ?? 1)) === 1;
    $proxy = $viaProxy ? maps_pick_proxy() : null;
    if ($viaProxy && $proxy === null) {
        $mark('failed', ['error' => 'code:proxy_empty']);
        return [false, 'code:proxy_empty'];
    }

    [$ok, $err] = maps_ensure_cli($viaProxy, $proxy);
    if (!$ok) {
        $mark('failed', ['error' => substr($err, 0, 200)]);
        return [false, $err];
    }

    [$build, $err] = maps_latest_build();
    if ($build === null) {
        $mark('failed', ['error' => substr($err, 0, 200)]);
        return [false, $err];
    }
    $planet = MAPS_PLANET_FILE_URL . $build . '.pmtiles';
    // File names carry the zone's secret token (see maps_zone_ensure_token):
    // resolved once, so a delete mid-run cannot redirect later steps.
    $partPath  = maps_zone_path($id, true);
    $finalPath = maps_zone_path($id);
    $bbox = $zone['min_lon'] . ',' . $zone['min_lat'] . ',' . $zone['max_lon'] . ',' . $zone['max_lat'];
    $maxzoom = (int)$zone['maxzoom'];

    // ── Sizing: exact bytes before a single tile is kept ──
    $mark('sizing', ['build_key' => $build]);
    [$ok, $out] = maps_cli_exec(
        ['extract', $planet, $partPath,
         '--bbox=' . $bbox, '--maxzoom=' . $maxzoom, '--dry-run'],
        $viaProxy ? ['HTTP_PROXY' => $proxy, 'HTTPS_PROXY' => $proxy] : null
    );
    if (!$ok) {
        $mark('failed', ['error' => 'code:sizing_failed|' . substr($out, -160)]);
        return [false, 'code:sizing_failed'];
    }
    if (!preg_match('/archive size of ([\d.]+)\s*([KMGT]?B)/', $out, $sm)) {
        $mark('failed', ['error' => 'code:sizing_empty']);
        return [false, 'code:sizing_empty'];
    }
    $expected = maps_parse_bytes($sm[1], $sm[2]);
    if ($expected === null || $expected <= 0) {
        $mark('failed', ['error' => 'code:sizing_empty']);
        return [false, 'code:sizing_empty'];
    }
    if (!maps_disk_ok($expected)) {
        $mark('failed', ['error' => 'code:disk_short|' . $expected]);
        return [false, 'code:disk_short'];
    }
    $mark('downloading', ['bytes_expected' => $expected, 'bytes_done' => 0]);

    // ── Extract: progress lines stream into the row (throttled) ──
    $lastWrite = 0;
    $onChunk = static function (string $chunk) use ($db, $id, &$lastWrite): void {
        $prog = null;
        foreach (preg_split('/[\r\n]+/', $chunk) as $line) {
            $p = maps_parse_progress((string)$line);
            if ($p !== null) {
                $prog = $p;
            }
        }
        if ($prog === null || (microtime(true) - $lastWrite) < 2.0) {
            return;
        }
        $lastWrite = microtime(true);
        try {
            $db->prepare(
                'UPDATE map_zones SET bytes_done = ?, speed_bps = ?, eta_secs = ? WHERE id = ?'
            )->execute([$prog['done'], $prog['speed'], $prog['eta'], $id]);
        } catch (Throwable) {
        }
    };
    [$ok, $out] = maps_cli_exec(
        ['extract', $planet, $partPath,
         '--bbox=' . $bbox, '--maxzoom=' . $maxzoom,
         '--download-threads=' . ($viaProxy ? '1' : '4')],
        $viaProxy ? ['HTTP_PROXY' => $proxy, 'HTTPS_PROXY' => $proxy] : null,
        $onChunk
    );
    $part = $partPath;
    if (!$ok || !is_file($part)) {
        $mark('failed', ['error' => 'code:download_failed|' . substr($out, -160)]);
        @unlink($part);
        return [false, 'code:download_failed'];
    }
    // Deleted while it downloaded: nothing may publish for a row that is gone.
    if (!maps_zone_exists($id)) {
        @unlink($part);
        return [false, 'code:deleted'];
    }

    // ── Verify + publish atomically ──
    [$ok, $out] = maps_cli_exec(['verify', $part]);
    if (!$ok) {
        $mark('failed', ['error' => 'code:verify_failed']);
        @unlink($part);
        return [false, 'code:verify_failed'];
    }
    $final = $finalPath;
    if (!@rename($part, $final)) {
        $mark('failed', ['error' => 'code:publish_failed']);
        @unlink($part);
        return [false, 'code:publish_failed'];
    }
    if (!maps_zone_exists($id)) { // deleted during verify/publish
        @unlink($final);
        return [false, 'code:deleted'];
    }
    $mark('ready', [
        'bytes_done' => filesize($final),
        'speed_bps' => null, 'eta_secs' => null, 'error' => null,
    ]);
    audit('maps_zone_ready', null, null, "id={$id} bytes=" . filesize($final));
    return [true, ''];
}

function maps_fmt_bytes(int $n): string {
    if ($n < 1024) {
        return $n . ' B';
    }
    $units = ['KiB', 'MiB', 'GiB', 'TiB'];
    $e = (int)floor(log($n, 1024));
    $e = min($e, 4);
    return round($n / (1024 ** $e), 1) . ' ' . $units[$e - 1];
}

// Zone error column holds either a code ('code:disk_short|12345') or legacy
// free text. Codes translate through admin.maps.err.*; details (byte counts,
// CLI tails) append raw — they are numbers and tool output, never secrets.
function maps_zone_error_text(?string $raw): string {
    if ($raw === null || $raw === '') {
        return '';
    }
    if (!str_starts_with($raw, 'code:')) {
        return $raw;
    }
    $parts = explode('|', substr($raw, 5), 2);
    $key = 'admin.maps.err.' . $parts[0];
    $msg = t($key);
    $text = $msg !== $key ? $msg : $parts[0];
    if (isset($parts[1]) && $parts[1] !== '') {
        $detail = $parts[1];
        if ($parts[0] === 'disk_short' && ctype_digit($detail)) {
            $detail = maps_fmt_bytes((int)$detail);
        }
        $text .= ' — ' . $detail;
    }
    return $text;
}
