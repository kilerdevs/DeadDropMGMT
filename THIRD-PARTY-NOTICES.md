# Third-Party Notices

DeadDropMGMT bundles the following third-party components. All of them are
committed unmodified as static files and served from your own domain — nothing
is fetched over the network to load them. Runtime calls to external *services*
(OpenStreetMap tiles/Nominatim) involve no third-party code distribution and
are documented in the README instead.

---

## Leaflet 1.9.4

- **Path:** `admin/vendor/leaflet/` (`leaflet.js`, `leaflet.css`, `images/`)
- **Homepage:** https://leafletjs.com/
- **License:** BSD-2-Clause

Copyright (c) 2010-2024, Vladimir Agafonkin
Copyright (c) 2011-2019, CloudMade
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

---

## QRCode.js

- **Path:** `admin/vendor/qrcode/qrcode.js`
- **Homepage:** https://github.com/davidshimjs/qrcodejs
- **License:** MIT
- **Note:** davidshimjs' port builds on Kazuhiko Arase's original QRCode
  generator (also MIT, https://www.d-project.com/).

Copyright (c) 2012 davidshimjo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## IBM Plex Mono v20 (latin + latin-ext subsets)

- **Path:** `fonts/ibm-plex-mono/` (4 `.woff2` files)
- **Homepage:** https://github.com/IBM/plex
- **License:** SIL Open Font License, Version 1.1

Copyright © 2017 IBM Corp. with Reserved Font Name "Plex"

The complete license text ships alongside the font itself — see
[`fonts/ibm-plex-mono/LICENSE.txt`](fonts/ibm-plex-mono/LICENSE.txt). The SIL
Open Font License requires that the font (with its license) stay together when
redistributed, which this layout preserves.

---

## Noto Sans map-label glyphs (Regular, Medium, Italic)

- **Path:** `fonts/glyphs/` (SDF glyph `.pbf` ranges: Latin, Latin Extended,
  Cyrillic, general punctuation)
- **Homepage:** https://github.com/protomaps/basemaps-assets (glyphs built
  with https://github.com/maplibre/font-maker from Noto Sans)
- **License:** SIL Open Font License, Version 1.1

Copyright 2022 The Noto Project Authors (https://github.com/notofonts)

Labels on the self-hosted map (street, place and POI names) are drawn from
these files, served from your own domain — no glyph server is contacted. The
complete license text ships alongside them in
[`fonts/glyphs/OFL.txt`](fonts/glyphs/OFL.txt), keeping the font and its
license together as the OFL requires.

---

## MapLibre GL JS 5.13.0

- **Path:** `maplibre/maplibre-gl.js`, `maplibre/maplibre-gl.css`
- **Homepage:** https://maplibre.org/
- **License:** BSD-3-Clause (incorporates BSD-3-Clause Mapbox code ≤ v1.13
  and MIT d3-color — full text in `maplibre/LICENSE-maplibre.txt`)

Vector map renderer for the self-hosted map provider. Served from your own
domain; fetches tiles only from your own `/tiles/` directory.

---

## PMTiles JS client 4.5.0

- **Path:** `maplibre/pmtiles.js`
- **Homepage:** https://github.com/protomaps/pmtiles
- **License:** BSD-3-Clause, Protomaps LLC (the PMTiles spec itself is
  public domain/CC0 — full text in `maplibre/LICENSE-pmtiles.txt`)

Single-file tile-archive reader: issues HTTP Range requests against local
`.pmtiles` zone files, no tile server involved.

---

## E2E map fixture (Protomaps basemap extract)

- **Path:** `e2e/fixtures/micro.pmtiles` (test-only, never served in prod)
- **Source:** Protomaps daily planet build (see `e2e/fixtures/README.md`
  for the exact build, bbox, and SHA256)
- **License:** Open Database License (ODbL) Produced Work —
  © OpenStreetMap contributors (attribution rendered on every map).
