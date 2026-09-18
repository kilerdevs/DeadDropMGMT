# e2e map fixture

`micro.pmtiles` is a tiny Protomaps-basemap extract used by the self-hosted
map e2e spec (`e2e/tests/maps-selfhosted.spec.js`). It is served by the test
web server as a same-origin static file — no test ever touches the network
for tiles.

- **Source:** `https://build.protomaps.com/20260918.pmtiles`
  (Protomaps basemap v4.15.2, ODbL — © OpenStreetMap contributors)
- **Command:**
  `pmtiles extract <planet> micro.pmtiles --bbox=20.95,52.20,21.10,52.28 --maxzoom=10`
  (central Warsaw; z0–10, overzoomed client-side in the test)
- **SHA256:** `C0BB9B4BE75F96F362C3BAED8770D5CF6335E2FA64C386B73E6135707C33032A`
- **Verified:** `pmtiles verify` passes.

Regenerate with the pinned `pmtiles` CLI (see `includes/maps.php`
`PMTILES_CLI_VERSION` once Phase 2 lands) if the spec needs a fresher build.
