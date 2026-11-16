# Offline mode

Enable with `scan.offline: true` in `config.yaml`, the Settings page toggle, or per run with
`python run_scan.py scan-all --offline` (override back with `--online`).

## What it does
* Trivy is invoked with `--skip-db-update --skip-java-db-update --offline-scan --skip-check-update`
  (and `--skip-version-check`, `--disable-telemetry` where supported). Each flag is only passed if the
  installed Trivy documents it in `--help`, so older/newer releases keep working.
* Before launching Trivy, the scanner checks that a cached vulnerability DB exists
  (`<cache_dir>/db/metadata.json`; default cache `%LOCALAPPDATA%\trivy`). If it is missing the run is
  recorded as **FAILED** with an explanation — it is never recorded as clean.
* Gitleaks never needs network access.
* `update-databases` refuses to run in offline mode unless `--force` is given.

## Freshness
Freshness is read directly from Trivy's `metadata.json` (no process launch, no network):
`UpdatedAt` is compared with `scan.db_freshness_hours` (default 72 h). The dashboard shows a green/amber/red
banner on every page that matters, the overview shows "Vuln DB age", and every scan run records
`database_updated_at` and `offline` so historical results can be judged later.
A stale DB produces a **warning**, never a silent pass.

## Preparing an offline machine
1. While online: `python run_scan.py update-databases` (runs `trivy image --download-db-only` and
   `--download-java-db-only`).
2. Optional air-gap transfer: copy the whole Trivy cache folder (`%LOCALAPPDATA%\trivy`) to the offline
   machine and point `trivy.cache_dir` at it.
3. Set `scan.offline: true`.

## Limitations
* Offline results only include vulnerabilities known at `UpdatedAt`.
* Misconfiguration checks use the bundle embedded in the Trivy binary when the checks bundle can't be updated.
* Verified for real with Trivy 0.76.2 (all flags confirmed in its `--help`): the VAPT test's offline phase
  (`scan-all --offline`) succeeds from the cached DB, flags runs `offline=1` and still detects CVEs.
  DB-missing handling is covered by automated tests.
