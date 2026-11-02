# Architecture

OSINT Terminal is deliberately small: three files, one runtime dependency, no build
step. This document explains how the pieces fit together.

## Overview

```
Browser ──HTTP──▶ server.py ──calls──▶ osint.py
   ▲                  │                    │
   │             caching /            438 tool functions
 index.html      persistence          (keyless sources)
 (globe.gl)      (data/, cases/)
```

- **`index.html`** — the entire front end: a single-page dashboard written in vanilla
  JavaScript and CSS. The only external asset is [globe.gl](https://globe.gl), loaded
  from a CDN for the 3D globe. There is no framework and nothing to compile.
- **`server.py`** — a `http.server.ThreadingHTTPServer` with one request handler. It
  routes the JSON API, applies caching and gzip, persists state, and runs batch and
  health checks on a thread pool.
- **`osint.py`** — the tool library. Each tool is a function of one query string that
  returns a JSON-serializable dict. The `TOOLS` dict maps a short key to the function
  plus its UI metadata (`label`, `accepts`, `desc`).

## The tool contract

```python
def tool_dns(q):
    """A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records."""
    ...
    return {"records": ..., "source": "dns.google"}   # or {"error": "..."} on failure
```

- **Input**: a single already-trimmed query string.
- **Output**: a dict. On any failure the tool returns `{"error": <message>}` rather
  than raising, so a single dead upstream never breaks a batch or the UI.
- **Registration**: an entry in `TOOLS`. `osint.run(tool, query)` looks the function
  up and calls it; `osint.catalog()` returns the metadata the UI and health check use.

All HTTP tools share a tuned `requests.Session` (`_SESSION`) with a custom TLS adapter
that lowers the OpenSSL security level — a workaround for renegotiating hosts that
otherwise raise `SSLEOFError`, notably on Windows builds. The `_get(...)` helper wraps
it with sane defaults.

## Request lifecycle

1. The browser requests `GET /api/run/<tool>?q=<input>`.
2. The handler checks the on-disk **result cache** (`data/cache/<md5>.json`). A fresh
   hit is returned immediately with `__cached: true`.
3. On a miss it calls `osint.run(tool, query)`, records latency and history, writes the
   result to the cache, and returns it.

## Caching layers

| Cache            | Scope                              | Lifetime            |
|------------------|------------------------------------|---------------------|
| Tool catalog     | `/api/tools` payload (memoized+gzip)| process lifetime    |
| Static page      | `index.html` via ETag + gzip       | per-content         |
| Result cache     | per `(tool, query)` on disk        | `CACHE_TTL` (1h)    |
| IOC blocklists   | `/api/threat` feeds                | 10 minutes          |
| C2 map feed      | `/api/threat-feed` points          | 30 minutes          |
| Health results   | `/api/health` smoke tests          | 5 minutes           |

The two threat caches are intentionally separate objects (`_ioc_cache` and
`_c2_cache`) with distinct TTLs; they serve different endpoints and different data
shapes.

## Persistence

State is stored as plain JSON so it survives restarts and is easy to inspect:

- `data/history.json` — recent queries (capped at 500)
- `data/stats.json` — per-tool run count and cumulative latency
- `data/favorites.json` — starred tools
- `data/cache/` — the result cache
- `cases/<name>.json` — saved investigations

Both `data/` and `cases/` are created on first run and are git-ignored, so
investigation data is never committed.

## Concurrency

- **Batch** (`/api/batch`) fans out over a `ThreadPoolExecutor` (32 workers) so many
  `{tool, query}` pairs run in parallel.
- **Health** (`/api/health`) checks each tool against a known-good fixture on a
  16-worker pool and caches the result for five minutes.

Because the server is threaded, shared state (history, stats, favorites) is guarded by
a lock when written to disk.

## Extending

Add a tool by writing the function and registering it in `TOOLS` — see
[CONTRIBUTING.md](../CONTRIBUTING.md). No server changes are needed; new tools are
picked up automatically by `/api/run`, `/api/tools`, batch, and the health check.

## Brand assets

Logo and banner artwork lives in `docs/`:

| File             | Size      | Use                                           |
|------------------|-----------|-----------------------------------------------|
| `banner.svg`     | 1280×320  | README hero (vector, scales crisply).         |
| `banner.png`     | 1280×320  | Raster banner (wide 4:1).                      |
| `social.svg`     | 1280×640  | Social-preview source (vector).               |
| `social.png`     | 1280×640  | GitHub social preview (Settings → Social preview). |
| `logo.svg`       | 512×512   | Vector logo / favicon source.                 |
| `logo.png`       | 512×512   | Raster logo.                                  |
| `logo-256.png`   | 256×256   | Avatar / profile image.                       |

The palette matches the dashboard theme: matrix green `#00ff41`, cyan `#00f0ff`,
mint `#b8ffd0`, on near-black panels. The `.svg` files are the source of truth; the
`.png` files are rasterized from them (rendered at 3× through a headless browser and
downsampled) so they stay as crisp as the vectors.
