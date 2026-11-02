"""OSINT Terminal server. Serves the dashboard and a thin JSON API over the
tool registry in osint.py.

Routes:
  GET /                          -> dashboard (index.html)
  GET /api/tools                 -> registry metadata {tool: {label, accepts, desc}}
  GET /api/run/<tool>?q=...      -> run one tool, return its JSON result
  GET /api/history               -> last 50 queries
  GET /api/stats                 -> tool usage stats
  GET /api/favorites             -> list/add/remove favourites
  GET|POST /api/batch            -> run multiple queries (POST preferred, parallel)
  GET /api/export                -> export history as JSON or CSV
  GET /api/cases                 -> list saved cases
  POST /api/cases/<name>         -> append entry to a case
  GET /api/cases/<name>          -> get full case
  DELETE /api/cases/<name>       -> delete a case
  GET /api/health[?force=1]      -> tool health smoke-test (5-min cache)
"""
import gzip
import hashlib
import json
import os
import re
import sys
import threading
import time
import csv
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

import osint

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "8080"))
CASES_DIR = os.path.join(HERE, "cases")
CACHE_DIR = os.path.join(HERE, "data", "cache")
CACHE_TTL = int(os.environ.get("CACHE_TTL", "3600"))  # seconds, default 1 hour

# Memoized /api/tools payload (catalog never changes while server runs)
_tools_gz: bytes | None = None
_tools_plain: bytes | None = None

def _tools_payload():
    global _tools_gz, _tools_plain
    if _tools_plain is None:
        _tools_plain = json.dumps(osint.catalog(), default=str).encode()
        _tools_gz = gzip.compress(_tools_plain, compresslevel=6)
    return _tools_plain, _tools_gz

# Indicator (IOC) blocklists — used by /api/threat to check a single IP/URL/hash.
_ioc_lock = threading.Lock()
_ioc_cache = {"ts": 0, "ipbl": set(), "urlbl": set(), "hashbl": set()}
_IOC_TTL = 600  # 10 minutes


def _load_ioc_feeds():
    with _ioc_lock:
        if time.time() - _ioc_cache["ts"] < _IOC_TTL:
            return
        import requests as _req
        ipbl, urlbl, hashbl = set(), set(), set()
        try:
            r = _req.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
                         timeout=10, headers={"User-Agent": "OSINT-Terminal/1.0"})
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ipbl.add(line.split()[0])
        except Exception:
            pass
        try:
            r = _req.get("https://urlhaus.abuse.ch/downloads/text_recent/",
                         timeout=10, headers={"User-Agent": "OSINT-Terminal/1.0"})
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    urlbl.add(line)
        except Exception:
            pass
        try:
            r = _req.get("https://bazaar.abuse.ch/export/txt/sha256/recent/",
                         timeout=10, headers={"User-Agent": "OSINT-Terminal/1.0"})
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and len(line) == 64:
                    hashbl.add(line.lower())
        except Exception:
            pass
        _ioc_cache.update({"ts": time.time(), "ipbl": ipbl, "urlbl": urlbl, "hashbl": hashbl})


# Result cache helpers
def _cache_key(tool, q):
    return hashlib.md5(f"{tool}|{q}".encode()).hexdigest()


def _cache_get(tool, q):
    os.makedirs(CACHE_DIR, exist_ok=True)
    p = os.path.join(CACHE_DIR, _cache_key(tool, q) + ".json")
    if not os.path.exists(p):
        return None
    try:
        with open(p) as f:
            entry = json.load(f)
        if time.time() - entry["ts"] > CACHE_TTL:
            os.remove(p)
            return None
        return entry["result"]
    except Exception:
        return None


def _cache_set(tool, q, result):
    os.makedirs(CACHE_DIR, exist_ok=True)
    p = os.path.join(CACHE_DIR, _cache_key(tool, q) + ".json")
    try:
        with open(p, "w") as f:
            json.dump({"ts": time.time(), "tool": tool, "query": q, "result": result}, f)
    except Exception:
        pass

# Global state: search history + stats (persisted to disk)
DATA_DIR = os.path.join(HERE, "data")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")
FAVS_FILE = os.path.join(DATA_DIR, "favorites.json")

_history = []  # {query, tool, time, result_keys}
_stats = defaultdict(lambda: {"count": 0, "total_ms": 0})  # tool -> {count, total_ms}
_favorites = set()  # tool names
_persist_lock = threading.Lock()

def _load_persist():
    """Load history, stats, and favorites from disk on startup."""
    global _history, _stats, _favorites
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE) as f:
                _history = json.load(f)[-500:]  # keep the last 500 entries, not the whole log
    except Exception:
        pass
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE) as f:
                _stats.update(json.load(f))
    except Exception:
        pass
    try:
        if os.path.exists(FAVS_FILE):
            with open(FAVS_FILE) as f:
                _favorites.update(json.load(f))
    except Exception:
        pass


def _save_history():
    """Persist history to disk."""
    with _persist_lock:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(HISTORY_FILE, "w") as f:
                json.dump(_history[-500:], f)
        except Exception:
            pass


def _save_stats():
    """Persist stats to disk."""
    with _persist_lock:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(STATS_FILE, "w") as f:
                json.dump(dict(_stats), f)
        except Exception:
            pass


def _save_favs():
    """Persist favorites to disk."""
    with _persist_lock:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(FAVS_FILE, "w") as f:
                json.dump(list(_favorites), f)
        except Exception:
            pass

# Health cache
_health_cache = {"ts": 0, "data": {}}
_HEALTH_TTL = 300  # 5 minutes

# C2 map feed — Feodo C2 IPs geo-resolved for the globe, refreshed every 30 min.
# Kept separate from the IOC blocklists above; both once shared a name and clobbered
# each other's cache shape.
_c2_cache = {"ts": 0, "data": []}
_C2_TTL = 1800

def _load_c2_feed():
    global _c2_cache
    if time.time() - _c2_cache["ts"] < _C2_TTL:
        return _c2_cache["data"]
    try:
        req = urllib.request.Request(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            headers={"User-Agent": "osint-terminal/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = json.loads(r.read())
        # geo-resolve each IP via ip-api batch (max 100 per call, free)
        online = [e for e in raw if e.get("status") == "online"][:100]
        if not online:
            online = raw[:100]
        ips = [e["ip_address"] for e in online]
        geo_map = {}
        try:
            gdata = json.loads(urllib.request.urlopen(
                urllib.request.Request("http://ip-api.com/batch?fields=query,lat,lon,country,isp",
                    data=json.dumps(ips).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "osint-terminal/1.0"},
                    method="POST"), timeout=8).read())
            geo_map = {g["query"]: g for g in gdata if g.get("lat")}
        except Exception:
            pass
        points = []
        for e in online:
            ip = e["ip_address"]
            g = geo_map.get(ip, {})
            if not g.get("lat"):
                continue
            points.append({"ip": ip, "lat": g["lat"], "lng": g["lon"],
                           "country": g.get("country", e.get("country", "?")),
                           "malware": e.get("malware", "C2"),
                           "port": e.get("port")})
        _c2_cache = {"ts": time.time(), "data": points}
        return points
    except Exception:
        return _c2_cache["data"]

# Health fixtures — known-good inputs per type
_FIXTURES = {
    "domain": "cloudflare.com",
    "ip": "8.8.8.8",
    "email": "test@example.com",
    "username": "torvalds",
    "asn": "AS13335",
    "url": "https://cloudflare.com",
    "coords": "51.5,-0.1",
    "cve": "CVE-2021-44228",
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "package": "requests",
    "orgname": "Cloudflare",
}


def _safe_case_name(name):
    """Strip path traversal chars from case name."""
    return re.sub(r'[^a-zA-Z0-9_\- ]', '_', name)[:80]


def _case_path(name):
    os.makedirs(CASES_DIR, exist_ok=True)
    return os.path.join(CASES_DIR, _safe_case_name(name) + ".json")


def _run_health_check(force=False):
    global _health_cache
    if not force and time.time() - _health_cache["ts"] < _HEALTH_TTL:
        return _health_cache["data"]

    catalog = osint.catalog()
    results = {}

    def check(tool, meta):
        fixture_type = next((t for t in meta.get("accepts", []) if t in _FIXTURES), None)
        if not fixture_type:
            return tool, {"ok": None, "ms": None, "note": "no fixture"}
        q = _FIXTURES[fixture_type]
        t0 = time.time()
        try:
            res = osint.run(tool, q)
            ms = int((time.time() - t0) * 1000)
            ok = "error" not in res and "note" not in res  # note = key missing
            return tool, {"ok": ok, "ms": ms, "error": res.get("error") or res.get("note")}
        except Exception as e:
            ms = int((time.time() - t0) * 1000)
            return tool, {"ok": False, "ms": ms, "error": str(e)}

    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(check, tool, meta): tool for tool, meta in catalog.items()}
        for fut in as_completed(futs):
            tool, result = fut.result()
            results[tool] = result

    _health_cache = {"ts": time.time(), "data": results}
    return results


class Handler(BaseHTTPRequestHandler):
    def _accepts_gz(self):
        return "gzip" in self.headers.get("Accept-Encoding", "")

    def _json(self, obj, code=200):
        plain = json.dumps(obj, default=str).encode("utf-8")
        if self._accepts_gz() and len(plain) > 512:
            body = gzip.compress(plain, compresslevel=6)
            enc = "gzip"
        else:
            body, enc = plain, None
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if enc:
            self.send_header("Content-Encoding", enc)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    raw = f.read()
            except OSError:
                self.send_error(500, "index.html missing")
                return
            etag = f'"{hashlib.md5(raw).hexdigest()}"'
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.end_headers()
                return
            body = gzip.compress(raw, compresslevel=6) if self._accepts_gz() else raw
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            if body is not raw:
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/tools":
            plain, gz = _tools_payload()
            body = gz if self._accepts_gz() else plain
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Content-Length", str(len(body)))
            if body is gz:
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(body)
            return

        if path.startswith("/api/run/"):
            tool = path[len("/api/run/"):]
            q = qs.get("q", [""])[0].strip()
            if not q:
                self._json({"error": "missing ?q="}, 400)
                return
            cached = _cache_get(tool, q)
            if cached is not None:
                cached["__cached"] = True
                self._json(cached)
                return
            t0 = time.time()
            result = osint.run(tool, q)
            ms = int((time.time() - t0) * 1000)
            _stats[tool]["count"] += 1
            _stats[tool]["total_ms"] += ms
            _history.append({"tool": tool, "query": q[:100], "time": time.time(), "ms": ms})
            del _history[:-100]
            _save_history(); _save_stats()  # persist
            result["__ms"] = ms
            _cache_set(tool, q, result)
            self._json(result)
            return

        if path == "/api/history":
            self._json({"history": _history[-50:]})
            return

        if path == "/api/stats":
            stats = {
                tool: {
                    "count": data["count"],
                    "avg_ms": data["total_ms"] // max(1, data["count"]),
                    "total_ms": data["total_ms"]
                }
                for tool, data in _stats.items()
            }
            sorted_stats = sorted(stats.items(), key=lambda x: x[1]["count"], reverse=True)
            self._json({"stats": {k: v for k, v in sorted_stats[:20]}})
            return

        if path == "/api/favorites":
            action = qs.get("action", [""])[0]
            tool = qs.get("tool", [""])[0]
            if action == "add" and tool:
                _favorites.add(tool)
            elif action == "remove" and tool:
                _favorites.discard(tool)
            if action:
                _save_favs()  # persist on change
            self._json({"favorites": list(_favorites)})
            return

        if path == "/api/batch":
            queries_param = qs.get("queries", [""])[0]
            if not queries_param:
                self._json({"error": "missing ?queries=json_array"}, 400)
                return
            try:
                queries = json.loads(queries_param)
                results = self._run_batch(queries)
                self._json({"results": results})
            except json.JSONDecodeError:
                self._json({"error": "invalid JSON"}, 400)
            return

        if path == "/api/export":
            fmt = qs.get("format", ["json"])[0]
            if fmt == "csv":
                out = StringIO()
                w = csv.writer(out)
                w.writerow(["Tool", "Query", "Time", "Duration (ms)"])
                for h in _history[-100:]:
                    w.writerow([h["tool"], h["query"], h["time"], h["ms"]])
                body = out.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", 'attachment; filename="osint-history.csv"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._json({"history": _history[-100:]})
            return

        # --- cases ---
        if path == "/api/cases":
            os.makedirs(CASES_DIR, exist_ok=True)
            cases = []
            for f in os.listdir(CASES_DIR):
                if not f.endswith(".json"):
                    continue
                fp = os.path.join(CASES_DIR, f)
                try:
                    with open(fp) as fh:
                        d = json.load(fh)
                    cases.append({
                        "name": d.get("name", f[:-5]),
                        "query_count": len(d.get("entries", [])),
                        "last_saved": d["entries"][-1]["saved_at"] if d.get("entries") else None,
                    })
                except Exception:
                    pass
            self._json({"cases": cases})
            return

        if path.startswith("/api/cases/"):
            name = path[len("/api/cases/"):]
            fp = _case_path(name)
            if not os.path.exists(fp):
                self._json({"error": "case not found"}, 404)
                return
            with open(fp) as fh:
                self._json(json.load(fh))
            return

        # --- threat intel ---
        if path == "/api/threat":
            q = qs.get("q", [""])[0].strip()
            if not q:
                self._json({"error": "missing ?q="}, 400)
                return
            _load_ioc_feeds()
            hits = []
            if q in _ioc_cache["ipbl"]:
                hits.append({"feed": "Feodo C2 blocklist", "type": "ip", "severity": "high"})
            for url in _ioc_cache["urlbl"]:
                if q in url:
                    hits.append({"feed": "URLhaus malware URLs", "type": "url", "severity": "high"})
                    break
            if q.lower() in _ioc_cache["hashbl"]:
                hits.append({"feed": "MalwareBazaar SHA256", "type": "hash", "severity": "high"})
            self._json({"query": q, "hits": hits,
                        "feeds_loaded": bool(_ioc_cache["ts"]),
                        "checked_at": _ioc_cache["ts"]})
            return

        # --- result cache ---
        if path == "/api/cache/stats":
            os.makedirs(CACHE_DIR, exist_ok=True)
            files = [f for f in os.listdir(CACHE_DIR) if f.endswith(".json")]
            total_size = sum(os.path.getsize(os.path.join(CACHE_DIR, f)) for f in files)
            self._json({"entries": len(files), "size_kb": total_size // 1024, "ttl_s": CACHE_TTL})
            return

        if path == "/api/cache/clear":
            os.makedirs(CACHE_DIR, exist_ok=True)
            cleared = 0
            for f in os.listdir(CACHE_DIR):
                if f.endswith(".json"):
                    try:
                        os.remove(os.path.join(CACHE_DIR, f))
                        cleared += 1
                    except Exception:
                        pass
            self._json({"ok": True, "cleared": cleared})
            return

        # --- threat feed (proxied to avoid browser CORS) ---
        if path == "/api/threat-feed":
            points = _load_c2_feed()
            self._json({"count": len(points), "points": points})
            return

        # --- health ---
        if path == "/api/health":
            force = qs.get("force", [""])[0] == "1"
            data = _run_health_check(force=force)
            total = len(data)
            healthy = sum(1 for v in data.values() if v.get("ok") is True)
            self._json({"checked_at": _health_cache["ts"], "healthy": healthy,
                        "total": total, "results": data})
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/batch":
            try:
                body = json.loads(self._read_body())
                queries = body.get("queries", [])
                results = self._run_batch(queries)
                self._json({"results": results})
            except (json.JSONDecodeError, Exception) as e:
                self._json({"error": str(e)}, 400)
            return

        if path.startswith("/api/cases/"):
            name = path[len("/api/cases/"):]
            fp = _case_path(name)
            try:
                entry = json.loads(self._read_body())
                entry["saved_at"] = int(time.time())
                if os.path.exists(fp):
                    with open(fp) as fh:
                        case = json.load(fh)
                else:
                    case = {"name": name, "entries": []}
                case["entries"].append(entry)
                with open(fp, "w") as fh:
                    json.dump(case, fh)
                self._json({"ok": True, "count": len(case["entries"])})
            except Exception as e:
                self._json({"error": str(e)}, 400)
            return

        self.send_error(404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/history":
            global _history
            _history = []
            _save_history()  # persist empty state
            self._json({"ok": True})
            return

        if path.startswith("/api/cases/"):
            name = path[len("/api/cases/"):]
            fp = _case_path(name)
            if os.path.exists(fp):
                os.remove(fp)
                self._json({"ok": True})
            else:
                self._json({"error": "case not found"}, 404)
            return

        self.send_error(404)

    def _run_batch(self, queries):
        results = []

        def _one(item):
            if "tool" not in item or "query" not in item:
                return None
            t0 = time.time()
            res = osint.run(item["tool"], item["query"])
            ms = int((time.time() - t0) * 1000)
            _stats[item["tool"]]["count"] += 1
            _stats[item["tool"]]["total_ms"] += ms
            return {"tool": item["tool"], "query": item["query"], "result": res, "ms": ms}

        with ThreadPoolExecutor(max_workers=32) as ex:
            futs = [ex.submit(_one, item) for item in queries]
            for fut in as_completed(futs):
                r = fut.result()
                if r:
                    results.append(r)
        _save_stats()  # persist after batch
        return results

    def log_message(self, *args):  # silence default request logging; print(args) to debug
        pass


def main():
    if "--selftest" in sys.argv:
        cat = osint.catalog()
        assert len(cat) >= 10, f"expected 10+ tools, got {len(cat)}"
        assert osint.run("nope", "x") == {"error": "unknown tool: nope"}
        print(f"SELFTEST OK ({len(cat)} tools registered)")
        return
    os.makedirs(CASES_DIR, exist_ok=True)
    _load_persist()
    print(f"OSINT Terminal on http://localhost:{PORT}  ({len(osint.TOOLS)} tools)")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
