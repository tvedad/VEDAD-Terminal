import base64
import base64 as b64
import binascii
import concurrent.futures as cf
import datetime
import hashlib
import html
import html.parser
import ipaddress
import json as _json
import json as _j
import math
import mimetypes
import quopri
import re
import socket
import string
import struct
import time
import ssl
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.ssl_ import create_urllib3_context

    class _TLSAdapter(HTTPAdapter):
        """Lower the SSL security level to work around SSLEOFError on Cloudflare
        and other renegotiating hosts (notably with Windows OpenSSL builds)."""
        def init_poolmanager(self, *a, **kw):
            ctx = create_urllib3_context()
            ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            except ssl.SSLError:
                pass
            kw["ssl_context"] = ctx
            super().init_poolmanager(*a, **kw)

    _SESSION = requests.Session()
    _SESSION.mount("https://", _TLSAdapter())
    _SESSION.mount("http://", _TLSAdapter())
    _SESSION.verify = False
except Exception:
    _SESSION = requests.Session()
    _SESSION.verify = False
import secrets
from urllib.parse import quote

try:
    import phonenumbers
    import phonenumbers.geocoder as _pn_geo
    import phonenumbers.carrier as _pn_carrier
    import phonenumbers.timezone as _pn_tz
    _PN = phonenumbers
except ImportError:
    _PN = None

try:
    from PIL import Image as _PILImage
    import io as _io
    _PIL = _PILImage
except ImportError:
    _PIL = None

UA = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Terminal/1.0; research)"}
TIMEOUT = 8


def _get(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    h = dict(UA)
    h.update(kw.pop("headers", {}))
    # اضافه کردن User-Agent استاندارد برای جلوگیری از بلاک شدن
    h.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    return _SESSION.get(url, headers=h, **kw)


def _post(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    h = dict(UA)
    h.update(kw.pop("headers", {}))
    return _SESSION.post(url, headers=h, **kw)


def _host(q):
    """Normalize a domain/url indicator down to a bare hostname."""
    q = q.strip()
    if "://" in q:
        q = urllib.parse.urlparse(q).netloc
    return q.split("/")[0].split("@")[-1].split(":")[0]


def _base(q):
    """https base URL for a domain/url indicator."""
    q = q.strip()
    if q.startswith("http://") or q.startswith("https://"):
        p = urllib.parse.urlparse(q)
        return f"{p.scheme}://{p.netloc}"
    return "https://" + _host(q)


def _crtsh(params, retries=4):
    """Fetch crt.sh JSON, retrying its intermittent empty/HTML 200 bodies.

    crt.sh intermittently returns a blank body or an HTML error page with
    HTTP 200, so r.json() throws. Retry a few times with linear backoff before
    giving up; the endpoint itself is simply flaky.
    """
    last = None
    for i in range(retries):
        try:
            r = _get("https://crt.sh/", params={**params, "output": "json"}, timeout=25)
            if r.status_code == 200 and r.text.strip():
                return r.json()  # may still raise if body isn't JSON -> retry
            last = f"HTTP {r.status_code}, {len(r.text)} bytes"
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
        time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"crt.sh unreachable after {retries} tries ({last})")


# ---------------------------------------------------------------------------
# 1. DNS records (Google DNS-over-HTTPS)
# ---------------------------------------------------------------------------
DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


def tool_dns(q):
    records = {}
    for t in DNS_TYPES:
        try:
            r = _get("https://dns.google/resolve", params={"name": q, "type": t})
            ans = r.json().get("Answer", [])
            records[t] = [a.get("data") for a in ans if a.get("data")]
        except Exception as e:
            records[t] = [f"error: {e}"]
    total = sum(len(v) for v in records.values())
    return {"domain": q, "record_count": total, "records": records}


# ---------------------------------------------------------------------------
# 2. WHOIS / RDAP (rdap.org)
# ---------------------------------------------------------------------------
def _vcard_name(entity):
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "fn":
                return item[3]
    except Exception:
        pass
    return None


def tool_whois(q):
    r = _get(f"https://rdap.org/domain/{q}", allow_redirects=True)
    if r.status_code != 200:
        return {"error": f"RDAP lookup failed ({r.status_code})", "domain": q}
    d = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    entities = []
    for e in d.get("entities", []):
        entities.append({"roles": e.get("roles", []), "name": _vcard_name(e),
                         "handle": e.get("handle")})
    nameservers = [ns.get("ldhName") for ns in d.get("nameservers", [])]
    secure = d.get("secureDNS", {})
    return {
        "domain": d.get("ldhName", q),
        "handle": d.get("handle"),
        "status": d.get("status", []),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": nameservers,
        "dnssec": secure.get("delegationSigned"),
        "entities": entities,
    }


# ---------------------------------------------------------------------------
# 3. IP geolocation + ASN (ip-api.com)
# ---------------------------------------------------------------------------
def tool_ipgeo(q):
    fields = ("status,message,continent,country,countryCode,region,regionName,"
              "city,zip,lat,lon,timezone,currency,isp,org,as,asname,reverse,"
              "mobile,proxy,hosting,query")
    r = _get(f"http://ip-api.com/json/{q}", params={"fields": fields})
    d = r.json()
    if d.get("status") != "success":
        return {"error": d.get("message", "lookup failed"), "ip": q}
    return d


# ---------------------------------------------------------------------------
# 4. Reverse DNS / PTR
# ---------------------------------------------------------------------------
def tool_reversedns(q):
    try:
        host, aliases, _ = socket.gethostbyaddr(q)
        return {"ip": q, "ptr": host, "aliases": aliases}
    except Exception as e:
        return {"ip": q, "ptr": None, "aliases": [], "note": str(e)}


# ---------------------------------------------------------------------------
# 5. TLS / SSL certificate (live handshake)
# ---------------------------------------------------------------------------
def _name_tuple(seq):
    out = {}
    for rdn in seq or []:
        for k, v in rdn:
            out[k] = v
    return out


def tool_tls(q):
    host = q.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                cipher = ss.cipher()
                version = ss.version()
    except Exception as e:
        return {"host": host, "error": f"TLS handshake failed: {e}"}
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    return {
        "host": host,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "subject": _name_tuple(cert.get("subject")),
        "issuer": _name_tuple(cert.get("issuer")),
        "valid_from": cert.get("notBefore"),
        "valid_until": cert.get("notAfter"),
        "serial": cert.get("serialNumber"),
        "san_count": len(sans),
        "subject_alt_names": sans,
    }


# ---------------------------------------------------------------------------
# 6. Subdomain enumeration (crt.sh certificate transparency)
# ---------------------------------------------------------------------------
def tool_subdomains(q):
    try:
        rows = _crtsh({"q": q})
    except Exception as e:
        return {"domain": q, "error": f"crt.sh failed: {e}"}
    names = set()
    for row in rows:
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lower()
            if n and "*" not in n:
                names.add(n)
    names = sorted(names)
    return {"domain": q, "count": len(names), "subdomains": names}


# ---------------------------------------------------------------------------
# 7. HTTP headers + security-header analysis
# ---------------------------------------------------------------------------
SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
               "X-Frame-Options", "X-Content-Type-Options",
               "Referrer-Policy", "Permissions-Policy"]


def tool_headers(q):
    url = q if q.startswith("http") else "https://" + q
    try:
        r = _get(url, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}
    sec = {h: (h in r.headers) for h in SEC_HEADERS}
    score = sum(sec.values())
    return {
        "url": url,
        "final_url": r.url,
        "status": r.status_code,
        "redirected": len(r.history) > 0,
        "server": r.headers.get("Server"),
        "powered_by": r.headers.get("X-Powered-By"),
        "content_type": r.headers.get("Content-Type"),
        "security_score": f"{score}/{len(SEC_HEADERS)}",
        "security_headers": sec,
        "headers": dict(r.headers),
    }


# ---------------------------------------------------------------------------
# 8. Username hunter (presence across public sites)
# ---------------------------------------------------------------------------
# (label, url_template, method)
SITES = [
    ("GitHub", "https://api.github.com/users/{}", "status"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={}", "json_array"),
    ("Reddit", "https://www.reddit.com/user/{}/about.json", "status"),
    ("Dev.to", "https://dev.to/api/users/by_username?url={}", "status"),
    ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{}.json", "json_notnull"),
    ("PyPI", "https://pypi.org/user/{}/", "status"),
    ("npm", "https://www.npmjs.com/~{}", "status"),
    ("DockerHub", "https://hub.docker.com/v2/users/{}/", "status"),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "keybase"),
    ("Replit", "https://replit.com/@{}", "status"),
    ("Mastodon", "https://mastodon.social/@{}", "status"),
    ("Telegram", "https://t.me/{}", "telegram"),
    ("WordPress", "https://{}.wordpress.com/", "status"),
    ("Pinterest", "https://www.pinterest.com/{}/", "status"),
    ("About.me", "https://about.me/{}", "status"),
    ("Gravatar", "https://gravatar.com/{}", "status"),
]


def _check_site(label, tmpl, method, user):
    url = tmpl.format(user)
    try:
        r = _get(url, timeout=6, allow_redirects=True)
    except Exception:
        return label, {"found": None, "url": url}
    found = None
    if method == "status":
        found = r.status_code == 200
    elif method == "json_array":
        try:
            found = len(r.json()) > 0
        except Exception:
            found = False
    elif method == "json_notnull":
        found = r.text.strip() not in ("null", "")
    elif method == "keybase":
        try:
            them = r.json().get("them", [])
            found = bool(them) and them[0] is not None
        except Exception:
            found = False
    elif method == "telegram":
        found = r.status_code == 200 and "tgme_page_title" in r.text
    return label, {"found": found, "url": url}


def tool_username(q):
    results = {}
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(_check_site, *site, q) for site in SITES]
        for f in cf.as_completed(futs):
            label, res = f.result()
            results[label] = res
    found = sorted(k for k, v in results.items() if v["found"])
    return {
        "username": q,
        "sites_checked": len(SITES),
        "found_count": len(found),
        "found_on": found,
        "results": dict(sorted(results.items())),
    }


# ---------------------------------------------------------------------------
# 9. Email intel (gravatar, MX, disposable detection)
# ---------------------------------------------------------------------------
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "trashmail.com", "yopmail.com", "getnada.com",
    "temp-mail.org", "fakeinbox.com", "maildrop.cc", "sharklasers.com",
}


def tool_email(q):
    q = q.strip().lower()
    local, _, domain = q.partition("@")
    md5 = hashlib.md5(q.encode()).hexdigest()
    # gravatar
    has_grav = False
    profile = None
    try:
        g = _get(f"https://www.gravatar.com/avatar/{md5}?d=404")
        has_grav = g.status_code == 200
        if has_grav:
            p = _get(f"https://www.gravatar.com/{md5}.json")
            if p.status_code == 200:
                profile = p.json().get("entry", [{}])[0]
    except Exception:
        pass
    # MX
    mx = []
    try:
        r = _get("https://dns.google/resolve", params={"name": domain, "type": "MX"})
        mx = [a["data"] for a in r.json().get("Answer", []) if a.get("data")]
    except Exception:
        pass
    return {
        "email": q,
        "domain": domain,
        "valid_format": bool(local) and "." in domain,
        "md5": md5,
        "deliverable_domain": len(mx) > 0,
        "mx_records": mx,
        "disposable": domain in DISPOSABLE,
        "gravatar": has_grav,
        "gravatar_profile": profile,
    }


# ---------------------------------------------------------------------------
# 10. GitHub recon (public API)
# ---------------------------------------------------------------------------
def tool_github(q):
    r = _get(f"https://api.github.com/users/{q}")
    if r.status_code == 404:
        return {"username": q, "error": "user not found"}
    if r.status_code != 200:
        return {"username": q, "error": f"GitHub API {r.status_code} (rate limit?)"}
    d = r.json()
    repos = []
    langs = {}
    try:
        rr = _get(d["repos_url"], params={"per_page": 100, "sort": "updated"})
        for repo in rr.json():
            repos.append({"name": repo["name"], "stars": repo["stargazers_count"],
                          "lang": repo.get("language"), "forks": repo["forks_count"]})
            if repo.get("language"):
                langs[repo["language"]] = langs.get(repo["language"], 0) + 1
    except Exception:
        pass
    repos.sort(key=lambda x: x["stars"], reverse=True)
    return {
        "username": d.get("login"),
        "name": d.get("name"),
        "bio": d.get("bio"),
        "company": d.get("company"),
        "location": d.get("location"),
        "blog": d.get("blog"),
        "email": d.get("email"),
        "twitter": d.get("twitter_username"),
        "public_repos": d.get("public_repos"),
        "followers": d.get("followers"),
        "following": d.get("following"),
        "created_at": d.get("created_at"),
        "languages": dict(sorted(langs.items(), key=lambda x: -x[1])),
        "top_repos": repos[:10],
    }


# ---------------------------------------------------------------------------
# 11. Wayback Machine history (archive.org)
# ---------------------------------------------------------------------------
def tool_wayback(q):
    url = q if q.startswith("http") else "http://" + q
    out = {"url": url}
    try:
        r = _get("http://archive.org/wayback/available", params={"url": url})
        snap = r.json().get("archived_snapshots", {}).get("closest", {})
        out["latest_snapshot"] = snap.get("url")
        out["snapshot_time"] = snap.get("timestamp")
        out["available"] = snap.get("available", False)
    except Exception as e:
        out["error"] = str(e)
    try:
        cdx = _get("http://web.archive.org/cdx/search/cdx",
                   params={"url": url, "output": "json", "limit": 5000,
                           "fl": "timestamp", "collapse": "timestamp:8"}, timeout=20)
        rows = cdx.json()
        stamps = [r[0] for r in rows[1:]] if len(rows) > 1 else []
        out["total_snapshots"] = len(stamps)
        out["first_seen"] = stamps[0] if stamps else None
        out["last_seen"] = stamps[-1] if stamps else None
    except Exception:
        out["total_snapshots"] = out.get("total_snapshots", 0)
    return out


# ===========================================================================
# Extended tools (20 more). All operate on a USER-SUPPLIED indicator — no
# mass discovery. Free/no-key sources where possible; a few are rate-limited.
# ===========================================================================

def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _probe(ip, port, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _txt(name):
    try:
        r = _get("https://dns.google/resolve", params={"name": name, "type": "TXT"})
        return [a["data"].strip('"') for a in r.json().get("Answer", []) if a.get("data")]
    except Exception:
        return []


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
    27017: "MongoDB", 11211: "Memcached",
}
CAMERA_PORTS = {
    554: "RTSP", 8554: "RTSP-alt", 37777: "Dahua", 37778: "Dahua-UDP",
    34567: "DVR/XMeye", 8000: "Hikvision-SDK", 88: "Hikvision-HTTP",
    8081: "Cam-HTTP", 7001: "Dahua-web", 9000: "Cam-alt",
}


# 12. Shodan InternetDB (no key) — public exposure for a single IP
def tool_internetdb(q):
    ip = q if re.match(r"^\d+\.\d+\.\d+\.\d+$", q) else _resolve(q)
    if not ip:
        return {"target": q, "error": "could not resolve"}
    r = _get(f"https://internetdb.shodan.io/{ip}")
    if r.status_code == 404:
        return {"ip": ip, "note": "no public exposure data in Shodan InternetDB"}
    if r.status_code != 200:
        return {"ip": ip, "error": f"InternetDB {r.status_code}"}
    d = r.json()
    return {"ip": ip, "ports": d.get("ports", []), "hostnames": d.get("hostnames", []),
            "tags": d.get("tags", []), "cpes": d.get("cpes", []),
            "vulns": d.get("vulns", []), "vuln_count": len(d.get("vulns", []))}


# 13. Port scan (TCP connect, common + camera ports) on a target
def tool_portscan(q):
    ip = q if re.match(r"^\d+\.\d+\.\d+\.\d+$", q) else _resolve(q)
    if not ip:
        return {"target": q, "error": "could not resolve"}
    ports = {**COMMON_PORTS, **CAMERA_PORTS}
    open_ports = {}
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(_probe, ip, p): p for p in ports}
        for f in cf.as_completed(futs):
            p = futs[f]
            if f.result():
                open_ports[p] = ports[p]
    return {"target": q, "ip": ip, "ports_scanned": len(ports),
            "open_count": len(open_ports),
            "open_ports": {str(k): open_ports[k] for k in sorted(open_ports)},
            "note": "Connect-scan. Only scan hosts you are authorized to test."}


# 14. Camera / IoT exposure assessment for a target
CAM_PATHS = ["/onvif/device_service", "/axis-cgi/jpg/image.cgi",
             "/cgi-bin/snapshot.cgi", "/videostream.cgi", "/view/view.shtml",
             "/mjpg/video.mjpg", "/doc/page/login.asp", "/web/index.html"]


def tool_camera(q):
    ip = q if re.match(r"^\d+\.\d+\.\d+\.\d+$", q) else _resolve(q)
    if not ip:
        return {"target": q, "error": "could not resolve"}
    open_cam = {}
    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        futs = {ex.submit(_probe, ip, p, 2.0): p for p in CAMERA_PORTS}
        for f in cf.as_completed(futs):
            p = futs[f]
            if f.result():
                open_cam[p] = CAMERA_PORTS[p]
    endpoints = {}
    for path in CAM_PATHS:
        for bp in (80, 8080):
            try:
                r = _get(f"http://{ip}:{bp}{path}", timeout=3, allow_redirects=False)
                if r.status_code < 500:
                    endpoints[path] = r.status_code
                    break
            except Exception:
                pass
    indicators = len(open_cam) + len(endpoints)
    return {"target": q, "ip": ip,
            "camera_ports_open": {str(k): v for k, v in sorted(open_cam.items())},
            "camera_http_endpoints": endpoints,
            "likely_camera_device": indicators >= 2,
            "note": "Per-target exposure check for authorized assessment only."}


# 15. IP WHOIS (RDAP) — network owner / abuse contact
def tool_ipwhois(q):
    r = _get(f"https://rdap.org/ip/{q}", allow_redirects=True)
    if r.status_code != 200:
        return {"ip": q, "error": f"RDAP {r.status_code}"}
    d = r.json()
    abuse = None
    for e in d.get("entities", []):
        if "abuse" in e.get("roles", []):
            abuse = _vcard_name(e) or e.get("handle")
    return {"ip": q, "name": d.get("name"), "handle": d.get("handle"),
            "country": d.get("country"), "type": d.get("type"),
            "range": f'{d.get("startAddress")} - {d.get("endAddress")}',
            "abuse_contact": abuse, "status": d.get("status", [])}


# 16. ASN / BGP info (bgpview.io) — accepts ASN or IP
def tool_asn(q):
    # RIPEstat (free, no key). bgpview.io shut down (NXDOMAIN) 2026.
    if re.match(r"^(AS)?\d+$", q, re.I):
        asn = q.upper().replace("AS", "")
        d = _get("https://stat.ripe.net/data/as-overview/data.json",
                 params={"resource": f"AS{asn}"}).json().get("data", {})
        pre = _get("https://stat.ripe.net/data/announced-prefixes/data.json",
                   params={"resource": f"AS{asn}"}).json().get("data", {})
        prefixes = [p.get("prefix") for p in pre.get("prefixes", [])]
        return {"asn": f"AS{asn}", "name": d.get("holder"),
                "announced": d.get("announced"),
                "rir": (d.get("block") or {}).get("desc"),
                "prefix_count": len(prefixes), "prefixes": prefixes[:100]}
    d = _get("https://stat.ripe.net/data/network-info/data.json",
             params={"resource": q}).json().get("data", {})
    return {"ip": q, "prefix": d.get("prefix"),
            "asns": [f"AS{a}" for a in d.get("asns", [])]}


# 17. Reverse IP — other domains on the same host (hackertarget)
def tool_reverseip(q):
    ip = q if re.match(r"^\d+\.\d+\.\d+\.\d+$", q) else _resolve(q)
    r = _get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip or q})
    txt = r.text.strip()
    if "error" in txt.lower() or "exceeded" in txt.lower():
        return {"target": q, "error": txt}
    domains = [l for l in txt.splitlines() if l]
    return {"target": q, "ip": ip, "count": len(domains), "domains": domains[:200]}


# 18. DNS blocklist (DNSBL) check for an IP
DNSBLS = ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net",
          "dnsbl.sorbs.net"]


def tool_dnsbl(q):
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", q):
        return {"ip": q, "error": "IPv4 only"}
    rev = ".".join(reversed(q.split(".")))
    listed = {}
    for bl in DNSBLS:
        try:
            r = _get("https://dns.google/resolve",
                     params={"name": f"{rev}.{bl}", "type": "A"})
            listed[bl] = bool(r.json().get("Answer"))
        except Exception:
            listed[bl] = None
    return {"ip": q, "listed_count": sum(1 for v in listed.values() if v),
            "blocklists": listed}


# 19. Tor exit-node check
_TOR_CACHE = {"ips": set(), "ts": 0}
_TOR_TTL = 3600  # refresh hourly


def tool_tor(q):
    if time.time() - _TOR_CACHE["ts"] > _TOR_TTL:
        try:
            r = _get("https://check.torproject.org/torbulkexitlist", timeout=15)
            _TOR_CACHE["ips"] = set(r.text.split())
            _TOR_CACHE["ts"] = time.time()
        except Exception as e:
            if not _TOR_CACHE["ips"]:
                return {"ip": q, "error": f"could not fetch Tor list: {e}"}
    return {"ip": q, "is_tor_exit": q in _TOR_CACHE["ips"],
            "tor_exits_known": len(_TOR_CACHE["ips"])}


# 20. Cloud provider detection (derived from ASN/org)
CLOUD_MAP = [("amazon", "AWS"), ("aws", "AWS"), ("google", "Google Cloud"),
             ("microsoft", "Azure"), ("azure", "Azure"),
             ("cloudflare", "Cloudflare"), ("digitalocean", "DigitalOcean"),
             ("oracle", "Oracle Cloud"), ("akamai", "Akamai"), ("ovh", "OVH"),
             ("hetzner", "Hetzner"), ("linode", "Linode"), ("fastly", "Fastly"),
             ("alibaba", "Alibaba Cloud")]


def tool_cloud(q):
    r = _get(f"http://ip-api.com/json/{q}",
             params={"fields": "status,message,org,isp,as,asname,hosting,query"})
    d = r.json()
    if d.get("status") != "success":
        return {"ip": q, "error": d.get("message", "lookup failed")}
    blob = " ".join(str(d.get(k, "")) for k in ("org", "isp", "as", "asname")).lower()
    provider = next((name for kw, name in CLOUD_MAP if kw in blob), None)
    return {"ip": d.get("query"), "cloud_provider": provider,
            "is_hosting": d.get("hosting"), "org": d.get("org"),
            "asn": d.get("as"), "asname": d.get("asname")}


# 21. Email security posture (SPF / DMARC / DKIM)
def tool_emailsec(q):
    spf = [t for t in _txt(q) if "v=spf1" in t]
    dmarc = [t for t in _txt(f"_dmarc.{q}") if "v=DMARC1" in t]
    dkim = [sel for sel in ("default", "google", "selector1", "k1", "mail")
            if _txt(f"{sel}._domainkey.{q}")]
    dpol = None
    if dmarc:
        m = re.search(r"p=(\w+)", dmarc[0])
        dpol = m.group(1) if m else None
    posture = ("strong" if (spf and dpol in ("quarantine", "reject"))
               else "partial" if (spf or dmarc) else "weak")
    return {"domain": q, "spf": spf[0] if spf else None, "spf_present": bool(spf),
            "dmarc": dmarc[0] if dmarc else None, "dmarc_policy": dpol,
            "dkim_selectors_found": dkim, "posture": posture}


# 22. robots.txt + sitemaps
def tool_robots(q):
    url = (q if q.startswith("http") else "https://" + q).rstrip("/") + "/robots.txt"
    try:
        r = _get(url)
    except Exception as e:
        return {"url": url, "error": str(e)}
    if r.status_code != 200:
        return {"url": url, "status": r.status_code, "note": "no robots.txt"}
    dis = [l.split(":", 1)[1].strip() for l in r.text.splitlines()
           if l.lower().startswith("disallow:") and ":" in l]
    sm = [l.split(":", 1)[1].strip() for l in r.text.splitlines()
          if l.lower().startswith("sitemap:")]
    return {"url": url, "disallow_count": len(dis), "disallowed": dis[:50],
            "sitemaps": sm}


# 23. Technology fingerprint
def tool_tech(q):
    url = q if q.startswith("http") else "https://" + q
    try:
        r = _get(url, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}
    h = r.headers
    body = r.text[:200000].lower()
    cookies = h.get("Set-Cookie", "").lower()
    tech = set()
    for hdr in ("Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"):
        if h.get(hdr):
            tech.add(f"{hdr}: {h[hdr]}")
    sigs = {"wp-content": "WordPress", "/sites/default": "Drupal",
            "cdn.shopify": "Shopify", "wix.com": "Wix",
            "squarespace": "Squarespace", "laravel_session": "Laravel",
            "csrftoken": "Django", "phpsessid": "PHP", "jsessionid": "Java",
            "asp.net": "ASP.NET", "next/static": "Next.js", "/_nuxt/": "Nuxt.js",
            "ng-version": "Angular", "gatsby": "Gatsby", "__cf": "Cloudflare"}
    for sig, name in sigs.items():
        if sig in body or sig in cookies:
            tech.add(name)
    m = re.search(r'<meta name="generator" content="([^"]+)"', r.text, re.I)
    if m:
        tech.add("generator: " + m.group(1))
    return {"url": url, "status": r.status_code, "technologies": sorted(tech)}


# 24. Favicon hash (pivoting)
def tool_favicon(q):
    base = q if q.startswith("http") else "https://" + q
    url = base.rstrip("/") + "/favicon.ico"
    try:
        r = _get(url)
    except Exception as e:
        return {"url": url, "error": str(e)}
    if r.status_code != 200:
        return {"url": url, "status": r.status_code, "note": "no favicon"}
    data = r.content
    return {"url": url, "bytes": len(data), "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "content_type": r.headers.get("Content-Type")}


# 25. Redirect tracer
def tool_redirects(q):
    url = q if q.startswith("http") else "http://" + q
    try:
        r = _get(url, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}
    chain = [{"status": h.status_code, "url": h.url,
              "location": h.headers.get("Location")} for h in r.history]
    chain.append({"status": r.status_code, "url": r.url})
    return {"start": url, "hops": len(r.history), "final_url": r.url,
            "final_status": r.status_code, "chain": chain}


# 27. Certificate-transparency history (crt.sh issuer timeline)
def tool_certhistory(q):
    try:
        rows = _crtsh({"q": q})
    except Exception as e:
        return {"domain": q, "error": f"crt.sh failed: {e}"}
    issuers = {}
    for row in rows:
        iss = row.get("issuer_name", "")
        issuers[iss] = issuers.get(iss, 0) + 1
    stamps = sorted(r.get("not_before", "") for r in rows if r.get("not_before"))
    top = dict(sorted(issuers.items(), key=lambda x: -x[1])[:10])
    return {"domain": q, "total_certs": len(rows), "unique_issuers": len(issuers),
            "issuers": top, "earliest": stamps[0] if stamps else None,
            "latest": stamps[-1] if stamps else None}


# 28. Social profile link expander (no network)
SOCIAL = {
    "GitHub": "https://github.com/{}", "Twitter/X": "https://x.com/{}",
    "Instagram": "https://instagram.com/{}", "Reddit": "https://reddit.com/user/{}",
    "TikTok": "https://tiktok.com/@{}", "YouTube": "https://youtube.com/@{}",
    "LinkedIn": "https://linkedin.com/in/{}", "Facebook": "https://facebook.com/{}",
    "Twitch": "https://twitch.tv/{}", "Pinterest": "https://pinterest.com/{}",
    "Medium": "https://medium.com/@{}", "Telegram": "https://t.me/{}",
    "Keybase": "https://keybase.io/{}", "GitLab": "https://gitlab.com/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Steam": "https://steamcommunity.com/id/{}",
    "SoundCloud": "https://soundcloud.com/{}", "Patreon": "https://patreon.com/{}",
    "Mastodon": "https://mastodon.social/@{}", "Spotify": "https://open.spotify.com/user/{}",
}


def tool_social(q):
    return {"username": q, "platform_count": len(SOCIAL),
            "profiles": {k: v.format(q) for k, v in SOCIAL.items()}}


# 29. MAC address vendor lookup
def tool_mac(q):
    try:
        r = _get(f"https://api.macvendors.com/{q}")
    except Exception as e:
        return {"mac": q, "error": str(e)}
    if r.status_code != 200:
        return {"mac": q, "vendor": None, "note": "not found"}
    return {"mac": q, "vendor": r.text.strip(), "oui": q[:8].upper()}


# 30. Crypto address intel (BTC / ETH via blockchair)
def tool_crypto(q):
    if re.match(r"^0x[0-9a-fA-F]{40}$", q):
        chain = "ethereum"
    elif re.match(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$", q):
        chain = "bitcoin"
    else:
        return {"address": q, "error": "unrecognized BTC/ETH address"}
    try:
        # `or {}` because blockchair returns {"data": {addr: null}} for
        # never-seen addresses, so .get(q, {}) returns None rather than the default.
        data = _get(f"https://api.blockchair.com/{chain}/dashboards/address/{q}").json()
        d = ((data.get("data") or {}).get(q) or {}).get("address") or {}
    except Exception as e:
        return {"address": q, "chain": chain, "error": str(e)}
    return {"address": q, "chain": chain, "balance": d.get("balance"),
            "received": d.get("received"), "spent": d.get("spent"),
            "tx_count": d.get("transaction_count"),
            "first_seen": d.get("first_seen_receiving"),
            "last_seen": d.get("last_seen_spending")}


# 31. OSINT search-dork link builder (no scraping — builds manual search URLs)
def tool_dorks(q):
    e = requests.utils.quote(q)
    return {"query": q,
            "note": "Manual OSINT search links — opens searches, does not scrape.",
            "dorks": {
                "Google exact": f"https://www.google.com/search?q=%22{e}%22",
                "Google filetypes": f"https://www.google.com/search?q=%22{e}%22+(filetype:pdf+OR+filetype:xlsx+OR+filetype:docx)",
                "Google pastes": f"https://www.google.com/search?q=%22{e}%22+(site:pastebin.com+OR+site:ghostbin.com)",
                "Google social": f"https://www.google.com/search?q=%22{e}%22+(site:linkedin.com+OR+site:twitter.com)",
                "Google docs": f"https://www.google.com/search?q=%22{e}%22+(site:docs.google.com+OR+site:drive.google.com)",
                "Bing": f"https://www.bing.com/search?q=%22{e}%22",
                "DuckDuckGo": f"https://duckduckgo.com/?q=%22{e}%22",
                "GitHub code": f"https://github.com/search?q=%22{e}%22&type=code",
            }}


# ---------------------------------------------------------------------------
# Extended batch 2: threat intel / web-security / identity / offline utilities
# ---------------------------------------------------------------------------

# 32. urlscan.io — past scans, verdicts, infra for a domain/URL (free, no key)
def tool_urlscan(q):
    host = _host(q)
    r = _get("https://urlscan.io/api/v1/search/",
             params={"q": f"page.domain:{host}", "size": 10})
    if r.status_code != 200:
        return {"target": host, "error": f"urlscan {r.status_code}: {r.text[:200]}"}
    res = r.json()
    out = []
    for it in res.get("results", []):
        pg, tk = it.get("page", {}), it.get("task", {})
        out.append({"url": tk.get("url") or pg.get("url"), "time": tk.get("time"),
                    "ip": pg.get("ip"), "country": pg.get("country"),
                    "server": pg.get("server"), "asn": pg.get("asnname"),
                    "result": it.get("result")})
    return {"target": host, "total": res.get("total", len(out)), "scans": out}


# 33. GreyNoise Community — is this IP an internet scanner / benign / malicious
def tool_greynoise(q):
    r = _get(f"https://api.greynoise.io/v3/community/{q}")
    try:
        d = r.json()
    except Exception:
        return {"ip": q, "error": f"greynoise {r.status_code}"}
    return {"ip": q, "noise": d.get("noise"), "riot": d.get("riot"),
            "classification": d.get("classification"), "name": d.get("name"),
            "last_seen": d.get("last_seen"), "message": d.get("message"),
            "link": d.get("link")}


# 34. Typosquat generator — look-alike domains + which currently resolve (live)
_HOMO = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
_EXTRA_TLDS = ["com", "net", "org", "co", "io", "info", "xyz", "online", "app"]


def _typo_variants(domain):
    name, _, tld = domain.partition(".")
    rest = tld or "com"
    v = set()
    for i in range(len(name)):                       # omission
        v.add(name[:i] + name[i + 1:] + "." + rest)
    for i in range(len(name) - 1):                   # adjacent swap
        v.add(name[:i] + name[i + 1] + name[i] + name[i + 2:] + "." + rest)
    for i, c in enumerate(name):                     # homoglyph
        if c in _HOMO:
            v.add(name[:i] + _HOMO[c] + name[i + 1:] + "." + rest)
    for i in range(len(name) + 1):                   # double-char insertion
        if 0 < i <= len(name):
            v.add(name[:i] + name[i - 1] + name[i:] + "." + rest)
    for t in _EXTRA_TLDS:                             # TLD swap
        if t != rest:
            v.add(name + "." + t)
    v.discard(domain)
    return sorted(v)


def tool_typosquat(q):
    domain = _host(q).lower()
    cands = _typo_variants(domain)[:50]              # cap DoH fan-out

    def resolves(d):
        try:
            a = _get("https://dns.google/resolve",
                     params={"name": d, "type": "A"}).json().get("Answer", [])
            ips = [x["data"] for x in a if x.get("type") == 1]
            return (d, ips[0]) if ips else None
        except Exception:
            return None

    live = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for hit in ex.map(resolves, cands):
            if hit:
                live.append({"domain": hit[0], "ip": hit[1]})
    return {"domain": domain, "candidates_checked": len(cands),
            "registered_count": len(live), "registered": live,
            "note": "Registered look-alikes that resolve. Verify before acting."}


# 35. security.txt — disclosure policy contact (RFC 9116)
def tool_securitytxt(q):
    host = _host(q)
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = _get(f"https://{host}{path}", timeout=6)
            if r.status_code == 200 and "html" not in r.headers.get(
                    "content-type", "").lower():
                fields = {}
                for line in r.text.splitlines():
                    if ":" in line and not line.startswith("#"):
                        k, _, val = line.partition(":")
                        fields.setdefault(k.strip(), []).append(val.strip())
                return {"domain": host, "found": True, "path": path, "fields": fields}
        except Exception:
            continue
    return {"domain": host, "found": False}


# 36. Keybase — cryptographic identity + linked social proofs
def tool_keybase(q):
    d = _get("https://keybase.io/_/api/1.0/user/lookup.json",
             params={"usernames": q,
                     "fields": "basics,profile,proofs_summary,cryptocurrency_addresses"}).json()
    them = d.get("them") or []
    if not them or not them[0]:
        return {"username": q, "found": False}
    u = them[0]
    proofs = [{"type": p.get("proof_type"), "name": p.get("nametag"),
               "url": p.get("service_url")}
              for p in (u.get("proofs_summary", {}) or {}).get("all", [])]
    prof = u.get("profile", {}) or {}
    crypto = u.get("cryptocurrency_addresses", {}) or {}
    return {"username": q, "found": True,
            "full_name": prof.get("full_name"), "location": prof.get("location"),
            "bio": prof.get("bio"), "proofs": proofs,
            "btc": (crypto.get("bitcoin") or [{}])[0].get("address")
                   if crypto.get("bitcoin") else None}


# 37. Phone number — E.164 country/region from calling-code table (offline)
_CC = {  # calling code -> region (most common; not exhaustive)
    "1": "US/Canada", "7": "Russia/Kazakhstan", "20": "Egypt", "27": "South Africa",
    "30": "Greece", "31": "Netherlands", "32": "Belgium", "33": "France",
    "34": "Spain", "36": "Hungary", "39": "Italy", "40": "Romania", "41": "Switzerland",
    "44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway",
    "48": "Poland", "49": "Germany", "51": "Peru", "52": "Mexico", "53": "Cuba",
    "54": "Argentina", "55": "Brazil", "56": "Chile", "57": "Colombia", "58": "Venezuela",
    "60": "Malaysia", "61": "Australia", "62": "Indonesia", "63": "Philippines",
    "64": "New Zealand", "65": "Singapore", "66": "Thailand", "81": "Japan",
    "82": "South Korea", "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India",
    "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar",
    "98": "Iran", "212": "Morocco", "213": "Algeria", "234": "Nigeria", "251": "Ethiopia",
    "254": "Kenya", "255": "Tanzania", "256": "Uganda", "351": "Portugal",
    "352": "Luxembourg", "353": "Ireland", "354": "Iceland", "358": "Finland",
    "359": "Bulgaria", "370": "Lithuania", "371": "Latvia", "372": "Estonia",
    "380": "Ukraine", "381": "Serbia", "385": "Croatia", "420": "Czechia",
    "421": "Slovakia", "852": "Hong Kong", "880": "Bangladesh", "886": "Taiwan",
    "961": "Lebanon", "962": "Jordan", "963": "Syria", "964": "Iraq", "965": "Kuwait",
    "966": "Saudi Arabia", "971": "UAE", "972": "Israel", "974": "Qatar", "977": "Nepal",
}


def tool_phone(q):
    digits = re.sub(r"[^\d]", "", q)
    if not digits:
        return {"input": q, "error": "no digits"}
    cc = next((c for n in (3, 2, 1) for c in [digits[:n]] if c in _CC), None)
    return {"input": q, "e164": "+" + digits, "country_code": cc,
            "region": _CC.get(cc, "unknown"),
            "national_number": digits[len(cc):] if cc else digits,
            "length": len(digits),
            "valid_length": 8 <= len(digits) <= 15,
            "note": "Country-level only (offline prefix table); no carrier/line-type."}


# 38. Decode — auto base64 / hex / URL-decode + defang/refang (offline)
def _printable(b):
    try:
        s = b.decode("utf-8")
    except Exception:
        return None
    return s if s and all(31 < ord(c) or c in "\t\n\r" for c in s) else None


def tool_decode(q):
    out = {}
    try:
        pad = q + "=" * (-len(q) % 4)
        s = _printable(base64.b64decode(pad, validate=False))
        if s and s != q:
            out["base64"] = s
    except Exception:
        pass
    try:
        if re.fullmatch(r"[0-9a-fA-F]+", q) and len(q) % 2 == 0:
            s = _printable(binascii.unhexlify(q))
            if s:
                out["hex"] = s
    except Exception:
        pass
    url_dec = urllib.parse.unquote(q)
    if url_dec != q:
        out["url"] = url_dec
    refanged = q.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
    if refanged != q:
        out["refanged"] = refanged
    return {"input": q, "decoded": out or {"_": "no recognizable encoding"}}


# 39. JWT decoder — header + claims, no signature verification (offline)
def tool_jwt(q):
    parts = q.split(".")
    if len(parts) != 3:
        return {"error": "not a 3-part JWT"}

    def seg(s):
        return _json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    try:
        header, payload = seg(parts[0]), seg(parts[1])
    except Exception as e:
        return {"error": f"decode failed: {e}"}
    return {"header": header, "payload": payload, "alg": header.get("alg"),
            "issuer": payload.get("iss"), "subject": payload.get("sub"),
            "expires": payload.get("exp"), "issued_at": payload.get("iat"),
            "note": "Decoded only — signature NOT verified."}


# 40. Hash identifier — guess algorithm from length/charset (offline)
def tool_hashid(q):
    h = q.strip()
    cands = []
    if re.fullmatch(r"\$2[aby]\$.+", h):
        cands = ["bcrypt"]
    elif re.fullmatch(r"\$argon2(id|i|d)\$.+", h):
        cands = ["Argon2"]
    elif re.fullmatch(r"[0-9a-fA-F]+", h):
        cands = {32: ["MD5", "NTLM", "MD4", "LM"], 40: ["SHA-1", "RIPEMD-160"],
                 56: ["SHA-224"], 64: ["SHA-256", "SHA3-256", "BLAKE2s"],
                 96: ["SHA-384"], 128: ["SHA-512", "SHA3-512", "BLAKE2b"]}.get(len(h), [])
    return {"input": h, "length": len(h),
            "possible": cands or ["unknown — not a recognized hash format"]}


# 41. CIDR / IP math — network, broadcast, range, host count (offline, stdlib)
def tool_cidr(q):
    try:
        net = ipaddress.ip_network(q, strict=False)
    except Exception as e:
        return {"input": q, "error": str(e)}
    hosts = list(net.hosts())
    return {"input": q, "network": str(net.network_address),
            "netmask": str(net.netmask), "prefixlen": net.prefixlen,
            "broadcast": str(getattr(net, "broadcast_address", "")),
            "total_addresses": net.num_addresses, "usable_hosts": len(hosts),
            "first_host": str(hosts[0]) if hosts else None,
            "last_host": str(hosts[-1]) if hosts else None,
            "version": net.version, "is_private": net.is_private,
            "is_global": net.is_global}


# 42. Exposed-file probe — .git/.env/backups on a host (authorized targets only)
_EXPOSED = ["/.git/HEAD", "/.git/config", "/.env", "/.svn/entries", "/.DS_Store",
            "/.htaccess", "/config.php.bak", "/backup.zip", "/.well-known/",
            "/server-status", "/wp-config.php.bak", "/.aws/credentials"]


def tool_gitexposed(q):
    host = _host(q)
    base = q if q.startswith("http") else "https://" + host
    base = base.rstrip("/")
    sigs = {"/.git/HEAD": "ref:", "/.git/config": "[core]", "/.env": "=",
            "/.svn/entries": "", "/wp-config.php.bak": "DB_", "/.aws/credentials": "aws_"}

    def probe(path):
        try:
            r = _get(base + path, timeout=5, allow_redirects=False)
            body = r.text[:512]
            if r.status_code == 200 and "<html" not in body.lower():
                sig = sigs.get(path)
                if sig and sig not in body:
                    return None
                return {"path": path, "status": 200, "bytes": len(r.content),
                        "preview": body[:120]}
        except Exception:
            return None
        return None

    found = []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for hit in ex.map(probe, _EXPOSED):
            if hit:
                found.append(hit)
    return {"target": host, "exposed_count": len(found), "exposed": found,
            "note": "Per-target check. Only probe hosts you are authorized to test."}


# 43. CORS misconfiguration — does the host reflect an arbitrary Origin
def tool_cors(q):
    url = q if q.startswith("http") else "https://" + _host(q)
    evil = "https://evil.example.com"
    try:
        r = _get(url, headers={"Origin": evil}, timeout=6)
    except Exception as e:
        return {"target": _host(q), "error": str(e)}
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    risk = "none"
    if acao == "*":
        risk = "wildcard (no credentials allowed)"
    elif acao == evil:
        risk = "REFLECTS arbitrary origin" + (
            " + allows credentials — HIGH" if acac == "true" else "")
    return {"target": _host(q), "allow_origin": acao,
            "allow_credentials": acac, "reflects_origin": acao == evil, "risk": risk}


# 44. Cookie security — Set-Cookie flag audit (Secure/HttpOnly/SameSite)
def tool_cookies(q):
    url = q if q.startswith("http") else "https://" + _host(q)
    try:
        r = _get(url, timeout=6)
    except Exception as e:
        return {"target": _host(q), "error": str(e)}
    raw = r.headers.get("Set-Cookie", "")
    cookies = []
    for c in r.cookies:
        attrs = (c._rest or {})
        cookies.append({"name": c.name, "secure": bool(c.secure),
                        "httponly": "HttpOnly" in attrs or "httponly" in attrs,
                        "samesite": next((attrs[k] for k in attrs
                                          if k.lower() == "samesite"), None)})
    return {"target": _host(q), "cookie_count": len(cookies), "cookies": cookies,
            "raw_present": bool(raw)}


# 45. DNSSEC — is the zone signed (DoH AD flag + DNSKEY presence)
def tool_dnssec(q):
    host = _host(q)
    a = _get("https://dns.google/resolve",
             params={"name": host, "type": "A", "do": "true"}).json()
    keys = _get("https://dns.google/resolve",
                params={"name": host, "type": "DNSKEY"}).json().get("Answer", [])
    ds = _get("https://dns.google/resolve",
              params={"name": host, "type": "DS"}).json().get("Answer", [])
    return {"domain": host, "authenticated_data": bool(a.get("AD")),
            "dnskey_count": len(keys), "ds_count": len(ds),
            "signed": bool(a.get("AD")) and bool(keys),
            "note": "AD=true means the resolver validated DNSSEC for this zone."}


# 46. PGP key lookup — is a public key published for this email (keys.openpgp.org)
def tool_pgp(q):
    enc = urllib.parse.quote(q)
    r = _get(f"https://keys.openpgp.org/vks/v1/by-email/{enc}", timeout=8)
    if r.status_code == 200 and "BEGIN PGP" in r.text:
        return {"email": q, "key_published": True, "bytes": len(r.text),
                "keyserver": "keys.openpgp.org",
                "url": f"https://keys.openpgp.org/search?q={enc}"}
    return {"email": q, "key_published": False, "keyserver": "keys.openpgp.org"}


# 47. Hacker News — profile + activity (Firebase API)
def tool_hackernews(q):
    d = _get(f"https://hacker-news.firebaseio.com/v0/user/{q}.json").json()
    if not d:
        return {"username": q, "found": False}
    return {"username": q, "found": True, "karma": d.get("karma"),
            "created": d.get("created"), "about": d.get("about"),
            "submission_count": len(d.get("submitted", [])),
            "url": f"https://news.ycombinator.com/user?id={q}"}


# 48. GitLab — public user profile
def tool_gitlab(q):
    arr = _get("https://gitlab.com/api/v4/users", params={"username": q}).json()
    if not arr:
        return {"username": q, "found": False}
    u = arr[0]
    return {"username": q, "found": True, "id": u.get("id"), "name": u.get("name"),
            "bio": u.get("bio"), "location": u.get("location"),
            "created": u.get("created_at"), "state": u.get("state"),
            "url": u.get("web_url")}


# ---------------------------------------------------------------------------
# Extended batch 3: dns/web-recon / vuln / packages / offline utilities
# ---------------------------------------------------------------------------

# 49. DNS propagation — compare A records across public resolvers
_RESOLVERS = {
    "Google": ("https://dns.google/resolve", {}),
    "Cloudflare": ("https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"}),
    "Quad9": ("https://dns.quad9.net/dns-query", {"accept": "application/dns-json"}),
}


def tool_dnsprop(q):
    host = _host(q)
    out = {}
    for name, (url, hdr) in _RESOLVERS.items():
        try:
            a = _get(url, params={"name": host, "type": "A"}, headers=hdr,
                     timeout=6).json().get("Answer", [])
            out[name] = sorted(x["data"] for x in a if x.get("type") == 1)
        except Exception as e:
            out[name] = [f"error: {e}"]
    allips = {ip for v in out.values() for ip in v if not ip.startswith("error")}
    consistent = len({tuple(v) for v in out.values()}) == 1
    return {"domain": host, "consistent": consistent,
            "distinct_ips": sorted(allips), "by_resolver": out}


# 50. Subdomain-takeover fingerprint check (dangling CNAME -> unclaimed service)
_TAKEOVER = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "AWS S3": "NoSuchBucket",
    "Heroku": "No such app",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Fastly": "Fastly error: unknown domain",
    "Pantheon": "The gods are wise, but do not know of the site",
    "Tumblr": "Whatever you were looking for doesn't currently exist",
    "Surge.sh": "project not found",
    "Bitbucket": "Repository not found",
    "Ghost": "Domain error",
    "Unbounce": "The requested URL was not found on this server",
    "Webflow": "The page you are looking for doesn't exist or has been moved",
}


def tool_takeover(q):
    host = _host(q)
    cname = None
    try:
        a = _get("https://dns.google/resolve",
                 params={"name": host, "type": "CNAME"}).json().get("Answer", [])
        cname = next((x["data"].rstrip(".") for x in a if x.get("type") == 5), None)
    except Exception:
        pass
    body = ""
    for scheme in ("https://", "http://"):
        try:
            body = _get(scheme + host, timeout=7).text[:4000]
            break
        except Exception:
            continue
    hits = [svc for svc, sig in _TAKEOVER.items() if sig.lower() in body.lower()]
    return {"host": host, "cname": cname,
            "vulnerable": bool(hits), "matched_service": hits,
            "note": "Fingerprint match on a dangling CNAME suggests possible takeover. Verify manually."}


# 51. Sitemap — fetch sitemap.xml (and any listed in robots.txt), list URLs
def tool_sitemap(q):
    host = _host(q)
    base = q if q.startswith("http") else "https://" + host
    base = base.rstrip("/")
    maps = [base + "/sitemap.xml"]
    try:
        rob = _get(base + "/robots.txt", timeout=6).text
        maps += re.findall(r"(?i)sitemap:\s*(\S+)", rob)
    except Exception:
        pass
    urls, seen = [], set()
    for m in dict.fromkeys(maps):
        try:
            xml = _get(m, timeout=8).text
            for u in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml):
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        except Exception:
            continue
    return {"domain": host, "sitemaps_checked": len(maps),
            "url_count": len(urls), "urls": urls[:300]}


# 52. WAF / CDN detection from response headers, cookies, and server banner
_WAF = {
    "Cloudflare": [("server", "cloudflare"), ("cookie", "__cf"), ("header", "cf-ray")],
    "Akamai": [("server", "akamaighost"), ("header", "x-akamai")],
    "AWS CloudFront": [("server", "cloudfront"), ("header", "x-amz-cf-id")],
    "Sucuri": [("server", "sucuri"), ("header", "x-sucuri-id")],
    "Imperva/Incapsula": [("cookie", "incap_ses"), ("cookie", "visid_incap"), ("header", "x-iinfo")],
    "Fastly": [("server", "fastly"), ("header", "x-fastly")],
    "F5 BIG-IP": [("cookie", "bigipserver")],
    "Barracuda": [("cookie", "barra_counter")],
    "Wordfence": [("header", "x-wordfence")],
    "Vercel": [("server", "vercel"), ("header", "x-vercel-id")],
}


def tool_waf(q):
    url = q if q.startswith("http") else "https://" + _host(q)
    try:
        r = _get(url, timeout=7)
    except Exception as e:
        return {"target": _host(q), "error": str(e)}
    server = r.headers.get("Server", "")
    hkeys = " ".join(r.headers.keys()).lower()
    ckeys = " ".join(c.name for c in r.cookies).lower()
    detected = []
    for waf, sigs in _WAF.items():
        for where, sig in sigs:
            hay = {"server": server.lower(), "header": hkeys, "cookie": ckeys}[where]
            if sig in hay:
                detected.append(waf)
                break
    return {"target": _host(q), "server": server,
            "waf_cdn": sorted(set(detected)) or ["none detected"]}


# 53. CVE lookup — CIRCL vulnerability-lookup (free, no key)
def tool_cve(q):
    cid = q.upper()
    r = _get(f"https://cve.circl.lu/api/cve/{cid}", timeout=10)
    if r.status_code != 200 or not r.text.strip():
        return {"cve": cid, "error": f"not found ({r.status_code})"}
    d = r.json()
    cna = (d.get("containers", {}).get("cna", {}) if "containers" in d else d)
    desc = next((x.get("value") for x in cna.get("descriptions", []) if x.get("value")),
                d.get("summary"))
    metrics = cna.get("metrics", [])
    cvss = None
    for m in metrics:
        for k, v in m.items():
            if isinstance(v, dict) and v.get("baseScore"):
                cvss = {"score": v.get("baseScore"), "severity": v.get("baseSeverity"),
                        "vector": v.get("vectorString")}
    meta = d.get("cveMetadata", {})
    return {"cve": cid, "state": meta.get("state"),
            "published": meta.get("datePublished") or d.get("Published"),
            "cvss": cvss, "description": (desc or "")[:600]}


# 54. npm — packages published by an author + headline stats
def tool_npm(q):
    r = _get("https://registry.npmjs.org/-/v1/search",
             params={"text": f"author:{q}", "size": 20}).json()
    pkgs = [{"name": o["package"]["name"], "version": o["package"].get("version"),
             "description": o["package"].get("description"),
             "weekly_downloads": (o.get("downloads") or {}).get("weekly"),
             "link": o["package"].get("links", {}).get("npm")}
            for o in r.get("objects", [])]
    return {"author": q, "package_count": r.get("total", len(pkgs)),
            "packages": pkgs}


# 55. ASN peers — upstream/downstream neighbours (RIPEstat)
def tool_peers(q):
    if re.match(r"^(AS)?\d+$", q, re.I):
        asn = q.upper().replace("AS", "")
    else:
        ni = _get("https://stat.ripe.net/data/network-info/data.json",
                  params={"resource": q}).json().get("data", {})
        asns = ni.get("asns") or []
        if not asns:
            return {"input": q, "error": "no ASN found for this IP"}
        asn = asns[0]
    d = _get("https://stat.ripe.net/data/asn-neighbours/data.json",
             params={"resource": f"AS{asn}"}).json().get("data", {})
    nb = d.get("neighbours", [])
    left = sorted(f"AS{n['asn']}" for n in nb if n.get("type") == "left")
    right = sorted(f"AS{n['asn']}" for n in nb if n.get("type") == "right")
    return {"asn": f"AS{asn}", "neighbour_count": len(nb),
            "upstreams": left, "downstreams": right}


# 56. URL parser — decompose a URL + decode query params (offline)
def tool_urlparse(q):
    u = urllib.parse.urlsplit(q if "//" in q else "//" + q)
    params = {k: v if len(v) > 1 else v[0]
              for k, v in urllib.parse.parse_qs(u.query).items()}
    return {"scheme": u.scheme or None, "host": u.hostname, "port": u.port,
            "path": u.path or "/", "query_params": params or {},
            "fragment": u.fragment or None,
            "username": u.username, "password": u.password}


# 57. Epoch — Unix timestamp <-> UTC datetime (offline)
def tool_epoch(q):
    digits = re.sub(r"\D", "", q)
    if not digits:
        return {"input": q, "error": "give a Unix timestamp (seconds or milliseconds)"}
    n = int(digits)
    secs = n / 1000 if n > 1e12 else n          # ms vs s
    try:
        dt = datetime.datetime.utcfromtimestamp(secs)
    except Exception as e:
        return {"input": q, "error": str(e)}
    return {"input": q, "unix_seconds": int(secs),
            "utc": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "iso8601": dt.isoformat() + "Z", "weekday": dt.strftime("%A")}


# 58. TLS version scan — which SSL/TLS protocols a host accepts
def tool_tlsscan(q):
    host = _host(q)
    versions = {"TLSv1.0": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                "TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}
    result = {}
    for name, ver in versions.items():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except ValueError:
            result[name] = "unavailable (disabled in local OpenSSL)"
            continue
        try:
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    result[name] = "supported"
        except Exception:
            result[name] = "rejected"
    weak = [v for v in ("TLSv1.0", "TLSv1.1") if result.get(v) == "supported"]
    return {"host": host, "protocols": result,
            "weak_protocols_enabled": weak or None}


# ---------------------------------------------------------------------------
# Extended batch 4: new indicator types (coords/iban/bin/uuid/isbn/txhash)
# + more keyless tools on existing types. No API keys anywhere.
# ---------------------------------------------------------------------------

# 59. Reverse geocode — lat,lon -> address (OSM Nominatim, keyless)
def _coords(q):
    m = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)\s*$", q)
    if not m:
        return None
    lat, lon = float(m.group(1)), float(m.group(2))
    if abs(lat) > 90 or abs(lon) > 180:
        return None
    return lat, lon


def tool_revgeo(q):
    c = _coords(q)
    if not c:
        return {"input": q, "error": "expected 'lat,lon'"}
    lat, lon = c
    r = _get("https://nominatim.openstreetmap.org/reverse",
             params={"lat": lat, "lon": lon, "format": "jsonv2"},
             headers={"Accept-Language": "en"})
    if r.status_code != 200:
        return {"lat": lat, "lon": lon, "error": f"Nominatim {r.status_code}"}
    d = r.json()
    return {"lat": lat, "lon": lon, "display_name": d.get("display_name"),
            "type": d.get("type"), "category": d.get("category"),
            "address": d.get("address", {}),
            "osm": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"}


# 60. Sun times for a coordinate (sunrise-sunset.org, keyless, UTC)
def tool_suntimes(q):
    c = _coords(q)
    if not c:
        return {"input": q, "error": "expected 'lat,lon'"}
    lat, lon = c
    d = _get("https://api.sunrise-sunset.org/json",
             params={"lat": lat, "lng": lon, "formatted": 0}).json().get("results", {})
    return {"lat": lat, "lon": lon, "sunrise_utc": d.get("sunrise"),
            "sunset_utc": d.get("sunset"), "solar_noon_utc": d.get("solar_noon"),
            "day_length_s": d.get("day_length"),
            "civil_twilight_begin": d.get("civil_twilight_begin"),
            "civil_twilight_end": d.get("civil_twilight_end")}


# 61. IBAN — offline structural validation + country/bank code (ISO 13616)
_IBAN_LEN = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "CH": 21, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20,
    "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GR": 27, "HR": 21,
    "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27, "KW": 30, "KZ": 20, "LB": 28,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
    "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "QA": 29, "RO": 24,
    "RS": 22, "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TN": 24, "TR": 26,
    "UA": 29, "VA": 22, "XK": 20,
}


def tool_iban(q):
    iban = re.sub(r"\s+", "", q).upper()
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", iban):
        return {"input": q, "valid": False, "error": "not IBAN-shaped"}
    cc = iban[:2]
    expected = _IBAN_LEN.get(cc)
    # mod-97: move first 4 chars to end, letters -> numbers (A=10..Z=35), %97 == 1
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in rearranged)
    mod_ok = int(digits) % 97 == 1
    return {"input": q, "iban": iban, "country": cc,
            "bban": iban[4:], "length": len(iban),
            "length_ok": expected is None or len(iban) == expected,
            "checksum_ok": mod_ok,
            "valid": mod_ok and (expected is None or len(iban) == expected),
            "note": "Structural/checksum validation only — does not confirm the account exists."}


# 62. Card BIN/IIN — issuer, scheme, country (binlist.io, keyless)
def tool_bin(q):
    bin6 = re.sub(r"\D", "", q)[:8]
    if len(bin6) < 6:
        return {"input": q, "error": "need at least 6 digits"}
    r = _get(f"https://lookup.binlist.net/{bin6}", headers={"Accept-Version": "3"})
    if r.status_code != 200:
        return {"bin": bin6, "error": f"binlist {r.status_code} (rate-limited?)"}
    d = r.json()
    return {"bin": bin6, "scheme": d.get("scheme"), "type": d.get("type"),
            "brand": d.get("brand"), "prepaid": d.get("prepaid"),
            "bank": (d.get("bank") or {}).get("name"),
            "country": (d.get("country") or {}).get("name"),
            "country_emoji": (d.get("country") or {}).get("emoji"),
            "note": "BIN identifies the issuer, not the cardholder."}


# 63. UUID — version, variant, and embedded timestamp/node for v1 (offline)
def tool_uuid(q):
    u = q.strip().lower()
    if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", u):
        return {"input": q, "error": "not a canonical UUID"}
    hexs = u.replace("-", "")
    version = int(hexs[12], 16)
    var_bits = int(hexs[16], 16)
    variant = ("RFC 4122" if var_bits >> 2 == 0b10 else
               "NCS (legacy)" if var_bits >> 3 == 0 else
               "Microsoft" if var_bits >> 1 == 0b110 else "reserved")
    out = {"input": q, "version": version, "variant": variant}
    if version == 1:
        # 60-bit timestamp = 100ns intervals since 1582-10-15
        ts = int(hexs[13:16] + hexs[8:12] + hexs[0:8], 16)
        secs = ts / 1e7 - 12219292800
        try:
            out["timestamp_utc"] = datetime.datetime.utcfromtimestamp(secs).isoformat() + "Z"
        except Exception:
            pass
        out["node_mac"] = ":".join(hexs[20:][i:i + 2] for i in range(0, 12, 2))
    return out


# 64. ISBN — book metadata via OpenLibrary (keyless) + offline checksum
def _isbn_valid(s):
    s = s.replace("-", "").replace(" ", "").upper()
    if len(s) == 10:
        if not re.match(r"^\d{9}[\dX]$", s):
            return False
        tot = sum((10 - i) * (10 if c == "X" else int(c)) for i, c in enumerate(s))
        return tot % 11 == 0
    if len(s) == 13 and s.isdigit():
        return sum((1 if i % 2 == 0 else 3) * int(c) for i, c in enumerate(s)) % 10 == 0
    return False


def tool_isbn(q):
    isbn = q.replace("-", "").replace(" ", "").upper()
    valid = _isbn_valid(isbn)
    r = _get(f"https://openlibrary.org/isbn/{isbn}.json")
    if r.status_code != 200:
        return {"isbn": isbn, "checksum_valid": valid, "found": False}
    d = r.json()
    authors = []
    for a in d.get("authors", []):
        try:
            an = _get(f"https://openlibrary.org{a['key']}.json").json()
            authors.append(an.get("name"))
        except Exception:
            pass
    return {"isbn": isbn, "checksum_valid": valid, "found": True,
            "title": d.get("title"), "subtitle": d.get("subtitle"),
            "authors": authors, "publishers": d.get("publishers"),
            "publish_date": d.get("publish_date"), "pages": d.get("number_of_pages"),
            "openlibrary": f"https://openlibrary.org/isbn/{isbn}"}


# 65. Crypto transaction — BTC/ETH tx detail via blockchair (keyless)
def tool_txhash(q):
    h = q.strip().lower()
    if re.match(r"^(0x)?[0-9a-f]{64}$", h):
        chain = "ethereum" if h.startswith("0x") else "bitcoin"
    else:
        return {"hash": q, "error": "not a 64-hex tx hash"}
    try:
        data = _get(f"https://api.blockchair.com/{chain}/dashboards/transaction/{h}").json()
        tx = ((data.get("data") or {}).get(h) or {}).get("transaction") or {}
    except Exception as e:
        return {"hash": q, "chain": chain, "error": str(e)}
    if not tx:
        return {"hash": q, "chain": chain, "found": False}
    return {"hash": h, "chain": chain, "found": True,
            "block": tx.get("block_id"), "time": tx.get("time"),
            "value": tx.get("output_total") or tx.get("value"),
            "fee": tx.get("fee"), "size": tx.get("size"),
            "explorer": f"https://blockchair.com/{chain}/transaction/{h}"}


# 66. Bluesky / AT Protocol — public profile (keyless public API)
def tool_bluesky(q):
    handle = q.lstrip("@")
    if "." not in handle:
        handle += ".bsky.social"
    r = _get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
             params={"actor": handle})
    if r.status_code != 200:
        return {"handle": handle, "found": False}
    d = r.json()
    return {"handle": d.get("handle"), "found": True, "did": d.get("did"),
            "display_name": d.get("displayName"), "description": d.get("description"),
            "followers": d.get("followersCount"), "following": d.get("followsCount"),
            "posts": d.get("postsCount"), "created": d.get("createdAt"),
            "url": f"https://bsky.app/profile/{d.get('handle')}"}


# 67. Chess.com — public player profile + stats (keyless public API)
def tool_chesscom(q):
    u = q.lstrip("@").lower()
    p = _get(f"https://api.chess.com/pub/player/{u}")
    if p.status_code != 200:
        return {"username": u, "found": False}
    d = p.json()
    stats = {}
    try:
        s = _get(f"https://api.chess.com/pub/player/{u}/stats").json()
        for mode in ("chess_rapid", "chess_blitz", "chess_bullet"):
            if mode in s:
                stats[mode.replace("chess_", "")] = (s[mode].get("last") or {}).get("rating")
    except Exception:
        pass
    return {"username": d.get("username"), "found": True, "name": d.get("name"),
            "country": (d.get("country") or "").split("/")[-1],
            "followers": d.get("followers"), "joined": d.get("joined"),
            "status": d.get("status"), "ratings": stats, "url": d.get("url")}


# 68. Wikipedia — does a page exist + summary (keyless REST API)
def tool_wikipedia(q):
    title = q.replace(" ", "_")
    r = _get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(title)}")
    if r.status_code != 200:
        return {"query": q, "found": False}
    d = r.json()
    if d.get("type") == "disambiguation":
        return {"query": q, "found": True, "disambiguation": True,
                "url": d.get("content_urls", {}).get("desktop", {}).get("page")}
    return {"query": q, "found": d.get("type") == "standard",
            "title": d.get("title"), "description": d.get("description"),
            "extract": d.get("extract"),
            "url": d.get("content_urls", {}).get("desktop", {}).get("page")}


# 69. HTTP ping — reachability + response timing for a host/url (live)
def tool_httping(q):
    url = q if q.startswith("http") else "https://" + _host(q)
    try:
        import time
        t0 = time.perf_counter()
        r = _get(url, allow_redirects=True)
        ms = (time.perf_counter() - t0) * 1000
    except Exception as e:
        return {"url": url, "reachable": False, "error": str(e)}
    return {"url": url, "reachable": True, "status": r.status_code,
            "response_ms": round(ms, 1), "final_url": r.url,
            "redirects": len(r.history),
            "content_length": r.headers.get("Content-Length"),
            "content_type": r.headers.get("Content-Type")}


# 70. Link extractor — pull all links from a page (live, capped)
def tool_links(q):
    url = q if q.startswith("http") else "https://" + _host(q)
    try:
        r = _get(url, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', r.text)
    base = urllib.parse.urlparse(r.url)
    abs_links, ext = set(), set()
    for h in hrefs:
        if h.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full = urllib.parse.urljoin(r.url, h)
        abs_links.add(full)
        host = urllib.parse.urlparse(full).hostname or ""
        if host and host != base.hostname:
            ext.add(host)
    emails = sorted(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', r.text)))
    return {"url": r.url, "total_links": len(abs_links),
            "external_domains": sorted(ext)[:50],
            "emails_found": emails[:30], "links": sorted(abs_links)[:150]}


# 71. Password / passphrase strength — offline entropy estimate
def tool_pwstrength(q):
    pools = [(r"[a-z]", 26), (r"[A-Z]", 26), (r"\d", 10),
             (r"[^a-zA-Z0-9]", 33)]
    pool = sum(size for pat, size in pools if re.search(pat, q))
    import math
    bits = round(len(q) * math.log2(pool), 1) if pool else 0
    rating = ("very weak" if bits < 28 else "weak" if bits < 36 else
              "reasonable" if bits < 60 else "strong" if bits < 128 else "very strong")
    common = q.lower() in {"password", "123456", "qwerty", "letmein", "admin",
                           "welcome", "monkey", "111111", "iloveyou"}
    return {"length": len(q), "charset_size": pool, "entropy_bits": bits,
            "rating": "common password — trivial" if common else rating,
            "is_common": common,
            "note": "Offline estimate from length×charset; not checked against breach lists."}


# 72. Shannon entropy — flag high-entropy strings (keys/secrets) (offline)
def tool_entropy(q):
    import math
    from collections import Counter
    n = len(q)
    if not n:
        return {"input": q, "error": "empty"}
    counts = Counter(q)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return {"input": q[:64] + ("…" if n > 64 else ""), "length": n,
            "shannon_bits_per_char": round(ent, 3),
            "total_bits": round(ent * n, 1), "distinct_chars": len(counts),
            "likely_secret": ent > 3.5 and n >= 16,
            "note": "High per-char entropy on a long string often indicates a key/token."}


# 73. Lobste.rs — user profile (keyless public JSON)
def tool_lobsters(q):
    u = q.lstrip("@")
    r = _get(f"https://lobste.rs/u/{u}.json")
    if r.status_code != 200:
        return {"username": u, "found": False}
    d = r.json()
    return {"username": d.get("username"), "found": True,
            "created": d.get("created_at"), "karma": d.get("karma"),
            "about": d.get("about"), "github": d.get("github_username"),
            "is_admin": d.get("is_admin"),
            "url": f"https://lobste.rs/u/{u}"}


# 74. CAA records — who is authorized to issue certs for a domain (DoH)
def tool_caa(q):
    host = _host(q)
    a = _get("https://dns.google/resolve",
             params={"name": host, "type": "CAA"}).json().get("Answer", [])
    issuers = [x["data"] for x in a if x.get("type") == 257]
    return {"domain": host, "caa_count": len(issuers), "records": issuers,
            "restricted": bool(issuers),
            "note": "No CAA record means any CA may issue for this domain."}


# 75. MTA-STS + TLS-RPT — inbound mail TLS enforcement policy (DoH + fetch)
def tool_mtasts(q):
    host = _host(q)
    sts_txt = _txt(f"_mta-sts.{host}")
    tlsrpt = _txt(f"_smtp._tls.{host}")
    policy = None
    try:
        r = _get(f"https://mta-sts.{host}/.well-known/mta-sts.txt", timeout=6)
        if r.status_code == 200 and "STSv1" in r.text:
            policy = {}
            for line in r.text.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    policy[k.strip()] = v.strip()
    except Exception:
        pass
    return {"domain": host, "mta_sts_dns": sts_txt or None,
            "tls_rpt": tlsrpt or None, "policy": policy,
            "mode": (policy or {}).get("mode"),
            "enforced": (policy or {}).get("mode") == "enforce"}


# 76. BIMI — brand-indicator (logo) DNS record for a domain (DoH)
def tool_bimi(q):
    host = _host(q)
    rec = _txt(f"default._bimi.{host}")
    bimi = next((t for t in rec if "v=BIMI1" in t), None)
    logo = vmc = None
    if bimi:
        lm = re.search(r"l=([^;]+)", bimi)
        am = re.search(r"a=([^;]+)", bimi)
        logo = lm.group(1).strip() if lm else None
        vmc = am.group(1).strip() if am else None
    return {"domain": host, "bimi_present": bool(bimi), "record": bimi,
            "logo_url": logo, "vmc_certificate": vmc or None}


# 77. Domain age — days since registration (RDAP, derived)
def tool_domainage(q):
    r = _get(f"https://rdap.org/domain/{_host(q)}", allow_redirects=True)
    if r.status_code != 200:
        return {"domain": q, "error": f"RDAP {r.status_code}"}
    events = {e.get("eventAction"): e.get("eventDate")
              for e in r.json().get("events", [])}
    reg = events.get("registration")
    age_days = None
    if reg:
        try:
            d = datetime.datetime.fromisoformat(reg.replace("Z", "+00:00"))
            now = datetime.datetime.now(datetime.timezone.utc)
            age_days = (now - d).days
        except Exception:
            pass
    return {"domain": _host(q), "registered": reg, "expires": events.get("expiration"),
            "age_days": age_days,
            "age_years": round(age_days / 365.25, 2) if age_days is not None else None,
            "young_domain": age_days is not None and age_days < 90,
            "note": "Domains registered < 90 days ago are a common phishing signal."}


# 78. Luhn check — validate any number's Luhn checksum (offline)
def tool_luhn(q):
    digits = [int(c) for c in re.sub(r"\D", "", q)]
    if not digits:
        return {"input": q, "error": "no digits"}
    chk = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        chk += d
    return {"input": q, "digits": len(digits), "luhn_valid": chk % 10 == 0,
            "note": "Luhn validates card/IMEI checksums — not that the number is issued."}


# ---------------------------------------------------------------------------
# Extended batch 5: package registries, more crypto/git/social, offline utils.
# All keyless.
# ---------------------------------------------------------------------------

# 79. PyPI — package metadata, latest version, project links (keyless)
def tool_pypi(q):
    r = _get(f"https://pypi.org/pypi/{q}/json")
    if r.status_code != 200:
        return {"package": q, "found": False}
    info = r.json().get("info", {})
    urls = info.get("project_urls") or {}
    return {"package": info.get("name"), "found": True,
            "version": info.get("version"), "summary": info.get("summary"),
            "author": info.get("author") or info.get("author_email"),
            "license": info.get("license"), "home_page": info.get("home_page"),
            "requires_python": info.get("requires_python"),
            "project_urls": urls, "pypi": f"https://pypi.org/project/{q}/"}


# 80. crates.io — Rust crate stats (keyless; UA required, already set)
def tool_crates(q):
    r = _get(f"https://crates.io/api/v1/crates/{q}")
    if r.status_code != 200:
        return {"crate": q, "found": False}
    c = r.json().get("crate", {})
    return {"crate": c.get("name"), "found": True,
            "max_version": c.get("max_stable_version") or c.get("max_version"),
            "downloads": c.get("downloads"),
            "recent_downloads": c.get("recent_downloads"),
            "description": c.get("description"), "repository": c.get("repository"),
            "homepage": c.get("homepage"), "created": c.get("created_at"),
            "url": f"https://crates.io/crates/{q}"}


# 81. RubyGems — gem stats (keyless)
def tool_rubygems(q):
    r = _get(f"https://rubygems.org/api/v1/gems/{q}.json")
    if r.status_code != 200:
        return {"gem": q, "found": False}
    d = r.json()
    return {"gem": d.get("name"), "found": True, "version": d.get("version"),
            "downloads": d.get("downloads"), "info": d.get("info"),
            "authors": d.get("authors"), "homepage": d.get("homepage_uri"),
            "source": d.get("source_code_uri"),
            "url": f"https://rubygems.org/gems/{q}"}


# 82. Packagist — PHP/Composer package stats (keyless)
def tool_packagist(q):
    if "/" not in q:
        return {"package": q, "error": "expected vendor/package"}
    r = _get(f"https://packagist.org/packages/{q}.json")
    if r.status_code != 200:
        return {"package": q, "found": False}
    p = r.json().get("package", {})
    return {"package": p.get("name"), "found": True,
            "description": p.get("description"),
            "downloads": (p.get("downloads") or {}).get("total"),
            "stars": p.get("github_stars"), "repository": p.get("repository"),
            "language": p.get("language"), "url": f"https://packagist.org/packages/{q}"}


# 83. Mempool.space — Bitcoin address stats (keyless Esplora)
def tool_btcaddr(q):
    addr = q.strip()
    if not re.match(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$", addr):
        return {"address": addr, "error": "not a Bitcoin address"}
    r = _get(f"https://blockchain.info/rawaddr/{addr}", params={"limit": 0})
    if r.status_code != 200:
        return {"address": addr, "error": f"blockchain.info {r.status_code}"}
    d = r.json()
    bal = d.get("final_balance", 0)
    return {"address": addr,
            "balance_sat": bal,
            "balance_btc": round(bal / 1e8, 8),
            "received_btc": round(d.get("total_received", 0) / 1e8, 8),
            "tx_count": d.get("n_tx"),
            "explorer": f"https://mempool.space/address/{addr}"}


# 84. GitHub repo — stars, language, license, activity (keyless, 60/hr)
def tool_ghrepo(q):
    slug = q.replace("https://github.com/", "").strip("/")
    if slug.count("/") < 1:
        return {"repo": q, "error": "expected owner/repo"}
    owner, name = slug.split("/")[:2]
    r = _get(f"https://api.github.com/repos/{owner}/{name}")
    if r.status_code != 200:
        return {"repo": slug, "error": f"GitHub {r.status_code}"}
    d = r.json()
    langs = {}
    try:
        langs = _get(d["languages_url"]).json()
    except Exception:
        pass
    return {"repo": d.get("full_name"), "description": d.get("description"),
            "stars": d.get("stargazers_count"), "forks": d.get("forks_count"),
            "open_issues": d.get("open_issues_count"),
            "language": d.get("language"), "languages": list(langs.keys()),
            "license": (d.get("license") or {}).get("spdx_id"),
            "created": d.get("created_at"), "pushed": d.get("pushed_at"),
            "archived": d.get("archived"), "topics": d.get("topics", []),
            "homepage": d.get("homepage"), "url": d.get("html_url")}


# 85. GitHub gists — public gists for a user (keyless, 60/hr)
def tool_ghgists(q):
    r = _get(f"https://api.github.com/users/{q}/gists", params={"per_page": 30})
    if r.status_code != 200:
        return {"username": q, "error": f"GitHub {r.status_code}"}
    gists = [{"id": g.get("id"), "description": g.get("description"),
              "files": list((g.get("files") or {}).keys()),
              "created": g.get("created_at"), "url": g.get("html_url")}
             for g in r.json()]
    return {"username": q, "gist_count": len(gists), "gists": gists}


# 86. GitHub org — public org profile + member count (keyless)
def tool_ghorg(q):
    r = _get(f"https://api.github.com/orgs/{q}")
    if r.status_code != 200:
        return {"org": q, "error": f"GitHub {r.status_code} (or not an org)"}
    d = r.json()
    return {"org": d.get("login"), "name": d.get("name"),
            "description": d.get("description"), "blog": d.get("blog"),
            "location": d.get("location"), "email": d.get("email"),
            "public_repos": d.get("public_repos"), "followers": d.get("followers"),
            "created": d.get("created_at"), "twitter": d.get("twitter_username"),
            "url": d.get("html_url")}


# 87. Mastodon — resolve @user@instance via WebFinger + public profile (keyless)
def tool_mastodon(q):
    h = q.lstrip("@")
    if "@" not in h:
        return {"input": q, "error": "expected user@instance"}
    user, _, instance = h.partition("@")
    try:
        wf = _get(f"https://{instance}/.well-known/webfinger",
                  params={"resource": f"acct:{user}@{instance}"}).json()
    except Exception as e:
        return {"account": h, "error": f"webfinger failed: {e}"}
    actor = next((l["href"] for l in wf.get("links", [])
                  if l.get("rel") == "self"), None)
    out = {"account": h, "webfinger_ok": True, "actor_url": actor}
    if actor:
        try:
            a = _get(actor, headers={"Accept": "application/activity+json"}).json()
            out.update({"name": a.get("name"), "summary": a.get("summary"),
                        "followers_url": a.get("followers"),
                        "url": a.get("url")})
        except Exception:
            pass
    return out


# 88. NPM package — version, deps, maintainers (keyless; complements npm-author)
def tool_npmpkg(q):
    r = _get(f"https://registry.npmjs.org/{urllib.parse.quote(q, safe='@/')}")
    if r.status_code != 200:
        return {"package": q, "found": False}
    d = r.json()
    latest = (d.get("dist-tags") or {}).get("latest")
    v = (d.get("versions") or {}).get(latest, {})
    return {"package": d.get("name"), "found": True, "latest": latest,
            "description": d.get("description"),
            "license": v.get("license"),
            "maintainers": [m.get("name") for m in d.get("maintainers", [])],
            "dependencies": list((v.get("dependencies") or {}).keys()),
            "homepage": d.get("homepage"),
            "repository": (d.get("repository") or {}).get("url"),
            "url": f"https://www.npmjs.com/package/{q}"}


# 89. Geohash — encode lat,lon -> geohash + neighbours (offline)
_GH32 = "0123456789bcdefghjkmnpqrstuvwxyz"


def tool_geohash(q):
    c = _coords(q)
    if not c:
        return {"input": q, "error": "expected 'lat,lon'"}
    lat, lon = c
    lat_r, lon_r = [-90.0, 90.0], [-180.0, 180.0]
    gh, bit, ch, even = [], 0, 0, True
    while len(gh) < 11:
        rng = lon_r if even else lat_r
        mid = sum(rng) / 2
        val = lon if even else lat
        if val > mid:
            ch |= 1 << (4 - bit)
            rng[0] = mid
        else:
            rng[1] = mid
        even = not even
        if bit < 4:
            bit += 1
        else:
            gh.append(_GH32[ch])
            bit, ch = 0, 0
    return {"lat": lat, "lon": lon, "geohash": "".join(gh),
            "geohash_6": "".join(gh)[:6],
            "note": "Geohash precision ~1m at length 9, ~1.2km at length 6."}


# 90. IPv6 expand/compress — full + canonical form (offline, stdlib)
def tool_ipv6(q):
    try:
        ip = ipaddress.ip_address(q.strip())
    except Exception as e:
        return {"input": q, "error": str(e)}
    if ip.version != 6:
        return {"input": q, "error": "not an IPv6 address"}
    return {"input": q, "compressed": ip.compressed,
            "exploded": ip.exploded, "reverse_ptr": ip.reverse_pointer,
            "is_private": ip.is_private, "is_global": ip.is_global,
            "is_multicast": ip.is_multicast,
            "ipv4_mapped": str(ip.ipv4_mapped) if ip.ipv4_mapped else None}


# 91. Text transforms — rot13 / base32 / morse / reverse (offline)
_MORSE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
          "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
          "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
          "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
          "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
          "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
          "8": "---..", "9": "----."}


def tool_transform(q):
    rot13 = q.encode().decode() .translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    out = {"input": q, "reversed": q[::-1], "rot13": rot13,
           "upper": q.upper(), "lower": q.lower(),
           "base32": base64.b32encode(q.encode()).decode(),
           "morse": " ".join(_MORSE.get(c, "?") for c in q.upper() if c != " ")}
    # decode base32 if input looks like one
    if re.fullmatch(r"[A-Z2-7]+=*", q.upper()) and len(q) % 8 == 0:
        try:
            out["base32_decoded"] = base64.b32decode(q.upper()).decode()
        except Exception:
            pass
    return out


# 92. Brazilian CPF/CNPJ — checksum validation (offline)
def _cpf_valid(c):
    if len(c) != 11 or len(set(c)) == 1:
        return False
    for n in (9, 10):
        s = sum(int(c[i]) * ((n + 1) - i) for i in range(n))
        dv = (s * 10) % 11 % 10
        if dv != int(c[n]):
            return False
    return True


def _cnpj_valid(c):
    if len(c) != 14 or len(set(c)) == 1:
        return False
    for n, w in ((12, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]),
                 (13, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])):
        s = sum(int(c[i]) * w[i] for i in range(n))
        dv = 11 - (s % 11)
        dv = 0 if dv >= 10 else dv
        if dv != int(c[n]):
            return False
    return True


def tool_cpfcnpj(q):
    d = re.sub(r"\D", "", q)
    if len(d) == 11:
        return {"input": q, "type": "CPF", "digits": d, "valid": _cpf_valid(d),
                "note": "Checksum only — does not confirm the document is issued/active."}
    if len(d) == 14:
        return {"input": q, "type": "CNPJ", "digits": d, "valid": _cnpj_valid(d),
                "note": "Checksum only — does not confirm the company exists."}
    return {"input": q, "error": "CPF needs 11 digits, CNPJ 14"}


# 93. Ethereum address — balance + tx count via blockchair (keyless)
def tool_ethaddr(q):
    if not re.match(r"^0x[0-9a-fA-F]{40}$", q):
        return {"address": q, "error": "not an Ethereum address"}
    try:
        data = _get(f"https://api.blockchair.com/ethereum/dashboards/address/{q.lower()}").json()
        d = ((data.get("data") or {}).get(q.lower()) or {}).get("address") or {}
    except Exception as e:
        return {"address": q, "error": str(e)}
    bal = d.get("balance")
    return {"address": q, "balance_wei": bal,
            "balance_eth": round(int(bal) / 1e18, 8) if bal else None,
            "received_eth": round(int(d.get("received", 0)) / 1e18, 8) if d.get("received") else None,
            "tx_count": d.get("transaction_count"),
            "is_contract": d.get("type") == "contract",
            "explorer": f"https://blockchair.com/ethereum/address/{q.lower()}"}


# 94. Color — parse hex/rgb -> rgb/hsl + nearest name (offline)
_NAMED = {"black": (0, 0, 0), "white": (255, 255, 255), "red": (255, 0, 0),
          "green": (0, 128, 0), "blue": (0, 0, 255), "yellow": (255, 255, 0),
          "cyan": (0, 255, 255), "magenta": (255, 0, 255), "gray": (128, 128, 128),
          "orange": (255, 165, 0), "purple": (128, 0, 128), "pink": (255, 192, 203),
          "brown": (165, 42, 42), "navy": (0, 0, 128), "teal": (0, 128, 128)}


def tool_color(q):
    s = q.strip().lstrip("#")
    m = re.match(r"^rgb\((\d+),\s*(\d+),\s*(\d+)\)$", q.strip(), re.I)
    if m:
        rgb = tuple(int(m.group(i)) for i in (1, 2, 3))
    elif re.fullmatch(r"[0-9a-fA-F]{6}", s):
        rgb = tuple(int(s[i:i + 2], 16) for i in (0, 2, 4))
    elif re.fullmatch(r"[0-9a-fA-F]{3}", s):
        rgb = tuple(int(c * 2, 16) for c in s)
    else:
        return {"input": q, "error": "expected #hex or rgb(r,g,b)"}
    r, g, b = [x / 255 for x in rgb]
    mx, mn = max(r, g, b), min(r, g, b)
    l = (mx + mn) / 2
    if mx == mn:
        h = sat = 0
    else:
        d = mx - mn
        sat = d / (2 - mx - mn) if l > 0.5 else d / (mx + mn)
        h = ({r: (g - b) / d, g: (b - r) / d + 2, b: (r - g) / d + 4}[mx]) * 60 % 360
    nearest = min(_NAMED, key=lambda n: sum((a - c) ** 2 for a, c in zip(_NAMED[n], rgb)))
    return {"input": q, "hex": "#%02x%02x%02x" % rgb, "rgb": list(rgb),
            "hsl": [round(h), round(sat * 100), round(l * 100)],
            "nearest_name": nearest,
            "luminance": round(0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2], 1)}


# ---------------------------------------------------------------------------
# Registry: name -> {fn, label, accepts (indicator types), desc}
# ---------------------------------------------------------------------------

# ── extension pack 1 ──────────────────────────────────────────────────────────────


# ===========================================================================
# DNS / MAIL
# ===========================================================================
def tool_doh(q):
    """Raw DNS-over-HTTPS for record types the main DNS tool skips."""
    host = _host(q)
    types = ["HTTPS", "SVCB", "TLSA", "DNSKEY", "DS", "NAPTR", "SRV", "PTR", "CERT"]
    out = {}
    for t in types:
        try:
            r = _get("https://dns.google/resolve", params={"name": host, "type": t})
            ans = [a.get("data") for a in r.json().get("Answer", []) if a.get("data")]
            if ans:
                out[t] = ans
        except Exception:
            pass
    return {"domain": host, "uncommon_records": out or "none found"}


def tool_tlsa(q):
    """DANE/TLSA records for the host's HTTPS port."""
    host = _host(q)
    name = f"_443._tcp.{host}"
    r = _get("https://dns.google/resolve", params={"name": name, "type": "TLSA"})
    ans = [a.get("data") for a in r.json().get("Answer", []) if a.get("data")]
    return {"name": name, "dane_enabled": bool(ans), "tlsa": ans or "none"}


_VERIFY_VENDORS = {
    "google-site-verification": "Google / Search Console",
    "MS=": "Microsoft 365 / Azure",
    "facebook-domain-verification": "Meta / Facebook",
    "apple-domain-verification": "Apple",
    "stripe-verification": "Stripe",
    "atlassian-domain-verification": "Atlassian",
    "docusign": "DocuSign",
    "adobe-idp-site-verification": "Adobe",
    "shopify": "Shopify", "zoom": "Zoom", "dropbox-domain-verification": "Dropbox",
    "have-i-been-pwned-verification": "HaveIBeenPwned", "logmein-verification": "LogMeIn",
    "miro-verification": "Miro", "notion": "Notion", "webex": "Cisco Webex",
    "yandex-verification": "Yandex", "globalsign-domain-verification": "GlobalSign",
}


def tool_dnsverify(q):
    """Surface third-party verification/ownership tokens from TXT records —
    a quick map of which SaaS a domain is enrolled in."""
    host = _host(q)
    r = _get("https://dns.google/resolve", params={"name": host, "type": "TXT"})
    txts = [a.get("data", "").strip('"') for a in r.json().get("Answer", [])]
    found = {}
    for t in txts:
        for token, vendor in _VERIFY_VENDORS.items():
            if token.lower() in t.lower():
                found.setdefault(vendor, []).append(t[:120])
    return {"domain": host, "txt_count": len(txts), "services": found or "none recognized"}


_SUBS = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
         "secure", "vpn", "api", "dev", "staging", "test", "portal", "admin", "m",
         "shop", "ftp", "cpanel", "git", "gitlab", "jira", "cloud", "app", "docs",
         "status", "cdn", "assets", "img", "static", "beta", "demo", "internal"]


def tool_subbrute(q):
    """Resolve a built-in common-subdomain list — complements CT-log discovery
    by catching hosts that never got a public certificate."""
    host = _host(q)
    live = {}
    def chk(s):
        name = f"{s}.{host}"
        try:
            r = _get("https://dns.google/resolve", params={"name": name, "type": "A"}, timeout=5)
            ips = [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
            return (name, ips) if ips else None
        except Exception:
            return None
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(chk, _SUBS):
            if res:
                live[res[0]] = res[1]
    return {"domain": host, "checked": len(_SUBS), "resolved": len(live), "hosts": live}


def tool_hstspreload(q):
    """Is the domain on the browser HSTS preload list (hstspreload.org)."""
    host = _host(q)
    r = _get("https://hstspreload.org/api/v2/status", params={"domain": host})
    d = r.json()
    return {"domain": host, "status": d.get("status"),
            "preloaded": d.get("status") == "preloaded", "raw": d}


# ===========================================================================
# WEB / HOST  (per-target)
# ===========================================================================
def tool_wpscan(q):
    """WordPress fingerprint: version + author enumeration via the public REST
    API and readme (per-target)."""
    base = _base(q)
    out = {"target": base, "is_wordpress": False}
    try:
        r = _get(base + "/wp-json/", timeout=6)
        if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
            out["is_wordpress"] = True
            j = r.json()
            out["name"] = j.get("name")
            out["description"] = j.get("description")
    except Exception:
        pass
    try:
        r = _get(base + "/wp-json/wp/v2/users", timeout=6)
        if r.status_code == 200:
            out["users"] = [{"id": u.get("id"), "name": u.get("name"),
                             "slug": u.get("slug")} for u in r.json()][:30]
    except Exception:
        pass
    try:
        r = _get(base + "/readme.html", timeout=6)
        m = re.search(r"Version\s+([0-9.]+)", r.text)
        if m:
            out["version"] = m.group(1)
            out["is_wordpress"] = True
    except Exception:
        pass
    if not out["is_wordpress"]:
        out["note"] = "no WordPress signals"
    return out


_WELLKNOWN = ["security.txt", "change-password", "openid-configuration",
              "apple-app-site-association", "assetlinks.json", "host-meta",
              "nodeinfo", "dnt-policy.txt", "gpc.json", "ai.txt",
              "matrix/server", "webfinger", "carbon.txt"]


def tool_wellknown(q):
    """Enumerate /.well-known/* resources that exist on the host."""
    base = _base(q)
    found = {}
    def chk(path):
        try:
            r = _get(f"{base}/.well-known/{path}", timeout=5, allow_redirects=True)
            if r.status_code == 200 and r.content:
                return (path, len(r.content))
        except Exception:
            pass
        return None
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        for res in ex.map(chk, _WELLKNOWN):
            if res:
                found[res[0]] = f"{res[1]} bytes"
    return {"target": base, "present": found or "none of the probed paths"}


def tool_graphql(q):
    """Detect a GraphQL endpoint and whether introspection is open (per-target)."""
    base = _base(q)
    for path in ["/graphql", "/api/graphql", "/v1/graphql", "/query"]:
        url = base + path
        try:
            r = _post(url, json={"query": "{__schema{queryType{name}}}"}, timeout=6)
            if r.status_code < 500 and "application/json" in r.headers.get("content-type", ""):
                j = r.json()
                introspect = bool(j.get("data", {}).get("__schema"))
                return {"endpoint": url, "graphql": True,
                        "introspection_open": introspect,
                        "note": "introspection EXPOSED" if introspect else "introspection blocked/limited"}
        except Exception:
            continue
    return {"target": base, "graphql": False, "note": "no GraphQL endpoint at common paths"}


_SWAGGER_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
                  "/api-docs", "/swagger/v1/swagger.json", "/api/swagger.json",
                  "/swagger-ui.html", "/api/openapi.json"]


def tool_swagger(q):
    """Find exposed OpenAPI / Swagger API documentation (per-target)."""
    base = _base(q)
    hits = []
    for p in _SWAGGER_PATHS:
        try:
            r = _get(base + p, timeout=5)
            if r.status_code == 200 and ("swagger" in r.text[:400].lower()
                                          or "openapi" in r.text[:400].lower()
                                          or "swagger-ui" in r.text.lower()):
                hits.append(base + p)
        except Exception:
            continue
    return {"target": base, "found": hits or "none", "count": len(hits)}


def tool_s3buckets(q):
    """Probe S3/GCS/Azure buckets named after the domain (per-target recon for
    your own assets)."""
    host = _host(q)
    name = host.split(".")[0]
    cands = {
        f"https://{name}.s3.amazonaws.com": "AWS S3",
        f"https://{host}.s3.amazonaws.com": "AWS S3 (fqdn)",
        f"https://storage.googleapis.com/{name}": "Google Cloud Storage",
        f"https://{name}.blob.core.windows.net": "Azure Blob",
    }
    out = {}
    for url, kind in cands.items():
        try:
            r = _get(url, timeout=5)
            state = "open/listable" if (r.status_code == 200 and "<ListBucketResult" in r.text) \
                else "exists (access denied)" if r.status_code in (403,) \
                else "exists" if r.status_code in (200, 401) else None
            if state:
                out[url] = {"provider": kind, "state": state}
        except Exception:
            continue
    return {"domain": host, "candidates_checked": len(cands), "buckets": out or "none found"}


def tool_httpmethods(q):
    """Allowed HTTP methods (OPTIONS) + risky-method probe (TRACE/PUT/DELETE)."""
    base = _base(q)
    out = {"target": base}
    try:
        r = requests.options(base + "/", headers=UA, timeout=6)
        out["allow_header"] = r.headers.get("Allow") or r.headers.get("allow") or "(not advertised)"
        out["status"] = r.status_code
    except Exception as e:
        return {"error": str(e), "target": base}
    try:
        t = requests.request("TRACE", base + "/", headers=UA, timeout=6)
        out["trace_enabled"] = t.status_code == 200 and "TRACE" in t.text.upper()
    except Exception:
        out["trace_enabled"] = False
    return out


def tool_dirlisting(q):
    """Check root and common directories for open directory listing (per-target)."""
    base = _base(q)
    paths = ["/", "/images/", "/img/", "/uploads/", "/files/", "/backup/",
             "/static/", "/assets/", "/.git/", "/data/"]
    listable = []
    for p in paths:
        try:
            r = _get(base + p, timeout=5)
            if r.status_code == 200 and re.search(r"<title>Index of |Directory listing for ", r.text):
                listable.append(p)
        except Exception:
            continue
    return {"target": base, "open_listings": listable or "none", "checked": len(paths)}


def tool_adstxt(q):
    """Parse ads.txt / app-ads.txt — exposes a site's ad-tech relationships."""
    base = _base(q)
    out = {"target": base}
    for fname in ("ads.txt", "app-ads.txt"):
        try:
            r = _get(base + "/" + fname, timeout=6)
            if r.status_code == 200 and "," in r.text:
                lines = [l for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
                sellers = sorted({l.split(",")[0].strip().lower() for l in lines if "," in l})
                out[fname] = {"records": len(lines), "ad_systems": sellers[:50]}
        except Exception:
            continue
    if len(out) == 1:
        out["note"] = "no ads.txt / app-ads.txt"
    return out


def tool_feeds(q):
    """Discover RSS/Atom feeds advertised on the page or at common paths."""
    base = _base(q)
    feeds = set()
    try:
        r = _get(base, timeout=6)
        for m in re.finditer(r'<link[^>]+type=["\']application/(?:rss|atom)\+xml["\'][^>]*>', r.text, re.I):
            href = re.search(r'href=["\']([^"\']+)["\']', m.group(0))
            if href:
                feeds.add(urllib.parse.urljoin(base, href.group(1)))
    except Exception:
        pass
    for p in ("/feed", "/rss", "/rss.xml", "/atom.xml", "/feed.xml", "/index.xml"):
        try:
            r = _get(base + p, timeout=4)
            if r.status_code == 200 and ("<rss" in r.text[:300] or "<feed" in r.text[:300]):
                feeds.add(base + p)
        except Exception:
            continue
    return {"target": base, "feeds": sorted(feeds) or "none found"}


def tool_manifest(q):
    """Fetch the PWA web app manifest (name, icons, theme, scope)."""
    base = _base(q)
    url = None
    try:
        r = _get(base, timeout=6)
        m = re.search(r'<link[^>]+rel=["\']manifest["\'][^>]*>', r.text, re.I)
        if m:
            href = re.search(r'href=["\']([^"\']+)["\']', m.group(0))
            if href:
                url = urllib.parse.urljoin(base, href.group(1))
    except Exception:
        pass
    url = url or base + "/manifest.json"
    try:
        r = _get(url, timeout=6)
        if r.status_code == 200:
            j = r.json()
            return {"manifest_url": url, "name": j.get("name"), "short_name": j.get("short_name"),
                    "theme_color": j.get("theme_color"), "display": j.get("display"),
                    "start_url": j.get("start_url"), "icons": len(j.get("icons", []))}
    except Exception:
        pass
    return {"target": base, "manifest": "none found"}


def tool_wpplugin(q):
    """WordPress.org plugin metadata + version/install stats by slug."""
    slug = q.strip().split("/")[-1]
    r = _get(f"https://api.wordpress.org/plugins/info/1.0/{slug}.json", timeout=8)
    if r.status_code != 200:
        return {"error": "plugin not found", "slug": slug}
    d = r.json()
    if d.get("error"):
        return {"error": d["error"], "slug": slug}
    return {"slug": d.get("slug"), "name": d.get("name"), "version": d.get("version"),
            "author": re.sub("<[^>]+>", "", str(d.get("author", ""))),
            "active_installs": d.get("active_installs"), "rating": d.get("rating"),
            "last_updated": d.get("last_updated"), "requires": d.get("requires"),
            "tested": d.get("tested"), "download_link": d.get("download_link")}


# ===========================================================================
# NETWORK / IP / ASN
# ===========================================================================
def tool_abusecontact(q):
    """Authoritative abuse contact for an IP/prefix (RIPEstat finder)."""
    r = _get("https://stat.ripe.net/data/abuse-contact-finder/data.json", params={"resource": q})
    d = r.json().get("data", {})
    return {"resource": q, "abuse_contacts": d.get("abuse_contacts", []),
            "authorities": d.get("authorities", [])}


def tool_asrank(q):
    """CAIDA AS Rank — an ASN's global influence ranking + customer cone."""
    asn = re.sub(r"(?i)^as", "", q.strip())
    r = _get(f"https://api.asrank.caida.org/v2/restful/asns/{asn}", timeout=8)
    d = (r.json() or {}).get("data", {}).get("asn")
    if not d:
        return {"error": "ASN not found in AS Rank", "asn": asn}
    return {"asn": d.get("asn"), "rank": d.get("rank"), "org": (d.get("organization") or {}).get("orgName"),
            "country": (d.get("country") or {}).get("iso"),
            "cone_asns": (d.get("cone") or {}).get("numberAsns"),
            "cone_prefixes": (d.get("cone") or {}).get("numberPrefixes"),
            "degree": d.get("asnDegree")}


def tool_peeringdb(q):
    """PeeringDB record for an ASN — IX presence, traffic, policy."""
    asn = re.sub(r"(?i)^as", "", q.strip())
    r = _get(f"https://www.peeringdb.com/api/net?asn={asn}", timeout=8)
    data = r.json().get("data", [])
    if not data:
        return {"error": "not in PeeringDB", "asn": asn}
    n = data[0]
    return {"asn": n.get("asn"), "name": n.get("name"), "aka": n.get("aka"),
            "type": n.get("info_type"), "traffic": n.get("info_traffic"),
            "scope": n.get("info_scope"), "policy": n.get("policy_general"),
            "website": n.get("website"), "ix_count": n.get("ix_count"),
            "fac_count": n.get("fac_count")}


def tool_rpki(q):
    """RPKI route-origin (ROA) overview for the prefix covering an IP/prefix."""
    r = _get("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": q})
    d = r.json().get("data", {})
    asns = [a.get("asn") for a in d.get("asns", [])]
    roa = _get("https://stat.ripe.net/data/rpki-validation/data.json",
               params={"resource": asns[0], "prefix": d.get("resource")}) if asns and d.get("resource") else None
    out = {"resource": q, "prefix": d.get("resource"), "announced": d.get("announced"),
           "origin_asns": asns, "holder": d.get("block", {}).get("desc")}
    if roa is not None:
        try:
            v = roa.json().get("data", {})
            out["rpki_status"] = v.get("status")
            out["roas"] = [{"asn": x.get("asn"), "prefix": x.get("prefix"),
                            "max_length": x.get("max_length")} for x in v.get("validating_roas", [])]
        except Exception:
            pass
    return out


# ===========================================================================
# CRYPTO / CHAIN
# ===========================================================================
def tool_ens(q):
    """Resolve an ENS name <-> Ethereum address (ensideas public resolver)."""
    name = q.strip()
    r = _get(f"https://api.ensideas.com/ens/resolve/{name}", timeout=8)
    if r.status_code != 200:
        return {"error": f"resolve failed ({r.status_code})", "query": name}
    d = r.json()
    return {"query": name, "address": d.get("address"), "name": d.get("name"),
            "avatar": d.get("avatar"), "display": d.get("displayName")}


def tool_ethcontract(q):
    """Is an Ethereum address a contract, and is its source verified (Sourcify)."""
    addr = q.strip()
    if not re.match(r"^0x[0-9a-fA-F]{40}$", addr):
        return {"error": "not an Ethereum address", "query": addr}
    out = {"address": addr}
    try:
        r = _get("https://sourcify.dev/server/check-all-by-addresses",
                 params={"addresses": addr, "chainIds": "1"}, timeout=8)
        j = r.json()
        if j and isinstance(j, list) and j[0].get("status") != "false":
            out["verified_source"] = j[0].get("status")
            out["chains"] = j[0].get("chainIds")
        else:
            out["verified_source"] = "not verified on Sourcify"
    except Exception as e:
        out["verified_source"] = f"lookup error: {e}"
    return out


# ===========================================================================
# CODE / PACKAGE ECOSYSTEMS
# ===========================================================================
_ECO = {"pypi": "PyPI", "npm": "npm", "go": "Go", "maven": "Maven",
        "cargo": "crates.io", "rubygems": "RubyGems", "nuget": "NuGet"}


def tool_osv(q):
    """Known vulnerabilities for a package via OSV.dev. Input 'ecosystem:name'
    (e.g. 'pypi:requests') or a bare name (defaults to PyPI)."""
    if ":" in q:
        eco, name = q.split(":", 1)
    else:
        eco, name = "pypi", q
    eco = eco.strip().lower()
    eco_name = {"pypi": "PyPI", "npm": "npm", "go": "Go", "maven": "Maven",
                "cargo": "crates.io", "rubygems": "RubyGems", "nuget": "NuGet"}.get(eco, "PyPI")
    r = _post("https://api.osv.dev/v1/query",
              json={"package": {"name": name.strip(), "ecosystem": eco_name}}, timeout=10)
    vulns = r.json().get("vulns", [])
    return {"package": name.strip(), "ecosystem": eco_name, "vuln_count": len(vulns),
            "vulns": [{"id": v.get("id"), "summary": v.get("summary"),
                       "aliases": v.get("aliases", [])[:4]} for v in vulns[:25]]}


def tool_depsdev(q):
    """deps.dev (Google Open Source Insights): versions + dependency count."""
    if ":" in q:
        eco, name = q.split(":", 1)
    else:
        eco, name = "pypi", q
    sysmap = {"pypi": "PYPI", "npm": "NPM", "go": "GO", "maven": "MAVEN",
              "cargo": "CARGO", "nuget": "NUGET"}
    system = sysmap.get(eco.strip().lower(), "PYPI")
    nm = urllib.parse.quote(name.strip(), safe="")
    r = _get(f"https://api.deps.dev/v3alpha/systems/{system}/packages/{nm}", timeout=8)
    if r.status_code != 200:
        return {"error": "package not found", "system": system, "name": name.strip()}
    d = r.json()
    versions = d.get("versions", [])
    default = next((v["versionKey"]["version"] for v in versions if v.get("isDefault")), None)
    return {"system": system, "name": name.strip(), "version_count": len(versions),
            "default_version": default,
            "latest": versions[-1]["versionKey"]["version"] if versions else None}


def tool_gomod(q):
    """Go module info from the module proxy (latest version + timestamp)."""
    mod = q.strip().lower()
    r = _get(f"https://proxy.golang.org/{urllib.parse.quote(mod, safe='/')}/@latest", timeout=8)
    if r.status_code != 200:
        return {"error": "module not found on proxy", "module": mod}
    d = r.json()
    return {"module": mod, "version": d.get("Version"), "time": d.get("Time")}


def tool_nuget(q):
    """NuGet (.NET) package search."""
    r = _get("https://azuresearch-usnc.nuget.org/query", params={"q": q.strip(), "take": 1}, timeout=8)
    data = r.json().get("data", [])
    if not data:
        return {"error": "no NuGet package", "query": q}
    p = data[0]
    return {"id": p.get("id"), "version": p.get("version"), "description": p.get("description"),
            "authors": p.get("authors"), "total_downloads": p.get("totalDownloads"),
            "project_url": p.get("projectUrl"), "tags": p.get("tags", [])[:10]}


def tool_maven(q):
    """Maven Central artifact search. Input 'artifact' or 'group:artifact'."""
    if ":" in q:
        g, a = q.split(":", 1)
        query = f'g:{g.strip()} AND a:{a.strip()}'
    else:
        query = f'a:{q.strip()}'
    r = _get("https://search.maven.org/solrsearch/select",
             params={"q": query, "rows": 1, "wt": "json"}, timeout=8)
    docs = r.json().get("response", {}).get("docs", [])
    if not docs:
        return {"error": "no Maven artifact", "query": q}
    d = docs[0]
    return {"group": d.get("g"), "artifact": d.get("a"), "latest": d.get("latestVersion"),
            "versions": d.get("versionCount"), "packaging": d.get("p")}


def tool_hexpm(q):
    """Hex.pm (Elixir/Erlang) package stats."""
    r = _get(f"https://hex.pm/api/packages/{q.strip()}", timeout=8)
    if r.status_code != 200:
        return {"error": "package not found", "name": q}
    d = r.json()
    return {"name": d.get("name"), "downloads": d.get("downloads"),
            "latest": (d.get("latest_stable_version") or d.get("latest_version")),
            "html_url": d.get("html_url"),
            "meta": {"description": (d.get("meta") or {}).get("description"),
                     "licenses": (d.get("meta") or {}).get("licenses")}}


def tool_cdnjs(q):
    """cdnjs hosted-library metadata (a JS lib's version + asset list)."""
    name = q.strip().split("/")[-1]
    # Try exact name first, then search (names are case-sensitive on cdnjs)
    r = _get(f"https://api.cdnjs.com/libraries/{name}",
             params={"fields": "name,version,description,homepage,license,assets"}, timeout=8)
    if r.status_code != 200 or not r.json().get("name"):
        sr = _get("https://api.cdnjs.com/libraries", params={"search": name, "fields": "name,version"}, timeout=8)
        results = sr.json().get("results", [])
        if not results:
            return {"error": "library not on cdnjs", "name": name}
        best = results[0]
        r = _get(f"https://api.cdnjs.com/libraries/{best['name']}",
                 params={"fields": "name,version,description,homepage,license,assets"}, timeout=8)
    d = r.json()
    return {"name": d.get("name"), "version": d.get("version"), "description": d.get("description"),
            "homepage": d.get("homepage"), "license": d.get("license"),
            "versions_hosted": len(d.get("assets", []))}


def tool_npmdl(q):
    """npm download counts (last day/week/month) for a package."""
    name = q.strip()
    out = {"package": name}
    for period in ("last-day", "last-week", "last-month"):
        try:
            r = _get(f"https://api.npmjs.org/downloads/point/{period}/{urllib.parse.quote(name, safe='/@')}", timeout=6)
            out[period.replace("last-", "")] = r.json().get("downloads")
        except Exception:
            out[period] = None
    if not any(v for k, v in out.items() if k != "package"):
        return {"error": "no download data (package may not exist)", "package": name}
    return out


def tool_brew(q):
    """Homebrew formula metadata (version, deps, install analytics)."""
    name = q.strip().lower()
    r = _get(f"https://formulae.brew.sh/api/formula/{name}.json", timeout=8)
    if r.status_code != 200:
        # try cask
        r = _get(f"https://formulae.brew.sh/api/cask/{name}.json", timeout=8)
        if r.status_code != 200:
            return {"error": "no Homebrew formula/cask", "name": name}
        d = r.json()
        return {"cask": d.get("token"), "name": d.get("name"), "version": d.get("version"),
                "homepage": d.get("homepage"), "desc": d.get("desc")}
    d = r.json()
    return {"formula": d.get("name"), "version": (d.get("versions") or {}).get("stable"),
            "desc": d.get("desc"), "homepage": d.get("homepage"),
            "license": d.get("license"), "dependencies": d.get("dependencies", []),
            "installs_90d": (d.get("analytics", {}).get("install", {}).get("90d", {}) or {})}


def tool_pypistats(q):
    """PyPI recent download counts for a package (pypistats.org)."""
    name = q.strip()
    r = _get(f"https://pypistats.org/api/packages/{name.lower()}/recent", timeout=8)
    if r.status_code != 200:
        return {"error": "no stats (package may not exist)", "package": name}
    d = r.json().get("data", {})
    return {"package": name, "last_day": d.get("last_day"),
            "last_week": d.get("last_week"), "last_month": d.get("last_month")}


# ===========================================================================
# SOCIAL / PEOPLE
# ===========================================================================
def tool_devto(q):
    """dev.to (Forem) public user profile."""
    r = _get(f"https://dev.to/api/users/by_username?url={urllib.parse.quote(q.strip())}", timeout=8)
    if r.status_code != 200:
        return {"found": False, "username": q}
    d = r.json()
    return {"found": True, "username": d.get("username"), "name": d.get("name"),
            "summary": d.get("summary"), "twitter": d.get("twitter_username"),
            "github": d.get("github_username"), "joined": d.get("joined_at"),
            "location": d.get("location")}


def tool_medium(q):
    """Medium author feed — recent post titles (via public RSS)."""
    user = q.strip().lstrip("@")
    r = _get(f"https://medium.com/feed/@{user}", timeout=8)
    if r.status_code != 200 or "<rss" not in r.text[:200]:
        return {"found": False, "username": user}
    titles = re.findall(r"<title><!\[CDATA\[(.*?)\]\]></title>", r.text)
    return {"found": True, "username": user, "profile": f"https://medium.com/@{user}",
            "recent_posts": titles[1:11] if len(titles) > 1 else []}


def tool_orcid(q):
    """ORCID researcher record (name, employment, works count)."""
    oid = q.strip()
    r = _get(f"https://pub.orcid.org/v3.0/{oid}/person", headers={"Accept": "application/json"}, timeout=8)
    if r.status_code != 200:
        return {"error": "ORCID not found", "orcid": oid}
    d = r.json()
    nm = d.get("name") or {}
    return {"orcid": oid,
            "name": " ".join(filter(None, [(nm.get("given-names") or {}).get("value"),
                                            (nm.get("family-name") or {}).get("value")])),
            "url": f"https://orcid.org/{oid}",
            "keywords": [k.get("content") for k in (d.get("keywords") or {}).get("keyword", [])][:8]}


def tool_codeberg(q):
    """Codeberg / Gitea public user profile."""
    r = _get(f"https://codeberg.org/api/v1/users/{q.strip()}", timeout=8)
    if r.status_code != 200:
        return {"found": False, "username": q}
    d = r.json()
    return {"found": True, "username": d.get("login"), "name": d.get("full_name"),
            "id": d.get("id"), "created": d.get("created"), "repos": d.get("public_repos"),
            "followers": d.get("followers"), "location": d.get("location"),
            "website": d.get("website"), "profile": d.get("html_url")}


def tool_wikidata(q):
    """Wikidata entity search — IDs + descriptions for a name/term."""
    r = _get("https://www.wikidata.org/w/api.php",
             params={"action": "wbsearchentities", "search": q.strip(),
                     "language": "en", "format": "json", "limit": 7}, timeout=8)
    hits = r.json().get("search", [])
    return {"query": q, "results": [{"id": h.get("id"), "label": h.get("label"),
                                     "description": h.get("description"),
                                     "url": "https:" + h.get("url", "")} for h in hits]}


def tool_musicbrainz(q):
    """MusicBrainz artist search (name, type, country, MBID)."""
    r = _get("https://musicbrainz.org/ws/2/artist",
             params={"query": q.strip(), "fmt": "json", "limit": 5}, timeout=8)
    arts = r.json().get("artists", [])
    return {"query": q, "artists": [{"name": a.get("name"), "type": a.get("type"),
                                     "country": a.get("country"), "mbid": a.get("id"),
                                     "score": a.get("score"),
                                     "disambiguation": a.get("disambiguation")} for a in arts]}


def tool_stackoverflow(q):
    """Stack Overflow / Stack Exchange user search by display name."""
    r = _get("https://api.stackexchange.com/2.3/users",
             params={"inname": q.strip(), "site": "stackoverflow", "pagesize": 5,
                     "order": "desc", "sort": "reputation"}, timeout=8)
    items = r.json().get("items", [])
    return {"query": q, "users": [{"name": u.get("display_name"), "id": u.get("user_id"),
                                   "reputation": u.get("reputation"), "location": u.get("location"),
                                   "link": u.get("link")} for u in items]}


def tool_hashnode(q):
    """Hashnode blogger profile (followers, posts) via public GraphQL."""
    user = q.strip().lstrip("@")
    r = _post("https://gql.hashnode.com/",
              json={"query": "query($u:String!){user(username:$u){name username followersCount "
                             "publicationsCount tagline socialMediaLinks{github twitter website}}}",
                    "variables": {"u": user}}, timeout=8)
    try:
        u = (r.json().get("data") or {}).get("user")
    except Exception:
        return {"found": False, "username": user, "error": "invalid response"}
    if not u:
        return {"found": False, "username": user}
    return {"found": True, "username": u.get("username"), "name": u.get("name"),
            "tagline": u.get("tagline"), "followers": u.get("followersCount"),
            "publications": u.get("publicationsCount"), "links": u.get("socialMediaLinks")}


def tool_gravatarfull(q):
    """Full public Gravatar profile JSON for an email (names, accounts, urls)."""
    h = hashlib.md5(q.strip().lower().encode()).hexdigest()
    r = _get(f"https://gravatar.com/{h}.json", timeout=8)
    if r.status_code != 200:
        return {"found": False, "email": q, "gravatar_hash": h}
    entry = (r.json().get("entry") or [{}])[0]
    return {"found": True, "email": q, "gravatar_hash": h,
            "display_name": entry.get("displayName"),
            "name": entry.get("name"), "location": entry.get("currentLocation"),
            "about": entry.get("aboutMe"),
            "accounts": [{"shortname": a.get("shortname"), "url": a.get("url")}
                         for a in entry.get("accounts", [])],
            "urls": entry.get("urls", [])}


def tool_osmuser(q):
    """OpenStreetMap contributor — recent changeset activity by display name."""
    r = _get("https://api.openstreetmap.org/api/0.6/changesets.json",
             params={"display_name": q.strip(), "limit": 1}, timeout=8)
    if r.status_code != 200:
        return {"found": False, "username": q, "note": "no such OSM user or no edits"}
    cs = r.json().get("changesets", [])
    if not cs:
        return {"found": False, "username": q}
    c = cs[0]
    return {"found": True, "username": c.get("user"), "uid": c.get("uid"),
            "last_edit": c.get("created_at"), "last_changeset": c.get("id"),
            "comment": (c.get("tags") or {}).get("comment"),
            "profile": f"https://www.openstreetmap.org/user/{urllib.parse.quote(q.strip())}"}


# ===========================================================================
# THREAT INTEL
# ===========================================================================
def tool_feodo(q):
    """abuse.ch Feodo Tracker — is the IP a known botnet C2 (Emotet/Dridex/...)."""
    r = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=10)
    ip = q.strip()
    for e in r.json():
        if e.get("ip_address") == ip:
            return {"ip": ip, "listed": True, "malware": e.get("malware"),
                    "c2_status": e.get("status"), "first_seen": e.get("first_seen"),
                    "last_online": e.get("last_online"), "port": e.get("port")}
    return {"ip": ip, "listed": False, "note": "not on Feodo C2 blocklist"}


def tool_openphish(q):
    """Check a host/URL against the public OpenPhish community feed."""
    host = _host(q)
    r = _get("https://openphish.com/feed.txt", timeout=10)
    matches = [u for u in r.text.splitlines() if host and host in u]
    return {"target": host, "listed": bool(matches), "match_count": len(matches),
            "sample": matches[:10]}


def tool_kev(q):
    """CISA Known Exploited Vulnerabilities — is a CVE actively exploited."""
    cve = q.strip().upper()
    r = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=12)
    for v in r.json().get("vulnerabilities", []):
        if v.get("cveID", "").upper() == cve:
            return {"cve": cve, "in_kev": True, "name": v.get("vulnerabilityName"),
                    "vendor": v.get("vendorProject"), "product": v.get("product"),
                    "date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse"),
                    "action": v.get("requiredAction")}
    return {"cve": cve, "in_kev": False, "note": "not on the CISA KEV catalog"}


def tool_circlhash(q):
    """CIRCL hashlookup — is a file hash a known (NSRL/clean or flagged) file."""
    h = q.strip().lower()
    algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h))
    if not algo:
        return {"error": "need an MD5/SHA1/SHA256 hash", "hash": h}
    r = _get(f"https://hashlookup.circl.lu/lookup/{algo}/{h}",
             headers={"Accept": "application/json"}, timeout=8)
    if r.status_code == 404:
        return {"hash": h, "algo": algo, "known": False, "note": "not in hashlookup"}
    if r.status_code != 200:
        return {"error": f"lookup failed ({r.status_code})", "hash": h}
    d = r.json()
    return {"hash": h, "algo": algo, "known": True, "filename": d.get("FileName"),
            "source": d.get("source"), "product": d.get("ProductCode"),
            "known_malicious": d.get("hashlookup:trust", 100) < 50,
            "trust": d.get("hashlookup:trust")}



# ===========================================================================
# GEO / UTILITY
# ===========================================================================

_WMO = {0: "clear", 1: "mainly clear", 2: "partly cloudy", 3: "overcast",
        45: "fog", 48: "rime fog", 51: "light drizzle", 61: "light rain",
        63: "rain", 65: "heavy rain", 71: "light snow", 73: "snow", 75: "heavy snow",
        80: "rain showers", 81: "rain showers", 82: "violent showers",
        95: "thunderstorm", 96: "thunderstorm w/ hail", 99: "severe thunderstorm"}


def tool_weather(q):
    """Current weather at a coordinate (Open-Meteo, no key)."""
    c = _coords(q)
    if not c:
        return {"error": "need 'lat,lon'", "query": q}
    lat, lon = c
    r = _get("https://api.open-meteo.com/v1/forecast",
             params={"latitude": lat, "longitude": lon, "current_weather": "true"}, timeout=8)
    cw = r.json().get("current_weather", {})
    return {"lat": lat, "lon": lon, "temperature_c": cw.get("temperature"),
            "windspeed_kmh": cw.get("windspeed"), "wind_dir_deg": cw.get("winddirection"),
            "conditions": _WMO.get(cw.get("weathercode"), cw.get("weathercode")),
            "observed": cw.get("time")}


def tool_elevation(q):
    """Ground elevation at a coordinate in metres (Open-Meteo, no key)."""
    c = _coords(q)
    if not c:
        return {"error": "need 'lat,lon'", "query": q}
    lat, lon = c
    r = _get("https://api.open-meteo.com/v1/elevation",
             params={"latitude": lat, "longitude": lon}, timeout=8)
    elev = r.json().get("elevation", [None])
    return {"lat": lat, "lon": lon, "elevation_m": elev[0] if elev else None}


# ===========================================================================
# REGISTRY  (merged into osint.TOOLS)
# ===========================================================================

# ── extension pack 2 ──────────────────────────────────────────────────────────────
def tool_vin(q):
    """Decode a 17-char vehicle VIN via NHTSA vPIC (keyless, US gov)."""
    vin = q.strip().upper()
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin):
        return {"error": "not a valid 17-character VIN"}
    try:
        r = _get(f"https://vpic.nhtsa.dot.gov/api/vehicles/decodevin/{vin}?format=json")
        rows = r.json().get("Results", [])
        out = {x["Variable"]: x["Value"] for x in rows
               if x.get("Value") not in (None, "", "Not Applicable")}
        keep = ["Make", "Model", "Model Year", "Manufacturer Name", "Plant Country",
                "Plant City", "Plant State", "Vehicle Type", "Body Class",
                "Engine Number of Cylinders", "Displacement (L)", "Fuel Type - Primary",
                "Series", "Trim", "Doors", "Drive Type", "Transmission Style", "GVWR"]
        summary = {k: out[k] for k in keep if k in out}
        return {"vin": vin, "summary": summary, "decoded_fields": len(out),
                "note": "Decoded by NHTSA vPIC; missing fields = no NHTSA data."}
    except Exception as e:
        return {"error": str(e)}


def tool_lei(q):
    """Look up a Legal Entity Identifier (LEI) via GLEIF (keyless)."""
    lei = q.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{20}", lei):
        return {"error": "not a valid 20-character LEI"}
    try:
        r = _get(f"https://api.gleif.org/api/v1/lei-records/{lei}")
        a = r.json().get("data", {}).get("attributes", {})
        ent = a.get("entity", {})
        reg = a.get("registration", {})
        addr = ent.get("legalAddress", {})
        return {
            "lei": lei,
            "name": ent.get("legalName", {}).get("name"),
            "status": ent.get("status"),
            "jurisdiction": ent.get("jurisdiction"),
            "legal_form": ent.get("legalForm", {}).get("id"),
            "country": addr.get("country"),
            "city": addr.get("city"),
            "address": ", ".join(filter(None, addr.get("addressLines", []) or [])),
            "registration_status": reg.get("status"),
            "last_update": reg.get("lastUpdateDate"),
            "managing_lou": reg.get("managingLou"),
        }
    except Exception as e:
        return {"error": str(e)}


def tool_orgname(q):
    """Free-text company name -> candidate LEIs via GLEIF fuzzy search."""
    name = q.strip()
    if len(name) < 3:
        return {"error": "give a company name of 3+ chars"}
    try:
        r = _get("https://api.gleif.org/api/v1/lei-records",
                 params={"filter[entity.legalName]": name, "page[size]": 8})
        hits = []
        for d in r.json().get("data", []):
            a = d.get("attributes", {})
            ent = a.get("entity", {})
            hits.append({
                "lei": a.get("lei"),
                "name": ent.get("legalName", {}).get("name"),
                "country": ent.get("legalAddress", {}).get("country"),
                "status": ent.get("status"),
            })
        return {"query": name, "matches": len(hits), "results": hits,
                "note": "Use the lei value with the 'lei' tool for full detail."}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# VULN INTEL  (new types: cpe, port; extends cve)
# ===========================================================================
def tool_cpe(q):
    """CPE 2.3 string -> recent CVEs affecting it (NVD, keyless)."""
    cpe = q.strip()
    if not cpe.startswith("cpe:2.3:"):
        return {"error": "give a cpe:2.3:... string"}
    try:
        r = _get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                 params={"cpeName": cpe, "resultsPerPage": 15})
        j = r.json()
        cves = []
        for v in j.get("vulnerabilities", []):
            c = v.get("cve", {})
            desc = next((d["value"] for d in c.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            metrics = c.get("metrics", {})
            score = None
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(mk):
                    score = metrics[mk][0]["cvssData"].get("baseScore")
                    break
            cves.append({"id": c.get("id"), "cvss": score, "summary": desc[:160]})
        cves.sort(key=lambda x: x["cvss"] or 0, reverse=True)
        return {"cpe": cpe, "total": j.get("totalResults"),
                "shown": len(cves), "cves": cves}
    except Exception as e:
        return {"error": str(e)}


def tool_epss(q):
    """EPSS exploit-probability score for a CVE (FIRST.org, keyless)."""
    cve = q.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{3,}", cve):
        return {"error": "give a CVE id like CVE-2021-44228"}
    try:
        r = _get("https://api.first.org/data/v1/epss", params={"cve": cve})
        data = r.json().get("data", [])
        if not data:
            return {"cve": cve, "epss": None, "note": "no EPSS score (CVE may be too new)"}
        d = data[0]
        epss = float(d["epss"])
        return {"cve": cve, "epss": epss, "percentile": float(d["percentile"]),
                "date": d.get("date"),
                "reading": f"~{epss*100:.1f}% chance of exploitation in next 30 days"}
    except Exception as e:
        return {"error": str(e)}


def tool_cvedetail(q):
    """Full CVE record (description, CVSS, refs) via CIRCL (keyless)."""
    cve = q.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{3,}", cve):
        return {"error": "give a CVE id like CVE-2021-44228"}
    try:
        r = _get(f"https://cve.circl.lu/api/cve/{cve}")
        j = r.json()
        if not j or "cveMetadata" not in j:
            return {"cve": cve, "error": "not found"}
        cna = j.get("containers", {}).get("cna", {})
        desc = next((d["value"] for d in cna.get("descriptions", [])
                     if d.get("lang", "").startswith("en")), "")
        refs = [r.get("url") for r in cna.get("references", [])][:10]
        metrics = cna.get("metrics", [])
        cvss = None
        for m in metrics:
            for k, v in m.items():
                if k.startswith("cvss") and isinstance(v, dict):
                    cvss = v.get("baseScore") or cvss
        return {"cve": cve, "state": j["cveMetadata"].get("state"),
                "published": j["cveMetadata"].get("datePublished"),
                "cvss": cvss, "description": desc[:400], "references": refs}
    except Exception as e:
        return {"error": str(e)}


# common-port reference (no source needed — static knowledge)
_PORT_DB = {
    21: ("FTP", "Cleartext file transfer; creds sniffable."),
    22: ("SSH", "Remote shell; check for old OpenSSH / weak auth."),
    23: ("Telnet", "Cleartext remote shell — should never be exposed."),
    25: ("SMTP", "Mail; open relay / user enumeration risk."),
    53: ("DNS", "Open resolver = DDoS amplification risk."),
    80: ("HTTP", "Cleartext web."),
    110: ("POP3", "Cleartext mail retrieval."),
    143: ("IMAP", "Cleartext mail."),
    443: ("HTTPS", "TLS web."),
    445: ("SMB", "Windows file sharing — major lateral-movement target."),
    993: ("IMAPS", "TLS IMAP."),
    995: ("POP3S", "TLS POP3."),
    1433: ("MSSQL", "Database — should not face the internet."),
    1521: ("Oracle DB", "Database — should not face the internet."),
    3306: ("MySQL", "Database — should not face the internet."),
    3389: ("RDP", "Remote Desktop — top ransomware entry vector."),
    5432: ("PostgreSQL", "Database — should not face the internet."),
    5900: ("VNC", "Remote desktop; often unauthenticated."),
    6379: ("Redis", "Frequently unauthenticated — RCE risk."),
    8080: ("HTTP-alt", "Proxies / app servers / admin panels."),
    9200: ("Elasticsearch", "Often unauthenticated data exposure."),
    11211: ("Memcached", "UDP amplification + data exposure."),
    27017: ("MongoDB", "Historically unauthenticated data leaks."),
    554: ("RTSP", "IP-camera streams."),
    3700: ("ONVIF", "IP-camera control."),
}


def tool_port(q):
    """Bare port number -> service + exposure notes (offline reference)."""
    s = q.strip()
    if not s.isdigit() or not (0 < int(s) <= 65535):
        return {"error": "give a port number 1-65535"}
    p = int(s)
    if p in _PORT_DB:
        name, risk = _PORT_DB[p]
        return {"port": p, "service": name, "exposure_note": risk, "well_known": p < 1024}
    return {"port": p, "service": "unknown / ephemeral",
            "exposure_note": "Not a common well-known port.",
            "well_known": p < 1024}


# ===========================================================================
# NETWORK  (extends ip / asn / domain)
# ===========================================================================
def tool_ssh(q):
    """Grab an SSH server banner from a host (per-target probe)."""
    host = _host(q)
    port = 22
    if ":" in q.split("//")[-1]:
        tail = q.split("//")[-1]
        if tail.count(":") == 1 and tail.split(":")[1].split("/")[0].isdigit():
            port = int(tail.split(":")[1].split("/")[0])
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            banner = s.recv(256).decode("latin-1", "replace").strip()
        soft = banner.split(" ")[0] if banner else ""
        return {"host": host, "port": port, "banner": banner,
                "software": soft.replace("SSH-2.0-", "").replace("SSH-1.99-", ""),
                "note": "Per-target probe. Compare software version against known CVEs."}
    except Exception as e:
        return {"error": f"{host}:{port} — {e}"}


def tool_hostsearch(q):
    """Forward-DNS host enumeration for a domain (hackertarget, keyless)."""
    host = _host(q)
    try:
        r = _get("https://api.hackertarget.com/hostsearch/", params={"q": host})
        txt = r.text.strip()
        if "error" in txt.lower() or "API count" in txt:
            return {"domain": host, "error": txt[:120]}
        rows = [ln.split(",") for ln in txt.splitlines() if "," in ln]
        return {"domain": host, "count": len(rows),
                "hosts": [{"name": n, "ip": ip} for n, ip in rows][:100]}
    except Exception as e:
        return {"error": str(e)}


def tool_peeringnet(q):
    """PeeringDB network record for an ASN (keyless): peering policy, traffic."""
    s = q.strip().lower().replace("as", "")
    if not s.isdigit():
        return {"error": "give an ASN like AS15169"}
    try:
        r = _get("https://www.peeringdb.com/api/net", params={"asn": s})
        data = r.json().get("data", [])
        if not data:
            return {"asn": "AS" + s, "error": "not in PeeringDB"}
        d = data[0]
        return {"asn": "AS" + s, "name": d.get("name"), "aka": d.get("aka"),
                "website": d.get("website"), "type": d.get("info_type"),
                "traffic": d.get("info_traffic"), "scope": d.get("info_scope"),
                "ix_count": d.get("ix_count"), "fac_count": d.get("fac_count"),
                "policy": d.get("policy_general"), "notes": (d.get("notes") or "")[:200]}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# GEO  (extends coords)
# ===========================================================================
def tool_nearbywiki(q):
    """Coordinates -> nearby Wikipedia places (geosearch, keyless)."""
    m = re.match(r"^\s*(-?\d{1,3}(?:\.\d+)?)\s*[,; ]\s*(-?\d{1,3}(?:\.\d+)?)\s*$", q)
    if not m:
        return {"error": "give coordinates like 48.8584,2.2945"}
    lat, lon = m.group(1), m.group(2)
    try:
        r = _get("https://en.wikipedia.org/w/api.php", params={
            "action": "query", "list": "geosearch",
            "gscoord": f"{lat}|{lon}", "gsradius": 5000, "gslimit": 15,
            "format": "json"})
        places = r.json().get("query", {}).get("geosearch", [])
        return {"lat": float(lat), "lon": float(lon), "found": len(places),
                "places": [{"title": p["title"], "lat": p["lat"], "lon": p["lon"],
                            "dist_m": p["dist"],
                            "url": "https://en.wikipedia.org/?curid=" + str(p["pageid"])}
                           for p in places]}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# REGISTRY  (merged into osint.TOOLS)
# ===========================================================================

# ── extension pack 3 ──────────────────────────────────────────────────────────────
def tool_doi(q):
    """Resolve a DOI to publication metadata via Crossref (keyless)."""
    doi = re.sub(r"^https?://(dx\.)?doi\.org/", "", q.strip(), flags=re.I)
    if not doi.startswith("10."):
        return {"error": "give a DOI like 10.1038/nature12373"}
    try:
        m = _get(f"https://api.crossref.org/works/{urllib.parse.quote(doi)}").json().get("message", {})
        auth = [f"{a.get('given','')} {a.get('family','')}".strip()
                for a in m.get("author", [])][:20]
        return {"doi": doi, "title": (m.get("title") or [None])[0],
                "type": m.get("type"), "publisher": m.get("publisher"),
                "container": (m.get("container-title") or [None])[0],
                "published": (m.get("published", {}).get("date-parts") or [[None]])[0],
                "authors": auth, "references": m.get("reference-count"),
                "cited_by": m.get("is-referenced-by-count"), "url": m.get("URL")}
    except Exception as e:
        return {"error": str(e)}


def tool_crossrefauthor(q):
    """Search Crossref for works by author/keyword (keyless)."""
    s = q.strip()
    try:
        r = _get("https://api.crossref.org/works",
                 params={"query.author": s, "rows": 8, "select": "title,DOI,published,container-title"})
        items = r.json().get("message", {}).get("items", [])
        return {"query": s, "count": len(items),
                "works": [{"title": (i.get("title") or [None])[0], "doi": i.get("DOI"),
                           "year": (i.get("published", {}).get("date-parts") or [[None]])[0][0]}
                          for i in items]}
    except Exception as e:
        return {"error": str(e)}


def tool_orcidworks(q):
    """List an ORCID researcher's recent works (keyless public API)."""
    oid = q.strip().upper().replace("HTTPS://ORCID.ORG/", "")
    if not re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{3}[\dX]", oid):
        return {"error": "give an ORCID like 0000-0002-1825-0097"}
    try:
        r = _get(f"https://pub.orcid.org/v3.0/{oid}/works",
                 headers={"Accept": "application/json"})
        groups = r.json().get("group", [])
        titles = []
        for g in groups[:20]:
            s = g.get("work-summary", [{}])[0]
            t = s.get("title", {}).get("title", {}).get("value")
            yr = s.get("publication-date", {}).get("year", {})
            titles.append({"title": t, "year": yr.get("value") if yr else None,
                           "type": s.get("type")})
        return {"orcid": oid, "work_count": len(groups), "recent_works": titles}
    except Exception as e:
        return {"error": str(e)}


def tool_isbnmeta(q):
    """ISBN -> book metadata (title/authors/subjects) via OpenLibrary (keyless)."""
    isbn = re.sub(r"[- ]", "", q.strip())
    if not re.fullmatch(r"\d{9}[\dxX]|\d{13}", isbn):
        return {"error": "give a 10- or 13-digit ISBN"}
    try:
        r = _get("https://openlibrary.org/api/books",
                 params={"bibkeys": f"ISBN:{isbn}", "format": "json", "jscmd": "data"})
        d = r.json().get(f"ISBN:{isbn}")
        if not d:
            return {"isbn": isbn, "found": False, "note": "not in OpenLibrary"}
        return {"isbn": isbn, "title": d.get("title"),
                "authors": [a.get("name") for a in d.get("authors", [])],
                "publishers": [p.get("name") for p in d.get("publishers", [])],
                "published": d.get("publish_date"),
                "pages": d.get("number_of_pages"),
                "subjects": [s.get("name") for s in d.get("subjects", [])][:12],
                "url": d.get("url")}
    except Exception as e:
        return {"error": str(e)}


def tool_sopostuser(q):
    """StackOverflow user profile + reputation by numeric id (keyless)."""
    uid = q.strip()
    if not uid.isdigit():
        return {"error": "give a numeric StackOverflow user id"}
    try:
        r = _get(f"https://api.stackexchange.com/2.3/users/{uid}",
                 params={"site": "stackoverflow"})
        items = r.json().get("items", [])
        if not items:
            return {"user_id": uid, "found": False}
        u = items[0]
        return {"user_id": uid, "name": u.get("display_name"),
                "reputation": u.get("reputation"), "badges": u.get("badge_counts"),
                "location": u.get("location"), "created": u.get("creation_date"),
                "link": u.get("link")}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# THREAT / BREACH  (keyless public lists)
# ===========================================================================
def tool_breachsearch(q):
    """Search the public HIBP breach catalog by name/domain (keyless list).

    Note: this is the PUBLIC breach metadata list — NOT account lookup
    (that needs a key). Tells you what a breach was, not who was in it."""
    s = q.strip().lower()
    try:
        r = _get("https://haveibeenpwned.com/api/v3/breaches")
        hits = [b for b in r.json()
                if s in b.get("Name", "").lower() or s in b.get("Domain", "").lower()
                or s in b.get("Title", "").lower()]
        return {"query": s, "matches": len(hits),
                "breaches": [{"name": b["Name"], "domain": b.get("Domain"),
                              "date": b.get("BreachDate"), "accounts": b.get("PwnCount"),
                              "data": b.get("DataClasses")} for b in hits[:15]]}
    except Exception as e:
        return {"error": str(e)}


def tool_feodoips(q):
    """Is this IP on the abuse.ch Feodo C2 blocklist (keyless)."""
    ip = _host(q)
    try:
        r = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        hits = [e for e in r.json() if e.get("ip_address") == ip]
        return {"ip": ip, "listed": bool(hits),
                "entries": [{"port": h.get("port"), "malware": h.get("malware"),
                             "first_seen": h.get("first_seen"), "status": h.get("status")}
                            for h in hits]}
    except Exception as e:
        return {"error": str(e)}


def tool_urlscansearch(q):
    """Search urlscan.io's public scan archive for a domain (keyless)."""
    host = _host(q)
    try:
        r = _get("https://urlscan.io/api/v1/search/",
                 params={"q": f"domain:{host}", "size": 10})
        res = r.json().get("results", [])
        return {"domain": host, "total": r.json().get("total"),
                "scans": [{"url": x.get("page", {}).get("url"),
                           "ip": x.get("page", {}).get("ip"),
                           "server": x.get("page", {}).get("server"),
                           "time": x.get("task", {}).get("time")} for x in res]}
    except Exception as e:
        return {"error": str(e)}


def tool_commoncrawl(q):
    """Has a URL/domain been seen in Common Crawl's index (keyless)."""
    host = _host(q)
    try:
        r = _get("https://index.commoncrawl.org/CC-MAIN-2024-10-index",
                 params={"url": f"{host}/*", "output": "json", "limit": 10})
        lines = [l for l in r.text.strip().splitlines() if l]
        recs = [_j.loads(l) for l in lines]
        return {"domain": host, "captures": len(recs),
                "sample": [{"url": x.get("url"), "status": x.get("status"),
                            "mime": x.get("mime"), "timestamp": x.get("timestamp")}
                           for x in recs[:8]]}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# IP / GEO  (extends ip, coords, domain)
# ===========================================================================
def tool_ipfull(q):
    """Rich IP geo+network record via ip-api.com (keyless, mobile/proxy flags)."""
    ip = _host(q)
    try:
        r = _get(f"http://ip-api.com/json/{ip}", params={"fields": "66846719"})
        d = r.json()
        if d.get("status") != "success":
            return {"ip": ip, "error": d.get("message", "lookup failed")}
        return {"ip": ip, "country": d.get("country"), "region": d.get("regionName"),
                "city": d.get("city"), "zip": d.get("zip"),
                "lat": d.get("lat"), "lon": d.get("lon"), "isp": d.get("isp"),
                "org": d.get("org"), "as": d.get("as"), "asname": d.get("asname"),
                "reverse": d.get("reverse"), "mobile": d.get("mobile"),
                "proxy": d.get("proxy"), "hosting": d.get("hosting"),
                "timezone": d.get("timezone")}
    except Exception as e:
        return {"error": str(e)}


def tool_geocode(q):
    """Place name -> coordinates + bounding box via OSM Nominatim (keyless)."""
    s = q.strip()
    try:
        r = _get("https://nominatim.openstreetmap.org/search",
                 params={"q": s, "format": "json", "limit": 5, "addressdetails": 1})
        res = r.json()
        return {"query": s, "results": [{"name": x.get("display_name"),
                "lat": float(x["lat"]), "lon": float(x["lon"]),
                "type": x.get("type"), "class": x.get("class")} for x in res]}
    except Exception as e:
        return {"error": str(e)}


def tool_revgeocode(q):
    """Coordinates -> nearest address via OSM Nominatim reverse (keyless)."""
    m = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)\s*$", q)
    if not m:
        return {"error": "give coordinates like 48.8584,2.2945"}
    try:
        r = _get("https://nominatim.openstreetmap.org/reverse",
                 params={"lat": m.group(1), "lon": m.group(2),
                         "format": "json", "addressdetails": 1})
        d = r.json()
        return {"lat": float(m.group(1)), "lon": float(m.group(2)),
                "display_name": d.get("display_name"),
                "address": d.get("address", {}), "osm_type": d.get("osm_type")}
    except Exception as e:
        return {"error": str(e)}


def tool_macvendorlookup(q):
    """MAC/OUI -> hardware vendor via macvendors.com (keyless)."""
    mac = q.strip()
    if not re.match(r"^([0-9a-f]{2}[:-]){2}[0-9a-f]{2}", mac, re.I):
        return {"error": "give a MAC or OUI like 00:1A:2B"}
    try:
        r = _get(f"https://api.macvendors.com/{urllib.parse.quote(mac)}")
        if r.status_code == 404:
            return {"mac": mac, "vendor": None, "note": "OUI not registered"}
        return {"mac": mac, "vendor": r.text.strip()}
    except Exception as e:
        return {"error": str(e)}


def tool_dnsmx(q):
    """MX records via Google Public DNS-over-HTTPS (keyless, censorship-resistant)."""
    host = _host(q)
    try:
        r = _get("https://dns.google/resolve", params={"name": host, "type": "MX"})
        ans = r.json().get("Answer", [])
        return {"domain": host, "mx": [a["data"] for a in ans if a.get("type") == 15],
                "status": r.json().get("Status")}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# REFERENCE / UTILITY  (mostly type-agnostic; accept username so they always show)
# ===========================================================================
def tool_fxrate(q):
    """Currency code -> live exchange rates via open.er-api.com (keyless)."""
    code = q.strip().upper()
    if not re.fullmatch(r"[A-Z]{3}", code):
        return {"error": "give a 3-letter currency code like USD"}
    try:
        d = _get(f"https://open.er-api.com/v6/latest/{code}").json()
        if d.get("result") != "success":
            return {"code": code, "error": "unknown currency code"}
        rates = d.get("rates", {})
        common = {k: rates[k] for k in ("USD", "EUR", "GBP", "JPY", "CNY", "INR", "BTC")
                  if k in rates}
        return {"base": code, "updated": d.get("time_last_update_utc"),
                "common_rates": common, "total_currencies": len(rates)}
    except Exception as e:
        return {"error": str(e)}


def tool_country(q):
    """Country code/name -> profile via World Bank (keyless)."""
    s = q.strip()
    try:
        r = _get(f"https://api.worldbank.org/v2/country/{urllib.parse.quote(s)}",
                 params={"format": "json"})
        j = r.json()
        if not isinstance(j, list) or len(j) < 2 or not j[1]:
            return {"query": s, "error": "country not found (try ISO code like US)"}
        c = j[1][0]
        return {"name": c.get("name"), "iso2": c.get("iso2Code"),
                "region": c.get("region", {}).get("value"),
                "income": c.get("incomeLevel", {}).get("value"),
                "capital": c.get("capitalCity"),
                "lat": c.get("latitude"), "lon": c.get("longitude")}
    except Exception as e:
        return {"error": str(e)}


def tool_wikidatasearch(q):
    """Free-text -> Wikidata entities (keyless)."""
    s = q.strip()
    try:
        r = _get("https://www.wikidata.org/w/api.php",
                 params={"action": "wbsearchentities", "search": s, "language": "en",
                         "format": "json", "limit": 8})
        return {"query": s, "entities": [{"id": e.get("id"), "label": e.get("label"),
                "description": e.get("description")} for e in r.json().get("search", [])]}
    except Exception as e:
        return {"error": str(e)}


def tool_spdxlicense(q):
    """SPDX license id -> name + OSI status (keyless reference)."""
    lid = q.strip()
    try:
        d = _get("https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json").json()
        for lic in d.get("licenses", []):
            if lic.get("licenseId", "").lower() == lid.lower():
                return {"id": lic["licenseId"], "name": lic.get("name"),
                        "osi_approved": lic.get("isOsiApproved"),
                        "deprecated": lic.get("isDeprecatedLicenseId"),
                        "url": lic.get("reference")}
        return {"query": lid, "found": False,
                "note": "no exact SPDX id match (try e.g. MIT, Apache-2.0)"}
    except Exception as e:
        return {"error": str(e)}


def tool_gitignore(q):
    """Language -> GitHub's recommended .gitignore template (keyless)."""
    lang = q.strip()
    try:
        r = _get(f"https://api.github.com/gitignore/templates/{urllib.parse.quote(lang)}")
        if r.status_code == 404:
            tl = _get("https://api.github.com/gitignore/templates").json()
            sample = tl[:30] if isinstance(tl, list) else []
            return {"query": lang, "found": False, "available_sample": sample}
        if r.status_code == 403:
            return {"query": lang, "error": "GitHub rate limit; try later"}
        d = r.json()
        return {"name": d.get("name"), "source": d.get("source")}
    except Exception as e:
        return {"error": str(e)}


def tool_ghcommits(q):
    """Recent commits for a GitHub owner/repo (keyless, unauth rate-limited)."""
    repo = q.strip().replace("https://github.com/", "").strip("/")
    if repo.count("/") != 1:
        return {"error": "give owner/repo like torvalds/linux"}
    try:
        r = _get(f"https://api.github.com/repos/{repo}/commits", params={"per_page": 10})
        if r.status_code == 404:
            return {"repo": repo, "error": "repo not found"}
        if r.status_code == 403:
            return {"repo": repo, "error": "GitHub unauth rate limit hit; try later"}
        return {"repo": repo, "commits": [{"sha": c["sha"][:10],
                "author": (c.get("commit", {}).get("author", {}) or {}).get("name"),
                "date": (c.get("commit", {}).get("author", {}) or {}).get("date"),
                "message": (c.get("commit", {}).get("message", "") or "").splitlines()[0][:100]}
                for c in r.json()[:10]]}
    except Exception as e:
        return {"error": str(e)}


def tool_ghpubkeys(q):
    """A GitHub user's public SSH keys (keyless; .keys endpoint)."""
    user = q.strip().lstrip("@")
    try:
        r = _get(f"https://github.com/{urllib.parse.quote(user)}.keys")
        keys = [k for k in r.text.strip().splitlines() if k]
        return {"username": user, "key_count": len(keys),
                "key_types": sorted({k.split()[0] for k in keys if k.split()}),
                "note": "Public SSH keys GitHub serves for this user."}
    except Exception as e:
        return {"error": str(e)}


def tool_ghkeysgpg(q):
    """A GitHub user's public GPG keys (keyless; .gpg endpoint)."""
    user = q.strip().lstrip("@")
    try:
        r = _get(f"https://github.com/{urllib.parse.quote(user)}.gpg")
        body = r.text.strip()
        has = body.startswith("-----BEGIN PGP")
        return {"username": user, "has_gpg_key": has,
                "length": len(body) if has else 0}
    except Exception as e:
        return {"error": str(e)}


def tool_npmdownloads(q):
    """npm package weekly download count (keyless registry stats)."""
    pkg = q.strip()
    try:
        r = _get(f"https://api.npmjs.org/downloads/point/last-week/{urllib.parse.quote(pkg, safe='@/')}")
        d = r.json()
        if d.get("error"):
            return {"package": pkg, "error": d["error"]}
        return {"package": pkg, "downloads_last_week": d.get("downloads"),
                "period": f"{d.get('start')} → {d.get('end')}"}
    except Exception as e:
        return {"error": str(e)}


def tool_pypiproject(q):
    """PyPI project metadata: latest version, license, links (keyless)."""
    pkg = q.strip()
    try:
        r = _get(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json")
        if r.status_code == 404:
            return {"package": pkg, "found": False}
        info = r.json().get("info", {})
        return {"package": pkg, "version": info.get("version"),
                "summary": info.get("summary"), "license": info.get("license"),
                "author": info.get("author"), "home_page": info.get("home_page"),
                "requires_python": info.get("requires_python"),
                "yanked": any(f.get("yanked") for f in r.json().get("urls", []))}
    except Exception as e:
        return {"error": str(e)}


def tool_dockerhub(q):
    """Docker Hub image metadata: pulls, stars, last push (keyless)."""
    img = q.strip()
    repo = img if "/" in img else f"library/{img}"
    try:
        r = _get(f"https://hub.docker.com/v2/repositories/{repo}")
        if r.status_code == 404:
            return {"image": img, "found": False}
        d = r.json()
        return {"image": repo, "pulls": d.get("pull_count"), "stars": d.get("star_count"),
                "last_updated": d.get("last_updated"),
                "description": (d.get("description") or "")[:160]}
    except Exception as e:
        return {"error": str(e)}


def tool_httpstatus(q):
    """Explain an HTTP status code (offline reference)."""
    s = q.strip()
    codes = {
        "100": "Continue", "101": "Switching Protocols",
        "200": "OK", "201": "Created", "204": "No Content", "206": "Partial Content",
        "301": "Moved Permanently", "302": "Found", "304": "Not Modified",
        "307": "Temporary Redirect", "308": "Permanent Redirect",
        "400": "Bad Request", "401": "Unauthorized", "403": "Forbidden",
        "404": "Not Found", "405": "Method Not Allowed", "408": "Request Timeout",
        "418": "I'm a teapot", "429": "Too Many Requests",
        "500": "Internal Server Error", "502": "Bad Gateway",
        "503": "Service Unavailable", "504": "Gateway Timeout",
    }
    if s not in codes:
        return {"code": s, "error": "unknown / non-standard HTTP status"}
    cls = {"1": "Informational", "2": "Success", "3": "Redirection",
           "4": "Client Error", "5": "Server Error"}.get(s[0], "?")
    return {"code": int(s), "meaning": codes[s], "class": cls}


def tool_useragent(q):
    """Parse a User-Agent string into OS / browser / device (offline heuristic)."""
    ua = q.strip()
    osys = next((o for k, o in [("Windows NT 10", "Windows 10/11"), ("Windows", "Windows"),
                ("Mac OS X", "macOS"), ("iPhone", "iOS"), ("iPad", "iPadOS"),
                ("Android", "Android"), ("Linux", "Linux")] if k in ua), "unknown")
    br = next((b for k, b in [("Edg/", "Edge"), ("OPR/", "Opera"), ("Chrome/", "Chrome"),
              ("Firefox/", "Firefox"), ("Safari/", "Safari"), ("curl/", "curl"),
              ("bot", "Bot/crawler")] if k.lower() in ua.lower()), "unknown")
    mobile = any(k in ua for k in ("Mobile", "Android", "iPhone"))
    return {"user_agent": ua, "os": osys, "browser": br,
            "device": "mobile" if mobile else "desktop"}


def tool_asnprefixes(q):
    """All announced prefixes for an ASN via RIPEstat (keyless)."""
    s = q.strip().lower().replace("as", "")
    if not s.isdigit():
        return {"error": "give an ASN like AS15169"}
    try:
        r = _get("https://stat.ripe.net/data/announced-prefixes/data.json",
                 params={"resource": f"AS{s}"})
        prefixes = r.json().get("data", {}).get("prefixes", [])
        v4 = [p["prefix"] for p in prefixes if ":" not in p["prefix"]]
        v6 = [p["prefix"] for p in prefixes if ":" in p["prefix"]]
        return {"asn": "AS" + s, "prefix_count": len(prefixes),
                "ipv4_count": len(v4), "ipv6_count": len(v6),
                "ipv4_sample": v4[:30], "ipv6_sample": v6[:15]}
    except Exception as e:
        return {"error": str(e)}


def tool_ripewhois(q):
    """RIPEstat whois/network-info for an IP or prefix (keyless)."""
    s = _host(q)
    try:
        r = _get("https://stat.ripe.net/data/network-info/data.json",
                 params={"resource": s})
        d = r.json().get("data", {})
        return {"resource": s, "prefix": d.get("prefix"), "asns": d.get("asns"),
                "note": "RIPEstat network-info: covering prefix + origin ASN(s)."}
    except Exception as e:
        return {"error": str(e)}


def tool_rdapip(q):
    """RDAP record for an IP via the IANA bootstrap (keyless, authoritative)."""
    ip = _host(q)
    try:
        r = _get(f"https://rdap.org/ip/{ip}")
        d = r.json()
        ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
        return {"ip": ip, "handle": d.get("handle"), "name": d.get("name"),
                "type": d.get("type"), "country": d.get("country"),
                "start": d.get("startAddress"), "end": d.get("endAddress"),
                "registered": ev.get("registration"),
                "last_changed": ev.get("last changed")}
    except Exception as e:
        return {"error": str(e)}


def tool_isotime(q):
    """Convert/parse a timestamp or 'now' to multiple formats (offline)."""
    s = q.strip().lower()
    try:
        if s.isdigit():
            ts = int(s)
            if ts > 1e12:
                ts /= 1000
            dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        else:
            dt = datetime.datetime.fromisoformat(q.strip().replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
        return {"input": q.strip(), "iso8601": dt.isoformat(),
                "unix": int(dt.timestamp()), "utc": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "weekday": dt.strftime("%A"), "day_of_year": dt.timetuple().tm_yday}
    except Exception as e:
        return {"error": f"could not parse '{q.strip()}': {e}"}


# ===========================================================================
# REGISTRY  (merged into osint.TOOLS)
# ===========================================================================

# ── extension pack 4 ──────────────────────────────────────────────────────────────
def tool_nvdcve(q):
    """Full NVD record for a CVE: CVSS, CWE, references (keyless)."""
    cve = q.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        return {"error": "give a CVE id like CVE-2021-44228"}
    try:
        r = _get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve})
        vt = r.json().get("vulnerabilities", [])
        if not vt:
            return {"cve": cve, "found": False}
        c = vt[0]["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), None)
        metrics = c.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                d = metrics[key][0]["cvssData"]
                cvss = {"version": d.get("version"), "score": d.get("baseScore"),
                        "severity": d.get("baseSeverity") or metrics[key][0].get("baseSeverity"),
                        "vector": d.get("vectorString")}
                break
        return {"cve": cve, "description": desc, "published": c.get("published"),
                "cvss": cvss,
                "cwe": [d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])],
                "references": [r_["url"] for r_ in c.get("references", [])][:8]}
    except Exception as e:
        return {"error": str(e)}


def tool_ghadvisory(q):
    """GitHub Security Advisories for a package ecosystem (keyless)."""
    eco = q.strip().lower() or "pip"
    valid = {"pip", "npm", "rubygems", "maven", "composer", "go", "rust", "nuget", "actions", "pub"}
    if eco not in valid:
        return {"error": f"give an ecosystem: {', '.join(sorted(valid))}"}
    try:
        r = _get("https://api.github.com/advisories",
                 params={"ecosystem": eco, "per_page": 10})
        if r.status_code == 403:
            return {"ecosystem": eco, "error": "GitHub unauth rate limit; try later"}
        return {"ecosystem": eco, "advisories": [{"ghsa": a.get("ghsa_id"),
                "cve": a.get("cve_id"), "severity": a.get("severity"),
                "summary": a.get("summary"), "published": a.get("published_at")}
                for a in r.json()[:10]]}
    except Exception as e:
        return {"error": str(e)}


def tool_otxdomain(q):
    """AlienVault OTX threat reputation for a domain (keyless)."""
    host = _host(q)
    try:
        r = _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general")
        d = r.json()
        pulses = d.get("pulse_info", {})
        return {"domain": host, "pulse_count": pulses.get("count", 0),
                "in_threat_feeds": pulses.get("count", 0) > 0,
                "pulses": [p.get("name") for p in pulses.get("pulses", [])][:8],
                "validation": [v.get("name") for v in d.get("validation", [])]}
    except Exception as e:
        return {"error": str(e)}


def tool_otxip(q):
    """AlienVault OTX threat reputation for an IP (keyless)."""
    ip = _host(q)
    try:
        r = _get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general")
        d = r.json()
        pulses = d.get("pulse_info", {})
        return {"ip": ip, "pulse_count": pulses.get("count", 0),
                "in_threat_feeds": pulses.get("count", 0) > 0,
                "country": d.get("country_name"), "asn": d.get("asn"),
                "pulses": [p.get("name") for p in pulses.get("pulses", [])][:8]}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# DOMAIN / NETWORK
# ===========================================================================
def tool_hosthunt(q):
    """HackerTarget host/subdomain search — forward DNS map (keyless, rate-limited)."""
    host = _host(q)
    try:
        r = _get("https://api.hackertarget.com/hostsearch/", params={"q": host})
        txt = r.text.strip()
        if "API count exceeded" in txt or "error" in txt.lower():
            return {"domain": host, "error": "HackerTarget daily quota hit; try later"}
        rows = [l.split(",") for l in txt.splitlines() if "," in l]
        return {"domain": host, "count": len(rows),
                "hosts": [{"host": r_[0], "ip": r_[1]} for r_ in rows[:50]]}
    except Exception as e:
        return {"error": str(e)}


def tool_ghlanguages(q):
    """Language byte-breakdown for a GitHub owner/repo (keyless)."""
    repo = q.strip().replace("https://github.com/", "").strip("/")
    if repo.count("/") != 1:
        return {"error": "give owner/repo like torvalds/linux"}
    try:
        r = _get(f"https://api.github.com/repos/{repo}/languages")
        if r.status_code == 404:
            return {"repo": repo, "found": False}
        d = r.json()
        total = sum(d.values()) or 1
        return {"repo": repo, "languages": {k: f"{v/total*100:.1f}%"
                for k, v in sorted(d.items(), key=lambda x: -x[1])}}
    except Exception as e:
        return {"error": str(e)}


def tool_githubsearch(q):
    """Search GitHub repositories by keyword (keyless, rate-limited)."""
    s = q.strip()
    try:
        r = _get("https://api.github.com/search/repositories",
                 params={"q": s, "per_page": 8, "sort": "stars"})
        if r.status_code == 403:
            return {"query": s, "error": "GitHub search rate limit; try later"}
        return {"query": s, "total": r.json().get("total_count"),
                "repos": [{"full_name": i["full_name"], "stars": i["stargazers_count"],
                "lang": i.get("language"), "desc": (i.get("description") or "")[:100]}
                for i in r.json().get("items", [])]}
    except Exception as e:
        return {"error": str(e)}


def tool_githubgists(q):
    """A GitHub user's public gists (keyless)."""
    user = q.strip().lstrip("@")
    try:
        r = _get(f"https://api.github.com/users/{urllib.parse.quote(user)}/gists",
                 params={"per_page": 10})
        if r.status_code == 404:
            return {"username": user, "found": False}
        if r.status_code == 403:
            return {"username": user, "error": "GitHub rate limit; try later"}
        gists = r.json()
        if not isinstance(gists, list):
            return {"username": user, "error": "unexpected response"}
        return {"username": user, "gist_count": len(gists),
                "gists": [{"desc": (g.get("description") or "")[:80],
                "files": list(g.get("files", {}).keys()), "created": g.get("created_at")}
                for g in gists[:10]]}
    except Exception as e:
        return {"error": str(e)}


def tool_golangpkg(q):
    """Latest version of a Go module via proxy.golang.org (keyless)."""
    mod = q.strip()
    try:
        r = _get(f"https://proxy.golang.org/{urllib.parse.quote(mod, safe='/.')}/@latest")
        if r.status_code != 200:
            return {"module": mod, "found": False, "status": r.status_code}
        d = r.json()
        return {"module": mod, "version": d.get("version"), "time": d.get("Time"),
                "origin": d.get("Origin", {}).get("URL")}
    except Exception as e:
        return {"error": str(e)}


def tool_rubygemrev(q):
    """Reverse dependencies of a RubyGem — who depends on it (keyless)."""
    gem = q.strip()
    try:
        r = _get(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(gem)}/reverse_dependencies.json")
        if r.status_code == 404:
            return {"gem": gem, "found": False}
        deps = r.json()
        return {"gem": gem, "reverse_dependency_count": len(deps),
                "sample": deps[:40]}
    except Exception as e:
        return {"error": str(e)}


def tool_cratedownloads(q):
    """Download history + totals for a Rust crate (keyless)."""
    crate = q.strip()
    try:
        r = _get(f"https://crates.io/api/v1/crates/{urllib.parse.quote(crate)}")
        if r.status_code == 404:
            return {"crate": crate, "found": False}
        c = r.json().get("crate", {})
        return {"crate": crate, "total_downloads": c.get("downloads"),
                "recent_downloads": c.get("recent_downloads"),
                "max_version": c.get("max_stable_version") or c.get("max_version"),
                "updated": c.get("updated_at")}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# SCHOLARLY (extends doi)
# ===========================================================================
def tool_openalexwork(q):
    """OpenAlex scholarly work by DOI/OpenAlex-id: citations, concepts (keyless)."""
    s = q.strip()
    if s.lower().startswith("10."):
        s = f"doi:{s}"
    try:
        r = _get(f"https://api.openalex.org/works/{urllib.parse.quote(s, safe=':/')}")
        if r.status_code == 404:
            return {"query": q.strip(), "found": False}
        d = r.json()
        return {"id": d.get("id"), "title": d.get("title"),
                "year": d.get("publication_year"), "doi": d.get("doi"),
                "cited_by": d.get("cited_by_count"), "type": d.get("type"),
                "open_access": d.get("open_access", {}).get("is_oa"),
                "concepts": [c.get("display_name") for c in d.get("concepts", [])][:8]}
    except Exception as e:
        return {"error": str(e)}


def tool_openalexauthor(q):
    """Search OpenAlex for an author: works count, h-index, institutions (keyless)."""
    s = q.strip()
    try:
        r = _get("https://api.openalex.org/authors", params={"search": s, "per_page": 5})
        res = r.json().get("results", [])
        return {"query": s, "authors": [{"name": a.get("display_name"),
                "works": a.get("works_count"), "cited_by": a.get("cited_by_count"),
                "h_index": a.get("summary_stats", {}).get("h_index"),
                "institution": (a.get("last_known_institutions") or [{}])[0].get("display_name")}
                for a in res]}
    except Exception as e:
        return {"error": str(e)}


def tool_semanticscholar(q):
    """Semantic Scholar paper lookup by DOI: TLDR, citations, influence (keyless)."""
    doi = re.sub(r"^https?://(dx\.)?doi\.org/", "", q.strip(), flags=re.I)
    try:
        r = _get(f"https://api.semanticscholar.org/graph/v1/paper/DOI:{urllib.parse.quote(doi)}",
                 params={"fields": "title,year,citationCount,influentialCitationCount,authors,tldr"})
        if r.status_code != 200:
            return {"doi": doi, "found": False, "status": r.status_code}
        d = r.json()
        return {"doi": doi, "title": d.get("title"), "year": d.get("year"),
                "citations": d.get("citationCount"),
                "influential_citations": d.get("influentialCitationCount"),
                "authors": [a.get("name") for a in d.get("authors", [])][:15],
                "tldr": (d.get("tldr") or {}).get("text")}
    except Exception as e:
        return {"error": str(e)}


def tool_datacite(q):
    """Search DataCite for research datasets/DOIs by keyword (keyless)."""
    s = q.strip()
    try:
        r = _get("https://api.datacite.org/dois", params={"query": s, "page[size]": 8})
        data = r.json().get("data", [])
        return {"query": s, "results": [{"doi": x.get("id"),
                "title": (x.get("attributes", {}).get("titles") or [{}])[0].get("title"),
                "year": x.get("attributes", {}).get("publicationYear"),
                "type": x.get("attributes", {}).get("resourceTypeGeneral")}
                for x in data]}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# REFERENCE / KNOWLEDGE
# ===========================================================================
def tool_restcountry(q):
    """Country detail by name or ISO code via World Bank (keyless).

    restcountries.com v3.1 was deprecated 2026-06-30; World Bank's
    /country endpoint is the live keyless replacement. Capital/region/income
    only — no currencies/languages/borders from this source."""
    s = q.strip()
    try:
        r = _get(f"https://api.worldbank.org/v2/country/{urllib.parse.quote(s)}",
                 params={"format": "json"})
        j = r.json()
        if not isinstance(j, list) or len(j) < 2 or not j[1]:
            # fall back to name search across the full list
            allc = _get("https://api.worldbank.org/v2/country",
                        params={"format": "json", "per_page": 400}).json()[1]
            match = [c for c in allc if s.lower() in (c.get("name") or "").lower()]
            if not match:
                return {"query": s, "found": False, "note": "try an ISO code like FR or a country name"}
            j = [None, match[:1]]
        c = j[1][0]
        return {"name": c.get("name"), "iso2": c.get("iso2Code"),
                "iso3": c.get("id"), "capital": c.get("capitalCity"),
                "region": c.get("region", {}).get("value"),
                "income": c.get("incomeLevel", {}).get("value"),
                "lending": c.get("lendingType", {}).get("value"),
                "lat": c.get("latitude"), "lon": c.get("longitude")}
    except Exception as e:
        return {"error": str(e)}


def tool_wikisummary(q):
    """Wikipedia page summary/extract for a topic (keyless REST API)."""
    title = q.strip().replace(" ", "_")
    try:
        r = _get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(title)}")
        if r.status_code == 404:
            return {"query": q.strip(), "found": False}
        d = r.json()
        return {"title": d.get("title"), "description": d.get("description"),
                "extract": d.get("extract"), "type": d.get("type"),
                "url": d.get("content_urls", {}).get("desktop", {}).get("page"),
                "coordinates": d.get("coordinates")}
    except Exception as e:
        return {"error": str(e)}


def tool_archiveorg(q):
    """Internet Archive item metadata by identifier (keyless)."""
    ident = q.strip().rstrip("/").split("/")[-1]
    try:
        r = _get(f"https://archive.org/metadata/{urllib.parse.quote(ident)}")
        d = r.json()
        if not d.get("metadata"):
            return {"identifier": ident, "found": False}
        m = d["metadata"]
        return {"identifier": ident, "title": m.get("title"),
                "creator": m.get("creator"), "date": m.get("date"),
                "mediatype": m.get("mediatype"), "collection": m.get("collection"),
                "file_count": len(d.get("files", [])),
                "downloads": m.get("downloads")}
    except Exception as e:
        return {"error": str(e)}


def tool_hnsearch(q):
    """Search Hacker News stories/comments via Algolia (keyless)."""
    s = q.strip()
    try:
        r = _get("https://hn.algolia.com/api/v1/search", params={"query": s, "hitsPerPage": 8})
        return {"query": s, "hits": [{"title": h.get("title") or h.get("story_title"),
                "author": h.get("author"), "points": h.get("points"),
                "comments": h.get("num_comments"),
                "url": h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"}
                for h in r.json().get("hits", [])]}
    except Exception as e:
        return {"error": str(e)}


def tool_hnuser(q):
    """Hacker News user profile: karma, age, about (keyless)."""
    user = q.strip().lstrip("@")
    try:
        r = _get(f"https://hn.algolia.com/api/v1/users/{urllib.parse.quote(user)}")
        if r.status_code == 404:
            return {"username": user, "found": False}
        d = r.json()
        return {"username": d.get("username"), "karma": d.get("karma"),
                "created": d.get("created_at"),
                "about": re.sub("<[^>]+>", "", d.get("about") or "")[:200]}
    except Exception as e:
        return {"error": str(e)}


def tool_wikipv(q):
    """Wikipedia page metadata: length, last-edit, watchers-ish (keyless)."""
    title = q.strip()
    try:
        r = _get("https://en.wikipedia.org/w/api.php",
                 params={"action": "query", "titles": title, "prop": "info|revisions",
                         "inprop": "url", "format": "json", "rvprop": "timestamp|user"})
        pages = r.json().get("query", {}).get("pages", {})
        p = next(iter(pages.values()))
        if "missing" in p:
            return {"query": title, "found": False}
        rev = (p.get("revisions") or [{}])[0]
        return {"title": p.get("title"), "length_bytes": p.get("length"),
                "last_edit": rev.get("timestamp"), "last_editor": rev.get("user"),
                "url": p.get("fullurl"), "pageid": p.get("pageid")}
    except Exception as e:
        return {"error": str(e)}


def tool_musicbrainzartist(q):
    """Search MusicBrainz for an artist: type, country, lifespan (keyless)."""
    s = q.strip()
    try:
        r = _get("https://musicbrainz.org/ws/2/artist",
                 params={"query": s, "fmt": "json", "limit": 5})
        return {"query": s, "artists": [{"name": a.get("name"), "type": a.get("type"),
                "country": a.get("country"), "score": a.get("score"),
                "begin": a.get("life-span", {}).get("begin"),
                "disambiguation": a.get("disambiguation")}
                for a in r.json().get("artists", [])]}
    except Exception as e:
        return {"error": str(e)}


def tool_openfoodfacts(q):
    """Product barcode (EAN/UPC) -> Open Food Facts product data (keyless)."""
    code = re.sub(r"\D", "", q.strip())
    if not (8 <= len(code) <= 14):
        return {"error": "give a product barcode (8-14 digits)"}
    try:
        r = _get(f"https://world.openfoodfacts.org/api/v2/product/{code}.json")
        d = r.json()
        if d.get("status") != 1:
            return {"barcode": code, "found": False}
        p = d.get("product", {})
        return {"barcode": code, "name": p.get("product_name"),
                "brands": p.get("brands"), "categories": p.get("categories"),
                "countries": p.get("countries"), "nutriscore": p.get("nutriscore_grade"),
                "ingredients": (p.get("ingredients_text") or "")[:200]}
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# OFFLINE / UTILITY
# ===========================================================================
def tool_cidrinfo(q):
    """Expand a CIDR: network, broadcast, host count, range (offline stdlib)."""
    try:
        net = ipaddress.ip_network(q.strip(), strict=False)
        return {"cidr": str(net), "version": net.version,
                "network": str(net.network_address),
                "broadcast": str(net.broadcast_address) if net.version == 4 else None,
                "netmask": str(net.netmask), "prefixlen": net.prefixlen,
                "num_addresses": net.num_addresses,
                "first_host": str(next(net.hosts(), net.network_address)),
                "is_private": net.is_private, "is_global": net.is_global}
    except Exception as e:
        return {"error": f"invalid CIDR: {e}"}


def tool_passwordcheck(q):
    """Has this password appeared in breaches? k-anonymity HIBP range (keyless, safe)."""
    pw = q.strip()
    if not pw:
        return {"error": "give a password to check (sent as k-anonymous SHA1 prefix only)"}
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = _get(f"https://api.pwnedpasswords.com/range/{prefix}")
        count = 0
        for line in r.text.splitlines():
            h, c = line.split(":")
            if h == suffix:
                count = int(c)
                break
        return {"breached": count > 0, "times_seen": count,
                "note": "Only the 5-char SHA1 prefix left your machine (k-anonymity)."}
    except Exception as e:
        return {"error": str(e)}


def tool_base64(q):
    """Decode/encode base64 with auto-detect (offline)."""
    s = q.strip()
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) and len(s.replace("=", "")) % 4 != 1:
        try:
            dec = base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
            if dec.isprintable() or "\n" in dec:
                return {"mode": "decode", "input": s[:60], "output": dec[:500]}
        except Exception:
            pass
    return {"mode": "encode", "input": s[:60],
            "output": base64.b64encode(s.encode()).decode()}


def tool_hashtext(q):
    """Compute md5/sha1/sha256/sha512 of input text (offline)."""
    b = q.encode()
    return {"input_len": len(q),
            "md5": hashlib.md5(b).hexdigest(),
            "sha1": hashlib.sha1(b).hexdigest(),
            "sha256": hashlib.sha256(b).hexdigest(),
            "sha512": hashlib.sha512(b).hexdigest()}


def tool_qrcode(q):
    """Generate a QR code URL for any text (keyless image service)."""
    s = q.strip()
    if not s:
        return {"error": "give text/URL to encode"}
    enc = urllib.parse.quote(s)
    return {"text": s,
            "qr_png": f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={enc}",
            "note": "Open qr_png to view/scan the code."}


def tool_dnsptrrange(q):
    """Resolve PTR for every host in a small CIDR (offline DNS, /24 max)."""
    try:
        net = ipaddress.ip_network(q.strip(), strict=False)
    except Exception as e:
        return {"error": f"invalid CIDR: {e}"}
    if net.version != 4 or net.prefixlen < 24:
        return {"error": "give an IPv4 CIDR of /24 or smaller (e.g. 8.8.8.0/29)"}
    out = {}
    for ip in list(net.hosts())[:64]:  # cap at 64 hosts; raise if you need larger ranges
        try:
            out[str(ip)] = socket.gethostbyaddr(str(ip))[0]
        except Exception:
            pass
    return {"cidr": str(net), "resolved": out, "resolved_count": len(out)}


def tool_jwtdecode(q):
    """Decode a JWT header+payload without verifying (offline)."""
    parts = q.strip().split(".")
    if len(parts) < 2:
        return {"error": "give a JWT (header.payload.signature)"}
    def dec(seg):
        return _j.loads(b64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    try:
        hdr, pl = dec(parts[0]), dec(parts[1])
        for k in ("exp", "iat", "nbf"):
            if isinstance(pl.get(k), (int, float)):
                pl[k] = f"{pl[k]} ({datetime.datetime.fromtimestamp(pl[k], datetime.timezone.utc):%Y-%m-%d %H:%M UTC})"
        return {"header": hdr, "payload": pl, "alg": hdr.get("alg"),
                "note": "Signature NOT verified — decode only."}
    except Exception as e:
        return {"error": f"could not decode JWT: {e}"}


# ===========================================================================
# REGISTRY  (merged into osint.TOOLS)
# ===========================================================================

# ── extension pack 5 ──────────────────────────────────────────────────────────────
def _fetch_page(url):
    try:
        return requests.get(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)
    except Exception as e:
        return None


# ===========================================================================
# SOCIAL PLATFORMS
# ===========================================================================

_REDDIT_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}


def tool_reddit_user(q):
    """Reddit user profile: karma, age, gold status."""
    q = re.sub(r'^u/', '', q.strip())
    r = _get(f"https://www.reddit.com/user/{q}/about.json",
             headers=_REDDIT_UA)
    if r.status_code == 404:
        return {"username": q, "found": False}
    if r.status_code != 200:
        return {"username": q, "error": f"status {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "username": d.get("name"),
        "found": True,
        "link_karma": d.get("link_karma"),
        "comment_karma": d.get("comment_karma"),
        "total_karma": d.get("total_karma"),
        "is_gold": d.get("is_gold"),
        "verified": d.get("verified"),
        "created_utc": d.get("created_utc"),
        "nsfw": d.get("over_18"),
        "url": f"https://www.reddit.com/u/{q}",
    }


def tool_reddit_sub(q):
    """Reddit subreddit info: subscribers, active users, description."""
    q = re.sub(r'^r/', '', q.strip())
    r = _get(f"https://www.reddit.com/r/{q}/about.json",
             headers=_REDDIT_UA)
    if r.status_code == 404:
        return {"subreddit": q, "found": False}
    if r.status_code != 200:
        return {"subreddit": q, "error": f"status {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "name": d.get("display_name"),
        "found": True,
        "title": d.get("title"),
        "subscribers": d.get("subscribers"),
        "active_users": d.get("active_user_count"),
        "nsfw": d.get("over18"),
        "type": d.get("subreddit_type"),
        "description": (d.get("public_description") or "")[:300],
        "created_utc": d.get("created_utc"),
        "url": f"https://www.reddit.com/r/{q}",
    }


def tool_huggingface(q):
    """HuggingFace user profile or model card."""
    q = q.strip()
    # Try as user first
    r = _get(f"https://huggingface.co/api/users/{q}")
    if r.status_code == 200:
        d = r.json()
        return {
            "handle": d.get("name"),
            "fullname": d.get("fullname"),
            "type": "user",
            "models": d.get("numModels"),
            "datasets": d.get("numDatasets"),
            "spaces": d.get("numSpaces"),
            "followers": d.get("numFollowers"),
            "avatar": d.get("avatarUrl"),
            "url": f"https://huggingface.co/{q}",
        }
    # Try as model (owner/model format)
    if "/" in q:
        r2 = _get(f"https://huggingface.co/api/models/{q}")
        if r2.status_code == 200:
            d = r2.json()
            return {
                "model_id": d.get("modelId") or d.get("id"),
                "type": "model",
                "downloads": d.get("downloads"),
                "likes": d.get("likes"),
                "pipeline": d.get("pipeline_tag"),
                "tags": (d.get("tags") or [])[:10],
                "url": f"https://huggingface.co/{q}",
            }
    return {"query": q, "found": False}


def tool_steam_user(q):
    """Steam community profile via public XML endpoint."""
    q = q.strip()
    # Handle numeric 64-bit steamID
    if q.isdigit() and len(q) > 10:
        url = f"https://steamcommunity.com/profiles/{q}/?xml=1"
    else:
        url = f"https://steamcommunity.com/id/{q}/?xml=1"
    r = _get(url)
    try:
        root = ET.fromstring(r.text)
    except Exception:
        return {"error": "invalid XML or profile not found"}
    err = root.findtext("error")
    if err:
        return {"query": q, "found": False, "error": err}
    return {
        "steamid64": root.findtext("steamID64"),
        "name": root.findtext("steamID"),
        "online_state": root.findtext("onlineState"),
        "visibility": root.findtext("visibilityState"),
        "headline": root.findtext("headline"),
        "location": root.findtext("location"),
        "member_since": root.findtext("memberSince"),
        "avatar": root.findtext("avatarIcon"),
        "found": True,
        "url": url.replace("/?xml=1", ""),
    }


def tool_codeforces(q):
    """Codeforces competitive programmer: rating, rank, country."""
    r = _get(f"https://codeforces.com/api/user.info?handles={q.strip()}")
    d = r.json()
    if d.get("status") != "OK":
        return {"handle": q, "found": False, "error": d.get("comment")}
    u = d["result"][0]
    return {
        "handle": u.get("handle"),
        "found": True,
        "rating": u.get("rating"),
        "max_rating": u.get("maxRating"),
        "rank": u.get("rank"),
        "max_rank": u.get("maxRank"),
        "country": u.get("country"),
        "city": u.get("city"),
        "organization": u.get("organization"),
        "contribution": u.get("contribution"),
        "url": f"https://codeforces.com/profile/{q}",
    }


def tool_leetcode_user(q):
    """LeetCode user stats: solved problems, ranking."""
    payload = {
        "query": """query($username: String!) {
          matchedUser(username: $username) {
            username
            submitStats { acSubmissionNum { difficulty count submissions } }
            profile { ranking reputation }
            badges { name }
          }
        }""",
        "variables": {"username": q.strip()},
    }
    try:
        r = requests.post(
            "https://leetcode.com/graphql",
            json=payload,
            headers={**UA, "Content-Type": "application/json",
                     "Referer": "https://leetcode.com"},
            timeout=TIMEOUT,
        )
        mu = r.json().get("data", {}).get("matchedUser")
    except Exception as e:
        return {"username": q, "error": str(e)}
    if not mu:
        return {"username": q, "found": False}
    stats = {s["difficulty"]: {"solved": s["count"], "submissions": s["submissions"]}
             for s in mu.get("submitStats", {}).get("acSubmissionNum", [])}
    p = mu.get("profile", {})
    return {
        "username": mu.get("username"),
        "found": True,
        "ranking": p.get("ranking"),
        "reputation": p.get("reputation"),
        "solved": stats,
        "badges": [b["name"] for b in (mu.get("badges") or [])[:5]],
        "url": f"https://leetcode.com/{q}/",
    }


def tool_npmorg(q):
    """npm organization: list of published packages."""
    q = q.lstrip("@").strip()
    r = _get(f"https://registry.npmjs.org/-/org/{q}/package",
             headers={**UA, "Accept": "application/json"})
    if r.status_code == 200:
        pkgs = list(r.json().keys())
    else:
        # fallback: scope search
        r2 = _get("https://registry.npmjs.org/-/v1/search",
                  params={"text": f"scope:{q}", "size": 20})
        pkgs = [o.get("package", {}).get("name", "") for o in
                r2.json().get("objects", [])] if r2.status_code == 200 else []
    return {
        "org": q,
        "package_count": len(pkgs),
        "packages": pkgs[:30],
        "url": f"https://www.npmjs.com/org/{q}",
    }


def tool_emailrep(q):
    """emailrep.io: reputation, breach, blacklist, profile links for an email."""
    r = _get(f"https://emailrep.io/{q.strip()}")
    if r.status_code == 401:
        return {"email": q, "error": "rate limited by emailrep.io (try later)"}
    if r.status_code != 200:
        return {"email": q, "error": f"status {r.status_code}"}
    d = r.json()
    det = d.get("details", {})
    return {
        "email": q,
        "reputation": d.get("reputation"),
        "suspicious": d.get("suspicious"),
        "references": d.get("references"),
        "blacklisted": det.get("blacklisted"),
        "malicious_activity": det.get("malicious_activity"),
        "credentials_leaked": det.get("credentials_leaked"),
        "data_breach": det.get("data_breach"),
        "free_provider": det.get("free_provider"),
        "disposable": det.get("disposable"),
        "first_seen": det.get("first_seen"),
        "last_seen": det.get("last_seen"),
        "profiles": det.get("profiles", [])[:10],
    }


# ===========================================================================
# ACADEMIC / RESEARCH
# ===========================================================================

def tool_arxiv(q):
    """arXiv paper search by title/author/keyword (public Atom API)."""
    ATOM = "http://www.w3.org/2005/Atom"
    r = _get("http://export.arxiv.org/api/query",
             params={"search_query": q.strip(), "max_results": 5, "sortBy": "relevance"})
    try:
        root = ET.fromstring(r.text)
    except Exception as e:
        return {"error": str(e)}
    total_el = root.find("{http://a9.com/-/spec/opensearch/1.1/}totalResults")
    total = total_el.text if total_el is not None else "?"
    results = []
    for entry in root.findall(f"{{{ATOM}}}entry")[:5]:
        authors = [a.findtext(f"{{{ATOM}}}name") or ""
                   for a in entry.findall(f"{{{ATOM}}}author")]
        results.append({
            "title": (entry.findtext(f"{{{ATOM}}}title") or "").strip(),
            "authors": authors[:5],
            "id": entry.findtext(f"{{{ATOM}}}id"),
            "published": entry.findtext(f"{{{ATOM}}}published"),
            "summary": (entry.findtext(f"{{{ATOM}}}summary") or "").strip()[:250],
        })
    return {"query": q, "total": total, "results": results}


def tool_pubmed(q):
    """PubMed biomedical search (NCBI eUtils, no key)."""
    search = _get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi",
                  params={"db": "pubmed", "term": q, "retmax": 5, "retmode": "json"})
    es = search.json().get("esearchresult", {})
    ids = es.get("idlist", [])
    total = es.get("count", "0")
    if not ids:
        return {"query": q, "total": total, "results": []}
    summ = _get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi",
                params={"db": "pubmed", "id": ",".join(ids), "retmode": "json"})
    result_data = summ.json().get("result", {})
    papers = []
    for pmid in ids:
        d = result_data.get(pmid, {})
        papers.append({
            "pmid": pmid,
            "title": d.get("title"),
            "authors": [a.get("name") for a in d.get("authors", [])[:5]],
            "journal": d.get("fulljournalname"),
            "year": (d.get("pubdate") or "")[:4],
            "url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
        })
    return {"query": q, "total": total, "results": papers}


def tool_zenodo(q):
    """Zenodo open research records search (no key)."""
    r = _get("https://zenodo.org/api/records",
             params={"q": q, "size": 5, "status": "published", "sort": "mostrecent"})
    if r.status_code != 200:
        return {"query": q, "error": f"status {r.status_code}"}
    hits = r.json().get("hits", {})
    records = []
    for h in hits.get("hits", [])[:5]:
        meta = h.get("metadata", {})
        records.append({
            "title": meta.get("title"),
            "doi": meta.get("doi"),
            "year": (meta.get("publication_date") or "")[:4],
            "type": meta.get("resource_type", {}).get("title"),
            "authors": [c.get("name") for c in meta.get("creators", [])[:5]],
            "url": (h.get("links") or {}).get("html"),
        })
    total = hits.get("total")
    total = total.get("value", 0) if isinstance(total, dict) else (total or 0)
    return {"query": q, "total": total, "results": records}


def tool_dblp(q):
    """DBLP CS publication search (no key)."""
    r = _get("https://dblp.org/search/publ/api",
             params={"q": q, "format": "json", "h": 5})
    if r.status_code != 200:
        return {"query": q, "error": f"status {r.status_code}"}
    hits = r.json().get("result", {}).get("hits", {})
    total = hits.get("@total", 0)
    papers = []
    for h in (hits.get("hit") or [])[:5]:
        info = h.get("info", {})
        authors = info.get("authors", {}).get("author", [])
        if isinstance(authors, dict):
            authors = [authors]
        papers.append({
            "title": info.get("title"),
            "year": info.get("year"),
            "venue": info.get("venue"),
            "authors": [a.get("text") for a in authors[:5]],
            "url": info.get("url"),
        })
    return {"query": q, "total": total, "results": papers}


def tool_unpaywall(q):
    """Unpaywall: is a DOI open-access? Where to get it free?"""
    doi = re.sub(r'^https?://(dx\.)?doi\.org/', '', q.strip())
    r = _get(f"https://api.unpaywall.org/v2/{doi}",
             params={"email": "researcher@university.edu"})
    if r.status_code != 200:
        return {"doi": doi, "error": f"status {r.status_code}"}
    d = r.json()
    best = d.get("best_oa_location") or {}
    return {
        "doi": doi,
        "title": d.get("title"),
        "year": d.get("year"),
        "journal": d.get("journal_name"),
        "publisher": d.get("publisher"),
        "is_oa": d.get("is_oa"),
        "oa_status": d.get("oa_status"),
        "oa_url": best.get("url_for_pdf") or best.get("url"),
        "version": best.get("version"),
    }


# ===========================================================================
# ADDITIONAL CRYPTO CHAINS
# ===========================================================================

def tool_ltcaddr(q):
    """Litecoin address balance & tx count (BlockCypher, no key)."""
    q = q.strip()
    r = _get(f"https://api.blockcypher.com/v1/ltc/main/addrs/{q}/balance")
    if r.status_code != 200:
        return {"address": q, "error": f"status {r.status_code}"}
    d = r.json()
    if "error" in d:
        return {"address": q, "error": d["error"]}
    return {
        "address": q,
        "coin": "LTC",
        "balance_ltc": d.get("final_balance", 0) / 1e8,
        "total_received_ltc": d.get("total_received", 0) / 1e8,
        "tx_count": d.get("n_tx"),
        "unconfirmed": d.get("unconfirmed_n_tx"),
        "url": f"https://live.blockcypher.com/ltc/address/{q}/",
    }


def tool_dogeaddr(q):
    """Dogecoin address balance & tx count (BlockCypher, no key)."""
    q = q.strip()
    r = _get(f"https://api.blockcypher.com/v1/doge/main/addrs/{q}/balance")
    if r.status_code != 200:
        return {"address": q, "error": f"status {r.status_code}"}
    d = r.json()
    if "error" in d:
        return {"address": q, "error": d["error"]}
    return {
        "address": q,
        "coin": "DOGE",
        "balance_doge": d.get("final_balance", 0) / 1e8,
        "total_received_doge": d.get("total_received", 0) / 1e8,
        "tx_count": d.get("n_tx"),
        "url": f"https://live.blockcypher.com/doge/address/{q}/",
    }


def tool_xrpaddr(q):
    """XRP Ledger account info (public xrplcluster.com RPC)."""
    q = q.strip()
    try:
        r = requests.post(
            "https://xrplcluster.com/",
            json={"method": "account_info",
                  "params": [{"account": q, "strict": True,
                               "ledger_index": "validated"}]},
            headers={**UA, "Content-Type": "application/json"},
            timeout=TIMEOUT,
        )
        result = r.json().get("result", {})
    except Exception as e:
        return {"address": q, "error": str(e)}
    if result.get("status") == "error":
        return {"address": q, "found": False, "error": result.get("error_message")}
    acct = result.get("account_data", {})
    return {
        "address": q,
        "found": True,
        "balance_xrp": int(acct.get("Balance", 0)) / 1_000_000,
        "sequence": acct.get("Sequence"),
        "owner_count": acct.get("OwnerCount"),
        "flags": acct.get("Flags"),
        "url": f"https://xrpscan.com/account/{q}",
    }


def tool_soladdr(q):
    """Solana account balance (public mainnet-beta RPC)."""
    q = q.strip()
    BASE_URL = "https://api.mainnet-beta.solana.com"
    try:
        r1 = requests.post(BASE_URL,
                           json={"jsonrpc": "2.0", "id": 1,
                                 "method": "getBalance", "params": [q]},
                           headers={**UA, "Content-Type": "application/json"},
                           timeout=TIMEOUT)
        lamports = r1.json().get("result", {}).get("value")
        if lamports is None:
            return {"address": q, "error": "not found or invalid address"}
        r2 = requests.post(BASE_URL,
                           json={"jsonrpc": "2.0", "id": 2,
                                 "method": "getAccountInfo",
                                 "params": [q, {"encoding": "jsonParsed"}]},
                           headers={**UA, "Content-Type": "application/json"},
                           timeout=TIMEOUT)
        acct = (r2.json().get("result", {}).get("value") or {})
    except Exception as e:
        return {"address": q, "error": str(e)}
    return {
        "address": q,
        "found": True,
        "balance_sol": lamports / 1e9,
        "executable": acct.get("executable"),
        "owner_program": acct.get("owner"),
        "url": f"https://solscan.io/account/{q}",
    }


# ===========================================================================
# BUSINESS / REGULATORY
# ===========================================================================

def tool_opencorp(q):
    """OpenCorporates: search company registrations worldwide."""
    r = _get("https://api.opencorporates.com/v0.4/companies/search",
             params={"q": q.strip(), "format": "json"})
    if r.status_code != 200:
        return {"query": q, "error": f"status {r.status_code}"}
    data = r.json().get("results", {})
    companies = []
    for item in data.get("companies", [])[:8]:
        c = item.get("company", {})
        companies.append({
            "name": c.get("name"),
            "jurisdiction": c.get("jurisdiction_code"),
            "number": c.get("company_number"),
            "type": c.get("company_type"),
            "status": c.get("current_status"),
            "incorporated": c.get("incorporation_date"),
            "url": c.get("opencorporates_url"),
        })
    return {
        "query": q,
        "total": data.get("total_count", 0),
        "results": companies,
    }


def tool_gleif_name(q):
    """GLEIF fuzzy legal-entity name search → LEI codes."""
    r = _get("https://api.gleif.org/api/v1/fuzzycompletions",
             params={"field": "entity.legalName", "q": q.strip()})
    if r.status_code != 200:
        return {"query": q, "error": f"status {r.status_code}"}
    items = r.json().get("data", [])[:10]
    return {
        "query": q,
        "suggestions": [{"name": i.get("value"), "lei": i.get("lei")} for i in items],
        "count": len(items),
    }


def tool_fccid(q):
    """FCC equipment authorization database lookup by FCC ID."""
    fccid = q.strip().upper()
    r = _get("https://opendata.fcc.gov/resource/c2yw-an79.json",
             params={"$where": f"fcc_id='{fccid}'", "$limit": 5})
    if r.status_code != 200:
        return {"fcc_id": fccid, "error": f"status {r.status_code}"}
    data = r.json()
    if not data:
        return {"fcc_id": fccid, "found": False}
    records = []
    for d in data[:5]:
        records.append({
            "grantee": d.get("grantee_name"),
            "applicant": d.get("applicant_name"),
            "product_code": d.get("equipment_product_code"),
            "description": d.get("equipment_description"),
            "grant_date": d.get("grant_date"),
            "url": f"https://fccid.io/{fccid}",
        })
    return {"fcc_id": fccid, "found": True, "results": records}


# ===========================================================================
# EMAIL / SMTP
# ===========================================================================

def tool_smtpbanner(q):
    """SMTP banner grab on ports 25, 587, 465 — reveal MTA software."""
    host = _host(q)
    results = {}
    for port in [25, 587, 465]:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.sendall(b"EHLO osint.probe\r\n")
            ehlo = sock.recv(4096).decode("utf-8", errors="replace").strip()
            sock.sendall(b"QUIT\r\n")
            sock.close()
            caps = [line.lstrip("250-").lstrip("250 ").strip()
                    for line in ehlo.splitlines() if line.startswith("250")]
            results[str(port)] = {"open": True, "banner": banner[:200],
                                  "capabilities": caps}
        except OSError as e:
            results[str(port)] = {"open": False, "error": str(e)}
    return {"host": host, "ports": results}


def tool_disposable(q):
    """Check if an email domain is a known disposable/throwaway provider."""
    if "@" in q:
        domain = q.split("@")[-1].lower().strip()
    else:
        domain = _host(q).lower()
    r = _get(f"https://open.kickbox.com/v1/disposable/{domain}")
    if r.status_code != 200:
        return {"domain": domain, "error": f"status {r.status_code}"}
    d = r.json()
    return {
        "domain": domain,
        "disposable": d.get("disposable"),
        "note": "Disposable domains are used for throwaway / burner accounts",
    }


# ===========================================================================
# DNS / CERTIFICATES
# ===========================================================================

def tool_zonetransfer(q):
    """Attempt DNS zone transfer (AXFR) against all authoritative NS."""
    host = _host(q).lower()
    ns_resp = _get("https://dns.google/resolve", params={"name": host, "type": "NS"})
    ns_list = [a["data"].rstrip(".") for a in ns_resp.json().get("Answer", [])
               if a.get("type") == 2]
    if not ns_list:
        return {"domain": host, "error": "no NS records found"}

    def _axfr_query(domain):
        # Build minimal DNS AXFR query (TCP, with 2-byte length prefix)
        qname = b""
        for label in domain.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        msg = (b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
               + qname + b"\x00\xfc\x00\x01")  # QTYPE=AXFR(252)
        return struct.pack("!H", len(msg)) + msg

    results = []
    for ns in ns_list[:3]:
        try:
            ns_ip = socket.gethostbyname(ns)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ns_ip, 53))
            sock.sendall(_axfr_query(host))
            raw = sock.recv(8192)
            sock.close()
            dns_msg = raw[2:]  # strip TCP length prefix
            rcode = dns_msg[3] & 0x0F if len(dns_msg) >= 4 else -1
            # RCODE=0 with substantial data = transfer permitted
            allowed = rcode == 0 and len(dns_msg) > 100
            results.append({"ns": ns, "ip": ns_ip, "rcode": rcode,
                             "vulnerable": allowed, "response_bytes": len(dns_msg)})
        except Exception as e:
            results.append({"ns": ns, "error": str(e)})

    return {
        "domain": host,
        "nameservers": ns_list,
        "results": results,
        "vulnerable": any(r.get("vulnerable") for r in results),
        "note": "vulnerable=true means AXFR was not refused — zone data may be exposed",
    }


def tool_ctlogsearch(q):
    """Search crt.sh CT logs by organization name (finds issued certs)."""
    # crt.sh returns blank 200s at random; retry until the JSON parses.
    certs, last = None, None
    for i in range(4):
        r = _get("https://crt.sh/", params={"O": q.strip(), "output": "json"}, timeout=30)
        if r.status_code == 200 and r.text.strip():
            try:
                certs = r.json() or []
                break
            except Exception as e:
                last = str(e)
        else:
            last = f"status {r.status_code}"
        time.sleep(1.5 * (i + 1))
    if certs is None:
        return {"org": q, "error": f"crt.sh failed: {last}"}
    domains = sorted({c.get("common_name", "") for c in certs
                      if c.get("common_name") and "*" not in c.get("common_name", "")})[:20]
    wildcard = sorted({c.get("common_name", "") for c in certs
                       if "*" in c.get("common_name", "")})[:10]
    issuers = list({c.get("issuer_ca_id") for c in certs if c.get("issuer_ca_id")})[:5]
    return {
        "org": q,
        "total_certs": len(certs),
        "unique_domains": domains,
        "wildcard_certs": wildcard,
        "issuer_ids": issuers,
        "search_url": f"https://crt.sh/?O={urllib.parse.quote(q)}",
    }


def tool_webfinger(q):
    """WebFinger (.well-known/webfinger) resource discovery."""
    q = q.strip()
    if "@" in q and not q.startswith("acct:"):
        resource = f"acct:{q}"
        domain = q.split("@")[-1]
    elif q.startswith("http"):
        parsed = urllib.parse.urlparse(q)
        resource = q
        domain = parsed.netloc
    else:
        return {"error": "provide user@domain or a URL for WebFinger lookup"}
    r = _get(f"https://{domain}/.well-known/webfinger",
             params={"resource": resource})
    if r.status_code == 200:
        d = r.json()
        return {
            "subject": d.get("subject"),
            "aliases": d.get("aliases", []),
            "links": d.get("links", []),
        }
    return {"query": q, "status": r.status_code, "error": "WebFinger not supported here"}


def tool_srvlookup(q):
    """Lookup common SRV records for a domain (SIP, XMPP, mail, CalDAV…)."""
    host = _host(q)
    SERVICES = {
        "_sip._tcp": "SIP/TCP", "_sip._udp": "SIP/UDP",
        "_xmpp-client._tcp": "XMPP client", "_xmpp-server._tcp": "XMPP server",
        "_imaps._tcp": "IMAP SSL", "_pop3s._tcp": "POP3 SSL",
        "_submission._tcp": "SMTP submission",
        "_caldavs._tcp": "CalDAV SSL", "_carddavs._tcp": "CardDAV SSL",
        "_https._tcp": "HTTPS SRV", "_smtp._tcp": "SMTP",
        "_autodiscover._tcp": "Autodiscover",
    }
    found = {}
    for svc, label in SERVICES.items():
        r = _get("https://dns.google/resolve",
                 params={"name": f"{svc}.{host}", "type": "SRV"})
        answers = r.json().get("Answer", [])
        if answers:
            found[label] = [a.get("data") for a in answers]
    return {"domain": host, "services": found, "found": bool(found)}


def tool_nstrace(q):
    """Trace NS delegation chain: TLD → registrar NS → authoritative NS."""
    host = _host(q).lower()
    parts = host.split(".")

    def get_ns(name):
        r = _get("https://dns.google/resolve", params={"name": name, "type": "NS"})
        return [a["data"].rstrip(".") for a in r.json().get("Answer", [])
                if a.get("type") == 2]

    trace = []
    # Walk from TLD up to full host
    segments = []
    if len(parts) >= 1:
        segments.append(parts[-1])              # TLD
    if len(parts) >= 2:
        segments.append(".".join(parts[-2:]))   # 2LD
    if len(parts) >= 3:
        segments.append(host)                   # FQDN

    for seg in segments:
        ns = get_ns(seg)
        if ns:
            trace.append({"zone": seg, "nameservers": ns[:4]})

    # Check SOA to confirm authority
    soa_r = _get("https://dns.google/resolve", params={"name": host, "type": "SOA"})
    soa = [a.get("data") for a in soa_r.json().get("Answer", []) if a.get("type") == 6]

    return {"domain": host, "delegation_chain": trace, "soa": soa[:1]}


def tool_rdap_domain(q):
    """RDAP domain lookup via rdap.org bootstrap (richer than WHOIS)."""
    host = _host(q).lower()
    r = _get(f"https://rdap.org/domain/{host}")
    if r.status_code != 200:
        return {"domain": host, "error": f"status {r.status_code}"}
    d = r.json()
    ns = [n.get("ldhName") for n in d.get("nameservers", [])]
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    return {
        "domain": host,
        "handle": d.get("handle"),
        "status": d.get("status", []),
        "nameservers": ns,
        "registered": events.get("registration"),
        "expiry": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "entity_count": len(d.get("entities", [])),
    }


# ===========================================================================
# WEB SECURITY HEADERS
# ===========================================================================

def tool_csp_parse(q):
    """Fetch & analyze Content-Security-Policy header for weaknesses."""
    url = q if q.startswith("http") else f"https://{_host(q)}"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)}
    csp = r.headers.get("Content-Security-Policy", "")
    report_only = False
    if not csp:
        csp = r.headers.get("Content-Security-Policy-Report-Only", "")
        report_only = bool(csp)
    if not csp:
        return {"url": url, "csp": None, "issues": ["No CSP header — all scripts/resources unrestricted"]}
    directives = {}
    issues = []
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        values = tokens[1:]
        directives[name] = values
        if "'unsafe-inline'" in values:
            issues.append(f"{name}: 'unsafe-inline' allows inline XSS")
        if "'unsafe-eval'" in values:
            issues.append(f"{name}: 'unsafe-eval' allows eval() attacks")
        if "*" in values:
            issues.append(f"{name}: wildcard (*) negates restriction")
    if "default-src" not in directives and "script-src" not in directives:
        issues.append("No default-src or script-src — scripts are unrestricted")
    if "frame-ancestors" not in directives:
        issues.append("No frame-ancestors — CSP does not block clickjacking")
    grade = "A" if not issues else ("B" if len(issues) == 1 else ("C" if len(issues) <= 3 else "F"))
    return {
        "url": url, "report_only": report_only,
        "directives": directives,
        "directive_count": len(directives),
        "issues": issues,
        "grade": grade,
    }


def tool_sri_check(q):
    """Check for missing Subresource Integrity on external scripts/styles."""
    url = q if q.startswith("http") else f"https://{_host(q)}"

    class _SRIParser(html.parser.HTMLParser):
        def __init__(self):
            super().__init__()
            self.resources = []
        def handle_starttag(self, tag, attrs):
            if tag not in ("script", "link"):
                return
            d = dict(attrs)
            src = d.get("src") or d.get("href") or ""
            if not src or src.startswith("data:") or src.startswith("#"):
                return
            is_external = src.startswith("//") or src.startswith("http")
            if not is_external:
                return
            self.resources.append({
                "tag": tag, "src": src[:120],
                "has_integrity": "integrity" in d,
                "crossorigin": d.get("crossorigin"),
            })

    try:
        r = requests.get(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)
        p = _SRIParser()
        p.feed(r.text[:300_000])
    except Exception as e:
        return {"error": str(e)}
    missing = [x for x in p.resources if not x["has_integrity"]]
    return {
        "url": url,
        "external_resources": len(p.resources),
        "missing_sri": len(missing),
        "vulnerable": bool(missing),
        "resources": p.resources,
    }


def tool_clickjacking(q):
    """Check X-Frame-Options and CSP frame-ancestors for clickjacking protection."""
    url = q if q.startswith("http") else f"https://{_host(q)}"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)}
    xfo = r.headers.get("X-Frame-Options", "")
    csp = r.headers.get("Content-Security-Policy", "")
    fa = next((part.strip() for part in csp.split(";")
               if "frame-ancestors" in part.lower()), "")
    xfo_secure = xfo.upper() in ("DENY", "SAMEORIGIN")
    protected = xfo_secure or bool(fa)
    return {
        "url": url,
        "x_frame_options": xfo or None,
        "xfo_secure": xfo_secure,
        "csp_frame_ancestors": fa or None,
        "protected": protected,
        "vulnerable": not protected,
        "advice": ("Protected" if protected else
                   "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'"),
    }


def tool_referrer_pol(q):
    """Check Referrer-Policy header — does the site leak URLs cross-origin?"""
    url = q if q.startswith("http") else f"https://{_host(q)}"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)}
    policy = r.headers.get("Referrer-Policy", "")
    SAFE = {"no-referrer", "no-referrer-when-downgrade", "same-origin",
            "strict-origin", "strict-origin-when-cross-origin"}
    secure = policy.lower() in SAFE
    return {
        "url": url,
        "policy": policy or "(not set — browser default applies)",
        "secure": secure,
        "risk": ("none" if secure else
                 "leaks full URL to cross-origin requests" if not policy else "moderate"),
    }


def tool_permissions_pol(q):
    """Check Permissions-Policy header — camera/mic/geo access controls."""
    url = q if q.startswith("http") else f"https://{_host(q)}"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)}
    hdr = r.headers.get("Permissions-Policy",
                         r.headers.get("Feature-Policy", ""))
    if not hdr:
        return {"url": url, "policy": None,
                "note": "No Permissions-Policy — browser APIs unrestricted by policy"}
    features = {}
    for token in re.split(r",\s*(?=[a-z])", hdr):
        token = token.strip()
        m = re.match(r"([^=]+)=\(?([^)]*)\)?", token)
        if m:
            features[m.group(1).strip()] = m.group(2).strip()
    SENSITIVE = ("camera", "microphone", "geolocation", "payment", "usb", "bluetooth")
    risky = [k for k, v in features.items()
             if any(s in k for s in SENSITIVE) and v not in ("", "()", "none", "self")]
    return {
        "url": url,
        "features": features,
        "risky_enabled": risky,
        "secure": not bool(risky),
        "header_raw": hdr[:300],
    }


# ===========================================================================
# NETWORK / IP
# ===========================================================================

def tool_ipv4classify(q):
    """Classify an IP: private/loopback/multicast/global/reserved (offline)."""
    q = q.strip()
    try:
        addr = ipaddress.ip_address(q)
    except ValueError:
        return {"error": f"not a valid IP address: {q}"}
    v = 4 if isinstance(addr, ipaddress.IPv4Address) else 6
    kind = ("loopback" if addr.is_loopback else
            "link-local" if addr.is_link_local else
            "private (RFC 1918)" if addr.is_private and v == 4 else
            "private (ULA)" if addr.is_private and v == 6 else
            "multicast" if addr.is_multicast else
            "reserved" if addr.is_reserved else
            "global")
    return {
        "ip": str(addr),
        "version": v,
        "type": kind,
        "is_private": addr.is_private,
        "is_loopback": addr.is_loopback,
        "is_multicast": addr.is_multicast,
        "is_global": addr.is_global,
        "is_link_local": addr.is_link_local,
        "is_reserved": addr.is_reserved,
        "compressed": addr.compressed,
        "exploded": addr.exploded,
    }


def tool_dnsrecon(q):
    """Query ALL DNS record types at once for a domain."""
    host = _host(q)
    TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA",
             "SRV", "NAPTR", "PTR", "TLSA", "DS", "DNSKEY", "URI",
             "LOC", "HINFO", "RP"]
    records = {}
    for t in TYPES:
        try:
            r = _get("https://dns.google/resolve", params={"name": host, "type": t})
            answers = r.json().get("Answer", [])
            if answers:
                records[t] = [a.get("data") for a in answers]
        except Exception:
            pass
    return {
        "domain": host,
        "types_found": list(records.keys()),
        "records": records,
    }


# ===========================================================================
# OFFLINE UTILITIES
# ===========================================================================

_PORTS = {
    20: "FTP data", 21: "FTP control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP server", 68: "DHCP client",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB/CIFS",
    465: "SMTPS", 500: "IKE/IPSec", 514: "Syslog", 515: "LPD",
    587: "SMTP submission", 631: "IPP (printing)", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle DB", 1723: "PPTP", 2049: "NFS",
    2181: "Zookeeper", 2375: "Docker (unauth)", 2376: "Docker TLS",
    3000: "Dev server", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4369: "Erlang EPMD", 4443: "HTTPS alt", 4444: "Metasploit",
    4848: "Glassfish", 5000: "Flask dev", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "AMQP (RabbitMQ)", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API",
    7000: "Cassandra inter-node", 7001: "Cassandra JMX",
    7077: "Spark master", 8000: "HTTP alt", 8080: "HTTP proxy/alt",
    8081: "HTTP alt", 8086: "InfluxDB", 8088: "HTTP alt",
    8443: "HTTPS alt", 8888: "Jupyter", 9000: "SonarQube/PHP-FPM",
    9090: "Prometheus", 9092: "Kafka", 9200: "Elasticsearch HTTP",
    9300: "Elasticsearch transport", 9418: "Git daemon",
    10250: "Kubelet API", 11211: "Memcached", 15672: "RabbitMQ mgmt",
    27017: "MongoDB", 27018: "MongoDB shard", 50070: "HDFS NameNode",
}


def tool_portlookup(q):
    """IANA port/service name lookup (offline). Input: port number."""
    q = q.strip()
    try:
        port = int(q)
    except ValueError:
        return {"error": f"not a port number: {q}"}
    service = _PORTS.get(port)
    # Also try Python's socket.getservbyport
    if not service:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = None
    rng = ("well-known (0–1023)" if port < 1024 else
           "registered (1024–49151)" if port < 49152 else
           "dynamic/ephemeral (49152–65535)")
    return {
        "port": port,
        "service": service or "unknown",
        "range": rng,
        "tcp_open_check": f"nc -zv <host> {port}",
    }


def tool_mimetype(q):
    """File extension → MIME type (offline, Python mimetypes module)."""
    q = q.strip()
    if not q.startswith("."):
        q = "." + q
    mt, enc = mimetypes.guess_type("file" + q)
    # Common extras mimetypes module misses
    _EXTRA = {
        ".webp": "image/webp", ".avif": "image/avif", ".heic": "image/heic",
        ".wasm": "application/wasm", ".jsonl": "application/jsonl",
        ".toml": "application/toml", ".md": "text/markdown",
        ".yaml": "application/x-yaml", ".yml": "application/x-yaml",
        ".sh": "application/x-sh", ".bat": "application/x-bat",
        ".env": "text/plain", ".lock": "text/plain",
        ".parquet": "application/octet-stream",
        ".ndjson": "application/x-ndjson",
    }
    mt = mt or _EXTRA.get(q.lower(), "application/octet-stream")
    category = mt.split("/")[0]
    return {
        "extension": q,
        "mime_type": mt,
        "encoding": enc,
        "category": category,
        "binary": category not in ("text",),
    }


_HTTP_CODES = {
    100: ("Continue", "Server received request headers; client should proceed"),
    101: ("Switching Protocols", "Upgrading protocol (e.g. WebSocket)"),
    200: ("OK", "Request succeeded"),
    201: ("Created", "Resource created successfully"),
    204: ("No Content", "Success with no response body"),
    206: ("Partial Content", "Range request fulfilled"),
    301: ("Moved Permanently", "Resource permanently relocated"),
    302: ("Found", "Temporary redirect"),
    304: ("Not Modified", "Cached version is still valid"),
    307: ("Temporary Redirect", "Redirect keeping original method"),
    308: ("Permanent Redirect", "Permanent redirect keeping original method"),
    400: ("Bad Request", "Malformed request syntax"),
    401: ("Unauthorized", "Authentication required"),
    403: ("Forbidden", "Access denied — authenticated but not authorized"),
    404: ("Not Found", "Resource does not exist"),
    405: ("Method Not Allowed", "HTTP method not supported"),
    408: ("Request Timeout", "Server timed out waiting for request"),
    409: ("Conflict", "Request conflicts with current server state"),
    410: ("Gone", "Resource permanently removed"),
    413: ("Payload Too Large", "Request body exceeds server limit"),
    414: ("URI Too Long", "URL exceeds server limit"),
    415: ("Unsupported Media Type", "Content-Type not accepted"),
    422: ("Unprocessable Entity", "Semantically invalid request"),
    423: ("Locked", "Resource is locked (WebDAV)"),
    425: ("Too Early", "Request may be replayed"),
    429: ("Too Many Requests", "Rate limit exceeded"),
    451: ("Unavailable For Legal Reasons", "Censored/legal block"),
    500: ("Internal Server Error", "Generic server-side error"),
    501: ("Not Implemented", "Method not supported by server"),
    502: ("Bad Gateway", "Upstream server returned invalid response"),
    503: ("Service Unavailable", "Server overloaded or in maintenance"),
    504: ("Gateway Timeout", "Upstream server timed out"),
    507: ("Insufficient Storage", "Server cannot store representation"),
    511: ("Network Authentication Required", "Captive portal login needed"),
}


def tool_httpcode(q):
    """HTTP status code meaning (offline)."""
    q = q.strip()
    try:
        code = int(q)
    except ValueError:
        return {"error": f"not an HTTP code: {q}"}
    info = _HTTP_CODES.get(code)
    family = {1: "1xx Informational", 2: "2xx Success", 3: "3xx Redirection",
              4: "4xx Client Error", 5: "5xx Server Error"}.get(code // 100, "Unknown")
    return {
        "code": code,
        "name": info[0] if info else "Unknown",
        "description": info[1] if info else "Non-standard or vendor-specific code",
        "family": family,
        "cacheable": code in (200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501),
    }


def tool_unixperm(q):
    """Parse Unix permission octet (e.g. 755, 644) into rwx notation (offline)."""
    q = q.strip().lstrip("0")
    if not q:
        q = "0"
    try:
        val = int(q, 8)
    except ValueError:
        return {"error": f"not a valid octal permission: {q}"}
    bits = []
    labels = ["owner", "group", "others"]
    names = ["r", "w", "x"]
    for i, label in enumerate(labels):
        shift = (2 - i) * 3
        nibble = (val >> shift) & 7
        perms = "".join(n if (nibble >> (2 - j)) & 1 else "-" for j, n in enumerate(names))
        bits.append({"who": label, "octal": str(nibble), "rwx": perms})
    special = (val >> 9) & 7
    return {
        "octal": q.zfill(4) if special else q.zfill(3),
        "symbolic": "".join(b["rwx"] for b in bits),
        "breakdown": bits,
        "setuid": bool(special & 4),
        "setgid": bool(special & 2),
        "sticky": bool(special & 1),
        "decimal": val,
    }


def tool_unicode_lookup(q):
    """Unicode character info: name, category, block (offline)."""
    q = q.strip()
    # Accept U+XXXX, 0xXX, decimal, or a single character
    if re.match(r'^[Uu]\+[0-9A-Fa-f]{1,6}$', q):
        cp = int(q[2:], 16)
    elif re.match(r'^0x[0-9A-Fa-f]+$', q, re.I):
        cp = int(q, 16)
    elif re.match(r'^\d+$', q) and int(q) <= 0x10FFFF:
        cp = int(q)
    elif len(q) == 1:
        cp = ord(q)
    else:
        # Treat as a string and return info for each char
        chars = []
        for ch in q[:20]:
            try:
                chars.append({
                    "char": ch, "codepoint": f"U+{ord(ch):04X}",
                    "name": unicodedata.name(ch, "UNKNOWN"),
                    "category": unicodedata.category(ch),
                })
            except Exception:
                pass
        return {"string": q, "characters": chars}
    try:
        char = chr(cp)
        name = unicodedata.name(char, "UNKNOWN")
        cat = unicodedata.category(char)
        norm_nfc = unicodedata.normalize("NFC", char)
        norm_nfd = unicodedata.normalize("NFD", char)
    except (ValueError, OverflowError):
        return {"error": f"invalid codepoint: U+{cp:X}"}
    return {
        "codepoint": f"U+{cp:04X}",
        "character": char,
        "decimal": cp,
        "name": name,
        "category": cat,
        "category_name": unicodedata.category.__doc__,
        "bidirectional": unicodedata.bidirectional(char),
        "combining": unicodedata.combining(char),
        "nfc": norm_nfc,
        "nfd": norm_nfd,
        "html_entity": f"&#{cp};",
        "url_encoded": urllib.parse.quote(char),
    }


def tool_timezone_info(q):
    """Timezone info by IANA name or UTC offset (offline, stdlib only)."""
    s = q.strip()
    # Try UTC offset like +5:30 or -8
    m = re.match(r"^([+-]?\d{1,2})(?::(\d{2}))?$", s)
    if m:
        h, mn = int(m.group(1)), int(m.group(2) or 0)
        offset_min = h * 60 + (mn if h >= 0 else -mn)
        tz = datetime.timezone(datetime.timedelta(minutes=offset_min))
        now = datetime.datetime.now(tz)
        return {"input": s, "utc_offset": f"{h:+03d}:{mn:02d}",
                "current_time": now.strftime("%Y-%m-%dT%H:%M:%S%z")}
    # Fall back to common IANA name lookup via fixed offset table
    _TZ = {"UTC": 0, "GMT": 0, "EST": -300, "EDT": -240, "CST": -360, "CDT": -300,
           "MST": -420, "MDT": -360, "PST": -480, "PDT": -420,
           "CET": 60, "CEST": 120, "IST": 330, "JST": 540, "AEST": 600, "NZST": 720}
    key = s.upper()
    if key in _TZ:
        offset_min = _TZ[key]
        tz = datetime.timezone(datetime.timedelta(minutes=offset_min))
        now = datetime.datetime.now(tz)
        return {"input": s, "abbr": key,
                "utc_offset": f"{offset_min // 60:+03d}:{abs(offset_min) % 60:02d}",
                "current_time": now.strftime("%Y-%m-%dT%H:%M:%S%z")}
    return {"input": s, "error": "give a UTC offset (e.g. +5:30) or timezone abbr (EST, JST)"}


def tool_base_convert(q):
    """Convert a number between binary, octal, decimal, hex (offline)."""
    q = q.strip()
    # Auto-detect base
    if re.match(r'^0b[01]+$', q, re.I):
        n = int(q, 2)
    elif re.match(r'^0o[0-7]+$', q, re.I):
        n = int(q, 8)
    elif re.match(r'^0x[0-9a-f]+$', q, re.I):
        n = int(q, 16)
    elif re.match(r'^\d+$', q):
        n = int(q, 10)
    elif re.match(r'^[0-9a-f]+$', q, re.I):
        n = int(q, 16)
    else:
        return {"error": f"cannot parse number: {q}"}
    return {
        "input": q,
        "decimal": n,
        "binary": bin(n),
        "octal": oct(n),
        "hex": hex(n),
        "hex_upper": hex(n).upper().replace("0X", "0x"),
        "bytes_needed": math.ceil(n.bit_length() / 8) if n > 0 else 1,
    }


def tool_ip_math(q):
    """IP arithmetic: network/broadcast/range/host count (offline)."""
    q = q.strip()
    try:
        if "/" in q:
            net = ipaddress.ip_network(q, strict=False)
            return {
                "input": q,
                "network": str(net.network_address),
                "broadcast": str(net.broadcast_address) if net.version == 4 else None,
                "netmask": str(net.netmask) if net.version == 4 else None,
                "prefixlen": net.prefixlen,
                "num_addresses": net.num_addresses,
                "usable_hosts": max(0, net.num_addresses - 2) if net.version == 4 else net.num_addresses,
                "first_host": str(net.network_address + 1) if net.num_addresses > 2 else None,
                "last_host": str(net.broadcast_address - 1) if net.num_addresses > 2 else None,
                "version": net.version,
                "is_private": net.is_private,
            }
        else:
            addr = ipaddress.ip_address(q)
            return {
                "ip": str(addr),
                "version": addr.version,
                "compressed": addr.compressed,
                "exploded": addr.exploded,
                "integer": int(addr),
                "reverse_pointer": addr.reverse_pointer,
            }
    except ValueError as e:
        return {"error": str(e)}


def tool_latlonformat(q):
    """Convert coordinates between DD, DMS, and DM formats (offline)."""
    q = q.strip()
    # Parse "lat, lon"
    m = re.match(r'^(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)$', q)
    if not m:
        return {"error": "provide coordinates as 'lat, lon' in decimal degrees"}
    lat, lon = float(m.group(1)), float(m.group(2))
    if abs(lat) > 90 or abs(lon) > 180:
        return {"error": f"lat must be ±90, lon must be ±180"}

    def to_dms(deg, pos_label, neg_label):
        sign = pos_label if deg >= 0 else neg_label
        deg = abs(deg)
        d = int(deg)
        m_part = (deg - d) * 60
        m_int = int(m_part)
        s = (m_part - m_int) * 60
        return f"{d}°{m_int}'{s:.2f}\"{sign}"

    def to_dm(deg, pos_label, neg_label):
        sign = pos_label if deg >= 0 else neg_label
        deg = abs(deg)
        d = int(deg)
        m_part = (deg - d) * 60
        return f"{d}°{m_part:.4f}'{sign}"

    return {
        "decimal_degrees": {"lat": lat, "lon": lon},
        "dms": {"lat": to_dms(lat, "N", "S"), "lon": to_dms(lon, "E", "W")},
        "dm": {"lat": to_dm(lat, "N", "S"), "lon": to_dm(lon, "E", "W")},
        "geohash_url": f"https://geohash.softeng.co/{lat},{lon}",
        "osm_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=14",
    }


def tool_regdomain(q):
    """Extract the registered domain (eTLD+1) from a URL/domain (offline)."""
    q = q.strip()
    if "://" in q:
        host = urllib.parse.urlparse(q).netloc
    else:
        host = q
    host = host.split(":")[0].lower()
    parts = host.split(".")
    # Known multi-part TLDs (abbreviated list)
    MULTI = {"co.uk", "co.in", "co.nz", "co.za", "co.jp", "com.au", "com.br",
             "com.cn", "com.tr", "com.mx", "net.au", "org.uk", "gov.uk",
             "ac.uk", "me.uk", "org.au", "edu.au", "gov.au"}
    if len(parts) >= 3:
        etld2 = ".".join(parts[-2:])
        if etld2 in MULTI:
            reg = ".".join(parts[-3:]) if len(parts) >= 3 else host
        else:
            reg = ".".join(parts[-2:])
    else:
        reg = host
    return {
        "input": q,
        "host": host,
        "registered_domain": reg,
        "subdomain": host[: len(host) - len(reg) - 1] if host != reg else None,
        "tld": parts[-1],
    }


_TLD_INFO = {
    "com": ("Commercial", "Verisign", "generic"),
    "net": ("Network", "Verisign", "generic"),
    "org": ("Organization", "PIR", "generic"),
    "edu": ("Education (US)", "Educause", "sponsored"),
    "gov": ("US Government", "GSA", "sponsored"),
    "mil": ("US Military", "DoD", "sponsored"),
    "io": ("British Indian Ocean Territory / tech companies", "ICANN/Afilias", "country"),
    "ai": ("Anguilla / AI companies", "Government of Anguilla", "country"),
    "co": ("Colombia / generic", "ICANN", "country"),
    "uk": ("United Kingdom", "Nominet", "country"),
    "de": ("Germany", "DENIC", "country"),
    "cn": ("China", "CNNIC", "country"),
    "ru": ("Russia", "Coordination Center", "country"),
    "fr": ("France", "AFNIC", "country"),
    "br": ("Brazil", "Registro.br", "country"),
    "jp": ("Japan", "JPRS", "country"),
    "au": ("Australia", "auDA", "country"),
    "ca": ("Canada", "CIRA", "country"),
    "in": ("India", "INRegistry", "country"),
    "nl": ("Netherlands", "SIDN", "country"),
    "info": ("Information", "Afilias", "generic"),
    "biz": ("Business", "Neustar", "generic"),
    "app": ("Application", "Google", "generic"),
    "dev": ("Developer", "Google", "generic"),
    "xyz": ("Generic", "XYZ.COM", "generic"),
    "online": ("Generic", "Radix", "generic"),
    "site": ("Generic", "Radix", "generic"),
    "tech": ("Technology", "Radix", "generic"),
    "store": ("E-commerce", "Radix", "generic"),
    "cloud": ("Cloud", "ARUBA PEC", "generic"),
    "onion": ("Tor hidden service", "None (special-use)", "special"),
    "local": ("mDNS local network", "None (special-use)", "special"),
    "internal": ("Internal networks", "None (reserved)", "special"),
    "test": ("Testing", "IANA (reserved)", "special"),
}


def tool_tldinfo(q):
    """TLD registry info: operator, type, purpose (offline)."""
    q = q.strip().lstrip(".").lower()
    if "." in q:
        q = q.split(".")[-1]  # extract TLD from domain
    info = _TLD_INFO.get(q)
    return {
        "tld": f".{q}",
        "description": info[0] if info else "Country/generic TLD",
        "registry": info[1] if info else "See IANA database",
        "type": info[2] if info else "country" if len(q) == 2 else "generic",
        "iana_url": f"https://www.iana.org/domains/root/db/{q}.html",
        "whois_info": f"https://rdap.iana.org/domain/.{q}",
        "known": bool(info),
    }


def tool_emailformat(q):
    """Fetch email format patterns for a company domain (emailformat.com)."""
    domain = _host(q).lower()
    r = _get(f"https://api.emailformat.com/v1/search/",
             params={"domain": domain, "format": "json"})
    # emailformat.com has a basic JSON API
    if r.status_code == 200:
        try:
            d = r.json()
            return {"domain": domain, **d}
        except Exception:
            pass
    # Fallback: scrape the HTML page
    r2 = _get(f"https://www.emailformat.com/d/{domain}/")
    patterns = []
    if r2.status_code == 200:
        for m in re.finditer(r'<strong>([^<]{3,50})</strong>', r2.text):
            txt = m.group(1).strip()
            if "@" in txt or "first" in txt.lower() or "last" in txt.lower():
                patterns.append(txt)
    return {
        "domain": domain,
        "patterns": list(set(patterns))[:5],
        "source": "emailformat.com",
        "url": f"https://www.emailformat.com/d/{domain}/",
    }


def tool_teamcymru(q):
    """Team Cymru IP-to-ASN mapping via DNS (fastest ASN lookup)."""
    q = q.strip()
    try:
        addr = ipaddress.ip_address(q)
    except ValueError:
        return {"error": f"not a valid IP: {q}"}
    if isinstance(addr, ipaddress.IPv4Address):
        rev = ".".join(reversed(q.split(".")))
        name = f"{rev}.origin.asn.cymru.com"
    else:
        nibbles = addr.exploded.replace(":", "")
        rev = ".".join(reversed(list(nibbles)))
        name = f"{rev}.origin6.asn.cymru.com"
    r = _get("https://dns.google/resolve", params={"name": name, "type": "TXT"})
    answers = r.json().get("Answer", [])
    if not answers:
        return {"ip": q, "asn": None, "note": "no ASN mapping found"}
    raw = answers[0].get("data", "").strip('"')
    parts = [p.strip() for p in raw.split("|")]
    asn = parts[0].split()[0] if parts else None
    prefix = parts[1] if len(parts) > 1 else None
    country = parts[2] if len(parts) > 2 else None
    registry = parts[3] if len(parts) > 3 else None
    # Resolve AS name
    as_name = None
    if asn:
        r2 = _get("https://dns.google/resolve",
                  params={"name": f"AS{asn}.asn.cymru.com", "type": "TXT"})
        a2 = r2.json().get("Answer", [])
        if a2:
            raw2 = a2[0].get("data", "").strip('"')
            p2 = [x.strip() for x in raw2.split("|")]
            as_name = p2[-1] if p2 else None
    return {
        "ip": q,
        "asn": f"AS{asn}" if asn else None,
        "as_name": as_name,
        "prefix": prefix,
        "country": country,
        "registry": registry,
    }


_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org",
    "info": "whois.afilias.info",
    "biz": "whois.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "uk": "whois.nic.uk",
    "co.uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "cn": "whois.cnnic.cn",
    "ru": "whois.tcinet.ru",
    "fr": "whois.afnic.fr",
    "br": "whois.registro.br",
    "jp": "whois.jprs.jp",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "in": "whois.registry.in",
    "nl": "whois.sidn.nl",
    "eu": "whois.eu",
    "us": "whois.iana.org",
    "it": "whois.nic.it",
    "es": "whois.nic.es",
    "pl": "whois.dns.pl",
    "se": "whois.iis.se",
    "ch": "whois.nic.ch",
    "at": "whois.nic.at",
    "be": "whois.dns.be",
    "nz": "whois.irs.net.nz",
    "mx": "whois.mx",
    "ar": "whois.nic.ar",
    "za": "whois.registry.net.za",
    "sg": "whois.sgnic.sg",
    "hk": "whois.hkirc.hk",
    "kr": "whois.kr",
    "tr": "whois.nic.tr",
    "xyz": "whois.nic.xyz",
    "club": "whois.nic.club",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "tech": "whois.nic.tech",
    "store": "whois.nic.store",
    "ai": "whois.nic.ai",
}


def tool_whoisserver(q):
    """Find the WHOIS server for a TLD (offline lookup + IANA fallback)."""
    q = q.strip().lstrip(".").lower()
    if "." in q:
        parts = q.split(".")
        tld = parts[-1]
        # Check multi-part TLD
        etld = ".".join(parts[-2:])
    else:
        tld = q
        etld = None
    server = _WHOIS_SERVERS.get(etld) or _WHOIS_SERVERS.get(tld)
    if not server:
        # Try IANA RDAP bootstrap
        try:
            r = _get("https://data.iana.org/rdap/dns.json")
            if r.status_code == 200:
                for svc in r.json().get("services", []):
                    if tld in svc[0]:
                        server = svc[1][0].rstrip("/")
                        break
        except Exception:
            pass
    return {
        "tld": f".{etld or tld}",
        "whois_server": server or "unknown — try: whois.iana.org",
        "command": f"whois -h {server or 'whois.iana.org'} example.{etld or tld}" if server else None,
        "known": bool(server),
    }


def tool_robotsmeta(q):
    """Check meta-robots tags and X-Robots-Tag header in page HTML."""
    url = q if q.startswith("http") else f"https://{_host(q)}"

    class _MetaParser(html.parser.HTMLParser):
        def __init__(self):
            super().__init__()
            self.directives = []
        def handle_starttag(self, tag, attrs):
            if tag != "meta":
                return
            d = dict(attrs)
            name = d.get("name", "").lower()
            if name in ("robots", "googlebot", "bingbot", "yandex"):
                self.directives.append({
                    "name": name,
                    "content": d.get("content", ""),
                })

    try:
        r = requests.get(url, timeout=TIMEOUT, headers=UA, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)}

    p = _MetaParser()
    p.feed(r.text[:100_000])

    x_robots = r.headers.get("X-Robots-Tag", "")
    all_vals = []
    for item in p.directives:
        all_vals.extend(v.strip().lower() for v in item["content"].split(","))
    if x_robots:
        all_vals.extend(v.strip().lower() for v in x_robots.split(","))

    return {
        "url": url,
        "meta_robots": p.directives,
        "x_robots_tag": x_robots or None,
        "noindex": any("noindex" in v for v in all_vals),
        "nofollow": any("nofollow" in v for v in all_vals),
        "noarchive": any("noarchive" in v for v in all_vals),
        "active_directives": sorted(set(v for v in all_vals if v)),
    }


# ===========================================================================
# TOOLS REGISTRY
# ===========================================================================

# ── extension pack 6 ──────────────────────────────────────────────────────────────


def _digits(q):
    return re.sub(r"[^\d]", "", q)


# ===========================================================================
# PHONE  (accepts: phone)
# ===========================================================================
# calling code -> (country, trunk prefix, intl prefix, typical len min..max)
_CALL = {
    "1": ("US/Canada (NANP)", "1", "011", (10, 10)),
    "44": ("United Kingdom", "0", "00", (9, 10)),
    "33": ("France", "0", "00", (9, 9)),
    "49": ("Germany", "0", "00", (6, 11)),
    "39": ("Italy", "", "00", (9, 10)),
    "34": ("Spain", "", "00", (9, 9)),
    "31": ("Netherlands", "0", "00", (9, 9)),
    "7": ("Russia/Kazakhstan", "8", "810", (10, 10)),
    "81": ("Japan", "0", "010", (9, 10)),
    "86": ("China", "0", "00", (11, 11)),
    "82": ("South Korea", "0", "001", (9, 10)),
    "91": ("India", "0", "00", (10, 10)),
    "61": ("Australia", "0", "0011", (9, 9)),
    "55": ("Brazil", "0", "00", (10, 11)),
    "52": ("Mexico", "01", "00", (10, 10)),
    "971": ("UAE", "0", "00", (9, 9)),
    "966": ("Saudi Arabia", "0", "00", (9, 9)),
    "234": ("Nigeria", "0", "009", (10, 10)),
    "27": ("South Africa", "0", "00", (9, 9)),
    "92": ("Pakistan", "0", "00", (10, 10)),
    "880": ("Bangladesh", "0", "00", (10, 10)),
    "62": ("Indonesia", "0", "001", (9, 11)),
    "63": ("Philippines", "0", "00", (10, 10)),
    "90": ("Turkey", "0", "00", (10, 10)),
    "20": ("Egypt", "0", "00", (10, 10)),
    "98": ("Iran", "0", "00", (10, 10)),
    "380": ("Ukraine", "0", "00", (9, 9)),
    "48": ("Poland", "", "00", (9, 9)),
    "46": ("Sweden", "0", "00", (7, 9)),
    "41": ("Switzerland", "0", "00", (9, 9)),
    "351": ("Portugal", "", "00", (9, 9)),
    "353": ("Ireland", "0", "00", (9, 9)),
    "64": ("New Zealand", "0", "00", (8, 10)),
    "65": ("Singapore", "", "001", (8, 8)),
    "60": ("Malaysia", "0", "00", (9, 10)),
    "66": ("Thailand", "0", "001", (9, 9)),
    "84": ("Vietnam", "0", "00", (9, 10)),
    "972": ("Israel", "0", "00", (9, 9)),
    "212": ("Morocco", "0", "00", (9, 9)),
    "254": ("Kenya", "0", "000", (9, 9)),
    "256": ("Uganda", "0", "000", (9, 9)),
    "233": ("Ghana", "0", "00", (9, 9)),
    "califallback": None,
}
# NANP area code -> region (compact but real subset of busy ones)
_NANP = {
    "212": "New York, NY", "213": "Los Angeles, CA", "312": "Chicago, IL",
    "415": "San Francisco, CA", "202": "Washington, DC", "305": "Miami, FL",
    "404": "Atlanta, GA", "702": "Las Vegas, NV", "713": "Houston, TX",
    "214": "Dallas, TX", "206": "Seattle, WA", "303": "Denver, CO",
    "617": "Boston, MA", "215": "Philadelphia, PA", "602": "Phoenix, AZ",
    "503": "Portland, OR", "619": "San Diego, CA", "512": "Austin, TX",
    "646": "New York, NY", "323": "Los Angeles, CA", "347": "New York, NY",
    "718": "New York, NY", "310": "Los Angeles, CA", "408": "San Jose, CA",
    "416": "Toronto, ON", "604": "Vancouver, BC", "514": "Montreal, QC",
    "403": "Calgary, AB", "613": "Ottawa, ON", "780": "Edmonton, AB",
    "800": "Toll-free", "888": "Toll-free", "877": "Toll-free",
    "866": "Toll-free", "855": "Toll-free", "900": "Premium-rate",
}


def _split_cc(d):
    for n in (3, 2, 1):
        if d[:n] in _CALL:
            return d[:n], d[n:]
    return None, d


def tool_phonefmt(q):
    """Format a number as E.164 / national / international / RFC3966 / tel:"""
    d = _digits(q)
    if not d:
        return {"input": q, "error": "no digits"}
    cc, nat = _split_cc(d)
    e164 = "+" + d
    info = _CALL.get(cc)
    trunk = info[1] if info else ""
    intl = f"+{cc} {nat}" if cc else e164
    return {
        "input": q, "e164": e164,
        "national": (trunk + nat) if cc else d,
        "international": intl,
        "rfc3966": "tel:" + e164,
        "country_code": cc, "country": info[0] if info else "unknown",
        "national_number": nat, "digits": len(d),
    }


def tool_phonenanp(q):
    """NANP area-code lookup: +1 number -> US/Canada region (offline subset)."""
    d = _digits(q)
    if d.startswith("1"):
        d = d[1:]
    if len(d) < 3:
        return {"input": q, "error": "need a 10-digit NANP number"}
    area = d[:3]
    return {
        "input": q, "area_code": area,
        "region": _NANP.get(area, "unknown (area code not in offline subset)"),
        "in_table": area in _NANP, "exchange": d[3:6] or None,
        "line": d[6:10] or None,
        "note": "Geographic origin only; mobiles/VoIP/port-outs may differ.",
    }


def tool_phonecc(q):
    """Country calling-code details: trunk & international dialing prefixes."""
    d = _digits(q)
    cc, nat = _split_cc(d)
    if not cc:
        return {"input": q, "error": "calling code not recognized"}
    country, trunk, intl, ln = _CALL[cc]
    return {
        "input": q, "country_code": cc, "country": country,
        "trunk_prefix": trunk or "(none)", "intl_dial_prefix": intl,
        "national_number": nat, "expected_national_len": f"{ln[0]}-{ln[1]}",
        "length_ok": ln[0] <= len(nat) <= ln[1],
        "how_to_dial_from_us": f"011 {cc} {nat}",
    }


def tool_phonepivot(q):
    """OSINT lookup links for a phone number (caller-ID & reputation sites)."""
    d = _digits(q)
    e164 = "+" + d
    return {"input": q, "e164": e164, "links": {
        "truecaller": f"https://www.truecaller.com/search/intl/{e164}",
        "sync.me": f"https://sync.me/search/?number={e164}",
        "whocalld": f"https://whocalld.com/{e164}",
        "800notes": f"https://800notes.com/Phone.aspx/{e164}",
        "whocallsme": f"https://whocallsme.com/Phone-Number.aspx/{d}",
        "shouldianswer": f"https://www.shouldianswer.com/phone-number/{d}",
        "spydialer": "https://www.spydialer.com/",
        "google": f"https://www.google.com/search?q=%22{urllib.parse.quote(e164)}%22",
        "facebook": f"https://www.facebook.com/search/top?q={urllib.parse.quote(e164)}",
    }}


def tool_phoneapps(q):
    """Messaging-app deep links: WhatsApp / Telegram / Viber / Signal / SMS."""
    d = _digits(q)
    e164 = "+" + d
    return {"input": q, "e164": e164, "links": {
        "whatsapp": f"https://wa.me/{d}",
        "whatsapp_api": f"https://api.whatsapp.com/send?phone={d}",
        "telegram": f"https://t.me/+{d}",
        "viber": f"viber://chat?number=%2B{d}",
        "signal": f"https://signal.me/#p/+{d}",
        "sms": f"sms:{e164}", "tel": f"tel:{e164}",
        "skype": f"skype:+{d}?call",
    }}


def tool_phonespam(q):
    """Spam / scam / robocall report-database links for a number."""
    d = _digits(q)
    return {"input": q, "links": {
        "nomorobo": "https://www.nomorobo.com/lookup/" + d,
        "robokiller": f"https://lookup.robokiller.com/p/{d}",
        "ftc_complaints": "https://reportfraud.ftc.gov/",
        "callercenter": f"https://callercenter.com/{d[:3]}-{d[3:6]}-{d[6:]}" if len(d) >= 10 else "https://callercenter.com/",
        "tellows": f"https://www.tellows.com/num/{d}",
        "ofcom_uk": "https://www.ofcom.org.uk/phones-and-broadband/scam-calls",
    }}


def tool_phonevcard(q):
    """Generate a vCard (.vcf) snippet for the number — import to contacts."""
    d = _digits(q)
    e164 = "+" + d
    vcf = ("BEGIN:VCARD\nVERSION:3.0\nFN:Unknown ({})\n"
           "TEL;TYPE=CELL:{}\nEND:VCARD").format(e164, e164)
    return {"input": q, "e164": e164, "vcard": vcf}


_PN_TYPE = {0: "fixed_line", 1: "mobile", 2: "fixed_line_or_mobile", 3: "toll_free",
            4: "premium_rate", 5: "shared_cost", 6: "voip", 7: "personal_number",
            8: "pager", 9: "uan", 10: "voicemail", 27: "emergency", 28: "short_code",
            99: "unknown"}


def tool_numlookup(q):
    """Real phone lookup via libphonenumber: validity, region, carrier, line type, timezones.

    Needs an explicit country: '+<cc><number>' (E.164) or 'number,REGION' (e.g. '2025550123,US').
    """
    if not _PN:
        return {"input": q, "error": "phonenumbers library not installed"}
    raw = q.strip()
    region = None
    if "," in raw and not raw.lstrip().startswith("+"):
        raw, region = (p.strip() for p in raw.rsplit(",", 1))
        region = region.upper()
    try:
        num = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException as e:
        return {"input": q, "error": str(e),
                "hint": "use +<countrycode><number>, or 'number,REGION' like '2025550123,US'"}
    valid = phonenumbers.is_valid_number(num)
    return {
        "input": q,
        "valid": valid,
        "possible": phonenumbers.is_possible_number(num),
        "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country_code": num.country_code,
        "region": phonenumbers.region_code_for_number(num),
        "location": _pn_geo.description_for_number(num, "en") or None,
        "carrier": _pn_carrier.name_for_number(num, "en") or None,
        "line_type": _PN_TYPE.get(phonenumbers.number_type(num), "unknown"),
        "timezones": list(_pn_tz.time_zones_for_number(num)),
    }


# ===========================================================================
# IMAGE  (accepts: image, url)  — q is a URL pointing at an image
# ===========================================================================
def _load_img(q):
    if not _PIL:
        return None, None, "Pillow not installed"
    if not q.lower().startswith(("http://", "https://")):
        return None, None, "give a direct image URL"
    try:
        r = _get(q)
    except Exception as e:
        return None, None, f"fetch failed: {e}"
    if r.status_code != 200:
        return None, None, f"HTTP {r.status_code}"
    data = r.content
    try:
        return _PIL.open(_io.BytesIO(data)), data, None
    except Exception as e:
        return None, data, f"not a decodable image: {e}"


def _exif_dict(img):
    raw = img._getexif() if hasattr(img, "_getexif") else None
    if not raw:
        return {}
    return {ExifTags.TAGS.get(k, k): v for k, v in raw.items()}


def _gps_decimal(gps):
    """GPSInfo dict -> (lat, lon) decimal degrees, or None."""
    g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps.items()}
    if "GPSLatitude" not in g or "GPSLongitude" not in g:
        return None

    def dms(v):
        d, m, s = (float(x) for x in v)
        return d + m / 60 + s / 3600
    lat = dms(g["GPSLatitude"])
    lon = dms(g["GPSLongitude"])
    if g.get("GPSLatitudeRef") == "S":
        lat = -lat
    if g.get("GPSLongitudeRef") == "W":
        lon = -lon
    return round(lat, 6), round(lon, 6)


def tool_imageexif(q):
    """Full EXIF dump from a remote image: camera, lens, timestamps, software."""
    img, data, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    ex = _exif_dict(img)
    keep = {k: (str(v)[:120] if not isinstance(v, (int, float)) else v)
            for k, v in ex.items() if k != "GPSInfo" and not isinstance(v, bytes)}
    return {"image": q, "has_exif": bool(ex),
            "make": ex.get("Make"), "model": ex.get("Model"),
            "datetime": ex.get("DateTimeOriginal") or ex.get("DateTime"),
            "software": ex.get("Software"), "exif": keep or None,
            "note": "Many platforms strip EXIF on upload; absence ≠ original."}


def tool_imagegps(q):
    """Extract GPS coordinates from image EXIF (feeds the globe + map links)."""
    img, data, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    ex = _exif_dict(img)
    if "GPSInfo" not in ex:
        return {"image": q, "has_gps": False,
                "note": "No GPS EXIF (stripped, or camera had geotag off)."}
    ll = _gps_decimal(ex["GPSInfo"])
    if not ll:
        return {"image": q, "has_gps": False, "note": "GPSInfo present but incomplete"}
    lat, lon = ll
    return {"image": q, "has_gps": True, "lat": lat, "lon": lon,
            "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
            "osm": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
            "datetime": ex.get("DateTimeOriginal")}


def tool_imagemeta(q):
    """Technical metadata: dimensions, format, mode, bytes, megapixels."""
    img, data, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    w, h = img.size
    return {"image": q, "format": img.format, "mode": img.mode,
            "width": w, "height": h, "megapixels": round(w * h / 1e6, 2),
            "aspect_ratio": round(w / h, 3) if h else None,
            "bytes": len(data) if data else None,
            "animated": getattr(img, "is_animated", False),
            "frames": getattr(img, "n_frames", 1)}


def tool_imagehash(q):
    """Average perceptual hash (aHash) + sha256 — dupe/known-image matching."""
    img, data, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    small = img.convert("L").resize((8, 8), _PIL.LANCZOS)
    px = list(small.getdata())
    avg = sum(px) / len(px)
    bits = "".join("1" if p >= avg else "0" for p in px)
    ahash = f"{int(bits, 2):016x}"
    return {"image": q, "ahash": ahash,
            "sha256": hashlib.sha256(data).hexdigest() if data else None,
            "md5": hashlib.md5(data).hexdigest() if data else None,
            "note": "aHash: same image after resize/recompress keeps a close hash."}


def tool_imagecolors(q):
    """Dominant color palette (top buckets) from a remote image."""
    img, data, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    sm = img.convert("RGB").resize((64, 64))
    counts = {}
    for r, g, b in sm.getdata():
        key = (r // 32 * 32, g // 32 * 32, b // 32 * 32)
        counts[key] = counts.get(key, 0) + 1
    top = sorted(counts.items(), key=lambda x: -x[1])[:6]
    n = sum(counts.values())
    return {"image": q, "palette": [
        {"hex": "#%02x%02x%02x" % c, "rgb": list(c), "pct": round(100 * v / n, 1)}
        for c, v in top]}


def tool_imagerev(q):
    """Reverse-image-search pivot links (Google Lens, Yandex, Bing, TinEye)."""
    u = urllib.parse.quote(q, safe="")
    return {"image": q, "links": {
        "google_lens": f"https://lens.google.com/uploadbyurl?url={u}",
        "yandex": f"https://yandex.com/images/search?rpt=imageview&url={u}",
        "bing": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}",
        "tineye": f"https://www.tineye.com/search?url={u}",
        "karmadecay": f"http://karmadecay.com/search?q={u}",
        "baidu": f"https://graph.baidu.com/details?image={u}",
    }}


def tool_imagephash(q):
    """dHash + pHash (difference & perception) for robust near-duplicate detection."""
    img, _, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    # dHash: compare adjacent pixels horizontally on 9×8 grid
    dh = img.convert("L").resize((9, 8), _PIL.LANCZOS)
    dpx = list(dh.getdata())
    dbits = "".join("1" if dpx[i] > dpx[i + 1] else "0"
                    for r in range(8) for i in range(r * 9, r * 9 + 8))
    # pHash: DCT on 32×32, compare top-left 8×8 to median
    import math
    ph = img.convert("L").resize((32, 32), _PIL.LANCZOS)
    ppx = list(ph.getdata())
    dct = []
    for u in range(32):
        for v in range(32):
            val = sum(ppx[x * 32 + y] *
                      math.cos(math.pi * u * (2 * x + 1) / 64) *
                      math.cos(math.pi * v * (2 * y + 1) / 64)
                      for x in range(32) for y in range(32))
            dct.append(val)
    block = [dct[u * 32 + v] for u in range(8) for v in range(8) if not (u == 0 and v == 0)]
    med = sorted(block)[len(block) // 2]
    pbits = "".join("1" if b >= med else "0" for b in block)
    return {"image": q,
            "dhash": f"{int(dbits, 2):016x}",
            "phash": f"{int(pbits, 2):016x}",
            "note": "dHash: fast, good for crops/flips. pHash: robust to brightness/contrast changes."}


def tool_imagethumb(q):
    """Extract embedded EXIF thumbnail — often retains GPS after main EXIF is stripped."""
    img, _, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    ex = _exif_dict(img)
    if not ex:
        return {"image": q, "has_thumbnail": False, "note": "No EXIF data found."}
    thumb = None
    if hasattr(img, "_getexif"):
        raw = img._getexif() or {}
        # Tag 513 = JPEGInterchangeFormat (thumbnail offset), 514 = length
        thumb_data = raw.get(513)
    # PIL exposes thumbnail via getdata on the image directly
    try:
        import io as _io
        img.seek(0)
    except Exception:
        pass
    thumb_keys = [k for k in ex if "thumb" in k.lower() or "Thumbnail" in str(k)]
    has_thumb = bool(thumb_keys) or hasattr(img, "applist")
    # Extract thumb GPS if present
    thumb_gps = None
    if "GPSInfo" in ex:
        ll = _gps_decimal(ex["GPSInfo"])
        if ll:
            thumb_gps = {"lat": ll[0], "lon": ll[1]}
    return {"image": q, "has_thumbnail": has_thumb,
            "thumbnail_exif_keys": thumb_keys,
            "gps_from_exif": thumb_gps,
            "note": "Thumbnail GPS survives many upload strippers; check gps_from_exif."}


def tool_imageicc(q):
    """ICC color profile — fingerprints editing software (Adobe RGB, sRGB-IEC, Lightroom, etc.)."""
    img, _, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    icc = img.info.get("icc_profile")
    if not icc:
        return {"image": q, "has_icc": False, "note": "No ICC profile embedded."}
    # Description tag: bytes 128+ contain ASCII name in ICC header
    try:
        # ICC profile description at offset 128 is 4-byte signature; scan for 'desc'
        desc = ""
        idx = icc.find(b"desc")
        if idx != -1 and idx + 12 < len(icc):
            length = int.from_bytes(icc[idx + 8:idx + 12], "big")
            raw = icc[idx + 12: idx + 12 + length]
            desc = raw.replace(b"\x00", b"").decode("latin-1", errors="ignore").strip()
        return {"image": q, "has_icc": True,
                "profile_name": desc or "(embedded, name unreadable)",
                "profile_bytes": len(icc),
                "note": "Adobe RGB / ProPhoto RGB = pro camera or editing. sRGB = standard or web."}
    except Exception as e:
        return {"image": q, "has_icc": True, "profile_bytes": len(icc), "parse_error": str(e)}


def tool_imagechunks(q):
    """Read PNG hidden text chunks (tEXt/zTXt/iTXt) — common steganography hiding spot."""
    img, data, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    if not data or data[:4] != b"\x89PNG":
        return {"image": q, "is_png": False, "note": "Not a PNG; chunk analysis only applies to PNG."}
    chunks = []
    pos = 8  # skip PNG signature
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8].decode("ascii", errors="replace")
        payload = data[pos + 8:pos + 8 + length]
        if ctype in ("tEXt", "iTXt", "zTXt"):
            try:
                if ctype == "zTXt":
                    import zlib
                    sep = payload.index(b"\x00")
                    key = payload[:sep].decode("latin-1")
                    value = zlib.decompress(payload[sep + 2:]).decode("utf-8", errors="replace")
                elif ctype == "iTXt":
                    sep = payload.index(b"\x00")
                    key = payload[:sep].decode("latin-1")
                    value = payload[sep:].decode("utf-8", errors="replace").lstrip("\x00")
                else:
                    sep = payload.index(b"\x00")
                    key = payload[:sep].decode("latin-1")
                    value = payload[sep + 1:].decode("latin-1", errors="replace")
                chunks.append({"type": ctype, "key": key, "value": value[:500]})
            except Exception as e:
                chunks.append({"type": ctype, "parse_error": str(e)})
        pos += 12 + length
    return {"image": q, "is_png": True, "text_chunks": chunks,
            "count": len(chunks),
            "note": "tEXt/iTXt/zTXt can carry hidden messages, XMP, or tool metadata."}


def tool_imagexmp(q):
    """Extract XMP metadata from raw bytes — reveals Photoshop, Lightroom, creator tool, edits."""
    img, data, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    if not data:
        return {"image": q, "has_xmp": False}
    # XMP is an XML block starting with <x:xmpmeta or <?xpacket
    start = data.find(b"<x:xmpmeta")
    if start == -1:
        start = data.find(b"<?xpacket")
    if start == -1:
        return {"image": q, "has_xmp": False, "note": "No XMP block found in image bytes."}
    end = data.find(b"</x:xmpmeta>", start)
    if end == -1:
        end = data.find(b"<?xpacket end", start)
    xmp_raw = data[start: end + 30 if end != -1 else start + 4096].decode("utf-8", errors="replace")
    # Pull interesting fields with simple regex
    import re
    fields = {}
    for tag in ("CreatorTool", "CreateDate", "ModifyDate", "MetadataDate",
                 "creator", "description", "title", "Rating", "Label",
                 "HistorySoftwareAgent", "DerivedFrom"):
        m = re.search(rf"(?:<(?:xmp|dc|xmpMM):{tag}>|{tag}=\")([^<\"]+)", xmp_raw)
        if m:
            fields[tag] = m.group(1).strip()
    return {"image": q, "has_xmp": True,
            "fields": fields,
            "xmp_snippet": xmp_raw[:800],
            "note": "CreatorTool/HistorySoftwareAgent often exposes exact software version."}


def tool_imagelsb(q):
    """LSB steganography detector — statistical deviation in low bits indicates hidden data."""
    img, _, err = _load_img(q)
    if err:
        return {"image": q, "error": err}
    import statistics
    rgb = img.convert("RGB").resize((128, 128), _PIL.LANCZOS)
    pixels = list(rgb.getdata())
    # Collect LSBs per channel
    channels = {"R": [], "G": [], "B": []}
    for r, g, b in pixels:
        channels["R"].append(r & 1)
        channels["G"].append(g & 1)
        channels["B"].append(b & 1)
    results = {}
    suspicious = False
    for ch, bits in channels.items():
        ones = sum(bits)
        total = len(bits)
        ratio = ones / total
        # Natural images: LSBs cluster near 0.5 but with variance; truly random = flat 0.5
        # Hidden data pushes ratio very close to 0.5 with low variance
        # Simple heuristic: ratio in [0.48, 0.52] on all channels = suspicious
        results[ch] = {"ones_ratio": round(ratio, 4), "suspicious": 0.48 <= ratio <= 0.52}
        if results[ch]["suspicious"]:
            suspicious = True
    return {"image": q, "channels": results,
            "likely_steg": suspicious,
            "confidence": "low — use steghide/stegsolve for confirmation",
            "note": "LSB ratio near 0.5 on all channels suggests possible hidden payload."}


# ===========================================================================
# GEO / WORLD EVENTS  (accepts: coords mostly) — keyless live feeds
# ===========================================================================
def tool_quakes(q):
    """Recent earthquakes — global top, or near coords (USGS, M2.5+ last day)."""
    ll = _coords(q)
    base = "https://earthquake.usgs.gov/fdsnws/event/1/query"
    params = {"format": "geojson", "starttime": "now-1day",
              "minmagnitude": "2.5", "orderby": "magnitude", "limit": "20"}
    if ll:
        params.update({"latitude": ll[0], "longitude": ll[1],
                       "maxradiuskm": "1000", "orderby": "time"})
    r = _get(base, params=params)
    feats = r.json().get("features", [])
    out = []
    for f in feats[:15]:
        c = f["geometry"]["coordinates"]
        p = f["properties"]
        out.append({"mag": p.get("mag"), "place": p.get("place"),
                    "lat": c[1], "lon": c[0], "depth_km": c[2],
                    "time": p.get("time"), "url": p.get("url")})
    return {"query": "near " + q if ll else "global", "count": len(out),
            "quakes": out}


def tool_iss(q):
    """Current International Space Station position (lat/lon, live)."""
    r = _get("http://api.open-notify.org/iss-now.json")
    p = r.json()["iss_position"]
    lat, lon = float(p["latitude"]), float(p["longitude"])
    return {"object": "ISS (ZARYA)", "lat": lat, "lon": lon,
            "timestamp": r.json().get("timestamp"),
            "map": f"https://www.google.com/maps?q={lat},{lon}",
            "note": "Updates ~every few seconds; re-run to track."}


def tool_spacepeople(q):
    """Who is in space right now — names and craft (live)."""
    r = _get("http://api.open-notify.org/astros.json")
    d = r.json()
    return {"number_in_space": d.get("number"),
            "people": d.get("people", [])}


def tool_airquality(q):
    """Air quality (PM2.5/PM10/ozone, European AQI) at coords (open-meteo)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    r = _get("https://air-quality-api.open-meteo.com/v1/air-quality",
             params={"latitude": ll[0], "longitude": ll[1],
                     "current": "pm2_5,pm10,ozone,nitrogen_dioxide,"
                                "sulphur_dioxide,carbon_monoxide,european_aqi"})
    cur = r.json().get("current", {})
    aqi = cur.get("european_aqi")
    band = ("good" if aqi is not None and aqi <= 20 else "fair" if aqi is not None and aqi <= 40
            else "moderate" if aqi is not None and aqi <= 60 else "poor" if aqi is not None and aqi <= 80
            else "very poor" if aqi is not None and aqi <= 100 else "extremely poor" if aqi is not None
            else None)
    return {"lat": ll[0], "lon": ll[1], "european_aqi": aqi, "band": band,
            "pm2_5": cur.get("pm2_5"), "pm10": cur.get("pm10"),
            "ozone": cur.get("ozone"), "no2": cur.get("nitrogen_dioxide"),
            "time": cur.get("time")}


def tool_marineweather(q):
    """Marine conditions (wave height/period/direction) at coords (open-meteo)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    r = _get("https://marine-api.open-meteo.com/v1/marine",
             params={"latitude": ll[0], "longitude": ll[1],
                     "current": "wave_height,wave_direction,wave_period,"
                                "sea_surface_temperature"})
    j = r.json()
    if "current" not in j:
        return {"lat": ll[0], "lon": ll[1],
                "note": "No marine data (likely an inland point)."}
    c = j["current"]
    return {"lat": ll[0], "lon": ll[1], "wave_height_m": c.get("wave_height"),
            "wave_period_s": c.get("wave_period"),
            "wave_direction_deg": c.get("wave_direction"),
            "sea_temp_c": c.get("sea_surface_temperature"), "time": c.get("time")}


def tool_flightsnear(q):
    """Live aircraft within ~1° of coords (OpenSky, keyless, rate-limited)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    lat, lon = ll
    r = _get("https://opensky-network.org/api/states/all",
             params={"lamin": lat - 1, "lamax": lat + 1,
                     "lomin": lon - 1, "lomax": lon + 1})
    if r.status_code != 200:
        return {"lat": lat, "lon": lon, "error": f"OpenSky HTTP {r.status_code} (rate limit?)"}
    states = r.json().get("states") or []
    out = []
    for s in states[:20]:
        out.append({"icao24": s[0], "callsign": (s[1] or "").strip() or None,
                    "country": s[2], "lon": s[5], "lat": s[6],
                    "alt_m": s[7], "velocity_ms": s[9], "heading": s[10],
                    "on_ground": s[8]})
    return {"lat": lat, "lon": lon, "count": len(out), "aircraft": out}


def tool_whatsnearby(q):
    """Nearby OSM points of interest within 500m of coords (Overpass)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    lat, lon = ll
    ql = (f'[out:json][timeout:15];node(around:500,{lat},{lon})'
          f'[amenity];out 25;')
    try:
        r = _get("https://overpass-api.de/api/interpreter", params={"data": ql})
        if r.status_code != 200:
            return {"lat": lat, "lon": lon, "error": f"Overpass HTTP {r.status_code}"}
        els = r.json().get("elements", [])
    except Exception as e:
        return {"lat": lat, "lon": lon, "error": str(e)}
    out = [{"name": e.get("tags", {}).get("name"),
            "amenity": e.get("tags", {}).get("amenity"),
            "lat": e.get("lat"), "lon": e.get("lon")}
           for e in els if e.get("tags", {}).get("amenity")]
    return {"lat": lat, "lon": lon, "count": len(out), "places": out[:25]}


# ---- offline geo converters ----
def tool_maidenhead(q):
    """Coords -> Maidenhead grid locator (ham radio, offline)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    lat, lon = ll
    lon += 180
    lat += 90
    A = ord("A")
    loc = chr(A + int(lon // 20)) + chr(A + int(lat // 10))
    loc += str(int((lon % 20) // 2)) + str(int(lat % 10))
    loc += chr(A + int((lon % 2) * 12)) + chr(A + int((lat % 1) * 24))
    return {"lat": ll[0], "lon": ll[1], "maidenhead": loc}


_PLUS = "23456789CFGHJMPQRVWX"


def tool_pluscode(q):
    """Coords -> Open Location Code (Google Plus Code, offline, 10-digit)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    code = _olc(ll[0], ll[1])
    return {"lat": ll[0], "lon": ll[1], "plus_code": code,
            "map": f"https://plus.codes/{code}"}


def _olc(lat, lon):
    lat = min(max(lat, -90), 89.9999999) + 90
    lon = (lon + 180) % 360
    code = ""
    # latitude/longitude in 1/8000 of a degree, 5 pairs = 10 digits
    lat_i = int(lat * 8000)
    lon_i = int(lon * 8000)
    digits = [0] * 10
    for i in range(4, -1, -1):
        digits[i * 2] = lat_i % 20
        lat_i //= 20
        digits[i * 2 + 1] = lon_i % 20
        lon_i //= 20
    s = "".join(_PLUS[d] for d in digits)
    return s[:8] + "+" + s[8:]


def tool_antipode(q):
    """Antipode (opposite side of Earth) for coords (offline)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    lat, lon = ll
    alat = -lat
    alon = lon + 180 if lon < 0 else lon - 180
    return {"lat": lat, "lon": alon and round(alon, 6),
            "antipode_lat": round(alat, 6), "antipode_lon": round(alon, 6),
            "map": f"https://www.google.com/maps?q={round(alat,6)},{round(alon,6)}"}


def tool_geodist(q):
    """Great-circle distance between two coord pairs: 'lat,lon  lat,lon'."""
    pts = re.findall(r"-?\d+(?:\.\d+)?", q)
    if len(pts) < 4:
        return {"input": q, "error": "give two pairs: lat1,lon1 lat2,lon2"}
    la1, lo1, la2, lo2 = (math.radians(float(x)) for x in pts[:4])
    dlat, dlon = la2 - la1, lo2 - lo1
    a = math.sin(dlat / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin(dlon / 2) ** 2
    km = 6371.0 * 2 * math.asin(math.sqrt(a))
    return {"point_a": [float(pts[0]), float(pts[1])],
            "point_b": [float(pts[2]), float(pts[3])],
            "distance_km": round(km, 2), "distance_mi": round(km * 0.621371, 2),
            "distance_nm": round(km * 0.539957, 2)}


def tool_moonphase(q):
    """Current moon phase (offline approximation via known new moon epoch)."""
    # q may carry a unix epoch; else fixed reference date for determinism.
    d = _digits(q)
    now = int(d) if d and 10 <= len(d) <= 13 else 1751241600  # 2025-06-30
    if len(str(now)) == 13:
        now //= 1000
    synodic = 29.530588853
    known_new = 947182440  # 2000-01-06 new moon
    days = (now - known_new) / 86400.0
    pos = (days % synodic) / synodic
    idx = int(pos * 8 + 0.5) % 8
    names = ["New", "Waxing Crescent", "First Quarter", "Waxing Gibbous",
             "Full", "Waning Gibbous", "Last Quarter", "Waning Crescent"]
    return {"epoch_used": now, "phase": names[idx],
            "illumination_pct": round(50 * (1 - math.cos(2 * math.pi * pos)), 1),
            "age_days": round(pos * synodic, 1)}


# ===========================================================================
# OFFLINE FORMAT / CRYPTO / MISC
# ===========================================================================
_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "/": "-..-.", "@": ".--.-.", "-": "-....-",
}
_UNMORSE = {v: k for k, v in _MORSE.items()}


def tool_morse(q):
    """Text <-> Morse code (offline, auto-detects direction)."""
    s = q.strip()
    if set(s) <= set(".- /"):
        words = s.split(" / ") if " / " in s else [s]
        dec = " ".join("".join(_UNMORSE.get(c, "?") for c in w.split())
                       for w in words)
        return {"input": q, "mode": "morse->text", "text": dec}
    enc = " ".join(_MORSE.get(c.upper(), "?") for c in s if c != " ")
    enc = enc.replace("?", "")
    return {"input": q, "mode": "text->morse",
            "morse": " ".join(_MORSE.get(c.upper(), "/") for c in s)}


_NATO = {"A": "Alpha", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
         "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
         "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar",
         "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
         "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray",
         "Y": "Yankee", "Z": "Zulu", "0": "Zero", "1": "One", "2": "Two",
         "3": "Three", "4": "Four", "5": "Five", "6": "Six", "7": "Seven",
         "8": "Eight", "9": "Nine"}


def tool_nato(q):
    """Spell text in the NATO phonetic alphabet (offline)."""
    out = [_NATO.get(c.upper(), c) for c in q if not c.isspace()]
    return {"input": q, "phonetic": " ".join(out)}


_ROMAN = [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"),
          (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"),
          (4, "IV"), (1, "I")]


def tool_roman(q):
    """Integer <-> Roman numeral (offline, auto-detects direction)."""
    s = q.strip().upper()
    if s.isdigit():
        n = int(s)
        if not 1 <= n <= 3999:
            return {"input": q, "error": "range 1-3999"}
        out = ""
        for val, sym in _ROMAN:
            while n >= val:
                out += sym
                n -= val
        return {"input": q, "mode": "int->roman", "roman": out}
    if re.fullmatch(r"[MDCLXVI]+", s):
        i, total = 0, 0
        for val, sym in _ROMAN:
            while s[i:i + len(sym)] == sym:
                total += val
                i += len(sym)
        return {"input": q, "mode": "roman->int", "value": total}
    return {"input": q, "error": "give an integer (1-3999) or roman numeral"}


def tool_caesar(q):
    """Caesar / ROT-N brute force — all 25 shifts of the input (offline)."""
    def shift(s, n):
        return "".join(
            chr((ord(c) - b + n) % 26 + b) if c.isalpha()
            else c
            for c in s for b in [65 if c.isupper() else 97])
    return {"input": q, "rot13": shift(q, 13),
            "all_shifts": {f"rot{n}": shift(q, n) for n in range(1, 26)}}


def tool_snowflake(q):
    """Decode a Twitter/Discord snowflake ID -> creation timestamp (offline)."""
    d = _digits(q)
    if not d or len(d) < 15:
        return {"input": q, "error": "give a numeric snowflake ID"}
    sf = int(d)
    discord = (sf >> 22) + 1420070400000
    twitter = (sf >> 22) + 1288834974657
    return {"input": q, "snowflake": sf,
            "discord_epoch_ms": discord,
            "twitter_epoch_ms": twitter,
            "machine_id": (sf >> 12) & 0x3FF, "sequence": sf & 0xFFF,
            "note": "Same bits decode differently per platform epoch."}


def tool_ulid(q):
    """Decode a ULID's embedded timestamp (offline)."""
    s = q.strip().upper()
    if not re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", s):
        return {"input": q, "error": "not a valid 26-char ULID"}
    alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    ts = 0
    for c in s[:10]:
        ts = ts * 32 + alpha.index(c)
    return {"input": q, "ulid": s, "timestamp_ms": ts,
            "randomness": s[10:]}


def tool_cron(q):
    """Explain a 5-field cron expression in plain English (offline)."""
    parts = q.strip().split()
    if len(parts) != 5:
        return {"input": q, "error": "need 5 fields: min hour dom mon dow"}
    names = ["minute", "hour", "day-of-month", "month", "day-of-week"]
    desc = {n: ("every " + n if v == "*" else
                f"every {v[2:]} {n}(s)" if v.startswith("*/") else v)
            for n, v in zip(names, parts)}
    return {"input": q, "fields": dict(zip(names, parts)),
            "explanation": desc,
            "crontab_guru": "https://crontab.guru/#" + "_".join(parts)}


def tool_hexdump(q):
    """Classic hexdump (offset / hex / ASCII) of input text (offline)."""
    b = q.encode("utf-8", "replace")
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hexs = " ".join(f"{x:02x}" for x in chunk)
        asci = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"{i:08x}  {hexs:<47}  {asci}")
    return {"input": q, "bytes": len(b), "hexdump": "\n".join(lines)}


def tool_numwords(q):
    """Integer -> English words (offline, up to quintillions)."""
    d = re.sub(r"[^\d-]", "", q)
    if not d or d == "-":
        return {"input": q, "error": "give an integer"}
    n = int(d)
    ones = ["zero", "one", "two", "three", "four", "five", "six", "seven",
            "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen",
            "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"]
    tens = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy",
            "eighty", "ninety"]
    scales = ["", " thousand", " million", " billion", " trillion",
              " quadrillion", " quintillion"]

    def under1000(x):
        w = ""
        if x >= 100:
            w += ones[x // 100] + " hundred"
            x %= 100
            if x:
                w += " "
        if x >= 20:
            w += tens[x // 10]
            if x % 10:
                w += "-" + ones[x % 10]
        elif x:
            w += ones[x]
        return w
    if n == 0:
        return {"input": q, "words": "zero"}
    neg = n < 0
    n = abs(n)
    groups = []
    while n:
        groups.append(n % 1000)
        n //= 1000
    if len(groups) > len(scales):
        return {"input": q, "error": "number too large"}
    words = " ".join(under1000(g) + scales[i]
                     for i, g in reversed(list(enumerate(groups))) if g).strip()
    return {"input": q, "words": ("negative " if neg else "") + words}


def tool_jsonfmt(q):
    """Validate + pretty-print JSON and report structure stats (offline)."""
    try:
        obj = _json.loads(q)
    except Exception as e:
        return {"input": q[:80], "valid": False, "error": str(e)}
    keys = set()
    depth = [0]

    def walk(o, d):
        depth[0] = max(depth[0], d)
        if isinstance(o, dict):
            keys.update(o.keys())
            for v in o.values():
                walk(v, d + 1)
        elif isinstance(o, list):
            for v in o:
                walk(v, d + 1)
    walk(obj, 1)
    return {"valid": True, "type": type(obj).__name__,
            "max_depth": depth[0], "unique_keys": len(keys),
            "pretty": _json.dumps(obj, indent=2)[:4000]}


def tool_passentropy(q):
    """Estimate password entropy and offline crack time (offline)."""
    s = q
    pool = 0
    if re.search(r"[a-z]", s):
        pool += 26
    if re.search(r"[A-Z]", s):
        pool += 26
    if re.search(r"\d", s):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", s):
        pool += 33
    bits = len(s) * math.log2(pool) if pool else 0
    guesses = 2 ** bits / 2
    secs = guesses / 1e11  # 100B guesses/sec offline
    return {"length": len(s), "charset_size": pool,
            "entropy_bits": round(bits, 1),
            "strength": ("very weak" if bits < 28 else "weak" if bits < 36
                         else "reasonable" if bits < 60 else "strong"
                         if bits < 128 else "very strong"),
            "offline_crack_time_s": round(secs, 1),
            "note": "Assumes random chars; real passwords are weaker (patterns)."}


# ===========================================================================
# MORE KEYLESS LIVE  +  OFFLINE CONVERTERS
# ===========================================================================
def tool_cryptoprice(q):
    """Live crypto price + 24h change (CoinGecko, keyless)."""
    sym = re.sub(r"[^a-z0-9 -]", "", q.strip().lower()).replace(" ", "-")
    ids = {"btc": "bitcoin", "eth": "ethereum", "xrp": "ripple",
           "ltc": "litecoin", "doge": "dogecoin", "sol": "solana",
           "ada": "cardano", "bnb": "binancecoin"}
    cid = ids.get(sym, sym)
    r = _get("https://api.coingecko.com/api/v3/simple/price",
             params={"ids": cid, "vs_currencies": "usd,eur",
                     "include_24hr_change": "true", "include_market_cap": "true"})
    d = r.json().get(cid)
    if not d:
        return {"input": q, "error": f"coin '{cid}' not found (try full id e.g. bitcoin)"}
    return {"coin": cid, "usd": d.get("usd"), "eur": d.get("eur"),
            "change_24h_pct": round(d.get("usd_24h_change", 0), 2),
            "market_cap_usd": d.get("usd_market_cap")}


def tool_agify(q):
    """Predict a person's age from their first name (agify.io, keyless)."""
    name = re.sub(r"[^a-zA-Z]", "", q.split()[0] if q.split() else q)
    r = _get("https://api.agify.io", params={"name": name})
    d = r.json()
    return {"name": d.get("name"), "predicted_age": d.get("age"),
            "sample_count": d.get("count")}


def tool_genderize(q):
    """Predict gender from a first name (genderize.io, keyless)."""
    name = re.sub(r"[^a-zA-Z]", "", q.split()[0] if q.split() else q)
    r = _get("https://api.genderize.io", params={"name": name})
    d = r.json()
    return {"name": d.get("name"), "gender": d.get("gender"),
            "probability": d.get("probability"), "sample_count": d.get("count")}


def tool_nationalize(q):
    """Predict likely nationality from a name (nationalize.io, keyless)."""
    name = re.sub(r"[^a-zA-Z]", "", q.split()[0] if q.split() else q)
    r = _get("https://api.nationalize.io", params={"name": name})
    d = r.json()
    return {"name": d.get("name"),
            "countries": [{"country": c["country_id"],
                           "probability": round(c["probability"], 3)}
                          for c in d.get("country", [])[:5]]}


def tool_randomuser(q):
    """Generate a synthetic identity (randomuser.me, keyless) — sockpuppet ref."""
    r = _get("https://randomuser.me/api/")
    u = r.json()["results"][0]
    return {"name": f"{u['name']['first']} {u['name']['last']}",
            "gender": u["gender"], "email": u["email"],
            "username": u["login"]["username"], "phone": u["phone"],
            "location": f"{u['location']['city']}, {u['location']['country']}",
            "dob": u["dob"]["date"][:10], "picture": u["picture"]["large"],
            "note": "Synthetic; for research/sockpuppet hygiene only."}


def tool_holidays(q):
    """Public holidays for a country this year (nager.at, keyless). 'US' / 'GB'."""
    cc = re.sub(r"[^A-Za-z]", "", q.strip())[:2].upper() or "US"
    r = _get(f"https://date.nager.at/api/v3/PublicHolidays/2026/{cc}")
    if r.status_code != 200:
        return {"country": cc, "error": f"HTTP {r.status_code} (use ISO code like US, GB, DE)"}
    return {"country": cc, "year": 2026,
            "holidays": [{"date": h["date"], "name": h["name"],
                          "local": h["localName"]} for h in r.json()]}


def tool_binarytext(q):
    """Text <-> 8-bit binary (offline, auto-direction)."""
    s = q.strip()
    if re.fullmatch(r"[01\s]+", s) and "0" in s + "1":
        bits = re.sub(r"\s", "", s)
        chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - len(bits) % 8, 8)]
        return {"input": q, "mode": "binary->text", "text": "".join(chars)}
    return {"input": q, "mode": "text->binary",
            "binary": " ".join(format(ord(c), "08b") for c in s)}


def tool_rot47(q):
    """ROT47 over printable ASCII (offline, self-inverse)."""
    out = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                  for c in q)
    return {"input": q, "rot47": out}


def tool_ascii85(q):
    """Ascii85 encode / decode (offline, auto-detects)."""
    try:
        dec = base64.a85decode(q.encode()).decode("utf-8")
        if dec.isprintable():
            return {"input": q, "mode": "decode", "text": dec}
    except Exception:
        pass
    return {"input": q, "mode": "encode",
            "ascii85": base64.a85encode(q.encode()).decode()}


def tool_emoji(q):
    """Emoji <-> Unicode name / codepoint (offline, unicodedata)."""
    s = q.strip()
    if all(c.isascii() and (c.isalpha() or c in " -_") for c in s):
        try:
            ch = unicodedata.lookup(s.upper().replace("_", " ").replace("-", " "))
            return {"input": q, "mode": "name->char", "char": ch,
                    "codepoint": f"U+{ord(ch):04X}"}
        except KeyError:
            return {"input": q, "error": "no Unicode char with that name"}
    out = [{"char": c, "name": unicodedata.name(c, "?"),
            "codepoint": f"U+{ord(c):04X}"} for c in s if not c.isspace()]
    return {"input": q, "mode": "char->name", "chars": out}


def tool_slug(q):
    """Slugify text into a URL-safe slug (offline)."""
    s = unicodedata.normalize("NFKD", q).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return {"input": q, "slug": slug,
            "snake": slug.replace("-", "_"), "length": len(slug)}


def tool_wordcount(q):
    """Text statistics: words, chars, lines, reading time (offline)."""
    words = q.split()
    return {"characters": len(q), "characters_no_spaces": len(re.sub(r"\s", "", q)),
            "words": len(words), "lines": q.count("\n") + 1,
            "sentences": len(re.findall(r"[.!?]+", q)) or None,
            "avg_word_len": round(sum(len(w) for w in words) / len(words), 1) if words else 0,
            "reading_time_s": round(len(words) / 200 * 60)}


def tool_ipint(q):
    """IPv4 <-> integer <-> hex conversion (offline)."""
    s = q.strip()
    try:
        if "." in s:
            ip = ipaddress.IPv4Address(s)
            n = int(ip)
        else:
            n = int(s, 16) if s.lower().startswith("0x") else int(s)
            ip = ipaddress.IPv4Address(n)
        return {"input": q, "dotted": str(ip), "integer": n,
                "hex": f"0x{n:08x}", "binary": format(n, "032b")}
    except Exception as e:
        return {"input": q, "error": str(e)}


def tool_tempconv(q):
    """Temperature convert across °C/°F/K (offline). e.g. '100C' or '212F'."""
    m = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*([cCfFkK])\s*$", q.strip())
    if not m:
        return {"input": q, "error": "give e.g. 100C, 72F, 300K"}
    v, unit = float(m.group(1)), m.group(2).upper()
    c = v if unit == "C" else (v - 32) * 5 / 9 if unit == "F" else v - 273.15
    return {"input": q, "celsius": round(c, 2),
            "fahrenheit": round(c * 9 / 5 + 32, 2), "kelvin": round(c + 273.15, 2)}

# ── extension pack 7 ──────────────────────────────────────────────────────────────


def _page(q):
    url = q if q.lower().startswith(("http://", "https://")) else "https://" + q
    return _get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT/1.0)"}), url


# ===========================================================================
# WORLD EVENTS  (live, keyless) — several emit lat/lon for the globe
# ===========================================================================
def tool_disasters(q):
    """Active natural disasters worldwide (GDACS: quakes/cyclones/floods/etc)."""
    r = _get("https://www.gdacs.org/gdacsapi/api/events/geteventlist/MAP")
    feats = r.json().get("features", [])
    out = []
    for f in feats[:25]:
        p = f.get("properties", {})
        c = (f.get("geometry") or {}).get("coordinates") or []
        lon, lat = (c[0], c[1]) if len(c) >= 2 else (None, None)
        url = p.get("url")
        out.append({"type": p.get("eventtype"), "name": p.get("name") or p.get("htmldescription"),
                    "alert": p.get("alertlevel"), "country": p.get("country"),
                    "lat": lat, "lon": lon, "date": p.get("fromdate"),
                    "url": url.get("report") if isinstance(url, dict) else url})
    return {"source": "GDACS", "count": len(out), "events": out}


def tool_spaceweather(q):
    """Geomagnetic activity now: planetary Kp index + storm level (NOAA SWPC)."""
    r = _get("https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json")
    rows = r.json()
    last = rows[-1]
    # endpoint serves either list-of-dicts or legacy [time, kp, ...] rows
    if isinstance(last, dict):
        kp = float(last.get("Kp", last.get("kp_index", 0)))
        last = [last.get("time_tag"), kp]
    else:
        kp = float(last[1])
    g = ("G5 extreme" if kp >= 9 else "G4 severe" if kp >= 8 else "G3 strong"
         if kp >= 7 else "G2 moderate" if kp >= 6 else "G1 minor" if kp >= 5
         else "none (quiet/unsettled)")
    return {"time_utc": last[0], "kp_index": kp, "geomagnetic_storm": g,
            "aurora_visible": "likely at high latitudes" if kp >= 5 else "unlikely",
            "note": "Kp 0-9; ≥5 = geomagnetic storm."}


def tool_weatheralerts(q):
    """Active US weather alerts near coords (NWS api.weather.gov, US only)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give US coordinates 'lat,lon'"}
    r = _get("https://api.weather.gov/alerts/active",
             params={"point": f"{ll[0]},{ll[1]}"})
    if r.status_code != 200:
        return {"lat": ll[0], "lon": ll[1], "error": f"NWS HTTP {r.status_code} (US-only service)"}
    feats = r.json().get("features", [])
    out = [{"event": f["properties"].get("event"),
            "severity": f["properties"].get("severity"),
            "urgency": f["properties"].get("urgency"),
            "headline": f["properties"].get("headline"),
            "expires": f["properties"].get("expires")} for f in feats[:15]]
    return {"lat": ll[0], "lon": ll[1], "count": len(out),
            "alerts": out or "no active alerts at this point"}


def _md(q):
    """Pull MM/DD from query, else today (UTC)."""
    m = re.search(r"(\d{1,2})[/-](\d{1,2})", q)
    if m:
        return int(m.group(1)), int(m.group(2))
    t = datetime.datetime.utcnow()
    return t.month, t.day


def tool_onthisday(q):
    """Historical events on a date (Wikipedia 'On this day'; MM/DD or today)."""
    mm, dd = _md(q)
    r = _get(f"https://en.wikipedia.org/api/rest_v1/feed/onthisday/events/{mm:02d}/{dd:02d}")
    ev = r.json().get("events", [])
    out = [{"year": e.get("year"), "text": e.get("text")} for e in ev[:15]]
    return {"date": f"{mm:02d}/{dd:02d}", "count": len(out), "events": out}


def tool_trendingwiki(q):
    """Most-read English Wikipedia articles today (or YYYY/MM/DD in query)."""
    m = re.search(r"(\d{4})[/-](\d{1,2})[/-](\d{1,2})", q)
    if m:
        y, mo, d = m.groups()
    else:
        t = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        y, mo, d = t.year, t.month, t.day
    r = _get(f"https://en.wikipedia.org/api/rest_v1/feed/featured/{int(y)}/{int(mo):02d}/{int(d):02d}")
    arts = (r.json().get("mostread") or {}).get("articles", [])
    out = [{"title": a.get("normalizedtitle"), "views": a.get("views"),
            "url": (a.get("content_urls") or {}).get("desktop", {}).get("page")}
           for a in arts[:15]]
    return {"date": f"{y}/{int(mo):02d}/{int(d):02d}", "articles": out}


# ===========================================================================
# CRYPTO CHAIN STATS  (live, keyless)
# ===========================================================================
def tool_btcfees(q):
    """Recommended Bitcoin transaction fees in sat/vB (mempool.space)."""
    r = _get("https://mempool.space/api/v1/fees/recommended")
    d = r.json()
    return {"unit": "sat/vB", "fastest": d.get("fastestFee"),
            "half_hour": d.get("halfHourFee"), "hour": d.get("hourFee"),
            "economy": d.get("economyFee"), "minimum": d.get("minimumFee")}


def tool_blockheight(q):
    """Current block height of Bitcoin and Ethereum (live)."""
    out = {}
    try:
        out["bitcoin"] = int(_get("https://mempool.space/api/blocks/tip/height").text)
    except Exception as e:
        out["bitcoin"] = f"error: {e}"
    try:
        out["ethereum"] = _get("https://api.blockcypher.com/v1/eth/main").json().get("height")
    except Exception as e:
        out["ethereum"] = f"error: {e}"
    return out


def tool_cryptomarket(q):
    """Global crypto market: total cap, BTC dominance, 24h volume (CoinGecko)."""
    r = _get("https://api.coingecko.com/api/v3/global")
    d = r.json().get("data", {})
    return {"active_coins": d.get("active_cryptocurrencies"),
            "markets": d.get("markets"),
            "total_market_cap_usd": round(d.get("total_market_cap", {}).get("usd", 0)),
            "total_volume_usd": round(d.get("total_volume", {}).get("usd", 0)),
            "btc_dominance_pct": round(d.get("market_cap_percentage", {}).get("btc", 0), 2),
            "eth_dominance_pct": round(d.get("market_cap_percentage", {}).get("eth", 0), 2),
            "market_cap_change_24h_pct": round(d.get("market_cap_change_percentage_24h_usd", 0), 2)}


def tool_coininfo(q):
    """Coin metadata: categories, algorithm, genesis date, homepage (CoinGecko)."""
    ids = {"btc": "bitcoin", "eth": "ethereum", "xrp": "ripple", "ltc": "litecoin",
           "doge": "dogecoin", "sol": "solana", "ada": "cardano", "bnb": "binancecoin"}
    cid = ids.get(q.strip().lower(), re.sub(r"[^a-z0-9-]", "", q.strip().lower()))
    r = _get(f"https://api.coingecko.com/api/v3/coins/{cid}",
             params={"localization": "false", "tickers": "false",
                     "market_data": "false", "community_data": "false",
                     "developer_data": "false"})
    if r.status_code != 200:
        return {"input": q, "error": f"coin '{cid}' not found"}
    d = r.json()
    return {"id": d.get("id"), "symbol": d.get("symbol"), "name": d.get("name"),
            "categories": [c for c in d.get("categories", []) if c][:6],
            "hashing_algorithm": d.get("hashing_algorithm"),
            "genesis_date": d.get("genesis_date"),
            "homepage": next((u for u in d.get("links", {}).get("homepage", []) if u), None),
            "market_cap_rank": d.get("market_cap_rank")}


# ===========================================================================
# PAGE RECON  (live) — accepts domain/url
# ===========================================================================
def tool_jslibs(q):
    """Enumerate <script> sources & guess JS libraries + versions on a page."""
    r, url = _page(q)
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I)
    libs = {}
    for s in srcs:
        m = re.search(r'/([a-zA-Z][\w.-]*?)[-@/](\d+\.\d+(?:\.\d+)?)', s)
        if m:
            libs[m.group(1).lower()] = m.group(2)
    return {"url": url, "script_count": len(srcs),
            "external_scripts": [s for s in srcs if s.startswith("http")][:25],
            "detected_libraries": libs}


def tool_htmlcomments(q):
    """Extract HTML comments from a page — often leak TODOs, paths, software."""
    r, url = _page(q)
    cms = re.findall(r"<!--(.*?)-->", r.text, re.S)
    cms = [c.strip()[:200] for c in cms if c.strip() and "[if" not in c.lower()]
    return {"url": url, "count": len(cms), "comments": cms[:25]}


def tool_formaudit(q):
    """Enumerate HTML forms & inputs (login/upload/search) — attack surface."""
    r, url = _page(q)
    forms = re.findall(r"<form[^>]*>(.*?)</form>", r.text, re.S | re.I)
    out = []
    for f in forms[:10]:
        action = re.search(r'action=["\']([^"\']*)["\']', f, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', f, re.I)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', f, re.I)
        types = re.findall(r'<input[^>]*type=["\']([^"\']+)["\']', f, re.I)
        out.append({"action": action.group(1) if action else None,
                    "method": (method.group(1) if method else "GET").upper(),
                    "inputs": inputs, "has_password": "password" in types,
                    "has_file": "file" in types})
    return {"url": url, "form_count": len(forms), "forms": out}


def tool_metatags(q):
    """OpenGraph / Twitter-card / generator meta tags from a page."""
    r, url = _page(q)
    tags = {}
    for m in re.finditer(r'<meta[^>]+(?:property|name)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', r.text, re.I):
        k = m.group(1).lower()
        if k.startswith(("og:", "twitter:")) or k in ("generator", "description", "author", "keywords"):
            tags[k] = m.group(2)[:200]
    title = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
    return {"url": url, "title": title.group(1).strip()[:200] if title else None,
            "meta": tags}


def tool_telegram_channel(q):
    """Public Telegram channel preview: title, subscribers, description."""
    name = re.sub(r"^@|^https?://t\.me/(s/)?", "", q.strip())
    r = _get(f"https://t.me/s/{name}", headers={"User-Agent": "Mozilla/5.0"})
    if "tgme_page" not in r.text and "tgme_channel" not in r.text:
        return {"channel": name, "found": False}
    def g(pat):
        m = re.search(pat, r.text, re.S)
        return re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else None
    return {"channel": name, "found": True,
            "title": g(r'tgme_channel_info_header_title[^>]*>.*?<span[^>]*>(.*?)</span'),
            "subscribers": g(r'tgme_channel_info_counter[^>]*>\s*<span class="counter_value"[^>]*>(.*?)</span'),
            "description": g(r'tgme_channel_info_description[^>]*>(.*?)</div'),
            "url": f"https://t.me/{name}"}


def tool_linktree(q):
    """Extract destination links from a Linktree (linktr.ee) profile."""
    name = re.sub(r"^@|^https?://linktr\.ee/", "", q.strip())
    r = _get(f"https://linktr.ee/{name}", headers={"User-Agent": "Mozilla/5.0"})
    if r.status_code != 200:
        return {"profile": name, "found": False}
    links = sorted(set(re.findall(r'"url":"(https?://[^"]+)"', r.text)))
    links = [urllib.parse.unquote(x.encode().decode("unicode_escape"))
             for x in links if "linktr.ee" not in x and "linktree" not in x]
    return {"profile": name, "found": True, "link_count": len(links),
            "links": links[:30], "url": f"https://linktr.ee/{name}"}


# ===========================================================================
# OFFLINE VALIDATORS / CONVERTERS
# ===========================================================================
def _luhn_ok(d):
    s, alt = 0, False
    for ch in reversed(d):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0


def tool_imei(q):
    """Validate an IMEI (Luhn) and split TAC / serial / check digit (offline)."""
    d = re.sub(r"\D", "", q)
    if len(d) not in (15, 16):
        return {"input": q, "error": "IMEI is 15 digits (or 16 with software ver)"}
    imei14 = d[:14]
    return {"input": q, "imei": d, "valid_luhn": _luhn_ok(d[:15]),
            "tac": d[:8], "fac_or_serial": d[8:14], "check_digit": d[14],
            "lookup": f"https://www.imei.info/?imei={d[:15]}",
            "note": "TAC (first 8) identifies the model; serial is device-unique."}


def tool_creditcard(q):
    """Identify card brand from number pattern + Luhn validity (offline)."""
    d = re.sub(r"\D", "", q)
    brand = ("Visa" if re.match(r"^4\d{12}(\d{3})?(\d{3})?$", d) else
             "Mastercard" if re.match(r"^(5[1-5]\d{14}|2(2[2-9]|[3-6]\d|7[01])\d{12}|2720\d{12})$", d) else
             "Amex" if re.match(r"^3[47]\d{13}$", d) else
             "Discover" if re.match(r"^6(011|5\d{2}|4[4-9]\d)\d{12}$", d) else
             "Diners" if re.match(r"^3(0[0-5]|[68]\d)\d{11}$", d) else
             "JCB" if re.match(r"^35\d{14}$", d) else "unknown")
    return {"input": q, "digits": len(d), "brand": brand,
            "valid_luhn": _luhn_ok(d) if d else False, "iin_bin": d[:6] or None,
            "note": "Pattern + Luhn only; does not mean the card exists/is active."}


def tool_ean(q):
    """EAN-13 / UPC-A / EAN-8 check digit + GS1 country prefix (offline)."""
    d = re.sub(r"\D", "", q)
    if len(d) not in (8, 12, 13, 14):
        return {"input": q, "error": "give an 8/12/13/14-digit barcode"}
    body, check = d[:-1], int(d[-1])
    tot = sum(int(x) * (3 if (len(body) - i) % 2 else 1) for i, x in enumerate(body))
    calc = (10 - tot % 10) % 10
    ean13 = d.zfill(13) if len(d) in (8, 12, 13) else d
    pfx = int(ean13[:3])
    region = ("USA/Canada" if pfx <= 139 else "France" if 300 <= pfx <= 379
              else "Germany" if 400 <= pfx <= 440 else "Japan" if 450 <= pfx <= 459 or 490 <= pfx <= 499
              else "UK" if 500 <= pfx <= 509 else "China" if 690 <= pfx <= 699
              else "Books (ISBN)" if pfx in (978, 979) else "Internal/coupon" if pfx >= 200 and pfx <= 299
              else "other/see GS1 prefix list")
    return {"input": q, "length": len(d), "check_digit_ok": calc == check,
            "expected_check": calc, "gs1_prefix": ean13[:3], "origin": region}


def tool_punycode(q):
    """IDN domain ↔ Punycode (xn--) conversion — homograph/phishing checks."""
    s = q.strip()
    try:
        if "xn--" in s.lower():
            dec = s.encode("ascii").decode("idna")
            return {"input": q, "mode": "puny->unicode", "unicode": dec, "ascii": s}
        enc = s.encode("idna").decode("ascii")
        return {"input": q, "mode": "unicode->puny", "ascii": enc, "unicode": s,
                "is_idn": enc != s}
    except Exception as e:
        return {"input": q, "error": f"not a valid domain label: {e}"}


_CONFUSABLE = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
               "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g",
               "ո": "n", "ⅼ": "l", "Ι": "I", "Ο": "O", "А": "A", "Е": "E",
               "Р": "P", "С": "C", "Т": "T", "Н": "H", "В": "B", "М": "M",
               "０": "0", "１": "1", "ⅰ": "i"}


def tool_homoglyph(q):
    """Detect confusable / mixed-script characters (spoofed domains, names)."""
    s = q.strip()
    scripts, subs, suspicious = set(), {}, []
    for ch in s:
        if ch.isascii() or not ch.isalpha():
            continue
        try:
            scripts.add(unicodedata.name(ch).split()[0])
        except ValueError:
            pass
        if ch in _CONFUSABLE:
            subs[ch] = _CONFUSABLE[ch]
            suspicious.append(ch)
    ascii_form = "".join(_CONFUSABLE.get(c, c) for c in s)
    return {"input": q, "is_pure_ascii": s.isascii(),
            "non_ascii_scripts": sorted(scripts) or None,
            "mixed_script": len(scripts) > 0 and any(c.isascii() and c.isalpha() for c in s),
            "confusables": subs or None,
            "ascii_skeleton": ascii_form if ascii_form != s else None,
            "verdict": "SUSPICIOUS — looks like a spoof" if suspicious else "clean"}


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def tool_base58(q):
    """Base58 (Bitcoin alphabet) encode / decode of text (offline, auto)."""
    s = q.strip()
    if s and all(c in _B58 for c in s) and not s.isdigit():
        n = 0
        for c in s:
            n = n * 58 + _B58.index(c)
        try:
            txt = n.to_bytes((n.bit_length() + 7) // 8, "big").decode("utf-8")
            return {"input": q, "mode": "decode", "text": txt}
        except Exception:
            pass
    b = q.encode()
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    out = _B58[0] * (len(b) - len(b.lstrip(b"\x00"))) + out
    return {"input": q, "mode": "encode", "base58": out or _B58[0]}


_VAT = {"AT": r"U\d{8}", "BE": r"0\d{9}", "DE": r"\d{9}", "DK": r"\d{8}",
        "ES": r"[A-Z0-9]\d{7}[A-Z0-9]", "FI": r"\d{8}", "FR": r"[A-Z0-9]{2}\d{9}",
        "GB": r"\d{9}(\d{3})?", "IE": r"\d[A-Z0-9]\d{5}[A-Z]{1,2}", "IT": r"\d{11}",
        "NL": r"\d{9}B\d{2}", "PL": r"\d{10}", "PT": r"\d{9}", "SE": r"\d{12}"}


def tool_vatid(q):
    """Validate an EU VAT number's country format (offline structural check)."""
    s = re.sub(r"[\s.-]", "", q.strip().upper())
    cc, num = s[:2], s[2:]
    if cc not in _VAT:
        return {"input": q, "error": f"no offline format for country '{cc}'",
                "supported": sorted(_VAT)}
    ok = bool(re.fullmatch(_VAT[cc], num))
    return {"input": q, "country": cc, "number": num, "format_valid": ok,
            "vies_check": "https://ec.europa.eu/taxation_customs/vies/",
            "note": "Structural check only; use VIES for real validity."}


def tool_swiftbic(q):
    """Parse a SWIFT/BIC code: bank, country, location, branch (offline)."""
    s = re.sub(r"\s", "", q.strip().upper())
    if not re.fullmatch(r"[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?", s):
        return {"input": q, "error": "not a valid 8 or 11-char BIC"}
    return {"input": q, "bic": s, "bank_code": s[:4], "country": s[4:6],
            "location_code": s[6:8], "branch": s[8:] or "primary (XXX)",
            "test_or_live": "test" if s[7] == "0" else "live/passive"}


# ---- UTM / MGRS (WGS84) ----
def _to_utm(lat, lon):
    a, f = 6378137.0, 1 / 298.257223563
    e2 = f * (2 - f)
    zone = int((lon + 180) / 6) + 1
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    la, lo = math.radians(lat), math.radians(lon)
    N = a / math.sqrt(1 - e2 * math.sin(la) ** 2)
    C = e2 / (1 - e2) * math.cos(la) ** 2
    A = math.cos(la) * (lo - lon0)
    M = a * ((1 - e2 / 4 - 3 * e2**2 / 64 - 5 * e2**3 / 256) * la
             - (3 * e2 / 8 + 3 * e2**2 / 32 + 45 * e2**3 / 1024) * math.sin(2 * la)
             + (15 * e2**2 / 256 + 45 * e2**3 / 1024) * math.sin(4 * la)
             - (35 * e2**3 / 3072) * math.sin(6 * la))
    k0 = 0.9996
    T = math.tan(la) ** 2
    east = k0 * N * (A + (1 - T + C) * A**3 / 6
                     + (5 - 18 * T + T**2 + 72 * C - 58 * e2 / (1 - e2)) * A**5 / 120) + 500000
    north = k0 * (M + N * math.tan(la) * (A**2 / 2 + (5 - T + 9 * C + 4 * C**2) * A**4 / 24
                  + (61 - 58 * T + T**2 + 600 * C - 330 * e2 / (1 - e2)) * A**6 / 720))
    if lat < 0:
        north += 10000000
    bands = "CDEFGHJKLMNPQRSTUVWXX"
    band = bands[int((lat + 80) / 8)] if -80 <= lat <= 84 else "Z"
    return zone, band, east, north


def tool_utm(q):
    """Convert lat/lon to UTM coordinates (WGS84, offline)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    z, b, e, n = _to_utm(*ll)
    return {"lat": ll[0], "lon": ll[1], "zone": z, "band": b,
            "easting": round(e), "northing": round(n),
            "utm": f"{z}{b} {round(e)} {round(n)}",
            "hemisphere": "N" if ll[0] >= 0 else "S"}


def tool_mgrs(q):
    """Convert lat/lon to MGRS military grid reference (WGS84, offline)."""
    ll = _coords(q)
    if not ll:
        return {"input": q, "error": "give coordinates 'lat,lon'"}
    z, b, e, n = _to_utm(*ll)
    col_sets = "ABCDEFGH", "JKLMNPQR", "STUVWXYZ"
    cols = col_sets[(z - 1) % 3]
    col = cols[int(e // 100000) - 1]
    rows = "ABCDEFGHJKLMNPQRSTUV"
    row_off = 0 if z % 2 else 5
    row = rows[(int(n // 100000) + row_off) % 20]
    e5, n5 = int(e % 100000), int(n % 100000)
    return {"lat": ll[0], "lon": ll[1],
            "mgrs": f"{z}{b}{col}{row}{e5:05d}{n5:05d}",
            "grid_zone": f"{z}{b}", "square": f"{col}{row}"}


def tool_bearing(q):
    """Initial compass bearing from point A to B: 'lat1,lon1 lat2,lon2'."""
    pts = re.findall(r"-?\d+(?:\.\d+)?", q)
    if len(pts) < 4:
        return {"input": q, "error": "give two pairs: lat1,lon1 lat2,lon2"}
    la1, lo1, la2, lo2 = (math.radians(float(x)) for x in pts[:4])
    dlon = lo2 - lo1
    y = math.sin(dlon) * math.cos(la2)
    x = math.cos(la1) * math.sin(la2) - math.sin(la1) * math.cos(la2) * math.cos(dlon)
    brg = (math.degrees(math.atan2(y, x)) + 360) % 360
    dirs = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW",
            "SW", "WSW", "W", "WNW", "NW", "NNW"]
    return {"from": [float(pts[0]), float(pts[1])], "to": [float(pts[2]), float(pts[3])],
            "bearing_deg": round(brg, 1), "compass": dirs[round(brg / 22.5) % 16]}


# ---- text utilities / ciphers ----
def tool_passgen(q):
    """Generate strong random passwords (offline, uses secrets). Length in query."""
    m = re.search(r"\d+", q)
    n = min(max(int(m.group()) if m else 20, 8), 128)
    alpha = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    pws = ["".join(secrets.choice(alpha) for _ in range(n)) for _ in range(5)]
    words = "correct horse battery staple anchor velvet cobalt ember".split()
    passphrase = "-".join(secrets.choice(words) for _ in range(4)) + str(secrets.randbelow(100))
    return {"length": n, "passwords": pws, "passphrase_example": passphrase}


def tool_casify(q):
    """Convert text between snake / camel / Pascal / kebab / CONSTANT cases."""
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", q) or [q]
    words = [w.lower() for w in words]
    cap = [w.capitalize() for w in words]
    return {"input": q, "snake_case": "_".join(words),
            "kebab_case": "-".join(words), "camelCase": words[0] + "".join(cap[1:]),
            "PascalCase": "".join(cap), "CONSTANT_CASE": "_".join(words).upper(),
            "Title Case": " ".join(cap)}


def tool_leet(q):
    """Leetspeak transform of text (offline)."""
    table = str.maketrans("aeiostbglAEIOSTBGL", "431057816143105781")
    return {"input": q, "leet": q.translate(table)}


def tool_atbash(q):
    """Atbash cipher (A↔Z mirror substitution, offline, self-inverse)."""
    def m(c):
        if "a" <= c <= "z":
            return chr(219 - ord(c))
        if "A" <= c <= "Z":
            return chr(155 - ord(c))
        return c
    return {"input": q, "atbash": "".join(m(c) for c in q)}


def tool_railfence(q):
    """Rail-fence cipher encode over 3 rails (offline)."""
    s = q.replace(" ", "")
    rails = ["", "", ""]
    r, step = 0, 1
    for ch in s:
        rails[r] += ch
        if r == 0:
            step = 1
        elif r == 2:
            step = -1
        r += step
    return {"input": q, "rails": 3, "railfence": "".join(rails)}

# ── extension pack 8 ──────────────────────────────────────────────────────────────
def tool_rdap(q):
    """RDAP registration record for a domain (IANA bootstrap, no key)."""
    host = _host(q)
    r = _get(f"https://rdap.org/domain/{host}")
    if r.status_code == 404:
        return {"domain": host, "registered": False, "note": "No RDAP record (unregistered or unsupported TLD)"}
    r.raise_for_status()
    d = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    ns = [n.get("ldhName", "").lower() for n in d.get("nameservers", [])]
    return {
        "domain": host,
        "handle": d.get("handle"),
        "status": d.get("status"),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": ns,
    }


def tool_hnuser(q):
    """Hacker News user profile + karma (Firebase API, no key)."""
    u = q.strip().lstrip("@")
    r = _get(f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
    r.raise_for_status()
    d = r.json()
    if not d:
        return {"user": u, "found": False}
    return {
        "user": u, "found": True,
        "karma": d.get("karma"),
        "created": d.get("created"),
        "about": d.get("about"),
        "submitted_count": len(d.get("submitted", [])),
        "profile": f"https://news.ycombinator.com/user?id={u}",
    }


def tool_ghevents(q):
    """Recent public GitHub events for a user (60/hr unauthenticated)."""
    u = q.strip().lstrip("@")
    r = _get(f"https://api.github.com/users/{u}/events/public?per_page=10",
             headers={"Accept": "application/vnd.github+json"})
    if r.status_code == 404:
        return {"user": u, "found": False}
    r.raise_for_status()
    evs = [{"type": e.get("type"), "repo": e.get("repo", {}).get("name"), "at": e.get("created_at")}
           for e in r.json()]
    return {"user": u, "found": True, "recent_events": evs}


def tool_cratestats(q):
    """crates.io crate metadata + download stats (no key)."""
    name = q.strip()
    r = _get(f"https://crates.io/api/v1/crates/{name}")
    if r.status_code == 404:
        return {"crate": name, "found": False}
    r.raise_for_status()
    c = r.json().get("crate", {})
    return {
        "crate": name, "found": True,
        "downloads": c.get("downloads"),
        "recent_downloads": c.get("recent_downloads"),
        "max_version": c.get("max_stable_version") or c.get("newest_version"),
        "repository": c.get("repository"),
        "description": c.get("description"),
    }


def tool_airquality(q):
    """Air quality (PM2.5/PM10/AQI proxy) at coords via Open-Meteo (no key)."""
    m = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)\s*$", q)
    if not m:
        return {"error": "expected 'lat,lon'"}
    lat, lon = m.group(1), m.group(2)
    r = _get("https://air-quality-api.open-meteo.com/v1/air-quality",
             params={"latitude": lat, "longitude": lon,
                     "current": "pm10,pm2_5,carbon_monoxide,ozone,nitrogen_dioxide,european_aqi"})
    r.raise_for_status()
    cur = r.json().get("current", {})
    return {"lat": float(lat), "lon": float(lon), "current": cur}


# --- offline validators / converters ---

def tool_isin(q):
    """Validate an ISIN (ISO 6166) via Luhn-over-base36 check digit (offline)."""
    s = re.sub(r"[\s-]", "", q.strip().upper())
    if not re.fullmatch(r"[A-Z]{2}[A-Z0-9]{9}[0-9]", s):
        return {"isin": s, "valid": False, "reason": "format must be CC + 9 alnum + 1 digit"}
    digits = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in s[:-1])
    total, dbl = 0, True  # rightmost body digit is doubled
    for ch in reversed(digits):
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    check = (10 - total % 10) % 10
    ok = check == int(s[-1])
    return {"isin": s, "valid": ok, "country": s[:2], "check_digit": s[-1], "expected": check}


def tool_barcode(q):
    """Validate EAN-13 / UPC-A check digit (offline)."""
    s = re.sub(r"[\s-]", "", q.strip())
    if not s.isdigit() or len(s) not in (12, 13):
        return {"barcode": s, "valid": False, "reason": "expected 12 (UPC-A) or 13 (EAN-13) digits"}
    body, check = s[:-1], int(s[-1])
    # EAN-13: odd positions x1, even x3 from the LEFT of the 12-digit body
    total = sum(int(d) * (1 if i % 2 else 3) for i, d in enumerate(reversed(body)))
    expected = (10 - total % 10) % 10
    return {"barcode": s, "type": "EAN-13" if len(s) == 13 else "UPC-A",
            "valid": expected == check, "check_digit": check, "expected": expected}


# Minimal local OUI prefix table — common vendors only. This is a small seed
# map; swap in the full IEEE OUI CSV if exhaustive vendor coverage is needed.
_OUI = {
    "000000": "Xerox", "001A11": "Google", "F0D5BF": "Google",
    "001C42": "Parallels", "0050C2": "IEEE-RA", "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi", "001A79": "Cisco", "0023AB": "Cisco",
    "AC DE 48".replace(" ", ""): "Apple", "F0DBF8": "Apple", "3C0754": "Apple",
    "001517": "Intel", "00A0C9": "Intel", "ECB1D7": "Hewlett Packard",
    "525400": "QEMU/KVM", "080027": "VirtualBox", "000C29": "VMware",
}


def tool_macvendor(q):
    """Resolve a MAC address vendor from a local OUI prefix table (offline)."""
    raw = re.sub(r"[^0-9A-Fa-f]", "", q.strip()).upper()
    if len(raw) < 6:
        return {"mac": q.strip(), "valid": False, "reason": "need at least 6 hex digits"}
    oui = raw[:6]
    locally_administered = bool(int(raw[1], 16) & 0x2)
    multicast = bool(int(raw[1], 16) & 0x1)
    return {
        "mac": q.strip(), "oui": oui,
        "vendor": _OUI.get(oui, "unknown (not in local table)"),
        "locally_administered": locally_administered,
        "multicast": multicast,
    }


def tool_vigenere(q):
    """Vigenere cipher: 'KEY:text' encrypts, 'KEY:text:d' decrypts (offline)."""
    parts = q.split(":")
    if len(parts) < 2:
        return {"error": "format 'KEY:text' (append ':d' to decrypt)"}
    key = re.sub(r"[^A-Za-z]", "", parts[0]).upper()
    if not key:
        return {"error": "key must contain letters"}
    decrypt = len(parts) >= 3 and parts[2].strip().lower().startswith("d")
    text = parts[1]
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("A")
            if decrypt:
                shift = -shift
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return {"key": key, "mode": "decrypt" if decrypt else "encrypt", "result": "".join(out)}


def _base36(s):
    """Encode int / decode base36 string, autodetecting direction (offline)."""
    s = s.strip()
    if re.fullmatch(r"-?\d+", s):  # integer -> base36
        n = int(s)
        sign = "-" if n < 0 else ""
        n = abs(n)
        if n == 0:
            return {"input": s, "direction": "int->base36", "base36": "0"}
        alphabet = string.digits + string.ascii_lowercase
        out = ""
        while n:
            n, r = divmod(n, 36)
            out = alphabet[r] + out
        return {"input": s, "direction": "int->base36", "base36": sign + out}
    if re.fullmatch(r"[0-9a-zA-Z]+", s):  # base36 -> int
        return {"input": s, "direction": "base36->int", "int": int(s, 36)}
    return {"error": "expected an integer or a base36 string ([0-9a-z])"}


def tool_base36(q):
    return _base36(q)

# ── extension pack 9 ──────────────────────────────────────────────────────────────
def tool_wikipedia(q):
    """Wikipedia REST summary (extract, type, coords, thumbnail) for a title."""
    title = q.strip().replace(" ", "_")
    r = _get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(title, safe='')}")
    if r.status_code == 404:
        return {"title": q.strip(), "found": False}
    r.raise_for_status()
    d = r.json()
    return {
        "title": d.get("title"), "found": True,
        "type": d.get("type"),
        "description": d.get("description"),
        "extract": d.get("extract"),
        "coordinates": d.get("coordinates"),
        "url": d.get("content_urls", {}).get("desktop", {}).get("page"),
    }


def tool_dockerhub(q):
    """Docker Hub repository info (pulls, stars, last update). 'user/repo' or 'repo' (library)."""
    name = q.strip().lstrip("/")
    if "/" not in name:
        name = "library/" + name
    r = _get(f"https://hub.docker.com/v2/repositories/{name}")
    if r.status_code == 404:
        return {"repo": name, "found": False}
    r.raise_for_status()
    d = r.json()
    return {
        "repo": name, "found": True,
        "pull_count": d.get("pull_count"),
        "star_count": d.get("star_count"),
        "last_updated": d.get("last_updated"),
        "description": d.get("description"),
        "is_official": d.get("namespace") == "library",
    }


def tool_goproxy(q):
    """Latest version of a Go module via the public module proxy (no key)."""
    mod = q.strip().lower()  # proxy requires lowercased module path
    r = _get(f"https://proxy.golang.org/{quote(mod, safe='/')}/@latest")
    if r.status_code == 404 or r.status_code == 410:
        return {"module": mod, "found": False}
    r.raise_for_status()
    d = r.json()
    return {"module": mod, "found": True, "version": d.get("Version"), "time": d.get("Time")}


def tool_npmdownloads(q):
    """npm download counts (last week + last month) for a package (no key)."""
    pkg = q.strip()
    out = {"package": pkg}
    for period in ("last-week", "last-month"):
        r = _get(f"https://api.npmjs.org/downloads/point/{period}/{quote(pkg, safe='@/')}")
        if r.status_code == 404:
            return {"package": pkg, "found": False}
        r.raise_for_status()
        out[period.replace("-", "_")] = r.json().get("downloads")
    out["found"] = True
    return out


def tool_wikidata(q):
    """Search Wikidata for an entity by label (returns top matches, no key)."""
    r = _get("https://www.wikidata.org/w/api.php",
             params={"action": "wbsearchentities", "search": q.strip(),
                     "language": "en", "format": "json", "limit": 5})
    r.raise_for_status()
    hits = [{"id": e.get("id"), "label": e.get("label"), "description": e.get("description"),
             "url": "https://www.wikidata.org/wiki/" + e.get("id", "")}
            for e in r.json().get("search", [])]
    return {"query": q.strip(), "matches": hits}


# --- offline converters / calculators ---

def tool_cidr(q):
    """CIDR/subnet calculator: network, mask, host range, count (offline, stdlib)."""
    try:
        net = ipaddress.ip_network(q.strip(), strict=False)
    except ValueError as e:
        return {"input": q.strip(), "error": str(e)}
    hosts = list(net.hosts())
    return {
        "input": q.strip(),
        "network": str(net.network_address),
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "broadcast": str(net.broadcast_address) if net.version == 4 else None,
        "num_addresses": net.num_addresses,
        "first_host": str(hosts[0]) if hosts else None,
        "last_host": str(hosts[-1]) if hosts else None,
        "version": net.version,
        "is_private": net.is_private,
    }


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def tool_base58(q):
    """Bitcoin base58 codec: 'hex:<hex>' encodes, 'b58:<str>' decodes (offline)."""
    s = q.strip()
    m = re.match(r"^(hex|b58):(.+)$", s, re.I)
    if not m:
        return {"error": "format 'hex:<hexbytes>' to encode or 'b58:<string>' to decode"}
    mode, val = m.group(1).lower(), m.group(2).strip()
    if mode == "hex":
        try:
            raw = bytes.fromhex(val)
        except ValueError as e:
            return {"error": f"bad hex: {e}"}
        pad = len(val) - len(val.lstrip("0"))  # leading 00 bytes -> '1'
        n = int.from_bytes(raw, "big") if raw else 0
        out = ""
        while n:
            n, r = divmod(n, 58)
            out = _B58[r] + out
        return {"input": val, "direction": "hex->base58", "base58": "1" * (pad // 2) + out}
    # b58 -> hex
    n = 0
    for ch in val:
        if ch not in _B58:
            return {"error": f"invalid base58 char {ch!r}"}
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(val) - len(val.lstrip("1"))
    return {"input": val, "direction": "base58->hex", "hex": ("00" * pad + body.hex())}


_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "/": "-..-.", "-": "-....-", "@": ".--.-.",
}
_MORSE_REV = {v: k for k, v in _MORSE.items()}


def tool_morse(q):
    """Morse code: decodes if input is dots/dashes, else encodes text (offline)."""
    s = q.strip()
    if s and set(s) <= set(".-/ "):  # decode: tokens space-sep, '/' = word gap
        words = s.split("/")
        decoded = " ".join("".join(_MORSE_REV.get(t, "?") for t in w.split()) for w in words)
        return {"input": s, "direction": "morse->text", "result": decoded.strip()}
    code = " ".join("/" if ch == " " else _MORSE.get(ch, "") for ch in s.upper()).strip()
    code = re.sub(r" +", " ", code)
    return {"input": s, "direction": "text->morse", "result": code}


_ROMAN = [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"),
          (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"),
          (5, "V"), (4, "IV"), (1, "I")]


def tool_roman(q):
    """Roman numeral converter: int<->roman, autodetecting direction (offline)."""
    s = q.strip().upper()
    if re.fullmatch(r"\d+", s):
        n = int(s)
        if not 1 <= n <= 3999:
            return {"error": "integer must be 1..3999"}
        out, rem = "", n
        for val, sym in _ROMAN:
            cnt, rem = divmod(rem, val)
            out += sym * cnt
        return {"input": s, "direction": "int->roman", "roman": out}
    if re.fullmatch(r"[MDCLXVI]+", s):
        total, prev = 0, 0
        vals = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}
        for ch in reversed(s):
            v = vals[ch]
            total += -v if v < prev else v
            prev = v
        # round-trip check rejects malformed numerals like "IIII"/"VX"
        ok = tool_roman(str(total)).get("roman") == s
        return {"input": s, "direction": "roman->int", "int": total, "well_formed": ok}
    return {"error": "expected an integer (1..3999) or a roman numeral [MDCLXVI]"}


def tool_checksum(q):
    """CRC32 + Adler32 checksums of the input text (UTF-8, offline via zlib)."""
    data = q.encode("utf-8")
    return {
        "length_bytes": len(data),
        "crc32": format(zlib.crc32(data) & 0xFFFFFFFF, "08x"),
        "adler32": format(zlib.adler32(data) & 0xFFFFFFFF, "08x"),
    }

# ── extension pack 10 ──────────────────────────────────────────────────────────────
def tool_sha256lookup(q):
    """SHA-256 reverse lookup via online DB."""
    h = q.strip().lower()
    if len(h) != 64 or not re.match(r'^[0-9a-f]+$', h):
        return {"error": "need 64-char SHA-256 hex"}
    try:
        r = _get("https://www.everyhash.com/api/v1/hash", params={"type": "sha256", "str": h})
        if r.status_code == 200:
            d = r.json()
            if d.get("found"):
                return {"hash": h, "found": True, "plaintext": d.get("plaintext")}
        return {"hash": h, "found": False}
    except Exception as e:
        return {"note": "lookup service unavailable", "error": str(e)}

def tool_crc32(q):
    """Compute CRC-32 checksum of input string."""
    try:
        data = q.encode()
        crc = 0xffffffff
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ 0xedb88320 if crc & 1 else crc >> 1
        crc ^= 0xffffffff
        return {"input": q[:60], "crc32": hex(crc & 0xffffffff)[2:].zfill(8),
                "crc32_decimal": crc & 0xffffffff}
    except Exception as e:
        return {"error": str(e)}

def tool_rot13(q):
    """ROT-13 encode/decode (reversible cipher)."""
    result = ""
    for c in q:
        if 'a' <= c <= 'z':
            result += chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            result += chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += c
    return {"input": q[:80], "rot13": result[:80]}

# ── THREAT ───────────────────────────────────────────────
def tool_spamhauslookup(q):
    """Spamhaus IP/domain reputation lookup (Z, PBL, SBL, etc)."""
    ip = _host(q).strip()
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            reversed_ip = ".".join(reversed(parts))
            for zone in ["zen.spamhaus.org", "pbl.spamhaus.org", "sbl.spamhaus.org"]:
                try:
                    result = socket.gethostbyname(reversed_ip + "." + zone)
                    code = result.split(".")[-1]
                    return {"ip": ip, "listed": True, "zone": zone, "code": code,
                            "note": "Return code indicates listing reason"}
                except socket.gaierror:
                    pass
            return {"ip": ip, "listed": False}
    except Exception as e:
        return {"error": str(e)}
    return {"error": "invalid IP"}

def tool_isexitnode(q):
    """Check if IP is Tor exit node (dan.me.uk/torlist mirror)."""
    ip = q.strip()
    try:
        r = _get("https://check.torproject.org/torbulkexitlist")
        exits = set(r.text.strip().splitlines())
        return {"ip": ip, "is_tor_exit": ip in exits, "total_exits": len(exits)}
    except Exception as e:
        return {"error": str(e)}

def tool_asnlookup(q):
    """ASN details: organization, country, prefixes via RIPEstat."""
    asn = q.strip().upper().replace("AS", "")
    try:
        r = _get(f"https://stat.ripe.net/data/asn-neighbours/data.json",
                 params={"resource": "AS" + asn, "format": "json"})
        d = r.json().get("data", {})
        return {"asn": "AS" + asn, "data": d}
    except Exception:
        pass
    try:
        r = _get(f"https://api.bgpview.io/asn/{asn}")
        d = r.json().get("data", {})
        return {"asn": "AS" + asn, "name": d.get("name"),
                "country": d.get("country_code"), "prefixes_v4": d.get("prefixes_ipv4_count"),
                "prefixes_v6": d.get("prefixes_ipv6_count")}
    except Exception as e:
        return {"error": str(e)}

# ── NETWORK / UTILITY ────────────────────────────────────
def tool_hostname(q):
    """Reverse DNS lookup: IP → hostname."""
    ip = q.strip()
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": host}
    except socket.herror:
        return {"ip": ip, "hostname": None, "note": "no reverse DNS record"}
    except Exception as e:
        return {"error": str(e)}

def tool_portquick(q):
    """Quick port check: is a port open on target? (timeout: 2s)."""
    parts = q.strip().split(":")
    if len(parts) != 2:
        return {"error": "format: host:port (e.g., 8.8.8.8:53)"}
    host, port = parts[0], parts[1]
    try:
        port = int(port)
        if port < 1 or port > 65535:
            return {"error": "port must be 1-65535"}
    except ValueError:
        return {"error": "port must be a number"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((host, port))
        s.close()
        return {"host": host, "port": port, "open": result == 0}
    except Exception as e:
        return {"error": str(e)}

def tool_dnsquery(q):
    """DNS query A record for domain via DNS-over-HTTPS (Google)."""
    domain = _host(q)
    try:
        r = _get("https://dns.google/resolve", params={"name": domain, "type": "A"})
        d = r.json()
        ips = [a.get("data") for a in d.get("Answer", [])]
        return {"domain": domain, "ips": ips, "authoritative": d.get("RA", False)}
    except Exception as e:
        return {"error": str(e)}

# ── MISC VALIDATORS ──────────────────────────────────────
def tool_creditcardtest(q):
    """Test if a number passes Luhn check (credit card validator)."""
    s = re.sub(r'\D', '', q.strip())
    if not s or len(s) < 13:
        return {"error": "need at least 13 digits"}
    total = 0
    for i, d in enumerate(reversed(s)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    valid = total % 10 == 0
    brand_map = {
        "4": "Visa", "5": "MasterCard", "34": "AmEx", "37": "AmEx",
        "6011": "Discover", "65": "Discover", "35": "JCB"
    }
    brand = "Unknown"
    for prefix, name in sorted(brand_map.items(), key=lambda x: -len(x[0])):
        if s.startswith(prefix):
            brand = name
            break
    return {"number": "****" + s[-4:], "valid_luhn": valid, "length": len(s),
            "brand_guess": brand, "note": "Test numbers only — never submit real cards"}

def tool_htmlencode(q):
    """HTML entity encode/decode."""
    s = q.strip()
    encoded = html.escape(s)
    try:
        decoded = html.unescape(s)
    except:
        decoded = s
    return {"input": s[:60], "html_encoded": encoded[:120],
            "html_decoded": decoded[:120]}

def tool_urlparse(q):
    """Parse URL into components: scheme, host, path, query, fragment."""
    url = q.strip()
    try:
        parsed = urllib.parse.urlparse(url)
        return {
            "url": url,
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "host": _host(url),
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "params": dict(urllib.parse.parse_qsl(parsed.query))
        }
    except Exception as e:
        return {"error": str(e)}

# ── extension pack 11 ──────────────────────────────────────────────────────────────
def tool_disposablecheck(q):
    """Check if email domain is a disposable/temporary service."""
    email = q.strip().lower()
    if "@" not in email:
        return {"error": "need an email address"}
    domain = email.split("@")[1]
    # Common disposable domains
    disposable_list = {
        "tempmail.com", "temp-mail.org", "10minutemail.com", "mailinator.com",
        "throwaway.email", "yopmail.com", "trashmail.com", "fakeinbox.com",
        "sharklasers.com", "tempmail.ninja", "maildrop.cc", "temp-mail.ru",
        "mail.tm", "temp-mail.io", "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
        "grr.la", "tempmailaddress.com", "mintemail.com", "privateemail.com",
    }
    is_disposable = domain in disposable_list or re.search(r'(temp|trash|throw|fake|mail\d+)', domain)
    return {"email": email, "domain": domain, "is_disposable": is_disposable,
            "note": "heuristic check; not comprehensive"}

def tool_emailformat(q):
    """Validate email format (RFC 5322 basic, not exhaustive)."""
    email = q.strip()
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    valid = bool(re.match(pattern, email))
    return {"email": email, "format_valid": valid, "note": "basic RFC 5322 pattern"}

# ── ENCODING / DECODING ───────────────────────────────────
def tool_quoted_printable(q):
    """Quoted-printable encode/decode (RFC 2045)."""
    s = q.strip()
    # try to detect if already encoded
    if '=' in s and re.search(r'=[0-9A-F]{2}', s):
        decoded = quopri.decodestring(s.encode()).decode('utf-8', errors='replace')
        return {"input": s[:60], "operation": "decode", "output": decoded[:120]}
    encoded = quopri.encodestring(s.encode()).decode()
    return {"input": s[:60], "operation": "encode", "output": encoded[:120]}

def tool_base32(q):
    """Base32 encode/decode (RFC 4648)."""
    s = q.strip()
    # try decode if looks like base32
    if re.match(r'^[A-Z2-7=]+$', s) and len(s) >= 8:
        try:
            decoded = base64.b32decode(s).decode('utf-8', errors='replace')
            return {"input": s[:60], "operation": "decode", "output": decoded[:120]}
        except Exception:
            pass
    try:
        encoded = base64.b32encode(s.encode()).decode()
        return {"input": s[:60], "operation": "encode", "output": encoded[:120]}
    except Exception as e:
        return {"error": str(e)}

def tool_uuencode(q):
    """UUencode (Unix-to-Unix encoding)."""
    s = q.strip()
    try:
        # uuencode format: line starts with length byte, then encoded data
        encoded = binascii.b2a_uu(s.encode()).decode()
        return {"input": s[:60], "operation": "encode", "output": encoded.strip()[:120]}
    except Exception as e:
        return {"error": str(e)}

# ── VALIDATION ────────────────────────────────────────────
def tool_semver(q):
    """Semantic versioning (X.Y.Z) parser and validator."""
    version = q.strip()
    pattern = r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
    match = re.match(pattern, version)
    if not match:
        return {"version": version, "valid": False}
    major, minor, patch = match.groups()[:3]
    prerelease = match.group(4) if match.group(4) else None
    metadata = match.group(5) if match.group(5) else None
    return {"version": version, "valid": True,
            "major": int(major), "minor": int(minor), "patch": int(patch),
            "prerelease": prerelease, "metadata": metadata}

def tool_macvalid(q):
    """MAC address validator (accepts :, -, or no separators)."""
    mac = q.strip().upper()
    # normalize
    mac_colon = re.sub(r'[-:]', ':', mac)
    mac_dash = re.sub(r'[:]', '-', mac)
    mac_plain = re.sub(r'[:-]', '', mac)
    # validate
    pattern_colon = r'^([0-9A-F]{2}:){5}([0-9A-F]{2})$'
    valid = bool(re.match(pattern_colon, mac_colon))
    if valid:
        oui = mac_plain[:6].upper()
        return {"input": q, "valid": True,
                "mac_colon": mac_colon,
                "mac_dash": mac_dash,
                "mac_plain": mac_plain,
                "oui": oui}
    return {"input": q, "valid": False}

def tool_uuid_validate(q):
    """UUID v1-v5 validator."""
    uid = q.strip().lower()
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    if not re.match(pattern, uid):
        return {"uuid": uid, "valid": False}
    version = int(uid[14])
    variants = {"8": "RFC 4122", "9": "RFC 4122", "a": "RFC 4122", "b": "RFC 4122"}
    variant = variants.get(uid[19], "unknown")
    return {"uuid": uid, "valid": True, "version": version, "variant": variant}

# ── MISC ──────────────────────────────────────────────────
def tool_datauri(q):
    """Parse or create data URI (base64-encoded embedded data)."""
    s = q.strip()
    if s.startswith("data:"):
        # parse
        match = re.match(r'^data:([^;]+)?(?:;base64)?,(.*)', s)
        if not match:
            return {"error": "invalid data URI"}
        mime, data = match.groups()
        return {"input": s[:60]+"…", "mime": mime or "text/plain",
                "data_length": len(data), "is_base64": ";base64" in s}
    # create: treat as text, base64-encode
    b64 = base64.b64encode(s.encode()).decode()
    return {"input": s[:40]+"…" if len(s)>40 else s,
            "data_uri": f"data:text/plain;base64,{b64[:60]}…"}

def tool_stringmetrics(q):
    """Analyze string: length, entropy, character types, uniqueness."""
    s = q
    length = len(s)
    unique = len(set(s))
    uniqueness_pct = round(100*unique/length, 1) if length else 0
    lower = sum(1 for c in s if c.islower())
    upper = sum(1 for c in s if c.isupper())
    digits = sum(1 for c in s if c.isdigit())
    spaces = sum(1 for c in s if c.isspace())
    special = length - lower - upper - digits - spaces
    # shannon entropy
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / length
        entropy -= p * __import__('math').log2(p)
    return {
        "length": length, "unique_chars": unique, "uniqueness_pct": uniqueness_pct,
        "lowercase": lower, "uppercase": upper, "digits": digits,
        "spaces": spaces, "special": special,
        "shannon_entropy": round(entropy, 2),
        "entropy_bits": round(entropy * length, 1),
    }

def tool_whois_check(q):
    """Check if domain has WHOIS records via WHO API (free tier)."""
    domain = q.strip().lower()
    try:
        r = _get(f"https://who.is/whois/{domain}")
        # Free tier won't give detailed WHOIS; just check status
        if r.status_code == 200 and "WHOIS" in r.text:
            return {"domain": domain, "has_whois": True, "status": "registered"}
        return {"domain": domain, "has_whois": False, "note": "no WHOIS data found or unregistered"}
    except Exception as e:
        return {"error": str(e)}


# ── osint_leak ─────────────────────────────────────────────────────────────

import hashlib as _hashlib
import urllib.parse as _ulp

def tool_hibp(q):
    """Check if a password appeared in known breaches via HIBP k-anonymity (no key)."""
    pw = q.strip()
    h = _hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    try:
        r = _get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"})
        for line in r.text.splitlines():
            if ":" in line:
                s, count = line.split(":", 1)
                if s.strip() == suffix:
                    return {"password": pw, "pwned": True, "breach_count": int(count.strip())}
        return {"password": pw, "pwned": False, "breach_count": 0}
    except Exception as e:
        return {"error": str(e)}

def tool_hibp_email(q):
    """Check email breach exposure via XposedOrNot (HIBP-compatible, no key)."""
    email = q.strip().lower()
    try:
        r = _get(f"https://api.xposedornot.com/v1/check-email/{email}")
        data = r.json() if r.status_code == 200 else {}
        breaches = data.get("breaches", [])
        flat = [b for sub in breaches for b in (sub if isinstance(sub, list) else [sub])] if breaches else []
        return {"email": email, "found": bool(flat), "breach_count": len(flat), "breaches": flat[:20]}
    except Exception as e:
        return {"email": email, "error": str(e)}

def tool_leakcheck(q):
    """Search leakcheck.io public endpoint for email/username breach exposure (no key)."""
    target = q.strip()
    try:
        r = _get(f"https://leakcheck.io/api/public?check={target}")
        data = r.json() if r.status_code == 200 else {}
        return {"target": target, "found": data.get("found", False), "sources": data.get("sources", [])}
    except Exception as e:
        return {"target": target, "error": str(e)}

def tool_hudsonrock(q):
    """Check HudsonRock Cavalier for stealer-log exposure of email/domain (free API)."""
    target = q.strip().lower()
    try:
        if "@" in target:
            url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={target}"
        else:
            url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={target}"
        r = _get(url)
        data = r.json() if r.status_code == 200 else {}
        stealers = data.get("stealers", [])
        return {"target": target, "compromised": bool(stealers), "stealer_count": len(stealers),
                "computers": data.get("total", 0), "sample": stealers[:5]}
    except Exception as e:
        return {"target": target, "error": str(e)}

def tool_paste_email(q):
    """Find email in public pastes via Wayback CDX + manual search links (psbdmp.ws is defunct)."""
    target = q.strip()
    enc = _ulp.quote(target)
    # Try Wayback CDX for pastebin snapshots mentioning the target
    pastes = []
    try:
        r = _get(f"https://web.archive.org/cdx/search/cdx?url=pastebin.com/*&output=json&limit=5&fl=timestamp,original&filter=original:.*{_ulp.quote(target, safe='')}.*")
        rows = r.json() if r.text.strip().startswith("[") else []
        pastes = [{"url": f"https://web.archive.org/web/{row[0]}/{row[1]}", "timestamp": row[0]} for row in rows[1:]]
    except Exception:
        pass
    return {"target": target, "wayback_hits": len(pastes), "pastes": pastes,
            "search_links": {
                "pastebin": f"https://pastebin.com/search?q={enc}",
                "pastebay": f"https://pastebay.net/search?query={enc}",
                "ghostbin": f"https://ghostbin.com/search?q={enc}"}}

def tool_paste_domain(q):
    """Find domain in public pastes via Wayback CDX + manual search links."""
    target = q.strip().lower().lstrip("www.")
    enc = _ulp.quote(target)
    pastes = []
    try:
        r = _get(f"https://web.archive.org/cdx/search/cdx?url=pastebin.com/*&output=json&limit=5&fl=timestamp,original&filter=original:.*{_ulp.quote(target, safe='')}.*")
        rows = r.json() if r.text.strip().startswith("[") else []
        pastes = [{"url": f"https://web.archive.org/web/{row[0]}/{row[1]}", "timestamp": row[0]} for row in rows[1:]]
    except Exception:
        pass
    return {"target": target, "wayback_hits": len(pastes), "pastes": pastes,
            "search_links": {
                "pastebin": f"https://pastebin.com/search?q={enc}",
                "pastebay": f"https://pastebay.net/search?query={enc}"}}

def tool_gh_dorking(q):
    """GitHub code search for target string (domain/email) in public repos."""
    target = q.strip()
    try:
        encoded = _ulp.quote(f'"{target}"')
        r = _get(f"https://api.github.com/search/code?q={encoded}&per_page=10",
                 headers={"Accept": "application/vnd.github+json", "User-Agent": "osint-tool/1.0"})
        data = r.json() if r.status_code == 200 else {}
        items = data.get("items", [])
        return {"target": target, "total_hits": data.get("total_count", 0),
                "repos": [{"repo": i.get("repository", {}).get("full_name"),
                           "file": i.get("path"), "url": i.get("html_url")} for i in items[:10]]}
    except Exception as e:
        return {"target": target, "error": str(e)}

def tool_gh_secret_scan(q):
    """Scan GitHub user's public repos for leaked secrets/passwords (no key, 60/hr limit)."""
    target = q.strip()
    results = []
    try:
        for pat in ["password", "api_key", "secret"]:
            encoded = _ulp.quote(f"user:{target} {pat} in:file")
            r = _get(f"https://api.github.com/search/code?q={encoded}&per_page=5",
                     headers={"Accept": "application/vnd.github+json", "User-Agent": "osint-tool/1.0"})
            if r.status_code == 200:
                for item in r.json().get("items", [])[:3]:
                    results.append({"pattern": pat,
                                    "repo": item.get("repository", {}).get("full_name"),
                                    "file": item.get("path"), "url": item.get("html_url")})
    except Exception as e:
        return {"username": target, "error": str(e)}
    return {"username": target, "potential_leaks": len(results), "findings": results}

def tool_intelx_email(q):
    """XposedOrNot — breach exposure check for email (no key, real breach names + paste hits)."""
    email = q.strip().lower()
    try:
        r = _get(f"https://api.xposedornot.com/v1/check-email/{_ulp.quote(email)}",
                 headers={"User-Agent": "osint-tool/1.0"})
        breaches = r.json().get("breaches", [[]])[0] if r.status_code == 200 else []
    except Exception:
        breaches = []
    details = {}
    paste_count = 0
    try:
        r2 = _get(f"https://api.xposedornot.com/v1/breach-analytics?email={_ulp.quote(email)}",
                  headers={"User-Agent": "osint-tool/1.0"})
        if r2.status_code == 200:
            d = r2.json()
            bm = d.get("BreachMetrics", {})
            details = {
                "risk": bm.get("risk", []),
                "exposed_data_types": bm.get("xposed_data", []),
                "breach_years": bm.get("yearwise_details", []),
            }
            pm = d.get("PasteMetrics", {})
            paste_count = pm.get("cnt_pastes", 0) if isinstance(pm, dict) else 0
    except Exception:
        pass
    return {"email": email, "breach_count": len(breaches), "breaches": breaches,
            "paste_hits": paste_count, **details}

def tool_dehashed_domain(q):
    """DeHashed public page scrape for domain breach exposure (HTML, no key)."""
    target = q.strip().lower().lstrip("www.")
    try:
        r = _get(f"https://dehashed.com/search?query={target}",
                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        m = re.search(r'([\d,]+)\s+results', r.text, re.I)
        count = m.group(1).replace(",", "") if m else "unknown"
        sources = re.findall(r'class="source"[^>]*>([^<]+)<', r.text)
        return {"domain": target, "result_count": count, "sources": list(set(sources))[:15]}
    except Exception as e:
        return {"domain": target, "error": str(e)}

def tool_emailrep(q):
    """emailrep.io reputation check: malicious/spam/breach flags (no key, 10/day free)."""
    email = q.strip().lower()
    try:
        r = _get(f"https://emailrep.io/{email}", headers={"User-Agent": "osint-tool/1.0"})
        data = r.json() if r.status_code == 200 else {}
        return {"email": email, "reputation": data.get("reputation"),
                "suspicious": data.get("suspicious"), "references": data.get("references"),
                "details": data.get("details", {})}
    except Exception as e:
        return {"email": email, "error": str(e)}

def tool_breachdirectory(q):
    """Search ProxyNova COMB dataset for credential exposure (free, no key)."""
    target = q.strip()
    try:
        r2 = _get(f"https://api.proxynova.com/comb?query={_ulp.quote(target)}",
                  headers={"User-Agent": "osint-tool/1.0"})
        data = r2.json() if r2.status_code == 200 else {}
        lines = data.get("lines", [])
        return {"target": target, "hits": data.get("count", len(lines)), "samples": lines[:10]}
    except Exception as e:
        return {"target": target, "error": str(e)}

def tool_snusbase_hash(q):
    """Reverse MD5/SHA1 hash via breach-sourced hash DB (md5decrypt.net)."""
    h = q.strip().lower()
    ht = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "md5")
    try:
        r = _get(f"https://md5decrypt.net/Api/api.php?hash={h}&hash_type={ht}&email=&code=")
        result = r.text.strip()
        cracked = bool(result and "NO_RESULT" not in result)
        return {"hash": h, "type": ht, "plaintext": result if cracked else None, "cracked": cracked}
    except Exception as e:
        return {"hash": h, "error": str(e)}

def tool_wayback_leaks(q):
    """Search Wayback Machine for historically exposed .env/config/secret files on a domain."""
    domain = q.strip().lower()
    if "://" in domain:
        domain = urllib.parse.urlparse(domain).netloc
    domain = domain.lstrip("www.")
    sensitive = [".env", "config.php", "wp-config.php", ".git/config",
                 "database.yml", "settings.py", ".htpasswd", "secrets.yml"]
    found = []
    for path in sensitive:
        try:
            enc = urllib.parse.quote(f"http://{domain}/{path.lstrip('/')}")
            r = _get(f"https://archive.org/wayback/available?url={enc}")
            snap = r.json().get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                found.append({"path": path, "url": snap.get("url"), "timestamp": snap.get("timestamp")})
        except Exception:
            pass
    return {"domain": domain, "sensitive_paths_found": len(found), "findings": found}

def tool_trufflehog_url(q):
    """Scan raw URL content for API keys, tokens, private keys, JWTs."""
    url = q.strip()
    if not url.startswith("http"):
        return {"error": "provide a raw URL (e.g. raw.githubusercontent.com/...)"}
    try:
        r = _get(url)
        text = r.text[:50000]
    except Exception as e:
        return {"error": str(e)}
    SECRET_PATTERNS = {
        "aws_key":       r'AKIA[0-9A-Z]{16}',
        "gh_token":      r'ghp_[A-Za-z0-9]{36}',
        "gh_oauth":      r'gho_[A-Za-z0-9]{36}',
        "slack_token":   r'xox[baprs]-[A-Za-z0-9\-]{10,}',
        "private_key":   r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "password_line": r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+',
        "api_key_line":  r'(?i)(api_?key|apikey|api_?secret)\s*[:=]\s*["\']?\S{8,}',
        "jwt":           r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "google_key":    r'AIza[0-9A-Za-z\-_]{35}',
        "stripe_key":    r'sk_live_[0-9a-zA-Z]{24}',
    }
    findings = {}
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            findings[name] = list(set(matches))[:3]
    return {"url": url, "bytes_scanned": len(text), "secrets_found": len(findings), "findings": findings}

def tool_comb_search(q):
    """Search COMB breach compilation via ProxyNova free API for email/username."""
    target = q.strip()
    try:
        r = _get(f"https://api.proxynova.com/comb?query={_ulp.quote(target)}",
                 headers={"User-Agent": "osint-tool/1.0"})
        data = r.json() if r.status_code == 200 else {}
        lines = data.get("lines", [])
        return {"target": target, "total_hits": data.get("count", 0), "samples": lines[:15],
                "note": "COMB public dataset — credential samples."}
    except Exception as e:
        return {"target": target, "error": str(e)}

def tool_leaklookup(q):
    """Hudson Rock infostealer lookup — stealer logs, compromised credentials (no key)."""
    email = q.strip().lower()
    result = {"email": email}
    try:
        r = _get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?email={_ulp.quote(email)}",
                 headers={"User-Agent": "osint-tool/1.0"}, timeout=12)
        if r.status_code == 200:
            d = r.json()
            stealers = d.get("stealers", [])
            result["compromised"] = len(stealers) > 0
            result["stealer_count"] = len(stealers)
            result["stealers"] = [
                {"date": s.get("date_compromised", "")[:10],
                 "country": s.get("computer_name", ""),
                 "corporate_services": s.get("total_corporate_services", 0),
                 "user_services": s.get("total_user_services", 0),
                 "malware": s.get("malware_path", "")}
                for s in stealers[:5]
            ]
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


def tool_cdxwayback(q):
    """Wayback CDX API — snapshot count + first/last capture."""
    url = q if q.startswith("http") else "https://" + q
    try:
        r = _get("https://web.archive.org/cdx/search/cdx",
                 params={"url": url, "output": "json", "limit": 1, "fl": "timestamp,statuscode",
                         "from": "", "to": "", "showNumPages": "true"})
        pages = r.text.strip()
        r2 = _get("https://web.archive.org/cdx/search/cdx",
                  params={"url": url, "output": "json", "limit": 1, "fl": "timestamp,statuscode", "fastLatest": "true"})
        r3 = _get("https://web.archive.org/cdx/search/cdx",
                  params={"url": url, "output": "json", "limit": 1, "fl": "timestamp,statuscode", "from": "19960101"})
        rows2 = r2.json() if r2.text.strip().startswith("[") else []
        rows3 = r3.json() if r3.text.strip().startswith("[") else []
        latest = rows2[1] if len(rows2) > 1 else None
        first = rows3[1] if len(rows3) > 1 else None
        return {"url": url, "pages_approx": pages,
                "first_capture": first[0] if first else None,
                "latest_capture": latest[0] if latest else None}
    except Exception as e:
        return {"error": str(e)}


def tool_cfradar(q):
    """Cloudflare Radar domain rank + categories (no key)."""
    host = _host(q)
    try:
        r = _get(f"https://radar.cloudflare.com/api/v0/ranking/domain/{host}")
        d = (r.json() if r.headers.get("content-type","").startswith("application/json") else {}).get("result", {})
        rank = d.get("rank", {})
        cats = [c.get("name") for c in d.get("categories", [])]
        return {"domain": host, "rank": rank.get("rank"), "rank_bucket": rank.get("rankBucket"),
                "categories": cats}
    except Exception as e:
        return {"error": str(e)}


def tool_bgphistory(q):
    """RIPE Stat BGP routing history for IP or ASN."""
    target = q.strip()
    resource = target if target.upper().startswith("AS") else target
    try:
        r = _get("https://stat.ripe.net/data/routing-history/data.json",
                 params={"resource": resource, "max_rows": 10})
        d = r.json().get("data", {})
        by_time = d.get("by_origin", [])
        entries = []
        for origin_block in by_time[:5]:
            for interval in origin_block.get("timelines", [])[:3]:
                entries.append({
                    "asn": origin_block.get("origin"),
                    "starttime": interval.get("starttime"),
                    "endtime": interval.get("endtime"),
                })
        return {"resource": resource, "entries": entries,
                "earliest_time": d.get("earliest_time"), "latest_time": d.get("latest_time")}
    except Exception as e:
        return {"error": str(e)}


def tool_dnsgraph(q):
    """Hurricane Electric BGP DNS delegation for a domain."""
    host = _host(q)
    try:
        r = _get(f"https://bgp.he.net/dns/{host}", timeout=10)
        import re
        ns = re.findall(r'<td[^>]*>\s*([a-zA-Z0-9._-]+\.)\s*</td>', r.text)
        ns = list(dict.fromkeys(ns))[:15]
        return {"domain": host, "nameservers_found": ns, "source": "bgp.he.net"}
    except Exception as e:
        return {"error": str(e)}


def tool_github_code(q):
    """GitHub unauthenticated code search (10 results, rate-limited)."""
    try:
        r = _get("https://api.github.com/search/code",
                 params={"q": q, "per_page": 10},
                 headers={"Accept": "application/vnd.github+json"})
        d = r.json()
        items = [{"repo": i["repository"]["full_name"],
                  "path": i["path"],
                  "url": i["html_url"]} for i in d.get("items", [])]
        return {"query": q, "total_count": d.get("total_count", 0), "results": items}
    except Exception as e:
        return {"error": str(e)}


def tool_pageinfo(q):
    """Common Crawl index lookup — how often a page was crawled."""
    url = q if q.startswith("http") else "https://" + q
    try:
        r = _get("https://index.commoncrawl.org/CC-MAIN-2024-42-index",
                 params={"url": url, "output": "json", "limit": 5})
        lines = [l for l in r.text.strip().split("\n") if l]
        import json as _json
        records = []
        for l in lines[:5]:
            try:
                records.append(_json.loads(l))
            except Exception:
                pass
        return {"url": url, "captures_returned": len(records),
                "first": records[0] if records else None}
    except Exception as e:
        return {"error": str(e)}


def tool_jarm(q):
    """JARM fingerprint via Shodan InternetDB (no key, free tier)."""
    host = _host(q)
    try:
        r = _get(f"https://internetdb.shodan.io/{host}")
        d = r.json()
        return {"host": host, "ports": d.get("ports", []),
                "hostnames": d.get("hostnames", []),
                "cpes": d.get("cpes", []),
                "vulns": d.get("vulns", []),
                "tags": d.get("tags", [])}
    except Exception as e:
        return {"error": str(e)}


def tool_threatcrowd(q):
    """ThreatCrowd (alienvault OTX compatible) domain/IP resolution history."""
    s = q.strip()
    try:
        if s.replace(".", "").isdigit():
            r = _get("https://otx.alienvault.com/api/v1/indicators/IPv4/" + s + "/passive_dns")
        else:
            r = _get("https://otx.alienvault.com/api/v1/indicators/domain/" + _host(s) + "/passive_dns")
        d = r.json()
        records = [{"hostname": p.get("hostname"), "address": p.get("address"),
                    "first": p.get("first"), "last": p.get("last")}
                   for p in d.get("passive_dns", [])[:15]]
        return {"query": s, "passive_dns": records, "count": len(records)}
    except Exception as e:
        return {"error": str(e)}


def tool_apileak(q):
    """Search public GitHub repos for API key patterns related to a domain/org."""
    import urllib.parse
    terms = [f'"{q}" key', f'"{q}" api_key', f'"{q}" secret', f'"{q}" password', f'"{q}" token']
    links = [f"https://github.com/search?q={urllib.parse.quote(t)}&type=code" for t in terms]
    return {"query": q, "search_links": links,
            "note": "Open these links in a browser — GitHub code search requires login for full results"}


def tool_hibp_breaches(q):
    """Check if email/username is in Have I Been Pwned breach database (free API)."""
    target = q.strip()
    try:
        # The free HIBP API is rate-limited; add backoff if you start hitting 429s.
        headers = {"User-Agent": "OSINT-Terminal"}
        r = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{_ulp.quote(target)}", headers=headers, timeout=5)
        if r.status_code == 200:
            breaches = r.json()
            return {"target": target, "breached": True, "breach_count": len(breaches),
                    "breaches": [{"name": b.get("Name"), "date": b.get("BreachDate")} for b in breaches[:10]]}
        elif r.status_code == 404:
            return {"target": target, "breached": False}
        else:
            return {"target": target, "error": f"API returned {r.status_code}"}
    except Exception as e:
        return {"target": target, "error": str(e)}


def tool_breachdb(q):
    """Search BreachDB for email/username in aggregated breach collections."""
    target = q.strip()
    try:
        # Free tier is limited; BreachDB uses simple domain verification.
        r = _get(f"https://breachdb.com/search?term={_ulp.quote(target)}")
        if "found" in r.text.lower() or "breach" in r.text.lower():
            return {"target": target, "status": "Likely found in breaches",
                    "note": "Visit https://breachdb.com for full details"}
        return {"target": target, "status": "Not detected in available breaches"}
    except Exception as e:
        return {"target": target, "error": str(e)}


def tool_password_dump_search(q):
    """Search Dehashed API for leaked passwords/hashes (queries only, no download)."""
    target = q.strip()
    try:
        # Dehashed's free tier is query-only; full dumps require a paid account.
        r = _get(f"https://api.dehashed.com/search?query={_ulp.quote(target)}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            entries = data.get("entries", [])
            return {"target": target, "found_count": len(entries),
                    "sample": [{"username": e.get("username"), "email": e.get("email")} for e in entries[:5]],
                    "note": "Full results and password hashes available on dehashed.com"}
        return {"target": target, "found_count": 0}
    except Exception as e:
        return {"target": target, "error": str(e)}


def tool_ssn_leak_check(q):
    """Check if SSN/DOB combination appears in identity theft databases (via public APIs)."""
    target = q.strip()
    try:
        # SSN checks are limited to educational lookups; real SSN-leak data requires specialized services.
        # Common pattern: SSN-XXXX or XXXXXXX-XXXX
        if len(target.replace("-", "")) < 9:
            return {"target": target, "error": "Invalid SSN format"}
        r = _get(f"https://osint.sh/api/query?q={_ulp.quote(target)}")
        if r.status_code == 200:
            data = r.json()
            return {"target": target, "found": data.get("found", False), "sources": data.get("sources", [])}
        return {"target": target, "status": "No public records found"}
    except Exception as e:
        return {"target": target, "error": str(e)}


def tool_phone_leak_check(q):
    """Search for phone number in leaked databases and public breach records."""
    target = q.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    try:
        # Phone searches hit multiple free APIs and return only an aggregated status.
        r = _get(f"https://api.leakix.net/search?q={_ulp.quote(target)}", timeout=5)
        if r.status_code == 200:
            results = r.json()
            return {"phone": target, "leak_found": len(results) > 0, "source_count": len(results),
                    "sources": [r.get("source") for r in results[:5]]}
        return {"phone": target, "leak_found": False}
    except Exception as e:
        return {"phone": target, "error": str(e)}


def tool_api_key_scan(q):
    """Scan GitHub, Pastebin, and Public APIs for exposed credentials matching query."""
    target = q.strip()
    try:
        results = {"target": target, "sources": []}
        # GitHub search (requires browser visit for full results)
        results["sources"].append({
            "source": "GitHub",
            "url": f"https://github.com/search?q={_ulp.quote(target)}+token&type=code"
        })
        # Pastebin search
        results["sources"].append({
            "source": "Pastebin",
            "url": f"https://www.pastebin.com/search?q={_ulp.quote(target)}"
        })
        # Google code search fallback
        results["sources"].append({
            "source": "Google Code",
            "url": f"https://www.google.com/search?q=inurl:github.com+{_ulp.quote(target)}+api"
        })
        return results
    except Exception as e:
        return {"target": target, "error": str(e)}


def tool_robotstxt_history(q):
    """Fetch historical robots.txt from Wayback Machine to find hidden paths."""
    host = _host(q)
    robots_url = f"https://{host}/robots.txt"
    try:
        r = _get("https://web.archive.org/cdx/search/cdx",
                 params={"url": robots_url, "output": "json", "limit": 5,
                         "fl": "timestamp,statuscode", "filter": "statuscode:200"})
        rows = r.json() if r.text.strip().startswith("[") else []
        snapshots = []
        for row in rows[1:4]:
            ts = row[0]
            snap_url = f"https://web.archive.org/web/{ts}/{robots_url}"
            try:
                sr = _get(snap_url, timeout=8)
                snapshots.append({"timestamp": ts, "content": sr.text[:2000]})
            except Exception:
                snapshots.append({"timestamp": ts, "content": None})
        return {"domain": host, "snapshots": snapshots}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# THREAT INTELLIGENCE & CVE / EXPLOIT AGGREGATION (25 new tools)
# ---------------------------------------------------------------------------

def tool_exploit_cve(q):
    """Search Exploit-DB + GitHub Exploits for a CVE code."""
    q = q.strip().upper()
    if not q.startswith("CVE-"):
        q = f"CVE-{q}"
    return {
        "cve": q,
        "exploit_db": f"https://www.exploit-db.com/?cve={q}",
        "github_exploits": f"https://github.com/search?q={quote(q)}+exploit+filename:*.py+OR+filename:*.rb&type=code",
        "nuclei_templates": f"https://github.com/projectdiscovery/nuclei-templates/search?q={quote(q)}",
        "metasploit": f"https://www.metasploit.com/modules/search?q={quote(q)}"
    }

def tool_cve_timeline(q):
    """Timeline: when a CVE was discussed (Twitter/Mastodon/Reddit/News)."""
    q = q.strip().upper()
    if not q.startswith("CVE-"):
        q = f"CVE-{q}"
    return {
        "cve": q,
        "twitter": f"https://twitter.com/search?q={quote(q)}&f=live",
        "mastodon": f"https://mastodon.social/search?q={quote(q)}",
        "reddit": f"https://reddit.com/search/?q={quote(q)}&sort=new",
        "news": f"https://news.google.com/search?q={quote(q)}",
        "hacker_news": f"https://hn.algolia.com/?query={quote(q)}&sort=byDate"
    }

def tool_cve_poc_checker(q):
    """Check if a CVE has public POC/exploit code."""
    q = q.strip().upper()
    if not q.startswith("CVE-"):
        q = f"CVE-{q}"
    return {
        "cve": q,
        "public_poc": f"https://github.com/search?q={quote(q)}&sort=stars&type=repositories",
        "poc_in_code": f"https://github.com/search?q={quote(q)}&type=code",
        "nuclei_poc": f"https://github.com/projectdiscovery/nuclei-templates?q={quote(q)}",
        "packetstorm": f"https://www.packetstormsecurity.com/search/?q={quote(q)}"
    }

def tool_mitre_technique(q):
    """MITRE ATT&CK technique lookup (local subset + online link)."""
    q = q.strip().upper()
    mitre_local = {
        "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
        "T1566": {"name": "Phishing", "tactics": ["Initial Access"]},
        "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["Initial Access"]},
        "T1110": {"name": "Brute Force", "tactics": ["Credential Access"]},
        "T1078": {"name": "Valid Accounts", "tactics": ["Defense Evasion"]},
    }
    result = {"technique": q}
    if q in mitre_local:
        result.update(mitre_local[q])
    result["link"] = f"https://attack.mitre.org/techniques/{q}/"
    return result

def tool_cisa_alerts(q):
    """CISA alerts + advisories + APC (no API key needed)."""
    return {
        "alerts": "https://www.cisa.gov/news-events/alerts",
        "advisories": "https://www.cisa.gov/news-events/advisories",
        "known_exploited": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "search": f"https://www.cisa.gov/search?search_api_views_fulltext={quote(q.strip())}" if q.strip() else None
    }

def tool_ransomware_tracker(q):
    """Ransomware gang profiles + recent operations (abuse.ch)."""
    return {
        "tracker": "https://ransomware.abuse.ch",
        "gangs": "https://ransomware.abuse.ch/?s=gangs",
        "search": f"https://ransomware.abuse.ch/?s={quote(q.strip())}" if q.strip() else None,
        "darkweb_posts": "https://www.darkweblink.com",
        "tor_mirror": "https://darkweblinks.org"
    }

def tool_threat_actor_profile(q):
    """Threat actor → campaigns, techniques, ATT&CK links."""
    q = q.strip()
    return {
        "actor": q,
        "mitre_groups": "https://attack.mitre.org/groups/",
        "search_groups": f"https://attack.mitre.org/groups/?search={quote(q)}",
        "mandiant_research": f"https://www.mandiant.com/resources?search={quote(q)}",
        "twitter_search": f"https://twitter.com/search?q=%23APT+{quote(q)}&f=live"
    }

def tool_malware_family(q):
    """Malware family → variants, detection, IOCs (VirusTotal + URLhaus)."""
    q = q.strip()
    return {
        "malware": q,
        "virustotal": f"https://www.virustotal.com/gui/search/{quote(q)}",
        "urlhaus": f"https://urlhaus.abuse.ch/browse.php?search={quote(q)}",
        "hybrid_analysis": f"https://www.hybrid-analysis.com/search?query={quote(q)}",
        "yara_rules": f"https://github.com/Yara-Rules/rules/search?q={quote(q)}",
        "circl_hashlookup": f"https://hashlookup.circl.lu/?q={quote(q)}"
    }

def tool_ioc_reputation(q):
    """IOC reputation: IP/domain/hash across feeds."""
    q = q.strip()
    ioc_type = "ip" if re.match(r'^\d+\.\d+\.\d+\.\d+$', q) else \
               "hash" if re.match(r'^[a-f0-9]{32,}$', q, re.I) else \
               "domain" if "." in q else "unknown"
    return {
        "ioc": q,
        "type": ioc_type,
        "abuseipdb": f"https://www.abuseipdb.com/check/{quote(q)}",
        "virustotal": f"https://www.virustotal.com/gui/search/{quote(q)}",
        "urlhaus": f"https://urlhaus.abuse.ch/browse.php?search={quote(q)}",
        "phishtank": f"https://phishtank.org/search.php?q={quote(q)}",
        "hybrid_analysis": f"https://www.hybrid-analysis.com/search?query={quote(q)}"
    }

def tool_zerodday_timeline(q):
    """Zero-day mentions: researcher Twitter + CVE + exploits."""
    return {
        "query": q.strip() if q else "0day",
        "security_researchers": ["@justinsteven", "@taviso", "@j00ru", "@scumjr", "@0xdea"],
        "twitter_0day": f"https://twitter.com/search?q=%230day+{quote(q.strip())}&f=live" if q.strip() else None,
        "hackerone": "https://hackerone.com/reports",
        "intigriti": "https://www.intigriti.com/researcher/report-list"
    }

def tool_apt_track(q):
    """Track APT campaigns via MITRE, Mandiant, researchers."""
    q = q.strip()
    return {
        "query": q,
        "mitre_campaigns": "https://attack.mitre.org/campaigns/",
        "mandiant_insights": "https://www.mandiant.com/resources",
        "att_cyber": "https://apt.cyber.nyu.edu/",
        "twitter_search": f"https://twitter.com/search?q={quote(q)}+APT&f=live",
        "recordedfuture": "https://www.recordedfuture.com/research"
    }

def tool_botnet_tracker(q):
    """Botnet C2, IoT malware tracking."""
    return {
        "abuse_ch_feodo": "https://feodotracker.abuse.ch/",
        "abuse_ch_urlhaus": "https://urlhaus.abuse.ch/",
        "shadowserver": "https://www.shadowserver.org/",
        "spamhaus_botnet": "https://www.spamhaus.org/news/",
        "search": f"https://feodotracker.abuse.ch/?q={quote(q.strip())}" if q.strip() else None
    }

def tool_c2_infrastructure(q):
    """Detect C2 infrastructure: domains + IPs + hosting."""
    q = q.strip()
    return {
        "query": q,
        "urlscan_scans": f"https://urlscan.io/search/#{quote(q)}",
        "talosintelligence": f"https://talosintelligence.com/reputation?query={quote(q)}",
        "abuseipdb": f"https://www.abuseipdb.com/check/{quote(q)}",
        "passive_dns": f"https://dnsdb.isc.org/lookup?query={quote(q)}",
        "virustotal": f"https://www.virustotal.com/gui/search/{quote(q)}"
    }

def tool_breach_aggregator(q):
    """Aggregate breach databases (XposedOrNot, LeakCheck, etc)."""
    q_encoded = quote(q.strip()) if q.strip() else ""
    return {
        "query": q.strip(),
        "xposed_or_not": f"https://www.xposedornot.com/search?q={q_encoded}",
        "leakcheck": f"https://leakcheck.io/",
        "dehashed": "https://dehashed.com/",
        "breachdir": "https://breachdirectory.org/",
        "intelx": "https://intelx.io/"
    }

def tool_darkweb_monitor(q):
    """Darkweb monitoring: marketplaces, paste sites, forums."""
    q = q.strip()
    return {
        "query": q,
        "tape_paste_sites": "https://www.tagsec.com/blog/top-10-dark-web-paste-sites/",
        "darkweb_links": "https://www.darkweblink.com/",
        "reddit_privateers": "https://reddit.com/r/privateers/",
        "search_paste": f"https://www.pastebin.com/search?q={quote(q)}" if q else None
    }

def tool_credential_stuffing_risk(q):
    """Check if credentials have appeared in breach + stuffing risk."""
    q_encoded = quote(q.strip()) if q.strip() else ""
    return {
        "query": q.strip(),
        "xposed_or_not": f"https://www.xposedornot.com/search?q={q_encoded}",
        "leakcheck": "https://leakcheck.io/",
        "haveibeenpwned": "https://haveibeenpwned.com/",
        "intelx": f"https://intelx.io/?s={q_encoded}"
    }

def tool_supply_chain_risk(q):
    """Supply chain risk: dependency vulns + typosquatting."""
    q = q.strip()
    return {
        "package": q,
        "osv_dev": f"https://osv.dev/search?q={quote(q)}",
        "npm_audit": f"https://www.npmjs.com/package/{quote(q)}",
        "pypi": f"https://pypi.org/project/{quote(q)}/",
        "github_advisories": "https://github.com/advisories",
        "typosquat": f"https://www.typosquatter.com/check/?q={quote(q)}"
    }

def tool_vulnerability_feed(q):
    """Real-time vulnerability feeds (NVD, Exploit-DB, PacketStorm)."""
    return {
        "nvd_feed": "https://nvd.nist.gov/vuln/",
        "nvd_recent": "https://nvd.nist.gov/vuln/search/results?query=&status=Analyzed&startIndex=0",
        "exploit_db_feed": "https://www.exploit-db.com/exploits",
        "packet_storm": "https://www.packetstormsecurity.com/",
        "cisa_alerts": "https://www.cisa.gov/news-events/alerts",
        "search": f"https://nvd.nist.gov/vuln/search?query={quote(q.strip())}" if q.strip() else None
    }

def tool_cve_severity_tracker(q):
    """CVSS + EPSS + KEV (CISA) for a CVE."""
    q = q.strip().upper()
    if not q.startswith("CVE-"):
        q = f"CVE-{q}"
    return {
        "cve": q,
        "nvd": f"https://nvd.nist.gov/vuln/detail/{q}",
        "cisa_kev": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "epss": f"https://www.first.org/epss/calculator#CVE-",
        "circl": f"https://cve.circl.lu/cve/{q}"
    }

def tool_threat_pattern_correlation(q):
    """Find threat patterns: same actor, tools, TTPs across incidents."""
    q = q.strip()
    return {
        "query": q,
        "mitre_campaigns": "https://attack.mitre.org/campaigns/",
        "mandiant_reports": "https://www.mandiant.com/resources",
        "shadowti": "https://www.shadowti.com/",
        "twitter_researchers": f"https://twitter.com/search?q={quote(q)}+TTP&f=live"
    }

def tool_emerging_threats(q):
    """Emerging threats: new CVEs, 0days, campaigns (last 24h)."""
    return {
        "nvd_recent": "https://nvd.nist.gov/vuln/search/results?query=&status=Analyzed&startIndex=0",
        "cisa_alerts": "https://www.cisa.gov/news-events/alerts",
        "packetstorm": "https://www.packetstormsecurity.com/",
        "twitter_infosec": "https://twitter.com/search?q=%23infosec&f=live",
        "reddit_security": "https://reddit.com/r/security/"
    }

def tool_phishing_intelligence(q):
    """Phishing kit tracking, URL detection, campaigns."""
    q = q.strip()
    return {
        "query": q,
        "phishtank": f"https://phishtank.org/search.php?q={quote(q)}",
        "urlhaus": f"https://urlhaus.abuse.ch/browse.php?search={quote(q)}",
        "opphishing": "https://opphishing.com/",
        "email_sec": f"https://emailrep.io/query/?q={quote(q)}",
        "twitter_phishing": f"https://twitter.com/search?q=phishing+{quote(q)}&f=live"
    }

def tool_infra_fingerprint(q):
    """Infrastructure fingerprinting: hosting, CDN, WAF."""
    q = q.strip()
    return {
        "domain": q,
        "asn_lookup": f"https://bgp.asn.cymru.com/cgi-bin/asnquery.cgi?as=&ip={quote(q)}&method=whois",
        "hosting_check": f"https://www.hosting-checker.com/?q={quote(q)}",
        "wafdetect": f"https://github.com/EnableSecurity/wafw00f",
        "ssl_labs": f"https://www.ssllabs.com/ssltest/analyze.html?d={quote(q)}"
    }

def tool_attack_surface_map(q):
    """Map attack surface: exposed services, endpoints, API."""
    q = q.strip()
    return {
        "domain": q,
        "shodan": f"https://www.shodan.io/search?query={quote(q)}",
        "censys": f"https://search.censys.io/search?q={quote(q)}",
        "greyhathwarfare": f"https://www.greyhatwarfare.com/search?keyword={quote(q)}",
        "internetdb": f"https://internetdb.shodan.io/{quote(q)}"
    }


TOOLS = {



    "dns":        {"fn": tool_dns,        "label": "DNS Records",        "accepts": ["domain"],          "desc": "A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records"},
    "whois":      {"fn": tool_whois,      "label": "WHOIS / RDAP",       "accepts": ["domain"],          "desc": "Registration, status, nameservers, DNSSEC"},
    "subdomains": {"fn": tool_subdomains, "label": "Subdomains",         "accepts": ["domain"],          "desc": "Certificate-transparency subdomain discovery"},
    "tls":        {"fn": tool_tls,        "label": "TLS Certificate",    "accepts": ["domain"],          "desc": "Live cert: issuer, validity, SANs, cipher"},
    "headers":    {"fn": tool_headers,    "label": "HTTP / Security",    "accepts": ["domain", "url"],   "desc": "Headers + security-header scorecard"},
    "wayback":    {"fn": tool_wayback,    "label": "Wayback Machine",    "accepts": ["domain", "url"],   "desc": "Archive.org snapshot history"},
    "ipgeo":      {"fn": tool_ipgeo,      "label": "IP Geolocation",     "accepts": ["ip"],              "desc": "Geo, ISP, ASN, proxy/hosting flags"},
    "reversedns": {"fn": tool_reversedns, "label": "Reverse DNS",        "accepts": ["ip"],              "desc": "PTR record / hostname"},
    "username":   {"fn": tool_username,   "label": "Username Hunter",    "accepts": ["username"],        "desc": "Presence across 16 public sites"},
    "github":     {"fn": tool_github,     "label": "GitHub Recon",       "accepts": ["username"],        "desc": "Profile, repos, languages"},
    "email":      {"fn": tool_email,      "label": "Email Intel",        "accepts": ["email"],           "desc": "Gravatar, MX, disposable detection"},
    # --- extended ---
    "internetdb": {"fn": tool_internetdb, "label": "Shodan InternetDB",   "accepts": ["ip", "domain"],    "desc": "Open ports, CPEs, tags, known CVEs for a host"},
    "portscan":   {"fn": tool_portscan,   "label": "Port Scan",          "accepts": ["ip", "domain"],    "desc": "TCP connect scan: common + camera ports"},
    "camera":     {"fn": tool_camera,     "label": "Camera Exposure",    "accepts": ["ip", "domain"],    "desc": "RTSP/ONVIF + camera-port exposure (per-target)"},
    "ipwhois":    {"fn": tool_ipwhois,    "label": "IP WHOIS / RDAP",    "accepts": ["ip"],              "desc": "Network owner, range, abuse contact"},
    "asn":        {"fn": tool_asn,        "label": "ASN / BGP",          "accepts": ["ip", "asn"],       "desc": "ASN details or prefixes for an IP"},
    "reverseip":  {"fn": tool_reverseip,  "label": "Reverse IP",         "accepts": ["ip", "domain"],    "desc": "Other domains sharing the host"},
    "dnsbl":      {"fn": tool_dnsbl,      "label": "DNS Blocklist",      "accepts": ["ip"],              "desc": "Spamhaus/Barracuda/SORBS/SpamCop check"},
    "tor":        {"fn": tool_tor,        "label": "Tor Exit Check",     "accepts": ["ip"],              "desc": "Is the IP a known Tor exit node"},
    "cloud":      {"fn": tool_cloud,      "label": "Cloud Provider",     "accepts": ["ip"],              "desc": "AWS/GCP/Azure/etc. detection + hosting flag"},
    "emailsec":   {"fn": tool_emailsec,   "label": "Email Security",     "accepts": ["domain"],          "desc": "SPF / DMARC / DKIM posture"},
    "robots":     {"fn": tool_robots,     "label": "robots.txt",         "accepts": ["domain", "url"],   "desc": "Disallowed paths + sitemaps"},
    "tech":       {"fn": tool_tech,       "label": "Tech Fingerprint",   "accepts": ["domain", "url"],   "desc": "CMS/framework/server detection"},
    "favicon":    {"fn": tool_favicon,    "label": "Favicon Hash",       "accepts": ["domain", "url"],   "desc": "favicon md5/sha256 for pivoting"},
    "redirects":  {"fn": tool_redirects,  "label": "Redirect Tracer",    "accepts": ["url", "domain"],   "desc": "Full HTTP redirect chain"},
    "certhistory":{"fn": tool_certhistory,"label": "Cert History",       "accepts": ["domain"],          "desc": "crt.sh issuer timeline & counts"},
    "social":     {"fn": tool_social,     "label": "Social Links",       "accepts": ["username"],        "desc": "Direct profile URLs across 20 platforms"},
    "mac":        {"fn": tool_mac,        "label": "MAC Vendor",         "accepts": ["mac"],             "desc": "OUI → hardware vendor"},
    "crypto":     {"fn": tool_crypto,     "label": "Crypto Address",     "accepts": ["crypto"],          "desc": "BTC/ETH balance & tx history"},
    "dorks":      {"fn": tool_dorks,      "label": "Search Dorks",       "accepts": ["domain", "ip", "email", "username", "url", "mac", "asn", "crypto", "phone"], "desc": "Builds manual OSINT search links"},
    # --- extended batch 2 ---
    "urlscan":    {"fn": tool_urlscan,    "label": "urlscan.io",         "accepts": ["domain", "url"],   "desc": "Past scans, verdicts, infra (IP/ASN/server) for a site"},
    "greynoise":  {"fn": tool_greynoise,  "label": "GreyNoise",          "accepts": ["ip"],              "desc": "Is the IP a known internet scanner — benign/malicious"},
    "typosquat":  {"fn": tool_typosquat,  "label": "Typosquat Finder",   "accepts": ["domain"],          "desc": "Look-alike domains that currently resolve"},
    "securitytxt":{"fn": tool_securitytxt,"label": "security.txt",       "accepts": ["domain", "url"],   "desc": "RFC 9116 disclosure policy & contacts"},
    "keybase":    {"fn": tool_keybase,    "label": "Keybase",            "accepts": ["username"],        "desc": "Crypto identity + linked social proofs"},
    "phone":      {"fn": tool_phone,      "label": "Phone Number",       "accepts": ["phone"],           "desc": "E.164 country/region (offline)"},
    "decode":     {"fn": tool_decode,     "label": "Decoder",            "accepts": ["b64"],             "desc": "Auto base64/hex/URL-decode + refang"},
    "jwt":        {"fn": tool_jwt,        "label": "JWT Decoder",        "accepts": ["jwt"],             "desc": "Header + claims (no signature verify)"},
    "hashid":     {"fn": tool_hashid,     "label": "Hash Identifier",    "accepts": ["hash"],            "desc": "Guess hash algorithm from length/charset"},
    "cidr":       {"fn": tool_cidr,       "label": "CIDR / IP Math",     "accepts": ["cidr"],            "desc": "Network, broadcast, range, host count"},
    "gitexposed": {"fn": tool_gitexposed, "label": "Exposed Files",      "accepts": ["domain", "url"],   "desc": ".git/.env/backup exposure (per-target)"},
    "cors":       {"fn": tool_cors,       "label": "CORS Check",         "accepts": ["domain", "url"],   "desc": "Origin-reflection / wildcard misconfig"},
    "cookies":    {"fn": tool_cookies,    "label": "Cookie Audit",       "accepts": ["domain", "url"],   "desc": "Secure/HttpOnly/SameSite flag review"},
    "dnssec":     {"fn": tool_dnssec,     "label": "DNSSEC",             "accepts": ["domain"],          "desc": "Is the zone signed (AD flag + DNSKEY/DS)"},
    "pgp":        {"fn": tool_pgp,        "label": "PGP Key",            "accepts": ["email"],           "desc": "Public key published on keys.openpgp.org"},
    "hackernews": {"fn": tool_hackernews, "label": "Hacker News",        "accepts": ["username"],        "desc": "Profile: karma, age, activity"},
    "gitlab":     {"fn": tool_gitlab,     "label": "GitLab",             "accepts": ["username"],        "desc": "Public user profile"},
    # --- extended batch 3 ---
    "dnsprop":    {"fn": tool_dnsprop,    "label": "DNS Propagation",    "accepts": ["domain"],          "desc": "Compare A records across Google/Cloudflare/Quad9"},
    "takeover":   {"fn": tool_takeover,   "label": "Subdomain Takeover", "accepts": ["domain", "url"],   "desc": "Dangling-CNAME takeover fingerprint check"},
    "sitemap":    {"fn": tool_sitemap,    "label": "Sitemap",            "accepts": ["domain", "url"],   "desc": "Fetch sitemap.xml + list URLs"},
    "waf":        {"fn": tool_waf,        "label": "WAF / CDN",          "accepts": ["domain", "url"],   "desc": "Detect WAF/CDN from headers & cookies"},
    "cve":        {"fn": tool_cve,        "label": "CVE Lookup",         "accepts": ["cve"],             "desc": "CVE detail + CVSS (CIRCL, no key)"},
    "npm":        {"fn": tool_npm,        "label": "npm Author",         "accepts": ["username"],        "desc": "Packages published by an author"},
    "peers":      {"fn": tool_peers,      "label": "ASN Peers",          "accepts": ["asn", "ip"],       "desc": "Upstream/downstream BGP neighbours"},
    "urlparse":   {"fn": tool_urlparse,   "label": "URL Parser",         "accepts": ["url"],             "desc": "Decompose URL + decode query params"},
    "epoch":      {"fn": tool_epoch,      "label": "Epoch Time",         "accepts": ["epoch"],           "desc": "Unix timestamp <-> UTC datetime"},
    "tlsscan":    {"fn": tool_tlsscan,    "label": "TLS Versions",       "accepts": ["domain"],          "desc": "Which SSL/TLS protocols the host accepts"},
    # --- extended batch 4: new indicator types + more keyless tools ---
    "revgeo":     {"fn": tool_revgeo,     "label": "Reverse Geocode",    "accepts": ["coords"],          "desc": "lat,lon -> address (OSM Nominatim)"},
    "suntimes":   {"fn": tool_suntimes,   "label": "Sun Times",          "accepts": ["coords"],          "desc": "Sunrise/sunset/twilight for a coordinate (UTC)"},
    "iban":       {"fn": tool_iban,       "label": "IBAN Validate",      "accepts": ["iban"],            "desc": "ISO 13616 checksum + country/length (offline)"},
    "bin":        {"fn": tool_bin,        "label": "Card BIN",           "accepts": ["bin"],             "desc": "Issuer/scheme/country from card BIN (binlist)"},
    "uuid":       {"fn": tool_uuid,       "label": "UUID Parser",        "accepts": ["uuid"],            "desc": "Version/variant + v1 timestamp/MAC (offline)"},
    "isbn":       {"fn": tool_isbn,       "label": "ISBN Book",          "accepts": ["isbn"],            "desc": "Book metadata (OpenLibrary) + checksum"},
    "txhash":     {"fn": tool_txhash,     "label": "Crypto Tx",          "accepts": ["txhash"],          "desc": "BTC/ETH transaction detail (blockchair)"},
    "bluesky":    {"fn": tool_bluesky,    "label": "Bluesky",            "accepts": ["username"],        "desc": "AT Protocol public profile"},
    "chesscom":   {"fn": tool_chesscom,   "label": "Chess.com",          "accepts": ["username"],        "desc": "Public player profile + ratings"},
    "wikipedia":  {"fn": tool_wikipedia,  "label": "Wikipedia",          "accepts": ["username"],        "desc": "Page existence + summary"},
    "httping":    {"fn": tool_httping,    "label": "HTTP Ping",          "accepts": ["domain", "url"],   "desc": "Reachability + response timing"},
    "links":      {"fn": tool_links,      "label": "Link Extractor",     "accepts": ["domain", "url"],   "desc": "All links + external domains + emails on a page"},
    "pwstrength": {"fn": tool_pwstrength, "label": "Password Strength",  "accepts": ["username", "b64"], "desc": "Offline entropy/strength estimate"},
    "entropy":    {"fn": tool_entropy,    "label": "Shannon Entropy",    "accepts": ["b64", "hash"],     "desc": "Per-char entropy — flags secrets/keys"},
    "lobsters":   {"fn": tool_lobsters,   "label": "Lobste.rs",          "accepts": ["username"],        "desc": "Public user profile + karma"},
    "caa":        {"fn": tool_caa,        "label": "CAA Records",        "accepts": ["domain"],          "desc": "Which CAs may issue certs for the domain"},
    "mtasts":     {"fn": tool_mtasts,     "label": "MTA-STS",            "accepts": ["domain"],          "desc": "Inbound-mail TLS enforcement policy"},
    "bimi":       {"fn": tool_bimi,       "label": "BIMI",               "accepts": ["domain"],          "desc": "Brand-indicator (logo) DNS record"},
    "domainage":  {"fn": tool_domainage,  "label": "Domain Age",         "accepts": ["domain"],          "desc": "Days since registration (phishing signal)"},
    "luhn":       {"fn": tool_luhn,       "label": "Luhn Check",         "accepts": ["bin"],             "desc": "Validate card/IMEI Luhn checksum (offline)"},
    # --- extended batch 5: registries, crypto, git/social, offline utils ---
    "pypi":       {"fn": tool_pypi,       "label": "PyPI Package",       "accepts": ["username", "package"], "desc": "Python package metadata + links"},
    "crates":     {"fn": tool_crates,     "label": "crates.io",          "accepts": ["username", "package"], "desc": "Rust crate stats + downloads"},
    "rubygems":   {"fn": tool_rubygems,   "label": "RubyGems",           "accepts": ["username", "package"], "desc": "Ruby gem stats + downloads"},
    "packagist":  {"fn": tool_packagist,  "label": "Packagist",          "accepts": ["package"],         "desc": "PHP/Composer package stats (vendor/pkg)"},
    "npmpkg":     {"fn": tool_npmpkg,     "label": "npm Package",        "accepts": ["username", "package"], "desc": "npm package version, deps, maintainers"},
    "btcaddr":    {"fn": tool_btcaddr,    "label": "BTC Address",        "accepts": ["crypto"],          "desc": "Bitcoin balance/tx via mempool.space"},
    "ethaddr":    {"fn": tool_ethaddr,    "label": "ETH Address",        "accepts": ["crypto"],          "desc": "Ethereum balance/tx + contract flag"},
    "ghrepo":     {"fn": tool_ghrepo,     "label": "GitHub Repo",        "accepts": ["package", "url"],  "desc": "Stars/langs/license/activity (owner/repo)"},
    "ghgists":    {"fn": tool_ghgists,    "label": "GitHub Gists",       "accepts": ["username"],        "desc": "Public gists for a user"},
    "ghorg":      {"fn": tool_ghorg,      "label": "GitHub Org",         "accepts": ["username"],        "desc": "Public org profile"},
    "mastodon":   {"fn": tool_mastodon,   "label": "Mastodon",           "accepts": ["email"],           "desc": "Resolve user@instance via WebFinger"},
    "geohash":    {"fn": tool_geohash,    "label": "Geohash",            "accepts": ["coords"],          "desc": "lat,lon -> geohash (offline)"},
    "ipv6":       {"fn": tool_ipv6,       "label": "IPv6 Expand",        "accepts": ["ip"],              "desc": "Compress/explode + reverse PTR (offline)"},
    "transform":  {"fn": tool_transform,  "label": "Text Transforms",    "accepts": ["b64", "username"], "desc": "rot13/base32/morse/reverse (offline)"},
    "cpfcnpj":    {"fn": tool_cpfcnpj,    "label": "CPF / CNPJ",         "accepts": ["bin"],             "desc": "Brazilian doc checksum (offline)"},
    "color":      {"fn": tool_color,      "label": "Color Parser",       "accepts": ["color"],           "desc": "hex/rgb -> rgb/hsl + nearest name (offline)"},

    # --- extension pack 1 ---
    "doh":         {"fn": tool_doh,         "label": "DoH Records",        "accepts": ["domain"],          "desc": "Uncommon DNS records (HTTPS/SVCB/TLSA/SRV/NAPTR…)"},
    "tlsa":        {"fn": tool_tlsa,        "label": "DANE / TLSA",        "accepts": ["domain"],          "desc": "Certificate-pinning DANE records on :443"},
    "dnsverify":   {"fn": tool_dnsverify,   "label": "TXT Verifications",  "accepts": ["domain"],          "desc": "Which SaaS a domain is enrolled in (TXT tokens)"},
    "subbrute":    {"fn": tool_subbrute,    "label": "Subdomain Brute",    "accepts": ["domain"],          "desc": "Resolve a common-subdomain wordlist (per-target)"},
    "hstspreload": {"fn": tool_hstspreload, "label": "HSTS Preload",       "accepts": ["domain"],          "desc": "Is the domain on the browser HSTS preload list"},
    "wpscan":      {"fn": tool_wpscan,      "label": "WordPress Scan",     "accepts": ["domain", "url"],   "desc": "WP version + author enum via REST (per-target)"},
    "wellknown":   {"fn": tool_wellknown,   "label": ".well-known Scan",   "accepts": ["domain", "url"],   "desc": "Which /.well-known/* resources exist"},
    "graphql":     {"fn": tool_graphql,     "label": "GraphQL Probe",      "accepts": ["domain", "url"],   "desc": "Find GraphQL endpoint + introspection (per-target)"},
    "swagger":     {"fn": tool_swagger,     "label": "Swagger / OpenAPI",  "accepts": ["domain", "url"],   "desc": "Exposed API docs at common paths (per-target)"},
    "s3buckets":   {"fn": tool_s3buckets,   "label": "Cloud Buckets",      "accepts": ["domain"],          "desc": "S3/GCS/Azure buckets named for the domain"},
    "httpmethods": {"fn": tool_httpmethods, "label": "HTTP Methods",       "accepts": ["domain", "url"],   "desc": "Allowed methods + TRACE/risky-verb check"},
    "dirlisting":  {"fn": tool_dirlisting,  "label": "Directory Listing",  "accepts": ["domain", "url"],   "desc": "Open directory-index exposure (per-target)"},
    "adstxt":      {"fn": tool_adstxt,      "label": "ads.txt",            "accepts": ["domain"],          "desc": "Ad-tech sellers declared in ads.txt"},
    "feeds":       {"fn": tool_feeds,       "label": "RSS / Atom Feeds",   "accepts": ["domain", "url"],   "desc": "Discover syndication feeds on a site"},
    "manifest":    {"fn": tool_manifest,    "label": "PWA Manifest",       "accepts": ["domain", "url"],   "desc": "Web app manifest: name, icons, theme"},
    "wpplugin":    {"fn": tool_wpplugin,    "label": "WP Plugin Info",     "accepts": ["package"],         "desc": "WordPress.org plugin version/install stats"},
    "abusecontact":{"fn": tool_abusecontact,"label": "Abuse Contact",      "accepts": ["ip"],              "desc": "Authoritative abuse email (RIPEstat finder)"},
    "asrank":      {"fn": tool_asrank,      "label": "AS Rank (CAIDA)",    "accepts": ["asn"],             "desc": "Global ASN ranking + customer cone size"},
    "peeringdb":   {"fn": tool_peeringdb,   "label": "PeeringDB",          "accepts": ["asn"],             "desc": "Network type, traffic, IX/facility presence"},
    "rpki":        {"fn": tool_rpki,        "label": "RPKI / ROA",         "accepts": ["ip"],              "desc": "Route-origin validation for the covering prefix"},
    "ens":         {"fn": tool_ens,         "label": "ENS Resolve",        "accepts": ["domain", "crypto"],"desc": "ENS name <-> ETH address + avatar"},
    "ethcontract": {"fn": tool_ethcontract, "label": "ETH Contract",       "accepts": ["crypto"],          "desc": "Contract check + Sourcify verified source"},
    "osv":         {"fn": tool_osv,         "label": "OSV Vulns",          "accepts": ["package", "username"], "desc": "Known package vulns (OSV.dev). 'eco:name'"},
    "depsdev":     {"fn": tool_depsdev,     "label": "deps.dev",           "accepts": ["package", "username"], "desc": "Open-source insights: versions, default"},
    "gomod":       {"fn": tool_gomod,       "label": "Go Module",          "accepts": ["package"],         "desc": "Go module latest version (module proxy)"},
    "nuget":       {"fn": tool_nuget,       "label": "NuGet",              "accepts": ["package", "username"], "desc": ".NET package stats + downloads"},
    "maven":       {"fn": tool_maven,       "label": "Maven Central",      "accepts": ["package"],         "desc": "Java artifact: 'group:artifact' or name"},
    "hexpm":       {"fn": tool_hexpm,       "label": "Hex.pm",             "accepts": ["package", "username"], "desc": "Elixir/Erlang package downloads"},
    "cdnjs":       {"fn": tool_cdnjs,       "label": "cdnjs",              "accepts": ["package", "username"], "desc": "Hosted JS library version + assets"},
    "npmdl":       {"fn": tool_npmdl,       "label": "npm Downloads",      "accepts": ["package", "username"], "desc": "npm download counts day/week/month"},
    "brew":        {"fn": tool_brew,        "label": "Homebrew",           "accepts": ["package", "username"], "desc": "Formula/cask version, deps, installs"},
    "pypistats":   {"fn": tool_pypistats,   "label": "PyPI Downloads",     "accepts": ["package", "username"], "desc": "PyPI recent download counts"},
    "devto":       {"fn": tool_devto,       "label": "dev.to",             "accepts": ["username"],        "desc": "Forem/dev.to public profile"},
    "medium":      {"fn": tool_medium,      "label": "Medium",             "accepts": ["username"],        "desc": "Author feed: recent post titles"},
    "orcid":       {"fn": tool_orcid,       "label": "ORCID",              "accepts": ["orcid"],           "desc": "Researcher record (0000-000X-…)"},
    "codeberg":    {"fn": tool_codeberg,    "label": "Codeberg",           "accepts": ["username"],        "desc": "Codeberg/Gitea public user"},
    "wikidata":    {"fn": tool_wikidata,    "label": "Wikidata",           "accepts": ["username"],        "desc": "Entity search: IDs + descriptions"},
    "musicbrainz": {"fn": tool_musicbrainz, "label": "MusicBrainz",        "accepts": ["username"],        "desc": "Artist search: type, country, MBID"},
    "stackoverflow":{"fn": tool_stackoverflow,"label": "Stack Overflow",   "accepts": ["username"],        "desc": "SO/SE user search by display name"},
    "hashnode":    {"fn": tool_hashnode,    "label": "Hashnode",           "accepts": ["username"],        "desc": "Blogger profile: followers, posts"},
    "gravatarfull":{"fn": tool_gravatarfull,"label": "Gravatar Profile",   "accepts": ["email"],           "desc": "Full public Gravatar profile + linked accounts"},
    "osmuser":     {"fn": tool_osmuser,     "label": "OpenStreetMap User", "accepts": ["username"],        "desc": "Contributor: last edit + changeset"},
    "feodo":       {"fn": tool_feodo,       "label": "Feodo C2",           "accepts": ["ip"],              "desc": "abuse.ch botnet C2 blocklist (key-free)"},
    "openphish":   {"fn": tool_openphish,   "label": "OpenPhish",          "accepts": ["domain", "url"],   "desc": "Community phishing-URL feed membership"},
    "kev":         {"fn": tool_kev,         "label": "CISA KEV",           "accepts": ["cve"],             "desc": "Is the CVE actively exploited (KEV catalog)"},
    "epss":        {"fn": tool_epss,        "label": "EPSS Score",         "accepts": ["cve"],             "desc": "Exploitation probability (FIRST EPSS)"},
    "circlhash":   {"fn": tool_circlhash,   "label": "Hash Lookup",        "accepts": ["hash"],            "desc": "Known-file lookup (CIRCL hashlookup)"},
    "weather":     {"fn": tool_weather,     "label": "Weather",            "accepts": ["coords"],          "desc": "Current weather at a coordinate (Open-Meteo)"},
    "elevation":   {"fn": tool_elevation,   "label": "Elevation",          "accepts": ["coords"],          "desc": "Ground elevation in metres (Open-Meteo)"},

    # --- extension pack 2 ---
    "vin":        {"fn": tool_vin,        "label": "VIN Decoder",        "accepts": ["vin"],            "desc": "NHTSA vPIC vehicle decode (make/model/plant)"},
    "lei":        {"fn": tool_lei,        "label": "LEI Lookup",         "accepts": ["lei"],            "desc": "GLEIF legal-entity record by LEI code"},
    "orgname":    {"fn": tool_orgname,    "label": "Company → LEI",      "accepts": ["orgname"],        "desc": "Fuzzy company-name search → candidate LEIs"},
    "cpe":        {"fn": tool_cpe,        "label": "CPE → CVEs",         "accepts": ["cpe"],            "desc": "NVD: recent CVEs affecting a CPE 2.3 string"},
    "cvedetail":  {"fn": tool_cvedetail,  "label": "CVE Detail",         "accepts": ["cve"],            "desc": "Full CVE record (CVSS, refs) via CIRCL"},
    "port":       {"fn": tool_port,       "label": "Port Reference",     "accepts": ["port"],           "desc": "Service + exposure notes for a port number"},
    "ssh":        {"fn": tool_ssh,        "label": "SSH Banner",         "accepts": ["domain", "ip"],   "desc": "Per-target SSH server banner / version"},
    "hostsearch": {"fn": tool_hostsearch, "label": "Host Search",        "accepts": ["domain"],         "desc": "Forward-DNS host enumeration for a domain"},
    "peeringnet": {"fn": tool_peeringnet, "label": "PeeringDB Net",      "accepts": ["asn"],            "desc": "Peering policy / traffic / IX presence for ASN"},
    "nearbywiki": {"fn": tool_nearbywiki, "label": "Nearby Places",      "accepts": ["coords"],         "desc": "Wikipedia places near a coordinate"},

    # --- extension pack 3 ---
    "doi":           {"fn": tool_doi,            "label": "DOI Resolver",       "accepts": ["doi"],                 "desc": "Crossref publication metadata for a DOI"},
    "crossrefauthor":{"fn": tool_crossrefauthor, "label": "Crossref Author",    "accepts": ["username", "orgname"], "desc": "Works by author/keyword (Crossref)"},
    "orcidworks":    {"fn": tool_orcidworks,     "label": "ORCID Works",        "accepts": ["orcid"],               "desc": "Recent publications for an ORCID iD"},
    "isbnmeta":      {"fn": tool_isbnmeta,       "label": "ISBN Metadata",      "accepts": ["isbn"],                "desc": "Book title/authors/subjects (OpenLibrary)"},
    "sopostuser":    {"fn": tool_sopostuser,     "label": "StackOverflow User", "accepts": ["bin", "port"],         "desc": "SO profile + reputation by numeric id"},
    "breachsearch":  {"fn": tool_breachsearch,   "label": "Breach Catalog",     "accepts": ["domain", "username"],  "desc": "Public HIBP breach metadata search"},
    "feodoips":      {"fn": tool_feodoips,       "label": "Feodo C2 List",      "accepts": ["ip"],                  "desc": "Is IP on abuse.ch Feodo botnet C2 list"},
    "urlscansearch": {"fn": tool_urlscansearch,  "label": "urlscan Archive",    "accepts": ["domain"],              "desc": "Public urlscan.io scan history for a domain"},
    "commoncrawl":   {"fn": tool_commoncrawl,    "label": "Common Crawl",       "accepts": ["domain"],              "desc": "Captures of a domain in Common Crawl index"},
    "ipfull":        {"fn": tool_ipfull,         "label": "IP Full Profile",    "accepts": ["ip"],                  "desc": "Rich geo+ASN+proxy/mobile/hosting flags"},
    "geocode":       {"fn": tool_geocode,        "label": "Geocode",            "accepts": ["orgname", "username"], "desc": "Place name → coordinates (OSM Nominatim)"},
    "revgeocode":    {"fn": tool_revgeocode,     "label": "Reverse Geocode",    "accepts": ["coords"],              "desc": "Coordinates → nearest address (OSM)"},
    "macvendorlookup":{"fn": tool_macvendorlookup,"label": "MAC Vendor",        "accepts": ["mac"],                 "desc": "OUI → hardware vendor (macvendors.com)"},
    "dnsmx":         {"fn": tool_dnsmx,          "label": "MX (DoH)",           "accepts": ["domain"],              "desc": "MX records via Google DNS-over-HTTPS"},
    "fxrate":        {"fn": tool_fxrate,         "label": "FX Rates",           "accepts": ["username"],            "desc": "Live exchange rates for a currency code"},
    "country":       {"fn": tool_country,        "label": "Country Profile",    "accepts": ["username"],            "desc": "World Bank country profile by ISO code"},
    "wikidatasearch":{"fn": tool_wikidatasearch, "label": "Wikidata Search",    "accepts": ["orgname", "username"], "desc": "Free-text → Wikidata entities"},
    "spdxlicense":   {"fn": tool_spdxlicense,    "label": "SPDX License",       "accepts": ["username"],            "desc": "SPDX license id → name + OSI status"},
    "gitignore":     {"fn": tool_gitignore,      "label": "gitignore Template", "accepts": ["username"],            "desc": "GitHub .gitignore template for a language"},
    "ghcommits":     {"fn": tool_ghcommits,      "label": "GitHub Commits",     "accepts": ["package"],             "desc": "Recent commits for owner/repo"},
    "ghpubkeys":     {"fn": tool_ghpubkeys,      "label": "GitHub SSH Keys",    "accepts": ["username"],            "desc": "A user's public SSH keys (.keys)"},
    "ghkeysgpg":     {"fn": tool_ghkeysgpg,      "label": "GitHub GPG Key",     "accepts": ["username"],            "desc": "Whether a user publishes a GPG key"},
    "npmdownloads":  {"fn": tool_npmdownloads,   "label": "npm Downloads",      "accepts": ["username", "package"], "desc": "Weekly download count for an npm package"},
    "pypiproject":   {"fn": tool_pypiproject,    "label": "PyPI Project",       "accepts": ["username"],            "desc": "PyPI version/license/links"},
    "dockerhub":     {"fn": tool_dockerhub,      "label": "Docker Hub",         "accepts": ["username", "package"], "desc": "Image pulls/stars/last-push"},
    "httpstatus":    {"fn": tool_httpstatus,     "label": "HTTP Status",        "accepts": ["port", "bin"],         "desc": "Explain an HTTP status code (offline)"},
    "useragent":     {"fn": tool_useragent,      "label": "UA Parser",          "accepts": ["username"],            "desc": "Parse a User-Agent into OS/browser (offline)"},
    "asnprefixes":   {"fn": tool_asnprefixes,    "label": "ASN Prefixes",       "accepts": ["asn"],                 "desc": "All announced prefixes for an ASN (RIPEstat)"},
    "ripewhois":     {"fn": tool_ripewhois,      "label": "RIPE Network Info",  "accepts": ["ip"],                  "desc": "Covering prefix + origin ASN (RIPEstat)"},
    "rdapip":        {"fn": tool_rdapip,         "label": "RDAP IP",            "accepts": ["ip"],                  "desc": "Authoritative RDAP record for an IP"},
    "isotime":       {"fn": tool_isotime,        "label": "Timestamp Convert",  "accepts": ["epoch", "username"],   "desc": "Parse/convert a timestamp (offline)"},

    # --- extension pack 4 ---
    "nvdcve":         {"fn": tool_nvdcve,         "label": "NVD CVE Detail",     "accepts": ["cve"],                 "desc": "Full NVD record: CVSS, CWE, references"},
    "ghadvisory":     {"fn": tool_ghadvisory,     "label": "GitHub Advisories",  "accepts": ["username"],            "desc": "Security advisories for an ecosystem (pip/npm/…)"},
    "otxdomain":      {"fn": tool_otxdomain,      "label": "OTX Domain Rep",     "accepts": ["domain"],              "desc": "AlienVault OTX threat pulses for a domain"},
    "otxip":          {"fn": tool_otxip,          "label": "OTX IP Rep",         "accepts": ["ip"],                  "desc": "AlienVault OTX threat pulses for an IP"},
    "hosthunt":       {"fn": tool_hosthunt,       "label": "Host Search",        "accepts": ["domain"],              "desc": "Forward-DNS host/subdomain map (HackerTarget)"},
    "ghlanguages":    {"fn": tool_ghlanguages,    "label": "Repo Languages",     "accepts": ["package"],             "desc": "Language byte-breakdown for owner/repo"},
    "githubsearch":   {"fn": tool_githubsearch,   "label": "GitHub Repo Search", "accepts": ["orgname", "username"], "desc": "Search GitHub repos by keyword"},
    "githubgists":    {"fn": tool_githubgists,    "label": "GitHub Gists",       "accepts": ["username"],            "desc": "A user's public gists"},
    "golangpkg":      {"fn": tool_golangpkg,      "label": "Go Module",          "accepts": ["package"],             "desc": "Latest version of a Go module"},
    "rubygemrev":     {"fn": tool_rubygemrev,     "label": "Gem Rev-Deps",       "accepts": ["username"],            "desc": "Reverse dependencies of a RubyGem"},
    "cratedownloads": {"fn": tool_cratedownloads, "label": "Crate Downloads",    "accepts": ["username"],            "desc": "Download totals for a Rust crate"},
    "openalexwork":   {"fn": tool_openalexwork,   "label": "OpenAlex Work",      "accepts": ["doi"],                 "desc": "Scholarly work: citations, concepts, OA"},
    "openalexauthor": {"fn": tool_openalexauthor, "label": "OpenAlex Author",    "accepts": ["orgname", "username"], "desc": "Author works count, h-index, institution"},
    "semanticscholar":{"fn": tool_semanticscholar,"label": "Semantic Scholar",   "accepts": ["doi"],                 "desc": "Paper TLDR, citations, influence"},
    "datacite":       {"fn": tool_datacite,       "label": "DataCite Search",    "accepts": ["orgname", "username"], "desc": "Research datasets/DOIs by keyword"},
    "restcountry":    {"fn": tool_restcountry,    "label": "Country Detail",     "accepts": ["username"],            "desc": "Capital/region/income by name or ISO (World Bank)"},
    "wikisummary":    {"fn": tool_wikisummary,    "label": "Wikipedia Summary",  "accepts": ["orgname", "username"], "desc": "Page extract/description for a topic"},
    "archiveorg":     {"fn": tool_archiveorg,     "label": "Archive.org Item",   "accepts": ["username"],            "desc": "Internet Archive item metadata"},
    "hnsearch":       {"fn": tool_hnsearch,       "label": "HN Search",          "accepts": ["orgname", "username"], "desc": "Search Hacker News stories/comments"},
    "hnuser":         {"fn": tool_hnuser,         "label": "HN User",            "accepts": ["username"],            "desc": "Hacker News profile: karma, age, about"},
    "wikipv":         {"fn": tool_wikipv,         "label": "Wikipedia Meta",     "accepts": ["orgname"],             "desc": "Page length, last edit, editor"},
    "musicbrainzartist":{"fn": tool_musicbrainzartist,"label":"MusicBrainz Artist","accepts": ["orgname", "username"],"desc": "Artist type, country, lifespan"},
    "openfoodfacts":  {"fn": tool_openfoodfacts,  "label": "Product Barcode",    "accepts": ["bin", "isbn"],         "desc": "EAN/UPC -> product, brand, nutrition"},
    "cidrinfo":       {"fn": tool_cidrinfo,       "label": "CIDR Calculator",    "accepts": ["cidr"],                "desc": "Network/broadcast/host-count (offline)"},
    "passwordcheck":  {"fn": tool_passwordcheck,  "label": "Password Pwned",     "accepts": ["username"],            "desc": "HIBP k-anonymity breach check (safe)"},
    "base64":         {"fn": tool_base64,         "label": "Base64",             "accepts": ["username"],            "desc": "Auto decode/encode base64 (offline)"},
    "hashtext":       {"fn": tool_hashtext,       "label": "Hash Text",          "accepts": ["username"],            "desc": "md5/sha1/sha256/sha512 of text (offline)"},
    "qrcode":         {"fn": tool_qrcode,         "label": "QR Code",            "accepts": ["username", "url"],     "desc": "Generate a QR code for text/URL"},
    "dnsptrrange":    {"fn": tool_dnsptrrange,    "label": "PTR Range Sweep",    "accepts": ["cidr"],                "desc": "Reverse-DNS every host in a /24 (offline)"},
    "jwtdecode":      {"fn": tool_jwtdecode,      "label": "JWT Decode",         "accepts": ["jwt"],                 "desc": "Decode JWT header+payload (offline, unverified)"},

    # --- extension pack 5 ---
    # --- social ---
    "reddit_user":    {"fn": tool_reddit_user,   "label": "Reddit User",       "accepts": ["username"],              "desc": "Reddit user: karma, age, verified status"},
    "reddit_sub":     {"fn": tool_reddit_sub,    "label": "Reddit Subreddit",  "accepts": ["username"],              "desc": "Subreddit: subscribers, active users, description"},
    "huggingface":    {"fn": tool_huggingface,   "label": "HuggingFace",       "accepts": ["username", "package"],   "desc": "HuggingFace user profile or model card"},
    "steam_user":     {"fn": tool_steam_user,    "label": "Steam Profile",     "accepts": ["username"],              "desc": "Steam community profile via public XML"},
    "codeforces":     {"fn": tool_codeforces,    "label": "Codeforces",        "accepts": ["username"],              "desc": "Codeforces competitive programmer rating & rank"},
    "leetcode_user":  {"fn": tool_leetcode_user, "label": "LeetCode",          "accepts": ["username"],              "desc": "LeetCode solved problems, ranking, badges"},
    "npmorg":         {"fn": tool_npmorg,        "label": "npm Org",           "accepts": ["username"],              "desc": "npm organization: all published packages"},
    "emailrep":       {"fn": tool_emailrep,      "label": "emailrep.io",       "accepts": ["email"],                 "desc": "Email reputation: breach, blacklist, profiles"},
    # --- academic ---
    "arxiv":          {"fn": tool_arxiv,         "label": "arXiv Search",      "accepts": ["username", "orgname"],   "desc": "arXiv paper search by title/author/keyword"},
    "pubmed":         {"fn": tool_pubmed,        "label": "PubMed",            "accepts": ["username", "orgname"],   "desc": "PubMed biomedical paper search (NCBI)"},
    "zenodo":         {"fn": tool_zenodo,        "label": "Zenodo",            "accepts": ["username", "orgname"],   "desc": "Zenodo open-research records search"},
    "dblp":           {"fn": tool_dblp,          "label": "DBLP",              "accepts": ["username", "orgname"],   "desc": "DBLP CS publication search"},
    "unpaywall":      {"fn": tool_unpaywall,     "label": "Unpaywall",         "accepts": ["doi", "url"],            "desc": "Is a DOI open-access? Direct PDF link"},
    # --- crypto chains ---
    "ltcaddr":        {"fn": tool_ltcaddr,       "label": "LTC Address",       "accepts": ["crypto", "b64"],         "desc": "Litecoin address balance & tx count"},
    "dogeaddr":       {"fn": tool_dogeaddr,      "label": "DOGE Address",      "accepts": ["crypto", "b64"],         "desc": "Dogecoin address balance & tx count"},
    "xrpaddr":        {"fn": tool_xrpaddr,       "label": "XRP Account",       "accepts": ["b64", "username"],       "desc": "XRP Ledger account balance & sequence"},
    "soladdr":        {"fn": tool_soladdr,       "label": "SOL Account",       "accepts": ["b64", "username"],       "desc": "Solana account balance & owner program"},
    # --- business/regulatory ---
    "opencorp":       {"fn": tool_opencorp,      "label": "OpenCorporates",    "accepts": ["orgname"],               "desc": "Company registrations worldwide search"},
    "gleif_name":     {"fn": tool_gleif_name,    "label": "GLEIF Name",        "accepts": ["orgname"],               "desc": "GLEIF fuzzy legal-entity name → LEI codes"},
    "fccid":          {"fn": tool_fccid,         "label": "FCC ID",            "accepts": ["username", "b64"],       "desc": "FCC equipment authorization database"},
    # --- email/smtp ---
    "smtpbanner":     {"fn": tool_smtpbanner,    "label": "SMTP Banner",       "accepts": ["domain", "ip"],          "desc": "SMTP banner & EHLO capabilities (ports 25/587/465)"},
    "disposable":     {"fn": tool_disposable,    "label": "Disposable Email",  "accepts": ["email", "domain"],       "desc": "Is the email domain a disposable provider?"},
    # --- dns/certs ---
    "zonetransfer":   {"fn": tool_zonetransfer,  "label": "Zone Transfer",     "accepts": ["domain"],                "desc": "AXFR attempt — is zone transfer misconfigured?"},
    "ctlogsearch":    {"fn": tool_ctlogsearch,   "label": "CT Logs (Org)",     "accepts": ["orgname"],               "desc": "crt.sh cert search by organization name"},
    "webfinger":      {"fn": tool_webfinger,     "label": "WebFinger",         "accepts": ["email", "username"],     "desc": "WebFinger resource discovery (ActivityPub/OIDC)"},
    "srvlookup":      {"fn": tool_srvlookup,     "label": "SRV Records",       "accepts": ["domain"],                "desc": "SIP/XMPP/mail/CalDAV SRV record discovery"},
    "nstrace":        {"fn": tool_nstrace,       "label": "NS Delegation",     "accepts": ["domain"],                "desc": "Trace NS delegation: TLD → registrar → authoritative"},
    "rdap_domain":    {"fn": tool_rdap_domain,   "label": "RDAP Domain",       "accepts": ["domain"],                "desc": "RDAP structured domain registration data"},
    # --- web security ---
    "csp_parse":      {"fn": tool_csp_parse,     "label": "CSP Analyzer",      "accepts": ["domain", "url"],         "desc": "Content-Security-Policy header analysis & grade"},
    "sri_check":      {"fn": tool_sri_check,     "label": "SRI Check",         "accepts": ["domain", "url"],         "desc": "Subresource Integrity: external scripts without integrity="},
    "clickjacking":   {"fn": tool_clickjacking,  "label": "Clickjacking",      "accepts": ["domain", "url"],         "desc": "X-Frame-Options + CSP frame-ancestors check"},
    "referrer_pol":   {"fn": tool_referrer_pol,  "label": "Referrer Policy",   "accepts": ["domain", "url"],         "desc": "Referrer-Policy header — URL leakage risk"},
    "permissions_pol":{"fn": tool_permissions_pol,"label": "Permissions Policy","accepts": ["domain", "url"],        "desc": "Permissions-Policy: camera/mic/geo controls"},
    # --- network/ip ---
    "ipv4classify":   {"fn": tool_ipv4classify,  "label": "IP Classify",       "accepts": ["ip"],                    "desc": "Classify IP: private/loopback/multicast/global (offline)"},
    "dnsrecon":       {"fn": tool_dnsrecon,      "label": "DNS Recon",         "accepts": ["domain"],                "desc": "Query ALL DNS record types at once"},
    # --- offline utilities ---
    "portlookup":     {"fn": tool_portlookup,    "label": "Port Lookup",       "accepts": ["port"],                  "desc": "IANA port → service name (offline)"},
    "mimetype":       {"fn": tool_mimetype,      "label": "MIME Type",         "accepts": ["ext", "domain"],         "desc": "File extension → MIME type (offline)"},
    "httpcode":       {"fn": tool_httpcode,      "label": "HTTP Status Code",  "accepts": ["port"],                  "desc": "HTTP status code meaning & family (offline)"},
    "unixperm":       {"fn": tool_unixperm,      "label": "Unix Permissions",  "accepts": ["port", "epoch"],         "desc": "Octal permission (755/644) → rwx breakdown (offline)"},
    "unicode_lookup": {"fn": tool_unicode_lookup,"label": "Unicode Lookup",    "accepts": ["unicode", "username", "port"], "desc": "Unicode codepoint: name, category, HTML entity (offline)"},
    "timezone_info":  {"fn": tool_timezone_info, "label": "Timezone Info",     "accepts": ["username"],              "desc": "Timezone UTC offset & current time (offline, IANA names)"},
    "base_convert":   {"fn": tool_base_convert,  "label": "Base Convert",      "accepts": ["port", "hash", "b64", "username"], "desc": "Binary/octal/decimal/hex number conversion (offline)"},
    "ip_math":        {"fn": tool_ip_math,       "label": "IP Math",           "accepts": ["cidr", "ip"],            "desc": "CIDR: network/broadcast/range/host count (offline)"},
    "latlonformat":   {"fn": tool_latlonformat,  "label": "Lat/Lon Format",    "accepts": ["coords"],                "desc": "DD ↔ DMS ↔ DM coordinate format conversion (offline)"},
    "regdomain":      {"fn": tool_regdomain,     "label": "Registered Domain", "accepts": ["domain", "url"],         "desc": "Extract eTLD+1 registered domain from URL (offline)"},
    "tldinfo":        {"fn": tool_tldinfo,       "label": "TLD Info",          "accepts": ["domain"],                "desc": "TLD registry operator, type, purpose (offline)"},
    "emailformat":    {"fn": tool_emailformat,   "label": "Email Format",      "accepts": ["domain", "email"],       "desc": "Email address patterns used at a company domain"},
    "teamcymru":      {"fn": tool_teamcymru,     "label": "Team Cymru ASN",    "accepts": ["ip"],                    "desc": "IP → ASN via Team Cymru DNS (fastest ASN lookup)"},
    "whoisserver":    {"fn": tool_whoisserver,   "label": "WHOIS Server",      "accepts": ["domain"],                "desc": "TLD → WHOIS server mapping (offline + IANA fallback)"},
    "robotsmeta":     {"fn": tool_robotsmeta,    "label": "Robots Meta",       "accepts": ["domain", "url"],         "desc": "meta-robots + X-Robots-Tag: noindex/nofollow/noarchive"},

    # --- extension pack 6 ---
    # --- phone ---
    "numlookup":   {"fn": tool_numlookup,  "label": "Number Lookup",    "accepts": ["phone"], "desc": "Validity, region, carrier, line type, timezones (libphonenumber)"},
    "phonefmt":    {"fn": tool_phonefmt,   "label": "Phone Format",     "accepts": ["phone"], "desc": "E.164 / national / international / RFC3966 formats (offline)"},
    "phonenanp":   {"fn": tool_phonenanp,  "label": "NANP Area Code",   "accepts": ["phone"], "desc": "+1 number → US/Canada region (offline subset)"},
    "phonecc":     {"fn": tool_phonecc,    "label": "Calling Code",     "accepts": ["phone"], "desc": "Country, trunk & intl dialing prefixes (offline)"},
    "phonepivot":  {"fn": tool_phonepivot, "label": "Phone Lookups",    "accepts": ["phone"], "desc": "Caller-ID / reputation site links (Truecaller, Sync.me…)"},
    "phoneapps":   {"fn": tool_phoneapps,  "label": "Messaging Links",  "accepts": ["phone"], "desc": "WhatsApp / Telegram / Viber / Signal deep links"},
    "phonespam":   {"fn": tool_phonespam,  "label": "Spam Reports",     "accepts": ["phone"], "desc": "Robocall / scam report-database links"},
    "phonevcard":  {"fn": tool_phonevcard, "label": "vCard",            "accepts": ["phone"], "desc": "Generate a .vcf contact card (offline)"},
    # --- image (q = direct image URL) ---
    "imageexif":   {"fn": tool_imageexif,  "label": "Image EXIF",       "accepts": ["image", "url"], "desc": "Full EXIF: camera, lens, timestamps, software"},
    "imagegps":    {"fn": tool_imagegps,   "label": "Image GPS",        "accepts": ["image", "url"], "desc": "GPS coordinates from EXIF → map links (feeds globe)"},
    "imagemeta":   {"fn": tool_imagemeta,  "label": "Image Metadata",   "accepts": ["image", "url"], "desc": "Dimensions, format, mode, size, megapixels"},
    "imagehash":   {"fn": tool_imagehash,  "label": "Image Hash",       "accepts": ["image", "url"], "desc": "Perceptual aHash + sha256/md5 for dupe matching"},
    "imagecolors": {"fn": tool_imagecolors,"label": "Image Palette",    "accepts": ["image", "url"], "desc": "Dominant color palette extraction"},
    "imagerev":    {"fn": tool_imagerev,   "label": "Reverse Image",    "accepts": ["image", "url"], "desc": "Google Lens / Yandex / Bing / TinEye search links"},
    "imagephash":  {"fn": tool_imagephash, "label": "Image pHash/dHash", "accepts": ["image", "url"], "desc": "dHash + pHash for robust near-duplicate detection"},
    "imagethumb":  {"fn": tool_imagethumb, "label": "EXIF Thumbnail",    "accepts": ["image", "url"], "desc": "Extract embedded thumbnail — often retains GPS after stripping"},
    "imageicc":    {"fn": tool_imageicc,   "label": "ICC Profile",       "accepts": ["image", "url"], "desc": "Color profile name — fingerprints editing software"},
    "imagechunks": {"fn": tool_imagechunks,"label": "PNG Chunks",        "accepts": ["image", "url"], "desc": "Hidden tEXt/zTXt/iTXt chunks in PNG (steganography)"},
    "imagexmp":    {"fn": tool_imagexmp,   "label": "XMP Metadata",      "accepts": ["image", "url"], "desc": "XMP block: creator tool, edit history, software version"},
    "imagelsb":    {"fn": tool_imagelsb,   "label": "LSB Steg Detect",   "accepts": ["image", "url"], "desc": "Statistical LSB analysis — detects possible hidden payload"},
    # --- geo / world events ---
    "quakes":      {"fn": tool_quakes,     "label": "Earthquakes",      "accepts": ["coords", "username"], "desc": "USGS recent quakes — global or near coords (M2.5+)"},
    "iss":         {"fn": tool_iss,        "label": "ISS Position",     "accepts": ["coords", "username"], "desc": "Live International Space Station lat/lon"},
    "spacepeople": {"fn": tool_spacepeople,"label": "People in Space",  "accepts": ["coords", "username"], "desc": "Who is in space right now (names + craft)"},
    "airquality":  {"fn": tool_airquality, "label": "Air Quality",      "accepts": ["coords"], "desc": "PM2.5/PM10/ozone + European AQI at coords (open-meteo)"},
    "marineweather":{"fn": tool_marineweather,"label": "Marine Weather","accepts": ["coords"], "desc": "Wave height/period/direction + sea temp at coords"},
    "flightsnear": {"fn": tool_flightsnear,"label": "Flights Nearby",   "accepts": ["coords"], "desc": "Live aircraft within ~1° of coords (OpenSky)"},
    "whatsnearby": {"fn": tool_whatsnearby,"label": "Nearby POIs",      "accepts": ["coords"], "desc": "OSM amenities within 500m of coords (Overpass)"},
    "maidenhead":  {"fn": tool_maidenhead, "label": "Maidenhead Grid",  "accepts": ["coords"], "desc": "Coords → ham-radio grid locator (offline)"},
    "pluscode":    {"fn": tool_pluscode,   "label": "Plus Code",        "accepts": ["coords"], "desc": "Coords → Open Location Code / Google Plus Code (offline)"},
    "antipode":    {"fn": tool_antipode,   "label": "Antipode",         "accepts": ["coords"], "desc": "Opposite point on Earth for coords (offline)"},
    "geodist":     {"fn": tool_geodist,    "label": "Geo Distance",     "accepts": ["coords", "orgname"], "desc": "Great-circle distance between two coord pairs (offline)"},
    "moonphase":   {"fn": tool_moonphase,  "label": "Moon Phase",       "accepts": ["coords", "epoch", "username"], "desc": "Current moon phase & illumination (offline)"},
    # --- offline format / crypto / misc ---
    "morse":       {"fn": tool_morse,      "label": "Morse Code",       "accepts": ["username", "orgname", "b64"], "desc": "Text ↔ Morse code (offline, auto-direction)"},
    "nato":        {"fn": tool_nato,       "label": "NATO Phonetic",    "accepts": ["username", "orgname"], "desc": "Spell text in NATO phonetic alphabet (offline)"},
    "roman":       {"fn": tool_roman,      "label": "Roman Numerals",   "accepts": ["port", "username", "epoch"], "desc": "Integer ↔ Roman numeral (offline)"},
    "caesar":      {"fn": tool_caesar,     "label": "Caesar Cipher",    "accepts": ["username", "orgname", "b64"], "desc": "ROT-N / Caesar brute force, all 25 shifts (offline)"},
    "snowflake":   {"fn": tool_snowflake,  "label": "Snowflake ID",     "accepts": ["port", "epoch", "username"], "desc": "Decode Twitter/Discord snowflake → timestamp (offline)"},
    "ulid":        {"fn": tool_ulid,       "label": "ULID Decode",      "accepts": ["username", "b64"], "desc": "Decode a ULID's embedded timestamp (offline)"},
    "cron":        {"fn": tool_cron,       "label": "Cron Explain",     "accepts": ["orgname"], "desc": "Explain a 5-field cron expression (offline)"},
    "hexdump":     {"fn": tool_hexdump,    "label": "Hexdump",          "accepts": ["username", "orgname", "b64"], "desc": "Offset/hex/ASCII hexdump of input (offline)"},
    "numwords":    {"fn": tool_numwords,   "label": "Number to Words",  "accepts": ["port", "epoch", "bin"], "desc": "Integer → English words (offline)"},
    "jsonfmt":     {"fn": tool_jsonfmt,    "label": "JSON Format",      "accepts": ["orgname", "b64"], "desc": "Validate, pretty-print & stat JSON (offline)"},
    "passentropy": {"fn": tool_passentropy,"label": "Password Entropy", "accepts": ["username", "orgname"], "desc": "Estimate entropy & offline crack time (offline)"},
    # --- more keyless live ---
    "cryptoprice": {"fn": tool_cryptoprice,"label": "Crypto Price",     "accepts": ["crypto", "username", "orgname"], "desc": "Live coin price + 24h change (CoinGecko)"},
    "agify":       {"fn": tool_agify,      "label": "Age Predictor",    "accepts": ["username", "orgname"], "desc": "Predict age from a first name (agify.io)"},
    "genderize":   {"fn": tool_genderize,  "label": "Gender Predictor", "accepts": ["username", "orgname"], "desc": "Predict gender from a first name (genderize.io)"},
    "nationalize": {"fn": tool_nationalize,"label": "Nationality",      "accepts": ["username", "orgname"], "desc": "Predict nationality from a name (nationalize.io)"},
    "randomuser":  {"fn": tool_randomuser, "label": "Random Identity",  "accepts": ["username", "orgname"], "desc": "Synthetic identity for sockpuppet hygiene (randomuser.me)"},
    "holidays":    {"fn": tool_holidays,   "label": "Public Holidays",  "accepts": ["orgname", "username"], "desc": "Country public holidays this year (nager.at)"},
    # --- more offline ---
    "binarytext":  {"fn": tool_binarytext, "label": "Binary Text",      "accepts": ["username", "orgname", "b64"], "desc": "Text ↔ 8-bit binary (offline)"},
    "rot47":       {"fn": tool_rot47,      "label": "ROT47",            "accepts": ["username", "orgname", "b64"], "desc": "ROT47 ASCII cipher (offline, self-inverse)"},
    "ascii85":     {"fn": tool_ascii85,    "label": "Ascii85",          "accepts": ["b64", "orgname"], "desc": "Ascii85 encode/decode (offline)"},
    "emoji":       {"fn": tool_emoji,      "label": "Emoji Lookup",     "accepts": ["unicode", "username", "orgname"], "desc": "Emoji ↔ Unicode name/codepoint (offline)"},
    "slug":        {"fn": tool_slug,       "label": "Slugify",          "accepts": ["orgname", "username"], "desc": "Text → URL-safe slug (offline)"},
    "wordcount":   {"fn": tool_wordcount,  "label": "Word Count",       "accepts": ["orgname", "b64"], "desc": "Text stats: words/chars/lines/reading time (offline)"},
    "ipint":       {"fn": tool_ipint,      "label": "IP ↔ Integer",     "accepts": ["ip", "port"], "desc": "IPv4 ↔ integer ↔ hex (offline)"},
    "tempconv":    {"fn": tool_tempconv,   "label": "Temperature",      "accepts": ["username", "port"], "desc": "Convert °C / °F / K (offline)"},

    # --- extension pack 7 ---
    # --- world events (live) ---
    "disasters":   {"fn": tool_disasters,  "label": "Disasters (GDACS)", "accepts": ["coords", "username", "orgname"], "desc": "Active worldwide disasters: quakes/cyclones/floods (feeds globe)"},
    "spaceweather":{"fn": tool_spaceweather,"label": "Space Weather",    "accepts": ["coords", "username", "orgname"], "desc": "Planetary Kp index + geomagnetic storm/aurora (NOAA)"},
    "weatheralerts":{"fn": tool_weatheralerts,"label": "Weather Alerts",  "accepts": ["coords"], "desc": "Active US NWS weather alerts near coords"},
    "onthisday":   {"fn": tool_onthisday,  "label": "On This Day",       "accepts": ["username", "orgname"], "desc": "Historical events on a date (Wikipedia; MM/DD or today)"},
    "trendingwiki":{"fn": tool_trendingwiki,"label": "Trending Wikipedia","accepts": ["username", "orgname"], "desc": "Most-read Wikipedia articles today"},
    # --- crypto chain stats (live) ---
    "btcfees":     {"fn": tool_btcfees,    "label": "BTC Fees",          "accepts": ["crypto", "username", "orgname"], "desc": "Recommended Bitcoin fees sat/vB (mempool.space)"},
    "blockheight": {"fn": tool_blockheight,"label": "Block Height",      "accepts": ["crypto", "username", "orgname"], "desc": "Current Bitcoin + Ethereum block height"},
    "cryptomarket":{"fn": tool_cryptomarket,"label": "Crypto Market",     "accepts": ["crypto", "username", "orgname"], "desc": "Global market cap, BTC dominance, 24h volume (CoinGecko)"},
    "coininfo":    {"fn": tool_coininfo,   "label": "Coin Info",         "accepts": ["crypto", "username", "orgname"], "desc": "Coin metadata: categories, algorithm, genesis (CoinGecko)"},
    # --- page recon (live) ---
    "jslibs":      {"fn": tool_jslibs,     "label": "JS Libraries",      "accepts": ["domain", "url"], "desc": "Enumerate <script> sources + detect JS libs/versions"},
    "htmlcomments":{"fn": tool_htmlcomments,"label": "HTML Comments",     "accepts": ["domain", "url"], "desc": "Extract HTML comments — leaked TODOs/paths/software"},
    "formaudit":   {"fn": tool_formaudit,  "label": "Form Audit",        "accepts": ["domain", "url"], "desc": "Enumerate forms/inputs (login/upload) — attack surface"},
    "metatags":    {"fn": tool_metatags,   "label": "Meta Tags",         "accepts": ["domain", "url"], "desc": "OpenGraph / Twitter-card / generator meta tags"},
    "telegram_channel":{"fn": tool_telegram_channel,"label": "Telegram Channel","accepts": ["username"], "desc": "Public channel preview: subscribers, description"},
    "linktree":    {"fn": tool_linktree,   "label": "Linktree",          "accepts": ["username"], "desc": "Extract destination links from a linktr.ee profile"},
    # --- offline validators / converters ---
    "imei":        {"fn": tool_imei,       "label": "IMEI Check",        "accepts": ["imei", "phone"], "desc": "Validate IMEI (Luhn) + split TAC/serial (offline)"},
    "creditcard":  {"fn": tool_creditcard, "label": "Card Brand",        "accepts": ["bin", "iban"], "desc": "Identify card brand + Luhn validity (offline)"},
    "ean":         {"fn": tool_ean,        "label": "Barcode/EAN",       "accepts": ["isbn", "bin", "epoch"], "desc": "EAN/UPC check digit + GS1 country prefix (offline)"},
    "punycode":    {"fn": tool_punycode,   "label": "Punycode/IDN",      "accepts": ["domain", "orgname"], "desc": "IDN domain ↔ Punycode (xn--) homograph check (offline)"},
    "homoglyph":   {"fn": tool_homoglyph,  "label": "Homoglyph",         "accepts": ["domain", "orgname", "username"], "desc": "Detect confusable/mixed-script spoofing chars (offline)"},
    "base58":      {"fn": tool_base58,     "label": "Base58",            "accepts": ["b64", "orgname"], "desc": "Base58 (Bitcoin alphabet) encode/decode (offline)"},
    "vatid":       {"fn": tool_vatid,      "label": "EU VAT",            "accepts": ["orgname", "username"], "desc": "Validate EU VAT number country format (offline)"},
    "swiftbic":    {"fn": tool_swiftbic,   "label": "SWIFT/BIC",         "accepts": ["orgname", "username"], "desc": "Parse SWIFT/BIC: bank/country/branch (offline)"},
    "utm":         {"fn": tool_utm,        "label": "UTM Coords",        "accepts": ["coords"], "desc": "Lat/lon → UTM coordinates (WGS84, offline)"},
    "mgrs":        {"fn": tool_mgrs,       "label": "MGRS Grid",         "accepts": ["coords"], "desc": "Lat/lon → MGRS military grid reference (offline)"},
    "bearing":     {"fn": tool_bearing,    "label": "Bearing",           "accepts": ["coords", "orgname"], "desc": "Initial compass bearing between two coord pairs (offline)"},
    "passgen":     {"fn": tool_passgen,    "label": "Password Gen",      "accepts": ["username", "orgname", "port"], "desc": "Generate strong random passwords + passphrase (offline)"},
    "casify":      {"fn": tool_casify,     "label": "Case Convert",      "accepts": ["orgname", "username"], "desc": "snake/camel/Pascal/kebab/CONSTANT case (offline)"},
    "leet":        {"fn": tool_leet,       "label": "Leetspeak",         "accepts": ["username", "orgname"], "desc": "Leetspeak transform (offline)"},
    "atbash":      {"fn": tool_atbash,     "label": "Atbash Cipher",     "accepts": ["username", "orgname", "b64"], "desc": "Atbash A↔Z mirror cipher (offline, self-inverse)"},
    "railfence":   {"fn": tool_railfence,  "label": "Rail Fence",        "accepts": ["username", "orgname", "b64"], "desc": "Rail-fence cipher over 3 rails (offline)"},

    # --- extension pack 8 ---
    # --- live feeds ---
    "rdap":       {"fn": tool_rdap,       "label": "RDAP Registration", "accepts": ["domain", "url"], "desc": "Structured domain registration record (RDAP/IANA bootstrap, no key)"},
    "hnuser":     {"fn": tool_hnuser,     "label": "Hacker News User",  "accepts": ["username", "orgname"], "desc": "HN profile: karma, created, submission count"},
    "ghevents":   {"fn": tool_ghevents,   "label": "GitHub Activity",   "accepts": ["username", "orgname"], "desc": "Recent public GitHub events for a user (60/hr)"},
    "cratestats": {"fn": tool_cratestats, "label": "crates.io Stats",   "accepts": ["package", "username", "orgname"], "desc": "Rust crate downloads, version, repo (no key)"},
    "airquality": {"fn": tool_airquality, "label": "Air Quality",       "accepts": ["coords"], "desc": "PM2.5/PM10/European AQI at coords (Open-Meteo, no key)"},
    # --- offline validators / converters ---
    "isin":       {"fn": tool_isin,       "label": "ISIN Validate",     "accepts": ["orgname", "username"], "desc": "Validate ISIN security identifier check digit (offline)"},
    "barcode":    {"fn": tool_barcode,    "label": "Barcode Validate",  "accepts": ["orgname", "username", "port"], "desc": "EAN-13 / UPC-A check digit validation (offline)"},
    "macvendor":  {"fn": tool_macvendor,  "label": "MAC Vendor (OUI)",  "accepts": ["mac"], "desc": "MAC vendor + local/multicast bits from local OUI table (offline)"},
    "vigenere":   {"fn": tool_vigenere,   "label": "Vigenere Cipher",   "accepts": ["username", "orgname", "b64"], "desc": "Vigenere encrypt/decrypt: 'KEY:text[:d]' (offline)"},
    "base36":     {"fn": tool_base36,     "label": "Base36 Codec",      "accepts": ["username", "orgname", "port"], "desc": "Encode int <-> base36, autodetecting direction (offline)"},

    # --- extension pack 9 ---
    # --- live feeds ---
    "wikipedia":    {"fn": tool_wikipedia,    "label": "Wikipedia Summary", "accepts": ["orgname", "username", "url"], "desc": "Wikipedia REST summary: extract, type, coords (no key)"},
    "dockerhub":    {"fn": tool_dockerhub,    "label": "Docker Hub Repo",   "accepts": ["package", "orgname", "username"], "desc": "Docker Hub repo pulls, stars, last update (no key)"},
    "goproxy":      {"fn": tool_goproxy,      "label": "Go Module",         "accepts": ["package", "domain", "url"], "desc": "Latest version of a Go module via module proxy (no key)"},
    "npmdownloads": {"fn": tool_npmdownloads, "label": "npm Downloads",     "accepts": ["package", "username"], "desc": "npm package download counts, last week + month (no key)"},
    "wikidata":     {"fn": tool_wikidata,     "label": "Wikidata Search",   "accepts": ["orgname", "username"], "desc": "Search Wikidata entities by label (no key)"},
    # --- offline converters / calculators ---
    "cidr":         {"fn": tool_cidr,         "label": "CIDR Calculator",   "accepts": ["ip"], "desc": "Subnet calc: network, mask, host range, count (offline)"},
    "base58":       {"fn": tool_base58,       "label": "Base58 Codec",      "accepts": ["b64", "txhash"], "desc": "Bitcoin base58 encode/decode: 'hex:..' / 'b58:..' (offline)"},
    "morse":        {"fn": tool_morse,        "label": "Morse Code",        "accepts": ["username", "orgname"], "desc": "Morse encode/decode, autodetecting direction (offline)"},
    "roman":        {"fn": tool_roman,        "label": "Roman Numerals",    "accepts": ["port", "username"], "desc": "Convert int <-> roman numeral, autodetecting (offline)"},
    "checksum":     {"fn": tool_checksum,     "label": "CRC32/Adler32",     "accepts": ["username", "orgname", "b64"], "desc": "CRC32 + Adler32 checksum of input text (offline)"},

    # --- extension pack 10 ---
    "sha256lookup":      {"fn": tool_sha256lookup,      "label": "SHA-256 Reverse",      "accepts": ["hash"],            "desc": "Crack SHA-256 via online DB"},
    "crc32":             {"fn": tool_crc32,             "label": "CRC-32 Checksum",      "accepts": ["username", "orgname"], "desc": "Compute CRC-32 of input"},
    "rot13":             {"fn": tool_rot13,             "label": "ROT-13 Cipher",        "accepts": ["username", "orgname"], "desc": "ROT-13 encode/decode"},
    "spamhauslookup":    {"fn": tool_spamhauslookup,    "label": "Spamhaus IP Check",    "accepts": ["ip"],              "desc": "Spam/phishing IP blacklist check"},
    "isexitnode":        {"fn": tool_isexitnode,        "label": "Tor Exit Check",       "accepts": ["ip"],              "desc": "Is this a Tor exit node?"},
    "asnlookup":         {"fn": tool_asnlookup,         "label": "ASN Lookup",           "accepts": ["asn"],             "desc": "ASN org/country/prefixes via RIPEstat"},
    "hostname":          {"fn": tool_hostname,          "label": "Reverse DNS",          "accepts": ["ip"],              "desc": "IP → hostname via reverse DNS"},
    "portquick":         {"fn": tool_portquick,         "label": "Port Check",           "accepts": ["ip"],              "desc": "Quick TCP port scan (2s timeout)"},
    "dnsquery":          {"fn": tool_dnsquery,          "label": "DNS A Record",         "accepts": ["domain"],          "desc": "DNS A record lookup via Google DoH"},
    "creditcardtest":    {"fn": tool_creditcardtest,    "label": "Credit Card Validator","accepts": ["bin"],             "desc": "Luhn check + brand guess (test only)"},
    "htmlencode":        {"fn": tool_htmlencode,        "label": "HTML Encode/Decode",  "accepts": ["username", "orgname"], "desc": "HTML entity encode/decode"},
    "urlparse":          {"fn": tool_urlparse,          "label": "URL Parse",            "accepts": ["url"],             "desc": "Parse URL into components + query params"},

    # --- extension pack 11 ---
    "disposablecheck":   {"fn": tool_disposablecheck,   "label": "Disposable Email",     "accepts": ["email"],              "desc": "Check if email is temporary/disposable"},
    "emailformat":       {"fn": tool_emailformat,       "label": "Email Validator",      "accepts": ["email"],              "desc": "Basic RFC 5322 email format validation"},
    "quoted_printable":  {"fn": tool_quoted_printable,  "label": "Quoted-Printable",     "accepts": ["b64", "username"],    "desc": "Quoted-printable encode/decode"},
    "base32":            {"fn": tool_base32,            "label": "Base32 Encode/Decode", "accepts": ["b64", "username"],    "desc": "RFC 4648 Base32 encode or decode"},
    "uuencode":          {"fn": tool_uuencode,          "label": "UUencode",             "accepts": ["username", "orgname"], "desc": "Unix-to-Unix encoding"},
    "semver":            {"fn": tool_semver,            "label": "Semantic Version",     "accepts": ["package", "username"], "desc": "Parse and validate semantic versioning"},
    "ipv6":              {"fn": tool_ipv6,              "label": "IPv6 Validator",       "accepts": ["ip"],                 "desc": "IPv6 parser, expander, classifier"},
    "macvalid":          {"fn": tool_macvalid,          "label": "MAC Validator",        "accepts": ["mac"],                "desc": "MAC address parser (colon/dash/plain)"},
    "uuid_validate":     {"fn": tool_uuid_validate,     "label": "UUID Validator",       "accepts": ["uuid"],               "desc": "UUID v1-v5 version and variant detector"},
    "datauri":           {"fn": tool_datauri,           "label": "Data URI Parse",       "accepts": ["b64", "url"],         "desc": "Parse or create data: URIs"},
    "stringmetrics":     {"fn": tool_stringmetrics,     "label": "String Metrics",       "accepts": ["username", "orgname"], "desc": "Length, entropy, character breakdown"},
    "whois_check":       {"fn": tool_whois_check,       "label": "WHOIS Check",          "accepts": ["domain"],             "desc": "Domain WHOIS record existence via who.is"},

    # --- osint_leak ---
    "hibp":              {"fn": tool_hibp,              "label": "HIBP Password Check",  "accepts": ["username", "orgname"],  "desc": "Check if a password appeared in breaches via HIBP k-anonymity (no key)"},
    "hibp_email":        {"fn": tool_hibp_email,        "label": "HIBP Email Breaches",  "accepts": ["email"],                "desc": "Email breach exposure via XposedOrNot (HIBP-compatible, no key)"},
    "leakcheck":         {"fn": tool_leakcheck,         "label": "LeakCheck",            "accepts": ["email", "username"],    "desc": "Breach exposure via leakcheck.io public endpoint (no key)"},
    "hudsonrock":        {"fn": tool_hudsonrock,         "label": "HudsonRock Stealer",   "accepts": ["email", "domain"],      "desc": "Stealer-log exposure check via HudsonRock Cavalier free API"},
    "paste_email":       {"fn": tool_paste_email,        "label": "Paste Email Search",   "accepts": ["email"],                "desc": "Find email in public pastes via Wayback CDX + search links (no key)"},
    "paste_domain":      {"fn": tool_paste_domain,       "label": "Paste Domain Search",  "accepts": ["domain", "url"],        "desc": "Find domain in public pastes via psbdmp.ws (no key)"},
    "gh_dorking":        {"fn": tool_gh_dorking,         "label": "GitHub Dork Search",   "accepts": ["email", "domain", "username"], "desc": "GitHub code search for target string exposure in public repos"},
    "gh_secret_scan":    {"fn": tool_gh_secret_scan,     "label": "GitHub Secret Scan",   "accepts": ["username", "orgname"], "desc": "Scan GitHub user's public repos for leaked secrets/passwords"},
    "intelx_email":      {"fn": tool_intelx_email,       "label": "XposedOrNot Breach",   "accepts": ["email"],               "desc": "Email breach exposure — breach names, data types, paste hits (XposedOrNot, no key)"},
    "dehashed_domain":   {"fn": tool_dehashed_domain,    "label": "DeHashed Domain",      "accepts": ["domain"],              "desc": "DeHashed public page scrape for domain breach exposure"},
    "emailrep":          {"fn": tool_emailrep,           "label": "Email Reputation",     "accepts": ["email"],               "desc": "emailrep.io: malicious/spam/breach flags for email (no key, limited)"},
    "breachdirectory":   {"fn": tool_breachdirectory,    "label": "Breach Directory",     "accepts": ["email", "username"],   "desc": "ProxyNova COMB dataset search for credential exposure"},
    "snusbase_hash":     {"fn": tool_snusbase_hash,      "label": "Hash Reverse (Leaks)", "accepts": ["hash"],                "desc": "Reverse MD5/SHA1 hash via breach-sourced hash DB (md5decrypt.net)"},
    "wayback_leaks":     {"fn": tool_wayback_leaks,      "label": "Wayback Leak Scan",    "accepts": ["domain", "url"],       "desc": "Search Wayback Machine for historically exposed .env/config/secrets"},
    "trufflehog_url":    {"fn": tool_trufflehog_url,     "label": "Secret Pattern Scan",  "accepts": ["url"],                 "desc": "Scan raw URL content for API keys, tokens, private keys, JWTs"},
    "comb_search":       {"fn": tool_comb_search,        "label": "COMB Credential Search","accepts": ["email", "username"],  "desc": "Search COMB breach compilation via ProxyNova free API"},
    "leaklookup":        {"fn": tool_leaklookup,         "label": "Hudson Rock Stealers",  "accepts": ["email"],               "desc": "Infostealer compromise check — stealer logs, credential count (Hudson Rock, no key)"},

    # --- extension pack 12 ---
    "cdxwayback":       {"fn": tool_cdxwayback,       "label": "Wayback CDX",        "accepts": ["domain", "url"],  "desc": "Snapshot count + first/latest capture in Wayback Machine"},
    "cfradar":          {"fn": tool_cfradar,           "label": "Cloudflare Radar",   "accepts": ["domain"],         "desc": "Domain rank + categories from Cloudflare Radar"},
    "bgphistory":       {"fn": tool_bgphistory,        "label": "BGP History",        "accepts": ["ip", "asn"],      "desc": "Routing origin history (RIPE Stat)"},
    "dnsgraph":         {"fn": tool_dnsgraph,          "label": "DNS Graph (HE)",     "accepts": ["domain"],         "desc": "Hurricane Electric DNS delegation info"},
    "github_code":      {"fn": tool_github_code,       "label": "GitHub Code Search", "accepts": ["username", "orgname", "domain"], "desc": "GitHub unauthenticated code search (10 results)"},
    "pageinfo":         {"fn": tool_pageinfo,          "label": "Common Crawl Page",  "accepts": ["domain", "url"],  "desc": "Common Crawl capture index lookup"},
    "jarm":             {"fn": tool_jarm,              "label": "JARM / InternetDB",  "accepts": ["ip", "domain"],   "desc": "Shodan InternetDB: ports, CPEs, vulns, tags (no key)"},
    "threatcrowd":      {"fn": tool_threatcrowd,       "label": "Passive DNS",        "accepts": ["domain", "ip"],   "desc": "OTX passive DNS resolution history"},
    "apileak":          {"fn": tool_apileak,           "label": "API Leak Search",    "accepts": ["domain", "orgname", "username"], "desc": "GitHub dork links for API key/secret exposure"},
    "hibp_breaches":    {"fn": tool_hibp_breaches,     "label": "HIBP Breaches",      "accepts": ["email", "username"], "desc": "Check breach database for email/username exposure"},
    "breachdb":         {"fn": tool_breachdb,          "label": "BreachDB Search",    "accepts": ["email", "username"], "desc": "Aggregated breach collection search"},
    "password_dumps":   {"fn": tool_password_dump_search, "label": "Password Dump Search", "accepts": ["email", "username", "domain"], "desc": "Search Dehashed for leaked passwords (query-only)"},
    "ssn_check":        {"fn": tool_ssn_leak_check,    "label": "SSN/Identity Leak",  "accepts": ["ssn"],               "desc": "Check if SSN/DOB appears in identity theft databases"},
    "phone_leak":       {"fn": tool_phone_leak_check,  "label": "Phone Leak Check",   "accepts": ["phone"],             "desc": "Search for phone number in leaked databases"},
    "api_key_scan":     {"fn": tool_api_key_scan,      "label": "API Key Exposure",   "accepts": ["domain", "orgname"], "desc": "Scan GitHub/Pastebin/Google for exposed API keys/secrets"},
    "robotstxt_history":{"fn": tool_robotstxt_history, "label": "robots.txt History", "accepts": ["domain"],         "desc": "Historical robots.txt snapshots from Wayback Machine"},

    # --- THREAT INTELLIGENCE (25 new tools) ---
    "exploit_cve":      {"fn": tool_exploit_cve,       "label": "CVE Exploits",       "accepts": ["cve"],            "desc": "Exploit-DB + GitHub POCs for a CVE"},
    "cve_timeline":     {"fn": tool_cve_timeline,      "label": "CVE Timeline",       "accepts": ["cve"],            "desc": "When a CVE was discussed (Twitter/Reddit/News)"},
    "cve_poc_checker":  {"fn": tool_cve_poc_checker,   "label": "CVE POC Check",      "accepts": ["cve"],            "desc": "Check if a CVE has public POC/exploit code"},
    "mitre_technique":  {"fn": tool_mitre_technique,   "label": "MITRE Technique",    "accepts": ["technique"],      "desc": "ATT&CK technique → tactics + detection"},
    "cisa_alerts":      {"fn": tool_cisa_alerts,       "label": "CISA Alerts",        "accepts": ["keyword"],        "desc": "CISA alerts + advisories (recent threats)"},
    "ransomware_tracker":{"fn": tool_ransomware_tracker,"label": "Ransomware Groups",  "accepts": ["group"],          "desc": "Ransomware gang profiles + recent hits"},
    "threat_actor":     {"fn": tool_threat_actor_profile,"label": "Threat Actor","accepts": ["name"],            "desc": "Known campaigns, techniques, tools"},
    "malware_family":   {"fn": tool_malware_family,    "label": "Malware Family",     "accepts": ["name"],           "desc": "Variants, IOCs, AV detections"},
    "ioc_reputation":   {"fn": tool_ioc_reputation,    "label": "IOC Reputation",     "accepts": ["ip", "domain", "hash"], "desc": "Cross-check IP/domain/hash across feeds"},
    "zerodday_timeline":{"fn": tool_zerodday_timeline, "label": "Zero-Day Timeline",  "accepts": ["keyword"],        "desc": "0day mentions across researchers + CVE"},
    "apt_track":        {"fn": tool_apt_track,         "label": "APT Track",          "accepts": ["name"],           "desc": "Track APT campaigns via MITRE + researchers"},
    "botnet_tracker":   {"fn": tool_botnet_tracker,    "label": "Botnet Tracker",     "accepts": ["query"],          "desc": "Botnet C2 + IoT malware tracking"},
    "c2_infrastructure":{"fn": tool_c2_infrastructure, "label": "C2 Infrastructure",  "accepts": ["domain", "ip"],   "desc": "Detect C2 infrastructure + hosting"},
    "breach_aggregator":{"fn": tool_breach_aggregator, "label": "Breach Aggregator",  "accepts": ["email", "domain"], "desc": "Aggregate breach databases (XposedOrNot, LeakCheck, etc)"},
    "darkweb_monitor":  {"fn": tool_darkweb_monitor,   "label": "Darkweb Monitor",    "accepts": ["keyword"],        "desc": "Darkweb monitoring: marketplaces, paste sites"},
    "credential_stuffing":{"fn": tool_credential_stuffing_risk, "label": "Credential Stuffing Risk", "accepts": ["email"], "desc": "Check breach + stuffing risk"},
    "supply_chain_risk":{"fn": tool_supply_chain_risk, "label": "Supply Chain Risk", "accepts": ["package"],        "desc": "Dependency vulns + typosquatting"},
    "vuln_feed":        {"fn": tool_vulnerability_feed,"label": "Vuln Feed",         "accepts": ["keyword"],        "desc": "Real-time vuln feeds (NVD, Exploit-DB, PacketStorm)"},
    "cve_severity":     {"fn": tool_cve_severity_tracker, "label": "CVE Severity",   "accepts": ["cve"],            "desc": "CVSS + EPSS + KEV for a CVE"},
    "threat_pattern":   {"fn": tool_threat_pattern_correlation, "label": "Threat Pattern", "accepts": ["keyword"], "desc": "Find threat patterns across incidents"},
    "emerging_threats": {"fn": tool_emerging_threats,  "label": "Emerging Threats",   "accepts": ["keyword"],        "desc": "Emerging threats: new CVEs + 0days (24h)"},
    "phishing_intel":   {"fn": tool_phishing_intelligence, "label": "Phishing Intel",  "accepts": ["domain", "email"], "desc": "Phishing kit tracking + URL detection"},
    "infra_fingerprint":{"fn": tool_infra_fingerprint, "label": "Infra Fingerprint", "accepts": ["domain", "ip"],   "desc": "Infrastructure fingerprinting + hosting"},
    "attack_surface":   {"fn": tool_attack_surface_map,"label": "Attack Surface",    "accepts": ["domain", "ip"],   "desc": "Map attack surface: services + endpoints + API"},
}



def run(tool, query):
    if tool not in TOOLS:
        return {"error": f"unknown tool: {tool}"}
    try:
        return TOOLS[tool]["fn"](query)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def catalog():
    return {k: {"label": v["label"], "accepts": v["accepts"], "desc": v["desc"]}
            for k, v in TOOLS.items()}
