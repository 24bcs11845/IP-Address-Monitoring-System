"""
threat_intel.py - IP enrichment (Phase 3)
==========================================
Takes a bare IP address and attaches context to it:

    WHERE is it from?     -> GeoLite2 City + ASN databases (local files)
    WHAT is its record?   -> AbuseIPDB API (internet, free key)
    HAVE WE ASKED BEFORE? -> SQLite cache (saves the 1000/day API budget)

Design rules (these match the report's non-functional requirements):
  * If a database file or API key is missing, or the API is down, the
    lookup still returns what it can. Enrichment must never crash the
    monitor.
  * API keys are never written in source code.
  * Private/LAN addresses (192.168.x.x, 10.x.x.x ...) are detected and
    skipped. They have no geography and no public reputation.

Quick test from the terminal:
    python3 threat_intel.py 8.8.8.8
"""

import ipaddress
import os
import sqlite3
import sys
import threading
import time

import requests

try:
    import geoip2.database
    import geoip2.errors
except ImportError:          # geoip2 not installed -> geolocation disabled
    geoip2 = None

HERE = os.path.dirname(os.path.abspath(__file__))

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL = 24 * 3600        # reuse a lookup for 24 hours


class ThreatIntel:
    def __init__(self, db_path="monitor.db",
                 city_db=os.path.join(HERE, "GeoLite2-City.mmdb"),
                 asn_db=os.path.join(HERE, "GeoLite2-ASN.mmdb")):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.city_reader = self._open_reader(city_db)
        self.asn_reader = self._open_reader(asn_db)
        self.api_key = self._load_api_key()
        self._init_cache_table()

        # Tell the user up front what is and isn't available
        print(f"[INTEL] GeoIP city : {'ready' if self.city_reader else 'MISSING (no country/city)'}")
        print(f"[INTEL] GeoIP ASN  : {'ready' if self.asn_reader else 'MISSING (no ISP/ASN)'}")
        print(f"[INTEL] AbuseIPDB  : {'key loaded' if self.api_key else 'NO KEY (no reputation score)'}")

    # ------------------------------------------------------------ setup
    @staticmethod
    def _open_reader(path):
        if geoip2 is None or not os.path.exists(path):
            return None
        try:
            return geoip2.database.Reader(path)
        except Exception:
            return None

    @staticmethod
    def _load_api_key():
        """Environment variable first, then a key file next to this script."""
        key = os.environ.get("ABUSEIPDB_KEY", "").strip()
        if key:
            return key
        key_file = os.path.join(HERE, "abuseipdb.key")
        if os.path.exists(key_file):
            with open(key_file) as f:
                return f.read().strip() or None
        return None

    def _init_cache_table(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_intel (
                    ip            TEXT PRIMARY KEY,
                    scope         TEXT NOT NULL,
                    country       TEXT,
                    city          TEXT,
                    asn           TEXT,
                    abuse_score   INTEGER,
                    total_reports INTEGER,
                    fetched_at    REAL NOT NULL
                )
            """)
            conn.commit()
            conn.close()

    # ------------------------------------------------------------ cache
    def _cache_get(self, ip):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            row = conn.execute(
                "SELECT scope, country, city, asn, abuse_score, total_reports, fetched_at "
                "FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
            conn.close()
        if row and time.time() - row[6] < CACHE_TTL:
            return {"ip": ip, "scope": row[0], "country": row[1], "city": row[2],
                    "asn": row[3], "abuse_score": row[4], "total_reports": row[5],
                    "cached": True}
        return None

    def _cache_put(self, r):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT OR REPLACE INTO ip_intel "
                "(ip, scope, country, city, asn, abuse_score, total_reports, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (r["ip"], r["scope"], r["country"], r["city"], r["asn"],
                 r["abuse_score"], r["total_reports"], time.time()))
            conn.commit()
            conn.close()

    # ---------------------------------------------------------- lookups
    def _geo(self, ip):
        country = city = asn = None
        if self.city_reader:
            try:
                resp = self.city_reader.city(ip)
                country, city = resp.country.name, resp.city.name
            except Exception:
                pass
        if self.asn_reader:
            try:
                resp = self.asn_reader.asn(ip)
                asn = f"AS{resp.autonomous_system_number} {resp.autonomous_system_organization}"
            except Exception:
                pass
        return country, city, asn

    def _abuse(self, ip):
        """Returns (score, total_reports) or (None, None) on any failure."""
        if not self.api_key:
            return None, None
        try:
            resp = requests.get(
                ABUSEIPDB_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            if resp.status_code == 429:
                print("[INTEL] AbuseIPDB daily limit reached - reputation skipped")
                return None, None
            resp.raise_for_status()
            data = resp.json()["data"]
            return data["abuseConfidenceScore"], data["totalReports"]
        except Exception as exc:
            print(f"[INTEL] AbuseIPDB lookup failed ({type(exc).__name__}) - continuing without it")
            return None, None

    # -------------------------------------------------------- public API
    def lookup(self, ip):
        # 1. Private / LAN addresses have nothing to look up
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"ip": ip, "scope": "invalid", "country": None, "city": None,
                    "asn": None, "abuse_score": None, "total_reports": None, "cached": False}
        if not addr.is_global:     # private, loopback, link-local, reserved, CGNAT ...
            return {"ip": ip, "scope": "private", "country": None, "city": None,
                    "asn": None, "abuse_score": None, "total_reports": None, "cached": False}

        # 2. Seen recently? reuse it
        cached = self._cache_get(ip)
        if cached:
            return cached

        # 3. Otherwise ask the databases and the API, then remember the answer
        country, city, asn = self._geo(ip)
        score, reports = self._abuse(ip)
        result = {"ip": ip, "scope": "public", "country": country, "city": city,
                  "asn": asn, "abuse_score": score, "total_reports": reports,
                  "cached": False}
        self._cache_put(result)
        return result


def describe(r):
    """One readable line for the console."""
    if r["scope"] == "private":
        return f"{r['ip']} | non-public address (private/LAN/reserved) - no geolocation or public reputation exists"
    if r["scope"] == "invalid":
        return f"{r['ip']} | not a valid IP address"
    place = ", ".join(x for x in (r["city"], r["country"]) if x) or "location unknown"
    asn = r["asn"] or "ASN unknown"
    if r["abuse_score"] is None:
        rep = "abuse score unavailable"
    else:
        rep = f"abuse score {r['abuse_score']}/100 ({r['total_reports']} reports)"
    tag = " [cached]" if r["cached"] else ""
    return f"{r['ip']} | {place} | {asn} | {rep}{tag}"


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    intel = ThreatIntel()
    print(describe(intel.lookup(target)))
    print(describe(intel.lookup(target)))   # second call should come from cache
