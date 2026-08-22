#!/usr/bin/env python3
"""Ingest Cowrie JSON event logs into SQLite with MaxMind GeoIP resolution."""

import glob
import hashlib
import ipaddress
import json
import os
import sqlite3
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


# Adjust these constants when deploying the script to a different host layout.
DB_PATH = os.environ.get("HONEYTRACE_DB_PATH", "/var/lib/honeytrace/cowrie-events.sqlite3")
COWRIE_LOG_GLOB = os.environ.get("COWRIE_LOG_GLOB", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*")
MMDB_CITY_PATHS = (
    os.environ.get("GEOIP_CITY_PATH", ""),
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/honeytrace/GeoLite2-City.mmdb",
    "./GeoLite2-City.mmdb",
)
MMDB_ASN_PATHS = (
    os.environ.get("GEOIP_ASN_PATH", ""),
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/honeytrace/GeoLite2-ASN.mmdb",
    "./GeoLite2-ASN.mmdb",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash TEXT NOT NULL UNIQUE,
    session_id TEXT,
    event_id TEXT,
    src_ip TEXT,
    dst_port INTEGER,
    timestamp TEXT,
    username TEXT,
    password TEXT,
    hassh TEXT,
    command_input TEXT,
    raw_json TEXT NOT NULL,
    source_file TEXT NOT NULL,
    file_offset INTEGER NOT NULL,
    latitude REAL,
    longitude REAL,
    country_code TEXT,
    city TEXT,
    asn TEXT,
    event_type TEXT
);

CREATE TABLE IF NOT EXISTS ingest_state (
    filename TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_lat_lon ON events (latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_events_country_code ON events (country_code);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
"""

# Global memory cache for GeoIP lookups within the process
_geo_cache = {}
_city_reader = None
_asn_reader = None


def log(message):
    print("{} {}".format(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), message), file=sys.stderr)


def init_maxmind():
    """Attempt to initialize geoip2 or maxminddb readers if database files exist."""
    global _city_reader, _asn_reader
    try:
        import geoip2.database

        for path in MMDB_CITY_PATHS:
            if path and os.path.isfile(path):
                try:
                    _city_reader = geoip2.database.Reader(path)
                    log("Loaded MaxMind City database: {}".format(path))
                    break
                except Exception as error:
                    log("Failed opening MMDB city {}: {}".format(path, error))

        for path in MMDB_ASN_PATHS:
            if path and os.path.isfile(path):
                try:
                    _asn_reader = geoip2.database.Reader(path)
                    log("Loaded MaxMind ASN database: {}".format(path))
                    break
                except Exception as error:
                    log("Failed opening MMDB asn {}: {}".format(path, error))
    except ImportError:
        pass


def resolve_geoip(ip):
    """Resolve latitude, longitude, country_code, city, and ASN for a given IP."""
    if not ip or ip in _geo_cache:
        return _geo_cache.get(ip, (None, None, None, None, None))

    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            res = (None, None, None, None, None)
            _geo_cache[ip] = res
            return res
    except ValueError:
        res = (None, None, None, None, None)
        _geo_cache[ip] = res
        return res

    lat, lon, country, city, asn = None, None, None, None, None

    # 1. Try MaxMind City reader
    if _city_reader is not None:
        try:
            resp = _city_reader.city(ip)
            if resp.location:
                lat = resp.location.latitude
                lon = resp.location.longitude
            if resp.country:
                country = resp.country.iso_code
            if resp.city:
                city = resp.city.name
        except Exception:
            pass

    # 2. Try MaxMind ASN reader
    if _asn_reader is not None:
        try:
            resp = _asn_reader.asn(ip)
            if resp.autonomous_system_organization:
                asn = "AS{} {}".format(resp.autonomous_system_number or "", resp.autonomous_system_organization).strip()
            elif resp.autonomous_system_number:
                asn = "AS{}".format(resp.autonomous_system_number)
        except Exception:
            pass

    # Fallback to ip-api if MaxMind is not configured and running in interactive/batch mode
    if lat is None and _city_reader is None:
        try:
            req = Request(
                "http://ip-api.com/json/{}?fields=status,lat,lon,countryCode,city,as".format(quote(ip)),
                headers={"User-Agent": "HoneyTrace-Ingest/0.1"},
            )
            with urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("status") == "success":
                    lat = data.get("lat")
                    lon = data.get("lon")
                    country = data.get("countryCode")
                    city = data.get("city")
                    asn = data.get("as")
        except Exception:
            pass

    res = (lat, lon, country, city, asn)
    _geo_cache[ip] = res
    return res


def ensure_database():
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.executescript(SCHEMA)

    # Apply incremental column migration for existing SQLite databases
    cursor = connection.cursor()
    cursor.execute("PRAGMA table_info(events)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    new_cols = [
        ("latitude", "REAL"),
        ("longitude", "REAL"),
        ("country_code", "TEXT"),
        ("city", "TEXT"),
        ("asn", "TEXT"),
        ("event_type", "TEXT"),
    ]
    for col_name, col_type in new_cols:
        if col_name not in existing_cols:
            try:
                connection.execute("ALTER TABLE events ADD COLUMN {} {}".format(col_name, col_type))
            except sqlite3.OperationalError:
                pass

    connection.commit()
    return connection


def saved_offset(connection, filename, inode):
    row = connection.execute(
        "SELECT inode, byte_offset FROM ingest_state WHERE filename = ?",
        (filename,),
    ).fetchone()
    if row is None or row[0] != inode:
        return 0
    return row[1]


def save_offset(connection, filename, inode, byte_offset):
    connection.execute(
        """
        INSERT INTO ingest_state (filename, inode, byte_offset)
        VALUES (?, ?, ?)
        ON CONFLICT(filename) DO UPDATE SET
            inode = excluded.inode,
            byte_offset = excluded.byte_offset
        """,
        (filename, inode, byte_offset),
    )


def event_values(event, event_hash, raw_json, filename, file_offset):
    src_ip = event.get("src_ip")
    lat, lon, country_code, city, asn = resolve_geoip(src_ip)
    event_id = event.get("eventid")

    return (
        event_hash,
        event.get("session"),
        event_id,
        src_ip,
        event.get("dst_port"),
        event.get("timestamp"),
        event.get("username"),
        event.get("password"),
        event.get("hassh"),
        event.get("input"),
        raw_json,
        filename,
        file_offset,
        lat,
        lon,
        country_code,
        city,
        asn,
        event_id,
    )


def ingest_file(connection, filename):
    stat_result = os.stat(filename)
    inode = stat_result.st_ino
    offset = saved_offset(connection, filename, inode)
    inserted = 0

    with open(filename, "rb") as log_file:
        log_file.seek(offset)
        while True:
            line_offset = log_file.tell()
            raw_line = log_file.readline()
            if not raw_line:
                break

            # Do not consume a partially written final line; retry it next run.
            if not raw_line.endswith(b"\n"):
                log_file.seek(line_offset)
                break

            offset = log_file.tell()
            raw_json = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            try:
                event = json.loads(raw_json)
            except json.JSONDecodeError as error:
                log("malformed JSON skipped: file={} offset={} error={}".format(filename, line_offset, error))
                continue
            if not isinstance(event, dict):
                log("non-object JSON skipped: file={} offset={}".format(filename, line_offset))
                continue

            event_hash = hashlib.sha256(raw_line).hexdigest()
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_hash, session_id, event_id, src_ip, dst_port,
                    timestamp, username, password, hassh, command_input,
                    raw_json, source_file, file_offset,
                    latitude, longitude, country_code, city, asn, event_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                event_values(event, event_hash, raw_json, filename, line_offset),
            )
            inserted += cursor.rowcount

    save_offset(connection, filename, inode, offset)
    connection.commit()
    return inserted, offset


def main():
    init_maxmind()
    connection = ensure_database()
    total_inserted = 0
    try:
        for filename in sorted(glob.glob(COWRIE_LOG_GLOB)):
            if not os.path.isfile(filename):
                continue
            inserted, offset = ingest_file(connection, filename)
            total_inserted += inserted
            log("file={} inserted={} offset={}".format(filename, inserted, offset))
    finally:
        connection.close()

    log("ingest complete: inserted={}".format(total_inserted))


if __name__ == "__main__":
    main()
