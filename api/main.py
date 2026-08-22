"""Read-only HoneyTrace API backed by Cowrie's SQLite event database."""

import json
import ipaddress
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware


DATABASE_PATH = os.environ.get(
    "HONEYTRACE_DB_PATH", "/var/lib/honeytrace/cowrie-events.sqlite3"
)
MAX_PAGE_SIZE = 500
GEO_API_URL = "http://ip-api.com/json/{}?fields=status,message,query,lat,lon,country,countryCode,regionName,city"
GEO_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    message TEXT,
    latitude REAL,
    longitude REAL,
    country TEXT,
    country_code TEXT,
    region_name TEXT,
    city TEXT,
    fetched_at TEXT NOT NULL
);
"""
GEO_LOOKUP_INTERVAL_SECONDS = 1.5  # ip-api free tier permits at most 45 requests/minute.
_geo_request_lock = threading.Lock()
_next_geo_request_at = 0.0

app = FastAPI(title="HoneyTrace API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    """Open a read-only SQLite connection for one API request."""
    db_uri = "file:{}?mode=ro".format(os.path.abspath(DATABASE_PATH))
    connection = sqlite3.connect(db_uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def actor_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert actor JSON text to the API's array representation."""
    actor = row_dict(row)
    try:
        actor["ip_list"] = json.loads(actor["ip_list"])
    except (TypeError, json.JSONDecodeError):
        actor["ip_list"] = []
    return actor


def timestamp_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@contextmanager
def geo_database() -> Iterator[sqlite3.Connection]:
    """Open a write-capable connection used solely for the geolocation cache."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.executescript(GEO_CACHE_SCHEMA)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def cached_geo_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "ip": row["ip"],
        "status": row["status"],
        "message": row["message"],
        "lat": row["latitude"],
        "lon": row["longitude"],
        "country": row["country"],
        "country_code": row["country_code"],
        "region_name": row["region_name"],
        "city": row["city"],
        "fetched_at": row["fetched_at"],
    }


def fetch_geo(ip: str) -> dict[str, Any]:
    """Query ip-api while keeping the process below the free tier rate limit."""
    global _next_geo_request_at
    with _geo_request_lock:
        delay = _next_geo_request_at - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        _next_geo_request_at = time.monotonic() + GEO_LOOKUP_INTERVAL_SECONDS

        request = Request(
            GEO_API_URL.format(quote(ip, safe="")),
            headers={"User-Agent": "HoneyTrace/0.1"},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            return {"status": "unavailable", "message": str(error)}


def save_geo(connection: sqlite3.Connection, ip: str, response: dict[str, Any]) -> sqlite3.Row:
    status = response.get("status", "unavailable")
    connection.execute(
        """
        INSERT INTO geo_cache (
            ip, status, message, latitude, longitude, country, country_code,
            region_name, city, fetched_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            status = excluded.status,
            message = excluded.message,
            latitude = excluded.latitude,
            longitude = excluded.longitude,
            country = excluded.country,
            country_code = excluded.country_code,
            region_name = excluded.region_name,
            city = excluded.city,
            fetched_at = excluded.fetched_at
        """,
        (
            ip,
            status,
            response.get("message"),
            response.get("lat"),
            response.get("lon"),
            response.get("country"),
            response.get("countryCode"),
            response.get("regionName"),
            response.get("city"),
            timestamp_now(),
        ),
    )
    return connection.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()


@app.get("/api/summary")
def summary() -> dict[str, int]:
    """Return aggregate event and login statistics."""
    with database() as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                COUNT(DISTINCT src_ip) AS unique_src_ips,
                COUNT(DISTINCT session_id) AS unique_sessions,
                SUM(CASE WHEN event_id = 'cowrie.login.success' THEN 1 ELSE 0 END) AS login_successes,
                SUM(CASE WHEN event_id = 'cowrie.login.failed' THEN 1 ELSE 0 END) AS login_failures,
                SUM(CASE WHEN timestamp >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS events_last_24h
            FROM events
            """
        ).fetchone()

    return {key: row[key] or 0 for key in row.keys()}


@app.get("/api/events")
def events(
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Return raw Cowrie events, newest first, using offset pagination."""
    with database() as connection:
        total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        rows = connection.execute(
            """
            SELECT id, event_hash, session_id, event_id, src_ip, dst_port,
                   timestamp, username, password, hassh, command_input,
                   raw_json, source_file, file_offset
            FROM events
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

    return {
        "items": [row_dict(row) for row in rows],
        "limit": limit,
        "offset": offset,
        "total": total,
    }


@app.get("/api/actors")
def actors() -> dict[str, list[dict[str, Any]]]:
    """Return HASSH-clustered actors produced by the ingest classifier."""
    with database() as connection:
        rows = connection.execute(
            """
            SELECT
                actor_id, hassh, ip_list, first_seen, last_seen, session_count
            FROM actors
            ORDER BY session_count DESC, actor_id ASC
            """
        ).fetchall()

    return {"items": [actor_dict(row) for row in rows]}


@app.get("/api/intent-breakdown")
def intent_breakdown() -> dict[str, int]:
    """Return classified session counts, grouped by intent."""
    with database() as connection:
        rows = connection.execute(
            "SELECT intent, COUNT(*) AS count FROM session_intent GROUP BY intent"
        ).fetchall()

    counts = {"probe": 0, "unknown": 0, "deploy": 0, "proxy": 0, "mixed": 0}
    counts.update({row["intent"]: row["count"] for row in rows})
    return counts


@app.get("/api/sessions")
def sessions() -> dict[str, list[dict[str, Any]]]:
    """Return session-level timing, commands, and authentication outcomes."""
    with database() as connection:
        rows = connection.execute(
            """
            SELECT
                session_id,
                MIN(src_ip) AS src_ip,
                MIN(timestamp) AS start_time,
                MAX(timestamp) AS end_time,
                GROUP_CONCAT(command_input, '\n') FILTER (
                    WHERE command_input IS NOT NULL AND command_input != ''
                ) AS commands_run,
                SUM(CASE WHEN event_id = 'cowrie.login.success' THEN 1 ELSE 0 END) AS login_success,
                SUM(CASE WHEN event_id = 'cowrie.login.failed' THEN 1 ELSE 0 END) AS login_fail
            FROM events
            WHERE session_id IS NOT NULL AND session_id != ''
            GROUP BY session_id
            ORDER BY end_time DESC, session_id ASC
            """
        ).fetchall()

    return {"items": [{key: row[key] or 0 for key in row.keys()} for row in rows]}


@app.get("/api/sessions/{session_id}")
def session_detail(session_id: str) -> dict[str, Any]:
    """Return ordered raw events, intent, and HASSH actor for one session."""
    with database() as connection:
        events_rows = connection.execute(
            """
            SELECT id, event_hash, session_id, event_id, src_ip, dst_port,
                   timestamp, username, password, hassh, command_input,
                   raw_json, source_file, file_offset
            FROM events
            WHERE session_id = ?
            ORDER BY timestamp ASC, id ASC
            """,
            (session_id,),
        ).fetchall()
        intent_row = connection.execute(
            "SELECT intent, actor_id, classified_at FROM session_intent WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        actor_row = None
        if intent_row is not None and intent_row["actor_id"] is not None:
            actor_row = connection.execute(
                """
                SELECT actor_id, hassh, ip_list, first_seen, last_seen, session_count
                FROM actors WHERE actor_id = ?
                """,
                (intent_row["actor_id"],),
            ).fetchone()

    return {
        "session_id": session_id,
        "intent": intent_row["intent"] if intent_row is not None else None,
        "classified_at": intent_row["classified_at"] if intent_row is not None else None,
        "actor": actor_dict(actor_row) if actor_row is not None else None,
        "events": [row_dict(row) for row in events_rows],
    }


@app.get("/api/geo-summary")
def geo_summary() -> dict[str, list[dict[str, Any]]]:
    """Return distinct source IPs and event counts for later geolocation."""
    with database() as connection:
        rows = connection.execute(
            """
            SELECT src_ip AS ip, COUNT(*) AS event_count
            FROM events
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY event_count DESC, ip ASC
            """
        ).fetchall()

    return {"items": [row_dict(row) for row in rows]}


@app.get("/api/geo/{ip}")
def geo(ip: str) -> dict[str, Any]:
    """Return cached or freshly resolved real-world geolocation for one public IP."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Invalid IP address: {}".format(error)) from error

    with geo_database() as connection:
        cached = connection.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
        if cached is not None:
            return cached_geo_dict(cached)

        if not address.is_global:
            skipped = save_geo(
                connection,
                ip,
                {"status": "skipped", "message": "Private, loopback, or reserved IP address"},
            )
            return cached_geo_dict(skipped)

        resolved = save_geo(connection, ip, fetch_geo(ip))
        return cached_geo_dict(resolved)


@app.get("/api/v1/telemetry/globe")
@app.get("/api/telemetry/globe")
def telemetry_globe() -> dict[str, Any]:
    """Return aggregated 3D globe markers, attack counts, and top targeted credentials."""
    with database() as connection:
        # Check if latitude/longitude exist on events table
        cursor = connection.cursor()
        cursor.execute("PRAGMA table_info(events)")
        columns = {row[1] for row in cursor.fetchall()}

        markers = []
        if "latitude" in columns and "longitude" in columns:
            rows = connection.execute(
                """
                SELECT latitude, longitude, city, country_code, COUNT(*) AS count
                FROM events
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                GROUP BY latitude, longitude, city, country_code
                ORDER BY count DESC
                """
            ).fetchall()

            max_count = max([row["count"] for row in rows], default=1)
            for row in rows:
                norm = row["count"] / max_count
                size = round(0.04 + 0.08 * norm, 3)
                markers.append({
                    "location": [row["latitude"], row["longitude"]],
                    "size": size,
                    "count": row["count"],
                    "city": row["city"] or "Unknown",
                    "country": row["country_code"] or "Unknown",
                })

        total_attacks = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        unique_ips = connection.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL").fetchone()[0]

        top_creds = []
        if "username" in columns and "password" in columns:
            cred_rows = connection.execute(
                """
                SELECT username, password, COUNT(*) AS count
                FROM events
                WHERE (username IS NOT NULL AND username != '') OR (password IS NOT NULL AND password != '')
                GROUP BY username, password
                ORDER BY count DESC
                LIMIT 8
                """
            ).fetchall()
            for r in cred_rows:
                top_creds.append({
                    "user": r["username"] or "<blank>",
                    "pass": r["password"] or "<blank>",
                    "count": r["count"],
                })

    return {
        "markers": markers,
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "top_credentials": top_creds,
    }

