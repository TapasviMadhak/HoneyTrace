#!/usr/bin/env python3
"""Export sanitized HoneyTrace telemetry snapshots to a private S3 origin."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import urlopen


DATABASE_PATH = "/var/lib/honeytrace/cowrie-events.sqlite3"
GEO_API_BASE_URL = "http://127.0.0.1:8000/api/geo"
S3_BUCKET = "honeytrace-telemetry-public-183174222877"
S3_PREFIX = "public"
AWS_REGION = "ap-south-1"


def database():
    connection = sqlite3.connect("file:{}?mode=ro".format(DATABASE_PATH), uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def geo_for_ip(ip):
    """Use the existing API geo lookup, which owns the persistent SQLite cache."""
    try:
        with urlopen("{}/{}".format(GEO_API_BASE_URL, quote(ip, safe="")), timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
        print("geolocation unavailable for {}: {}".format(ip, error), file=sys.stderr)
        return {"status": "unavailable"}


def summary(connection):
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


def intent_breakdown(connection):
    counts = {"probe": 0, "unknown": 0, "deploy": 0, "proxy": 0, "mixed": 0}
    for row in connection.execute("SELECT intent, COUNT(*) AS count FROM session_intent GROUP BY intent"):
        counts[row["intent"]] = row["count"]
    return counts


def public_actors(connection):
    actors = []
    rows = connection.execute(
        """
        SELECT hassh, ip_list, first_seen, last_seen, session_count
        FROM actors
        ORDER BY session_count DESC, actor_id ASC
        """
    ).fetchall()
    for row in rows:
        try:
            ips = json.loads(row["ip_list"])
        except (TypeError, json.JSONDecodeError):
            ips = []

        locations = set()
        for ip in ips:
            geo = geo_for_ip(ip)
            if geo.get("status") == "success" and geo.get("country"):
                locations.add((geo.get("city") or None, geo["country"]))

        actors.append(
            {
                "hassh": hashlib.sha256(row["hassh"].encode("utf-8")).hexdigest() if row["hassh"] else None,
                "session_count": row["session_count"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "locations": [
                    {"city": city, "country": country}
                    for city, country in sorted(locations, key=lambda item: (item[1], item[0] or ""))
                ],
            }
        )
    return actors


def write_json(directory, filename, payload):
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as output:
        json.dump(payload, output, separators=(",", ":"), ensure_ascii=False)
        output.write("\n")
    return path


def upload(path):
    key = "{}/{}".format(S3_PREFIX.strip("/"), os.path.basename(path))
    subprocess.run(
        [
            "aws",
            "s3api",
            "put-object",
            "--bucket",
            S3_BUCKET,
            "--key",
            key,
            "--body",
            path,
            "--content-type",
            "application/json",
            "--cache-control",
            "public, max-age=60",
            "--region",
            AWS_REGION,
        ],
        check=True,
    )
    return key


def main():
    with database() as connection:
        payloads = {
            "summary.json": summary(connection),
            "actors.json": public_actors(connection),
            "intent_breakdown.json": intent_breakdown(connection),
        }

    with tempfile.TemporaryDirectory(prefix="honeytrace-public-") as directory:
        for filename, payload in payloads.items():
            path = write_json(directory, filename, payload)
            key = upload(path)
            records = len(payload) if isinstance(payload, list) else len(payload.keys())
            print("exported {}: {} bytes, {} records, s3://{}/{}".format(
                filename, os.path.getsize(path), records, S3_BUCKET, key
            ))


if __name__ == "__main__":
    main()
