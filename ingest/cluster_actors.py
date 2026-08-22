#!/usr/bin/env python3
"""Cluster Cowrie sessions by HASSH and classify session intent once."""

import hashlib
import json
import os
import re
import sqlite3
import sys
import time


DB_PATH = "/var/lib/honeytrace/cowrie-events.sqlite3"

SCHEMA = """
CREATE TABLE IF NOT EXISTS actors (
    actor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    hassh TEXT UNIQUE,
    ip_list TEXT NOT NULL,
    username_corpus_hash TEXT,
    first_seen TEXT,
    last_seen TEXT,
    session_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS session_intent (
    session_id TEXT PRIMARY KEY,
    actor_id INTEGER,
    intent TEXT NOT NULL,
    classified_at TEXT NOT NULL,
    FOREIGN KEY(actor_id) REFERENCES actors(actor_id)
);
"""

DEPLOY_PATTERNS = (
    re.compile(r"\bwget\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\b(?:sh|bash)\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+\+x\b", re.IGNORECASE),
    re.compile(r"\bbase64\s+-d\b", re.IGNORECASE),
    re.compile(r"\bpython(?:3)?\s+-c\b", re.IGNORECASE),
    re.compile(r"/tmp/[^\s]*\.(?:sh|py|elf)\b", re.IGNORECASE),
)


def log(message):
    print("{} {}".format(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), message))


def database():
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection


def build_actors(connection):
    rows = connection.execute(
        """
        SELECT
            hassh,
            GROUP_CONCAT(DISTINCT src_ip) AS ips,
            GROUP_CONCAT(DISTINCT username) AS usernames,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen,
            COUNT(DISTINCT session_id) AS session_count
        FROM events
        WHERE hassh IS NOT NULL AND hassh != ''
        GROUP BY hassh
        """
    ).fetchall()

    for row in rows:
        ips = sorted(ip for ip in (row["ips"] or "").split(",") if ip)
        usernames = sorted(name for name in (row["usernames"] or "").split(",") if name)
        username_corpus_hash = hashlib.sha256(",".join(usernames).encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO actors (
                hassh, ip_list, username_corpus_hash, first_seen, last_seen, session_count
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hassh) DO UPDATE SET
                ip_list = excluded.ip_list,
                username_corpus_hash = excluded.username_corpus_hash,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                session_count = excluded.session_count
            """,
            (
                row["hassh"],
                json.dumps(ips),
                username_corpus_hash,
                row["first_seen"],
                row["last_seen"],
                row["session_count"],
            ),
        )

    return len(rows)


def actor_ids_by_session(connection):
    rows = connection.execute(
        """
        SELECT e.session_id, MIN(a.actor_id) AS actor_id
        FROM events AS e
        JOIN actors AS a ON a.hassh = e.hassh
        WHERE e.session_id IS NOT NULL AND e.session_id != ''
          AND e.hassh IS NOT NULL AND e.hassh != ''
        GROUP BY e.session_id
        """
    ).fetchall()
    return {row["session_id"]: row["actor_id"] for row in rows}


def is_deploy(commands):
    return any(pattern.search(command) for command in commands for pattern in DEPLOY_PATTERNS)


def classify_session(rows):
    event_ids = [row["event_id"] or "" for row in rows]
    commands = [row["command_input"] for row in rows if row["command_input"]]
    timestamps = [row["timestamp"] for row in rows if row["timestamp"]]

    deploy = is_deploy(commands)
    proxy = any(event_id.startswith("cowrie.direct-tcpip") for event_id in event_ids)
    login_success = any(event_id == "cowrie.login.success" for event_id in event_ids)
    login_failed = any(event_id == "cowrie.login.failed" for event_id in event_ids)
    connect_disconnect_only = (
        bool(event_ids)
        and set(event_ids).issubset({"cowrie.session.connect", "cowrie.session.closed"})
    )
    failed_login_only = login_failed and not login_success and not commands and not proxy
    probe = connect_disconnect_only or failed_login_only

    if len(timestamps) >= 2:
        try:
            start = _parse_timestamp(min(timestamps))
            end = _parse_timestamp(max(timestamps))
            # Short-lived sessions are probes only if they did not exhibit a
            # higher-signal deploy or proxy behavior.
            probe = probe or (not commands and not proxy and (end - start).total_seconds() < 2)
        except ValueError:
            pass

    # Deploy and proxy behavior has priority over probe classification.
    # "mixed" is reserved for sessions showing both higher-signal behaviors.
    if deploy and proxy:
        return "mixed"
    if deploy:
        return "deploy"
    if proxy:
        return "proxy"
    if probe:
        return "probe"
    return "unknown"


def _parse_timestamp(value):
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def classify_sessions(connection):
    actor_map = actor_ids_by_session(connection)
    sessions = connection.execute(
        """
        SELECT session_id, event_id, command_input, timestamp
        FROM events
        WHERE session_id IS NOT NULL AND session_id != ''
        ORDER BY session_id, timestamp, id
        """
    ).fetchall()

    grouped = {}
    for row in sessions:
        grouped.setdefault(row["session_id"], []).append(row)

    classified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for session_id, rows in grouped.items():
        connection.execute(
            """
            INSERT INTO session_intent (session_id, actor_id, intent, classified_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                actor_id = excluded.actor_id,
                intent = excluded.intent,
                classified_at = excluded.classified_at
            """,
            (session_id, actor_map.get(session_id), classify_session(rows), classified_at),
        )

    return len(grouped)


def main():
    connection = database()
    try:
        actor_count = build_actors(connection)
        session_count = classify_sessions(connection)
        connection.commit()
    finally:
        connection.close()

    log("cluster complete: actors={} sessions_classified={}".format(actor_count, session_count))


if __name__ == "__main__":
    main()
