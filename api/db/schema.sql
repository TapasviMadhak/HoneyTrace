CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    actor_id TEXT,
    technique_id TEXT,
    severity TEXT NOT NULL,
    summary TEXT,
    raw_json TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    country_code TEXT,
    city TEXT,
    asn TEXT,
    session_id TEXT,
    username TEXT,
    password TEXT,
    event_type TEXT
);

CREATE TABLE IF NOT EXISTS payloads (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    session_id TEXT,
    url TEXT,
    sha256 TEXT,
    file_path TEXT,
    size_bytes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    session_id TEXT,
    command TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actor_clusters (
    actor_id TEXT PRIMARY KEY,
    hassh TEXT,
    username_corpus TEXT,
    label TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triage_cache (
    event_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    summary TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_state (
    filename TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_lat_lon ON events (latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_events_country_code ON events (country_code);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id);

CREATE INDEX IF NOT EXISTS idx_payloads_timestamp ON payloads (timestamp);
CREATE INDEX IF NOT EXISTS idx_payloads_source_ip ON payloads (source_ip);
CREATE INDEX IF NOT EXISTS idx_payloads_sha256 ON payloads (sha256);

CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands (timestamp);
CREATE INDEX IF NOT EXISTS idx_commands_session_id ON commands (session_id);
CREATE INDEX IF NOT EXISTS idx_commands_source_ip ON commands (source_ip);
