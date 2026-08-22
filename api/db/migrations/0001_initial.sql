-- Initial HoneyTrace schema

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    actor_id TEXT,
    technique_id TEXT,
    severity TEXT NOT NULL,
    summary TEXT,
    raw_json TEXT NOT NULL
);
