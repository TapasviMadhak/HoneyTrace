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

CREATE INDEX IF NOT EXISTS idx_payloads_timestamp ON payloads (timestamp);
CREATE INDEX IF NOT EXISTS idx_payloads_source_ip ON payloads (source_ip);
CREATE INDEX IF NOT EXISTS idx_payloads_sha256 ON payloads (sha256);

CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands (timestamp);
CREATE INDEX IF NOT EXISTS idx_commands_session_id ON commands (session_id);
CREATE INDEX IF NOT EXISTS idx_commands_source_ip ON commands (source_ip);
