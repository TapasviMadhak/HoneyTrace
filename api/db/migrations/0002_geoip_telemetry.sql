-- 0002_geoip_telemetry.sql
-- Add GeoIP and attack telemetry columns to events

ALTER TABLE events ADD COLUMN latitude REAL;
ALTER TABLE events ADD COLUMN longitude REAL;
ALTER TABLE events ADD COLUMN country_code TEXT;
ALTER TABLE events ADD COLUMN city TEXT;
ALTER TABLE events ADD COLUMN asn TEXT;
ALTER TABLE events ADD COLUMN session_id TEXT;
ALTER TABLE events ADD COLUMN username TEXT;
ALTER TABLE events ADD COLUMN password TEXT;
ALTER TABLE events ADD COLUMN event_type TEXT;

CREATE INDEX IF NOT EXISTS idx_events_lat_lon ON events (latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_events_country_code ON events (country_code);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id);
