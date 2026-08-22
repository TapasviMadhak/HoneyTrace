package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	_ "modernc.org/sqlite"
)

type CowrieEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	SessionID   string    `json:"session_id,omitempty"`
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"password,omitempty"`
	EventType   string    `json:"event_type,omitempty"`
	TechniqueID string    `json:"technique_id,omitempty"`
	Severity    string    `json:"severity"`
	Summary     string    `json:"summary"`
	Latitude    float64   `json:"latitude,omitempty"`
	Longitude   float64   `json:"longitude,omitempty"`
	CountryCode string    `json:"country_code,omitempty"`
	City        string    `json:"city,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	Message     string    `json:"message,omitempty"`
	RawJSON     string    `json:"raw_json,omitempty"`
}

type GeoLocation struct {
	Latitude    float64
	Longitude   float64
	CountryCode string
	City        string
	ASN         string
}

type GeoResolver struct {
	mu     sync.RWMutex
	cache  map[string]GeoLocation
	reader *geoip2.Reader
}

func NewGeoResolver(customPath string) *GeoResolver {
	resolver := &GeoResolver{
		cache: make(map[string]GeoLocation),
	}

	candidates := []string{
		customPath,
		os.Getenv("GEOIP_CITY_PATH"),
		"/opt/honeytrace/data/geoip/GeoLite2-City.mmdb",
		"/var/lib/GeoIP/GeoLite2-City.mmdb",
		"/usr/share/GeoIP/GeoLite2-City.mmdb",
		"/var/lib/honeytrace/GeoLite2-City.mmdb",
		"./data/geoip/GeoLite2-City.mmdb",
		"./GeoLite2-City.mmdb",
	}

	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			db, err := geoip2.Open(p)
			if err == nil {
				resolver.reader = db
				log.Printf("[GeoIP] Loaded MaxMind City database: %s", p)
				break
			}
		}
	}

	if resolver.reader == nil {
		log.Println("[GeoIP] MaxMind MMDB not found; using fallback/local resolver.")
	}

	return resolver
}

func (g *GeoResolver) Close() {
	if g.reader != nil {
		_ = g.reader.Close()
	}
}

func (g *GeoResolver) Resolve(ipStr string) GeoLocation {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return GeoLocation{}
	}

	g.mu.RLock()
	if loc, ok := g.cache[ipStr]; ok {
		g.mu.RUnlock()
		return loc
	}
	g.mu.RUnlock()

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil || parsedIP.IsPrivate() || parsedIP.IsLoopback() {
		return GeoLocation{}
	}

	loc := GeoLocation{}

	if g.reader != nil {
		record, err := g.reader.City(parsedIP)
		if err == nil && record != nil {
			loc.Latitude = record.Location.Latitude
			loc.Longitude = record.Location.Longitude
			loc.CountryCode = record.Country.IsoCode
			loc.City = record.City.Names["en"]
		}
	}

	g.mu.Lock()
	g.cache[ipStr] = loc
	g.mu.Unlock()

	return loc
}

type Tailer struct {
	dbPath    string
	logPath   string
	db        *sql.DB
	geo       *GeoResolver
	abuse     *IngestAbuseClient
	stopChan  chan struct{}
	eventChan chan CowrieEvent
}

func NewTailer(dbPath, logPath, mmdbPath string) (*Tailer, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed creating database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed opening SQLite database: %w", err)
	}

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed initializing database schema: %w", err)
	}

	geo := NewGeoResolver(mmdbPath)
	abuse := NewIngestAbuseClient()

	return &Tailer{
		dbPath:    dbPath,
		logPath:   logPath,
		db:        db,
		geo:       geo,
		abuse:     abuse,
		stopChan:  make(chan struct{}),
		eventChan: make(chan CowrieEvent, 100),
	}, nil
}

func initSchema(db *sql.DB) error {
	schema := `
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
	`
	_, err := db.Exec(schema)
	return err
}

func (t *Tailer) getSavedOffset(filename string, inode uint64) int64 {
	var savedInode int64
	var offset int64
	err := t.db.QueryRow("SELECT inode, byte_offset FROM ingest_state WHERE filename = ?", filename).Scan(&savedInode, &offset)
	if err != nil || uint64(savedInode) != inode {
		return 0
	}
	return offset
}

func (t *Tailer) saveOffset(filename string, inode uint64, offset int64) {
	_, _ = t.db.Exec(`
		INSERT INTO ingest_state (filename, inode, byte_offset)
		VALUES (?, ?, ?)
		ON CONFLICT(filename) DO UPDATE SET
			inode = excluded.inode,
			byte_offset = excluded.byte_offset
	`, filename, inode, offset)
}

func getFileInode(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

func (t *Tailer) parseEvent(line []byte) (*CowrieEvent, map[string]any, error) {
	var rawMap map[string]any
	if err := json.Unmarshal(line, &rawMap); err != nil {
		return nil, nil, err
	}

	srcIP, _ := rawMap["src_ip"].(string)
	sessionID, _ := rawMap["session"].(string)
	eventID, _ := rawMap["eventid"].(string)
	username, _ := rawMap["username"].(string)
	password, _ := rawMap["password"].(string)
	inputCmd, _ := rawMap["input"].(string)

	var ts time.Time
	if tsStr, ok := rawMap["timestamp"].(string); ok {
		ts, _ = time.Parse(time.RFC3339Nano, tsStr)
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	geo := t.geo.Resolve(srcIP)

	techniqueID := "T1110"
	severity := "medium"
	summary := fmt.Sprintf("Authentication event (%s) from %s", eventID, srcIP)

	if eventID == "cowrie.login.success" {
		severity = "critical"
		summary = fmt.Sprintf("Decoy honeypot login success: user '%s' from %s", username, srcIP)
	} else if eventID == "cowrie.command.input" {
		techniqueID = "T1059"
		severity = "high"
		summary = fmt.Sprintf("Honeypot shell command: '%s' from %s", inputCmd, srcIP)
	} else if strings.HasPrefix(eventID, "cowrie.session.file_download") || strings.HasPrefix(eventID, "cowrie.session.file_upload") {
		techniqueID = "T1105"
		severity = "critical"
		summary = fmt.Sprintf("Malware payload capture from %s", srcIP)
	} else if strings.HasPrefix(eventID, "cowrie.direct-tcpip") {
		techniqueID = "T1090"
		severity = "critical"
		summary = fmt.Sprintf("Direct TCP-IP tunnel/proxy attempt from %s", srcIP)
	}

	hash := sha256.Sum256(line)
	id := "evt-" + hex.EncodeToString(hash[:8])

	return &CowrieEvent{
		ID:          id,
		Timestamp:   ts,
		SourceIP:    srcIP,
		SessionID:   sessionID,
		Username:    username,
		Password:    password,
		EventType:   eventID,
		TechniqueID: techniqueID,
		Severity:    severity,
		Summary:     summary,
		Latitude:    geo.Latitude,
		Longitude:   geo.Longitude,
		CountryCode: geo.CountryCode,
		City:        geo.City,
		ASN:         geo.ASN,
		RawJSON:     string(line),
	}, rawMap, nil
}

func (t *Tailer) insertAuxiliary(tx *sql.Tx, rawMap map[string]any, ev *CowrieEvent) {
	eventID, _ := rawMap["eventid"].(string)

	// Ingest commands
	if eventID == "cowrie.command.input" {
		cmdStr, _ := rawMap["input"].(string)
		if cmdStr != "" {
			cmdHash := sha256.Sum256([]byte(ev.ID + ":" + cmdStr))
			cmdID := "cmd-" + hex.EncodeToString(cmdHash[:8])
			_, _ = tx.Exec(`
				INSERT INTO commands (id, timestamp, source_ip, session_id, command)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(id) DO NOTHING;
			`, cmdID, ev.Timestamp.Format(time.RFC3339Nano), ev.SourceIP, ev.SessionID, cmdStr)
		}
	}

	// Ingest malware payloads
	if strings.HasPrefix(eventID, "cowrie.session.file_download") || strings.HasPrefix(eventID, "cowrie.session.file_upload") || strings.HasPrefix(eventID, "cowrie.direct-tcpip.data") {
		urlStr, _ := rawMap["url"].(string)
		shasum, _ := rawMap["shasum"].(string)
		if shasum == "" {
			shasum, _ = rawMap["sha256"].(string)
		}
		if shasum == "" {
			shasum, _ = rawMap["hash"].(string)
		}
		outFile, _ := rawMap["outfile"].(string)
		if outFile == "" {
			outFile, _ = rawMap["file_path"].(string)
		}
		var sizeBytes int64
		if s, ok := rawMap["size"].(float64); ok {
			sizeBytes = int64(s)
		} else if s, ok := rawMap["size_bytes"].(float64); ok {
			sizeBytes = int64(s)
		}

		if urlStr != "" || shasum != "" || outFile != "" {
			payHash := sha256.Sum256([]byte(ev.ID + ":" + shasum + ":" + urlStr))
			payID := "pay-" + hex.EncodeToString(payHash[:8])
			_, _ = tx.Exec(`
				INSERT INTO payloads (id, timestamp, source_ip, session_id, url, sha256, file_path, size_bytes)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(id) DO NOTHING;
			`, payID, ev.Timestamp.Format(time.RFC3339Nano), ev.SourceIP, ev.SessionID, urlStr, shasum, outFile, sizeBytes)
		}
	}
}

func (t *Tailer) insertEvent(tx *sql.Tx, ev *CowrieEvent) error {
	query := `
	INSERT INTO events (
		id, timestamp, source_ip, latitude, longitude, country_code, city, asn,
		session_id, username, password, event_type, severity, summary, raw_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO NOTHING;
	`
	_, err := tx.Exec(query,
		ev.ID,
		ev.Timestamp.Format(time.RFC3339Nano),
		ev.SourceIP,
		ev.Latitude,
		ev.Longitude,
		ev.CountryCode,
		ev.City,
		ev.ASN,
		ev.SessionID,
		ev.Username,
		ev.Password,
		ev.EventType,
		ev.Severity,
		ev.Summary,
		ev.RawJSON,
	)

	// Automated AbuseIPDB reporting for confirmed breaches or critical exploitation
	if err == nil && t.abuse != nil && (ev.EventType == "cowrie.login.success" || ev.Severity == "critical") {
		go func(ip, user string) {
			_ = t.abuse.ReportAttacker(ip, 25, user)
		}(ev.SourceIP, ev.Username)
	}

	return err
}

// IngestFile reads lines from startOffset to end of file, performing bulk insert.
func (t *Tailer) IngestFile(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	inode := getFileInode(info)
	offset := t.getSavedOffset(path, inode)

	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			offset = 0
			_, _ = file.Seek(0, io.SeekStart)
		}
	}

	reader := bufio.NewReader(file)
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	inserted := 0
	currentPos := offset

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			currentPos += int64(len(line))
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				ev, rawMap, pErr := t.parseEvent([]byte(trimmed))
				if pErr == nil {
					if err := t.insertEvent(tx, ev); err == nil {
						t.insertAuxiliary(tx, rawMap, ev)
						inserted++
						select {
						case t.eventChan <- *ev:
						default:
						}
					}
				}
			}
		}

		if err != nil {
			break
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	t.saveOffset(path, inode, currentPos)
	return inserted, nil
}

// Start begins backfill and continuous tailing.
func (t *Tailer) Start() {
	log.Printf("[Ingest] Starting Cowrie active tailer for: %s (Database: %s)", t.logPath, t.dbPath)

	if _, err := os.Stat(t.logPath); err == nil {
		count, err := t.IngestFile(t.logPath)
		if err != nil {
			log.Printf("[Ingest] Startup backfill warning: %v", err)
		} else {
			log.Printf("[Ingest] Startup backfill complete: %d events ingested into SQLite", count)
		}
	} else {
		log.Printf("[Ingest] Log file not found at startup: %s. Watching for creation...", t.logPath)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopChan:
			log.Println("[Ingest] Tailer stopped.")
			return
		case <-ticker.C:
			if _, err := os.Stat(t.logPath); err == nil {
				count, err := t.IngestFile(t.logPath)
				if err != nil {
					log.Printf("[Ingest] Error reading %s: %v", t.logPath, err)
				} else if count > 0 {
					log.Printf("[Ingest] Ingested %d new events into database", count)
				}
			}
		}
	}
}

func (t *Tailer) Stop() {
	close(t.stopChan)
	t.geo.Close()
	_ = t.db.Close()
}
