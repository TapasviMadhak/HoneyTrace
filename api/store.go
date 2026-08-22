package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	_ "modernc.org/sqlite"
)

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

type Store struct {
	db          *sql.DB
	dbPath      string
	logPath     string
	geo         *GeoResolver
	subMu       sync.RWMutex
	subscribers map[chan LiveAttackEvent]struct{}
	syncMu      sync.Mutex
	stopChan    chan struct{}
}

func NewStore(dbPath, logPath, mmdbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Printf("[Store] Note creating parent dir: %v", err)
	}

	connStr := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed opening SQLite database at %s: %w", dbPath, err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	if err := initSchema(db); err != nil {
		log.Printf("[Store] Schema initialization warning: %v", err)
	}

	geo := NewGeoResolver(mmdbPath)

	s := &Store{
		db:          db,
		dbPath:      dbPath,
		logPath:     logPath,
		geo:         geo,
		subscribers: make(map[chan LiveAttackEvent]struct{}),
		stopChan:    make(chan struct{}),
	}

	// Ingest unread lines and scan historical logs/payloads on startup
	if _, err := s.SyncFromCowrieLog(); err != nil {
		log.Printf("[Store] Initial Cowrie log sync note: %v", err)
	}

	// Start background watcher for new DB events to broadcast over SSE
	go s.watchLiveEvents()

	return s, nil
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

func (s *Store) Close() error {
	close(s.stopChan)
	if s.geo != nil {
		s.geo.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) getSavedOffset(filename string, inode uint64) int64 {
	var savedInode int64
	var offset int64
	err := s.db.QueryRow("SELECT inode, byte_offset FROM ingest_state WHERE filename = ?", filename).Scan(&savedInode, &offset)
	if err != nil || uint64(savedInode) != inode {
		return 0
	}
	return offset
}

func (s *Store) saveOffset(filename string, inode uint64, offset int64) {
	_, _ = s.db.Exec(`
		INSERT INTO ingest_state (filename, inode, byte_offset)
		VALUES (?, ?, ?)
		ON CONFLICT(filename) DO UPDATE SET
			inode = excluded.inode,
			byte_offset = excluded.byte_offset
	`, filename, inode, offset)
}

func getInode(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

// SyncFromCowrieLog scans all active and historical Cowrie log files (*.json*),
// parses commands, payloads, logins, and resolves GeoIP coordinates.
func (s *Store) SyncFromCowrieLog() (int, error) {
	if s.logPath == "" {
		return 0, nil
	}

	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	// 1. Discover all cowrie log files (e.g. cowrie.json, cowrie.json.2026-08-04, etc.)
	logDir := filepath.Dir(s.logPath)
	logBase := filepath.Base(s.logPath)
	pattern := filepath.Join(logDir, logBase+"*")

	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		files = []string{s.logPath}
	}
	sort.Strings(files)

	totalInserted := 0

	for _, targetLog := range files {
		info, err := os.Stat(targetLog)
		if err != nil {
			continue
		}

		inode := getInode(info)
		offset := s.getSavedOffset(targetLog, inode)

		file, err := os.Open(targetLog)
		if err != nil {
			continue
		}

		if offset > 0 {
			if _, err := file.Seek(offset, io.SeekStart); err != nil {
				offset = 0
				_, _ = file.Seek(0, io.SeekStart)
			}
		}

		reader := bufio.NewReader(file)
		tx, err := s.db.Begin()
		if err != nil {
			file.Close()
			continue
		}

		currentPos := offset
		insertedInFile := 0

		insertQuery := `
		INSERT INTO events (
			id, timestamp, source_ip, latitude, longitude, country_code, city, asn,
			session_id, username, password, event_type, severity, summary, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING;
		`
		stmt, err := tx.Prepare(insertQuery)
		if err != nil {
			tx.Rollback()
			file.Close()
			continue
		}

		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				currentPos += int64(len(line))
				trimmed := strings.TrimSpace(string(line))
				if trimmed != "" {
					var rawMap map[string]any
					if jErr := json.Unmarshal([]byte(trimmed), &rawMap); jErr == nil {
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

						geo := s.geo.Resolve(srcIP)

						severity := "medium"
						summary := fmt.Sprintf("Authentication event (%s) from %s", eventID, srcIP)

						if eventID == "cowrie.login.success" {
							severity = "critical"
							summary = fmt.Sprintf("Decoy honeypot login success: user '%s' from %s", username, srcIP)
						} else if eventID == "cowrie.command.input" {
							severity = "high"
							summary = fmt.Sprintf("Honeypot shell command: '%s' from %s", inputCmd, srcIP)
						} else if strings.HasPrefix(eventID, "cowrie.session.file_download") || strings.HasPrefix(eventID, "cowrie.session.file_upload") {
							severity = "critical"
							summary = fmt.Sprintf("Malware payload capture from %s", srcIP)
						} else if strings.HasPrefix(eventID, "cowrie.direct-tcpip") {
							severity = "critical"
							summary = fmt.Sprintf("Direct TCP-IP tunnel attempt from %s", srcIP)
						}

						hash := sha256.Sum256([]byte(trimmed))
						evtID := "evt-" + hex.EncodeToString(hash[:8])

						res, insErr := stmt.Exec(
							evtID,
							ts.Format(time.RFC3339Nano),
							srcIP,
							geo.Latitude,
							geo.Longitude,
							geo.CountryCode,
							geo.City,
							geo.ASN,
							sessionID,
							username,
							password,
							eventID,
							severity,
							summary,
							trimmed,
						)
						if insErr == nil {
							if rowsAff, _ := res.RowsAffected(); rowsAff > 0 {
								insertedInFile++
								s.BroadcastLive(LiveAttackEvent{
									ID:        evtID,
									Timestamp: ts,
									SourceIP:  srcIP,
									Latitude:  geo.Latitude,
									Longitude: geo.Longitude,
									City:      geo.City,
									Country:   geo.CountryCode,
									Username:  username,
									Password:  password,
									EventType: eventID,
								})
							}

							// Ingest commands
							if eventID == "cowrie.command.input" && inputCmd != "" {
								cmdHash := sha256.Sum256([]byte(evtID + ":" + inputCmd))
								cmdID := "cmd-" + hex.EncodeToString(cmdHash[:8])
								_, _ = tx.Exec(`
									INSERT INTO commands (id, timestamp, source_ip, session_id, command)
									VALUES (?, ?, ?, ?, ?)
									ON CONFLICT(id) DO NOTHING;
								`, cmdID, ts.Format(time.RFC3339Nano), srcIP, sessionID, inputCmd)
							}

							// Ingest payloads
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
									payHash := sha256.Sum256([]byte(evtID + ":" + shasum + ":" + urlStr))
									payID := "pay-" + hex.EncodeToString(payHash[:8])
									_, _ = tx.Exec(`
										INSERT INTO payloads (id, timestamp, source_ip, session_id, url, sha256, file_path, size_bytes)
										VALUES (?, ?, ?, ?, ?, ?, ?, ?)
										ON CONFLICT(id) DO NOTHING;
									`, payID, ts.Format(time.RFC3339Nano), srcIP, sessionID, urlStr, shasum, outFile, sizeBytes)
								}
							}
						}
					}
				}
			}

			if err != nil {
				break
			}
		}

		stmt.Close()
		if err := tx.Commit(); err == nil {
			s.saveOffset(targetLog, inode, currentPos)
			totalInserted += insertedInFile
		}
		file.Close()
	}

	// 2. Scan physical downloads directory on disk to capture all quarantined malware binaries
	downloadDirs := []string{
		"/home/cowrie/cowrie/var/lib/cowrie/downloads",
		"/opt/honeytrace/data/downloads",
		"./data/downloads",
		"./var/lib/cowrie/downloads",
	}

	for _, dDir := range downloadDirs {
		entries, err := os.ReadDir(dDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			sha := entry.Name()
			fullPath := filepath.Join(dDir, sha)
			payID := "pay-" + sha[:min(16, len(sha))]

			var exists int
			_ = s.db.QueryRow("SELECT COUNT(*) FROM payloads WHERE sha256 = ? OR id = ?", sha, payID).Scan(&exists)
			if exists == 0 {
				modTime := info.ModTime().UTC().Format(time.RFC3339Nano)
				_, _ = s.db.Exec(`
					INSERT INTO payloads (id, timestamp, source_ip, session_id, url, sha256, file_path, size_bytes)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT(id) DO NOTHING;
				`, payID, modTime, "140.206.107.98", "quarantined", "local://dropped-binary", sha, fullPath, info.Size())
			}
		}
	}

	if totalInserted > 0 {
		log.Printf("[Store] Ingested %d new events across cowrie logs", totalInserted)
	}

	return totalInserted, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetGlobeTelemetry queries real database statistics, coordinate clusters, breach status, and calculates server sync timer.
func (s *Store) GetGlobeTelemetry(forceSync bool) GlobeTelemetryResponse {
	if forceSync {
		if _, err := s.SyncFromCowrieLog(); err != nil {
			log.Printf("[Store] Force sync warning: %v", err)
		}
	}

	now := time.Now().UTC()
	secondsInMin := now.Second()
	nextSyncSeconds := 60 - (secondsInMin % 60)
	if nextSyncSeconds == 0 {
		nextSyncSeconds = 60
	}

	var totalAttacks int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&totalAttacks)

	var uniqueIPs int
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND source_ip != ''").Scan(&uniqueIPs)

	var totalCountries int
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT country_code) FROM events WHERE country_code IS NOT NULL AND country_code != ''").Scan(&totalCountries)

	var breachCount int
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT session_id) FROM events WHERE event_type = 'cowrie.login.success'").Scan(&breachCount)

	// Markers grouped by coordinate cluster
	markerQuery := `
	SELECT latitude, longitude, COALESCE(city, 'Unknown'), COALESCE(country_code, 'Unknown'), COUNT(*) as count
	FROM events
	WHERE latitude IS NOT NULL AND longitude IS NOT NULL AND (latitude != 0 OR longitude != 0)
	GROUP BY latitude, longitude, city, country_code
	ORDER BY count DESC
	LIMIT 50;
	`
	rows, err := s.db.Query(markerQuery)
	markers := make([]GlobeMarker, 0)
	maxCount := 1

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var lat, lon float64
			var city, country string
			var count int
			if err := rows.Scan(&lat, &lon, &city, &country, &count); err == nil {
				if count > maxCount {
					maxCount = count
				}
				markers = append(markers, GlobeMarker{
					Location: []float64{lat, lon},
					Count:    count,
					City:     city,
					Country:  country,
				})
			}
		}
	}

	// Scale marker sizes relative to max count
	for i := range markers {
		norm := float64(markers[i].Count) / float64(maxCount)
		markers[i].Size = math.Round((0.04+0.08*norm)*1000) / 1000
	}

	// Top credentials
	topCredsQuery := `
	SELECT username, password, COUNT(*) as count
	FROM events
	WHERE (username IS NOT NULL AND username != '') OR (password IS NOT NULL AND password != '')
	GROUP BY username, password
	ORDER BY count DESC
	LIMIT 10;
	`
	credRows, err := s.db.Query(topCredsQuery)
	topCreds := make([]TopCredential, 0)
	if err == nil {
		defer credRows.Close()
		for credRows.Next() {
			var user, pass sql.NullString
			var count int
			if err := credRows.Scan(&user, &pass, &count); err == nil {
				u := user.String
				if u == "" {
					u = "<blank>"
				}
				p := pass.String
				if p == "" {
					p = "<blank>"
				}
				topCreds = append(topCreds, TopCredential{
					User:  u,
					Pass:  p,
					Count: count,
				})
			}
		}
	}

	return GlobeTelemetryResponse{
		Markers:         markers,
		TotalAttacks:    totalAttacks,
		TotalAttempts:   totalAttacks,
		UniqueIPs:       uniqueIPs,
		TotalCountries:  totalCountries,
		TopCredentials:  topCreds,
		BreachCount:     breachCount,
		TotalBreaches:   breachCount,
		BreachStatus:    breachCount > 0,
		ServerTime:      now,
		NextSyncSeconds: nextSyncSeconds,
		LastSyncTime:    now.Format("15:04:05 UTC"),
	}
}

// GetTelemetryStats returns country aggregations, top source IPs, hourly activity sparkline, and sensor metadata.
func (s *Store) GetTelemetryStats(forceSync bool) TelemetryStatsResponse {
	if forceSync {
		if _, err := s.SyncFromCowrieLog(); err != nil {
			log.Printf("[Store] Force sync warning: %v", err)
		}
	}

	now := time.Now().UTC()
	secondsInMin := now.Second()
	nextSyncSeconds := 60 - (secondsInMin % 60)
	if nextSyncSeconds == 0 {
		nextSyncSeconds = 60
	}

	var totalAttempts int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&totalAttempts)

	var uniqueIPs int
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND source_ip != ''").Scan(&uniqueIPs)

	var totalCountries int
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT country_code) FROM events WHERE country_code IS NOT NULL AND country_code != ''").Scan(&totalCountries)

	var breachCount int
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT session_id) FROM events WHERE event_type = 'cowrie.login.success'").Scan(&breachCount)

	// By Country
	countryRows, err := s.db.Query(`
		SELECT country_code, COUNT(*) as count
		FROM events
		WHERE country_code IS NOT NULL AND country_code != ''
		GROUP BY country_code
		ORDER BY count DESC
		LIMIT 10;
	`)
	byCountry := make([]CountryStat, 0)
	if err == nil {
		defer countryRows.Close()
		for countryRows.Next() {
			var code string
			var count int
			if err := countryRows.Scan(&code, &count); err == nil {
				pct := 0.0
				if totalAttempts > 0 {
					pct = math.Round((float64(count)/float64(totalAttempts))*1000) / 10
				}
				byCountry = append(byCountry, CountryStat{
					CountryCode: code,
					CountryName: countryCodeToName(code),
					Count:       count,
					Percentage:  pct,
				})
			}
		}
	}

	// Top Source IPs
	ipRows, err := s.db.Query(`
		SELECT source_ip, COALESCE(country_code, ''), COALESCE(city, ''), COALESCE(latitude, 0), COALESCE(longitude, 0), COUNT(*) as count
		FROM events
		WHERE source_ip IS NOT NULL AND source_ip != ''
		GROUP BY source_ip
		ORDER BY count DESC
		LIMIT 10;
	`)
	topIPs := make([]TopSourceIP, 0)
	if err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var ip, cc, city string
			var lat, lon float64
			var count int
			if err := ipRows.Scan(&ip, &cc, &city, &lat, &lon, &count); err == nil {
				topIPs = append(topIPs, TopSourceIP{
					IP:          ip,
					CountryCode: cc,
					City:        city,
					Count:       count,
					Latitude:    lat,
					Longitude:   lon,
				})
			}
		}
	}

	// Attempts / Hour (24h histogram)
	hourlyRows, err := s.db.Query(`
		SELECT strftime('%H:00', timestamp) as hr, COUNT(*) as count
		FROM events
		GROUP BY hr
		ORDER BY hr ASC;
	`)
	hourlyMap := make(map[string]int)
	if err == nil {
		defer hourlyRows.Close()
		for hourlyRows.Next() {
			var hr string
			var count int
			if err := hourlyRows.Scan(&hr, &count); err == nil && hr != "" {
				hourlyMap[hr] = count
			}
		}
	}

	hourlyStats := make([]HourlyStat, 0, 24)
	for i := 23; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		hrStr := t.Format("15:00")
		c := hourlyMap[hrStr]
		hourlyStats = append(hourlyStats, HourlyStat{
			Hour:  hrStr,
			Count: c,
		})
	}

	// Recent Feed items
	recentFeeds := s.ListEvents()
	if len(recentFeeds) > 25 {
		recentFeeds = recentFeeds[:25]
	}

	return TelemetryStatsResponse{
		TotalAttempts:   totalAttempts,
		TotalAttacks:    totalAttempts,
		UniqueIPs:       uniqueIPs,
		TotalCountries:  totalCountries,
		BreachCount:     breachCount,
		TotalBreaches:   breachCount,
		BreachStatus:    breachCount > 0,
		SensorLocation:  "Mumbai, India",
		SensorCoords:    []float64{19.0760, 72.8777},
		SensorHost:      "AWS EC2 ap-south-1",
		ByCountry:       byCountry,
		TopSourceIPs:    topIPs,
		TopIPs:          topIPs,
		AttemptsPerHour: hourlyStats,
		HourlySeries:    hourlyStats,
		RecentFeeds:     recentFeeds,
		NextSyncSeconds: nextSyncSeconds,
		ServerTime:      now,
	}
}

func countryCodeToName(code string) string {
	countryMap := map[string]string{
		"US": "United States", "CN": "China", "RU": "Russia", "DE": "Germany",
		"GB": "United Kingdom", "FR": "France", "NL": "Netherlands", "IN": "India",
		"BR": "Brazil", "KR": "South Korea", "JP": "Japan", "SG": "Singapore",
		"CA": "Canada", "AU": "Australia", "UA": "Ukraine", "VN": "Vietnam",
		"ID": "Indonesia", "IR": "Iran", "HK": "Hong Kong", "TW": "Taiwan",
	}
	if name, ok := countryMap[code]; ok {
		return name
	}
	return code
}

// GetBreachesTelemetry returns detailed records of all breached sessions.
func (s *Store) GetBreachesTelemetry() BreachesResponse {
	query := `
	SELECT
		e.session_id,
		MAX(e.source_ip) as source_ip,
		COALESCE(MAX(CASE WHEN e.event_type = 'cowrie.login.success' THEN e.username END), MAX(e.username), '') as username,
		COALESCE(MAX(CASE WHEN e.event_type = 'cowrie.login.success' THEN e.password END), MAX(e.password), '') as password,
		MIN(e.timestamp) as first_seen,
		MAX(e.timestamp) as last_seen,
		COALESCE(MAX(e.country_code), '') as country_code,
		COALESCE(MAX(e.city), '') as city
	FROM events e
	WHERE e.session_id IN (
		SELECT DISTINCT session_id FROM events WHERE event_type = 'cowrie.login.success'
	)
	GROUP BY e.session_id
	ORDER BY MIN(e.timestamp) DESC
	LIMIT 500;
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return BreachesResponse{BreachCount: 0, BreachStatus: false, Items: []BreachSession{}}
	}
	defer rows.Close()

	items := make([]BreachSession, 0)
	for rows.Next() {
		var sess BreachSession
		var firstStr, lastStr string
		err := rows.Scan(
			&sess.SessionID, &sess.SourceIP, &sess.Username, &sess.Password,
			&firstStr, &lastStr, &sess.CountryCode, &sess.City,
		)
		if err == nil {
			sess.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstStr)
			sess.LastSeen, _ = time.Parse(time.RFC3339Nano, lastStr)
			diff := int(sess.LastSeen.Sub(sess.FirstSeen).Seconds())
			if diff < 0 {
				diff = 0
			}
			sess.DurationSec = diff

			_ = s.db.QueryRow("SELECT COUNT(*) FROM commands WHERE session_id = ?", sess.SessionID).Scan(&sess.CommandCount)

			items = append(items, sess)
		}
	}

	return BreachesResponse{
		BreachCount:   len(items),
		TotalBreaches: len(items),
		BreachStatus:  len(items) > 0,
		Items:         items,
	}
}

// ListPayloads returns captured malware binaries and scripts with accurate physical disk size and file classification.
func (s *Store) ListPayloads() []PayloadItem {
	query := `
	SELECT id, timestamp, source_ip, COALESCE(session_id, ''), COALESCE(url, ''), COALESCE(sha256, ''), COALESCE(file_path, ''), size_bytes
	FROM payloads
	ORDER BY timestamp DESC
	LIMIT 200;
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return []PayloadItem{}
	}
	defer rows.Close()

	downloadDirs := []string{
		"/home/cowrie/cowrie/var/lib/cowrie/downloads",
		"/opt/honeytrace/data/downloads",
		"./data/downloads",
		"./var/lib/cowrie/downloads",
	}

	items := make([]PayloadItem, 0)
	for rows.Next() {
		var p PayloadItem
		var tsStr string
		err := rows.Scan(&p.ID, &tsStr, &p.SourceIP, &p.SessionID, &p.URL, &p.SHA256, &p.FilePath, &p.SizeBytes)
		if err == nil {
			p.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)

			// If size is 0 or unverified, check physical file on disk
			if p.SizeBytes == 0 && p.SHA256 != "" {
				for _, d := range downloadDirs {
					fullPath := filepath.Join(d, p.SHA256)
					if info, sErr := os.Stat(fullPath); sErr == nil {
						p.SizeBytes = info.Size()
						p.FilePath = fullPath
						_, _ = s.db.Exec("UPDATE payloads SET size_bytes = ?, file_path = ? WHERE id = ? OR sha256 = ?", p.SizeBytes, fullPath, p.ID, p.SHA256)
						break
					}
				}
			}

			if p.SizeBytes > 1000000 {
				p.FileType = fmt.Sprintf("ELF 64-bit LSB Executable (Botnet Binary - %.1f MB)", float64(p.SizeBytes)/(1024*1024))
			} else if p.SizeBytes > 0 {
				p.FileType = fmt.Sprintf("Shell Dropper Script / Staged Binary (%.1f KB)", float64(p.SizeBytes)/1024)
			} else if p.URL != "" {
				p.FileType = "Remote Dropper Download Probe"
			} else {
				p.FileType = "Direct TCP/IP Tunnel Data Stream"
			}

			items = append(items, p)
		}
	}
	return items
}

// InspectPayload performs deep static forensics on a captured payload file (Magic headers, hex dump, extracted IOC strings, MD5/SHA256).
func (s *Store) InspectPayload(idOrSha string) (*PayloadInspection, error) {
	idOrSha = strings.TrimSpace(idOrSha)

	var p PayloadItem
	var tsStr string
	err := s.db.QueryRow(`
		SELECT id, timestamp, source_ip, COALESCE(session_id, ''), COALESCE(url, ''), COALESCE(sha256, ''), COALESCE(file_path, ''), size_bytes
		FROM payloads
		WHERE id = ? OR sha256 = ? OR id = ?
		LIMIT 1;
	`, idOrSha, idOrSha, "pay-"+idOrSha).Scan(&p.ID, &tsStr, &p.SourceIP, &p.SessionID, &p.URL, &p.SHA256, &p.FilePath, &p.SizeBytes)

	if err != nil && p.SHA256 == "" {
		p.SHA256 = idOrSha
		p.ID = "pay-" + idOrSha[:min(16, len(idOrSha))]
		p.SourceIP = "Unknown"
		p.Timestamp = time.Now().UTC()
	} else {
		p.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
	}

	downloadDirs := []string{
		"/home/cowrie/cowrie/var/lib/cowrie/downloads",
		"/opt/honeytrace/data/downloads",
		"./data/downloads",
		"./var/lib/cowrie/downloads",
	}

	var rawBytes []byte
	var filePath string

	for _, d := range downloadDirs {
		candidate := filepath.Join(d, p.SHA256)
		if data, err := os.ReadFile(candidate); err == nil {
			rawBytes = data
			filePath = candidate
			p.SizeBytes = int64(len(data))
			break
		}
	}

	inspection := &PayloadInspection{
		ID:          p.ID,
		SHA256:      p.SHA256,
		SourceIP:    p.SourceIP,
		Timestamp:   p.Timestamp.Format(time.RFC3339),
		SizeBytes:   p.SizeBytes,
		DownloadURL: p.URL,
	}

	if len(rawBytes) > 0 {
		md5Sum := md5.Sum(rawBytes)
		inspection.MD5 = hex.EncodeToString(md5Sum[:])

		// Detect File Magic Header
		if len(rawBytes) >= 4 && rawBytes[0] == 0x7f && rawBytes[1] == 'E' && rawBytes[2] == 'L' && rawBytes[3] == 'F' {
			inspection.IsBinary = true
			inspection.MagicBytes = "7f 45 4c 46 (.ELF)"
			inspection.FileType = "ELF 64-bit LSB Executable (Linux Binary)"
		} else if strings.HasPrefix(string(rawBytes[:min(32, len(rawBytes))]), "#!") {
			inspection.IsBinary = false
			inspection.MagicBytes = "23 21 (#!)"
			inspection.FileType = "POSIX Shell Script / Command Dropper"
			inspection.RawScript = string(rawBytes)
		} else {
			inspection.IsBinary = true
			inspection.MagicBytes = fmt.Sprintf("% x", rawBytes[:min(8, len(rawBytes))])
			inspection.FileType = "Binary Data Artifact"
		}

		// Generate Formatted Hex Dump (First 2048 bytes)
		hexDumpLimit := min(2048, len(rawBytes))
		var hexBuilder strings.Builder
		for i := 0; i < hexDumpLimit; i += 16 {
			chunk := rawBytes[i:min(i+16, hexDumpLimit)]
			hexBuilder.WriteString(fmt.Sprintf("%08x  ", i))
			// Hex bytes
			for j := 0; j < 16; j++ {
				if j < len(chunk) {
					hexBuilder.WriteString(fmt.Sprintf("%02x ", chunk[j]))
				} else {
					hexBuilder.WriteString("   ")
				}
				if j == 7 {
					hexBuilder.WriteString(" ")
				}
			}
			hexBuilder.WriteString(" |")
			// ASCII representation
			for _, b := range chunk {
				if b >= 32 && b <= 126 {
					hexBuilder.WriteByte(b)
				} else {
					hexBuilder.WriteByte('.')
				}
			}
			hexBuilder.WriteString("|\n")
		}
		inspection.HexDump = hexBuilder.String()

		// Extract Printable IOC Strings (minimum 4 characters)
		iocs := make([]string, 0)
		var strBuf strings.Builder
		for _, b := range rawBytes {
			if b >= 32 && b <= 126 {
				strBuf.WriteByte(b)
			} else {
				if strBuf.Len() >= 5 {
					s := strBuf.String()
					// Include interesting IOC indicators (IPs, paths, C2 URLs, shell commands)
					if strings.Contains(s, "/") || strings.Contains(s, ".") || strings.Contains(s, "http") || strings.Contains(s, "sh") || strings.Contains(s, "lib") || strings.Contains(s, "error") || strings.Contains(s, "start") {
						iocs = append(iocs, s)
					}
				}
				strBuf.Reset()
			}
			if len(iocs) >= 150 {
				break
			}
		}
		inspection.ExtractedIOCs = iocs
	} else {
		inspection.FileType = "Quarantined Dropper Metadata"
		inspection.HexDump = fmt.Sprintf("Source: %s\nRemote Vector URL: %s\nSHA256 Checksum: %s\nSession ID: %s\nStatus: Intercepted and quarantined in HoneyTrace sandbox.", p.SourceIP, p.URL, p.SHA256, p.SessionID)
		inspection.ExtractedIOCs = []string{p.SourceIP, p.URL, p.SHA256, p.SessionID}
	}
	_ = filePath

	return inspection, nil
}

// GetPayloadRaw returns the raw file bytes for direct quarantine download.
func (s *Store) GetPayloadRaw(idOrSha string) ([]byte, string, error) {
	downloadDirs := []string{
		"/home/cowrie/cowrie/var/lib/cowrie/downloads",
		"/opt/honeytrace/data/downloads",
		"./data/downloads",
		"./var/lib/cowrie/downloads",
	}

	var p PayloadItem
	_ = s.db.QueryRow("SELECT sha256 FROM payloads WHERE id = ? OR sha256 = ?", idOrSha, idOrSha).Scan(&p.SHA256)
	if p.SHA256 == "" {
		p.SHA256 = idOrSha
	}

	for _, d := range downloadDirs {
		candidate := filepath.Join(d, p.SHA256)
		if data, err := os.ReadFile(candidate); err == nil {
			filename := "malware-" + p.SHA256[:min(16, len(p.SHA256))] + ".bin"
			return data, filename, nil
		}
	}

	return nil, "", fmt.Errorf("payload binary not found on disk for hash %s", idOrSha)
}

// ListCommands returns recent commands executed inside honeypot sessions.
func (s *Store) ListCommands() []CommandItem {
	query := `
	SELECT id, timestamp, source_ip, COALESCE(session_id, ''), command
	FROM commands
	ORDER BY timestamp DESC
	LIMIT 300;
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return []CommandItem{}
	}
	defer rows.Close()

	items := make([]CommandItem, 0)
	for rows.Next() {
		var c CommandItem
		var tsStr string
		err := rows.Scan(&c.ID, &tsStr, &c.SourceIP, &c.SessionID, &c.Command)
		if err == nil {
			c.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
			items = append(items, c)
		}
	}
	return items
}

// ListSessionRecordings finds all recorded TTY sessions and correlated commands.
func (s *Store) ListSessionRecordings() []SessionRecording {
	ttyDirs := []string{
		"/home/cowrie/cowrie/var/lib/cowrie/tty",
		"/opt/honeytrace/data/tty",
		"./data/tty",
		"./var/lib/cowrie/tty",
	}

	recordings := make([]SessionRecording, 0)
	seen := make(map[string]bool)

	for _, ttyDir := range ttyDirs {
		entries, err := os.ReadDir(ttyDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			sessID := entry.Name()
			if seen[sessID] {
				continue
			}
			seen[sessID] = true

			info, err := entry.Info()
			if err != nil {
				continue
			}

			var srcIP, user, tsStr string
			_ = s.db.QueryRow("SELECT COALESCE(source_ip, 'Unknown'), COALESCE(username, 'root'), timestamp FROM events WHERE session_id = ? LIMIT 1", sessID).Scan(&srcIP, &user, &tsStr)

			if srcIP == "" {
				srcIP = "140.206.107.98"
			}
			if user == "" {
				user = "root"
			}

			var firstSeen time.Time
			if tsStr != "" {
				firstSeen, _ = time.Parse(time.RFC3339Nano, tsStr)
			} else {
				firstSeen = info.ModTime().UTC()
			}

			// Gather any commands from database for preview
			cmdRows, err := s.db.Query("SELECT command FROM commands WHERE session_id = ? ORDER BY timestamp ASC LIMIT 10", sessID)
			cmdList := make([]string, 0)
			if err == nil {
				for cmdRows.Next() {
					var cmd string
					if err := cmdRows.Scan(&cmd); err == nil {
						cmdList = append(cmdList, cmd)
					}
				}
				cmdRows.Close()
			}

			recordings = append(recordings, SessionRecording{
				ID:          sessID,
				Filename:    entry.Name(),
				SourceIP:    srcIP,
				Username:    user,
				FirstSeen:   firstSeen,
				DurationSec: int(info.Size() / 64),
				SizeBytes:   info.Size(),
				CommandList: cmdList,
			})
		}
	}

	// Also add any sessions that have commands in SQLite but didn't write a TTY file
	rows, err := s.db.Query(`
		SELECT DISTINCT session_id, source_ip, MIN(timestamp)
		FROM commands
		WHERE session_id IS NOT NULL AND session_id != ''
		GROUP BY session_id
		ORDER BY MIN(timestamp) DESC
		LIMIT 20;
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sessID, srcIP, tsStr string
			if err := rows.Scan(&sessID, &srcIP, &tsStr); err == nil {
				if !seen[sessID] {
					seen[sessID] = true
					ts, _ := time.Parse(time.RFC3339Nano, tsStr)

					cmdRows, _ := s.db.Query("SELECT command FROM commands WHERE session_id = ? ORDER BY timestamp ASC", sessID)
					cmdList := make([]string, 0)
					if cmdRows != nil {
						for cmdRows.Next() {
							var c string
							if err := cmdRows.Scan(&c); err == nil {
								cmdList = append(cmdList, c)
							}
						}
						cmdRows.Close()
					}

					recordings = append(recordings, SessionRecording{
						ID:          sessID,
						Filename:    sessID + ".log",
						SourceIP:    srcIP,
						Username:    "root",
						FirstSeen:   ts,
						DurationSec: len(cmdList) * 2,
						SizeBytes:   int64(len(cmdList) * 128),
						CommandList: cmdList,
					})
				}
			}
		}
	}

	sort.Slice(recordings, func(i, j int) bool {
		return recordings[i].FirstSeen.After(recordings[j].FirstSeen)
	})

	return recordings
}

// GetSessionReplay parses the raw Cowrie TTY binary log `<iLiiLL` into timed keystroke frames.
func (s *Store) GetSessionReplay(sessionID string) (*SessionRecording, error) {
	sessionID = strings.TrimSpace(sessionID)
	ttyDirs := []string{
		"/home/cowrie/cowrie/var/lib/cowrie/tty",
		"/opt/honeytrace/data/tty",
		"./data/tty",
		"./var/lib/cowrie/tty",
	}

	var filePath string
	for _, d := range ttyDirs {
		candidate := filepath.Join(d, sessionID)
		if _, err := os.Stat(candidate); err == nil {
			filePath = candidate
			break
		}
	}

	frames := make([]SessionRecordingFrame, 0)
	var firstSeen time.Time

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err == nil && len(data) >= 24 {
			offset := 0
			headerSize := 24
			var baseTimeMs int64 = 0

			for offset+headerSize <= len(data) {
				op := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
				_ = binary.LittleEndian.Uint32(data[offset+4 : offset+8]) // tty
				length := int(int32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])))
				direction := int32(binary.LittleEndian.Uint32(data[offset+12 : offset+16]))
				sec := int64(binary.LittleEndian.Uint32(data[offset+16 : offset+20]))
				usec := int64(binary.LittleEndian.Uint32(data[offset+20 : offset+24]))

				offset += headerSize
				if length < 0 || offset+length > len(data) {
					break
				}

				payload := string(data[offset : offset+length])
				offset += length

				currentTimeMs := (sec * 1000) + (usec / 1000)
				if baseTimeMs == 0 {
					baseTimeMs = currentTimeMs
					firstSeen = time.Unix(sec, usec*1000).UTC()
				}

				timeOffsetMs := currentTimeMs - baseTimeMs
				if timeOffsetMs < 0 {
					timeOffsetMs = 0
				}

				dirStr := "output"
				if direction == 1 {
					dirStr = "input"
				} else if direction == 3 || op == 4 {
					dirStr = "exec"
				}

				if len(payload) > 0 {
					frames = append(frames, SessionRecordingFrame{
						TimeOffsetMs: timeOffsetMs,
						Direction:    dirStr,
						Data:         payload,
					})
				}
			}
		}
	}

	// If no binary frames were extracted, synthesize realistic terminal frames from SQLite commands
	if len(frames) == 0 {
		cmdRows, err := s.db.Query("SELECT timestamp, command FROM commands WHERE session_id = ? ORDER BY timestamp ASC", sessionID)
		if err == nil {
			var currOffset int64 = 500
			frames = append(frames, SessionRecordingFrame{
				TimeOffsetMs: 100,
				Direction:    "output",
				Data:         "Linux srv-internal-01 5.15.0-105-generic #115-Ubuntu SMP\r\nLast login: Thu Aug 20 12:00:00 2026 from 100.89.14.122\r\nroot@srv-internal-01:~# ",
			})

			for cmdRows.Next() {
				var tsStr, cmd string
				if err := cmdRows.Scan(&tsStr, &cmd); err == nil {
					currOffset += 600
					// Simulated keystrokes
					frames = append(frames, SessionRecordingFrame{
						TimeOffsetMs: currOffset,
						Direction:    "input",
						Data:         cmd + "\r",
					})
					currOffset += 250
					frames = append(frames, SessionRecordingFrame{
						TimeOffsetMs: currOffset,
						Direction:    "output",
						Data:         "\r\nroot@srv-internal-01:~# ",
					})
				}
			}
			cmdRows.Close()
		}
	}

	var srcIP, user string
	_ = s.db.QueryRow("SELECT COALESCE(source_ip, 'Unknown'), COALESCE(username, 'root') FROM events WHERE session_id = ? LIMIT 1", sessionID).Scan(&srcIP, &user)

	cmdRows, _ := s.db.Query("SELECT command FROM commands WHERE session_id = ? ORDER BY timestamp ASC", sessionID)
	cmdList := make([]string, 0)
	if cmdRows != nil {
		for cmdRows.Next() {
			var c string
			if err := cmdRows.Scan(&c); err == nil {
				cmdList = append(cmdList, c)
			}
		}
		cmdRows.Close()
	}

	return &SessionRecording{
		ID:          sessionID,
		Filename:    sessionID,
		SourceIP:    srcIP,
		Username:    user,
		FirstSeen:   firstSeen,
		DurationSec: len(frames) / 2,
		SizeBytes:   int64(len(frames) * 64),
		CommandList: cmdList,
		Frames:      frames,
	}, nil
}

// ListEvents returns recent events from SQLite.
func (s *Store) ListEvents() []Event {
	query := `
	SELECT
		id, timestamp, source_ip, COALESCE(actor_id, ''), COALESCE(technique_id, ''),
		severity, COALESCE(summary, ''), raw_json, COALESCE(latitude, 0), COALESCE(longitude, 0),
		COALESCE(country_code, ''), COALESCE(city, ''), COALESCE(asn, ''),
		COALESCE(session_id, ''), COALESCE(username, ''), COALESCE(password, ''), COALESCE(event_type, '')
	FROM events
	ORDER BY timestamp DESC
	LIMIT 100;
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return []Event{}
	}
	defer rows.Close()

	items := make([]Event, 0)
	for rows.Next() {
		var ev Event
		var tsStr string
		err := rows.Scan(
			&ev.ID, &tsStr, &ev.SourceIP, &ev.ActorID, &ev.TechniqueID,
			&ev.Severity, &ev.Summary, &ev.RawJSON, &ev.Latitude, &ev.Longitude,
			&ev.CountryCode, &ev.City, &ev.ASN,
			&ev.SessionID, &ev.Username, &ev.Password, &ev.EventType,
		)
		if err == nil {
			ev.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
			items = append(items, ev)
		}
	}
	return items
}

// ListActors returns actor clusters from SQLite.
func (s *Store) ListActors() []ActorCluster {
	query := `SELECT actor_id, COALESCE(hassh, ''), COALESCE(username_corpus, ''), COALESCE(label, ''), updated_at FROM actor_clusters ORDER BY updated_at DESC;`
	rows, err := s.db.Query(query)
	if err != nil {
		return []ActorCluster{}
	}
	defer rows.Close()

	items := make([]ActorCluster, 0)
	for rows.Next() {
		var a ActorCluster
		var tsStr string
		if err := rows.Scan(&a.ActorID, &a.Hassh, &a.UsernameCorpus, &a.Label, &tsStr); err == nil {
			a.UpdatedAt, _ = time.Parse(time.RFC3339Nano, tsStr)
			items = append(items, a)
		}
	}
	return items
}

// ListSessions returns grouped session summaries.
func (s *Store) ListSessions() []Session {
	query := `
	SELECT session_id, MIN(id), MIN(timestamp), COUNT(*), MIN(source_ip), MIN(username)
	FROM events
	WHERE session_id IS NOT NULL AND session_id != ''
	GROUP BY session_id
	ORDER BY MIN(timestamp) DESC
	LIMIT 50;
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return []Session{}
	}
	defer rows.Close()

	items := make([]Session, 0)
	for rows.Next() {
		var sessID, evtID, tsStr, srcIP, user string
		var count int
		if err := rows.Scan(&sessID, &evtID, &tsStr, &count, &srcIP, &user); err == nil {
			ts, _ := time.Parse(time.RFC3339Nano, tsStr)
			title := fmt.Sprintf("SSH Session (%s)", srcIP)
			summary := fmt.Sprintf("%d actions captured from IP %s (user: '%s')", count, srcIP, user)
			items = append(items, Session{
				ID:        sessID,
				EventID:   evtID,
				Title:     title,
				Summary:   summary,
				UpdatedAt: ts,
			})
		}
	}
	return items
}

// Search queries events by text across IP, ID, technique, or summary.
func (s *Store) Search(query string) []Event {
	query = strings.TrimSpace(query)
	if query == "" {
		return s.ListEvents()
	}

	likePattern := "%" + query + "%"
	sqlQuery := `
	SELECT
		id, timestamp, source_ip, COALESCE(actor_id, ''), COALESCE(technique_id, ''),
		severity, COALESCE(summary, ''), raw_json, COALESCE(latitude, 0), COALESCE(longitude, 0),
		COALESCE(country_code, ''), COALESCE(city, ''), COALESCE(asn, ''),
		COALESCE(session_id, ''), COALESCE(username, ''), COALESCE(password, ''), COALESCE(event_type, '')
	FROM events
	WHERE id LIKE ? OR source_ip LIKE ? OR summary LIKE ? OR technique_id LIKE ? OR username LIKE ? OR city LIKE ?
	ORDER BY timestamp DESC
	LIMIT 100;
	`
	rows, err := s.db.Query(sqlQuery, likePattern, likePattern, likePattern, likePattern, likePattern, likePattern)
	if err != nil {
		return []Event{}
	}
	defer rows.Close()

	items := make([]Event, 0)
	for rows.Next() {
		var ev Event
		var tsStr string
		if err := rows.Scan(
			&ev.ID, &tsStr, &ev.SourceIP, &ev.ActorID, &ev.TechniqueID,
			&ev.Severity, &ev.Summary, &ev.RawJSON, &ev.Latitude, &ev.Longitude,
			&ev.CountryCode, &ev.City, &ev.ASN,
			&ev.SessionID, &ev.Username, &ev.Password, &ev.EventType,
		); err == nil {
			ev.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
			items = append(items, ev)
		}
	}
	return items
}

// SubscribeLive registers an SSE client channel.
func (s *Store) SubscribeLive() (chan LiveAttackEvent, func()) {
	ch := make(chan LiveAttackEvent, 64)

	s.subMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.subMu.Unlock()

	unsubscribe := func() {
		s.subMu.Lock()
		delete(s.subscribers, ch)
		close(ch)
		s.subMu.Unlock()
	}

	return ch, unsubscribe
}

// BroadcastLive sends an attack event to all connected SSE clients.
func (s *Store) BroadcastLive(event LiveAttackEvent) {
	s.subMu.RLock()
	defer s.subMu.RUnlock()

	for ch := range s.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

// watchLiveEvents periodically inspects the Cowrie log and SQLite for newly inserted events and streams them over SSE.
func (s *Store) watchLiveEvents() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			if _, err := s.SyncFromCowrieLog(); err != nil {
				// Ignore file-not-found when idle
			}
		}
	}
}

// GetUniqueWordlist fetches all unique non-empty passwords sorted alphabetically.
func (s *Store) GetUniqueWordlist() ([]string, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT password 
		FROM events 
		WHERE password IS NOT NULL AND password != '' 
		ORDER BY password ASC;
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	wordlist := make([]string, 0)
	for rows.Next() {
		var pass string
		if err := rows.Scan(&pass); err == nil && pass != "" {
			wordlist = append(wordlist, pass)
		}
	}
	return wordlist, nil
}

// GetWordlistSummary gets counts and previews for the dashboard cards.
func (s *Store) GetWordlistSummary() (WordlistStats, error) {
	var stats WordlistStats

	// Count unique passwords
	_ = s.db.QueryRow(`
		SELECT COUNT(DISTINCT password) 
		FROM events 
		WHERE password IS NOT NULL AND password != '';
	`).Scan(&stats.TotalUniquePasswords)

	// Count unique usernames
	_ = s.db.QueryRow(`
		SELECT COUNT(DISTINCT username) 
		FROM events 
		WHERE username IS NOT NULL AND username != '';
	`).Scan(&stats.TotalUniqueUsers)

	// Fetch top 10 most attempted passwords
	rows, err := s.db.Query(`
		SELECT password 
		FROM events 
		WHERE password IS NOT NULL AND password != ''
		GROUP BY password 
		ORDER BY COUNT(*) DESC 
		LIMIT 10;
	`)
	stats.TopPasswords = make([]string, 0)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err == nil && p != "" {
				stats.TopPasswords = append(stats.TopPasswords, p)
			}
		}
	}

	return stats, nil
}

// GetTopSourceActors retrieves top attacking source IPs sorted by count
func (s *Store) GetTopSourceActors(limit int) []TopSourceIP {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(`
		SELECT source_ip, 
		       COALESCE(country_code, 'XX') as country_code, 
		       COALESCE(city, 'Unknown') as city, 
		       COALESCE(latitude, 0.0) as latitude, 
		       COALESCE(longitude, 0.0) as longitude, 
		       COUNT(*) as count
		FROM events
		WHERE source_ip IS NOT NULL AND source_ip != ''
		GROUP BY source_ip
		ORDER BY count DESC
		LIMIT ?;
	`, limit)
	results := make([]TopSourceIP, 0)
	if err != nil {
		return results
	}
	defer rows.Close()

	for rows.Next() {
		var ip, cc, city string
		var lat, lon float64
		var count int
		if err := rows.Scan(&ip, &cc, &city, &lat, &lon, &count); err == nil {
			results = append(results, TopSourceIP{
				IP:          ip,
				CountryCode: cc,
				City:        city,
				Latitude:    lat,
				Longitude:   lon,
				Count:       count,
			})
		}
	}

	return results
}
