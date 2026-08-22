package main

import "time"

type Event struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	ActorID     string    `json:"actor_id,omitempty"`
	TechniqueID string    `json:"technique_id,omitempty"`
	Severity    string    `json:"severity"`
	Summary     string    `json:"summary,omitempty"`
	RawJSON     string    `json:"raw_json,omitempty"`
	Latitude    float64   `json:"latitude,omitempty"`
	Longitude   float64   `json:"longitude,omitempty"`
	CountryCode string    `json:"country_code,omitempty"`
	City        string    `json:"city,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"password,omitempty"`
	EventType   string    `json:"event_type,omitempty"`
}

type PayloadItem struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	SessionID string    `json:"session_id,omitempty"`
	URL       string    `json:"url,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	FilePath  string    `json:"file_path,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	FileType  string    `json:"file_type,omitempty"`
}

type PayloadInspection struct {
	ID            string   `json:"id"`
	SHA256        string   `json:"sha256"`
	MD5           string   `json:"md5"`
	SourceIP      string   `json:"source_ip"`
	Timestamp     string   `json:"timestamp"`
	SizeBytes     int64    `json:"size_bytes"`
	FileType      string   `json:"file_type"`
	MagicBytes    string   `json:"magic_bytes"`
	HexDump       string   `json:"hex_dump"`
	IsBinary      bool     `json:"is_binary"`
	RawScript     string   `json:"raw_script,omitempty"`
	ExtractedIOCs []string `json:"extracted_iocs"`
	DownloadURL   string   `json:"download_url"`
}

type CommandItem struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	SessionID string    `json:"session_id,omitempty"`
	Command   string    `json:"command"`
}

type SessionRecordingFrame struct {
	TimeOffsetMs int64  `json:"time_offset_ms"`
	Direction    string `json:"direction"` // "input", "output", "exec"
	Data         string `json:"data"`
}

type SessionRecording struct {
	ID          string                  `json:"id"`
	Filename    string                  `json:"filename"`
	SourceIP    string                  `json:"source_ip"`
	Username    string                  `json:"username"`
	FirstSeen   time.Time               `json:"first_seen"`
	DurationSec int                     `json:"duration_sec"`
	SizeBytes   int64                   `json:"size_bytes"`
	CommandList []string                `json:"command_list"`
	Frames      []SessionRecordingFrame `json:"frames,omitempty"`
}

type BreachSession struct {
	SessionID    string    `json:"session_id"`
	SourceIP     string    `json:"source_ip"`
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	DurationSec  int       `json:"duration_sec"`
	CommandCount int       `json:"command_count"`
	CountryCode  string    `json:"country_code,omitempty"`
	City         string    `json:"city,omitempty"`
}

type BreachesResponse struct {
	BreachCount   int             `json:"breach_count"`
	TotalBreaches int             `json:"total_breaches"`
	BreachStatus  bool            `json:"breach_status"`
	Items         []BreachSession `json:"items"`
}

type WordlistStats struct {
	TotalUniquePasswords int      `json:"total_unique_passwords"`
	TotalUniqueUsers     int      `json:"total_unique_users"`
	TopPasswords         []string `json:"top_passwords"`
}

type ActorCluster struct {
	ActorID        string    `json:"actor_id"`
	Hassh          string    `json:"hassh,omitempty"`
	UsernameCorpus string    `json:"username_corpus,omitempty"`
	Label          string    `json:"label,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Session struct {
	ID        string    `json:"id"`
	EventID   string    `json:"event_id"`
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	UpdatedAt time.Time `json:"updated_at"`
}

type GlobeMarker struct {
	Location []float64 `json:"location"` // [lat, lon]
	Size     float64   `json:"size"`
	Count    int       `json:"count"`
	City     string    `json:"city"`
	Country  string    `json:"country"`
}

type TopCredential struct {
	User  string `json:"user"`
	Pass  string `json:"pass"`
	Count int    `json:"count"`
}

type GlobeTelemetryResponse struct {
	Markers         []GlobeMarker   `json:"markers"`
	TotalAttacks    int             `json:"total_attacks"`
	TotalAttempts   int             `json:"total_attempts"`
	UniqueIPs       int             `json:"unique_ips"`
	TotalCountries  int             `json:"total_countries"`
	TopCredentials  []TopCredential `json:"top_credentials"`
	BreachCount     int             `json:"breach_count"`
	TotalBreaches   int             `json:"total_breaches"`
	BreachStatus    bool            `json:"breach_status"`
	ServerTime      time.Time       `json:"server_time"`
	NextSyncSeconds int             `json:"next_sync_seconds"`
	LastSyncTime    string          `json:"last_sync_time"`
}

type CountryStat struct {
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Count       int     `json:"count"`
	Percentage  float64 `json:"percentage"`
}

type TopSourceIP struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Count       int     `json:"count"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

type HourlyStat struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

type TelemetryStatsResponse struct {
	TotalAttempts   int           `json:"total_attempts"`
	TotalAttacks    int           `json:"total_attacks"`
	UniqueIPs       int           `json:"unique_ips"`
	TotalCountries  int           `json:"total_countries"`
	BreachCount     int           `json:"breach_count"`
	TotalBreaches   int           `json:"total_breaches"`
	BreachStatus    bool          `json:"breach_status"`
	SensorLocation  string        `json:"sensor_location"`
	SensorCoords    []float64     `json:"sensor_coords"` // [19.0760, 72.8777]
	SensorHost      string        `json:"sensor_host"`
	ByCountry       []CountryStat `json:"by_country"`
	TopSourceIPs    []TopSourceIP `json:"top_source_ips"`
	TopIPs          []TopSourceIP `json:"top_ips"`
	AttemptsPerHour []HourlyStat  `json:"attempts_per_hour"`
	HourlySeries    []HourlyStat  `json:"hourly_series"`
	RecentFeeds     []Event       `json:"recent_feeds"`
	NextSyncSeconds int           `json:"next_sync_seconds"`
	ServerTime      time.Time     `json:"server_time"`
}

type StatsResponse = TelemetryStatsResponse

type LiveAttackEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	City      string    `json:"city"`
	Country   string    `json:"country"`
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	EventType string    `json:"event_type"`
}
