import { useCallback, useEffect, useRef, useState } from 'react';
import { AttackArc, ThreatMarker } from '../components/CyberGlobe';

export interface CountryStat {
  country_code: string;
  country_name: string;
  count: number;
  percentage: number;
}

export interface TopSourceIP {
  ip: string;
  country_code: string;
  city: string;
  count: number;
  latitude: number;
  longitude: number;
}

export interface HourlyStat {
  hour: string;
  count: number;
}

export interface FeedEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  latitude?: number;
  longitude?: number;
  country_code?: string;
  city?: string;
  username?: string;
  password?: string;
  event_type?: string;
  severity?: string;
  summary?: string;
}

export interface TelemetryStats {
  total_attempts: number;
  total_attacks: number;
  unique_ips: number;
  total_countries: number;
  breach_count: number;
  total_breaches: number;
  breach_status: boolean;
  sensor_location: string;
  sensor_coords: [number, number];
  sensor_host: string;
  by_country: CountryStat[];
  top_source_ips: TopSourceIP[];
  top_ips?: TopSourceIP[];
  attempts_per_hour: HourlyStat[];
  hourly_series?: HourlyStat[];
  recent_feeds: FeedEvent[];
  next_sync_seconds?: number;
  server_time?: string;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
const DEFAULT_TARGET: [number, number] = [19.0760, 72.8777]; // Mumbai, India

export function useTelemetry() {
  const [stats, setStats] = useState<TelemetryStats>({
    total_attempts: 0,
    total_attacks: 0,
    unique_ips: 0,
    total_countries: 0,
    breach_count: 0,
    total_breaches: 0,
    breach_status: false,
    sensor_location: 'Mumbai, India',
    sensor_coords: DEFAULT_TARGET,
    sensor_host: 'AWS EC2 ap-south-1',
    by_country: [],
    top_source_ips: [],
    attempts_per_hour: [],
    recent_feeds: [],
  });

  const [markers, setMarkers] = useState<ThreatMarker[]>([]);
  const [liveArcs, setLiveArcs] = useState<AttackArc[]>([]);
  const [liveDelta, setLiveDelta] = useState(0);
  const [countdown, setCountdown] = useState<number>(5);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastSyncTime, setLastSyncTime] = useState<string>('Syncing...');

  const statsRef = useRef(stats);
  statsRef.current = stats;

  const fetchTelemetry = useCallback((forceRefresh = false) => {
    setIsRefreshing(true);
    const endpoint = forceRefresh
      ? `${API_BASE_URL}/api/v1/telemetry/sync`
      : `${API_BASE_URL}/api/v1/telemetry/stats`;

    const requestOptions: RequestInit = {
      method: forceRefresh ? 'POST' : 'GET',
      cache: 'no-store',
      headers: {
        'Cache-Control': 'no-cache',
        Pragma: 'no-cache',
      },
    };

    Promise.all([
      fetch(endpoint, requestOptions)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      fetch(`${API_BASE_URL}/api/v1/telemetry/globe`, { cache: 'no-store' })
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
    ])
      .then(([statsData, globeData]) => {
        // Retain previous state and merge without zeroing out existing non-zero values on network glitch
        if (statsData) {
          const totalAttempts = statsData.total_attempts ?? statsData.total_attacks ?? statsData.attempts ?? statsRef.current.total_attempts;
          const uniqueIps = statsData.unique_ips ?? statsRef.current.unique_ips;
          const totalCountries = statsData.total_countries ?? (statsData.by_country ? statsData.by_country.length : statsRef.current.total_countries);
          const breachCount = statsData.breach_count ?? statsData.total_breaches ?? statsRef.current.breach_count;
          const byCountry = Array.isArray(statsData.by_country) && statsData.by_country.length > 0 ? statsData.by_country : statsRef.current.by_country;
          const topIPs = (Array.isArray(statsData.top_source_ips) && statsData.top_source_ips.length > 0)
            ? statsData.top_source_ips
            : (Array.isArray(statsData.top_ips) && statsData.top_ips.length > 0 ? statsData.top_ips : statsRef.current.top_source_ips);
          const hourly = (Array.isArray(statsData.attempts_per_hour) && statsData.attempts_per_hour.length > 0)
            ? statsData.attempts_per_hour
            : (Array.isArray(statsData.hourly_series) && statsData.hourly_series.length > 0 ? statsData.hourly_series : statsRef.current.attempts_per_hour);
          const feeds = Array.isArray(statsData.recent_feeds) && statsData.recent_feeds.length > 0 ? statsData.recent_feeds : statsRef.current.recent_feeds;

          setStats((prev) => ({
            ...prev,
            total_attempts: totalAttempts,
            total_attacks: totalAttempts,
            unique_ips: uniqueIps,
            total_countries: totalCountries,
            breach_count: breachCount,
            total_breaches: breachCount,
            breach_status: breachCount > 0 || statsData.breach_status || prev.breach_status,
            sensor_location: statsData.sensor_location || prev.sensor_location,
            sensor_coords: statsData.sensor_coords || prev.sensor_coords,
            sensor_host: statsData.sensor_host || prev.sensor_host,
            by_country: byCountry,
            top_source_ips: topIPs,
            attempts_per_hour: hourly,
            recent_feeds: feeds,
            next_sync_seconds: statsData.next_sync_seconds,
            server_time: statsData.server_time,
          }));

          setLiveDelta(0);
          setLastSyncTime(new Date().toLocaleTimeString());
        }

        if (globeData && Array.isArray(globeData.markers) && globeData.markers.length > 0) {
          const formatted: ThreatMarker[] = globeData.markers.map((m: any) => ({
            lat: m.location ? m.location[0] : m.lat || 0,
            lng: m.location ? m.location[1] : m.lng || 0,
            size: m.size || 0.2,
            count: m.count || 1,
            city: m.city || 'Unknown',
            country: m.country || 'Unknown',
          }));
          setMarkers(formatted);
        }
      })
      .catch((err) => {
        console.warn('Telemetry sync error:', err);
      })
      .finally(() => {
        setIsRefreshing(false);
      });
  }, []);

  // 5-Second polling interval
  useEffect(() => {
    fetchTelemetry(false);

    const pollInterval = setInterval(() => {
      fetchTelemetry(false);
    }, 5000);

    return () => {
      clearInterval(pollInterval);
    };
  }, [fetchTelemetry]);

  // Connect to SSE stream for live real-time attack arcs and feed push
  useEffect(() => {
    const sseUrl = `${API_BASE_URL}/api/v1/telemetry/live`;
    let eventSource: EventSource | null = null;

    try {
      eventSource = new EventSource(sseUrl);

      eventSource.onmessage = (e) => {
        if (!e.data || e.data === ': connected') return;
        try {
          const raw = JSON.parse(e.data);
          const lat = raw.latitude || 0;
          const lon = raw.longitude || 0;

          // Increment real-time hits
          setLiveDelta((prev) => prev + 1);

          // Add to live feed
          const feedItem: FeedEvent = {
            id: raw.id || `live-${Date.now()}`,
            timestamp: raw.timestamp || new Date().toISOString(),
            source_ip: raw.source_ip || 'Unknown',
            country_code: raw.country || 'XX',
            city: raw.city || 'Unknown',
            username: raw.username || 'root',
            password: raw.password || '***',
            event_type: raw.event_type || 'auth',
            severity: 'medium',
            summary: `Live authentication probe from ${raw.source_ip}`,
          };

          setStats((prev) => ({
            ...prev,
            total_attempts: prev.total_attempts + 1,
            total_attacks: prev.total_attacks + 1,
            recent_feeds: [feedItem, ...prev.recent_feeds.slice(0, 35)],
          }));

          // Trigger live arc on the globe
          if (lat !== 0 || lon !== 0) {
            const newArc: AttackArc = {
              startLat: lat,
              startLng: lon,
              endLat: DEFAULT_TARGET[0],
              endLng: DEFAULT_TARGET[1],
              color: ['#ff3366', '#00ff9d'],
              city: raw.city,
              country: raw.country,
              ip: raw.source_ip,
            };

            setLiveArcs((prev) => [newArc, ...prev.slice(0, 25)]);
          }
        } catch (err) {
          console.warn('SSE packet parse error:', err);
        }
      };

      eventSource.onerror = () => {
        // SSE auto-reconnects
      };
    } catch (err) {
      console.warn('SSE connection failed:', err);
    }

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, []);

  return {
    stats,
    markers,
    liveArcs,
    liveDelta,
    countdown,
    isRefreshing,
    lastSyncTime,
    fetchTelemetry,
  };
}

export default useTelemetry;
