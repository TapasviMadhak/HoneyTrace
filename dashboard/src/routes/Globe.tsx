import { useState, useMemo } from 'react';
import CyberGlobe, { ThreatMarker } from '../components/CyberGlobe';
import useTelemetry, { HourlyStat } from '../hooks/useTelemetry';
import {
  ShieldAlert,
  Globe2,
  Users,
  AlertOctagon,
  RefreshCw,
  Activity,
  Radio,
  TrendingUp,
  Maximize2,
  Minimize2,
  ChevronDown,
  ChevronUp,
  X,
  Target,
  Eye,
  EyeOff,
} from 'lucide-react';

export default function Globe() {
  const {
    stats,
    markers,
    liveArcs,
    liveDelta,
    isRefreshing,
    fetchTelemetry,
  } = useTelemetry();

  // Selected IP filter for single-graph focus
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const [selectedMarker, setSelectedMarker] = useState<ThreatMarker | null>(null);

  // Expandable/collapsible states for HUD panels
  const [hudMinimized, setHudMinimized] = useState(false);
  const [showTelemetryHUD, setShowTelemetryHUD] = useState(true);
  const [showTopIPs, setShowTopIPs] = useState(true);
  const [showCountries, setShowCountries] = useState(true);
  const [showSparkline, setShowSparkline] = useState(true);
  const [showLiveStream, setShowLiveStream] = useState(true);

  const totalAttemptsDisplay = (stats.total_attempts || stats.total_attacks || 0) + liveDelta;
  const uniqueIpsDisplay = stats.unique_ips || 0;
  const countriesCountDisplay = stats.total_countries || stats.by_country.length || 0;
  const breachesCountDisplay = stats.breach_count || stats.total_breaches || 0;

  // Resolve coordinates for selected IP from top source IPs or recent feeds or markers
  const selectedIPCoords = useMemo(() => {
    if (!selectedIP) return null;

    // Check in top_source_ips
    const foundTop = stats.top_source_ips?.find((item) => item.ip === selectedIP);
    if (foundTop && foundTop.latitude && foundTop.longitude && (foundTop.latitude !== 0 || foundTop.longitude !== 0)) {
      return {
        lat: Number(foundTop.latitude),
        lng: Number(foundTop.longitude),
        city: foundTop.city,
        country: foundTop.country_code,
        ip: foundTop.ip,
      };
    }

    // Check in recent_feeds
    const foundFeed = stats.recent_feeds?.find((ev) => ev.source_ip === selectedIP);
    if (foundFeed && foundFeed.latitude && foundFeed.longitude && (foundFeed.latitude !== 0 || foundFeed.longitude !== 0)) {
      return {
        lat: Number(foundFeed.latitude),
        lng: Number(foundFeed.longitude),
        city: foundFeed.city,
        country: foundFeed.country_code,
        ip: foundFeed.source_ip,
      };
    }

    // Fallback: search in markers
    const foundMarker = markers.find((m) => m.ip === selectedIP || (m.city && foundTop && m.city === foundTop.city));
    if (foundMarker && typeof foundMarker.lat === 'number' && typeof foundMarker.lng === 'number') {
      return {
        lat: foundMarker.lat,
        lng: foundMarker.lng,
        city: foundMarker.city,
        country: foundMarker.country,
        ip: selectedIP,
      };
    }

    // Fallback to top hit IP Santa Clara if lat/lon is default 0
    if (selectedIP === '143.198.98.252') {
      return { lat: 37.3541, lng: -121.9552, city: 'Santa Clara', country: 'US', ip: selectedIP };
    }

    return null;
  }, [selectedIP, stats, markers]);

  const handleSelectIP = (ip: string) => {
    if (selectedIP === ip) {
      setSelectedIP(null);
    } else {
      setSelectedIP(ip);
    }
  };

  // Helper to format country code to flag emoji
  const getFlagEmoji = (countryCode?: string) => {
    if (!countryCode || countryCode === 'XX' || countryCode === 'Unknown') return '🌐';
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  };

  // Sparkline calculation
  const hourlyData: HourlyStat[] = stats.attempts_per_hour && stats.attempts_per_hour.length > 0
    ? stats.attempts_per_hour
    : (stats.hourly_series && stats.hourly_series.length > 0
      ? stats.hourly_series
      : Array.from({ length: 24 }, (_, i) => ({ hour: `${i}:00`, count: 0 })));

  const maxHourlyCount = Math.max(1, ...hourlyData.map((h: HourlyStat) => h.count));
  const svgWidth = 360;
  const svgHeight = 55;
  const stepX = svgWidth / Math.max(1, hourlyData.length - 1);

  // Generate SVG path for sparkline
  const points = hourlyData.map((h: HourlyStat, i: number) => {
    const x = i * stepX;
    const y = svgHeight - (h.count / maxHourlyCount) * (svgHeight - 12) - 6;
    return `${x},${y}`;
  });

  const pathD = points.length > 0 ? `M ${points.join(' L ')}` : '';
  const areaD = points.length > 0 ? `M 0,${svgHeight} L ${points.join(' L ')} L ${svgWidth},${svgHeight} Z` : '';

  return (
    <div className="relative w-full h-full min-h-[640px] rounded-2xl overflow-hidden bg-[#06080d] border border-[#1e2638] shadow-2xl">
      {/* 1. Full-Screen 3D CyberGlobe Canvas */}
      <div className="absolute inset-0 z-0">
        <CyberGlobe
          markers={markers}
          liveArcs={liveArcs}
          targetCoords={stats.sensor_coords}
          selectedIP={selectedIP}
          selectedIPCoords={selectedIPCoords}
          onSelectMarker={(m) => {
            setSelectedMarker(m);
            if (m.ip) setSelectedIP(m.ip);
          }}
        />
      </div>

      {/* Subtle Starfield & Vignette Gradient Overlay */}
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_center,_transparent_50%,_#06080d_95%)]" />

      {/* FLOATING TOP-CENTER TOOLBAR: Full Globe Toggle & IP Focus Filter */}
      <div className="absolute top-4 left-1/2 -translate-x-1/2 z-20 pointer-events-auto flex items-center gap-2">
        {/* Selected IP Filter Notification Badge */}
        {selectedIP && (
          <div className="flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-[#0d1117]/90 border border-[#00f0ff]/50 text-white font-mono text-xs shadow-[0_0_20px_rgba(0,240,255,0.3)] backdrop-blur-md animate-pulse">
            <Target className="w-4 h-4 text-[#00f0ff]" />
            <span>
              Target Focus: <strong className="text-[#00f0ff]">{selectedIP}</strong>
              {selectedIPCoords?.city ? ` (${selectedIPCoords.city}, ${selectedIPCoords.country})` : ''}
            </span>
            <button
              onClick={() => setSelectedIP(null)}
              className="p-0.5 rounded-full hover:bg-slate-800 text-slate-400 hover:text-white transition-all ml-1"
              title="Clear Filter (Show All Global Vectors)"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Global HUD Visibility Toggle (Full Globe Mode) */}
        <button
          onClick={() => setHudMinimized((prev) => !prev)}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-full font-mono text-xs font-bold border backdrop-blur-md transition-all shadow-lg ${
            hudMinimized
              ? 'bg-[#00ff9d]/20 text-[#00ff9d] border-[#00ff9d]/50 shadow-[0_0_15px_rgba(0,255,157,0.3)]'
              : 'bg-[#0d1117]/90 text-slate-300 hover:text-white border-[#1e2638] hover:border-slate-700'
          }`}
        >
          {hudMinimized ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5 text-slate-400" />}
          <span>{hudMinimized ? 'Show Telemetry HUD' : 'Full Globe View'}</span>
        </button>
      </div>

      {/* HUD OVERLAYS WRAPPER */}
      <div
        className={`absolute inset-0 pointer-events-none z-10 p-5 flex flex-col justify-between transition-opacity duration-300 ${
          hudMinimized ? 'opacity-0 pointer-events-none' : 'opacity-100'
        }`}
      >
        {/* TOP ROW */}
        <div className="flex items-start justify-between gap-4">
          {/* TOP-LEFT: Attack Telemetry & Sensor Host HUD */}
          <div className="flex flex-col gap-3 pointer-events-auto max-w-xs sm:max-w-sm w-full">
            <div className="hud-card p-4 transition-all">
              <div className="flex items-center justify-between gap-3 mb-2">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-3 w-3">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff9d] opacity-75" />
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-[#00ff9d]" />
                  </span>
                  <span className="text-xs font-mono font-bold tracking-widest text-[#00f0ff] uppercase">
                    ATTACK TELEMETRY
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#00ff9d]/10 border border-[#00ff9d]/30 text-[#00ff9d]">
                    ACTIVE
                  </span>
                  <button
                    onClick={() => setShowTelemetryHUD((prev) => !prev)}
                    className="p-1 rounded hover:bg-[#1e2638] text-slate-400 hover:text-white"
                    title={showTelemetryHUD ? 'Collapse' : 'Expand'}
                  >
                    {showTelemetryHUD ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {showTelemetryHUD && (
                <div className="space-y-1 font-mono text-xs mt-2 border-t border-[#1e2638] pt-2">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Target Node:</span>
                    <strong className="text-slate-100">{stats.sensor_location}</strong>
                  </div>
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Host:</span>
                    <span className="text-cyan-300 font-semibold">{stats.sensor_host}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-400 pt-1 border-t border-[#1e2638]">
                    <span>Telemetry Feed:</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[#00ff9d] font-semibold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#00ff9d] animate-pulse" />
                        <span>Live Ingest</span>
                      </span>
                      <button
                        onClick={() => fetchTelemetry(true)}
                        disabled={isRefreshing}
                        className="p-1 rounded hover:bg-[#1e2638] text-slate-300 hover:text-[#00f0ff] transition-all disabled:opacity-50"
                        title="Force DB Ingest & Refresh"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-[#00f0ff]' : ''}`} />
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* MID-LEFT: 4-Stat Metric Box */}
            <div className="hud-card p-3 grid grid-cols-2 gap-2">
              {/* Total Attempts */}
              <div className="p-2 rounded-lg bg-[#06080d]/80 border border-[#1e2638] hover:border-[#ff3366]/40 transition-colors">
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                  <ShieldAlert className="w-3.5 h-3.5 text-[#ff3366]" />
                  <span>Attempts</span>
                </div>
                <div className="text-lg font-mono font-black text-white mt-0.5 tracking-tight">
                  {totalAttemptsDisplay.toLocaleString()}
                </div>
              </div>

              {/* Unique IPs */}
              <div className="p-2 rounded-lg bg-[#06080d]/80 border border-[#1e2638] hover:border-[#00f0ff]/40 transition-colors">
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                  <Users className="w-3.5 h-3.5 text-[#00f0ff]" />
                  <span>Unique IPs</span>
                </div>
                <div className="text-lg font-mono font-black text-cyan-300 mt-0.5 tracking-tight">
                  {uniqueIpsDisplay.toLocaleString()}
                </div>
              </div>

              {/* Countries */}
              <div className="p-2 rounded-lg bg-[#06080d]/80 border border-[#1e2638] hover:border-purple-500/40 transition-colors">
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                  <Globe2 className="w-3.5 h-3.5 text-purple-400" />
                  <span>Countries</span>
                </div>
                <div className="text-lg font-mono font-black text-purple-300 mt-0.5 tracking-tight">
                  {countriesCountDisplay}
                </div>
              </div>

              {/* Breaches */}
              <div className="p-2 rounded-lg bg-[#06080d]/80 border border-[#1e2638] hover:border-amber-500/40 transition-colors">
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                  <AlertOctagon className="w-3.5 h-3.5 text-amber-400" />
                  <span>Breaches</span>
                </div>
                <div className="text-lg font-mono font-black text-amber-300 mt-0.5 tracking-tight">
                  {breachesCountDisplay}
                </div>
              </div>
            </div>
          </div>

          {/* TOP-RIGHT: "Top Source IPs" Table (Expandable / Selectable) */}
          <div className="pointer-events-auto max-w-xs sm:max-w-sm w-full">
            <div className="hud-card p-4">
              <div className="flex items-center justify-between mb-2.5">
                <div className="flex items-center gap-2">
                  <Radio className="w-4 h-4 text-[#ff3366]" />
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                    Top Source IPs
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#ff3366]/10 border border-[#ff3366]/30 text-[#ff3366]">
                    {stats.top_source_ips.length} IPs
                  </span>
                  <button
                    onClick={() => setShowTopIPs((prev) => !prev)}
                    className="p-1 rounded hover:bg-[#1e2638] text-slate-400 hover:text-white"
                    title={showTopIPs ? 'Collapse Top IPs' : 'Expand Top IPs'}
                  >
                    {showTopIPs ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {showTopIPs && (
                <>
                  <div className="text-[10px] font-mono text-slate-500 mb-2 flex items-center justify-between">
                    <span>Click IP to isolate on 3D Globe</span>
                    {selectedIP && (
                      <button
                        onClick={() => setSelectedIP(null)}
                        className="text-[#00f0ff] hover:underline"
                      >
                        Reset All
                      </button>
                    )}
                  </div>
                  <div className="overflow-x-auto max-h-[160px] overflow-y-auto pr-1">
                    <table className="w-full text-left font-mono text-xs">
                      <thead className="text-[10px] text-slate-500 uppercase border-b border-[#1e2638]">
                        <tr>
                          <th className="pb-1">Attacker IP</th>
                          <th className="pb-1">Location</th>
                          <th className="pb-1 text-right">Hits</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1e2638]/60 text-slate-300">
                        {stats.top_source_ips.length > 0 ? (
                          stats.top_source_ips.map((item, i) => {
                            const isSelected = selectedIP === item.ip;
                            return (
                              <tr
                                key={item.ip || i}
                                onClick={() => handleSelectIP(item.ip)}
                                className={`cursor-pointer transition-colors ${
                                  isSelected
                                    ? 'bg-[#00f0ff]/15 border-l-2 border-l-[#00f0ff]'
                                    : 'hover:bg-[#1e2638]/60'
                                }`}
                              >
                                <td className={`py-1.5 font-bold truncate max-w-[120px] ${
                                  isSelected ? 'text-[#00f0ff]' : 'text-cyan-300'
                                }`}>
                                  {item.ip}
                                </td>
                                <td className="py-1.5 text-slate-400 truncate max-w-[90px]">
                                  <span className="mr-1">{getFlagEmoji(item.country_code)}</span>
                                  <span>{item.city || item.country_code || 'N/A'}</span>
                                </td>
                                <td className="py-1.5 text-right font-bold text-[#ff3366]">
                                  {item.count.toLocaleString()}
                                </td>
                              </tr>
                            );
                          })
                        ) : (
                          <tr>
                            <td colSpan={3} className="py-3 text-center text-xs text-slate-500">
                              No source IP patterns recorded yet.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>

        {/* BOTTOM ROW */}
        <div className="flex items-end justify-between gap-4 mt-auto">
          {/* BOTTOM-LEFT: "By Country" Ranked List (Expandable) */}
          <div className="pointer-events-auto max-w-xs sm:max-w-sm w-full hidden md:block">
            <div className="hud-card p-4">
              <div className="flex items-center justify-between mb-2.5">
                <div className="flex items-center gap-2">
                  <Globe2 className="w-4 h-4 text-[#00f0ff]" />
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                    Threats by Country
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-slate-400">
                    Top {stats.by_country.length}
                  </span>
                  <button
                    onClick={() => setShowCountries((prev) => !prev)}
                    className="p-1 rounded hover:bg-[#1e2638] text-slate-400 hover:text-white"
                    title={showCountries ? 'Collapse Threats' : 'Expand Threats'}
                  >
                    {showCountries ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {showCountries && (
                <div className="space-y-1.5 max-h-[145px] overflow-y-auto pr-1">
                  {stats.by_country.length > 0 ? (
                    stats.by_country.map((c, i) => (
                      <div key={c.country_code || i} className="space-y-0.5 font-mono text-xs">
                        <div className="flex items-center justify-between text-slate-300">
                          <div className="flex items-center gap-1.5 truncate">
                            <span className="text-sm">{getFlagEmoji(c.country_code)}</span>
                            <span className="font-semibold text-slate-200 truncate max-w-[140px]">
                              {c.country_name || c.country_code}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0 text-[11px]">
                            <span className="text-slate-400">{c.percentage}%</span>
                            <span className="text-[#00f0ff] font-bold">{c.count.toLocaleString()}</span>
                          </div>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-[#06080d] overflow-hidden border border-[#1e2638]">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-[#ff3366] to-[#00f0ff] transition-all duration-700"
                            style={{ width: `${Math.max(5, Math.min(100, c.percentage))}%` }}
                          />
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-3 text-xs font-mono text-slate-500">
                      Waiting for geo-resolved ingress events...
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* BOTTOM-CENTER: "Attempts / Hour" Area Sparkline Chart (Expandable) */}
          <div className="pointer-events-auto hidden xl:block">
            <div className="hud-card p-3 px-4 flex flex-col items-center">
              <div className="flex items-center justify-between w-full mb-1">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-3.5 h-3.5 text-[#00f0ff]" />
                  <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-300">
                    Attempts / Hour (24h Activity)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-slate-400">
                    Peak: <strong className="text-[#00f0ff]">{maxHourlyCount} hits/hr</strong>
                  </span>
                  <button
                    onClick={() => setShowSparkline((prev) => !prev)}
                    className="p-1 rounded hover:bg-[#1e2638] text-slate-400 hover:text-white"
                  >
                    {showSparkline ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>
                </div>
              </div>

              {showSparkline && (
                <>
                  <div className="relative w-[360px] h-[55px]">
                    <svg width={svgWidth} height={svgHeight} className="overflow-visible">
                      <defs>
                        <linearGradient id="cyanSparklineGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.45" />
                          <stop offset="100%" stopColor="#00f0ff" stopOpacity="0.0" />
                        </linearGradient>
                      </defs>
                      <path d={areaD} fill="url(#cyanSparklineGrad)" />
                      <path
                        d={pathD}
                        fill="none"
                        stroke="#00f0ff"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </div>

                  <div className="flex items-center justify-between w-full text-[9px] font-mono text-slate-500 mt-0.5">
                    <span>24 Hours Ago</span>
                    <span>Current Real-Time</span>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* BOTTOM-RIGHT: "Live Attack Stream" (Expandable / Selectable) */}
          <div className="pointer-events-auto max-w-xs sm:max-w-sm w-full hidden sm:block">
            <div className="hud-card p-4">
              <div className="flex items-center justify-between mb-2.5">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#00ff9d]" />
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                    Live Attack Stream
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-[#00ff9d] animate-pulse">
                    ● LIVE
                  </span>
                  <button
                    onClick={() => setShowLiveStream((prev) => !prev)}
                    className="p-1 rounded hover:bg-[#1e2638] text-slate-400 hover:text-white"
                    title={showLiveStream ? 'Collapse Stream' : 'Expand Stream'}
                  >
                    {showLiveStream ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {showLiveStream && (
                <div className="space-y-1.5 max-h-[145px] overflow-y-auto pr-1">
                  {stats.recent_feeds.length > 0 ? (
                    stats.recent_feeds.slice(0, 8).map((ev, i) => {
                      const isSelected = selectedIP === ev.source_ip;
                      return (
                        <div
                          key={ev.id || i}
                          onClick={() => handleSelectIP(ev.source_ip)}
                          className={`p-1.5 rounded-lg border font-mono text-[11px] space-y-0.5 cursor-pointer transition-all ${
                            isSelected
                              ? 'bg-[#00f0ff]/15 border-[#00f0ff]'
                              : 'bg-[#06080d]/80 border-[#1e2638] hover:border-[#00f0ff]/40'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px]">
                              {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                            </span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                              {getFlagEmoji(ev.country_code)} {ev.country_code || 'XX'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className={`font-bold ${isSelected ? 'text-[#00f0ff]' : 'text-[#ff3366]'}`}>
                              {ev.source_ip}
                            </span>
                            <span className="text-slate-400 truncate max-w-[110px] text-[10px]">
                              user: <code className="text-cyan-300">{ev.username || 'root'}</code>
                            </span>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="text-center py-3 text-xs font-mono text-slate-500">
                      Awaiting incoming honeypot connection stream...
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Marker Drill-Down Modal if clicked */}
      {selectedMarker && (
        <div className="absolute top-16 left-1/2 -translate-x-1/2 z-30 hud-card hud-card-active p-4 max-w-sm w-full pointer-events-auto animate-bounce-short">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono font-bold text-[#00f0ff] uppercase">
              Target Cluster Selected
            </span>
            <button
              onClick={() => setSelectedMarker(null)}
              className="text-xs font-mono text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="font-mono text-xs space-y-1 text-slate-300">
            <div>
              Coordinates: <strong className="text-white">[{selectedMarker.lat.toFixed(4)}°, {selectedMarker.lng.toFixed(4)}°]</strong>
            </div>
            <div>
              Location: <span className="text-cyan-300">{selectedMarker.city}, {selectedMarker.country}</span>
            </div>
            <div>
              Ingress Volume: <span className="text-[#ff3366] font-bold">{selectedMarker.count.toLocaleString()} hits</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
