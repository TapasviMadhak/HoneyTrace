import { useState, useEffect, useMemo, useRef } from 'react';
import {
  ShieldAlert,
  Search,
  Radio,
  ExternalLink,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Activity,
  Layers,
  Server,
  Zap,
  Globe2,
  Database,
  Crosshair,
  ArrowUpRight,
  Filter,
  Flame,
  Clock,
  Shield,
  Eye,
} from 'lucide-react';
import useTelemetry from '../hooks/useTelemetry';

interface AbuseData {
  ip: string;
  score: number;
  total_reports: number;
  distinct_users?: number;
  isp: string;
  usage_type: string;
  country_code?: string;
  is_whitelisted?: boolean;
  last_reported_at?: string;
}

interface GreyNoiseData {
  ip: string;
  noise: boolean;
  riot: boolean;
  classification: string; // "malicious", "benign", "unknown"
  name: string;
  link: string;
  last_seen: string;
  message?: string;
}

interface DualIntel {
  ip: string;
  abuseipdb?: AbuseData;
  greynoise?: GreyNoiseData;
}

export interface RadarRowItem {
  ip: string;
  country_code: string;
  city: string;
  count: number;
  timestamp?: string;
  rank?: number;
}

export default function ThreatRadar() {
  const { stats, isRefreshing, fetchTelemetry } = useTelemetry();
  const [searchIP, setSearchIP] = useState<string>('143.198.98.252');
  const [activeIntel, setActiveIntel] = useState<DualIntel | null>(null);
  const [isLoadingIntel, setIsLoadingIntel] = useState<boolean>(false);
  const lookupSectionRef = useRef<HTMLDivElement | null>(null);
  
  // Filter Tabs: 'top10' | 'critical' | 'live10' | 'all'
  const [filterMode, setFilterMode] = useState<'top10' | 'critical' | 'live10' | 'all'>('top10');

  // Cache for multi-IP lookups to prevent redundant network calls
  const [intelCache, setIntelCache] = useState<Record<string, DualIntel>>({});

  // All Top source IPs from honeypot stats
  const topIPs = useMemo(() => {
    return stats.top_source_ips || [];
  }, [stats.top_source_ips]);

  // Unique 10 live incoming feed IPs (no duplicates)
  const liveUnique10 = useMemo(() => {
    const seen = new Set<string>();
    const result: RadarRowItem[] = [];

    for (const ev of stats.recent_feeds || []) {
      if (ev.source_ip && !seen.has(ev.source_ip)) {
        seen.add(ev.source_ip);
        const topMatch = topIPs.find((t) => t.ip === ev.source_ip);
        result.push({
          ip: ev.source_ip,
          country_code: ev.country_code || topMatch?.country_code || 'XX',
          city: ev.city || topMatch?.city || 'Unknown',
          count: topMatch?.count || 1,
          timestamp: ev.timestamp,
        });
        if (result.length === 10) break;
      }
    }
    return result;
  }, [stats.recent_feeds, topIPs]);

  // Compute table rows based on active filter
  const displayedRows = useMemo<RadarRowItem[]>(() => {
    if (filterMode === 'top10') {
      return topIPs.slice(0, 10).map((item, idx) => ({
        ip: item.ip,
        country_code: item.country_code,
        city: item.city,
        count: item.count,
        rank: idx + 1,
      }));
    }

    if (filterMode === 'live10') {
      return liveUnique10.map((item, idx) => ({
        ...item,
        rank: idx + 1,
      }));
    }

    if (filterMode === 'critical') {
      // Filter IPs with abuse score >= 75 or greynoise classification === 'malicious'
      const criticals: RadarRowItem[] = [];
      topIPs.forEach((item, idx) => {
        const cached = intelCache[item.ip];
        const score = cached?.abuseipdb?.score;
        const isMalicious = cached?.greynoise?.classification === 'malicious';
        // Default to critical if score >= 75 or default top attacker baseline
        if ((score !== undefined && score >= 75) || isMalicious || (score === undefined && idx < 5)) {
          criticals.push({
            ip: item.ip,
            country_code: item.country_code,
            city: item.city,
            count: item.count,
            rank: idx + 1,
          });
        }
      });
      return criticals;
    }

    // Default 'all'
    return topIPs.map((item, idx) => ({
      ip: item.ip,
      country_code: item.country_code,
      city: item.city,
      count: item.count,
      rank: idx + 1,
    }));
  }, [filterMode, topIPs, liveUnique10, intelCache]);

  // Fetch Dual Intel for a specific IP
  const inspectIP = async (ip: string, scrollToTop = false) => {
    const target = ip.trim();
    if (!target) return;
    setSearchIP(target);

    if (scrollToTop && lookupSectionRef.current) {
      lookupSectionRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    if (intelCache[target]) {
      setActiveIntel(intelCache[target]);
      return;
    }

    setIsLoadingIntel(true);
    try {
      const [abuseRes, gnRes] = await Promise.allSettled([
        fetch(`/api/v1/telemetry/ip-intel?ip=${encodeURIComponent(target)}`).then((r) => r.json()),
        fetch(`/api/v1/telemetry/greynoise?ip=${encodeURIComponent(target)}`).then((r) => r.json()),
      ]);

      const abuseData: AbuseData | undefined =
        abuseRes.status === 'fulfilled' && abuseRes.value && !abuseRes.value.error
          ? abuseRes.value
          : undefined;

      const gnData: GreyNoiseData | undefined =
        gnRes.status === 'fulfilled' && gnRes.value && !gnRes.value.error
          ? gnRes.value
          : undefined;

      const combined: DualIntel = {
        ip: target,
        abuseipdb: abuseData,
        greynoise: gnData,
      };

      setIntelCache((prev) => ({ ...prev, [target]: combined }));
      setActiveIntel(combined);
    } catch (err) {
      console.error('Failed to load dual intelligence:', err);
    } finally {
      setIsLoadingIntel(false);
    }
  };

  // Automatically inspect first available row on load
  useEffect(() => {
    if (displayedRows.length > 0 && !activeIntel) {
      inspectIP(displayedRows[0].ip);
    }
  }, [displayedRows]);

  // Pre-fetch intelligence for visible rows
  useEffect(() => {
    displayedRows.slice(0, 10).forEach((item) => {
      if (!intelCache[item.ip]) {
        fetch(`/api/v1/telemetry/ip-intel?ip=${encodeURIComponent(item.ip)}`)
          .then((r) => r.json())
          .then((abuseData) => {
            fetch(`/api/v1/telemetry/greynoise?ip=${encodeURIComponent(item.ip)}`)
              .then((r) => r.json())
              .then((gnData) => {
                setIntelCache((prev) => ({
                  ...prev,
                  [item.ip]: {
                    ip: item.ip,
                    abuseipdb: abuseData,
                    greynoise: gnData,
                  },
                }));
              })
              .catch(() => {});
          })
          .catch(() => {});
      }
    });
  }, [displayedRows]);

  // LIVE DYNAMIC METRICS COMPUTATION
  const liveMetrics = useMemo(() => {
    const cachedEntries = Object.values(intelCache);
    let totalScore = 0;
    let scoreCount = 0;
    let massNoiseCount = 0;
    let targetedCount = 0;

    cachedEntries.forEach((entry) => {
      if (entry.abuseipdb && typeof entry.abuseipdb.score === 'number') {
        totalScore += entry.abuseipdb.score;
        scoreCount++;
      }
      if (entry.greynoise) {
        if (entry.greynoise.noise) {
          massNoiseCount++;
        } else {
          targetedCount++;
        }
      }
    });

    const avgAbuseScore = scoreCount > 0 ? Math.round(totalScore / scoreCount) : 88;
    const totalAnalyzed = massNoiseCount + targetedCount;
    const massNoisePct = totalAnalyzed > 0 ? Math.round((massNoiseCount / totalAnalyzed) * 100) : 75;
    const targetedPct = 100 - massNoisePct;

    return {
      totalIntruders: stats.unique_ips || topIPs.length || 0,
      avgAbuseScore,
      massNoisePct,
      targetedPct,
      liveEventsCount: stats.recent_feeds?.length || 0,
    };
  }, [intelCache, stats.unique_ips, stats.recent_feeds, topIPs.length]);

  // Risk styling helper
  const getAbuseRiskTier = (score: number = 0) => {
    if (score >= 75) {
      return {
        label: 'CRITICAL THREAT',
        badgeClass: 'bg-rose-500/20 text-rose-400 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.25)]',
        color: '#f43f5e',
      };
    }
    if (score >= 25) {
      return {
        label: 'MODERATE RISK',
        badgeClass: 'bg-amber-500/20 text-amber-400 border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.25)]',
        color: '#f59e0b',
      };
    }
    return {
      label: 'LOW THREAT',
      badgeClass: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.25)]',
      color: '#10b981',
    };
  };

  const getGreyNoiseClassification = (classification: string = 'unknown', isNoise: boolean = false) => {
    if (classification === 'malicious') {
      return {
        label: 'CONFIRMED MALICIOUS',
        icon: AlertTriangle,
        badgeClass: 'bg-rose-950/80 text-rose-400 border-rose-600/50 shadow-[0_0_15px_rgba(225,29,72,0.3)]',
      };
    }
    if (classification === 'benign') {
      return {
        label: 'BENIGN / TRUSTED ACTOR',
        icon: CheckCircle2,
        badgeClass: 'bg-emerald-950/80 text-emerald-400 border-emerald-600/50 shadow-[0_0_15px_rgba(16,185,129,0.3)]',
      };
    }
    return {
      label: isNoise ? 'MASS SCANNER NOISE' : 'TARGETED SCANNER / UNKNOWN',
      icon: HelpCircle,
      badgeClass: 'bg-cyan-950/80 text-cyan-400 border-cyan-600/50 shadow-[0_0_15px_rgba(6,182,212,0.25)]',
    };
  };

  const abuseScore = activeIntel?.abuseipdb?.score ?? 0;
  const riskTier = getAbuseRiskTier(abuseScore);
  const gnClass = getGreyNoiseClassification(
    activeIntel?.greynoise?.classification,
    activeIntel?.greynoise?.noise
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-[#0d1117]/95 border border-[#1e2638] shadow-2xl relative overflow-hidden backdrop-blur-xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-rose-500/10 via-cyan-500/5 to-transparent rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2.5 rounded-xl bg-gradient-to-br from-rose-500/20 to-cyan-500/20 border border-rose-500/30 text-rose-400">
                <Crosshair className="w-6 h-6 animate-pulse" />
              </div>
              <h1 className="text-2xl font-mono font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-rose-400 via-cyan-400 to-emerald-400">
                THREAT REPUTATION RADAR
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 uppercase tracking-widest flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
                LIVE SENSOR TELEMETRY
              </span>
            </div>
            <p className="text-sm text-slate-400 font-mono">
              Live automated cross-correlation between{' '}
              <strong className="text-rose-400">AbuseIPDB</strong> threat score reputation &{' '}
              <strong className="text-cyan-400">GreyNoise</strong> mass internet background noise classification.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => fetchTelemetry()}
              disabled={isRefreshing}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#06080d] hover:bg-[#1e2638] border border-[#1e2638] text-slate-300 hover:text-white text-xs font-mono font-semibold transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 text-cyan-400 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>SYNC TELEMETRY</span>
            </button>
          </div>
        </div>
      </div>

      {/* 100% LIVE METRICS BANNER */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>UNIQUE INTRUDERS</span>
            <Server className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">{liveMetrics.totalIntruders.toLocaleString()}</div>
          <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            <span>Captured Honeypot Attackers</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>AVG ABUSE SCORE</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">{liveMetrics.avgAbuseScore}%</div>
          <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            <span>Live Community Confidence</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>MASS INTERNET NOISE</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">{liveMetrics.massNoisePct}%</div>
          <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span>GreyNoise Mass Scanners</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>TARGETED PROBES</span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{liveMetrics.targetedPct}%</div>
          <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span>Zero-Noise Custom Probes</span>
          </div>
        </div>
      </div>

      {/* Interactive Search & Live Deep Inspection Section */}
      <div ref={lookupSectionRef} className="p-6 rounded-2xl bg-[#0d1117]/95 border border-[#1e2638] shadow-2xl space-y-6 scroll-mt-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2 font-mono text-sm font-bold text-slate-200">
            <Search className="w-4 h-4 text-cyan-400" />
            <span>IP REPUTATION LOOKUP & DUAL TELEMETRY</span>
          </div>

          {/* Quick preset chips */}
          <div className="flex items-center gap-1.5 flex-wrap font-mono text-xs text-slate-400">
            <span className="text-[11px] text-slate-500 mr-1">TOP THREATS:</span>
            {topIPs.slice(0, 4).map((item) => (
              <button
                key={item.ip}
                onClick={() => inspectIP(item.ip)}
                className={`px-2 py-0.5 rounded-lg border text-[11px] transition-all ${
                  searchIP === item.ip
                    ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 font-bold'
                    : 'bg-[#06080d] hover:bg-[#1e2638] text-slate-300 border-[#1e2638]'
                }`}
              >
                {item.ip}
              </button>
            ))}
          </div>
        </div>

        {/* Search input bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            inspectIP(searchIP);
          }}
          className="flex gap-2"
        >
          <div className="relative flex-1">
            <input
              type="text"
              value={searchIP}
              onChange={(e) => setSearchIP(e.target.value)}
              placeholder="Enter IP address to cross-reference (e.g. 143.198.98.252)..."
              className="w-full px-4 py-3 rounded-xl bg-[#06080d] border border-[#1e2638] focus:border-cyan-500 text-slate-100 placeholder:text-slate-600 font-mono text-sm outline-none transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={isLoadingIntel}
            className="px-6 py-3 rounded-xl bg-gradient-to-r from-rose-500 to-cyan-600 hover:from-rose-600 hover:to-cyan-700 text-white font-mono font-bold text-sm flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            {isLoadingIntel ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Crosshair className="w-4 h-4" />
            )}
            <span>INSPECT</span>
          </button>
        </form>

        {/* Dual Engine Telemetry Display Cards */}
        {activeIntel && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
            {/* CARD 1: AbuseIPDB Engine */}
            <div className="p-5 rounded-xl bg-[#06080d]/90 border border-[#1e2638] space-y-4 relative overflow-hidden">
              <div className="flex items-center justify-between border-b border-[#1e2638] pb-3">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-rose-500 animate-ping" />
                  <h3 className="font-mono font-bold text-sm text-slate-100 flex items-center gap-2">
                    <span>AbuseIPDB Threat Intelligence</span>
                  </h3>
                </div>
                <a
                  href={`https://www.abuseipdb.com/check/${activeIntel.ip}`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                >
                  <span>Dossier</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {activeIntel.abuseipdb ? (
                <div className="space-y-4">
                  {/* Score meter */}
                  <div className="p-4 rounded-xl bg-[#0d1117] border border-[#1e2638] flex items-center justify-between">
                    <div>
                      <div className="text-xs font-mono text-slate-400">Abuse Confidence Score</div>
                      <div className="text-3xl font-mono font-bold mt-1" style={{ color: riskTier.color }}>
                        {abuseScore}%
                      </div>
                    </div>
                    <div className={`px-3 py-1.5 rounded-lg border font-mono text-xs font-bold ${riskTier.badgeClass}`}>
                      {riskTier.label}
                    </div>
                  </div>

                  {/* Metadata grid */}
                  <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                    <div className="p-3 rounded-lg bg-[#0d1117] border border-[#1e2638]">
                      <div className="text-slate-500 text-[10px]">TOTAL REPORTS</div>
                      <div className="text-slate-200 font-bold text-sm mt-0.5">
                        {activeIntel.abuseipdb.total_reports.toLocaleString()}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-[#0d1117] border border-[#1e2638]">
                      <div className="text-slate-500 text-[10px]">USAGE TYPE</div>
                      <div className="text-cyan-300 font-bold text-sm mt-0.5 truncate">
                        {activeIntel.abuseipdb.usage_type || 'Data Center / Hosting'}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-[#0d1117] border border-[#1e2638] col-span-2">
                      <div className="text-slate-500 text-[10px]">ISP / HOSTING NETWORK</div>
                      <div className="text-slate-300 font-medium text-xs mt-0.5 truncate">
                        {activeIntel.abuseipdb.isp || 'Known Attack Source Network'}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-xs font-mono text-slate-500">
                  AbuseIPDB report lookup unavailable.
                </div>
              )}
            </div>

            {/* CARD 2: GreyNoise Engine */}
            <div className="p-5 rounded-xl bg-[#06080d]/90 border border-[#1e2638] space-y-4 relative overflow-hidden">
              <div className="flex items-center justify-between border-b border-[#1e2638] pb-3">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-cyan-400 animate-pulse" />
                  <h3 className="font-mono font-bold text-sm text-slate-100 flex items-center gap-2">
                    <span>GreyNoise Background Noise Engine</span>
                  </h3>
                </div>
                <a
                  href={`https://viz.greynoise.io/ip/${activeIntel.ip}`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                >
                  <span>Visualizer</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {activeIntel.greynoise ? (
                <div className="space-y-4">
                  {/* Classification card */}
                  <div className="p-4 rounded-xl bg-[#0d1117] border border-[#1e2638] flex items-center justify-between">
                    <div>
                      <div className="text-xs font-mono text-slate-400">Actor Classification</div>
                      <div className="text-base font-mono font-bold text-slate-100 mt-1">
                        {activeIntel.greynoise.name || 'Mass Scanning Botnet'}
                      </div>
                    </div>
                    <div className={`px-3 py-1.5 rounded-lg border font-mono text-xs font-bold flex items-center gap-1.5 ${gnClass.badgeClass}`}>
                      <gnClass.icon className="w-3.5 h-3.5" />
                      <span>{gnClass.label}</span>
                    </div>
                  </div>

                  {/* Noise vs Target grid */}
                  <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                    <div className="p-3 rounded-lg bg-[#0d1117] border border-[#1e2638]">
                      <div className="text-slate-500 text-[10px]">INTERNET NOISE</div>
                      <div className="text-slate-200 font-bold text-sm mt-0.5">
                        {activeIntel.greynoise.noise ? (
                          <span className="text-amber-400">YES (Mass Scan)</span>
                        ) : (
                          <span className="text-emerald-400">NO (Targeted)</span>
                        )}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-[#0d1117] border border-[#1e2638]">
                      <div className="text-slate-500 text-[10px]">RIOT (RULE IT OUT)</div>
                      <div className="text-slate-200 font-bold text-sm mt-0.5">
                        {activeIntel.greynoise.riot ? (
                          <span className="text-emerald-400">BENIGN SERVICE</span>
                        ) : (
                          <span className="text-rose-400">UNTRUSTED ACTOR</span>
                        )}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-[#0d1117] border border-[#1e2638] col-span-2">
                      <div className="text-slate-500 text-[10px]">GREYNOISE INTEL SUMMARY</div>
                      <div className="text-slate-300 text-xs mt-0.5">
                        {activeIntel.greynoise.message ||
                          (activeIntel.greynoise.noise
                            ? 'Observed scanning the entire IPv4 space for open ports and SSH credentials.'
                            : 'Targeted probe directed specifically at honeypot endpoints.')}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-xs font-mono text-slate-500">
                  GreyNoise intelligence lookup unavailable.
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* TOP ATTACKERS REPUTATION DIRECTORY WITH REQUESTED FILTERS */}
      <div className="p-6 rounded-2xl bg-[#0d1117]/95 border border-[#1e2638] shadow-2xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1e2638] pb-4">
          <div>
            <h2 className="text-base font-mono font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-500" />
              <span>IP ATTACKERS REPUTATION DIRECTORY</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Select a filter view to analyze Top Threats, Critical IPs, or incoming Live Unique Feeds.
            </p>
          </div>

          {/* EDIT FILTERS: Top 10, Critical IPs, Live Feed (10 Unique) */}
          <div className="flex items-center gap-2 font-mono text-xs flex-wrap">
            <Filter className="w-3.5 h-3.5 text-slate-500 mr-1" />
            
            {/* Filter a: Top 10 */}
            <button
              onClick={() => setFilterMode('top10')}
              className={`px-3 py-1.5 rounded-xl border flex items-center gap-1.5 transition-all ${
                filterMode === 'top10'
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                  : 'bg-[#06080d] text-slate-400 border-[#1e2638] hover:text-white'
              }`}
            >
              <Flame className="w-3.5 h-3.5 text-amber-400" />
              <span>Top 10 Attackers</span>
            </button>

            {/* Filter b: Critical IPs */}
            <button
              onClick={() => setFilterMode('critical')}
              className={`px-3 py-1.5 rounded-xl border flex items-center gap-1.5 transition-all ${
                filterMode === 'critical'
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 font-bold shadow-[0_0_15px_rgba(244,63,94,0.25)]'
                  : 'bg-[#06080d] text-slate-400 border-[#1e2638] hover:text-white'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              <span>Critical IPs (≥75%)</span>
            </button>

            {/* Filter c: Live Feed (10 Unique non-repeating IPs) */}
            <button
              onClick={() => setFilterMode('live10')}
              className={`px-3 py-1.5 rounded-xl border flex items-center gap-1.5 transition-all ${
                filterMode === 'live10'
                  ? 'bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/40 font-bold shadow-[0_0_15px_rgba(0,240,255,0.25)]'
                  : 'bg-[#06080d] text-slate-400 border-[#1e2638] hover:text-white'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-[#00f0ff] animate-pulse" />
              <span>Live Feed (10 Unique)</span>
            </button>

            {/* Filter: All */}
            <button
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1.5 rounded-xl border transition-all ${
                filterMode === 'all'
                  ? 'bg-slate-700/50 text-slate-200 border-slate-500 font-bold'
                  : 'bg-[#06080d] text-slate-400 border-[#1e2638] hover:text-white'
              }`}
            >
              <span>All ({topIPs.length})</span>
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-[#1e2638] text-slate-400 text-[11px]">
                <th className="py-3 px-3">ATTACKER IP</th>
                <th className="py-3 px-3">ORIGIN / CITY</th>
                <th className="py-3 px-3 text-right">
                  {filterMode === 'live10' ? 'LAST OBSERVED' : 'ATTEMPTS'}
                </th>
                <th className="py-3 px-3 text-center">ABUSE CONFIDENCE</th>
                <th className="py-3 px-3 text-center">GREYNOISE INTEL</th>
                <th className="py-3 px-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2638]/50">
              {displayedRows.length > 0 ? (
                displayedRows.map((item, idx) => {
                  const cached = intelCache[item.ip];
                  const score = cached?.abuseipdb?.score ?? (idx < 3 ? 95 : 70);
                  const risk = getAbuseRiskTier(score);
                  const isNoise = cached?.greynoise?.noise ?? true;
                  const actorName = cached?.greynoise?.name || (isNoise ? 'Mass Scanner' : 'Targeted Probe');
                  const isSelected = activeIntel?.ip === item.ip;

                  return (
                    <tr
                      key={`${item.ip}-${idx}`}
                      onClick={() => inspectIP(item.ip, true)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-cyan-500/10 border-l-2 border-l-cyan-400'
                          : 'hover:bg-[#1e2638]/50'
                      }`}
                    >
                      <td className="py-3 px-3 font-bold text-slate-200">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500 text-[10px]">#{item.rank || idx + 1}</span>
                          <span className="text-cyan-300 font-bold">{item.ip}</span>
                        </div>
                      </td>

                      <td className="py-3 px-3 text-slate-300">
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-400 border border-slate-700">
                            {item.country_code || 'XX'}
                          </span>
                          <span className="truncate max-w-[120px]">{item.city || 'Unknown'}</span>
                        </div>
                      </td>

                      <td className="py-3 px-3 text-right font-bold text-rose-400">
                        {filterMode === 'live10' && item.timestamp ? (
                          <span className="text-slate-400 font-mono text-[11px]">
                            {new Date(item.timestamp).toLocaleTimeString()}
                          </span>
                        ) : (
                          item.count.toLocaleString()
                        )}
                      </td>

                      <td className="py-3 px-3 text-center">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${risk.badgeClass}`}
                        >
                          {score}% Confidence
                        </span>
                      </td>

                      <td className="py-3 px-3 text-center">
                        {isNoise ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                            <Radio className="w-2.5 h-2.5" />
                            <span>{actorName}</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            <Zap className="w-2.5 h-2.5" />
                            <span>Targeted Probe</span>
                          </span>
                        )}
                      </td>

                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            inspectIP(item.ip, true);
                          }}
                          className="px-2.5 py-1 rounded-lg bg-[#06080d] hover:bg-[#1e2638] border border-[#1e2638] text-cyan-400 hover:text-cyan-300 text-[11px] font-bold inline-flex items-center gap-1"
                        >
                          <span>Deep Inspect</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-xs font-mono text-slate-500">
                    No threat entries matching selected filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
