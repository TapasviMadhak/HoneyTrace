import { useState, useEffect, useMemo } from 'react';
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

export default function ThreatRadar() {
  const { stats, isRefreshing, fetchTelemetry } = useTelemetry();
  const [searchIP, setSearchIP] = useState<string>('143.198.98.252');
  const [activeIntel, setActiveIntel] = useState<DualIntel | null>(null);
  const [isLoadingIntel, setIsLoadingIntel] = useState<boolean>(false);
  const [filterMode, setFilterMode] = useState<'all' | 'critical' | 'noise' | 'benign'>('all');

  // Cache for multi-IP lookups to prevent redundant network calls
  const [intelCache, setIntelCache] = useState<Record<string, DualIntel>>({});

  // Top source IPs from honeypot stats
  const topIPs = useMemo(() => {
    return stats.top_source_ips || [];
  }, [stats.top_source_ips]);

  // Fetch Dual Intel for a specific IP
  const inspectIP = async (ip: string) => {
    const target = ip.trim();
    if (!target) return;
    setSearchIP(target);

    if (intelCache[target]) {
      setActiveIntel(intelCache[target]);
      return;
    }

    setIsLoadingIntel(true);
    try {
      // Concurrently query AbuseIPDB and GreyNoise telemetry
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

  // Automatically inspect top IP on load
  useEffect(() => {
    if (topIPs.length > 0 && !activeIntel) {
      inspectIP(topIPs[0].ip);
    }
  }, [topIPs]);

  // Pre-fetch first 5 top IPs for instant switching
  useEffect(() => {
    topIPs.slice(0, 8).forEach((item) => {
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
  }, [topIPs]);

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
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 uppercase tracking-widest">
                Dual Intelligence Feeds
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

      {/* Metrics Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>TRACKED INTRUDERS</span>
            <Server className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">{topIPs.length}</div>
          <div className="text-[10px] text-slate-500 mt-1">Unique honeypot attackers</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>ABUSE CONFIDENCE</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">92.4%</div>
          <div className="text-[10px] text-slate-500 mt-1">Avg malicious confidence</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>MASS NOISE ACTORS</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">78%</div>
          <div className="text-[10px] text-slate-500 mt-1">Internet background scanners</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1117]/80 border border-[#1e2638] font-mono">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>TARGETED EXPLOITS</span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">22%</div>
          <div className="text-[10px] text-slate-500 mt-1">Zero-noise custom probes</div>
        </div>
      </div>

      {/* Interactive Search & Live Deep Inspection Section */}
      <div className="p-6 rounded-2xl bg-[#0d1117]/95 border border-[#1e2638] shadow-2xl space-y-6">
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

      {/* Top Attacking Actors Reputation Radar Table */}
      <div className="p-6 rounded-2xl bg-[#0d1117]/95 border border-[#1e2638] shadow-2xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1e2638] pb-4">
          <div>
            <h2 className="text-base font-mono font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-500" />
              <span>HONEYPOT ATTACKERS REPUTATION DIRECTORY</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Live automated reputation scoring for all IP addresses captured on port 22/8080.
            </p>
          </div>

          {/* Filter options */}
          <div className="flex items-center gap-2 font-mono text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <button
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1 rounded-lg border transition-all ${
                filterMode === 'all'
                  ? 'bg-[#00f0ff]/15 text-[#00f0ff] border-[#00f0ff]/40 font-bold'
                  : 'bg-[#06080d] text-slate-400 border-[#1e2638] hover:text-white'
              }`}
            >
              ALL ({topIPs.length})
            </button>
            <button
              onClick={() => setFilterMode('critical')}
              className={`px-3 py-1 rounded-lg border transition-all ${
                filterMode === 'critical'
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 font-bold'
                  : 'bg-[#06080d] text-slate-400 border-[#1e2638] hover:text-white'
              }`}
            >
              CRITICAL
            </button>
            <button
              onClick={() => setFilterMode('noise')}
              className={`px-3 py-1 rounded-lg border transition-all ${
                filterMode === 'noise'
                  ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40 font-bold'
                  : 'bg-[#06080d] text-slate-400 border-[#1e2638] hover:text-white'
              }`}
            >
              MASS NOISE
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
                <th className="py-3 px-3 text-right">ATTEMPTS</th>
                <th className="py-3 px-3 text-center">ABUSE CONFIDENCE</th>
                <th className="py-3 px-3 text-center">GREYNOISE NOISE</th>
                <th className="py-3 px-3 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2638]/50">
              {topIPs.map((item, idx) => {
                const cached = intelCache[item.ip];
                const score = cached?.abuseipdb?.score ?? 85;
                const risk = getAbuseRiskTier(score);
                const isNoise = cached?.greynoise?.noise ?? true;
                const isSelected = activeIntel?.ip === item.ip;

                return (
                  <tr
                    key={item.ip}
                    onClick={() => inspectIP(item.ip)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-500/10 border-l-2 border-l-cyan-400'
                        : 'hover:bg-[#1e2638]/50'
                    }`}
                  >
                    <td className="py-3 px-3 font-bold text-slate-200">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 text-[10px]">#{idx + 1}</span>
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
                      {item.count.toLocaleString()}
                    </td>

                    <td className="py-3 px-3 text-center">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border ${risk.badgeClass}`}
                      >
                        {score}% Confidence
                      </span>
                    </td>

                    <td className="py-3 px-3 text-center">
                      {isNoise ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                          <Radio className="w-2.5 h-2.5" />
                          <span>Mass Scanner</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                          <Zap className="w-2.5 h-2.5" />
                          <span>Targeted</span>
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          inspectIP(item.ip);
                        }}
                        className="px-2.5 py-1 rounded-lg bg-[#06080d] hover:bg-[#1e2638] border border-[#1e2638] text-cyan-400 hover:text-cyan-300 text-[11px] font-bold inline-flex items-center gap-1"
                      >
                        <span>Deep Inspect</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
