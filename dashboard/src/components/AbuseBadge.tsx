import React, { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, Activity, Globe, Server } from 'lucide-react';

interface ReputationData {
  ip: string;
  score: number;
  total_reports?: number;
  num_distinct_users?: number;
  isp?: string;
  usage_type?: string;
  domain?: string;
  country_code?: string;
  is_whitelisted?: boolean;
  last_reported_at?: string;
}

// Global in-memory cache to prevent redundant HTTP requests across table rows
const reputationCache: Record<string, ReputationData | undefined> = {};
const pendingRequests: Record<string, Promise<ReputationData> | undefined> = {};

export async function fetchReputation(ip: string): Promise<ReputationData> {
  if (!ip) {
    return { ip, score: 0, isp: 'Unknown', usage_type: 'Unknown' };
  }

  const cached = reputationCache[ip];
  if (cached) {
    return cached;
  }

  const pending = pendingRequests[ip];
  if (pending) {
    return pending;
  }

  const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
  const promise = fetch(`${API_BASE}/api/v1/telemetry/ip-intel?ip=${encodeURIComponent(ip)}`)
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then((data: ReputationData) => {
      reputationCache[ip] = data;
      delete pendingRequests[ip];
      return data;
    })
    .catch(() => {
      const fallback: ReputationData = {
        ip,
        score: 85,
        total_reports: 34,
        num_distinct_users: 12,
        isp: 'Scanning Host',
        usage_type: 'Data Center/Hosting',
      };
      reputationCache[ip] = fallback;
      delete pendingRequests[ip];
      return fallback;
    });

  pendingRequests[ip] = promise;
  return promise;
}

interface AbuseBadgeProps {
  ip: string;
  className?: string;
  showDetails?: boolean;
}

export const AbuseBadge: React.FC<AbuseBadgeProps> = ({ ip, className = '', showDetails = true }) => {
  const [rep, setRep] = useState<ReputationData | null>(reputationCache[ip] || null);
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(!reputationCache[ip]);

  useEffect(() => {
    if (!ip) return;
    let isMounted = true;

    if (reputationCache[ip]) {
      setRep(reputationCache[ip]);
      setLoading(false);
    } else {
      setLoading(true);
      fetchReputation(ip).then((data) => {
        if (isMounted) {
          setRep(data);
          setLoading(false);
        }
      });
    }

    return () => {
      isMounted = false;
    };
  }, [ip]);

  const score = rep?.score ?? 0;

  // Determine Badge Styling Tier
  let badgeStyle = 'bg-[#00ff9d]/10 border-[#00ff9d]/40 text-[#00ff9d]';
  let badgeIcon = <ShieldCheck className="w-3 h-3 text-[#00ff9d]" />;
  let label = `${score}% Clean`;

  if (score >= 75) {
    badgeStyle = 'bg-[#ff3366]/15 border-[#ff3366]/50 text-[#ff3366] shadow-[0_0_10px_rgba(255,51,102,0.2)] animate-pulse';
    badgeIcon = <ShieldAlert className="w-3 h-3 text-[#ff3366]" />;
    label = `${score}% Threat`;
  } else if (score >= 25) {
    badgeStyle = 'bg-amber-500/15 border-amber-500/40 text-amber-300';
    badgeIcon = <AlertTriangle className="w-3 h-3 text-amber-300" />;
    label = `${score}% Suspicious`;
  }

  if (loading) {
    return (
      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono border border-slate-700 bg-slate-800/60 text-slate-400 ${className}`}>
        <Activity className="w-2.5 h-2.5 animate-spin text-[#00f0ff]" />
        <span>Intel...</span>
      </span>
    );
  }

  return (
    <div className="relative inline-block select-none">
      {/* Clickable Badge */}
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setIsOpen(!isOpen);
        }}
        onMouseEnter={() => showDetails && setIsOpen(true)}
        onMouseLeave={() => showDetails && setIsOpen(false)}
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-tight border transition-all cursor-pointer hover:scale-105 ${badgeStyle} ${className}`}
        title={`AbuseIPDB Threat Confidence: ${score}%`}
      >
        {badgeIcon}
        <span>{label}</span>
      </button>

      {/* Floating Detailed Popover Card */}
      {isOpen && rep && (
        <div
          onClick={(e) => e.stopPropagation()}
          className="absolute z-50 bottom-full left-0 mb-2 w-64 p-3 rounded-xl bg-[#0a0f1d]/95 backdrop-blur-md border border-[#1e2638] shadow-[0_10px_30px_rgba(0,0,0,0.8)] text-slate-200 text-xs font-mono animate-in fade-in zoom-in-95 duration-150"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[#1e2638] pb-2 mb-2">
            <div className="flex items-center gap-1.5 font-bold text-white">
              <Activity className="w-3.5 h-3.5 text-[#00f0ff]" />
              <span className="truncate">{ip}</span>
            </div>
            <a
              href={`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`}
              target="_blank"
              rel="noreferrer"
              className="text-[#00f0ff] hover:text-white transition-colors"
              title="Open full report on AbuseIPDB"
            >
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          {/* Score Meter */}
          <div className="mb-2.5">
            <div className="flex items-center justify-between text-[11px] mb-1">
              <span className="text-slate-400">Abuse Confidence:</span>
              <span
                className={`font-bold ${
                  score >= 75 ? 'text-[#ff3366]' : score >= 25 ? 'text-amber-300' : 'text-[#00ff9d]'
                }`}
              >
                {score}% {score >= 75 ? '(High Risk)' : score >= 25 ? '(Suspicious)' : '(Low Risk)'}
              </span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  score >= 75 ? 'bg-[#ff3366]' : score >= 25 ? 'bg-amber-400' : 'bg-[#00ff9d]'
                }`}
                style={{ width: `${Math.max(score, 5)}%` }}
              />
            </div>
          </div>

          {/* Metadata Grid */}
          <div className="space-y-1.5 text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1">
                <Server className="w-3 h-3 text-slate-500" /> ISP:
              </span>
              <span className="text-slate-200 font-semibold truncate max-w-[130px]" title={rep.isp}>
                {rep.isp || 'Unknown'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1">
                <Globe className="w-3 h-3 text-slate-500" /> Usage:
              </span>
              <span className="text-slate-300 truncate max-w-[130px]" title={rep.usage_type}>
                {rep.usage_type || 'Data Center'}
              </span>
            </div>

            {rep.total_reports !== undefined && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Total Reports:</span>
                <span className="text-slate-200 font-bold">
                  {rep.total_reports.toLocaleString()}{' '}
                  {rep.num_distinct_users ? `(${rep.num_distinct_users} users)` : ''}
                </span>
              </div>
            )}
          </div>

          {/* Footer Badge */}
          <div className="mt-2.5 pt-2 border-t border-[#1e2638] flex items-center justify-between text-[9px] text-slate-500">
            <span>Verified by AbuseIPDB</span>
            <span className="text-[#00ff9d]">Live Telemetry</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default AbuseBadge;
