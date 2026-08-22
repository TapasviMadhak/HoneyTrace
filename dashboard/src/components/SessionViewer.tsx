import { useEffect, useState } from 'react';
import { Terminal, Clock, ShieldCheck, AlertTriangle } from 'lucide-react';

interface SessionItem {
  id: string;
  event_id?: string;
  title: string;
  summary: string;
  updated_at?: string;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

const DEFAULT_SESSIONS: SessionItem[] = [
  {
    id: 'sess-1042',
    title: 'SSH Brute-Force Wave',
    summary: 'High-frequency credential stuffing against root and admin accounts. Mapped to T1110.',
    updated_at: '2m ago',
  },
  {
    id: 'sess-1043',
    title: 'Network Port & Banner Probe',
    summary: 'Attacker performed SSH banner handshake followed by disconnect without auth payload.',
    updated_at: '6m ago',
  },
];

export default function SessionViewer() {
  const [sessions, setSessions] = useState<SessionItem[]>(DEFAULT_SESSIONS);

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/v1/sessions`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { items: SessionItem[] } | null) => {
        if (data && data.items && data.items.length > 0) {
          setSessions(data.items.slice(0, 4));
        }
      })
      .catch(() => {
        // Fallback to default
      });
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider">
            <Terminal className="w-3.5 h-3.5" />
            <span>Analyst Triage Feed</span>
          </div>
          <h3 className="text-base font-bold text-white tracking-tight mt-0.5">
            Active Honeypot Sessions
          </h3>
        </div>
        <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 text-emerald-400 font-mono flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Live
        </span>
      </div>

      <div className="space-y-3">
        {sessions.map((session) => (
          <article
            key={session.id}
            className="p-3.5 rounded-2xl bg-slate-950/50 border border-slate-800/80 hover:border-slate-700 transition-all space-y-2"
          >
            <div className="flex items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-1.5 font-bold text-slate-200">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span>{session.title}</span>
              </div>
              <span className="font-mono text-[11px] text-cyan-400 bg-cyan-950/60 border border-cyan-500/20 px-1.5 py-0.5 rounded">
                {session.id}
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">{session.summary}</p>
          </article>
        ))}
      </div>
    </div>
  );
}
