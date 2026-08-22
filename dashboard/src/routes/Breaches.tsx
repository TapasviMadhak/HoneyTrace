import { useEffect, useState } from 'react';
import { ShieldAlert, AlertOctagon, Clock, Terminal, Globe, KeyRound, RefreshCw, CheckCircle2 } from 'lucide-react';
import AbuseBadge from '../components/AbuseBadge';

interface BreachSession {
  session_id: string;
  source_ip: string;
  username: string;
  password: string;
  first_seen: string;
  last_seen: string;
  duration_sec: number;
  command_count: number;
  country_code?: string;
  city?: string;
}

interface BreachesData {
  breach_count: number;
  breach_status: boolean;
  items: BreachSession[];
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export default function Breaches() {
  const [data, setData] = useState<BreachesData>({
    breach_count: 0,
    breach_status: false,
    items: [],
  });
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchBreaches = () => {
    setLoading(true);
    fetch(`${API_BASE_URL}/api/v1/telemetry/breaches`)
      .then((res) => (res.ok ? res.json() : null))
      .then((resData: BreachesData | null) => {
        if (resData) {
          setData({
            breach_count: resData.breach_count || 0,
            breach_status: resData.breach_status || false,
            items: Array.isArray(resData.items) ? resData.items : [],
          });
        }
      })
      .catch((err) => console.warn('Breaches fetch warning:', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchBreaches();
    const timer = setInterval(fetchBreaches, 15000);
    return () => clearInterval(timer);
  }, []);

  const filteredItems = data.items.filter(
    (item) =>
      item.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.session_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (item.city && item.city.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div className="space-y-6 w-full">
      {/* Header Banner */}
      <div className="relative rounded-3xl p-6 sm:p-8 bg-slate-900/60 border border-slate-700/50 shadow-2xl backdrop-blur-xl overflow-hidden">
        <div className="absolute -top-24 -left-24 w-96 h-96 bg-rose-500/15 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-rose-500/10 border border-rose-400/30 text-rose-300 text-xs font-mono font-semibold uppercase tracking-wider">
                Honeypot Infiltrations
              </span>
              <span className={`flex items-center gap-1 text-xs font-mono ${data.breach_status ? 'text-rose-400 font-bold' : 'text-emerald-400'}`}>
                {data.breach_status ? (
                  <>
                    <AlertOctagon className="w-3.5 h-3.5 animate-pulse" />
                    <span>Active Breach Activity Detected</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>No Infiltrations Recorded</span>
                  </>
                )}
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Attacker Infiltration &amp; Session Duration Tracker
            </h1>
            <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
              When an attacker successfully authenticates against decoy credentials (<code className="text-rose-300 bg-slate-800 px-1 py-0.5 rounded text-xs">cowrie.login.success</code>),
              their session is isolated, timing is benchmarked, and command activity is strictly monitored.
            </p>
          </div>

          <button
            onClick={fetchBreaches}
            disabled={loading}
            className="self-start lg:self-auto p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 active:scale-95 transition-all text-slate-200 flex items-center gap-2 border border-slate-700"
          >
            <RefreshCw className={`w-4 h-4 text-rose-400 ${loading ? 'animate-spin' : ''}`} />
            <span className="text-xs font-mono text-slate-300">Sync Breaches</span>
          </button>
        </div>

        {/* Metrics Row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-6 pt-6 border-t border-slate-800">
          <div className="p-4 rounded-2xl bg-slate-950/50 border border-slate-800/80 flex items-center gap-4">
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xs font-mono uppercase text-slate-400 block">Total Breached Sessions</span>
              <strong className="text-2xl font-black text-white font-mono">{data.breach_count}</strong>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-950/50 border border-slate-800/80 flex items-center gap-4">
            <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <KeyRound className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xs font-mono uppercase text-slate-400 block">Decoy Auth Successes</span>
              <strong className="text-2xl font-black text-white font-mono">{data.items.length}</strong>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-950/50 border border-slate-800/80 flex items-center gap-4">
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Terminal className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xs font-mono uppercase text-slate-400 block">Commands Post-Infiltration</span>
              <strong className="text-2xl font-black text-white font-mono">
                {data.items.reduce((acc, curr) => acc + (curr.command_count || 0), 0)}
              </strong>
            </div>
          </div>
        </div>
      </div>

      {/* Filter / Search */}
      <div className="flex items-center justify-between gap-4">
        <input
          type="text"
          placeholder="Filter by IP, username, session ID, or location..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full max-w-md px-4 py-2.5 rounded-xl bg-slate-900/80 border border-slate-700/60 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-400"
        />
        <span className="text-xs font-mono text-slate-400 whitespace-nowrap">
          Showing {filteredItems.length} of {data.items.length} Breaches
        </span>
      </div>

      {/* Breached Sessions Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredItems.length > 0 ? (
          filteredItems.map((sess) => (
            <div
              key={sess.session_id}
              className="p-5 rounded-2xl bg-slate-900/60 border border-rose-500/30 hover:border-rose-500/60 transition-all shadow-xl backdrop-blur-xl space-y-4"
            >
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[10px] font-mono font-bold uppercase">
                  BREACH ISOLATED
                </span>
                <span className="text-xs font-mono text-slate-400">
                  {sess.first_seen ? new Date(sess.first_seen).toLocaleTimeString() : 'N/A'}
                </span>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <strong className="text-sm font-mono text-white">{sess.source_ip}</strong>
                    {sess.city && (
                      <span className="text-xs text-slate-400">({sess.city}, {sess.country_code})</span>
                    )}
                  </div>
                  <AbuseBadge ip={sess.source_ip} />
                </div>
                <div className="text-xs font-mono text-slate-300">
                  auth: <code className="bg-slate-800 px-1.5 py-0.5 rounded text-emerald-400">{sess.username}</code>:<code>{sess.password || '***'}</code>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-1.5 text-slate-400">
                  <Clock className="w-3.5 h-3.5 text-amber-400" />
                  <span>{sess.duration_sec}s in honeypot</span>
                </div>
                <div className="flex items-center gap-1.5 text-cyan-300 font-bold">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>{sess.command_count} commands</span>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="col-span-full p-8 rounded-2xl bg-slate-900/40 border border-slate-800 text-center text-slate-400 font-mono text-xs">
            No honeypot infiltration breaches recorded yet. Waiting for decoy login events...
          </div>
        )}
      </div>
    </div>
  );
}
