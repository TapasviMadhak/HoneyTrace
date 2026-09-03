import { useState, useEffect } from 'react';
import { Sliders, Cpu, HardDrive, ShieldCheck, Key, Check } from 'lucide-react';

export default function SettingsPanel() {
  const [apiKey, setApiKey] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const existing = localStorage.getItem('honeytrace_api_key') || '';
    setApiKey(existing);
  }, []);

  const handleSaveKey = () => {
    localStorage.setItem('honeytrace_api_key', apiKey.trim());
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <section className="p-6 rounded-3xl bg-slate-900/60 border border-slate-700/50 shadow-xl backdrop-blur-xl space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider">
            <Sliders className="w-3.5 h-3.5" />
            <span>Config &amp; Feeds</span>
          </div>
          <h3 className="text-base font-bold text-white tracking-tight mt-0.5">
            System &amp; Security Controls
          </h3>
        </div>
      </div>

      <div className="space-y-3">
        {/* HoneyTrace Master API Key */}
        <div className="space-y-1.5">
          <label className="flex items-center justify-between text-xs font-medium text-slate-300">
            <span className="flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-amber-400" />
              <span>Operator API Key</span>
            </span>
            {saved && (
              <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                <Check className="w-3 h-3" /> Saved
              </span>
            )}
          </label>
          <div className="flex gap-2">
            <input
              type="password"
              placeholder="Enter HONEYTRACE_API_KEY for privileged actions..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="flex-1 px-3.5 py-2 rounded-xl bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-amber-500/50"
            />
            <button
              onClick={handleSaveKey}
              className="px-3 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 text-xs font-mono font-bold transition-all"
            >
              Save
            </button>
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="flex items-center gap-1.5 text-xs font-medium text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>LLM Triage Engine</span>
          </label>
          <input
            type="text"
            value="Groq Llama-3.3 70B Versatile"
            readOnly
            className="w-full px-3.5 py-2 rounded-xl bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none"
          />
        </div>

        <div className="space-y-1.5">
          <label className="flex items-center gap-1.5 text-xs font-medium text-slate-300">
            <HardDrive className="w-3.5 h-3.5 text-emerald-400" />
            <span>Triaged Event Cache</span>
          </label>
          <input
            type="text"
            value="SQLite WAL (24-hour TTL)"
            readOnly
            className="w-full px-3.5 py-2 rounded-xl bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none"
          />
        </div>

        <div className="space-y-1.5">
          <label className="flex items-center gap-1.5 text-xs font-medium text-slate-300">
            <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
            <span>Threat Intelligence Feeds</span>
          </label>
          <input
            type="text"
            value="MaxMind GeoLite2, AbuseIPDB, GreyNoise"
            readOnly
            className="w-full px-3.5 py-2 rounded-xl bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none"
          />
        </div>
      </div>
    </section>
  );
}
