import { Sliders, Cpu, HardDrive, ShieldCheck } from 'lucide-react';

export default function SettingsPanel() {
  return (
    <section className="p-6 rounded-3xl bg-slate-900/60 border border-slate-700/50 shadow-xl backdrop-blur-xl space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider">
            <Sliders className="w-3.5 h-3.5" />
            <span>Config &amp; Feeds</span>
          </div>
          <h3 className="text-base font-bold text-white tracking-tight mt-0.5">
            System Controls
          </h3>
        </div>
      </div>

      <div className="space-y-3">
        <div className="space-y-1.5">
          <label className="flex items-center gap-1.5 text-xs font-medium text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>LLM Triage Engine</span>
          </label>
          <input
            type="text"
            value="Gemini 1.5 Flash / Groq Llama-3"
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
            value="MaxMind GeoLite2, AlienVault OTX, AbuseIPDB"
            readOnly
            className="w-full px-3.5 py-2 rounded-xl bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none"
          />
        </div>
      </div>
    </section>
  );
}
