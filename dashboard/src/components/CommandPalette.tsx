import { Command, Zap, Search, Shield, Cpu, RefreshCw } from 'lucide-react';

const commands = [
  { label: 'Inspect Ingress Hit', icon: Search },
  { label: 'Jump to Threat Actor', icon: Shield },
  { label: 'Run LLM Triage', icon: Zap },
  { label: 'Flush Cache & Sync', icon: RefreshCw },
];

export default function CommandPalette() {
  return (
    <section className="p-6 rounded-3xl bg-slate-900/60 border border-slate-700/50 shadow-xl backdrop-blur-xl space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider">
            <Command className="w-3.5 h-3.5" />
            <span>Fast Actions</span>
          </div>
          <h3 className="text-base font-bold text-white tracking-tight mt-0.5">
            Command Palette
          </h3>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        {commands.map((cmd) => {
          const Icon = cmd.icon;
          return (
            <button
              key={cmd.label}
              type="button"
              className="flex items-center gap-2.5 p-3 rounded-2xl bg-slate-950/50 border border-slate-800/80 hover:border-cyan-500/40 hover:bg-slate-800/50 text-slate-300 hover:text-cyan-300 text-xs font-medium transition-all text-left group"
            >
              <Icon className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition-colors" />
              <span>{cmd.label}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
