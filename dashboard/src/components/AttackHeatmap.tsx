import { ShieldAlert, Layers } from 'lucide-react';

const techniqueRows = [
  { id: 'T1110', name: 'Brute Force / Password Guessing', score: 94, severity: 'CRITICAL', color: 'from-rose-500 to-amber-500' },
  { id: 'T1046', name: 'Network Service Scanning', score: 78, severity: 'HIGH', color: 'from-cyan-500 to-blue-500' },
  { id: 'T1190', name: 'Exploit Public-Facing Service', score: 52, severity: 'MEDIUM', color: 'from-purple-500 to-rose-500' },
  { id: 'T1059', name: 'Command & Scripting Interpreter', score: 38, severity: 'MEDIUM', color: 'from-emerald-500 to-cyan-500' },
  { id: 'T1090', name: 'Proxy / Direct-TCPIP Tunneling', score: 24, severity: 'LOW', color: 'from-blue-500 to-indigo-500' },
];

export default function AttackHeatmap() {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider">
            <Layers className="w-3.5 h-3.5" />
            <span>MITRE ATT&amp;CK Coverage</span>
          </div>
          <h3 className="text-base font-bold text-white tracking-tight mt-0.5">
            Technique Distribution
          </h3>
        </div>
        <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
          5 Techniques
        </span>
      </div>

      <div className="space-y-3">
        {techniqueRows.map((row) => (
          <div key={row.id} className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-slate-200 bg-slate-800 px-1.5 py-0.5 rounded">
                  {row.id}
                </span>
                <span className="text-slate-300 font-medium truncate max-w-[200px] sm:max-w-none">
                  {row.name}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400">
                  {row.severity}
                </span>
                <span className="font-mono text-cyan-400 font-bold">{row.score}%</span>
              </div>
            </div>
            <div className="w-full h-1.5 rounded-full bg-slate-800/80 overflow-hidden">
              <div
                className={`h-full rounded-full bg-gradient-to-r ${row.color} transition-all duration-700`}
                style={{ width: `${row.score}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
