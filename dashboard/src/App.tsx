import { useState } from 'react';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import Globe from './routes/Globe';
import Breaches from './routes/Breaches';
import CapturedAttacks from './routes/CapturedAttacks';
import Payloads from './routes/Payloads';
import TerminalViewer from './routes/TerminalViewer';
import Intel from './routes/Intel';
import ThreatRadar from './routes/ThreatRadar';
import {
  Globe2,
  Terminal,
  Shield,
  FileCode,
  Sliders,
  ChevronLeft,
  ChevronRight,
  Server,
  Zap,
  KeyRound,
  Crosshair,
} from 'lucide-react';
import HoneyTraceLogo from './components/HoneyTraceLogo';
import useTelemetry from './hooks/useTelemetry';

export default function App() {
  const location = useLocation();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const { stats } = useTelemetry();

  const navItems = [
    { path: '/', label: '3D Threat Globe', shortLabel: 'Globe', icon: Globe2 },
    {
      path: '/breaches',
      label: 'Breach Intelligence',
      shortLabel: 'Breaches',
      icon: Zap,
      badge: stats.breach_count > 0 ? stats.breach_count : undefined,
      badgeColor: 'bg-[#ff3366] text-white',
    },
    {
      path: '/wordlist',
      label: 'Wordlist & Shell Scripts',
      shortLabel: 'Wordlist',
      icon: KeyRound,
      badge: 'DICT',
      badgeColor: 'bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/30',
    },
    {
      path: '/radar',
      label: 'Threat Radar (IP Intel)',
      shortLabel: 'Radar',
      icon: Crosshair,
      badge: 'DUAL',
      badgeColor: 'bg-rose-500/20 text-rose-400 border border-rose-500/30',
    },
    { path: '/payloads', label: 'Captured Payloads', shortLabel: 'Payloads', icon: FileCode },
    { path: '/terminal', label: 'Live Terminal', shortLabel: 'Terminal', icon: Terminal },
    { path: '/intel', label: 'Intel Console', shortLabel: 'Intel', icon: Sliders },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#06080d] text-slate-100 font-sans selection:bg-[#00f0ff]/30 selection:text-[#00f0ff]">
      {/* Background Starfield / Matrix Glow */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-950/20 via-[#06080d] to-[#06080d]" />

      {/* Collapsible Glass Cyber Sidebar */}
      <aside
        className={`relative z-40 flex flex-col justify-between h-full bg-[#0d1117]/95 backdrop-blur-xl border-r border-[#1e2638] shadow-2xl transition-all duration-300 select-none ${
          isCollapsed ? 'w-16' : 'w-64'
        }`}
      >
        {/* Top Sidebar Header */}
        <div className="p-3.5 border-b border-[#1e2638] flex items-center justify-between">
          <Link to="/" className="flex items-center overflow-hidden hover:opacity-90 transition-opacity">
            <HoneyTraceLogo size={30} showText={!isCollapsed} />
          </Link>

          {/* Collapse Toggle Button */}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1.5 rounded-lg bg-[#06080d] hover:bg-[#1e2638] border border-[#1e2638] text-slate-400 hover:text-white transition-all flex-shrink-0"
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4 text-[#00f0ff]" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Middle Navigation Menu */}
        <nav className="flex-1 py-4 px-2 space-y-1.5 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;

            return (
              <Link
                key={item.path}
                to={item.path}
                className={`relative flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-mono font-semibold transition-all group ${
                  isActive
                    ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/40 shadow-[0_0_20px_rgba(0,240,255,0.15)]'
                    : 'text-slate-400 hover:text-white hover:bg-[#1e2638]/50 border border-transparent'
                }`}
                title={isCollapsed ? item.label : undefined}
              >
                <Icon
                  className={`w-5 h-5 flex-shrink-0 transition-transform group-hover:scale-110 ${
                    isActive ? 'text-[#00f0ff]' : 'text-slate-400 group-hover:text-slate-200'
                  }`}
                />
                {!isCollapsed && (
                  <span className="truncate flex-1 font-medium">{item.label}</span>
                )}
                {item.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0.2 rounded-full text-[10px] font-bold ${item.badgeColor} ${
                      isCollapsed ? 'absolute top-1 right-1' : ''
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Bottom Sensor Health Status Card */}
        <div className="p-3 border-t border-[#1e2638] font-mono text-xs text-slate-400">
          {!isCollapsed ? (
            <div className="p-2.5 rounded-xl bg-[#06080d]/80 border border-[#1e2638] space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <Server className="w-3.5 h-3.5 text-[#00ff9d]" />
                  <span>AWS EC2</span>
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30">
                  ONLINE
                </span>
              </div>
              <div className="text-[10px] text-slate-500 truncate">
                Node: <span className="text-slate-400">Mumbai (ap-south-1)</span>
              </div>
            </div>
          ) : (
            <div className="flex justify-center" title="Sensor Active: AWS EC2 Mumbai">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff9d] opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-[#00ff9d]" />
              </span>
            </div>
          )}
        </div>
      </aside>

      {/* Main Full-Screen Content View */}
      <main className="relative flex-1 h-full overflow-y-auto overflow-x-hidden p-4 sm:p-6">
        <Routes>
          <Route path="/" element={<Globe />} />
          <Route path="/breaches" element={<Breaches />} />
          <Route path="/wordlist" element={<CapturedAttacks />} />
          <Route path="/radar" element={<ThreatRadar />} />
          <Route path="/payloads" element={<Payloads />} />
          <Route path="/terminal" element={<TerminalViewer />} />
          <Route path="/intel" element={<Intel />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
