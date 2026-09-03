import { useEffect, useRef, useState } from 'react';
import {
  Terminal as TerminalIcon,
  Play,
  Pause,
  RotateCcw,
  RefreshCw,
  Search,
  Server,
  Zap,
  Activity,
  User,
  Clock,
  Sparkles,
} from 'lucide-react';
import { getAuthHeaders } from '../api/client';

interface CommandItem {
  id: string;
  timestamp: string;
  source_ip: string;
  session_id?: string;
  command: string;
}

interface SessionRecordingFrame {
  time_offset_ms: number;
  direction: string;
  data: string;
}

interface SessionRecording {
  id: string;
  filename: string;
  source_ip: string;
  username: string;
  first_seen: string;
  duration_sec: number;
  size_bytes: number;
  command_list: string[];
  frames?: SessionRecordingFrame[];
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export default function TerminalViewer() {
  const [recordings, setRecordings] = useState<SessionRecording[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [activeReplay, setActiveReplay] = useState<SessionRecording | null>(null);
  const [commands, setCommands] = useState<CommandItem[]>([]);
  const [activeMode, setActiveMode] = useState<'replay' | 'live'>('replay');
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(2); // 2x speed by default
  const [currentFrameIdx, setCurrentFrameIdx] = useState(0);
  const [terminalOutput, setTerminalOutput] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const playTimerRef = useRef<NodeJS.Timeout | null>(null);

  // 1. Fetch available recorded sessions and raw commands
  const fetchAllData = () => {
    setIsLoading(true);
    Promise.all([
      fetch(`${API_BASE_URL}/api/v1/telemetry/sessions/recordings`, { headers: { ...getAuthHeaders() } })
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      fetch(`${API_BASE_URL}/api/v1/telemetry/commands`, { headers: { ...getAuthHeaders() } })
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
    ])
      .then(([recData, cmdData]) => {
        if (recData && Array.isArray(recData.items) && recData.items.length > 0) {
          setRecordings(recData.items);
          if (!selectedSessionId) {
            setSelectedSessionId(recData.items[0].id);
          }
        }
        if (cmdData && Array.isArray(cmdData.items)) {
          setCommands(cmdData.items);
        }
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  // 2. Fetch specific session frames when selected
  useEffect(() => {
    if (!selectedSessionId) return;

    setIsPlaying(false);
    setCurrentFrameIdx(0);
    setTerminalOutput('');

    fetch(`${API_BASE_URL}/api/v1/telemetry/sessions/replay?id=${selectedSessionId}`, {
      headers: { ...getAuthHeaders() },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data: SessionRecording | null) => {
        if (data) {
          setActiveReplay(data);
          if (data.frames && data.frames.length > 0) {
            // Render first frame immediately
            setTerminalOutput(data.frames[0].data);
            setCurrentFrameIdx(1);
          }
        }
      })
      .catch((err) => console.warn('Error loading session replay:', err));
  }, [selectedSessionId]);

  // 3. Playback Frame Ticker Loop
  useEffect(() => {
    if (!isPlaying || !activeReplay || !activeReplay.frames || activeReplay.frames.length === 0) {
      if (playTimerRef.current) clearInterval(playTimerRef.current);
      return;
    }

    const frames = activeReplay.frames;

    if (currentFrameIdx >= frames.length) {
      setIsPlaying(false);
      return;
    }

    const currFrame = frames[currentFrameIdx];
    const prevFrame = currentFrameIdx > 0 ? frames[currentFrameIdx - 1] : { time_offset_ms: 0 };
    const rawDelay = Math.max(20, currFrame.time_offset_ms - prevFrame.time_offset_ms);
    const delay = Math.max(30, Math.min(1500, rawDelay / playbackSpeed));

    playTimerRef.current = setTimeout(() => {
      setTerminalOutput((prev) => prev + currFrame.data);
      setCurrentFrameIdx((idx) => idx + 1);
    }, delay);

    return () => {
      if (playTimerRef.current) clearTimeout(playTimerRef.current);
    };
  }, [isPlaying, currentFrameIdx, activeReplay, playbackSpeed]);

  // Auto-scroll to bottom of terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalOutput]);

  const handleRestart = () => {
    setIsPlaying(false);
    setCurrentFrameIdx(0);
    setTerminalOutput(activeReplay?.frames?.[0]?.data || '');
    setTimeout(() => setIsPlaying(true), 150);
  };

  const handlePlayPause = () => {
    if (currentFrameIdx >= (activeReplay?.frames?.length || 0)) {
      handleRestart();
    } else {
      setIsPlaying(!isPlaying);
    }
  };

  const totalFrames = activeReplay?.frames?.length || 1;
  const progressPct = Math.min(100, Math.round((currentFrameIdx / totalFrames) * 100));

  const filteredRecordings = recordings.filter(
    (r) =>
      r.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.command_list && r.command_list.some((c) => c.toLowerCase().includes(searchTerm.toLowerCase())))
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="hud-card p-6 border-l-4 border-l-[#00ff9d]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="p-1.5 rounded-lg bg-[#00ff9d]/10 border border-[#00ff9d]/30 text-[#00ff9d]">
                <TerminalIcon className="w-5 h-5" />
              </span>
              <span className="text-xs font-mono font-bold tracking-widest text-[#00ff9d] uppercase">
                INTERACTIVE FORENSICS &amp; TTY REPLAY
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              Attacker Session Video Replay &amp; Terminal Stream
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 font-mono mt-1">
              Watch authentic recorded botnet sessions step-by-step with typing speeds, command attempts, and live execution streams.
            </p>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveMode('replay')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
                activeMode === 'replay'
                  ? 'bg-[#00ff9d]/20 text-[#00ff9d] border border-[#00ff9d]/40 shadow-[0_0_15px_rgba(0,255,157,0.2)]'
                  : 'bg-[#0d1117] text-slate-400 hover:text-white border border-[#1e2638]'
              }`}
            >
              <Play className="w-3.5 h-3.5" />
              <span>Session Replay ({recordings.length})</span>
            </button>

            <button
              onClick={() => setActiveMode('live')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
                activeMode === 'live'
                  ? 'bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/40 shadow-[0_0_15px_rgba(0,240,255,0.2)]'
                  : 'bg-[#0d1117] text-slate-400 hover:text-white border border-[#1e2638]'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Raw Command Log ({commands.length})</span>
            </button>

            <button
              onClick={fetchAllData}
              disabled={isLoading}
              className="p-2 rounded-xl bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] text-slate-300 hover:text-white transition-all disabled:opacity-50"
              title="Refresh Sessions"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-[#00ff9d]' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {activeMode === 'replay' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Recorded Sessions List */}
          <div className="hud-card p-4 flex flex-col h-[650px]">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#00ff9d]" />
                <h3 className="text-xs font-mono font-bold uppercase text-slate-200">
                  Recorded Sessions ({filteredRecordings.length})
                </h3>
              </div>
            </div>

            {/* Search Input */}
            <div className="relative mb-3">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Filter by IP, user, session..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#06080d] border border-[#1e2638] text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#00ff9d]/40"
              />
            </div>

            {/* Session Items List */}
            <div className="space-y-2 overflow-y-auto flex-1 pr-1">
              {filteredRecordings.length > 0 ? (
                filteredRecordings.map((rec) => {
                  const isSelected = selectedSessionId === rec.id;
                  return (
                    <div
                      key={rec.id}
                      onClick={() => setSelectedSessionId(rec.id)}
                      className={`p-3 rounded-xl border font-mono text-xs cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-[#00ff9d]/10 border-[#00ff9d]/50 text-white shadow-[0_0_15px_rgba(0,255,157,0.15)]'
                          : 'bg-[#06080d]/80 border-[#1e2638] text-slate-300 hover:border-slate-700 hover:bg-[#1e2638]/40'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[11px] mb-1">
                        <span className="font-bold text-cyan-300 truncate max-w-[130px]">
                          {rec.source_ip}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {new Date(rec.first_seen).toLocaleTimeString()}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                        <span className="flex items-center gap-1">
                          <User className="w-3 h-3 text-slate-500" />
                          <span>{rec.username}</span>
                        </span>
                        <span className="text-slate-500">
                          {rec.size_bytes ? `${(rec.size_bytes / 1024).toFixed(1)} KB` : '1.0 KB'}
                        </span>
                      </div>

                      {rec.command_list && rec.command_list.length > 0 && (
                        <div className="p-1 px-2 rounded bg-black/60 border border-[#1e2638] text-[#00ff9d] text-[10px] truncate">
                          $ {rec.command_list[0]}
                        </div>
                      )}
                    </div>
                  );
                })
              ) : (
                <div className="p-8 text-center text-slate-500 font-mono text-xs">
                  No recorded sessions matching criteria.
                </div>
              )}
            </div>
          </div>

          {/* Right 2 Columns: Interactive Terminal Player */}
          <div className="lg:col-span-2 hud-card flex flex-col h-[650px] overflow-hidden border border-[#00ff9d]/30">
            {/* Player Controls Bar */}
            <div className="p-3.5 bg-[#0d1117] border-b border-[#1e2638] flex flex-wrap items-center justify-between gap-3">
              {/* Session Meta */}
              <div className="flex items-center gap-3 font-mono text-xs text-slate-300">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#00ff9d] animate-pulse" />
                  <strong className="text-white">{activeReplay?.source_ip || '140.206.107.98'}</strong>
                </div>
                <span className="text-slate-500 text-[11px]">
                  (user: <code className="text-cyan-300">{activeReplay?.username || 'root'}</code>)
                </span>
              </div>

              {/* VCR Controls */}
              <div className="flex items-center gap-2">
                <button
                  onClick={handlePlayPause}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#00ff9d]/15 hover:bg-[#00ff9d]/25 border border-[#00ff9d]/40 text-[#00ff9d] font-mono text-xs font-bold transition-all"
                >
                  {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{isPlaying ? 'Pause' : currentFrameIdx >= totalFrames ? 'Replay' : 'Play'}</span>
                </button>

                <button
                  onClick={handleRestart}
                  className="p-1.5 rounded-lg bg-[#06080d] hover:bg-[#1e2638] border border-[#1e2638] text-slate-400 hover:text-white transition-all"
                  title="Restart Session"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>

                {/* Speed Selectors */}
                <div className="flex items-center gap-1 bg-[#06080d] p-1 rounded-lg border border-[#1e2638]">
                  {[1, 2, 5, 10].map((s) => (
                    <button
                      key={s}
                      onClick={() => setPlaybackSpeed(s)}
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold transition-all ${
                        playbackSpeed === s
                          ? 'bg-[#00ff9d] text-black'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {s}x
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Progress Scrubber */}
            <div className="w-full bg-[#06080d] h-1 border-b border-[#1e2638]">
              <div
                className="bg-gradient-to-r from-[#00ff9d] to-[#00f0ff] h-full transition-all duration-150"
                style={{ width: `${progressPct}%` }}
              />
            </div>

            {/* Simulated ASCII Terminal Output Window */}
            <div className="flex-1 p-5 overflow-y-auto bg-black font-mono text-xs leading-relaxed text-[#00ff9d] selection:bg-[#00ff9d]/30 selection:text-black">
              <pre className="whitespace-pre-wrap font-mono break-all font-medium text-[12px]">
                {terminalOutput || 'Initializing honeypot session stream...'}
              </pre>
              <div ref={terminalEndRef} />
            </div>

            {/* Terminal Bottom Status */}
            <div className="p-2.5 px-4 bg-[#0d1117] border-t border-[#1e2638] flex items-center justify-between text-[10px] font-mono text-slate-500">
              <div className="flex items-center gap-2">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                <span>Cowrie Decoy Terminal VT100 Emulator</span>
              </div>
              <div className="flex items-center gap-2 text-slate-400">
                <span>Frame: {currentFrameIdx} / {totalFrames}</span>
                <span>•</span>
                <span>Speed: {playbackSpeed}x</span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Mode: Raw Command Log Table */
        <div className="hud-card overflow-hidden">
          <div className="p-4 border-b border-[#1e2638] flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              Raw Attacker Infiltration Commands
            </h3>
            <span className="text-[10px] font-mono text-slate-400">
              {commands.length} total commands logged
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#06080d]/80 text-slate-500 uppercase text-[10px] border-b border-[#1e2638]">
                <tr>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Source IP</th>
                  <th className="p-3">Session ID</th>
                  <th className="p-3">Command Executed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2638]/60 text-slate-300">
                {commands.length > 0 ? (
                  commands.map((c) => (
                    <tr key={c.id} className="hover:bg-[#1e2638]/40 transition-colors">
                      <td className="p-3 text-slate-400 whitespace-nowrap text-[11px]">
                        {new Date(c.timestamp).toLocaleString()}
                      </td>
                      <td className="p-3 font-bold text-cyan-300 whitespace-nowrap">
                        {c.source_ip}
                      </td>
                      <td className="p-3 text-slate-500 whitespace-nowrap text-[10px]">
                        <code>{c.session_id ? c.session_id.slice(0, 10) : 'N/A'}</code>
                      </td>
                      <td className="p-3">
                        <span className="inline-block px-2.5 py-1 rounded bg-[#06080d] border border-[#1e2638] text-[#00ff9d]">
                          $ {c.command}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500">
                      No commands logged yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
