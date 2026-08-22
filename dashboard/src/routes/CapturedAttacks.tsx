import { useEffect, useState } from 'react';
import {
  KeyRound,
  Download,
  Eye,
  Copy,
  Check,
  Terminal,
  FileCode,
  Search,
  RefreshCw,
  Zap,
  Shield,
  FileText,
} from 'lucide-react';

interface WordlistSummary {
  total_unique_passwords: number;
  total_unique_users: number;
  top_passwords: string[];
}

interface CommandItem {
  id: string;
  timestamp: string;
  source_ip: string;
  session_id: string;
  command: string;
}

interface PayloadItem {
  id: string;
  timestamp: string;
  source_ip: string;
  session_id?: string;
  url?: string;
  sha256?: string;
  file_path?: string;
  size_bytes: number;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export default function CapturedAttacks() {
  const [wordlistSummary, setWordlistSummary] = useState<WordlistSummary>({
    total_unique_passwords: 0,
    total_unique_users: 0,
    top_passwords: [],
  });
  const [commands, setCommands] = useState<CommandItem[]>([]);
  const [payloads, setPayloads] = useState<PayloadItem[]>([]);
  const [fullWordlist, setFullWordlist] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [wordlistSearch, setWordlistSearch] = useState('');
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'commands' | 'payloads' | 'wordlist'>('commands');

  const fetchData = () => {
    setIsLoading(true);
    Promise.all([
      fetch(`${API_BASE_URL}/api/v1/telemetry/wordlist/summary`)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      fetch(`${API_BASE_URL}/api/v1/telemetry/commands`)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      fetch(`${API_BASE_URL}/api/v1/telemetry/payloads`)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
    ])
      .then(([summaryData, cmdData, payloadData]) => {
        if (summaryData) {
          setWordlistSummary(summaryData);
        }
        if (cmdData && Array.isArray(cmdData.items)) {
          setCommands(cmdData.items);
        }
        if (payloadData && Array.isArray(payloadData.items)) {
          setPayloads(payloadData.items);
        }
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  useEffect(() => {
    fetchData();
  }, []);

  const openWordlistModal = () => {
    setIsModalOpen(true);
    if (fullWordlist.length === 0) {
      fetch(`${API_BASE_URL}/api/v1/telemetry/wordlist/download`)
        .then((res) => (res.ok ? res.text() : ''))
        .then((text) => {
          const lines = text
            .split('\n')
            .map((l) => l.trim())
            .filter((l) => l.length > 0);
          setFullWordlist(lines);
        })
        .catch(() => {});
    }
  };

  const handleCopyWordlist = () => {
    const textToCopy = fullWordlist.join('\n');
    navigator.clipboard.writeText(textToCopy).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const filteredCommands = commands.filter(
    (c) =>
      c.command.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.source_ip.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredPayloads = payloads.filter(
    (p) =>
      (p.url && p.url.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (p.sha256 && p.sha256.toLowerCase().includes(searchTerm.toLowerCase())) ||
      p.source_ip.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredWordlist = fullWordlist.filter((w) =>
    w.toLowerCase().includes(wordlistSearch.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Header & Stat Badges */}
      <div className="hud-card p-6 border-l-4 border-l-[#00f0ff]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="p-1.5 rounded-lg bg-[#00f0ff]/10 border border-[#00f0ff]/30 text-[#00f0ff]">
                <KeyRound className="w-5 h-5" />
              </span>
              <span className="text-xs font-mono font-bold tracking-widest text-[#00f0ff] uppercase">
                DYNAMIC ATTACKER WORDLIST &amp; EXECUTION INTEL
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              Botnet Password Dictionary &amp; Shell Artifacts
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 font-mono mt-1">
              Live harvested credential dictionary and post-exploitation shell command logs captured directly from bot probes.
            </p>
          </div>

          {/* Action CTAs */}
          <div className="flex flex-wrap items-center gap-3">
            <a
              href={`${API_BASE_URL}/api/v1/telemetry/wordlist/download`}
              download="honeytrace-attacker-passwords.txt"
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-[#00f0ff]/20 to-[#00ff9d]/20 hover:from-[#00f0ff]/30 hover:to-[#00ff9d]/30 border border-[#00f0ff]/50 text-white font-mono text-xs font-bold shadow-[0_0_20px_rgba(0,240,255,0.2)] transition-all hover:scale-105"
            >
              <Download className="w-4 h-4 text-[#00ff9d]" />
              <span>Download Wordlist (.txt)</span>
            </a>

            <button
              onClick={openWordlistModal}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] hover:border-[#00f0ff]/40 text-slate-200 font-mono text-xs font-semibold transition-all"
            >
              <Eye className="w-4 h-4 text-[#00f0ff]" />
              <span>Inspect Dictionary</span>
            </button>

            <button
              onClick={fetchData}
              disabled={isLoading}
              className="p-2.5 rounded-xl bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] text-slate-300 hover:text-white transition-all disabled:opacity-50"
              title="Refresh Intel"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-[#00f0ff]' : ''}`} />
            </button>
          </div>
        </div>

        {/* Credential Counters Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-6 pt-6 border-t border-[#1e2638]">
          <div className="p-3.5 rounded-xl bg-[#06080d]/80 border border-[#1e2638]">
            <div className="flex items-center justify-between text-slate-400 font-mono text-xs mb-1">
              <span className="flex items-center gap-1.5">
                <KeyRound className="w-4 h-4 text-[#00f0ff]" />
                <span>Captured Passwords</span>
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30">
                DISTINCT
              </span>
            </div>
            <div className="text-2xl font-mono font-black text-white">
              {wordlistSummary.total_unique_passwords.toLocaleString()}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#06080d]/80 border border-[#1e2638]">
            <div className="flex items-center justify-between text-slate-400 font-mono text-xs mb-1">
              <span className="flex items-center gap-1.5">
                <Shield className="w-4 h-4 text-[#00ff9d]" />
                <span>Target Usernames</span>
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30">
                SPRAYED
              </span>
            </div>
            <div className="text-2xl font-mono font-black text-[#00ff9d]">
              {wordlistSummary.total_unique_users.toLocaleString()}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#06080d]/80 border border-[#1e2638]">
            <div className="flex items-center justify-between text-slate-400 font-mono text-xs mb-1">
              <span className="flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-purple-400" />
                <span>Format Standard</span>
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                READY
              </span>
            </div>
            <div className="text-sm font-mono font-bold text-slate-200 mt-1">
              SecLists / John / Hashcat
            </div>
          </div>
        </div>
      </div>

      {/* Tabs Selector & Search Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 p-1 rounded-xl bg-[#0d1117] border border-[#1e2638]">
          <button
            onClick={() => setActiveTab('commands')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-semibold transition-all ${
              activeTab === 'commands'
                ? 'bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Shell Execution Logs ({commands.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('payloads')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-semibold transition-all ${
              activeTab === 'payloads'
                ? 'bg-[#ff3366]/20 text-[#ff3366] border border-[#ff3366]/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Captured Payloads ({payloads.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('wordlist')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-semibold transition-all ${
              activeTab === 'wordlist'
                ? 'bg-[#00ff9d]/20 text-[#00ff9d] border border-[#00ff9d]/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <KeyRound className="w-4 h-4" />
            <span>Top Attempted Passwords</span>
          </button>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search commands, hashes, IPs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#0d1117] border border-[#1e2638] text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#00f0ff]/50 transition-all"
          />
        </div>
      </div>

      {/* Main Tab Content */}
      {activeTab === 'commands' && (
        <div className="hud-card overflow-hidden">
          <div className="p-4 border-b border-[#1e2638] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#00f0ff]" />
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                Attacker Shell Commands Executed During Infiltration
              </h2>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              Showing {filteredCommands.length} command events
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="text-[10px] uppercase text-slate-500 bg-[#06080d]/60 border-b border-[#1e2638]">
                <tr>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Attacker IP</th>
                  <th className="p-3">Session ID</th>
                  <th className="p-3">Command Executed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2638]/60 text-slate-300">
                {filteredCommands.length > 0 ? (
                  filteredCommands.map((c) => (
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
                        <span className="inline-block px-2.5 py-1 rounded bg-[#06080d] border border-[#1e2638] text-[#00ff9d] font-mono text-xs selection:bg-[#00ff9d]/30">
                          $ {c.command}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500 font-mono text-xs">
                      No attacker commands recorded yet. Active bots are currently probing login credentials.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'payloads' && (
        <div className="hud-card overflow-hidden">
          <div className="p-4 border-b border-[#1e2638] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-[#ff3366]" />
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                Captured Malware Binaries &amp; Remote Droppers
              </h2>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              Showing {filteredPayloads.length} payloads
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="text-[10px] uppercase text-slate-500 bg-[#06080d]/60 border-b border-[#1e2638]">
                <tr>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Source IP</th>
                  <th className="p-3">SHA256 Checksum</th>
                  <th className="p-3">Remote URL / Stored Path</th>
                  <th className="p-3 text-right">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2638]/60 text-slate-300">
                {filteredPayloads.length > 0 ? (
                  filteredPayloads.map((p) => (
                    <tr key={p.id} className="hover:bg-[#1e2638]/40 transition-colors">
                      <td className="p-3 text-slate-400 whitespace-nowrap text-[11px]">
                        {new Date(p.timestamp).toLocaleString()}
                      </td>
                      <td className="p-3 font-bold text-[#ff3366] whitespace-nowrap">
                        {p.source_ip}
                      </td>
                      <td className="p-3 font-mono text-xs text-amber-300 truncate max-w-[200px]" title={p.sha256}>
                        {p.sha256 || 'N/A'}
                      </td>
                      <td className="p-3 text-slate-300 truncate max-w-[280px]">
                        {p.url || p.file_path || 'N/A'}
                      </td>
                      <td className="p-3 text-right font-mono text-slate-400">
                        {p.size_bytes ? `${(p.size_bytes / 1024).toFixed(1)} KB` : 'N/A'}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="p-8 text-center text-slate-500 font-mono text-xs">
                      No malware binaries quarantined in this period.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'wordlist' && (
        <div className="hud-card p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-[#00f0ff]" />
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                Top 10 Most Attempted Passwords by Ingress Botnets
              </h2>
            </div>
            <button
              onClick={openWordlistModal}
              className="text-xs font-mono text-[#00f0ff] hover:underline"
            >
              View Full Dictionary ({wordlistSummary.total_unique_passwords}) →
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
            {wordlistSummary.top_passwords.length > 0 ? (
              wordlistSummary.top_passwords.map((pw, i) => (
                <div
                  key={i}
                  className="p-3 rounded-xl bg-[#06080d] border border-[#1e2638] font-mono text-xs space-y-1 hover:border-[#00f0ff]/40 transition-colors"
                >
                  <div className="text-[10px] text-slate-500 font-bold">RANK #{i + 1}</div>
                  <div className="text-sm font-bold text-white truncate" title={pw}>
                    {pw}
                  </div>
                </div>
              ))
            ) : (
              <div className="col-span-5 text-center py-6 text-slate-500 font-mono text-xs">
                Analyzing password distribution...
              </div>
            )}
          </div>
        </div>
      )}

      {/* Inspect Wordlist Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="hud-card max-w-2xl w-full max-h-[85vh] flex flex-col overflow-hidden border border-[#00f0ff]/40 shadow-2xl">
            {/* Modal Header */}
            <div className="p-4 border-b border-[#1e2638] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <KeyRound className="w-5 h-5 text-[#00f0ff]" />
                <div>
                  <h3 className="text-sm font-mono font-bold text-white uppercase">
                    Captured Attacker Wordlist Preview
                  </h3>
                  <div className="text-[10px] font-mono text-slate-400">
                    {fullWordlist.length.toLocaleString()} unique password entries
                  </div>
                </div>
              </div>

              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white font-mono text-sm px-2 py-1"
              >
                ✕
              </button>
            </div>

            {/* Search & Copy Toolbar */}
            <div className="p-3 bg-[#06080d]/80 border-b border-[#1e2638] flex items-center justify-between gap-3">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter dictionary entries..."
                  value={wordlistSearch}
                  onChange={(e) => setWordlistSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#0d1117] border border-[#1e2638] text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#00f0ff]/40"
                />
              </div>

              <button
                onClick={handleCopyWordlist}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 border border-[#00f0ff]/30 text-[#00f0ff] font-mono text-xs font-bold transition-all"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-[#00ff9d]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied!' : 'Copy All'}</span>
              </button>

              <a
                href={`${API_BASE_URL}/api/v1/telemetry/wordlist/download`}
                download="honeytrace-attacker-passwords.txt"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#00ff9d]/10 hover:bg-[#00ff9d]/20 border border-[#00ff9d]/30 text-[#00ff9d] font-mono text-xs font-bold transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Save .txt</span>
              </a>
            </div>

            {/* Wordlist Code Block */}
            <div className="p-4 overflow-y-auto flex-1 bg-[#06080d] font-mono text-xs text-slate-300 divide-y divide-slate-900">
              {filteredWordlist.length > 0 ? (
                filteredWordlist.slice(0, 500).map((pw, idx) => (
                  <div key={idx} className="py-1 px-2 hover:bg-[#1e2638]/40 rounded flex items-center justify-between">
                    <span className="text-slate-500 text-[10px] mr-3">{idx + 1}.</span>
                    <span className="text-slate-200 flex-1 font-semibold">{pw}</span>
                  </div>
                ))
              ) : (
                <div className="text-center py-12 text-slate-500 text-xs">
                  {fullWordlist.length === 0 ? 'Loading dictionary...' : 'No matching entries found.'}
                </div>
              )}
            </div>

            {filteredWordlist.length > 500 && (
              <div className="p-2 text-center text-[10px] font-mono text-slate-500 bg-[#0d1117] border-t border-[#1e2638]">
                Showing first 500 entries. Download full .txt for all {fullWordlist.length} entries.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
