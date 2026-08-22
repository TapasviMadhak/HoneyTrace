import { useEffect, useState, useRef } from 'react';
import {
  BrainCircuit,
  RefreshCw,
  Search,
  MessageSquare,
  Lock,
  Download,
  Flame,
  ShieldCheck,
  Send,
  Sparkles,
  Zap,
  Trash2,
  Copy,
  Check,
} from 'lucide-react';
import CyberMarkdown from '../components/CyberMarkdown';

interface EventItem {
  id: string;
  timestamp: string;
  source_ip: string;
  event_type: string;
  severity: string;
  summary: string;
  username?: string;
  password?: string;
  city?: string;
  country_code?: string;
  raw_json?: string;
}

interface PlaybookData {
  iptables: string;
  ufw: string;
  fail2ban: string;
  top_ips: { ip: string; city: string; country_code: string; count: number }[];
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
const CHAT_STORAGE_KEY = 'honeytrace_soc_chat_history';

const DEFAULT_WELCOME_MSG: ChatMessage = {
  role: 'assistant',
  content:
    '🛡️ **HoneyTrace Blue Team SOC Assistant Online**.\nI am connected to your live honeypot sensor telemetry. Ask me to analyze botnet command payloads, generate custom firewall blocklists, write Snort/Suricata IDS rules, or investigate specific attacker subnets.',
  timestamp: new Date().toLocaleTimeString(),
};

export default function Intel() {
  const [activeTab, setActiveTab] = useState<'briefing' | 'playbook' | 'forensics' | 'chat'>('briefing');

  // Executive Briefing States
  const [report, setReport] = useState<string>('');
  const [reportUpdated, setReportUpdated] = useState<string>('');
  const [isReportLoading, setIsReportLoading] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  // Playbook States
  const [playbook, setPlaybook] = useState<PlaybookData | null>(null);
  const [copiedScript, setCopiedScript] = useState<string | null>(null);

  // Forensics & Triage States
  const [events, setEvents] = useState<EventItem[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [triageNotes, setTriageNotes] = useState<{ [eventId: string]: string }>({});
  const [triagingEventId, setTriagingEventId] = useState<string | null>(null);

  // AI Chat States (Persistent in LocalStorage)
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>(() => {
    try {
      const saved = localStorage.getItem(CHAT_STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      }
    } catch {
      // ignore
    }
    return [DEFAULT_WELCOME_MSG];
  });

  const [chatInput, setChatInput] = useState('');
  const [isChatLoading, setIsChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Save chat to localStorage on change
  useEffect(() => {
    try {
      localStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(chatMessages));
    } catch (err) {
      console.warn('LocalStorage save error:', err);
    }
  }, [chatMessages]);

  // 1. Fetch cached or fresh AI summary
  const fetchExecutiveReport = (force = false) => {
    setIsReportLoading(true);
    fetch(`${API_BASE_URL}/api/v1/ai/summary${force ? '?force=true' : ''}`, { method: 'POST' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { report: string; updated_at: string; cached: boolean } | null) => {
        if (data && data.report) {
          setReport(data.report);
          setReportUpdated(data.updated_at);
        }
      })
      .catch((err) => console.warn('AI Summary error:', err))
      .finally(() => setIsReportLoading(false));
  };

  // 2. Fetch Playbook rules
  const fetchPlaybook = () => {
    fetch(`${API_BASE_URL}/api/v1/ai/playbook`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data: PlaybookData | null) => {
        if (data) setPlaybook(data);
      })
      .catch((err) => console.warn('Playbook error:', err));
  };

  // 3. Fetch Raw Events for Forensics
  const fetchEvents = () => {
    fetch(`${API_BASE_URL}/api/v1/events`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { items: EventItem[] } | null) => {
        if (data && Array.isArray(data.items)) {
          setEvents(data.items);
        }
      })
      .catch((err) => console.warn('Events error:', err));
  };

  useEffect(() => {
    fetchExecutiveReport(false);
    fetchPlaybook();
    fetchEvents();
  }, []);

  useEffect(() => {
    if (activeTab === 'chat' && chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, activeTab]);

  // Handle Event Triage with AI
  const handleTriageEvent = (ev: EventItem) => {
    setTriagingEventId(ev.id);
    fetch(`${API_BASE_URL}/api/v1/ai/triage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event_id: ev.id,
        event_type: ev.event_type,
        source_ip: ev.source_ip,
        username: ev.username,
        password: ev.password,
        raw_json: ev.raw_json,
      }),
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { triage: string } | null) => {
        if (data && data.triage) {
          setTriageNotes((prev) => ({ ...prev, [ev.id]: data.triage }));
        }
      })
      .catch((err) => console.warn('Triage error:', err))
      .finally(() => setTriagingEventId(null));
  };

  // Handle AI SOC Chat
  const handleSendChat = (messageText?: string) => {
    const text = messageText || chatInput;
    if (!text.trim() || isChatLoading) return;

    const userMsg: ChatMessage = {
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString(),
    };

    const nextMessages = [...chatMessages, userMsg];
    setChatMessages(nextMessages);
    setChatInput('');
    setIsChatLoading(true);

    const historyPayload = nextMessages.slice(-10).map((m) => ({
      role: m.role,
      content: m.content,
    }));

    fetch(`${API_BASE_URL}/api/v1/ai/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: text,
        history: historyPayload,
      }),
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { response: string } | null) => {
        if (data && data.response) {
          setChatMessages((prev) => [
            ...prev,
            {
              role: 'assistant',
              content: data.response,
              timestamp: new Date().toLocaleTimeString(),
            },
          ]);
        }
      })
      .catch((err) => {
        setChatMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: `⚠️ Error contacting Groq AI: ${err.message}`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      })
      .finally(() => setIsChatLoading(false));
  };

  const handleClearChat = () => {
    setChatMessages([DEFAULT_WELCOME_MSG]);
    try {
      localStorage.removeItem(CHAT_STORAGE_KEY);
    } catch {
      // ignore
    }
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedScript(id);
    setTimeout(() => setCopiedScript(null), 2000);
  };

  const handleDownloadReport = () => {
    if (!report) return;
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `honeytrace-soc-report-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredEvents = events.filter((ev) => {
    const matchesSearch =
      ev.source_ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ev.username && ev.username.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (ev.city && ev.city.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesSeverity = selectedSeverity === 'ALL' || ev.severity.toUpperCase() === selectedSeverity;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 font-mono">
      {/* Top Banner */}
      <div className="hud-card p-6 sm:p-8 border-l-4 border-l-[#00f0ff] relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-lg bg-[#00f0ff]/10 border border-[#00f0ff]/30 text-[#00f0ff]">
                <BrainCircuit className="w-5 h-5" />
              </span>
              <span className="text-xs font-bold tracking-widest text-[#00f0ff] uppercase">
                AI BLUE TEAM &amp; THREAT INTELLIGENCE COMMANDER
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 border border-purple-500/40">
                Groq LPU Acceleration (gpt-oss-120b)
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              Security Operations Center (SOC) Defense Console
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-2xl font-mono mt-1">
              Automated threat triage, MITRE ATT&amp;CK classification, executable firewall containment scripts, and interactive Blue Team forensics.
            </p>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 self-start lg:self-auto">
            <button
              onClick={() => fetchExecutiveReport(true)}
              disabled={isReportLoading}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-[#00f0ff]/20 to-[#00ff9d]/20 hover:from-[#00f0ff]/30 hover:to-[#00ff9d]/30 border border-[#00f0ff]/40 text-white text-xs font-bold transition-all shadow-[0_0_20px_rgba(0,240,255,0.2)] disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-[#00f0ff] ${isReportLoading ? 'animate-spin' : ''}`} />
              <span>{isReportLoading ? 'Analyzing Sensor Logs...' : 'Regenerate AI Briefing'}</span>
            </button>

            <button
              onClick={handleDownloadReport}
              disabled={!report}
              className="p-2 rounded-xl bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] text-slate-300 hover:text-white transition-all disabled:opacity-50"
              title="Export Full Report (.md)"
            >
              <Download className="w-4 h-4 text-[#00ff9d]" />
            </button>
          </div>
        </div>

        {/* Quick SOC Metrics Chips */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-[#1e2638]">
          <div className="p-3 rounded-lg bg-[#06080d]/80 border border-[#1e2638]">
            <span className="text-[10px] text-slate-400 uppercase block">MITRE T1110.001 (Spray)</span>
            <strong className="text-lg text-[#ff3366] font-black">41.4k Hits</strong>
          </div>
          <div className="p-3 rounded-lg bg-[#06080d]/80 border border-[#1e2638]">
            <span className="text-[10px] text-slate-400 uppercase block">T1059.004 (Unix Shell)</span>
            <strong className="text-lg text-amber-400 font-black">166 Commands</strong>
          </div>
          <div className="p-3 rounded-lg bg-[#06080d]/80 border border-[#1e2638]">
            <span className="text-[10px] text-slate-400 uppercase block">T1105 (Ingress Malware)</span>
            <strong className="text-lg text-purple-400 font-black">123.2 MB Captured</strong>
          </div>
          <div className="p-3 rounded-lg bg-[#06080d]/80 border border-[#1e2638]">
            <span className="text-[10px] text-slate-400 uppercase block">Breach Sessions</span>
            <strong className="text-lg text-[#00ff9d] font-black">135 Isolated</strong>
          </div>
        </div>
      </div>

      {/* Main Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-[#1e2638] pb-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab('briefing')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'briefing'
              ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/40 shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#1e2638]/40'
          }`}
        >
          <BrainCircuit className="w-4 h-4" />
          <span>AI Executive Threat Briefing</span>
        </button>

        <button
          onClick={() => setActiveTab('playbook')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'playbook'
              ? 'bg-[#00ff9d]/15 text-[#00ff9d] border border-[#00ff9d]/40 shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#1e2638]/40'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>Firewall &amp; Mitigation Playbooks</span>
        </button>

        <button
          onClick={() => setActiveTab('forensics')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'forensics'
              ? 'bg-purple-500/15 text-purple-300 border border-purple-500/40 shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#1e2638]/40'
          }`}
        >
          <Search className="w-4 h-4" />
          <span>Live Log Forensics &amp; Rapid Triage</span>
        </button>

        <button
          onClick={() => setActiveTab('chat')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'chat'
              ? 'bg-amber-500/15 text-amber-300 border border-amber-500/40 shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#1e2638]/40'
          }`}
        >
          <MessageSquare className="w-4 h-4" />
          <span>SOC Analyst AI Assistant</span>
          {chatMessages.length > 1 && (
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-300">
              {chatMessages.length}
            </span>
          )}
        </button>
      </div>

      {/* TAB 1: AI Executive Threat Briefing (Rendered with CyberMarkdown) */}
      {activeTab === 'briefing' && (
        <div className="hud-card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1e2638] pb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#00f0ff]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Threat Intelligence Assessment &amp; Campaign Attribution
              </h3>
            </div>
            {reportUpdated && (
              <span className="text-[10px] text-slate-500">
                Generated: {new Date(reportUpdated).toLocaleString()}
              </span>
            )}
          </div>

          {isReportLoading ? (
            <div className="py-24 text-center space-y-3">
              <RefreshCw className="w-8 h-8 animate-spin text-[#00f0ff] mx-auto" />
              <p className="text-sm text-slate-300 font-bold">
                Synthesizing Ingress Telemetry via Groq LPU Inference...
              </p>
              <p className="text-xs text-slate-500">
                Analyzing 41k hits, Santa Clara spray campaigns, 135 breaches, and quarantined botnet binaries.
              </p>
            </div>
          ) : report ? (
            <div className="space-y-4">
              <div className="p-6 rounded-2xl bg-[#06080d] border border-[#1e2638] overflow-x-auto shadow-2xl">
                <CyberMarkdown content={report} />
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-slate-500">
                  Engine: <code className="text-[#00f0ff]">openai/gpt-oss-120b</code> on Groq LPUs
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(report);
                    setCopiedReport(true);
                    setTimeout(() => setCopiedReport(false), 2000);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] text-slate-300 hover:text-white text-xs font-bold transition-all"
                >
                  {copiedReport ? <Check className="w-3.5 h-3.5 text-[#00ff9d]" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedReport ? 'Copied Briefing' : 'Copy Full Markdown'}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-slate-500">
              No report generated yet. Click &quot;Regenerate AI Briefing&quot; to produce real-time analysis.
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Blue Team Mitigation & Firewall Playbooks */}
      {activeTab === 'playbook' && (
        <div className="space-y-6">
          {/* iptables Block Script */}
          <div className="hud-card p-6 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-[#ff3366]" />
                <h3 className="text-xs font-bold uppercase text-white">
                  Automated `iptables` Ingress Quarantine Script
                </h3>
              </div>
              <button
                onClick={() => playbook && handleCopyText(playbook.iptables, 'iptables')}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#ff3366]/15 hover:bg-[#ff3366]/25 border border-[#ff3366]/40 text-[#ff3366] text-xs font-bold transition-all"
              >
                {copiedScript === 'iptables' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy Script</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-black border border-[#1e2638] text-[#00ff9d] text-xs overflow-x-auto leading-relaxed">
              {playbook?.iptables || '# Generating rules...'}
            </pre>
          </div>

          {/* UFW Block Rules */}
          <div className="hud-card p-6 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#00f0ff]" />
                <h3 className="text-xs font-bold uppercase text-white">
                  Ubuntu UFW Defense Block Rules
                </h3>
              </div>
              <button
                onClick={() => playbook && handleCopyText(playbook.ufw, 'ufw')}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#00f0ff]/15 hover:bg-[#00f0ff]/25 border border-[#00f0ff]/40 text-[#00f0ff] text-xs font-bold transition-all"
              >
                {copiedScript === 'ufw' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy UFW</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-black border border-[#1e2638] text-cyan-300 text-xs overflow-x-auto leading-relaxed">
              {playbook?.ufw || '# Generating rules...'}
            </pre>
          </div>

          {/* Fail2Ban Config */}
          <div className="hud-card p-6 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-purple-400" />
                <h3 className="text-xs font-bold uppercase text-white">
                  Fail2Ban Hardening Jail (`/etc/fail2ban/jail.d/sshd.local`)
                </h3>
              </div>
              <button
                onClick={() => playbook && handleCopyText(playbook.fail2ban, 'f2b')}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/40 text-purple-300 text-xs font-bold transition-all"
              >
                {copiedScript === 'f2b' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy Config</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-black border border-[#1e2638] text-purple-300 text-xs overflow-x-auto leading-relaxed">
              {playbook?.fail2ban || '# Generating config...'}
            </pre>
          </div>
        </div>
      )}

      {/* TAB 3: Live Log Forensics & Rapid AI Triage */}
      {activeTab === 'forensics' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="relative w-full max-w-md">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search by IP, summary, username, city..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#0d1117] border border-[#1e2638] text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#00f0ff]"
              />
            </div>

            <div className="flex items-center gap-2">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`px-3 py-1 rounded-lg text-[11px] font-bold transition-all ${
                    selectedSeverity === sev
                      ? sev === 'CRITICAL'
                        ? 'bg-[#ff3366] text-white'
                        : sev === 'HIGH'
                        ? 'bg-amber-400 text-black'
                        : 'bg-[#00f0ff] text-black'
                      : 'bg-[#0d1117] text-slate-400 border border-[#1e2638]'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Events Forensic List */}
          <div className="hud-card overflow-hidden">
            <div className="divide-y divide-[#1e2638]/60">
              {filteredEvents.length > 0 ? (
                filteredEvents.slice(0, 30).map((ev) => {
                  const hasTriage = triageNotes[ev.id];
                  const isTriaging = triagingEventId === ev.id;
                  return (
                    <div key={ev.id} className="p-4 hover:bg-[#1e2638]/30 transition-all space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              ev.severity === 'critical'
                                ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                : ev.severity === 'high'
                                ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                            }`}
                          >
                            {ev.severity || 'INFO'}
                          </span>
                          <strong className="text-cyan-300">{ev.source_ip}</strong>
                          {ev.city && (
                            <span className="text-slate-500 text-[11px]">
                              ({ev.city}, {ev.country_code})
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-3 text-[11px] text-slate-500">
                          <span>{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}</span>
                          <button
                            onClick={() => handleTriageEvent(ev)}
                            disabled={isTriaging}
                            className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 border border-[#00f0ff]/30 text-[#00f0ff] font-bold text-[10px] transition-all disabled:opacity-50"
                          >
                            <Zap className={`w-3 h-3 ${isTriaging ? 'animate-spin' : ''}`} />
                            <span>{isTriaging ? 'Triaging...' : hasTriage ? 'Re-Triage' : '⚡ AI Triage'}</span>
                          </button>
                        </div>
                      </div>

                      <div className="text-xs text-slate-300 font-mono">
                        {ev.summary}
                        {ev.username && (
                          <span className="text-slate-400 ml-2">
                            (creds: <code className="text-emerald-300">{ev.username}</code>:<code>{ev.password || '***'}</code>)
                          </span>
                        )}
                      </div>

                      {/* Rendered AI Triage Note with Markdown */}
                      {hasTriage && (
                        <div className="p-3.5 rounded-xl bg-black/90 border border-[#00f0ff]/40 text-xs space-y-1.5 mt-2">
                          <div className="flex items-center gap-1.5 text-[#00f0ff] font-bold text-[10px] uppercase">
                            <Sparkles className="w-3 h-3" />
                            <span>AI SOC Analyst Triage Note</span>
                          </div>
                          <CyberMarkdown content={hasTriage} />
                        </div>
                      )}
                    </div>
                  );
                })
              ) : (
                <div className="p-8 text-center text-slate-500 text-xs">
                  No events matching criteria.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: SOC AI Analyst Chat Assistant (Persistent & Rendered in Markdown) */}
      {activeTab === 'chat' && (
        <div className="hud-card p-6 flex flex-col h-[650px] border border-amber-500/30">
          {/* Header Controls Bar */}
          <div className="flex items-center justify-between pb-3 border-b border-[#1e2638]">
            <div className="flex items-center gap-2 overflow-x-auto text-xs pr-2">
              <span className="text-slate-500 text-[10px] font-bold uppercase flex-shrink-0">
                Quick Inquiries:
              </span>
              {[
                'Explain the `chmod +x sshd; nohup` botnet payload',
                'Generate an iptables script for Santa Clara DigitalOcean subnet',
                'What does the JA4H HTTP fingerprint in direct-tcpip mean?',
                'Write a Suricata IDS rule for this honeypot attack wave',
              ].map((preset) => (
                <button
                  key={preset}
                  onClick={() => handleSendChat(preset)}
                  className="px-2.5 py-1 rounded-full bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] hover:border-amber-400/40 text-slate-300 hover:text-amber-300 text-[11px] whitespace-nowrap transition-all"
                >
                  {preset}
                </button>
              ))}
            </div>

            <button
              onClick={handleClearChat}
              className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] text-slate-400 hover:text-rose-400 text-[11px] font-bold transition-all flex-shrink-0 ml-2"
              title="Clear Conversation History"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear History</span>
            </button>
          </div>

          {/* Chat Messages Log */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 my-3 bg-black/60 rounded-xl border border-[#1e2638]">
            {chatMessages.map((msg, i) => (
              <div
                key={i}
                className={`flex flex-col ${
                  msg.role === 'user' ? 'items-end' : 'items-start'
                }`}
              >
                <div className="flex items-center gap-2 text-[10px] text-slate-500 mb-1">
                  <span>{msg.role === 'user' ? 'SOC Engineer' : 'HoneyTrace AI SOC Analyst'}</span>
                  <span>•</span>
                  <span>{msg.timestamp}</span>
                </div>
                <div
                  className={`p-4 rounded-2xl max-w-2xl text-xs leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-amber-500/20 text-amber-200 border border-amber-500/30'
                      : 'bg-[#0d1117] text-slate-200 border border-[#1e2638] shadow-xl'
                  }`}
                >
                  {msg.role === 'assistant' ? (
                    <CyberMarkdown content={msg.content} />
                  ) : (
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                  )}
                </div>
              </div>
            ))}
            {isChatLoading && (
              <div className="flex items-center gap-2 text-xs text-amber-400 animate-pulse p-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>AI SOC Analyst is formulating defense response...</span>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Chat Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendChat();
            }}
            className="flex items-center gap-2 pt-2"
          >
            <input
              type="text"
              placeholder="Ask Blue Team AI analyst about botnets, IDS rules, or firewall blocks..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              className="flex-1 px-4 py-2.5 rounded-xl bg-[#06080d] border border-[#1e2638] text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-400"
            />
            <button
              type="submit"
              disabled={isChatLoading || !chatInput.trim()}
              className="px-4 py-2.5 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 font-bold text-xs flex items-center gap-1.5 transition-all disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
