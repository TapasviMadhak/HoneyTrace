import { useEffect, useState } from 'react';
import {
  Download,
  FileCode,
  ShieldCheck,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  HardDrive,
  Eye,
  Search,
  Zap,
  Terminal,
  FileText,
  AlertTriangle,
} from 'lucide-react';

interface PayloadItem {
  id: string;
  timestamp: string;
  source_ip: string;
  session_id?: string;
  url?: string;
  sha256?: string;
  file_path?: string;
  size_bytes: number;
  file_type?: string;
}

interface PayloadInspection {
  id: string;
  sha256: string;
  md5: string;
  source_ip: string;
  timestamp: string;
  size_bytes: number;
  file_type: string;
  magic_bytes: string;
  hex_dump: string;
  is_binary: boolean;
  raw_script?: string;
  extracted_iocs: string[];
  download_url?: string;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export default function Payloads() {
  const [payloads, setPayloads] = useState<PayloadItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [inspectModalOpen, setInspectModalOpen] = useState(false);
  const [inspectData, setInspectData] = useState<PayloadInspection | null>(null);
  const [inspectLoading, setInspectLoading] = useState(false);
  const [inspectTab, setInspectTab] = useState<'hex' | 'iocs' | 'script'>('hex');
  const [iocSearch, setIocSearch] = useState('');

  const fetchPayloads = () => {
    setLoading(true);
    fetch(`${API_BASE_URL}/api/v1/telemetry/payloads`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { items: PayloadItem[] } | null) => {
        if (data && Array.isArray(data.items)) {
          setPayloads(data.items);
        }
      })
      .catch((err) => console.warn('Payloads fetch warning:', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchPayloads();
    const timer = setInterval(fetchPayloads, 10000);
    return () => clearInterval(timer);
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleInspect = (p: PayloadItem) => {
    setInspectModalOpen(true);
    setInspectLoading(true);
    setInspectData(null);
    setInspectTab('hex');

    fetch(`${API_BASE_URL}/api/v1/telemetry/payloads/inspect?id=${p.id || p.sha256}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data: PayloadInspection | null) => {
        if (data) {
          setInspectData(data);
          if (data.raw_script) {
            setInspectTab('script');
          }
        }
      })
      .catch((err) => console.warn('Inspect error:', err))
      .finally(() => setInspectLoading(false));
  };

  const filteredPayloads = payloads.filter(
    (p) =>
      p.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (p.url && p.url.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (p.sha256 && p.sha256.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (p.file_path && p.file_path.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (p.file_type && p.file_type.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const totalSize = payloads.reduce((acc, curr) => acc + (curr.size_bytes || 0), 0);
  const uniqueHashes = new Set(payloads.map((p) => p.sha256).filter(Boolean)).size;

  const formatSize = (bytes: number) => {
    if (!bytes || bytes === 0) return '0.0 KB';
    if (bytes >= 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }
    return `${(bytes / 1024).toFixed(1)} KB`;
  };

  const filteredIOCs = inspectData?.extracted_iocs.filter((s) =>
    s.toLowerCase().includes(iocSearch.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="hud-card p-6 sm:p-8 border-l-4 border-l-purple-500">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-purple-500/10 border border-purple-400/30 text-purple-300">
                <FileCode className="w-5 h-5" />
              </span>
              <span className="text-xs font-mono font-bold tracking-widest text-purple-300 uppercase">
                BINARY STATIC ANALYSIS &amp; MALWARE DISCOVERY
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              Captured Attack Payloads &amp; Dropper Artifacts
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-2xl leading-relaxed font-mono">
              Intercepted botnet binaries, droppers, and post-exploitation scripts quarantined directly from honeypot ingress sessions. Inspect hex structures, extracted IOCs, and SHA256 checksums.
            </p>
          </div>

          <div className="flex items-center gap-3 self-start lg:self-auto">
            <button
              onClick={fetchPayloads}
              disabled={loading}
              className="p-2.5 rounded-xl bg-[#0d1117] hover:bg-[#1e2638] border border-[#1e2638] text-slate-300 hover:text-white transition-all flex items-center gap-2 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 text-purple-400 ${loading ? 'animate-spin' : ''}`} />
              <span className="text-xs font-mono text-slate-300">Sync Payloads</span>
            </button>
          </div>
        </div>

        {/* Metrics Row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-6 pt-6 border-t border-[#1e2638]">
          <div className="p-4 rounded-xl bg-[#06080d]/80 border border-[#1e2638] flex items-center gap-4">
            <div className="p-3 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Download className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xs font-mono uppercase text-slate-400 block">Total Captured Artifacts</span>
              <strong className="text-2xl font-black text-white font-mono">{payloads.length}</strong>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#06080d]/80 border border-[#1e2638] flex items-center gap-4">
            <div className="p-3 rounded-xl bg-[#00f0ff]/10 border border-[#00f0ff]/20 text-[#00f0ff]">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xs font-mono uppercase text-slate-400 block">Unique SHA256 Hashes</span>
              <strong className="text-2xl font-black text-[#00f0ff] font-mono">{uniqueHashes}</strong>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#06080d]/80 border border-[#1e2638] flex items-center gap-4">
            <div className="p-3 rounded-xl bg-[#00ff9d]/10 border border-[#00ff9d]/20 text-[#00ff9d]">
              <HardDrive className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xs font-mono uppercase text-slate-400 block">Total Ingested Volume</span>
              <strong className="text-2xl font-black text-[#00ff9d] font-mono">
                {formatSize(totalSize)}
              </strong>
            </div>
          </div>
        </div>
      </div>

      {/* Filter / Search */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="relative w-full max-w-md">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Filter by IP, URL, SHA256 hash, or file type..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-[#0d1117] border border-[#1e2638] text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-400"
          />
        </div>
        <span className="text-xs font-mono text-slate-400 whitespace-nowrap">
          Showing {filteredPayloads.length} of {payloads.length} Captured Artifacts
        </span>
      </div>

      {/* Payloads Table */}
      <div className="hud-card overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#06080d]/80 text-slate-400 border-b border-[#1e2638] uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-4">Timestamp</th>
                <th className="p-4">Attacker IP</th>
                <th className="p-4">File Type &amp; Classification</th>
                <th className="p-4">SHA256 Signature</th>
                <th className="p-4 text-right">Size</th>
                <th className="p-4 text-center">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2638]/60 text-slate-300">
              {filteredPayloads.length > 0 ? (
                filteredPayloads.map((p) => (
                  <tr key={p.id} className="hover:bg-[#1e2638]/40 transition-colors">
                    <td className="p-4 text-slate-400 whitespace-nowrap text-[11px]">
                      {p.timestamp ? new Date(p.timestamp).toLocaleString() : 'N/A'}
                    </td>
                    <td className="p-4 font-bold text-cyan-300 whitespace-nowrap">{p.source_ip}</td>
                    <td className="p-4 max-w-xs">
                      <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold border ${
                        p.size_bytes > 1000000
                          ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                          : p.size_bytes > 0
                          ? 'bg-purple-500/10 text-purple-300 border-purple-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {p.file_type || (p.size_bytes > 0 ? 'ELF Binary Artifact' : 'Network Transfer')}
                      </span>
                      {p.url && (
                        <div className="text-[10px] text-slate-500 truncate mt-0.5" title={p.url}>
                          Vector: {p.url}
                        </div>
                      )}
                    </td>
                    <td className="p-4 max-w-xs">
                      {p.sha256 ? (
                        <div className="flex items-center gap-2">
                          <span className="truncate text-slate-400 font-mono text-[11px] bg-[#06080d] px-2 py-0.5 rounded border border-[#1e2638]" title={p.sha256}>
                            {p.sha256.slice(0, 16)}...
                          </span>
                          <button
                            onClick={() => handleCopy(p.sha256!, p.id)}
                            className="p-1 rounded hover:bg-[#1e2638] text-slate-400 hover:text-white"
                            title="Copy Full SHA256"
                          >
                            {copiedId === p.id ? (
                              <Check className="w-3.5 h-3.5 text-[#00ff9d]" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      ) : (
                        <span className="text-slate-500 italic">Pending Hash</span>
                      )}
                    </td>
                    <td className="p-4 whitespace-nowrap text-right font-bold text-white">
                      {formatSize(p.size_bytes)}
                    </td>
                    <td className="p-4 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <button
                          onClick={() => handleInspect(p)}
                          className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/40 text-purple-300 font-mono text-xs font-bold transition-all hover:scale-105"
                          title="Deep Static Forensics & Hex Dump"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Inspect</span>
                        </button>

                        {p.sha256 && (
                          <a
                            href={`${API_BASE_URL}/api/v1/telemetry/payloads/download?sha256=${p.sha256}`}
                            download={`malware-${p.sha256.slice(0, 8)}.bin`}
                            className="p-1.5 rounded-lg bg-[#06080d] hover:bg-[#1e2638] border border-[#1e2638] text-slate-400 hover:text-white transition-all"
                            title="Download Raw Quarantined Binary"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500 italic">
                    No malware payloads captured yet. HoneyTrace is monitoring ingress download streams...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deep Payload Static Forensics Modal */}
      {inspectModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
          <div className="hud-card max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden border border-purple-500/40 shadow-2xl">
            {/* Modal Header */}
            <div className="p-5 border-b border-[#1e2638] flex items-center justify-between bg-[#0d1117]">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-300">
                  <FileCode className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-sm sm:text-base font-mono font-bold text-white uppercase flex items-center gap-2">
                    <span>Static Malware Analysis &amp; Hex Inspector</span>
                    {inspectData?.file_type && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                        {inspectData.magic_bytes}
                      </span>
                    )}
                  </h3>
                  <div className="text-xs font-mono text-slate-400 flex items-center gap-3 mt-0.5">
                    <span>IP: <strong className="text-cyan-300">{inspectData?.source_ip || 'Unknown'}</strong></span>
                    <span>•</span>
                    <span>Size: <strong className="text-white">{formatSize(inspectData?.size_bytes || 0)}</strong></span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {inspectData?.sha256 && (
                  <a
                    href={`https://www.virustotal.com/gui/file/${inspectData.sha256}`}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-[#06080d] hover:bg-[#1e2638] border border-[#1e2638] text-slate-300 hover:text-white text-xs font-mono"
                  >
                    <span>VirusTotal</span>
                    <ExternalLink className="w-3 h-3 text-cyan-400" />
                  </a>
                )}
                <button
                  onClick={() => setInspectModalOpen(false)}
                  className="text-slate-400 hover:text-white font-mono text-sm px-2 py-1"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Checksums Bar */}
            <div className="p-3 px-5 bg-[#06080d]/90 border-b border-[#1e2638] font-mono text-xs text-slate-300 flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2 truncate">
                <span className="text-slate-500 text-[10px] uppercase font-bold">SHA256:</span>
                <code className="text-purple-300 text-[11px] truncate max-w-sm sm:max-w-md">{inspectData?.sha256 || 'N/A'}</code>
                {inspectData?.sha256 && (
                  <button
                    onClick={() => handleCopy(inspectData.sha256, 'modal-sha')}
                    className="p-1 text-slate-500 hover:text-white"
                  >
                    {copiedId === 'modal-sha' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                )}
              </div>

              {inspectData?.md5 && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-[10px] uppercase font-bold">MD5:</span>
                  <code className="text-slate-300 text-[11px]">{inspectData.md5}</code>
                </div>
              )}
            </div>

            {/* Forensics Navigation Tabs */}
            <div className="p-2.5 bg-[#0d1117] border-b border-[#1e2638] flex items-center justify-between gap-3">
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setInspectTab('hex')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                    inspectTab === 'hex'
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Hex Dump &amp; Magic Bytes</span>
                </button>

                <button
                  onClick={() => setInspectTab('iocs')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                    inspectTab === 'iocs'
                      ? 'bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/40 shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>Extracted Strings &amp; IOCs ({inspectData?.extracted_iocs.length || 0})</span>
                </button>

                {inspectData?.raw_script && (
                  <button
                    onClick={() => setInspectTab('script')}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                      inspectTab === 'script'
                        ? 'bg-[#00ff9d]/20 text-[#00ff9d] border border-[#00ff9d]/40 shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Raw Script Content</span>
                  </button>
                )}
              </div>

              {inspectTab === 'iocs' && (
                <div className="relative w-48">
                  <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Filter strings..."
                    value={iocSearch}
                    onChange={(e) => setIocSearch(e.target.value)}
                    className="w-full pl-7 pr-2 py-1 rounded bg-[#06080d] border border-[#1e2638] text-[11px] font-mono text-slate-200 placeholder-slate-500 focus:outline-none"
                  />
                </div>
              )}
            </div>

            {/* Modal Body Content */}
            <div className="p-4 overflow-y-auto flex-1 bg-black font-mono text-xs">
              {inspectLoading ? (
                <div className="flex flex-col items-center justify-center py-20 text-slate-400 gap-3">
                  <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
                  <span>Analyzing payload binary headers and extracting string signatures...</span>
                </div>
              ) : inspectTab === 'hex' ? (
                <div className="space-y-2">
                  <div className="text-[11px] text-slate-500 flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>Quarantined binary header dump (first 2,048 bytes disassembled):</span>
                  </div>
                  <pre className="p-4 rounded-xl bg-[#06080d] border border-[#1e2638] text-purple-300 overflow-x-auto text-[11px] leading-relaxed font-mono selection:bg-purple-500/30 selection:text-white">
                    {inspectData?.hex_dump || 'No hex dump available.'}
                  </pre>
                </div>
              ) : inspectTab === 'iocs' ? (
                <div className="space-y-2">
                  <div className="text-[11px] text-slate-400">
                    Printable ASCII strings extracted from binary (C2 paths, library hooks, commands):
                  </div>
                  <div className="p-3 rounded-xl bg-[#06080d] border border-[#1e2638] max-h-[400px] overflow-y-auto divide-y divide-slate-900">
                    {filteredIOCs.length > 0 ? (
                      filteredIOCs.map((ioc, idx) => (
                        <div key={idx} className="py-1 px-2 hover:bg-[#1e2638]/40 rounded flex items-center justify-between text-[11px]">
                          <span className="text-slate-500 text-[10px] mr-3">{idx + 1}.</span>
                          <span className="text-cyan-300 font-semibold flex-1 break-all">{ioc}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12 text-slate-500">No matching IOC strings found.</div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <pre className="p-4 rounded-xl bg-[#06080d] border border-[#1e2638] text-[#00ff9d] overflow-x-auto text-xs leading-relaxed font-mono">
                    {inspectData?.raw_script || 'No plaintext script available.'}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-3.5 bg-[#0d1117] border-t border-[#1e2638] flex items-center justify-between font-mono text-xs text-slate-400">
              <span className="text-[11px]">HoneyTrace Quarantined Sandbox Storage</span>
              {inspectData?.sha256 && (
                <a
                  href={`${API_BASE_URL}/api/v1/telemetry/payloads/download?sha256=${inspectData.sha256}`}
                  download={`malware-${inspectData.sha256.slice(0, 8)}.bin`}
                  className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-gradient-to-r from-purple-500/20 to-[#00f0ff]/20 hover:from-purple-500/30 hover:to-[#00f0ff]/30 border border-purple-500/40 text-white font-bold transition-all"
                >
                  <Download className="w-3.5 h-3.5 text-purple-400" />
                  <span>Download Quarantined File</span>
                </a>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
