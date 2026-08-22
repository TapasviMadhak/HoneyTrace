import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Copy, Check } from 'lucide-react';

interface CyberMarkdownProps {
  content: string;
  className?: string;
}

export const CyberMarkdown: React.FC<CyberMarkdownProps> = ({ content, className = '' }) => {
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  const handleCopy = (codeText: string, id: string) => {
    navigator.clipboard.writeText(codeText);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  return (
    <div className={`cyber-markdown font-mono text-slate-200 ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight mt-6 mb-3 pb-2 border-b border-[#1e2638] flex items-center gap-2 text-[#00f0ff]">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-lg sm:text-xl font-extrabold text-white tracking-tight mt-5 mb-2.5 flex items-center gap-2 text-[#00ff9d]">
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-sm sm:text-base font-bold text-cyan-300 mt-4 mb-2">
              {children}
            </h3>
          ),
          h4: ({ children }) => (
            <h4 className="text-xs sm:text-sm font-bold text-purple-300 mt-3 mb-1.5 uppercase tracking-wider">
              {children}
            </h4>
          ),
          p: ({ children }) => (
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed my-2 font-normal">
              {children}
            </p>
          ),
          strong: ({ children }) => (
            <strong className="font-bold text-white text-[#00f0ff]">
              {children}
            </strong>
          ),
          em: ({ children }) => (
            <em className="text-cyan-200 not-italic font-medium">
              {children}
            </em>
          ),
          ul: ({ children }) => (
            <ul className="space-y-1.5 my-2.5 pl-4 list-disc marker:text-[#00f0ff] text-xs sm:text-sm text-slate-300">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="space-y-1.5 my-2.5 pl-4 list-decimal marker:text-[#00ff9d] text-xs sm:text-sm text-slate-300">
              {children}
            </ol>
          ),
          li: ({ children }) => (
            <li className="leading-relaxed pl-1">
              {children}
            </li>
          ),
          table: ({ children }) => (
            <div className="overflow-x-auto my-4 rounded-xl border border-[#1e2638] bg-[#06080d]/90 shadow-xl">
              <table className="w-full text-left text-xs border-collapse font-mono">
                {children}
              </table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="bg-[#0d1117] text-slate-400 uppercase text-[10px] tracking-wider border-b border-[#1e2638]">
              {children}
            </thead>
          ),
          tbody: ({ children }) => (
            <tbody className="divide-y divide-[#1e2638]/70 text-slate-200">
              {children}
            </tbody>
          ),
          tr: ({ children }) => (
            <tr className="hover:bg-[#1e2638]/40 transition-colors">
              {children}
            </tr>
          ),
          th: ({ children }) => (
            <th className="p-3 font-bold text-cyan-300">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="p-3 text-slate-300 leading-normal">
              {children}
            </td>
          ),
          blockquote: ({ children }) => (
            <blockquote className="my-3 border-l-4 border-[#00f0ff] bg-[#00f0ff]/5 p-3 rounded-r-xl text-xs text-cyan-200 italic">
              {children}
            </blockquote>
          ),
          hr: () => (
            <hr className="my-5 border-t border-[#1e2638]" />
          ),
          code: ({ inline, className, children, ...props }: any) => {
            const codeString = String(children).replace(/\n$/, '');
            const codeId = `code-${Math.random().toString(36).substring(2, 8)}`;

            if (inline) {
              return (
                <code
                  className="px-1.5 py-0.5 rounded bg-[#0d1117] border border-[#1e2638] text-purple-300 text-[11px] font-mono font-semibold"
                  {...props}
                >
                  {children}
                </code>
              );
            }

            return (
              <div className="relative group my-3 rounded-xl overflow-hidden border border-[#1e2638] bg-black">
                <div className="flex items-center justify-between px-3.5 py-1.5 bg-[#0d1117] border-b border-[#1e2638] text-[10px] text-slate-400">
                  <span className="font-bold text-cyan-400 uppercase">
                    {className ? className.replace('language-', '') : 'Code / Payload'}
                  </span>
                  <button
                    onClick={() => handleCopy(codeString, codeId)}
                    className="flex items-center gap-1 px-2 py-0.5 rounded hover:bg-[#1e2638] text-slate-400 hover:text-white transition-all"
                    title="Copy code"
                  >
                    {copiedCodeId === codeId ? (
                      <Check className="w-3 h-3 text-[#00ff9d]" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                    <span>{copiedCodeId === codeId ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3.5 overflow-x-auto text-[11px] font-mono leading-relaxed text-[#00ff9d] selection:bg-[#00ff9d]/20 selection:text-white">
                  <code>{children}</code>
                </pre>
              </div>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};

export default CyberMarkdown;
