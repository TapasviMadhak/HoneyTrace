import React from 'react';

interface HoneyTraceLogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
}

export const HoneyTraceLogo: React.FC<HoneyTraceLogoProps> = ({
  className = '',
  size = 24,
  showText = false,
}) => {
  return (
    <div className={`flex items-center gap-2.5 select-none ${className}`}>
      {/* Minimalist Vector Icon */}
      <svg
        width={size}
        height={size}
        viewBox="0 0 32 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="flex-shrink-0"
      >
        {/* Crisp Hexagon Outline */}
        <path
          d="M16 3.2 L27.2 9.6 V22.4 L16 28.8 L4.8 22.4 V9.6 Z"
          stroke="#00f0ff"
          strokeWidth="2.2"
          strokeLinejoin="round"
        />
        {/* Minimalist Geometric 'H' Core */}
        <path
          d="M11 12 V20 M21 12 V20 M11 16 H21"
          stroke="#00f0ff"
          strokeWidth="2.2"
          strokeLinecap="round"
        />
      </svg>

      {showText && (
        <div className="truncate">
          <div className="flex items-center gap-1.5 leading-none">
            <span className="text-xs font-mono font-bold tracking-widest text-white uppercase">
              HONEYTRACE
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-[#00f0ff]" />
          </div>
          <div className="text-[10px] font-mono text-slate-400 leading-none mt-1">
            Sensor Telemetry
          </div>
        </div>
      )}
    </div>
  );
};

export default HoneyTraceLogo;
