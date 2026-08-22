import { useEffect, useRef, useState } from 'react';
import createGlobe from 'cobe';
import {
  Radio,
  Activity,
  ShieldAlert,
  Wifi,
  Globe2,
} from 'lucide-react';

export interface GlobeMarkerData {
  location: [number, number]; // [lat, lon]
  size: number;
  count: number;
  city?: string;
  country?: string;
}

export interface LiveAttackEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  username?: string;
  password?: string;
  event_type?: string;
}

interface CobeGlobeProps {
  markers?: GlobeMarkerData[];
  onLiveAttack?: (attack: LiveAttackEvent) => void;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export default function CobeGlobe({ markers = [], onLiveAttack }: CobeGlobeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const pointerInteracting = useRef<number | null>(null);
  const pointerInteractionMovement = useRef(0);
  const phiRef = useRef(0);
  const thetaRef = useRef(0.25);
  const onLiveAttackRef = useRef(onLiveAttack);

  // Initialize strictly with real markers (no dummy fallback data)
  const [activeMarkers, setActiveMarkers] = useState<GlobeMarkerData[]>(markers);
  const [recentAttacks, setRecentAttacks] = useState<LiveAttackEvent[]>([]);
  const [latestLive, setLatestLive] = useState<LiveAttackEvent | null>(null);
  const [sseConnected, setSseConnected] = useState(false);

  useEffect(() => {
    onLiveAttackRef.current = onLiveAttack;
  }, [onLiveAttack]);

  // Sync historical markers when parent receives fresh database poll
  useEffect(() => {
    if (markers && markers.length > 0) {
      setActiveMarkers((prev) => {
        // Merge fresh database markers with any active dynamic markers
        const map = new Map<string, GlobeMarkerData>();
        for (const m of markers) {
          const key = `${m.location[0].toFixed(2)},${m.location[1].toFixed(2)}`;
          map.set(key, { ...m });
        }
        // Retain any live hits that were dynamically added since last poll
        for (const p of prev) {
          const key = `${p.location[0].toFixed(2)},${p.location[1].toFixed(2)}`;
          if (!map.has(key)) {
            map.set(key, p);
          }
        }
        return Array.from(map.values());
      });
    }
  }, [markers]);

  // Dynamic markers reference for Cobe onRender
  const cobeMarkersRef = useRef<{ location: [number, number]; size: number }[]>([]);
  useEffect(() => {
    cobeMarkersRef.current = activeMarkers.map((m) => ({
      location: m.location,
      size: m.size || 0.06,
    }));
  }, [activeMarkers]);

  // Connect to SSE live stream once on mount
  useEffect(() => {
    const sseUrl = `${API_BASE_URL}/api/v1/telemetry/live`;
    let es: EventSource | null = null;

    try {
      es = new EventSource(sseUrl);

      es.onopen = () => {
        setSseConnected(true);
      };

      es.onmessage = (e) => {
        if (!e.data || e.data.startsWith(':')) return;
        try {
          const attack: LiveAttackEvent = JSON.parse(e.data);
          if (attack.latitude && attack.longitude) {
            setLatestLive(attack);
            setRecentAttacks((prev) => [attack, ...prev.slice(0, 4)]);

            // Increment parent counter (+1) in real-time
            if (onLiveAttackRef.current) {
              onLiveAttackRef.current(attack);
            }

            // Spawn or elevate glowing beacon at attacker's coordinates without wiping existing markers
            setActiveMarkers((prev) => {
              const matchIndex = prev.findIndex(
                (m) =>
                  Math.abs(m.location[0] - attack.latitude) < 0.6 &&
                  Math.abs(m.location[1] - attack.longitude) < 0.6
              );

              if (matchIndex >= 0) {
                const updated = [...prev];
                updated[matchIndex] = {
                  ...updated[matchIndex],
                  size: Math.min(0.18, (updated[matchIndex].size || 0.06) + 0.03),
                  count: (updated[matchIndex].count || 0) + 1,
                  city: attack.city || updated[matchIndex].city,
                  country: attack.country || updated[matchIndex].country,
                };
                return updated;
              } else {
                return [
                  ...prev,
                  {
                    location: [attack.latitude, attack.longitude],
                    size: 0.11, // Glowing beacon size for new hit
                    count: 1,
                    city: attack.city,
                    country: attack.country,
                  },
                ];
              }
            });
          }
        } catch {
          // Ignored ping
        }
      };

      es.onerror = () => {
        setSseConnected(false);
      };
    } catch {
      setSseConnected(false);
    }

    return () => {
      if (es) es.close();
    };
  }, []);

  // Mount Cobe WebGL Canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    const wrapper = wrapperRef.current;
    if (!canvas || !wrapper) return;

    let width = wrapper.clientWidth || 360;

    const onResize = () => {
      if (wrapper) {
        width = Math.min(wrapper.clientWidth, 400);
      }
    };

    window.addEventListener('resize', onResize);
    onResize();

    let globe: any = null;
    try {
      globe = createGlobe(canvas, {
        devicePixelRatio: Math.min(window.devicePixelRatio || 1, 2),
        width: width * 2,
        height: width * 2,
        phi: 0,
        theta: 0.25,
        dark: 1,
        diffuse: 1.3,
        mapSamples: 16000,
        mapBrightness: 5.5,
        baseColor: [0.07, 0.11, 0.22],
        markerColor: [1.0, 0.35, 0.45], // Glowing crimson red for attacker probes
        glowColor: [0.15, 0.45, 0.85],
        markers: cobeMarkersRef.current,
        onRender: (state) => {
          if (pointerInteracting.current === null) {
            phiRef.current += 0.0035;
          }
          state.phi = phiRef.current + pointerInteractionMovement.current;
          state.theta = thetaRef.current;
          state.width = width * 2;
          state.height = width * 2;
          state.markers = cobeMarkersRef.current;
        },
      });

      canvas.style.opacity = '1';
    } catch (err) {
      console.warn('Cobe WebGL initialization:', err);
    }

    return () => {
      window.removeEventListener('resize', onResize);
      if (globe) globe.destroy();
    };
  }, []);

  return (
    <div className="relative w-full h-full min-h-[400px] flex flex-col justify-between rounded-2xl overflow-hidden bg-gradient-to-b from-slate-950/80 via-slate-900/60 to-slate-950/90 border border-slate-700/40 shadow-2xl backdrop-blur-xl">
      {/* Top Cyber HUD Bar */}
      <div className="flex items-center justify-between px-5 py-3.5 bg-slate-950/70 border-b border-slate-700/30 backdrop-blur-md z-10">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2.5 w-2.5">
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                sseConnected ? 'bg-emerald-400' : 'bg-amber-400'
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                sseConnected ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' : 'bg-amber-500 shadow-[0_0_8px_#f59e0b]'
              }`}
            />
          </span>
          <div className="flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-xs font-semibold tracking-wide text-slate-200 uppercase font-mono">
              {sseConnected ? 'LIVE THREAT STREAM' : 'CONNECTING STREAM...'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/20 text-cyan-300 text-xs font-mono">
            <Globe2 className="w-3 h-3 text-cyan-400" />
            <span>{activeMarkers.length} Nodes</span>
          </div>
          <div className="hidden sm:flex items-center gap-1 px-2.5 py-1 rounded-full bg-slate-800/60 border border-slate-700/40 text-slate-400 text-xs font-mono">
            <Wifi className="w-3 h-3 text-emerald-400" />
            <span>SSE 2.0</span>
          </div>
        </div>
      </div>

      {/* Interactive 3D Canvas with HUD Crosshairs */}
      <div
        ref={wrapperRef}
        className="relative w-full max-w-[380px] max-h-[380px] aspect-square mx-auto flex items-center justify-center cursor-grab active:cursor-grabbing overflow-hidden flex-shrink-0"
        onPointerDown={(e) => {
          pointerInteracting.current = e.clientX - pointerInteractionMovement.current;
        }}
        onPointerUp={() => {
          pointerInteracting.current = null;
        }}
        onPointerOut={() => {
          pointerInteracting.current = null;
        }}
        onMouseMove={(e) => {
          if (pointerInteracting.current !== null) {
            const delta = e.clientX - pointerInteracting.current;
            pointerInteractionMovement.current = delta * 0.008;
          }
        }}
        onTouchMove={(e) => {
          if (pointerInteracting.current !== null && e.touches[0]) {
            const delta = e.touches[0].clientX - pointerInteracting.current;
            pointerInteractionMovement.current = delta * 0.008;
          }
        }}
      >
        {/* Subtle Cyber Corner Brackets */}
        <div className="absolute top-2 left-2 w-4 h-4 border-t-2 border-l-2 border-cyan-400/40 pointer-events-none" />
        <div className="absolute top-2 right-2 w-4 h-4 border-t-2 border-r-2 border-cyan-400/40 pointer-events-none" />
        <div className="absolute bottom-2 left-2 w-4 h-4 border-b-2 border-l-2 border-cyan-400/40 pointer-events-none" />
        <div className="absolute bottom-2 right-2 w-4 h-4 border-b-2 border-r-2 border-cyan-400/40 pointer-events-none" />

        <canvas
          ref={canvasRef}
          className="w-full h-full max-w-full max-h-full aspect-square block object-contain opacity-0 transition-opacity duration-700"
        />

        {/* Ambient Center Badge */}
        <div className="absolute bottom-3 text-center pointer-events-none bg-slate-950/85 backdrop-blur-md px-4 py-1.5 rounded-xl border border-slate-700/50 shadow-lg">
          <span className="text-[10px] font-bold tracking-widest text-cyan-400 uppercase block font-mono">
            INGRESS TELEMETRY
          </span>
          <h4 className="text-xs font-semibold text-white tracking-wide">
            {activeMarkers.length > 0 ? `${activeMarkers.length} Threat Coordinate Clusters` : 'Awaiting Ingress Beacons'}
          </h4>
        </div>
      </div>

      {/* Live Attack Toast Overlay */}
      {latestLive && (
        <div className="absolute top-14 right-4 z-20 flex items-center gap-3 px-3.5 py-2.5 rounded-xl bg-rose-950/90 border border-rose-500/50 shadow-[0_8px_24px_rgba(244,63,94,0.3)] backdrop-blur-xl animate-bounce-short max-w-[calc(100%-32px)]">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_12px_#f43f5e] animate-pulse flex-shrink-0" />
          <div className="flex flex-col min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold tracking-wider text-rose-400 uppercase font-mono">
                LIVE INGRESS
              </span>
              <span className="text-xs font-semibold text-white truncate">
                {latestLive.city ? `${latestLive.city}, ` : ''}
                {latestLive.country || 'Global'}
              </span>
            </div>
            <div className="flex items-center gap-2 text-xs truncate">
              <span className="font-mono text-slate-300">{latestLive.source_ip}</span>
              {latestLive.username && (
                <span className="text-cyan-300 text-[11px] font-mono">
                  auth: <code className="bg-slate-800/80 px-1 py-0.5 rounded text-emerald-400">{latestLive.username}</code>
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Live Recent Attack Ticker Footer */}
      {recentAttacks.length > 0 && (
        <div className="flex items-center gap-3 px-4 py-2.5 bg-slate-950/90 border-t border-slate-700/30 overflow-x-auto z-10 flex-shrink-0">
          <div className="flex items-center gap-1.5 text-[10px] font-bold tracking-widest text-slate-400 uppercase font-mono whitespace-nowrap">
            <Activity className="w-3 h-3 text-rose-400 animate-pulse" />
            <span>RECENT PROBES</span>
          </div>
          <div className="flex items-center gap-2">
            {recentAttacks.map((atk, i) => (
              <div
                key={atk.id || i}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900/80 border border-slate-700/50 text-[11px] font-mono whitespace-nowrap shadow-sm"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                <span className="text-slate-200">{atk.source_ip}</span>
                <span className="text-slate-400">({atk.city || atk.country || 'Unknown'})</span>
                {atk.username && <span className="text-emerald-400">[{atk.username}]</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
