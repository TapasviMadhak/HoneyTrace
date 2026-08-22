import React, { useEffect, useMemo, useRef, useState } from 'react';
import Globe, { GlobeMethods } from 'react-globe.gl';

export interface ThreatMarker {
  lat: number;
  lng: number;
  size: number;
  count: number;
  city?: string;
  country?: string;
  ip?: string;
}

export interface AttackArc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color?: string[];
  city?: string;
  country?: string;
  ip?: string;
}

interface CyberGlobeProps {
  markers: ThreatMarker[];
  liveArcs: AttackArc[];
  targetCoords?: [number, number]; // [lat, lon], default Mumbai [19.0760, 72.8777]
  selectedIP?: string | null;
  selectedIPCoords?: { lat: number; lng: number; city?: string; country?: string; ip?: string } | null;
  onSelectMarker?: (marker: ThreatMarker) => void;
}

const DEFAULT_TARGET: [number, number] = [19.0760, 72.8777]; // Mumbai, India

export const CyberGlobe: React.FC<CyberGlobeProps> = ({
  markers,
  liveArcs,
  targetCoords = DEFAULT_TARGET,
  selectedIP = null,
  selectedIPCoords = null,
  onSelectMarker,
}) => {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const hasInitializedCameraRef = useRef(false);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  // Dynamically track container dimensions
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const { clientWidth, clientHeight } = containerRef.current;
        setDimensions({
          width: clientWidth || window.innerWidth,
          height: clientHeight || window.innerHeight,
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    const resizeObserver = new ResizeObserver(updateDimensions);
    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }

    return () => {
      window.removeEventListener('resize', updateDimensions);
      resizeObserver.disconnect();
    };
  }, []);

  // Configure initial globe camera point toward Asia/India ONCE on mount
  useEffect(() => {
    if (globeRef.current && !hasInitializedCameraRef.current) {
      hasInitializedCameraRef.current = true;
      globeRef.current.pointOfView({ lat: targetCoords[0] + 5, lng: targetCoords[1], altitude: 2.2 }, 1200);

      const controls = globeRef.current.controls();
      if (controls) {
        controls.autoRotate = false;
        controls.autoRotateSpeed = 0;
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;
        controls.minDistance = 140;
        controls.maxDistance = 650;
      }
    }
  }, [targetCoords]);

  // Smoothly pan camera to selected IP location when chosen
  useEffect(() => {
    if (selectedIPCoords && globeRef.current && (selectedIPCoords.lat !== 0 || selectedIPCoords.lng !== 0)) {
      globeRef.current.pointOfView(
        { lat: selectedIPCoords.lat, lng: selectedIPCoords.lng, altitude: 1.85 },
        1200
      );
    }
  }, [selectedIPCoords]);

  // Target Sensor Pulsing Rings
  const ringsData = useMemo(() => [
    {
      lat: targetCoords[0],
      lng: targetCoords[1],
      maxR: 4.5,
      propagationSpeed: 2.2,
      repeatPeriod: 1000,
      color: () => '#00ff9d',
    },
  ], [targetCoords]);

  // Only include markers from countries/coordinates where attacks have actually been received
  const activeAttackMarkers = useMemo(() => {
    return markers.filter(
      (m) =>
        (m.lat !== 0 || m.lng !== 0) &&
        m.count > 0 &&
        m.country &&
        m.country !== 'Unknown' &&
        m.country !== 'XX'
    );
  }, [markers]);

  // Maximum hit count for 3D pillar height scaling
  const maxHits = useMemo(() => {
    if (!activeAttackMarkers || activeAttackMarkers.length === 0) return 1;
    return Math.max(1, ...activeAttackMarkers.map((m) => m.count || 1));
  }, [activeAttackMarkers]);

  // 3D Vertical Pillars: if selectedIP is active, only show that IP's pillar + sensor node
  const pointsData = useMemo(() => {
    let sourceMarkers = activeAttackMarkers;

    if (selectedIPCoords && (selectedIPCoords.lat !== 0 || selectedIPCoords.lng !== 0)) {
      // Show only the selected IP's pillar
      sourceMarkers = [
        {
          lat: selectedIPCoords.lat,
          lng: selectedIPCoords.lng,
          count: 100,
          size: 0.1,
          city: selectedIPCoords.city || 'Attacker',
          country: selectedIPCoords.country || 'Origin',
          ip: selectedIPCoords.ip || selectedIP || 'Selected IP',
        },
      ];
    }

    const pts = sourceMarkers.map((m) => {
      const densityRatio = (m.count || 1) / maxHits;
      const altitude = Math.min(0.75, Math.max(0.15, densityRatio * 0.65));
      const radius = Math.min(0.5, Math.max(0.25, 0.25 + densityRatio * 0.3));

      return {
        ...m,
        altitude: selectedIP ? 0.45 : altitude,
        radius: selectedIP ? 0.45 : radius,
        color: selectedIP ? '#00f0ff' : '#ff3366',
        city: m.city || 'Unknown',
        country: m.country || 'Unknown',
      };
    });

    // Add Honeypot Receiver Node in Mumbai
    pts.push({
      lat: targetCoords[0],
      lng: targetCoords[1],
      altitude: 0.15,
      radius: 0.45,
      count: 99999,
      size: 0.5,
      city: 'Mumbai (Sensor)',
      country: 'India',
      color: '#00ff9d',
      ip: '13.234.121.199',
    });

    return pts;
  }, [activeAttackMarkers, targetCoords, maxHits, selectedIP, selectedIPCoords]);

  // Attack trajectory arcs: if selectedIP is active, ONLY show trajectory from that selected IP!
  const arcsData = useMemo(() => {
    if (selectedIPCoords && (selectedIPCoords.lat !== 0 || selectedIPCoords.lng !== 0)) {
      return [
        {
          startLat: selectedIPCoords.lat,
          startLng: selectedIPCoords.lng,
          endLat: targetCoords[0],
          endLng: targetCoords[1],
          color: ['#00f0ff', '#00ff9d'],
          city: selectedIPCoords.city,
          country: selectedIPCoords.country,
          ip: selectedIPCoords.ip,
        },
      ];
    }

    if (liveArcs && liveArcs.length > 0) {
      return liveArcs;
    }

    return activeAttackMarkers.slice(0, 20).map((m) => ({
      startLat: m.lat,
      startLng: m.lng,
      endLat: targetCoords[0],
      endLng: targetCoords[1],
      color: ['#ff3366', '#00ff9d'],
      city: m.city,
      country: m.country,
    }));
  }, [liveArcs, activeAttackMarkers, targetCoords, selectedIPCoords]);

  return (
    <div ref={containerRef} className="relative w-full h-full min-h-[500px] overflow-hidden select-none bg-[#06080d]">
      <Globe
        ref={globeRef}
        width={dimensions.width}
        height={dimensions.height}
        backgroundColor="#06080d"
        globeImageUrl="https://unpkg.com/three-globe/example/img/earth-night.jpg"
        backgroundImageUrl="https://unpkg.com/three-globe/example/img/night-sky.png"
        showAtmosphere={true}
        atmosphereColor={selectedIP ? '#00f0ff' : '#00f0ff'}
        atmosphereAltitude={0.18}
        // Attack Trajectory Arcs
        arcsData={arcsData}
        arcColor={(d: any) => d.color || ['#ff3366', '#00ff9d']}
        arcAltitude={0.32}
        arcStroke={selectedIP ? 1.2 : 0.6}
        arcDashLength={0.45}
        arcDashGap={0.15}
        arcDashAnimateTime={1600}
        arcDashInitialGap={(d: any) => (d.startLat ? Math.abs(d.startLat) % 1 : 0)}
        // 3D Vertical Column / Pillar Graphs
        pointsData={pointsData}
        pointColor={(d: any) => d.color}
        pointAltitude={(d: any) => d.altitude}
        pointRadius={(d: any) => d.radius}
        pointResolution={24}
        pointLabel={(d: any) => `
          <div style="background: rgba(13, 17, 23, 0.95); border: 1px solid ${d.color === '#00ff9d' ? '#00ff9d' : d.color === '#00f0ff' ? '#00f0ff' : '#ff3366'}; border-radius: 10px; padding: 8px 12px; font-family: monospace; font-size: 11px; color: #fff; box-shadow: 0 0 25px ${d.color === '#00ff9d' ? 'rgba(0,255,157,0.35)' : 'rgba(255,51,102,0.45)'}; backdrop-filter: blur(8px);">
            <div style="color: #00f0ff; font-weight: bold; font-size: 12px; margin-bottom: 2px;">
              📍 ${d.city}, ${d.country}
            </div>
            ${d.ip ? `<div style="color: #fff; font-size: 11px; margin-bottom: 2px;">IP: <strong style="color: #00f0ff;">${d.ip}</strong></div>` : ''}
            ${d.color === '#00ff9d' ? '<div style="color: #00ff9d; font-weight: bold;">🛡️ Decoy Sensor Receiver Node</div>' : `<div style="color: #ff3366; font-weight: bold;">⚡ ${d.count.toLocaleString()} Ingress Attacks</div>`}
            <div style="color: #8b949e; font-size: 10px; margin-top: 2px;">
              Coords: [${d.lat.toFixed(2)}°, ${d.lng.toFixed(2)}°]
            </div>
          </div>
        `}
        onPointClick={(pt: any) => onSelectMarker && onSelectMarker(pt)}
        // Pulsing Rings at Target Sensor
        ringsData={ringsData}
        ringColor={(d: any) => d.color}
        ringMaxRadius={(d: any) => d.maxR}
        ringPropagationSpeed={(d: any) => d.propagationSpeed}
        ringRepeatPeriod={(d: any) => d.repeatPeriod}
      />
    </div>
  );
};

export default CyberGlobe;
