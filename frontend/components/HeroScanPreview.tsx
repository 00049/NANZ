'use client';

import { useEffect, useState } from 'react';
import { CheckCircle2, Zap, Circle, AlertTriangle } from 'lucide-react';

const modules = [
  { name: 'SSL Certificate Analysis', delay: 800 },
  { name: '13 Security Headers', delay: 1400 },
  { name: 'DNS & Email Security', delay: 2200 },
  { name: 'DPDP Compliance Mapping', delay: 3000 },
  { name: 'LLM/AI Security Scan', delay: 4200 },
  { name: 'OWASP API Audit', delay: 5800 },
  { name: 'CVE Intelligence (NVD)', delay: 7000 },
];

type ModuleState = 'pending' | 'running' | 'done';

export default function HeroScanPreview() {
  const [states, setStates] = useState<ModuleState[]>(modules.map(() => 'pending'));
  const [showFinding, setShowFinding] = useState(false);

  useEffect(() => {
    const timers: NodeJS.Timeout[] = [];

    modules.forEach((mod, i) => {
      // Set to running
      timers.push(setTimeout(() => {
        setStates(prev => {
          const next = [...prev];
          next[i] = 'running';
          return next;
        });
      }, mod.delay));

      // Set to done
      timers.push(setTimeout(() => {
        setStates(prev => {
          const next = [...prev];
          next[i] = 'done';
          return next;
        });
      }, mod.delay + 1200));
    });

    // Show finding card after a few modules complete
    timers.push(setTimeout(() => setShowFinding(true), 3800));

    // Reset cycle
    const resetTimer = setTimeout(() => {
      setStates(modules.map(() => 'pending'));
      setShowFinding(false);
    }, 10000);
    timers.push(resetTimer);

    return () => timers.forEach(clearTimeout);
  }, []);

  // Restart animation loop
  useEffect(() => {
    if (states.every(s => s === 'pending') && !showFinding) {
      const timers: NodeJS.Timeout[] = [];
      modules.forEach((mod, i) => {
        timers.push(setTimeout(() => {
          setStates(prev => { const n = [...prev]; n[i] = 'running'; return n; });
        }, mod.delay));
        timers.push(setTimeout(() => {
          setStates(prev => { const n = [...prev]; n[i] = 'done'; return n; });
        }, mod.delay + 1200));
      });
      timers.push(setTimeout(() => setShowFinding(true), 3800));
      timers.push(setTimeout(() => {
        setStates(modules.map(() => 'pending'));
        setShowFinding(false);
      }, 10000));
      return () => timers.forEach(clearTimeout);
    }
  }, [states, showFinding]);

  return (
    <div className="relative w-full max-w-md">
      {/* Scan Module Checklist */}
      <div className="rounded-panel border border-card-border bg-card/80 backdrop-blur-sm p-5 nanz-glow-sm">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Scanning shop.example.in
          </span>
        </div>
        <div className="space-y-2.5">
          {modules.map((mod, i) => (
            <div key={mod.name} className="flex items-center gap-3">
              {states[i] === 'done' && <CheckCircle2 className="w-4 h-4 text-success flex-shrink-0" />}
              {states[i] === 'running' && <Zap className="w-4 h-4 text-nanz-400 animate-pulse flex-shrink-0" />}
              {states[i] === 'pending' && <Circle className="w-4 h-4 text-text-muted/40 flex-shrink-0" />}
              <span className={`text-sm ${states[i] === 'done' ? 'text-text-secondary' : states[i] === 'running' ? 'text-text-primary font-medium' : 'text-text-muted/60'}`}>
                {mod.name}
              </span>
              {states[i] === 'running' && (
                <span className="text-[10px] text-nanz-400 font-mono ml-auto">running...</span>
              )}
            </div>
          ))}
        </div>
        <div className="mt-4 pt-3 border-t border-surface-border">
          <div className="flex items-center justify-between text-xs text-text-muted">
            <span>{states.filter(s => s === 'done').length}/{modules.length} modules</span>
            <span className="text-nanz-400 font-medium">
              {states.every(s => s === 'done') ? '29/29 complete' : 'Scanning...'}
            </span>
          </div>
          <div className="mt-2 h-1.5 rounded-full bg-surface-border overflow-hidden">
            <div
              className="h-full rounded-full bg-nanz-gradient transition-all duration-500 ease-out"
              style={{ width: `${(states.filter(s => s === 'done').length / modules.length) * 100}%` }}
            />
          </div>
        </div>
      </div>

      {/* Sample Finding Card */}
      <div
        className={`mt-3 rounded-card border border-high/30 bg-high/5 p-4 transition-all duration-500 ${showFinding ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}
      >
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-high flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-high/20 text-high uppercase">HIGH</span>
              <span className="text-xs font-semibold text-text-primary">DPDP S.8(4) Violation</span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed">
              Your site transmits personal data without encryption on 3 forms.
            </p>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-[10px] text-high font-semibold">Penalty: ₹250 Crore</span>
              <span className="text-[10px] text-text-muted">•</span>
              <span className="text-[10px] text-text-muted">ALE: ₹38 lakh/yr</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
