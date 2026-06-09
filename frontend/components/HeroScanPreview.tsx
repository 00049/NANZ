'use client';

import { useEffect, useState, useRef } from 'react';
import { CheckCircle2, Zap, Circle, AlertTriangle, Info, ShieldAlert } from 'lucide-react';

const ALL_MODULES = [
  'SSL/TLS Deep Analysis', 'DNS & Email Security', 'HTTP Security Headers (13)', 
  'Port & Service Scan', 'WAF & CDN Detection', 'Web Application Security', 
  'CORS Misconfiguration', 'HTTP Methods Audit', 'Cookie & Session Security', 
  'JWT & OAuth Audit', 'API Security (OWASP)', 'GraphQL Security', 
  'JavaScript Source Analysis', 'Software Composition (SCA)', 'Technology Inventory', 
  'Crawl Intelligence', 'IAST Behavioral Analysis', 'OAST Detection', 
  'CVE Intelligence (NVD+EPSS)', 'BOLA/IDOR Detection', 'LLM / AI Security', 
  'Cloud Storage Exposure', 'IaC & Container Exposure', 'CMS & Plugin Security', 
  'Brand & Reputation', 'Infrastructure & Subdomain', 'Email Security Deep Scan', 
  'DPDP Compliance Mapping'
];

const FAKE_FINDINGS = [
  { severity: 'HIGH', title: 'DPDP S.8(4) Violation', desc: 'Your site transmits personal data without encryption on 3 forms.', penalty: '₹250 Crore', ale: '₹38 lakh/yr' },
  { severity: 'MEDIUM', title: 'HSTS max-age too short', desc: 'Strict-Transport-Security max-age is under 1 year.', penalty: 'N/A', ale: '₹12 lakh/yr' },
  { severity: 'INFO', title: 'SPF record found', desc: 'SPF mechanism is ~all, which is valid but could be stricter.', penalty: 'N/A', ale: 'N/A' },
  { severity: 'CRITICAL', title: 'Cloud Storage Exposure', desc: 'Publicly writable bucket detected at assets-shop-example.', penalty: 'High Risk', ale: '₹1.2 Cr/yr' },
];

export default function HeroScanPreview() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [visibleFindings, setVisibleFindings] = useState<any[]>([]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentIndex((prev) => {
        const next = prev + 1;
        if (next >= ALL_MODULES.length) {
          // Restart loop after a short pause
          setTimeout(() => {
            setCurrentIndex(0);
            setVisibleFindings([]);
          }, 3000);
          return prev;
        }
        
        // Add findings progressively after 8 modules
        if (next === 8) setVisibleFindings([FAKE_FINDINGS[0]]);
        if (next === 14) setVisibleFindings([FAKE_FINDINGS[0], FAKE_FINDINGS[1]]);
        if (next === 20) setVisibleFindings([FAKE_FINDINGS[0], FAKE_FINDINGS[1], FAKE_FINDINGS[2]]);
        if (next === 26) setVisibleFindings(FAKE_FINDINGS);
        
        return next;
      });
    }, 1200);

    return () => clearInterval(timer);
  }, []);

  // Show last 6 modules to create a scrolling terminal effect
  const startIdx = Math.max(0, currentIndex - 5);
  const displayModules = ALL_MODULES.slice(startIdx, startIdx + 6);

  return (
    <div className="relative w-full max-w-2xl flex flex-col md:flex-row gap-4 items-start">
      {/* Scan Module Checklist (Left side) */}
      <div className="w-full md:w-64 flex-shrink-0 rounded-panel border border-card-border bg-card/80 backdrop-blur-sm p-4 nanz-glow-sm relative overflow-hidden">
        <div className="flex items-center gap-2 mb-4 pb-3 border-b border-surface-border">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Scanning shop.example.in
          </span>
        </div>
        
        <div className="space-y-3 min-h-[200px]">
          {displayModules.map((modName, idx) => {
            // Absolute index in the full list
            const absIdx = startIdx + idx;
            const isRunning = absIdx === currentIndex;
            const isDone = absIdx < currentIndex;
            
            return (
              <div key={modName} className="flex items-center gap-3 animate-fade-in">
                {isDone && <CheckCircle2 className="w-4 h-4 text-success flex-shrink-0" />}
                {isRunning && <Zap className="w-4 h-4 text-nanz-400 animate-pulse flex-shrink-0" />}
                <span className={`text-xs truncate ${isDone ? 'text-text-secondary' : isRunning ? 'text-text-primary font-medium' : 'text-text-muted/60'}`}>
                  {modName}
                </span>
                {isRunning && (
                  <span className="text-[9px] text-nanz-400 font-mono ml-auto animate-pulse">running...</span>
                )}
              </div>
            );
          })}
        </div>
        
        <div className="mt-4 pt-3 border-t border-surface-border">
          <div className="flex items-center justify-between text-xs text-text-muted mb-1.5">
            <span>{currentIndex}/{ALL_MODULES.length} modules</span>
            <span className="text-nanz-400 font-medium">
              {currentIndex >= ALL_MODULES.length - 1 ? 'Complete' : 'Scanning...'}
            </span>
          </div>
          <div className="h-1.5 rounded-full bg-surface-border overflow-hidden">
            <div
              className="h-full rounded-full bg-nanz-gradient transition-all duration-300 ease-out"
              style={{ width: `${(currentIndex / ALL_MODULES.length) * 100}%` }}
            />
          </div>
        </div>
      </div>

      {/* Findings Container (Right side) */}
      <div className="w-full flex-1 flex flex-col gap-3 min-h-[200px]">
        {visibleFindings.map((finding, idx) => {
          const isCritical = finding.severity === 'CRITICAL';
          const isHigh = finding.severity === 'HIGH';
          const isMedium = finding.severity === 'MEDIUM';
          
          return (
            <div
              key={idx}
              className="animate-fade-in rounded-card border bg-card p-3.5 shadow-lg relative overflow-hidden"
              style={{
                borderColor: isCritical ? 'rgba(239, 68, 68, 0.3)' : isHigh ? 'rgba(249, 115, 22, 0.3)' : isMedium ? 'rgba(234, 179, 8, 0.3)' : 'rgba(59, 130, 246, 0.3)',
                backgroundColor: isCritical ? 'rgba(239, 68, 68, 0.05)' : isHigh ? 'rgba(249, 115, 22, 0.05)' : isMedium ? 'rgba(234, 179, 8, 0.05)' : 'rgba(59, 130, 246, 0.05)'
              }}
            >
              <div className="flex items-start gap-2.5">
                {isCritical || isHigh ? <AlertTriangle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${isCritical ? 'text-critical' : 'text-high'}`} /> : 
                 isMedium ? <ShieldAlert className="w-4 h-4 text-medium flex-shrink-0 mt-0.5" /> :
                 <Info className="w-4 h-4 text-low flex-shrink-0 mt-0.5" />}
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide
                      ${isCritical ? 'bg-critical/20 text-critical' : isHigh ? 'bg-high/20 text-high' : isMedium ? 'bg-medium/20 text-medium' : 'bg-low/20 text-low'}`}>
                      {finding.severity}
                    </span>
                    <span className="text-xs font-semibold text-text-primary truncate">{finding.title}</span>
                  </div>
                  <p className="text-[11px] text-text-secondary leading-relaxed mb-2">
                    {finding.desc}
                  </p>
                  {(finding.penalty !== 'N/A' || finding.ale !== 'N/A') && (
                    <div className="flex items-center gap-2 text-[9px]">
                      {finding.penalty !== 'N/A' && <span className="text-critical font-semibold">Penalty: {finding.penalty}</span>}
                      {finding.penalty !== 'N/A' && finding.ale !== 'N/A' && <span className="text-text-muted">•</span>}
                      {finding.ale !== 'N/A' && <span className="text-text-muted">ALE: {finding.ale}</span>}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
