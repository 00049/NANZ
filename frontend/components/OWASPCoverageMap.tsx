'use client';

import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info } from 'lucide-react';
import { normalizeSeverity } from '@/lib/severity';

interface OWASPCoverage {
  id: string;
  name: string;
  covered: boolean;
  findings_count: number;
  severity: string;
  modules_tested: string[];
}

interface OWASPCoverageMapProps {
  coverage?: OWASPCoverage[];
  coveredCount?: number;
}

const SEVERITY_META: Record<string, {
  icon: React.ReactNode;
  badgeBg: string;
  badgeText: string;
  badgeBorder: string;
  label: string;
}> = {
  CRITICAL: {
    icon: <XCircle className="w-4 h-4 text-red-400 shrink-0" />,
    badgeBg: 'bg-red-500/10',
    badgeText: 'text-red-400',
    badgeBorder: 'border-red-500/30',
    label: 'Critical',
  },
  HIGH: {
    icon: <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />,
    badgeBg: 'bg-orange-500/10',
    badgeText: 'text-orange-400',
    badgeBorder: 'border-orange-500/30',
    label: 'High',
  },
  MEDIUM: {
    icon: <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />,
    badgeBg: 'bg-yellow-500/10',
    badgeText: 'text-yellow-400',
    badgeBorder: 'border-yellow-500/30',
    label: 'Medium',
  },
  LOW: {
    icon: <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />,
    badgeBg: 'bg-green-500/10',
    badgeText: 'text-green-400',
    badgeBorder: 'border-green-500/30',
    label: 'Low',
  },
  INFO: {
    icon: <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />,
    badgeBg: 'bg-green-500/10',
    badgeText: 'text-green-400',
    badgeBorder: 'border-green-500/30',
    label: 'Pass',
  },
};

const NO_FINDING_META = {
  icon: <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />,
  badgeBg: 'bg-green-500/10',
  badgeText: 'text-green-400',
  badgeBorder: 'border-green-500/30',
  label: 'Pass',
};

function getHeatColor(severity: string, count: number): string {
  if (count === 0) return '#22c55e20';   // green, transparent
  const ns = normalizeSeverity(severity);
  if (ns === 'CRITICAL') return '#ef444440';
  if (ns === 'HIGH')     return '#f9731640';
  if (ns === 'MEDIUM')   return '#eab30840';
  return '#22c55e20';
}

export default function OWASPCoverageMap({ coverage, coveredCount }: OWASPCoverageMapProps) {
  if (!coverage || coverage.length === 0) return null;

  const total = coverage.length;
  const clean = coverage.filter(c => c.findings_count === 0 && c.covered).length;
  const pct = Math.round((clean / total) * 100);

  return (
    <section id="owasp-coverage" className="scroll-mt-8">
      <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2">
        OWASP Top 10 — 2021 Coverage Map
      </h2>

      {/* Summary bar */}
      <div className="flex items-center gap-4 mb-6">
        <div className="flex-1 bg-background rounded-full h-3 overflow-hidden border border-card-border">
          <div
            className="h-full rounded-full bg-gradient-to-r from-primary to-green-400 transition-all duration-1000"
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="text-sm font-black text-text-primary whitespace-nowrap">
          {clean}/{total} categories clear
        </span>
      </div>

      {/* Grid of categories */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {coverage.map((cat) => {
          const meta = cat.findings_count > 0
            ? (SEVERITY_META[normalizeSeverity(cat.severity)] || SEVERITY_META.INFO)
            : NO_FINDING_META;

          return (
            <div
              key={cat.id}
              className={`
                rounded-card border p-4 transition-all
                ${meta.badgeBg} ${meta.badgeBorder}
              `}
              style={{ borderColor: '', backgroundColor: getHeatColor(cat.severity, cat.findings_count) }}
            >
              <div className="flex items-start gap-3">
                {meta.icon}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <span className="text-xs font-black text-primary mr-2">{cat.id}</span>
                      <span className="text-sm font-semibold text-text-primary">{cat.name}</span>
                    </div>
                    {cat.findings_count > 0 && (
                      <span
                        className={`text-xs font-black px-2 py-0.5 rounded-full border ${meta.badgeBg} ${meta.badgeText} ${meta.badgeBorder} shrink-0`}
                      >
                        {cat.findings_count} finding{cat.findings_count !== 1 ? 's' : ''}
                      </span>
                    )}
                  </div>

                  {/* Modules tested */}
                  {cat.modules_tested.length > 0 ? (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {cat.modules_tested.map((m) => (
                        <span
                          key={m}
                          className="text-[10px] bg-card-border/30 text-text-muted px-1.5 py-0.5 rounded font-mono"
                        >
                          {m.replace(/_check$|_security$/, '')}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-text-muted mt-1 opacity-60">Not tested</p>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 mt-4 text-xs text-text-muted">
        {[
          { color: '#ef444440', label: 'Critical findings' },
          { color: '#f9731640', label: 'High findings' },
          { color: '#eab30840', label: 'Medium findings' },
          { color: '#22c55e20', label: 'No findings' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded" style={{ backgroundColor: color, border: '1px solid rgba(255,255,255,0.1)' }} />
            <span>{label}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
