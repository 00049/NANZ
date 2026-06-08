'use client';

import { Shield, AlertTriangle, CheckCircle2, XCircle, Info } from 'lucide-react';

interface ComplianceClause {
  framework: string;
  clause_id: string;
  clause_title: string;
  description: string;
  severity: string;
}

interface FrameworkReport {
  framework: string;
  full_name: string;
  readiness_score: number;
  violated_clauses: ComplianceClause[];
  compliant_controls: string[];
  summary: string;
}

interface ComplianceData {
  dpdp: FrameworkReport;
  gdpr: FrameworkReport;
  pci_dss: FrameworkReport;
  soc2: FrameworkReport;
  dora: FrameworkReport;
}

const FRAMEWORK_COLORS: Record<string, { ring: string; bg: string; label: string }> = {
  DPDP:    { ring: 'border-orange-500', bg: 'bg-orange-500/10', label: 'text-orange-400' },
  GDPR:    { ring: 'border-blue-500',   bg: 'bg-blue-500/10',   label: 'text-blue-400'   },
  PCI_DSS: { ring: 'border-purple-500', bg: 'bg-purple-500/10', label: 'text-purple-400' },
  SOC2:    { ring: 'border-cyan-500',   bg: 'bg-cyan-500/10',   label: 'text-cyan-400'   },
  DORA:    { ring: 'border-rose-500',   bg: 'bg-rose-500/10',   label: 'text-rose-400'   },
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
  HIGH:     'bg-orange-500/20 text-orange-400 border-orange-500/40',
  MEDIUM:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  LOW:      'bg-blue-500/20 text-blue-400 border-blue-500/40',
};

function ScoreGauge({ score, color }: { score: number; color: string }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const progress = circumference - (score / 100) * circumference;

  const strokeColor = score >= 80 ? '#22c55e' : score >= 60 ? '#f59e0b' : score >= 35 ? '#f97316' : '#ef4444';

  return (
    <div className="relative w-24 h-24 flex items-center justify-center">
      <svg className="w-24 h-24 -rotate-90" viewBox="0 0 88 88">
        <circle cx="44" cy="44" r={radius} stroke="rgba(255,255,255,0.08)" strokeWidth="8" fill="none" />
        <circle
          cx="44" cy="44" r={radius}
          stroke={strokeColor}
          strokeWidth="8"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-black text-text-primary">{score}</span>
        <span className="text-[10px] text-text-muted font-medium">/ 100</span>
      </div>
    </div>
  );
}

function FrameworkCard({ report }: { report: FrameworkReport }) {
  const key = report.framework.replace(/ /g, '_').toUpperCase();
  const colors = FRAMEWORK_COLORS[key] || FRAMEWORK_COLORS['GDPR'];
  const [expanded, setExpanded] = React.useState(false);

  const quality =
    report.readiness_score >= 80 ? { label: 'Compliant', icon: <CheckCircle2 className="w-4 h-4 text-green-400" /> } :
    report.readiness_score >= 60 ? { label: 'Mostly Compliant', icon: <Info className="w-4 h-4 text-yellow-400" /> } :
    report.readiness_score >= 35 ? { label: 'Gaps Identified', icon: <AlertTriangle className="w-4 h-4 text-orange-400" /> } :
    { label: 'Non-Compliant', icon: <XCircle className="w-4 h-4 text-red-400" /> };

  return (
    <div className={`rounded-card border ${colors.ring} ${colors.bg} p-5 flex flex-col gap-4 break-inside-avoid mb-4`}>
      <div className="flex items-center justify-between">
        <div>
          <h3 className={`font-bold text-lg ${colors.label}`}>{report.full_name}</h3>
          <div className="flex items-center gap-1.5 mt-1 text-sm text-text-muted">
            {quality.icon}
            <span>{quality.label}</span>
          </div>
        </div>
        <ScoreGauge score={report.readiness_score} color={key} />
      </div>

      <p className="text-sm text-text-muted leading-relaxed">{report.summary}</p>

      {report.violated_clauses.length > 0 && (
        <div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs font-semibold text-text-muted hover:text-text-primary transition-colors"
          >
            {expanded ? '▲ Hide' : '▼ Show'} {report.violated_clauses.length} violated clause(s)
          </button>

          {expanded && (
            <div className="mt-3 space-y-2">
              {report.violated_clauses.map((clause, i) => (
                <div key={i} className="bg-background/60 rounded-lg p-3 border border-card-border">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold text-text-primary font-mono">{clause.clause_id}</span>
                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${SEVERITY_COLORS[clause.severity] || SEVERITY_COLORS.MEDIUM}`}>
                      {clause.severity}
                    </span>
                  </div>
                  <p className="text-xs font-semibold text-text-primary">{clause.clause_title}</p>
                  <p className="text-xs text-text-muted mt-1 leading-relaxed">{clause.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {report.compliant_controls.length > 0 && (
        <div className="space-y-1">
          {report.compliant_controls.slice(0, 3).map((ctrl, i) => (
            <div key={i} className="flex items-center gap-2 text-xs text-green-400">
              <CheckCircle2 className="w-3 h-3 flex-shrink-0" />
              <span>{ctrl}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

import React from 'react';

export default function ComplianceReport({ data }: { data: ComplianceData | null }) {
  if (!data) return null;

  const frameworks = [data.dpdp, data.gdpr, data.pci_dss, data.soc2, data.dora];
  const avgScore = Math.round(frameworks.reduce((sum, f) => sum + f.readiness_score, 0) / frameworks.length);

  return (
    <section id="compliance" className="scroll-mt-8">
      <div className="flex items-center gap-3 mb-6 border-b border-card-border pb-3">
        <Shield className="w-6 h-6 text-primary" />
        <h2 className="text-2xl font-bold text-text-primary">Regulatory Compliance Assessment</h2>
        <span className="ml-auto bg-primary/20 text-primary font-black text-sm px-3 py-1 rounded-full border border-primary/30">
          Avg: {avgScore}/100
        </span>
      </div>

      <div className="columns-1 md:columns-2 xl:columns-3 gap-4">
        {frameworks.map((fw, i) => (
          <FrameworkCard key={i} report={fw} />
        ))}
      </div>

      <p className="text-xs text-text-muted mt-4 text-center">
        This assessment is based on detected security findings. It is informational and does not substitute a formal compliance audit.
      </p>
    </section>
  );
}
