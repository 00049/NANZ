'use client';

import React from 'react';
import { Shield, AlertTriangle, CheckCircle2, TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface OWASPCategory {
  id: string;
  name: string;
  covered: boolean;
  findings_count: number;
  severity: string;
  modules_tested: string[];
}

interface ASPMData {
  aspm_score: number;
  posture_tier: string;
  posture_label: string;
  posture_color: string;
  posture_description: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_findings: number;
  owasp_coverage: OWASPCategory[];
  owasp_covered_count: number;
  owasp_total: number;
  modules_tested: string[];
  enterprise_modules_active: boolean;
  dpdp_impact: number;
  gdpr_impact: number;
  pci_impact: number;
  score_trend: string;
}

interface ASPMScorePanelProps {
  data?: ASPMData;
}

const SEVERITY_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border-red-500/30' },
  RED:      { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  AMBER:    { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  GREEN:    { bg: 'bg-green-500/10',  text: 'text-green-400',  border: 'border-green-500/30' },
  INFO:     { bg: 'bg-blue-500/10',   text: 'text-blue-400',   border: 'border-blue-500/30' },
};

export default function ASPMScorePanel({ data }: ASPMScorePanelProps) {
  if (!data) return null;

  const { aspm_score, posture_tier, posture_label, posture_color, posture_description } = data;

  const scoreAngle = (aspm_score / 100) * 251.2; // 251.2 = 2*PI*40 (circumference for r=40)

  const TrendIcon = data.score_trend === 'improving' ? TrendingUp
    : data.score_trend === 'declining' ? TrendingDown : Minus;

  return (
    <section id="aspm-posture" className="scroll-mt-8">
      <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2 flex items-center gap-3">
        <Shield className="w-6 h-6 text-primary" />
        ASPM Posture Score
        {data.enterprise_modules_active && (
          <span className="ml-auto text-xs font-bold bg-primary/15 text-primary border border-primary/30 px-2 py-1 rounded-full">
            Enterprise Grade
          </span>
        )}
      </h2>

      <div className="grid md:grid-cols-3 gap-6">
        {/* Gauge */}
        <div className="bg-surface border border-card-border rounded-card p-6 flex flex-col items-center justify-center">
          <div className="relative w-40 h-40 mb-4">
            <svg className="w-40 h-40 -rotate-90" viewBox="0 0 100 100">
              {/* Track */}
              <circle cx="50" cy="50" r="40" fill="none" stroke="#1a1a2e" strokeWidth="10" />
              {/* Score arc */}
              <circle
                cx="50" cy="50" r="40"
                fill="none"
                stroke={posture_color}
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray={`${scoreAngle} 251.2`}
                style={{ transition: 'stroke-dasharray 1s ease' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-4xl font-black text-text-primary">{aspm_score}</span>
              <span className="text-xs text-text-muted font-semibold">/100</span>
            </div>
          </div>

          <div
            className="text-center px-4 py-2 rounded-full font-black text-sm border"
            style={{ color: posture_color, borderColor: `${posture_color}40`, backgroundColor: `${posture_color}15` }}
          >
            {posture_label}
          </div>

          <div className="flex items-center gap-1 mt-3 text-xs text-text-muted">
            <TrendIcon className="w-3 h-3" />
            <span className="capitalize">{data.score_trend}</span>
          </div>

          <p className="text-xs text-text-muted text-center mt-3 leading-relaxed">
            {posture_description}
          </p>
        </div>

        {/* Risk Breakdown */}
        <div className="bg-surface border border-card-border rounded-card p-6">
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-4">Risk Breakdown</h3>
          <div className="space-y-3">
            {[
              { label: 'Critical', count: data.critical_count, color: '#ef4444' },
              { label: 'High',     count: data.high_count,     color: '#f97316' },
              { label: 'Medium',   count: data.medium_count,   color: '#eab308' },
              { label: 'Low/Info', count: data.low_count,      color: '#22c55e' },
            ].map(({ label, count, color }) => (
              <div key={label}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-text-muted">{label}</span>
                  <span className="font-bold" style={{ color }}>{count}</span>
                </div>
                <div className="h-1.5 bg-background rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: data.total_findings > 0 ? `${Math.min(100, (count / data.total_findings) * 100)}%` : '0%',
                      backgroundColor: color,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 pt-4 border-t border-card-border">
            <div className="text-sm text-text-muted mb-3 font-semibold">Compliance Exposure</div>
            {[
              { label: 'DPDP Act',  value: data.dpdp_impact, color: '#00b4d8' },
              { label: 'GDPR',      value: data.gdpr_impact,  color: '#7c3aed' },
              { label: 'PCI DSS',   value: data.pci_impact,   color: '#f59e0b' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex items-center gap-2 text-xs mb-2">
                <span className="text-text-muted w-16 shrink-0">{label}</span>
                <div className="flex-1 h-1.5 bg-background rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${value}%`, backgroundColor: color }}
                  />
                </div>
                <span className="font-bold w-6 text-right" style={{ color }}>
                  {Math.round(value)}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Module Coverage */}
        <div className="bg-surface border border-card-border rounded-card p-6">
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-4">
            OWASP Top 10 Coverage ({data.owasp_covered_count}/{data.owasp_total})
          </h3>
          <div className="space-y-2">
            {(data.owasp_coverage || []).map((cat) => {
              const sev = SEVERITY_STYLES[cat.severity] || SEVERITY_STYLES.INFO;
              return (
                <div
                  key={cat.id}
                  className={`flex items-center justify-between text-xs rounded-md px-2 py-1.5 border ${
                    cat.covered ? `${sev.bg} ${sev.border}` : 'bg-background/50 border-card-border opacity-40'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {cat.findings_count > 0 ? (
                      <AlertTriangle className={`w-3 h-3 ${sev.text}`} />
                    ) : (
                      <CheckCircle2 className="w-3 h-3 text-green-400" />
                    )}
                    <span className="font-bold text-text-primary">{cat.id}</span>
                    <span className="text-text-muted truncate max-w-[100px]">{cat.name}</span>
                  </div>
                  {cat.findings_count > 0 && (
                    <span className={`font-black text-[10px] ${sev.text}`}>{cat.findings_count}</span>
                  )}
                </div>
              );
            })}
          </div>

          <div className="mt-3 pt-3 border-t border-card-border">
            <p className="text-xs text-text-muted">
              <span className="font-bold text-primary">{data.modules_tested?.length || 0}</span> scan modules run
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
