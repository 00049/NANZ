'use client';

import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Code2, TrendingUp, ShieldCheck, Clock, Zap } from 'lucide-react';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/20 border-red-500/40',
  RED:      'text-red-400 bg-red-500/20 border-red-500/40',
  AMBER:    'text-yellow-400 bg-yellow-500/20 border-yellow-500/40',
  GREEN:    'text-green-400 bg-green-500/20 border-green-500/40',
  INFO:     'text-blue-400 bg-blue-500/20 border-blue-500/40',
};

const PHASE_META = [
  {
    id: 'phase_1_immediate',
    label: 'Phase 1 — Fix Today',
    icon: <Zap className="w-5 h-5 text-red-400" />,
    border: 'border-red-500',
    bg: 'bg-red-500/5',
    time: '< 4 hours',
  },
  {
    id: 'phase_2_short_term',
    label: 'Phase 2 — Fix This Week',
    icon: <TrendingUp className="w-5 h-5 text-yellow-400" />,
    border: 'border-yellow-500',
    bg: 'bg-yellow-500/5',
    time: '1–3 days',
  },
  {
    id: 'phase_3_long_term',
    label: 'Phase 3 — Fix This Month',
    icon: <ShieldCheck className="w-5 h-5 text-blue-400" />,
    border: 'border-blue-500',
    bg: 'bg-blue-500/5',
    time: '1–4 weeks',
  },
];

function CodeFix({ code, framework }: { code: string; framework?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-card-border overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-[#1a1a2e] border-b border-card-border">
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 text-primary opacity-70" />
          <span className="text-xs font-bold text-text-muted uppercase tracking-wider">
            {framework ? `${framework} Fix` : 'Remediation Code'}
          </span>
        </div>
        <button
          onClick={handleCopy}
          className="text-xs font-semibold text-text-muted hover:text-primary transition-colors"
        >
          {copied ? '✓ Copied!' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 text-xs text-green-300 font-mono leading-relaxed overflow-x-auto bg-[#0d0d1a] whitespace-pre-wrap">
        {code}
      </pre>
    </div>
  );
}

function FindingItem({ finding, framework }: { finding: any; framework?: string }) {
  const [expanded, setExpanded] = useState(false);
  const severity = finding.severity || 'INFO';
  const severityColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.INFO;

  const hasCodeFix = finding.code_fix && finding.code_fix.trim().length > 0;
  const delta = finding.risk_score_reduction_delta || 0;
  const regulatory = finding.regulatory_impact || [];

  return (
    <div className="bg-background rounded-lg border border-card-border overflow-hidden">
      <div className="p-5">
        <div className="flex items-start justify-between mb-2">
          <h4 className="font-bold text-text-primary text-base pr-4 leading-snug">
            {finding.title || finding.display_title || finding.key}
          </h4>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`text-[11px] font-bold uppercase px-2 py-0.5 rounded border ${severityColor}`}>
              {severity}
            </span>
            {delta > 0 && (
              <span className="text-[11px] font-bold text-green-400 bg-green-500/10 border border-green-500/30 px-2 py-0.5 rounded">
                +{delta}pts after fix
              </span>
            )}
          </div>
        </div>

        <p className="text-sm text-text-muted leading-relaxed mb-3">
          {finding.business_impact || finding.plain_english || ''}
        </p>

        {/* ROI badge */}
        {finding.roi_score !== undefined && (
          <div className="flex items-center gap-4 text-xs text-text-muted mb-3">
            <span>ROI Score: <strong className="text-text-primary">{finding.roi_score}</strong></span>
            {finding.fix_difficulty && (
              <span>Effort: <strong className="text-text-primary">{finding.fix_difficulty}</strong></span>
            )}
            {finding.estimated_fix_time && (
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {finding.estimated_fix_time}
              </span>
            )}
          </div>
        )}

        {/* Regulatory impact */}
        {regulatory.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-3">
            {regulatory.map((clause: string, i: number) => (
              <span key={i} className="text-[10px] font-bold text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded">
                {clause}
              </span>
            ))}
          </div>
        )}

        {/* Fix instructions */}
        {(finding.detailed_fix_steps || finding.fix_action) && (
          <div className="bg-surface rounded-md p-3 mb-3 border border-card-border">
            <h5 className="text-xs font-bold text-text-primary mb-1 uppercase tracking-wider">Fix Instructions:</h5>
            <p className="text-xs text-text-muted whitespace-pre-line leading-relaxed">
              {finding.detailed_fix_steps || finding.fix_action}
            </p>
          </div>
        )}

        {/* Code fix toggle */}
        {hasCodeFix && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-2 text-xs font-semibold text-primary hover:text-primary/80 transition-colors"
          >
            <Code2 className="w-3.5 h-3.5" />
            {expanded ? 'Hide' : 'Show'} code fix
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {hasCodeFix && expanded && (
        <div className="px-5 pb-5">
          <CodeFix code={finding.code_fix} framework={framework} />
        </div>
      )}
    </div>
  );
}

export default function RemediationRoadmap({ roadmap }: { roadmap: any }) {
  if (!roadmap) return null;

  const phases = roadmap?.phases || {};
  const framework = roadmap?.detected_framework;
  const totalItems = roadmap?.total_items || 0;
  const estimatedGain = roadmap?.estimated_score_gain || 0;

  return (
    <section id="roadmap" className="scroll-mt-8 space-y-6">
      <div className="flex items-center gap-3 mb-6 border-b border-card-border pb-3">
        <TrendingUp className="w-6 h-6 text-primary" />
        <h2 className="text-2xl font-bold text-text-primary">Remediation Roadmap</h2>
        <div className="ml-auto flex items-center gap-3">
          {framework && framework !== 'default' && (
            <span className="text-xs font-bold text-primary bg-primary/10 border border-primary/20 px-3 py-1 rounded-full">
              {framework.toUpperCase()} detected
            </span>
          )}
          {estimatedGain > 0 && (
            <span className="text-xs font-bold text-green-400 bg-green-500/10 border border-green-500/30 px-3 py-1 rounded-full">
              Potential +{estimatedGain}pt score gain
            </span>
          )}
        </div>
      </div>

      {totalItems === 0 ? (
        <div className="bg-green-500/10 border border-green-500/30 rounded-card p-8 text-center">
          <ShieldCheck className="w-12 h-12 text-green-400 mx-auto mb-3" />
          <h3 className="font-bold text-green-400 text-lg">No Remediation Items</h3>
          <p className="text-text-muted text-sm mt-1">Your platform has no actionable findings requiring a fix.</p>
        </div>
      ) : (
        PHASE_META.map((meta) => {
          const findings = phases[meta.id] || [];
          if (findings.length === 0) return null;

          return (
            <div
              key={meta.id}
              className={`rounded-card border-l-4 ${meta.border} ${meta.bg} shadow-lg overflow-hidden`}
            >
              <div className="flex items-center justify-between px-6 py-4 border-b border-card-border">
                <div className="flex items-center gap-3">
                  {meta.icon}
                  <h3 className="text-lg font-bold text-text-primary">{meta.label}</h3>
                  <span className="text-xs font-bold bg-surface border border-card-border text-text-muted px-2 py-0.5 rounded">
                    {findings.length} item{findings.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-text-muted">
                  <Clock className="w-3.5 h-3.5" />
                  {meta.time}
                </div>
              </div>

              <div className="p-6 space-y-4">
                {findings.map((finding: any, idx: number) => (
                  <FindingItem key={idx} finding={finding} framework={framework} />
                ))}
              </div>
            </div>
          );
        })
      )}
    </section>
  );
}
