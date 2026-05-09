'use client';

import { useState, useCallback, useMemo } from 'react';
import { ShieldAlert, AlertTriangle, Info, ShieldCheck, Zap, Copy, CheckCircle2 } from 'lucide-react';
import { RiskItem, VisualWeight, FixDifficulty, SLATier, formatALE, aleColorClass, severityToWeight } from '@/types';
import { normalizeSeverity } from '@/lib/severity';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import FindingPriorityBadge from './FindingPriorityBadge';

// ─── Visual weight config ──────────────────────────────────────────────────────

const WEIGHT_CONFIG: Record<VisualWeight, {
  card: string;
  border: string;
  titleSize: string;
  shadow: string;
  pulse: boolean;
  defaultExpanded: boolean;
  badgeBg: string;
  badgeText: string;
  dotClass: string;
  sectionBg: string;
}> = {
  critical: {
    card: 'bg-[#450a0a]',
    border: 'border-[#dc2626] border-2',
    titleSize: 'text-[18px] font-black',
    shadow: 'shadow-[0_0_32px_-4px_rgba(220,38,38,0.5)] drop-shadow-xl',
    pulse: true,
    defaultExpanded: true,
    badgeBg: 'bg-red-950 border-red-700',
    badgeText: 'text-red-300',
    dotClass: 'animate-ping',
    sectionBg: 'bg-red-950/40',
  },
  high: {
    card: 'bg-[#1c0a0a]',
    border: 'border-[#ef4444] border',
    titleSize: 'text-base font-bold',
    shadow: 'shadow-lg',
    pulse: false,
    defaultExpanded: true,
    badgeBg: 'bg-red-950/60 border-red-800/50',
    badgeText: 'text-red-400',
    dotClass: '',
    sectionBg: 'bg-red-950/20',
  },
  medium: {
    card: 'bg-[#1c1209]',
    border: 'border-[#f59e0b] border',
    titleSize: 'text-sm font-semibold',
    shadow: 'shadow-md',
    pulse: false,
    defaultExpanded: false,
    badgeBg: 'bg-amber-950/50 border-amber-800/40',
    badgeText: 'text-amber-400',
    dotClass: '',
    sectionBg: 'bg-amber-950/20',
  },
  low: {
    card: 'bg-[#0a1a0e]',
    border: 'border-[#22c55e]/40 border border-[0.5px]',
    titleSize: 'text-[13px] font-medium',
    shadow: '',
    pulse: false,
    defaultExpanded: false,
    badgeBg: 'bg-green-950/30 border-green-900/30',
    badgeText: 'text-green-600',
    dotClass: '',
    sectionBg: '',
  },
  info: {
    card: 'bg-transparent',
    border: 'border-slate-800/40 border',
    titleSize: 'text-xs font-medium',
    shadow: '',
    pulse: false,
    defaultExpanded: false,
    badgeBg: 'bg-slate-900/30 border-slate-700/30',
    badgeText: 'text-slate-600',
    dotClass: '',
    sectionBg: '',
  },
};

// ─── Fix button config ─────────────────────────────────────────────────────────

function getFixButtonConfig(
  difficulty: FixDifficulty | undefined,
  fixTime: string | undefined,
  severity: string,
  slaTier: SLATier | undefined,
  onFix: () => void,
) {
  // P0 Critical — URGENT red blinking
  if (severity === 'CRITICAL' || slaTier === 'P0') {
    return (
      <button
        onClick={onFix}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-500 text-white border border-red-500 animate-pulse transition-all"
      >
        <span>🚨</span>
        <span>URGENT: Fix Now</span>
      </button>
    );
  }
  // Easy — Quick win
  if (difficulty === 'Easy') {
    return (
      <button
        onClick={onFix}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white border border-blue-500 transition-all"
      >
        <Zap className="w-3 h-3" />
        <span>Fix Now — {fixTime || 'Quick'}</span>
      </button>
    );
  }
  // Medium — Guide
  if (difficulty === 'Medium') {
    return (
      <button
        onClick={onFix}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-transparent border border-blue-600 text-blue-400 hover:bg-blue-950/40 transition-all"
      >
        <span>📋</span>
        <span>View Fix Guide</span>
      </button>
    );
  }
  // Hard — Assign
  return (
    <button
      onClick={onFix}
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-transparent border border-slate-600 text-slate-400 hover:border-slate-500 transition-all"
    >
      <span>👨‍💻</span>
      <span>Assign to Developer</span>
    </button>
  );
}

// ─── Severity badge (delegated to shared component) ────────────────────────────────────────

function RiskCardSeverityBadge({ severity, cfg }: { severity: string; cfg: typeof WEIGHT_CONFIG[VisualWeight] }) {
  const normalized = normalizeSeverity(severity);
  return (
    <div className="inline-flex items-center gap-1.5">
      {/* Animated dot for critical */}
      {normalized === 'CRITICAL' && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
        </span>
      )}
      <SeverityBadge severity={normalized} size="sm" />
    </div>
  );
}

// ─── Main RiskCard component ───────────────────────────────────────────────────

interface RiskCardProps {
  finding: RiskItem;
  visualWeight?: VisualWeight;
  isBlurred?: boolean;
  onFixClick?: (finding: RiskItem) => void;
  // Legacy props (backward compat)
  title?: string;
  severity?: string;
  business_impact?: string;
}

export default function RiskCard({
  finding,
  visualWeight,
  isBlurred = false,
  onFixClick,
  // Legacy compat
  title: legacyTitle,
  severity: legacySeverity,
  business_impact: legacyImpact,
}: RiskCardProps) {
  // Support both new (finding object) and legacy (individual props) call signatures
  const item: RiskItem = useMemo(() => finding ?? {
    title: legacyTitle ?? '',
    severity: (legacySeverity as any) ?? 'INFO',
    business_impact: legacyImpact ?? '',
    fix_action: '',
  }, [finding, legacyTitle, legacySeverity, legacyImpact]);

  const weight = visualWeight ?? severityToWeight(item.severity as any);
  const cfg = WEIGHT_CONFIG[weight];
  const [expanded, setExpanded] = useState(cfg.defaultExpanded);
  const [copied, setCopied] = useState(false);

  const isMinimal = weight === 'info';

  const handleCopy = useCallback(() => {
    const text = `${item.title}\nSeverity: ${item.severity}\nImpact: ${item.business_impact}\nFix: ${item.fix_action}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [item]);

  const handleFix = useCallback(() => {
    onFixClick?.(item);
  }, [onFixClick, item]);

  // INFO: single line only
  if (isMinimal) {
    return (
      <div className={`flex items-center gap-3 px-3 py-2 rounded-lg ${cfg.card} ${cfg.border} ${isBlurred ? 'blur-sm opacity-40 select-none' : ''}`}>
        <span className={`h-1.5 w-1.5 rounded-full bg-slate-600 shrink-0`} />
        <span className={`${cfg.titleSize} text-slate-600 truncate`}>{item.title}</span>
        <span className="ml-auto text-[10px] text-slate-700">INFO</span>
      </div>
    );
  }

  return (
    <div
      className={`
        relative rounded-xl ${cfg.card} ${cfg.border} ${cfg.shadow} transition-all
        ${cfg.pulse ? 'animate-[criticalPulse_3s_ease-in-out_infinite]' : ''}
        ${isBlurred ? 'blur-sm select-none opacity-60' : ''}
      `}
      style={cfg.pulse ? {
        animation: 'criticalBorderPulse 3s ease-in-out infinite',
      } : undefined}
    >
      {/* Critical pulse border overlay */}
      {cfg.pulse && !isBlurred && (
        <div className="absolute inset-0 rounded-xl border-2 border-red-500/60 animate-ping pointer-events-none" />
      )}

      <div className="relative p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <RiskCardSeverityBadge severity={item.severity} cfg={cfg} />

            {/* CISA KEV badge */}
            {item.cisa_kev && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 border border-red-700/60 text-red-300">
                🚨 CISA KEV
              </span>
            )}

            {/* EPSS badge */}
            {item.epss_score !== undefined && item.epss_score >= 0.3 && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950/60 border border-orange-700/40 text-orange-300">
                ⚡ EPSS {(item.epss_score * 100).toFixed(0)}%
              </span>
            )}

            {/* SLA badge */}
            {item.sla_tier === 'P0' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 border border-red-800/50 text-red-400">
                P0 — 24h SLA
              </span>
            )}
            {item.sla_tier === 'P1' && item.severity !== 'CRITICAL' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-amber-950/40 border border-amber-800/30 text-amber-500">
                P1 — 7 days
              </span>
            )}
          </div>

          {!isBlurred && (
            <button
              onClick={handleCopy}
              className="shrink-0 text-slate-600 hover:text-slate-300 transition-colors"
              title="Copy finding details"
            >
              {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          )}
        </div>

        {/* Title */}
        <h4
          className={`${cfg.titleSize} text-slate-100 mb-2 leading-snug cursor-pointer`}
          onClick={() => setExpanded(e => !e)}
        >
          {item.title}
          {!cfg.defaultExpanded && (
            <span className="ml-2 text-[10px] text-slate-600 font-normal">
              {expanded ? '▲' : '▼'}
            </span>
          )}
        </h4>

        {/* Business impact — always visible */}
        <p className={`text-sm mb-3 leading-relaxed ${
          weight === 'critical' ? 'text-red-200' :
          weight === 'high' ? 'text-red-300/80' :
          weight === 'medium' ? 'text-amber-200/70' :
          'text-slate-500'
        }`}>
          {item.business_impact}
        </p>

        {/* ALE display */}
        {item.ale_reduction_inr !== undefined && item.ale_reduction_inr > 0 && (
          <div className={`text-xs font-semibold mb-3 ${aleColorClass(item.ale_reduction_inr)}`}>
            {item.ale_display || formatALE(item.ale_reduction_inr)} estimated annual loss prevented
          </div>
        )}

        {/* Expanded section */}
        {expanded && (
          <div className={`mt-3 pt-3 border-t ${
            weight === 'critical' ? 'border-red-800/30' :
            weight === 'high' ? 'border-red-900/30' :
            weight === 'medium' ? 'border-amber-900/30' : 'border-slate-800/30'
          } space-y-3`}>

            {/* Technical detail */}
            {item.technical_detail && (
              <p className="text-xs text-slate-400 leading-relaxed">{item.technical_detail}</p>
            )}

            {/* CVE info */}
            {item.cve_id && (
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-slate-600">CVE:</span>
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] font-mono text-blue-400 hover:underline"
                >
                  {item.cve_id}
                </a>
                {item.cvss_score && (
                  <span className="text-[10px] text-slate-500">CVSS {item.cvss_score.toFixed(1)}</span>
                )}
              </div>
            )}

            {/* RRF display */}
            {item.rrf_display && (
              <div className="text-xs text-slate-500">
                {item.rrf_display}
              </div>
            )}

            {/* Compliance violations */}
            {item.compliance_violations && item.compliance_violations.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {item.compliance_violations.map((v, i) => (
                  <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-purple-950/50 border border-purple-800/40 text-purple-300 font-mono">
                    {v}
                  </span>
                ))}
              </div>
            )}

            {/* Priority badge */}
            {!isBlurred && <FindingPriorityBadge finding={item} />}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-white/5">
          <div className="flex items-center gap-2">
            {item.fix_difficulty && (
              <span className={`text-[10px] font-medium px-2 py-0.5 rounded ${
                item.fix_difficulty === 'Easy' ? 'bg-green-950/50 text-green-500' :
                item.fix_difficulty === 'Medium' ? 'bg-blue-950/50 text-blue-400' :
                'bg-slate-900/50 text-slate-500'
              } border border-white/5`}>
                {item.fix_difficulty}
              </span>
            )}
            {item.estimated_fix_time && (
              <span className="text-[10px] text-slate-600">{item.estimated_fix_time}</span>
            )}
          </div>
          {!isBlurred && getFixButtonConfig(
            item.fix_difficulty,
            item.estimated_fix_time,
            item.severity,
            item.sla_tier,
            handleFix,
          )}
        </div>
      </div>
    </div>
  );
}
