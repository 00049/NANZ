'use client';

import { useState } from 'react';
import { BarChart2, ChevronDown, ChevronUp, Globe, Zap, BookOpen, CreditCard, Shield } from 'lucide-react';
import { RiskItem } from '@/types';

interface FindingPriorityBadgeProps {
  finding: RiskItem;
}

export default function FindingPriorityBadge({ finding }: FindingPriorityBadgeProps) {
  const [open, setOpen] = useState(false);

  const reasons: { icon: React.ReactNode; text: string; priority: 'critical' | 'high' | 'normal' }[] = [];

  // Build factual reason list
  if (finding.cisa_kev) {
    reasons.push({
      icon: <span className="text-red-400">🚨</span>,
      text: 'In CISA Known Exploited Vulnerabilities catalog',
      priority: 'critical',
    });
  }
  if (finding.epss_score !== undefined && finding.epss_score >= 0.5) {
    reasons.push({
      icon: <Zap className="w-3 h-3 text-red-400" />,
      text: `EPSS ${(finding.epss_score * 100).toFixed(0)}% — actively exploited in the wild`,
      priority: 'critical',
    });
  } else if (finding.epss_score !== undefined && finding.epss_score >= 0.3) {
    reasons.push({
      icon: <Zap className="w-3 h-3 text-amber-400" />,
      text: `EPSS ${(finding.epss_score * 100).toFixed(0)}% — elevated exploit probability`,
      priority: 'high',
    });
  }
  if (finding.severity_adjusted && finding.severity_reason) {
    reasons.push({
      icon: <BarChart2 className="w-3 h-3 text-orange-400" />,
      text: `Severity escalated: ${finding.severity_reason}`,
      priority: 'high',
    });
  }
  if (finding.compliance_violations && finding.compliance_violations.length > 0) {
    finding.compliance_violations.slice(0, 2).forEach(v => {
      const vStr = typeof v === 'string' ? v : `${v?.framework || ''} ${v?.clause_id || ''}`.trim();
      reasons.push({
        icon: <BookOpen className="w-3 h-3 text-purple-400" />,
        text: `Regulatory violation: ${vStr}`,
        priority: 'high',
      });
    });
  }
  if (finding.check_domain === 'payment' || finding.module?.includes('payment')) {
    reasons.push({
      icon: <CreditCard className="w-3 h-3 text-amber-400" />,
      text: 'Near payment processing endpoint',
      priority: 'high',
    });
  }
  if (!finding.source_scanner && finding.severity !== 'GREEN' && finding.severity !== 'INFO') {
    reasons.push({
      icon: <Globe className="w-3 h-3 text-blue-400" />,
      text: 'Externally visible from the public internet',
      priority: 'normal',
    });
  }
  if (finding.sla_tier === 'P0') {
    reasons.push({
      icon: <Shield className="w-3 h-3 text-red-400" />,
      text: 'P0 SLA — must be fixed within 24 hours',
      priority: 'critical',
    });
  }

  if (reasons.length === 0) return null;

  return (
    <div className="relative">
      <button
        onClick={(e) => { e.stopPropagation(); setOpen(o => !o); }}
        className="inline-flex items-center gap-1 text-[10px] font-medium text-slate-500 hover:text-slate-300 transition-colors"
        aria-label="Why is this finding prioritized?"
      >
        <BarChart2 className="w-3 h-3" />
        <span>Why prioritized</span>
        {open ? <ChevronUp className="w-2.5 h-2.5" /> : <ChevronDown className="w-2.5 h-2.5" />}
      </button>

      {open && (
        <div className="absolute bottom-full left-0 mb-2 z-30 w-72 bg-[#0d0d12] border border-slate-700/60 rounded-xl shadow-2xl p-4">
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2.5">
            Why this is prioritized:
          </p>
          <ul className="space-y-1.5">
            {reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="mt-0.5 shrink-0">{r.icon}</span>
                <span
                  className={`text-xs ${
                    r.priority === 'critical' ? 'text-red-300' :
                    r.priority === 'high' ? 'text-amber-300' : 'text-slate-400'
                  }`}
                >
                  {r.text}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
