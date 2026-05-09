'use client';

import { useRef } from 'react';
import { AlertCircle, Clock, Calendar } from 'lucide-react';
import { RiskItem } from '@/types';
import { normalizeSeverity } from '@/lib/severity';

interface SmartSummaryBarProps {
  findings: RiskItem[];
  onPillClick?: (tier: 'immediate' | 'week' | 'month') => void;
}

export default function SmartSummaryBar({ findings, onPillClick }: SmartSummaryBarProps) {
  const immediate = findings.filter(f => normalizeSeverity(f.severity) === 'CRITICAL' || f.sla_tier === 'P0');
  const thisWeek = findings.filter(f =>
    (normalizeSeverity(f.severity) === 'HIGH' || f.sla_tier === 'P1') &&
    normalizeSeverity(f.severity) !== 'CRITICAL' && f.sla_tier !== 'P0',
  );
  const thisMonth = findings.filter(f => {
    const ns = normalizeSeverity(f.severity);
    return ns === 'MEDIUM' || f.sla_tier === 'P2' || f.sla_tier === 'P3';
  });

  if (findings.length === 0) return null;

  const handlePill = (tier: 'immediate' | 'week' | 'month') => {
    onPillClick?.(tier);
    // Scroll to section
    const id = tier === 'immediate' ? 'findings-critical' : tier === 'week' ? 'findings-high' : 'findings-medium';
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="flex flex-wrap items-center gap-2 p-3 bg-[#0a0a0d] border border-slate-800/50 rounded-xl mb-6">
      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mr-1">
        Workload:
      </span>

      {immediate.length > 0 && (
        <button
          onClick={() => handlePill('immediate')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-red-950/60 border border-red-800/50 text-red-300 text-xs font-bold hover:bg-red-900/60 transition-colors cursor-pointer"
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
          </span>
          <AlertCircle className="w-3 h-3" />
          {immediate.length} need immediate action (24h)
        </button>
      )}

      {thisWeek.length > 0 && (
        <button
          onClick={() => handlePill('week')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-amber-950/40 border border-amber-800/40 text-amber-400 text-xs font-semibold hover:bg-amber-900/40 transition-colors cursor-pointer"
        >
          <span className="h-2 w-2 rounded-full bg-amber-400" />
          <Clock className="w-3 h-3" />
          {thisWeek.length} fix this week
        </button>
      )}

      {thisMonth.length > 0 && (
        <button
          onClick={() => handlePill('month')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-blue-950/30 border border-blue-800/30 text-blue-400 text-xs font-medium hover:bg-blue-900/30 transition-colors cursor-pointer"
        >
          <span className="h-2 w-2 rounded-full bg-blue-400" />
          <Calendar className="w-3 h-3" />
          {thisMonth.length} address this month
        </button>
      )}
    </div>
  );
}
