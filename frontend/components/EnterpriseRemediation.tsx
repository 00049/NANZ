'use client';

import React, { useState } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, ChevronDown, ChevronRight, Cpu, Globe, GitBranch, Layers, Shield, Zap } from 'lucide-react';

interface RemediationItem {
  priority: number;
  severity: string;
  title: string;
  finding_key: string;
  module: string;
  estimated_fix_time: string;
  impact_score: number;
  quick_win: boolean;
}

interface EnterpriseRemediationProps {
  roadmap?: RemediationItem[];
  quickWins?: RemediationItem[];
  immediateActions?: RemediationItem[];
}

const SEVERITY_CONFIG: Record<string, {
  bg: string; text: string; border: string; label: string; icon: React.ReactNode;
}> = {
  CRITICAL: { bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border-red-500/30',    label: 'Critical', icon: <XCircle className="w-3.5 h-3.5" /> },
  RED:      { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30', label: 'High',     icon: <AlertTriangle className="w-3.5 h-3.5" /> },
  AMBER:    { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30', label: 'Medium',   icon: <AlertTriangle className="w-3.5 h-3.5" /> },
  GREEN:    { bg: 'bg-green-500/10',  text: 'text-green-400',  border: 'border-green-500/30',  label: 'Low',      icon: <CheckCircle2 className="w-3.5 h-3.5" /> },
  INFO:     { bg: 'bg-blue-500/10',   text: 'text-blue-400',   border: 'border-blue-500/30',   label: 'Info',     icon: <CheckCircle2 className="w-3.5 h-3.5" /> },
};

const MODULE_ICONS: Record<string, React.ReactNode> = {
  iast:           <Cpu className="w-3.5 h-3.5 text-purple-400" />,
  oast:           <Globe className="w-3.5 h-3.5 text-blue-400" />,
  api_security:   <Layers className="w-3.5 h-3.5 text-cyan-400" />,
  graphql:        <GitBranch className="w-3.5 h-3.5 text-pink-400" />,
  business_logic: <Shield className="w-3.5 h-3.5 text-amber-400" />,
  container:      <Zap className="w-3.5 h-3.5 text-orange-400" />,
  dependency:     <GitBranch className="w-3.5 h-3.5 text-green-400" />,
  llm_security:   <Cpu className="w-3.5 h-3.5 text-violet-400" />,
  ssl:            <Shield className="w-3.5 h-3.5 text-blue-400" />,
  headers:        <Layers className="w-3.5 h-3.5 text-yellow-400" />,
  dns:            <Globe className="w-3.5 h-3.5 text-green-400" />,
};

function getModuleIcon(module: string): React.ReactNode {
  return MODULE_ICONS[module] || <Shield className="w-3.5 h-3.5 text-text-muted" />;
}

function RemediationRow({ item, index, isExpanded, onToggle }: {
  item: RemediationItem;
  index: number;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const sev = SEVERITY_CONFIG[item.severity] || SEVERITY_CONFIG.INFO;
  const isQuickWin = item.quick_win;

  return (
    <div
      className={`rounded-card border transition-all ${sev.bg} ${sev.border} overflow-hidden`}
      onClick={onToggle}
      style={{ cursor: 'pointer' }}
    >
      <div className="flex items-center gap-3 p-3">
        {/* Priority number */}
        <div className="w-7 h-7 rounded-full bg-background flex items-center justify-center text-xs font-black text-text-muted shrink-0">
          {item.priority}
        </div>

        {/* Severity badge */}
        <div className={`flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-bold ${sev.bg} ${sev.text} ${sev.border} shrink-0`}>
          {sev.icon}
          {sev.label}
        </div>

        {/* Title */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-text-primary truncate">{item.title}</p>
        </div>

        {/* Quick win badge */}
        {isQuickWin && (
          <span className="text-[10px] font-black bg-primary/15 text-primary border border-primary/30 px-2 py-0.5 rounded-full shrink-0">
            Quick Win
          </span>
        )}

        {/* Fix time */}
        <span className="text-xs text-text-muted shrink-0 hidden sm:block">{item.estimated_fix_time}</span>

        {/* Expand icon */}
        <div className="text-text-muted shrink-0">
          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </div>

      {/* Expanded detail */}
      {isExpanded && (
        <div className="px-3 pb-3 pt-0 border-t border-card-border/30 mt-1">
          <div className="flex items-center gap-2 mt-2">
            {getModuleIcon(item.module)}
            <span className="text-xs text-text-muted font-mono">
              {item.module.replace(/_check$|_security$/, '')} module
            </span>
            <span className="ml-auto text-xs text-text-muted">
              Impact score: <span className="font-bold text-text-primary">{item.impact_score}</span>
            </span>
          </div>
          <div className="mt-2 p-2 bg-background/60 rounded-md">
            <code className="text-[10px] text-text-muted font-mono">{item.finding_key}</code>
          </div>
        </div>
      )}
    </div>
  );
}

export default function EnterpriseRemediation({ roadmap, quickWins, immediateActions }: EnterpriseRemediationProps) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [showAll, setShowAll] = useState(false);
  const [activeTab, setActiveTab] = useState<'all' | 'quick' | 'immediate'>('immediate');

  if (!roadmap || roadmap.length === 0) return null;

  const toggle = (idx: number) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const TABS = [
    { key: 'immediate' as const, label: `Immediate (${immediateActions?.length || 0})`, items: immediateActions || [] },
    { key: 'quick' as const,     label: `Quick Wins (${quickWins?.length || 0})`,       items: quickWins || [] },
    { key: 'all' as const,       label: `Full Roadmap (${roadmap.length})`,              items: roadmap },
  ];

  const activeItems = TABS.find(t => t.key === activeTab)?.items || [];
  const displayItems = showAll ? activeItems : activeItems.slice(0, 8);

  return (
    <section id="enterprise-remediation" className="scroll-mt-8">
      <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2">
        Enterprise Remediation Roadmap
      </h2>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-surface rounded-btn p-1 border border-card-border w-fit">
        {TABS.map(({ key, label }) => (
          <button
            key={key}
            onClick={() => { setActiveTab(key); setShowAll(false); }}
            className={`
              px-3 py-1.5 rounded text-xs font-bold transition-all
              ${activeTab === key
                ? 'bg-primary text-background'
                : 'text-text-muted hover:text-text-primary'
              }
            `}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Items */}
      <div className="flex flex-col gap-2">
        {displayItems.map((item, idx) => (
          <RemediationRow
            key={`${item.finding_key}-${idx}`}
            item={item}
            index={idx}
            isExpanded={expanded.has(idx)}
            onToggle={() => toggle(idx)}
          />
        ))}
      </div>

      {/* Show more */}
      {activeItems.length > 8 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="mt-4 text-sm text-primary hover:text-primary/80 font-bold transition-colors"
        >
          {showAll ? 'Show less ↑' : `Show all ${activeItems.length} items ↓`}
        </button>
      )}
    </section>
  );
}
