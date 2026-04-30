'use client';

import { ShieldAlert, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { ReactNode } from 'react';

export default function RiskCard({ 
  title, 
  severity, 
  business_impact, 
  isBlurred = false 
}: { 
  title: string;
  severity: string;
  business_impact: string;
  isBlurred?: boolean;
}) {
  
  const getSeverityStyles = (sev: string) => {
    switch(sev) {
      case 'CRITICAL': return 'bg-critical-bg text-high border-high/30';
      case 'RED': return 'bg-high/10 text-high border-high/30';
      case 'AMBER': return 'bg-medium-bg text-medium border-medium/30';
      case 'GREEN': return 'bg-low/10 text-low border-low/30';
      default: return 'bg-background text-text-muted border-card-border';
    }
  };

  const getIcon = (sev: string) => {
    switch(sev) {
      case 'CRITICAL': 
      case 'RED': return <ShieldAlert className="w-4 h-4" />;
      case 'AMBER': return <AlertTriangle className="w-4 h-4" />;
      case 'GREEN': return <ShieldCheck className="w-4 h-4" />;
      default: return <Info className="w-4 h-4" />;
    }
  };

  return (
    <div className={`relative bg-surface rounded-card border border-card-border p-5 transition-all ${isBlurred ? 'filter blur-sm select-none opacity-60' : 'hover:border-primary/50 hover:shadow-xl'}`}>
      <div className="flex items-start justify-between mb-3">
        <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider border ${getSeverityStyles(severity)}`}>
          {getIcon(severity)}
          {severity === 'RED' ? 'HIGH' : severity === 'AMBER' ? 'MEDIUM' : severity}
        </div>
        {!isBlurred && <span className="text-xs font-medium text-text-muted px-2 py-1 bg-background rounded border border-card-border">High Confidence</span>}
      </div>
      
      <h4 className="text-lg font-bold text-text-primary mb-2 leading-tight">{title}</h4>
      <p className="text-sm text-text-muted mb-4 line-clamp-2">{business_impact}</p>
      
      <div className="flex items-center justify-between pt-4 border-t border-card-border">
        <div className="flex gap-2">
          <span className="text-xs font-medium bg-background px-2 py-1 rounded text-text-muted border border-card-border">Dev effort: Medium</span>
          <span className="text-xs font-medium bg-background px-2 py-1 rounded text-text-muted border border-card-border">~1 hour</span>
        </div>
        <button className="text-xs font-bold text-primary hover:text-blue-400 transition-colors uppercase tracking-wider disabled:opacity-50" disabled={isBlurred}>
          Fix Now →
        </button>
      </div>
    </div>
  );
}
