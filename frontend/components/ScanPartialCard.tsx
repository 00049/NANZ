// WHAT THIS FILE DOES: Displays a partial module result card on the scan progress page.
// KEY DEPENDENCIES: react, lucide-react, ../store/scanStore
// MOCKED DATA: None.

'use client';

import { PartialModuleResult } from '@/store/scanStore';
import { Shield, AlertTriangle, CheckCircle2, Info } from 'lucide-react';
import { motion } from 'framer-motion';
import { normalizeSeverity } from '@/lib/severity';

interface ScanPartialCardProps {
  moduleName: string;
  result: PartialModuleResult;
}

export default function ScanPartialCard({ moduleName, result }: ScanPartialCardProps) {
  const getSeverityStyles = (severity: string) => {
    const ns = normalizeSeverity(severity);
    switch (ns) {
      case 'CRITICAL':
        return 'bg-red-950/30 border-red-800/40 text-red-300';
      case 'HIGH':
        return 'bg-orange-950/20 border-orange-900/30 text-orange-400';
      case 'MEDIUM':
        return 'bg-amber-950/20 border-amber-800/30 text-amber-400';
      case 'LOW':
        return 'bg-green-950/20 border-green-800/30 text-green-400';
      default:
        return 'bg-slate-900/30 border-slate-800/40 text-slate-400';
    }
  };

  const getSeverityIcon = (severity: string) => {
    const ns = normalizeSeverity(severity);
    switch (ns) {
      case 'CRITICAL':
      case 'HIGH':
      case 'MEDIUM':
        return <AlertTriangle className="w-4 h-4" />;
      case 'LOW':
        return <CheckCircle2 className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
    }
  };

  const displayName = moduleName
    .replace(/_check$|_security$/, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (l) => l.toUpperCase());

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className={`rounded-xl border p-4 mb-3 ${getSeverityStyles(result.severity)}`}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          {getSeverityIcon(result.severity)}
          <h4 className="text-sm font-bold uppercase tracking-wider">{displayName}</h4>
        </div>
        {result.grade && (
          <span className="text-xl font-black opacity-80">{result.grade}</span>
        )}
      </div>

      <p className="text-sm font-medium mb-1 opacity-90">{result.summary}</p>

      {result.key_metric && (
        <div className="text-xs opacity-70 flex items-center gap-1.5 mt-2">
          <Shield className="w-3.5 h-3.5" />
          {result.key_metric}
        </div>
      )}
    </motion.div>
  );
}
