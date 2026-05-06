'use client';

import { useState } from 'react';
import { CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronUp, RefreshCw } from 'lucide-react';
import { ModuleStatus } from '@/types';

interface ScanModuleStatusProps {
  modules?: ModuleStatus[];
  totalModules?: number;
}

// Default known module list when not provided
const DEFAULT_MODULES: string[] = [
  'ssl_check', 'headers_check', 'dns_check', 'port_check', 'webapp_check',
  'cookie_check', 'cors_check', 'http_methods_check', 'cms_check', 'reputation_check',
  'api_security_check', 'graphql_check', 'business_logic_check', 'iast_behavioral',
  'oast_check', 'dependency_check', 'llm_security_check', 'container_check',
  'javascript_check', 'cloud_check',
];

function derivedModuleStatus(progressRecord?: Record<string, string>): ModuleStatus[] {
  if (!progressRecord) return [];
  return Object.entries(progressRecord).map(([name, status]) => ({
    name,
    display_name: name.replace(/_check$|_security$|_behavioral$/, '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
    status: status === 'complete' ? 'success' : status === 'running' ? 'success' : status === 'failed' ? 'failed' : 'skipped',
    findings_count: undefined,
  }));
}

export default function ScanModuleStatus({ modules, totalModules = 20 }: ScanModuleStatusProps) {
  const [expanded, setExpanded] = useState(false);

  const allModules = modules && modules.length > 0 ? modules : [];
  const successful = allModules.filter(m => m.status === 'success').length;
  const failed = allModules.filter(m => m.status === 'failed');
  const degraded = allModules.filter(m => m.status === 'degraded');
  const hasIssues = failed.length > 0 || degraded.length > 0;
  const total = allModules.length || totalModules;

  if (total === 0) return null;

  return (
    <div className={`rounded-xl border ${hasIssues ? 'border-amber-800/40 bg-amber-950/10' : 'border-slate-800/40 bg-[#09090b]'} p-4`}>
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center justify-between gap-3"
      >
        <div className="flex items-center gap-3">
          {hasIssues ? (
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
          )}
          <span className="text-sm font-semibold text-slate-300">
            {allModules.length > 0
              ? `${successful}/${total} modules completed successfully`
              : `${totalModules} modules scanned`}
          </span>
          {hasIssues && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-amber-950/60 border border-amber-800/40 text-amber-400 font-medium">
              {failed.length + degraded.length} with errors
            </span>
          )}
        </div>
        {hasIssues && (
          expanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />
        )}
      </button>

      {/* Module grid (always visible, compact) */}
      {allModules.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {allModules.map(m => (
            <span
              key={m.name}
              title={m.error || m.display_name}
              className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded font-mono border ${
                m.status === 'success' ? 'bg-green-950/20 border-green-900/30 text-green-700' :
                m.status === 'failed' ? 'bg-red-950/30 border-red-800/40 text-red-400' :
                m.status === 'degraded' ? 'bg-amber-950/30 border-amber-800/40 text-amber-500' :
                'bg-slate-900/30 border-slate-800/30 text-slate-600'
              }`}
            >
              {m.status === 'success' ? '✓' : m.status === 'failed' ? '✗' : m.status === 'degraded' ? '~' : '○'}
              {' '}{m.name.replace(/_check$|_security$/, '').replace(/_/g, '_')}
            </span>
          ))}
        </div>
      )}

      {/* Expanded warning panel */}
      {expanded && hasIssues && (
        <div className="mt-4 p-4 bg-amber-950/20 rounded-xl border border-amber-800/30">
          <h4 className="text-xs font-bold uppercase tracking-widest text-amber-400 mb-3">
            Data Gaps — Manual Testing Recommended
          </h4>
          <div className="space-y-2 mb-4">
            {[...failed, ...degraded].map(m => (
              <div key={m.name} className="flex items-start gap-2">
                <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <span className="text-xs font-mono text-slate-300">{m.name}</span>
                  {m.error && (
                    <span className="text-xs text-slate-500 ml-2">({m.error})</span>
                  )}
                </div>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-500 mb-3">
            Findings in these areas may be incomplete. Manual penetration testing is recommended for full coverage.
          </p>
          <button className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors">
            <RefreshCw className="w-3 h-3" />
            Re-run scan for complete coverage
          </button>
        </div>
      )}
    </div>
  );
}
