'use client';

import { useEffect, useState, useCallback } from 'react';
import { X, Copy, CheckCircle2, Clock, AlertTriangle, Shield, ExternalLink, ChevronRight } from 'lucide-react';
import { RiskItem, formatALE, aleColorClass } from '@/types';
import { normalizeSeverity } from '@/lib/severity';

interface FixNowModalProps {
  finding: RiskItem | null;
  onClose: () => void;
  onMarkFixed?: (findingId: string) => void;
  onFalsePositive?: (findingId: string) => void;
}

export default function FixNowModal({ finding, onClose, onMarkFixed, onFalsePositive }: FixNowModalProps) {
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [markedFixed, setMarkedFixed] = useState(false);

  const isCriticalUrgent = finding?.severity === 'CRITICAL' || finding?.sla_tier === 'P0';

  // ESC to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  // Prevent body scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  const handleCopy = useCallback(() => {
    if (!finding) return;
    const text = [
      `Title: ${finding.title}`,
      `Severity: ${finding.severity}`,
      finding.cve_id ? `CVE: ${finding.cve_id}` : '',
      finding.cvss_score ? `CVSS: ${finding.cvss_score}` : '',
      `Business Impact: ${finding.business_impact}`,
      `Technical Detail: ${finding.technical_detail || ''}`,
      `Fix Action: ${finding.fix_action}`,
      finding.ale_display ? `Risk Reduction: ${finding.ale_display}` : '',
      finding.sla_deadline ? `SLA: ${finding.sla_deadline}` : '',
      finding.references?.length ? `References:\n${finding.references.join('\n')}` : '',
    ].filter(Boolean).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  }, [finding]);

  const handleMarkFixed = useCallback(() => {
    if (!finding?.id) return;
    onMarkFixed?.(finding.id);
    setMarkedFixed(true);
  }, [finding, onMarkFixed]);

  const handleFalsePositive = useCallback(() => {
    if (!finding?.id) return;
    onFalsePositive?.(finding.id);
    onClose();
  }, [finding, onFalsePositive, onClose]);

  if (!finding) return null;

  // Parse fix steps from fix_action
  const fixSteps = finding.fix_action
    ? finding.fix_action.split(/\d+\.|•|\n/).filter(s => s.trim().length > 0)
    : [];

  const SeverityColors: Record<string, string> = {
    CRITICAL: 'text-red-400 bg-red-950/50 border-red-700/50',
    HIGH: 'text-red-400 bg-red-950/30 border-red-800/40',
    MEDIUM: 'text-amber-400 bg-amber-950/30 border-amber-800/40',
    LOW: 'text-green-400 bg-green-950/30 border-green-800/40',
    INFO: 'text-slate-400 bg-slate-900/30 border-slate-700/40',
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Critical confirmation gate */}
      {isCriticalUrgent && !confirmed && showConfirm && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-6">
          <div className="bg-[#1a0505] border-2 border-red-600 rounded-2xl p-8 max-w-sm w-full shadow-2xl text-center">
            <div className="text-4xl mb-4">⚠️</div>
            <h3 className="text-lg font-black text-red-300 mb-3">Critical Security Issue</h3>
            <p className="text-sm text-slate-400 leading-relaxed mb-6">
              This is a critical security vulnerability actively affecting your users right now.
              Confirm you understand the severity before proceeding.
            </p>
            {finding.sla_deadline && (
              <div className="flex items-center justify-center gap-2 mb-6 text-red-400">
                <Clock className="w-4 h-4" />
                <span className="text-sm font-bold">SLA: Must be fixed within {finding.sla_deadline}</span>
              </div>
            )}
            <div className="flex gap-3">
              <button
                onClick={() => setShowConfirm(false)}
                className="flex-1 px-4 py-2.5 rounded-lg border border-slate-700 text-slate-400 text-sm font-medium hover:border-slate-600"
              >
                Go Back
              </button>
              <button
                onClick={() => { setConfirmed(true); setShowConfirm(false); }}
                className="flex-1 px-4 py-2.5 rounded-lg bg-red-700 hover:bg-red-600 text-white text-sm font-bold"
              >
                I Understand — Continue
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main modal — side panel on desktop, full screen on mobile */}
      <div className="fixed inset-y-0 right-0 z-50 w-full md:w-[520px] bg-[#09090b] border-l border-slate-800/60 shadow-2xl overflow-y-auto">
        {/* Header */}
        <div className={`sticky top-0 z-10 border-b ${
          finding.severity === 'CRITICAL' ? 'border-red-900/50 bg-[#1a0505]' :
          normalizeSeverity(finding.severity) === 'HIGH' ? 'border-red-900/30 bg-[#120505]' :
          normalizeSeverity(finding.severity) === 'MEDIUM' ? 'border-amber-900/30 bg-[#120d05]' :
          'border-slate-800/50 bg-[#0a0a0d]'
        } p-5`}>
          <div className="flex items-start justify-between gap-3 mb-4">
            <div>
              {/* Severity badge */}
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-widest border mb-2 ${SeverityColors[normalizeSeverity(finding.severity)] || SeverityColors.INFO}`}>
                {finding.cisa_kev ? '🚨 CISA KEV — ' : ''}
                {normalizeSeverity(finding.severity)}
              </span>
              <h2 className="text-base font-black text-slate-100 leading-snug">
                {finding.title}
              </h2>
            </div>
            <button
              onClick={onClose}
              className="shrink-0 p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-800/50 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Key metrics row */}
          <div className="grid grid-cols-2 gap-3">
            {/* ALE */}
            {finding.ale_reduction_inr && finding.ale_reduction_inr > 0 && (
              <div className="bg-black/30 rounded-xl p-3 border border-slate-800/50">
                <div className="text-[10px] text-slate-500 mb-1 uppercase tracking-wider">Annual Risk Reduced</div>
                <div className={`text-sm font-black ${aleColorClass(finding.ale_reduction_inr)}`}>
                  {finding.ale_display || formatALE(finding.ale_reduction_inr)}
                </div>
              </div>
            )}

            {/* SLA */}
            {finding.sla_deadline && (
              <div className={`rounded-xl p-3 border ${
                finding.sla_tier === 'P0' ? 'bg-red-950/40 border-red-800/50' : 'bg-black/30 border-slate-800/50'
              }`}>
                <div className="text-[10px] text-slate-500 mb-1 uppercase tracking-wider">SLA Deadline</div>
                <div className={`text-sm font-bold flex items-center gap-1.5 ${
                  finding.sla_tier === 'P0' ? 'text-red-300' : 'text-amber-400'
                }`}>
                  <Clock className="w-3 h-3" />
                  {finding.sla_deadline}
                </div>
              </div>
            )}

            {/* EPSS */}
            {finding.epss_score !== undefined && (
              <div className="bg-black/30 rounded-xl p-3 border border-slate-800/50">
                <div className="text-[10px] text-slate-500 mb-1 uppercase tracking-wider">Exploit Probability</div>
                <div className={`text-sm font-bold ${
                  finding.epss_score >= 0.5 ? 'text-red-400' :
                  finding.epss_score >= 0.3 ? 'text-amber-400' : 'text-blue-400'
                }`}>
                  {(finding.epss_score * 100).toFixed(1)}%
                  {finding.epss_percentile !== undefined && (
                    <span className="text-[10px] text-slate-600 font-normal ml-1">
                      ({finding.epss_percentile}th %ile)
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* RRF */}
            {finding.rrf_score !== undefined && (
              <div className="bg-black/30 rounded-xl p-3 border border-slate-800/50">
                <div className="text-[10px] text-slate-500 mb-1 uppercase tracking-wider">Risk Reduction Factor</div>
                <div className="text-sm font-bold text-blue-400">
                  {finding.rrf_score.toFixed(2)} ({finding.rrf_label})
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Body */}
        <div className="p-5 space-y-6">
          {/* Business Impact */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">Business Impact</h3>
            <p className="text-sm text-slate-300 leading-relaxed">{finding.business_impact}</p>
          </div>

          {/* Technical Detail */}
          {finding.technical_detail && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">Technical Detail</h3>
              <p className="text-sm text-slate-400 leading-relaxed">{finding.technical_detail}</p>
            </div>
          )}

          {/* CVE info */}
          {finding.cve_id && (
            <div className="flex items-center gap-3 p-3 bg-slate-900/50 rounded-xl border border-slate-800/50">
              <Shield className="w-4 h-4 text-slate-500 shrink-0" />
              <div>
                <div className="text-xs text-slate-500">CVE Reference</div>
                <div className="flex items-center gap-2">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-mono text-blue-400 hover:underline flex items-center gap-1"
                  >
                    {finding.cve_id}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                  {finding.cvss_score && (
                    <span className="text-xs text-slate-500">CVSS {finding.cvss_score.toFixed(1)}</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Fix Steps */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">
              {finding.fix_difficulty === 'Easy' ? '⚡ Quick Fix Steps' :
               finding.fix_difficulty === 'Hard' ? '👨‍💻 Developer Fix Steps' : '📋 Fix Guide'}
            </h3>

            {fixSteps.length > 1 ? (
              <ol className="space-y-2.5">
                {fixSteps.map((step, i) => (
                  <li key={i} className="flex gap-3">
                    <span className="shrink-0 w-5 h-5 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-bold text-slate-400">
                      {i + 1}
                    </span>
                    <p className="text-sm text-slate-300 leading-relaxed">{step.trim()}</p>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-sm text-slate-300 leading-relaxed">{finding.fix_action}</p>
            )}

            {/* Hard difficulty note */}
            {finding.fix_difficulty === 'Hard' && (
              <div className="mt-4 p-3 bg-slate-900/50 rounded-xl border border-slate-800/50">
                <div className="flex items-center gap-2 text-slate-400 text-xs">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                  This fix requires backend code changes. Estimated developer time: {finding.estimated_fix_time || 'Multiple days'}.
                </div>
              </div>
            )}
          </div>

          {/* Compliance mapping */}
          {finding.compliance_violations && finding.compliance_violations.length > 0 && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">Compliance Impact</h3>
              <div className="flex flex-wrap gap-1.5">
                {finding.compliance_violations.map((v, i) => (
                  <span key={i} className="text-xs px-2.5 py-1 rounded-lg bg-purple-950/50 border border-purple-800/40 text-purple-300 font-mono">
                    {typeof v === 'string' ? v : `${v?.framework || ''} ${v?.clause_id || ''}`.trim()}
                  </span>
                ))}
              </div>
              <p className="text-xs text-slate-600 mt-2">Fixing this issue addresses the above regulatory requirements.</p>
            </div>
          )}

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">References</h3>
              <ul className="space-y-1.5">
                {finding.references.slice(0, 5).map((ref, i) => (
                  <li key={i}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-xs text-blue-400 hover:underline truncate"
                    >
                      <ChevronRight className="w-3 h-3 shrink-0" />
                      {ref.replace('https://', '').replace('http://', '')}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 border-t border-slate-800/60 bg-[#09090b] p-5">
          <div className="flex flex-col gap-2">
            {markedFixed ? (
              <div className="flex items-center justify-center gap-2 py-3 rounded-xl bg-green-950/50 border border-green-800/50 text-green-400">
                <CheckCircle2 className="w-4 h-4" />
                <span className="text-sm font-bold">Marked as Fixed — We&apos;ll re-check this on the next scan</span>
              </div>
            ) : (
              <button
                onClick={handleMarkFixed}
                className="w-full py-2.5 rounded-xl bg-green-700 hover:bg-green-600 text-white text-sm font-bold transition-colors flex items-center justify-center gap-2"
              >
                <CheckCircle2 className="w-4 h-4" />
                Mark as Fixed
              </button>
            )}

            <div className="flex gap-2">
              <button
                onClick={handleCopy}
                className="flex-1 py-2 rounded-xl border border-slate-700 text-slate-400 text-sm font-medium hover:border-slate-600 hover:text-slate-300 transition-colors flex items-center justify-center gap-1.5"
              >
                {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy for Ticket'}
              </button>
              <button
                onClick={handleFalsePositive}
                className="flex-1 py-2 rounded-xl border border-slate-700 text-slate-500 text-sm font-medium hover:border-slate-600 transition-colors"
              >
                False Positive
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
