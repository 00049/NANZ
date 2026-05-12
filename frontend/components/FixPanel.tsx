'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import * as Dialog from '@radix-ui/react-dialog';
import {
  X, Copy, Check, ChevronDown, ChevronRight, ExternalLink,
  Clock, AlertTriangle, CheckCircle2, RefreshCw, ShieldAlert,
  Terminal, BookOpen,
} from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { RiskItem } from '@/types';
import { normalizeSeverity, type Severity } from '@/lib/severity';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { Skeleton } from '@/components/ui/Skeleton';
import { useFixGeneration, type FixRequestPayload, type FixStep as FixStepType } from '@/hooks/useFixGeneration';
import { useAuthStore } from '@/store/authStore';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ─── Severity-typed color maps ───────────────────────────────────────────────

const SEVERITY_HEADER_BG: Record<Severity, string> = {
  CRITICAL: 'bg-[#1a0505]',
  HIGH: 'bg-[#120505]',
  MEDIUM: 'bg-[#120d05]',
  LOW: 'bg-[#0a0a0d]',
  INFO: 'bg-[#0a0a0d]',
};

type FixDifficulty = 'easy' | 'medium' | 'hard';

const DIFFICULTY_COLORS: Record<FixDifficulty, string> = {
  easy: 'bg-green-950/50 text-green-400 border-green-800/40',
  medium: 'bg-blue-950/50 text-blue-400 border-blue-800/40',
  hard: 'bg-amber-950/50 text-amber-400 border-amber-800/40',
};

// ─── Props ───────────────────────────────────────────────────────────────────

interface FixPanelProps {
  finding: RiskItem | null;
  open: boolean;
  onClose: () => void;
  scanId?: string;
  targetDomain?: string;
}

// ─── Code Block with copy ────────────────────────────────────────────────────

function CodeBlock({ code, language }: { code: string; language: string | null }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  }, [code]);

  return (
    <div className="relative group mt-2 rounded-lg overflow-hidden border border-slate-800/60">
      {language && (
        <div className="flex items-center justify-between px-3 py-1.5 bg-[#161b22] border-b border-slate-800/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
            {language}
          </span>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
            aria-label={copied ? 'Copied code' : 'Copy code to clipboard'}
          >
            {copied
              ? <Check className="w-3 h-3 text-green-400" />
              : <Copy className="w-3 h-3" />
            }
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      )}
      <pre className="bg-[#0d1117] p-3 overflow-x-auto text-[13px] leading-relaxed">
        <code className="font-mono text-slate-300 whitespace-pre-wrap break-words">
          {code}
        </code>
      </pre>
      {!language && (
        <button
          onClick={handleCopy}
          aria-label={copied ? 'Copied code' : 'Copy code to clipboard'}
          className="absolute top-2 right-2 p-1.5 rounded-md bg-slate-800/60 hover:bg-slate-700/80 text-slate-400 hover:text-slate-200 opacity-0 group-hover:opacity-100 transition-all"
        >
          {copied
            ? <Check className="w-3.5 h-3.5 text-green-400" />
            : <Copy className="w-3.5 h-3.5" />
          }
        </button>
      )}
    </div>
  );
}

// ─── Expandable Fix Step ─────────────────────────────────────────────────────

function FixStepCard({ step, defaultExpanded }: { step: FixStepType; defaultExpanded: boolean }) {
  const [expanded, setExpanded] = useState(defaultExpanded);

  return (
    <div className="border border-slate-800/40 rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-start gap-3 p-3 hover:bg-slate-800/20 transition-colors text-left"
        aria-expanded={expanded}
        aria-label={`Step ${step.order}: ${step.title}`}
      >
        <span className="shrink-0 w-6 h-6 rounded-full bg-blue-950/60 border border-blue-800/40 flex items-center justify-center text-[11px] font-bold text-blue-400 mt-0.5">
          {step.order}
        </span>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-semibold text-slate-200 leading-snug">
            {step.title}
          </h4>
        </div>
        <ChevronDown
          className={cn(
            'w-4 h-4 text-slate-600 shrink-0 mt-0.5 transition-transform',
            expanded && 'rotate-180'
          )}
        />
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-3 pb-3 pl-12">
              <p className="text-sm text-slate-400 leading-relaxed">
                {step.description}
              </p>
              {step.code_snippet && (
                <CodeBlock code={step.code_snippet} language={step.code_language} />
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Loading skeleton ────────────────────────────────────────────────────────

function FixPanelSkeleton() {
  return (
    <div className="p-5 space-y-6" aria-label="Loading fix guide" role="status">
      <div>
        <Skeleton className="h-3 w-20 mb-3" />
        <Skeleton className="h-4 w-full mb-2" />
        <Skeleton className="h-4 w-4/5" />
      </div>
      <div>
        <Skeleton className="h-3 w-16 mb-3" />
        <Skeleton className="h-4 w-full mb-2" />
        <Skeleton className="h-4 w-3/5" />
      </div>
      <div>
        <Skeleton className="h-3 w-20 mb-3" />
        {[1, 2, 3].map(i => (
          <div key={i} className="flex items-center gap-3 mb-3">
            <Skeleton className="h-6 w-6 rounded-full" />
            <Skeleton className="h-4 flex-1" />
          </div>
        ))}
      </div>
      <div>
        <Skeleton className="h-3 w-24 mb-3" />
        <Skeleton className="h-10 w-full rounded-lg" />
      </div>
    </div>
  );
}

// ─── Streaming cursor indicator ──────────────────────────────────────────────

function StreamingCursor() {
  return (
    <span className="inline-flex items-center gap-1 ml-1" aria-hidden="true">
      <span className="w-2 h-4 bg-blue-400 rounded-sm animate-pulse" />
    </span>
  );
}

// ─── FixPanel Component ──────────────────────────────────────────────────────

export function FixPanel({ finding, open, onClose, scanId, targetDomain }: FixPanelProps) {
  const { fixData, isLoading, isStreaming, error, rawStream, generate, reset } = useFixGeneration();
  const [markedFixed, setMarkedFixed] = useState(false);
  const token = useAuthStore((state) => state.token);
  const hasTriggered = useRef(false);

  const severity: Severity = finding ? normalizeSeverity(finding.severity) : 'INFO';
  const isCritical = severity === 'CRITICAL';

  // ── Map RiskItem category from check_domain or check_type ─────────────
  const inferCategory = useCallback((f: RiskItem): string => {
    if (f.check_domain) return f.check_domain;
    const key = f.check_type || f.key || '';
    if (key.startsWith('ssl_')) return 'ssl';
    if (key.startsWith('dns_')) return 'dns';
    if (key.startsWith('headers_')) return 'headers';
    if (key.startsWith('ports_') || key.startsWith('dangerous_')) return 'ports';
    if (key.startsWith('cms_')) return 'cms';
    if (key.startsWith('cookie_') || key.startsWith('session_')) return 'cookies';
    if (key.startsWith('cors_')) return 'cors';
    if (key.includes('cloud') || key.includes('bucket')) return 'cloud_storage';
    return 'general';
  }, []);

  // ── Map internal severity string to backend-expected lowercase ────────
  const mapSeverityToBackend = useCallback((sev: Severity): FixRequestPayload['severity'] => {
    switch (sev) {
      case 'CRITICAL': return 'critical';
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'low';
    }
  }, []);

  // ── Build the payload once ────────────────────────────────────────────
  const buildPayload = useCallback((f: RiskItem): FixRequestPayload => ({
    finding_id: f.id || f.check_type || f.key || 'unknown',
    finding_title: f.title,
    finding_description: f.business_impact,
    finding_detail: f.technical_detail || f.business_impact,
    severity: mapSeverityToBackend(severity),
    category: inferCategory(f),
    target_domain: targetDomain || 'unknown',
    scan_id: scanId || 'unknown',
  }), [severity, inferCategory, mapSeverityToBackend, scanId, targetDomain]);

  // ── Auto-trigger generation when panel opens ──────────────────────────
  useEffect(() => {
    if (open && finding && !hasTriggered.current) {
      hasTriggered.current = true;
      generate(buildPayload(finding));
    }

    if (!open) {
      hasTriggered.current = false;
      reset();
      setMarkedFixed(false);
    }
  }, [open, finding, generate, reset, buildPayload]);

  // ── Retry handler ─────────────────────────────────────────────────────
  const handleRetry = useCallback(() => {
    if (!finding) return;
    hasTriggered.current = false;
    reset();
    setTimeout(() => {
      if (finding) {
        hasTriggered.current = true;
        generate(buildPayload(finding));
      }
    }, 100);
  }, [finding, generate, reset, buildPayload]);

  // ── Mark as fixed handler ─────────────────────────────────────────────
  const handleMarkFixed = useCallback(async () => {
    if (!finding?.id) return;
    try {
      const reqHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) reqHeaders['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`${API_BASE}/api/v1/findings/${finding.id}/status`, {
        method: 'PATCH',
        headers: reqHeaders,
        body: JSON.stringify({ status: 'fixed' }),
      });

      if (res.ok) {
        setMarkedFixed(true);
        toast.success('Marked as fixed');
      } else {
        toast.error('Failed to update status');
      }
    } catch {
      toast.error('Failed to update status');
    }
  }, [finding, token]);

  if (!finding) return null;

  return (
    <Dialog.Root open={open} onOpenChange={(isOpen) => { if (!isOpen) onClose(); }}>
      <Dialog.Portal>
        {/* Backdrop */}
        <Dialog.Overlay asChild>
          <motion.div
            className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          />
        </Dialog.Overlay>

        {/* Panel */}
        <Dialog.Content
          asChild
          aria-describedby="fix-panel-description"
        >
          <motion.div
            className="fixed inset-y-0 right-0 z-50 w-full md:w-[560px] bg-[#09090b] border-l border-slate-800/60 shadow-2xl flex flex-col outline-none"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 30, stiffness: 300 }}
          >
            {/* ── Header ──────────────────────────────────────────────── */}
            <div className={cn(
              'sticky top-0 z-10 border-b p-5',
              isCritical ? 'border-red-900/50' : 'border-slate-800/50',
              SEVERITY_HEADER_BG[severity],
            )}>
              <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <SeverityBadge severity={severity} size="sm" />
                    {fixData?.difficulty && (
                      <span className={cn(
                        'text-[10px] font-semibold px-2 py-0.5 rounded border',
                        DIFFICULTY_COLORS[fixData.difficulty],
                      )}>
                        {fixData.difficulty}
                      </span>
                    )}
                    {fixData?.estimated_minutes != null && fixData.estimated_minutes > 0 && (
                      <span className="flex items-center gap-1 text-[10px] text-slate-500">
                        <Clock className="w-3 h-3" />
                        ~{fixData.estimated_minutes} min
                      </span>
                    )}
                    {fixData?.cached && (
                      <span className="text-[10px] text-slate-600 px-1.5 py-0.5 rounded bg-slate-900/50 border border-slate-800/40">
                        cached
                      </span>
                    )}
                  </div>
                  <Dialog.Title className="text-base font-black text-slate-100 leading-snug">
                    {finding.title}
                  </Dialog.Title>
                  <Dialog.Description id="fix-panel-description" asChild>
                    <div className="flex items-center gap-2 mt-1.5 text-xs text-slate-500">
                      <span>AI-generated remediation guide for {inferCategory(finding)} finding</span>
                      {targetDomain && (
                        <>
                          <span className="text-slate-700">·</span>
                          <span>{targetDomain}</span>
                        </>
                      )}
                    </div>
                  </Dialog.Description>
                </div>
                <Dialog.Close asChild>
                  <button
                    className="shrink-0 p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-800/50 transition-colors"
                    aria-label="Close fix panel"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </Dialog.Close>
              </div>
            </div>

            {/* ── Scrollable body ─────────────────────────────────────── */}
            <div className="flex-1 overflow-y-auto">
              {/* Critical urgency banner */}
              {isCritical && (
                <div className="mx-5 mt-4 p-3 rounded-xl bg-red-950/60 border border-red-800/50" role="alert">
                  <div className="flex items-start gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-bold text-red-300">
                        This issue exposes your data publicly.
                      </p>
                      <p className="text-xs text-red-400/80 mt-0.5">
                        Address this before all other findings.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* ── Error state ── */}
              {error && (
                <div className="p-5" role="alert">
                  <div className="p-4 rounded-xl bg-red-950/30 border border-red-800/40">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                      <div className="flex-1">
                        <p className="text-sm font-semibold text-red-300 mb-1">Fix generation failed</p>
                        <p className="text-xs text-red-400/80 leading-relaxed">{error}</p>
                      </div>
                    </div>
                    <button
                      onClick={handleRetry}
                      className="mt-3 w-full flex items-center justify-center gap-2 py-2 rounded-lg bg-red-800/40 hover:bg-red-700/50 text-red-300 text-sm font-medium transition-colors"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      Retry
                    </button>
                  </div>
                </div>
              )}

              {/* ── Loading state ── */}
              {isLoading && !error && <FixPanelSkeleton />}

              {/* ── Streaming state (show raw stream as preview) ── */}
              {isStreaming && !error && !fixData && (
                <div className="p-5">
                  <div className="flex items-center gap-2 mb-4" role="status" aria-live="polite">
                    <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                    <span className="text-xs text-blue-400 font-medium">Generating your fix…</span>
                  </div>
                  <div className="bg-[#0d1117] rounded-xl p-4 border border-slate-800/40 max-h-[400px] overflow-y-auto">
                    <pre className="text-xs font-mono text-slate-400 whitespace-pre-wrap break-words leading-relaxed">
                      {rawStream}
                      <StreamingCursor />
                    </pre>
                  </div>
                </div>
              )}

              {/* ── Loaded content ── */}
              {fixData && !error && (
                <div className="p-5 space-y-6">
                  {/* Summary */}
                  <section>
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">
                      Summary
                    </h3>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {fixData.summary}
                    </p>
                  </section>

                  {/* Impact */}
                  <section>
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">
                      Impact
                    </h3>
                    <div className="flex items-start gap-2 p-3 rounded-xl bg-slate-900/40 border border-slate-800/40">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {fixData.impact}
                      </p>
                    </div>
                  </section>

                  {/* Fix Steps */}
                  <section>
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">
                      Fix Steps
                      <span className="ml-2 text-slate-600 normal-case tracking-normal">
                        ({fixData.steps.length} {fixData.steps.length === 1 ? 'step' : 'steps'})
                      </span>
                    </h3>
                    <div className="space-y-2">
                      {fixData.steps.map((step) => (
                        <FixStepCard
                          key={step.order}
                          step={step}
                          defaultExpanded={fixData.steps.length <= 3}
                        />
                      ))}
                    </div>
                  </section>

                  {/* Verification */}
                  <section>
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">
                      <Terminal className="w-3.5 h-3.5 inline mr-1.5 -mt-0.5" />
                      Verify
                    </h3>
                    <p className="text-sm text-slate-300 leading-relaxed mb-2">
                      {fixData.verification}
                    </p>
                    {fixData.verification_command && (
                      <CodeBlock code={fixData.verification_command} language="bash" />
                    )}
                  </section>

                  {/* References */}
                  {fixData.references.length > 0 && (
                    <section>
                      <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">
                        References
                      </h3>
                      <ul className="space-y-1.5">
                        {fixData.references.map((ref, i) => (
                          <li key={i}>
                            <a
                              href={ref}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                            >
                              <ChevronRight className="w-3 h-3 shrink-0" />
                              <span className="truncate">
                                {ref.replace('https://', '').replace('http://', '')}
                              </span>
                              <ExternalLink className="w-3 h-3 shrink-0 opacity-60" />
                            </a>
                          </li>
                        ))}
                      </ul>
                    </section>
                  )}
                </div>
              )}
            </div>

            {/* ── Footer ──────────────────────────────────────────────── */}
            <div className="sticky bottom-0 border-t border-slate-800/60 bg-[#09090b] p-5">
              <div className="flex flex-col gap-2">
                {markedFixed ? (
                  <div className="flex items-center justify-center gap-2 py-3 rounded-xl bg-green-950/50 border border-green-800/50 text-green-400">
                    <CheckCircle2 className="w-4 h-4" />
                    <span className="text-sm font-bold">Marked as Fixed — We&apos;ll re-check on the next scan</span>
                  </div>
                ) : (
                  <button
                    onClick={handleMarkFixed}
                    disabled={!finding.id}
                    className={cn(
                      'w-full py-2.5 rounded-xl text-sm font-bold transition-colors flex items-center justify-center gap-2',
                      finding.id
                        ? 'bg-green-700 hover:bg-green-600 text-white'
                        : 'bg-slate-800 text-slate-500 cursor-not-allowed',
                    )}
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Mark as Fixed
                  </button>
                )}

                {fixData?.references && fixData.references.length > 0 && (
                  <a
                    href={fixData.references[0]}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full py-2 rounded-xl border border-slate-700 text-slate-400 text-sm font-medium hover:border-slate-600 hover:text-slate-300 transition-colors flex items-center justify-center gap-1.5"
                  >
                    <BookOpen className="w-3.5 h-3.5" />
                    Open docs ↗
                  </a>
                )}
              </div>
            </div>
          </motion.div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
