'use client';

import { useState } from 'react';
import { Info, X } from 'lucide-react';
import { ScoreBreakdown } from '@/types';

interface ScoreExplainerProps {
  score: number;
  breakdown?: ScoreBreakdown;
  epssAdjustments?: string[];
  wafAdjustments?: string[];
  label?: string;
}

export default function ScoreExplainer({
  score,
  breakdown,
  epssAdjustments,
  wafAdjustments,
  label = 'Score',
}: ScoreExplainerProps) {
  const [open, setOpen] = useState(false);

  // Build fallback breakdown from score
  const items = breakdown?.items || [];
  const baseScore = breakdown?.base_score ?? 100;
  const finalScore = breakdown?.final_score ?? score;

  return (
    <span className="relative inline-flex items-center">
      <button
        onClick={() => setOpen(true)}
        aria-label="Explain score"
        className="ml-1.5 text-slate-500 hover:text-blue-400 transition-colors focus:outline-none focus:ring-1 focus:ring-blue-500 rounded-full"
      >
        <Info className="w-3.5 h-3.5" />
      </button>

      {open && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            onClick={() => setOpen(false)}
          />

          {/* Popover */}
          <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-md bg-[#0d0d10] border border-slate-700/60 rounded-xl shadow-2xl p-6">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
                How this {label} is calculated
              </h3>
              <button
                onClick={() => setOpen(false)}
                className="text-slate-500 hover:text-slate-200 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1.5 font-mono text-xs">
              {/* Base */}
              <div className="flex justify-between text-slate-400">
                <span>Starting score</span>
                <span className="text-slate-200">+{baseScore}</span>
              </div>

              {/* Penalty / bonus items */}
              {items.length > 0 ? (
                items.map((item, i) => (
                  <div key={i} className="flex justify-between">
                    <span className="text-slate-400 truncate max-w-[300px]">{item.label}</span>
                    <span className={item.delta < 0 ? 'text-red-400' : 'text-green-400'}>
                      {item.delta > 0 ? '+' : ''}{item.delta}
                    </span>
                  </div>
                ))
              ) : (
                // Generic explanation when no breakdown provided
                <>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Critical findings penalty</span>
                    <span className="text-red-400">variable</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">High severity findings penalty</span>
                    <span className="text-red-400">variable</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Security controls detected</span>
                    <span className="text-green-400">+variable</span>
                  </div>
                </>
              )}

              {/* Divider */}
              <div className="border-t border-slate-700/50 my-2" />
              <div className="flex justify-between font-bold">
                <span className="text-slate-300">Final Score</span>
                <span className={finalScore >= 75 ? 'text-green-400' : finalScore >= 50 ? 'text-amber-400' : 'text-red-400'}>
                  {finalScore}/100
                </span>
              </div>
            </div>

            {/* Contextual notes */}
            {(epssAdjustments?.length || wafAdjustments?.length) ? (
              <div className="mt-4 space-y-2">
                {wafAdjustments && wafAdjustments.length > 0 && (
                  <div className="bg-blue-950/50 border border-blue-800/40 rounded-lg p-3">
                    <p className="text-xs text-blue-300 font-medium mb-1">WAF Adjustments</p>
                    {wafAdjustments.map((note, i) => (
                      <p key={i} className="text-xs text-slate-400">{note}</p>
                    ))}
                  </div>
                )}
                {epssAdjustments && epssAdjustments.length > 0 && (
                  <div className="bg-red-950/50 border border-red-800/40 rounded-lg p-3">
                    <p className="text-xs text-red-300 font-medium mb-1">EPSS / KEV Adjustments</p>
                    {epssAdjustments.map((note, i) => (
                      <p key={i} className="text-xs text-slate-400">{note}</p>
                    ))}
                  </div>
                )}
              </div>
            ) : null}

            <p className="mt-4 text-[10px] text-slate-600">
              Scores computed by the ShieldCheck ASPM Engine using CVSS, EPSS, CISA KEV, asset criticality and WAF context.
            </p>
          </div>
        </>
      )}
    </span>
  );
}
