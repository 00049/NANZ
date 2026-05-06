'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getScanPreview } from '@/lib/api';
import { useScanStore } from '@/store/scanStore';
import { PreviewResponse, formatALE } from '@/types';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ScoreRing from '@/components/ScoreRing';
import RazorpayButton from '@/components/RazorpayButton';
import { Shield, AlertTriangle, Lock, Clock, ChevronRight, Loader2 } from 'lucide-react';

export default function ResultsPage({ params }: { params: { scanId: string } }) {
  const [preview, setPreview] = useState<PreviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const { reportJWT, isPaid } = useScanStore();
  const router = useRouter();

  useEffect(() => {
    if (isPaid) {
      router.replace(`/report/${params.scanId}`);
      return;
    }
    getScanPreview(params.scanId)
      .then(setPreview)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [params.scanId, isPaid, router]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#030303] flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (!preview) {
    return (
      <div className="min-h-screen bg-[#030303] flex items-center justify-center text-slate-400">
        <p>Could not load preview. Please try again.</p>
      </div>
    );
  }

  const topRisk = preview.top_risks?.[0];
  const dpdpScore = preview.dpdp_compliance_score ?? 0;
  const dpdpRisk = dpdpScore < 50 ? 'At Risk' : dpdpScore < 80 ? 'Partial Compliance' : 'Compliant';
  const totalALE = preview.total_ale_reduction_inr;
  const aleRange = totalALE ? formatALE(totalALE) : null;
  const isHighRisk = preview.overall_severity === 'CRITICAL' || preview.critical_count > 0;

  return (
    <>
      <Navbar />
      <main className="min-h-screen bg-[#030303] pb-20">
        <div className="max-w-2xl mx-auto px-4 py-8 space-y-6">

          {/* ── LEAD: Financial context FIRST (not score ring) ── */}
          {aleRange && (
            <div className={`rounded-2xl border p-6 text-center ${
              isHighRisk
                ? 'bg-[#1a0505] border-red-700/60 shadow-[0_0_40px_-10px_rgba(220,38,38,0.3)]'
                : 'bg-[#0d1220] border-amber-800/40'
            }`}>
              <div className="text-2xl mb-2">⚠️</div>
              <h1 className="text-xl font-black text-slate-100 mb-2">
                We found security issues that could cost your business
              </h1>
              <div className={`text-2xl font-black mb-1 ${
                isHighRisk ? 'text-red-400' : 'text-amber-400'
              }`}>
                {aleRange} in estimated risk
              </div>
              <p className="text-sm text-slate-400">if these vulnerabilities are not addressed</p>
            </div>
          )}

          {/* ── Score Ring (below financial context) ── */}
          <div className="flex justify-center">
            <ScoreRing score={preview.overall_score} severity={preview.overall_severity} />
          </div>

          {/* ── DPDP always shown free ── */}
          <div className={`rounded-2xl border p-5 ${
            dpdpScore < 50
              ? 'bg-red-950/20 border-red-800/50'
              : dpdpScore < 80
              ? 'bg-amber-950/20 border-amber-800/40'
              : 'bg-green-950/20 border-green-800/40'
          }`}>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-slate-400" />
                <span className="text-sm font-bold text-slate-200">DPDP Act Compliance</span>
              </div>
              <span className={`text-lg font-black ${
                dpdpScore < 50 ? 'text-red-400' : dpdpScore < 80 ? 'text-amber-400' : 'text-green-400'
              }`}>
                {dpdpScore}/100 — {dpdpRisk}
              </span>
            </div>
            <div className="w-full bg-slate-900/60 rounded-full h-1.5 mb-3">
              <div
                className={`h-1.5 rounded-full ${dpdpScore < 50 ? 'bg-red-500' : dpdpScore < 80 ? 'bg-amber-500' : 'bg-green-500'}`}
                style={{ width: `${dpdpScore}%` }}
              />
            </div>
            {dpdpScore < 80 && (
              <p className="text-xs text-slate-500">
                Section 8(4) violations may result in penalties up to{' '}
                <span className="text-red-400 font-semibold">₹250 Crore</span> under the DPDP Act 2023.
              </p>
            )}
          </div>

          {/* ── Top finding preview ── */}
          {topRisk && (
            <div className={`rounded-2xl border overflow-hidden ${
              topRisk.severity === 'CRITICAL'
                ? 'bg-[#450a0a] border-red-700/70 shadow-[0_0_24px_-6px_rgba(220,38,38,0.4)]'
                : 'bg-[#1c0a0a] border-red-900/40'
            }`}>
              {topRisk.severity === 'CRITICAL' && (
                <div className="bg-red-700/30 border-b border-red-800/50 px-5 py-2 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-300" />
                  <span className="text-xs font-bold text-red-300 uppercase tracking-widest">
                    This issue has a 24-hour SLA — Requires immediate action
                  </span>
                </div>
              )}
              <div className="p-5">
                <div className="flex items-center gap-2 mb-3">
                  <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded border ${
                    topRisk.severity === 'CRITICAL'
                      ? 'bg-red-950 border-red-700/60 text-red-300'
                      : 'bg-red-950/50 border-red-800/40 text-red-400'
                  }`}>
                    {topRisk.severity === 'RED' ? 'HIGH' : topRisk.severity} — Most Critical Finding
                  </span>
                </div>
                <h2 className="text-base font-black text-slate-100 mb-2">{topRisk.title}</h2>
                <p className="text-sm text-slate-400 leading-relaxed mb-4">{topRisk.business_impact}</p>

                <div className="flex flex-wrap gap-3">
                  {topRisk.ale_reduction_inr !== undefined && topRisk.ale_reduction_inr > 0 && (
                    <div className="bg-black/30 rounded-xl px-4 py-2 border border-slate-800/50">
                      <div className="text-[10px] text-slate-600 uppercase tracking-wider mb-0.5">Annual Risk</div>
                      <div className={`text-sm font-black ${
                        topRisk.ale_reduction_inr >= 5_000_000 ? 'text-red-400' :
                        topRisk.ale_reduction_inr >= 1_000_000 ? 'text-amber-400' : 'text-blue-400'
                      }`}>
                        {topRisk.ale_display || formatALE(topRisk.ale_reduction_inr)}
                      </div>
                    </div>
                  )}
                  {topRisk.sla_tier === 'P0' && (
                    <div className="bg-red-950/40 rounded-xl px-4 py-2 border border-red-800/40">
                      <div className="text-[10px] text-slate-600 uppercase tracking-wider mb-0.5">SLA</div>
                      <div className="text-sm font-black text-red-400 flex items-center gap-1">
                        <Clock className="w-3 h-3" /> 24 Hours
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Paywall blur on fix steps */}
              <div className="relative border-t border-red-900/30 p-5 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#1c0505]/80 to-[#1c0505] z-10 flex items-end justify-center pb-4">
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <Lock className="w-3 h-3" />
                    Fix steps available in full report
                  </div>
                </div>
                <div className="blur-sm opacity-50 space-y-2">
                  {[1, 2, 3].map(i => (
                    <div key={i} className="flex gap-2">
                      <span className="w-5 h-5 rounded-full bg-slate-800 border border-slate-700 shrink-0" />
                      <div className="h-3 bg-slate-700/40 rounded w-full" />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Paywall CTA ── */}
          <div className="rounded-2xl border border-blue-800/50 bg-[#050d1a] p-6">
            <h2 className="text-lg font-black text-slate-100 mb-1">
              See all {preview.total_findings} security issues threatening your business
            </h2>
            <p className="text-sm text-slate-400 mb-4">Including the exact fix for each one.</p>

            {/* Stats row */}
            <div className="flex flex-wrap gap-3 mb-4">
              {preview.critical_count > 0 && (
                <span className="text-xs px-3 py-1.5 rounded-full bg-red-950/60 border border-red-800/50 text-red-300 font-bold">
                  {preview.critical_count} critical
                </span>
              )}
              {preview.high_count > 0 && (
                <span className="text-xs px-3 py-1.5 rounded-full bg-red-950/30 border border-red-900/30 text-red-400 font-medium">
                  {preview.high_count} high
                </span>
              )}
              {preview.medium_count > 0 && (
                <span className="text-xs px-3 py-1.5 rounded-full bg-amber-950/30 border border-amber-800/30 text-amber-400 font-medium">
                  {preview.medium_count} medium
                </span>
              )}
            </div>

            {aleRange && (
              <div className="flex items-center gap-2 mb-5 p-3 bg-red-950/20 border border-red-900/30 rounded-xl">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span className="text-sm text-slate-300">
                  Total estimated risk: <span className="font-black text-red-400">{aleRange}</span>
                </span>
              </div>
            )}

            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-xl font-black text-slate-100">Full Report + Remediation Plan</div>
                <div className="text-sm text-slate-400">Role-based views · AI fix steps · SBOM</div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-black text-blue-400">₹499</div>
                <div className="text-xs text-slate-600">one-time</div>
              </div>
            </div>

            <RazorpayButton scanId={params.scanId} />

            <p className="text-center text-xs text-slate-600 mt-3">
              Secure payment · Instant access · No subscription
            </p>
          </div>

          {/* ── Risk count summary ── */}
          <div className="grid grid-cols-4 gap-2">
            {[
              { label: 'Critical', value: preview.critical_count, color: 'text-red-400 bg-red-950/30 border-red-800/40' },
              { label: 'High', value: preview.high_count, color: 'text-orange-400 bg-orange-950/30 border-orange-800/40' },
              { label: 'Medium', value: preview.medium_count, color: 'text-amber-400 bg-amber-950/20 border-amber-800/30' },
              { label: 'Low', value: preview.low_count, color: 'text-slate-500 bg-slate-900/30 border-slate-800/30' },
            ].map(stat => (
              <div key={stat.label} className={`rounded-xl border p-3 text-center ${stat.color}`}>
                <div className="text-2xl font-black">{stat.value || 0}</div>
                <div className="text-[10px] font-bold uppercase opacity-70">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
