'use client';

import { useState } from 'react';
import { TrendingUp, AlertTriangle, ChevronDown, ChevronUp, Shield } from 'lucide-react';
import {
  FullReport, ASPMReport, RiskItem, ComplianceV2,
  formatALE, aleColorClass,
} from '@/types';
import { normalizeSeverity } from '@/lib/severity';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import ScoreRing from '@/components/ScoreRing';

// ─── Compliance Grade helper ──────────────────────────────────────────────────

function scoreToGrade(score?: number): { grade: string; color: string; bg: string } {
  if (!score) return { grade: 'N/A', color: 'text-slate-500', bg: 'bg-slate-900/40' };
  if (score >= 90) return { grade: 'A', color: 'text-green-400', bg: 'bg-green-950/30' };
  if (score >= 75) return { grade: 'B', color: 'text-blue-400', bg: 'bg-blue-950/30' };
  if (score >= 60) return { grade: 'C', color: 'text-amber-400', bg: 'bg-amber-950/30' };
  if (score >= 40) return { grade: 'D', color: 'text-orange-400', bg: 'bg-orange-950/30' };
  return { grade: 'F', color: 'text-red-400', bg: 'bg-red-950/30' };
}

// ─── Compliance Box ───────────────────────────────────────────────────────────

function ComplianceBox({
  label, score, status, violations, penalty, isLoading
}: {
  label: string;
  score?: number;
  status?: string;
  violations?: string[];
  penalty?: string;
  isLoading?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const g = scoreToGrade(score);

  if (isLoading) {
    return (
      <div className="rounded-xl border border-slate-800/50 bg-slate-900/20 p-5 animate-pulse">
        <div className="flex items-start justify-between mb-2">
          <div>
            <div className="w-20 h-3 bg-slate-800 rounded mb-2"></div>
            <div className="w-12 h-10 bg-slate-800 rounded"></div>
          </div>
          <div className="flex flex-col items-end">
            <div className="w-16 h-4 bg-slate-800 rounded mb-1"></div>
            <div className="w-24 h-3 bg-slate-800 rounded mt-1"></div>
          </div>
        </div>
        <div className="flex items-center justify-end mt-2">
          <div className="w-4 h-4 bg-slate-800 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`rounded-xl border border-slate-800/50 ${g.bg} p-5 cursor-pointer transition-all hover:border-slate-700/60`}
      onClick={() => setOpen(o => !o)}
    >
      <div className="flex items-start justify-between mb-2">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">{label}</div>
          <div className={`text-4xl font-black ${g.color}`}>{g.grade}</div>
        </div>
        <div className="text-right">
          <div className={`text-xs font-semibold ${g.color}`}>{status || (score !== undefined ? `${score}/100` : '—')}</div>
          {penalty && <div className="text-[10px] text-slate-600 mt-1">{penalty}</div>}
        </div>
      </div>

      {open && violations && violations.length > 0 && (
        <div className="mt-3 pt-3 border-t border-slate-800/50">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-2">Violations</div>
          <ul className="space-y-1">
            {violations.slice(0, 5).map((v, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-slate-400">
                <AlertTriangle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                {v}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex items-center justify-end mt-2">
        {open
          ? <ChevronUp className="w-3.5 h-3.5 text-slate-600" />
          : <ChevronDown className="w-3.5 h-3.5 text-slate-600" />}
      </div>
    </div>
  );
}

// ─── Top Risk Card (CISO-safe — no CVE/tech details) ─────────────────────────

function CISOFindingCard({ finding, rank }: { finding: RiskItem; rank: number }) {
  const aleColor = aleColorClass(finding.ale_reduction_inr);

  return (
    <div className={`rounded-xl border p-5 ${
      finding.severity === 'CRITICAL' ? 'bg-[#450a0a]/60 border-red-800/50' :
      normalizeSeverity(finding.severity) === 'HIGH' ? 'bg-[#1c0a0a]/60 border-red-900/40' :
      'bg-[#0d0d10] border-slate-800/40'
    }`}>
      <div className="flex items-start gap-4">
        <div className={`text-3xl font-black shrink-0 ${
          rank <= 2 ? 'text-red-500' : rank <= 4 ? 'text-amber-500' : 'text-slate-600'
        }`}>
          #{rank}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-bold text-slate-200 mb-1 leading-snug">{finding.title}</h3>
          <p className="text-xs text-slate-400 leading-relaxed mb-3">{finding.business_impact}</p>
          <div className="flex flex-wrap gap-2">
            {finding.ale_reduction_inr !== undefined && finding.ale_reduction_inr > 0 && (
              <span className={`text-xs font-bold ${aleColor}`}>
                {finding.ale_display || formatALE(finding.ale_reduction_inr)} risk reduced
              </span>
            )}
            {finding.sla_tier === 'P0' && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-950/60 border border-red-800/50 text-red-400">
                24h SLA
              </span>
            )}
            {finding.compliance_violations?.slice(0, 2).map((v, i) => (
              <span key={i} className="text-[10px] px-2 py-0.5 rounded-full bg-purple-950/40 border border-purple-800/40 text-purple-400">
                {typeof v === 'string' ? v : `${v?.framework || ''} ${v?.clause_id || ''}`.trim()}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main CISOView ────────────────────────────────────────────────────────────

interface CISOViewProps {
  report: FullReport;
  aspmData?: ASPMReport;
  historicalScores?: { date: string; score: number }[];
}

export default function CISOView({ report, aspmData, historicalScores }: CISOViewProps) {
  const totalALE = aspmData?.total_ale_reduction_inr || report.total_ale_reduction_inr || 0;
  const dpdpPenalty = aspmData?.dpdp_penalty_crore || report.dpdp_penalty_crore || 0;

  // Estimate time to compliance: sum of P0+P1 remediation hours
  const allFindings: RiskItem[] = [
    ...(report.critical_risks || []),
    ...(report.high_risks || []),
    ...(report.findings || report.risk_items || []),
  ];

  const urgentFindings = allFindings.filter(f =>
    f.severity === 'CRITICAL' || normalizeSeverity(f.severity) === 'HIGH'
  );
  // Rough estimate: each finding ~3 days average
  const weeksEstimate = Math.ceil((urgentFindings.length * 3) / 5);

  // Top 5 by ALE reduction
  const topFindings = [...allFindings]
    .filter(f => f.ale_reduction_inr !== undefined && f.ale_reduction_inr > 0)
    .sort((a, b) => (b.ale_reduction_inr || 0) - (a.ale_reduction_inr || 0))
    .slice(0, 5);

  // Fallback: top by severity if no ALE data
  const topFindingsFinal = topFindings.length > 0
    ? topFindings
    : allFindings
        .filter(f => normalizeSeverity(f.severity) === 'CRITICAL' || normalizeSeverity(f.severity) === 'HIGH')
        .slice(0, 5);

  const cv2 = aspmData?.compliance_v2 || (report.compliance_report_v2 as any);
  const dpdpViolations = cv2?.dpdp?.violated_sections?.map((s: any) => s.description) || [];
  const gdprViolations = cv2?.gdpr?.violated_articles?.map((a: any) => a.description) || [];
  const pciViolations = cv2?.pci_dss?.violated_requirements?.map((r: any) => r.description) || [];
  const soc2Violations = cv2?.soc2?.violated_criteria?.map((c: any) => c.description) || [];

  const aleClass = totalALE >= 5_000_000 ? 'text-red-400' :
                   totalALE >= 1_000_000 ? 'text-amber-400' : 'text-blue-400';

  return (
    <div className="space-y-10">

      {/* Section 1 — Executive Risk Cards */}
      <section>
        <h2 className="text-xl font-black text-slate-200 mb-5 flex items-center gap-2">
          <Shield className="w-5 h-5 text-red-400" />
          Executive Risk Summary
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* ASPM Score */}
          <div className="relative rounded-2xl border border-slate-800/40 bg-slate-900/30 overflow-hidden flex flex-col justify-center">
            <div className="absolute top-4 left-0 right-0 text-center z-10 pointer-events-none">
              <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">ASPM Security Score</span>
            </div>
            <div className="transform scale-[0.85] origin-center mt-6">
              <ScoreRing score={aspmData?.aspm_score || report.overall_score} severity={aspmData?.posture_tier || report.overall_severity} />
            </div>
          </div>

          {/* Financial Exposure */}
          <div className={`rounded-2xl border p-6 ${
            totalALE >= 5_000_000 ? 'bg-red-950/20 border-red-800/40' :
            totalALE >= 1_000_000 ? 'bg-amber-950/20 border-amber-800/40' :
            'bg-blue-950/20 border-blue-800/30'
          }`}>
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
              Total Financial Exposure
            </div>
            <div className={`text-2xl font-black mb-1 ${aleClass}`}>
              {formatALE(totalALE) || 'Calculating…'}
            </div>
            <div className="text-xs text-slate-500">Estimated annual loss if unmitigated</div>
          </div>

          {/* DPDP Penalty */}
          <div className={`rounded-2xl border p-6 ${
            dpdpPenalty > 0 ? 'bg-red-950/20 border-red-800/40' : 'bg-slate-900/30 border-slate-800/40'
          }`}>
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
              DPDP Penalty Exposure
            </div>
            <div className={`text-2xl font-black mb-1 ${dpdpPenalty > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {dpdpPenalty > 0 ? `₹${dpdpPenalty} Crore` : 'Compliant'}
            </div>
            <div className="text-xs text-slate-500">
              {dpdpPenalty > 0
                ? 'Maximum DPDP Act 2023 fine exposure'
                : 'No DPDP violations detected'}
            </div>
          </div>

          {/* Time to Compliance */}
          <div className="rounded-2xl border p-6 bg-slate-900/30 border-slate-800/40">
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
              Estimated Remediation Time
            </div>
            <div className="text-2xl font-black text-blue-400 mb-1">
              ~{weeksEstimate} {weeksEstimate === 1 ? 'week' : 'weeks'}
            </div>
            <div className="text-xs text-slate-500">
              Based on {urgentFindings.length} critical + high findings
            </div>
          </div>
        </div>
      </section>

      {/* Section 2 — Risk Trend */}
      {historicalScores && historicalScores.length >= 2 && (
        <section>
          <h2 className="text-xl font-black text-slate-200 mb-5 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-blue-400" />
            Risk Trend
          </h2>
          <div className="bg-[#09090b] rounded-2xl border border-slate-800/50 p-6">
            {(() => {
              const delta = historicalScores[historicalScores.length - 1].score - historicalScores[0].score;
              return (
                <div className="mb-4">
                  <span className={`text-2xl font-black ${delta >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                    {delta >= 0 ? '+' : ''}{delta} points
                  </span>
                  <span className="text-sm text-slate-500 ml-2">since first scan</span>
                </div>
              );
            })()}
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={historicalScores}>
                <XAxis dataKey="date" tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#0d0d10', border: '1px solid #1e293b', borderRadius: 8 }}
                  labelStyle={{ color: '#94a3b8', fontSize: 10 }}
                  itemStyle={{ color: '#60a5fa', fontSize: 12, fontWeight: 700 }}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={{ fill: '#3b82f6', r: 4 }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>
      )}

      {/* Section 3 — Compliance Status */}
      <section>
        <h2 className="text-xl font-black text-slate-200 mb-5">Compliance Status</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <ComplianceBox
            label="DPDP Act 2023"
            score={cv2?.dpdp?.dpdp_score}
            status={cv2?.dpdp?.dpdp_risk_level || report.dpdp_risk_level}
            violations={dpdpViolations}
            penalty={dpdpPenalty > 0 ? `₹${dpdpPenalty} Crore exposure` : undefined}
            isLoading={!aspmData && !report.compliance_report_v2}
          />
          <ComplianceBox
            label="GDPR"
            score={cv2?.gdpr?.gdpr_score}
            status={cv2?.gdpr?.gdpr_status || report.gdpr_status}
            violations={gdprViolations}
            isLoading={!aspmData && !report.compliance_report_v2}
          />
          <ComplianceBox
            label="PCI DSS v4.0"
            score={cv2?.pci_dss?.pci_score}
            status={cv2?.pci_dss?.pci_status || report.pci_status}
            violations={pciViolations}
            isLoading={!aspmData && !report.compliance_report_v2}
          />
          <ComplianceBox
            label="SOC 2 Type II"
            score={cv2?.soc2?.soc2_score}
            status={cv2?.soc2?.soc2_status || report.soc2_status}
            violations={soc2Violations}
            isLoading={!aspmData && !report.compliance_report_v2}
          />
        </div>
      </section>

      {/* Section 4 — Top Business Risks (no technical detail) */}
      {topFindingsFinal.length > 0 && (
        <section>
          <h2 className="text-xl font-black text-slate-200 mb-2">Top Business Risks</h2>
          <p className="text-sm text-slate-500 mb-5">
            Ranked by estimated financial impact. Technical details are available in the Analyst view.
          </p>
          <div className="space-y-3">
            {topFindingsFinal.map((f, i) => (
              <CISOFindingCard key={f.id || i} finding={f} rank={i + 1} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
