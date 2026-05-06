'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  getFullReport, getRoadmap, getComplianceReport,
  getBrandThreats, getEnterpriseData, getASPMScore,
  submitFindingFeedback,
} from '@/lib/api';
import { useScanStore } from '@/store/scanStore';
import { FullReport, RemediationRoadmap as RoadmapType, RiskItem, ASPMReport, severityToWeight } from '@/types';

// Components
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import DisclaimerBanner from '@/components/DisclaimerBanner';
import ScoreRing from '@/components/ScoreRing';
import ScoreExplainer from '@/components/ScoreExplainer';
import RiskCard from '@/components/RiskCard';
import FixNowModal from '@/components/FixNowModal';
import SmartSummaryBar from '@/components/SmartSummaryBar';
import AlertFatigueGuard from '@/components/AlertFatigueGuard';
import ScanModuleStatus from '@/components/ScanModuleStatus';
import RoleSelector, { useRole } from '@/components/RoleSelector';
import TechInventory from '@/components/TechInventory';
import RemediationRoadmap from '@/components/RemediationRoadmap';
import EmailSecurityGrade from '@/components/EmailSecurityGrade';
import ComplianceReport from '@/components/ComplianceReport';
import BrandThreatCard from '@/components/BrandThreatCard';
import ASPMScorePanel from '@/components/ASPMScorePanel';
import OWASPCoverageMap from '@/components/OWASPCoverageMap';
import EnterpriseRemediation from '@/components/EnterpriseRemediation';
import DependencyScanPanel from '@/components/DependencyScanPanel';
import LLMSecurityPanel from '@/components/LLMSecurityPanel';

// Role views
import CISOView from './views/CISOView';
import AnalystView from './views/AnalystView';
import DeveloperView from './views/DeveloperView';

import {
  Loader2, Download, ShieldAlert, CheckCircle2,
  ChevronDown, ChevronUp,
} from 'lucide-react';

// ─── Sidebar nav ──────────────────────────────────────────────────────────────

const NAV_SECTIONS = [
  { id: 'overview',               label: 'Overview' },
  { id: 'role-view',              label: 'Role View' },
  { id: 'aspm-posture',           label: 'ASPM Posture' },
  { id: 'enterprise-remediation', label: 'Remediation' },
  { id: 'owasp-coverage',         label: 'OWASP Coverage' },
  { id: 'dependency-scan',        label: 'Dependencies' },
  { id: 'llm-security',           label: 'AI/LLM Security' },
  { id: 'compliance',             label: 'Compliance' },
  { id: 'brand-threats',          label: 'Brand Protection' },
  { id: 'email-security',         label: 'Email Security' },
  { id: 'technology-stack',       label: 'Tech Stack' },
  { id: 'all-findings',           label: 'All Findings' },
];

// ─── Progressive disclosure findings list ─────────────────────────────────────

function FindingsList({
  findings,
  onFixClick,
}: {
  findings: RiskItem[];
  onFixClick: (f: RiskItem) => void;
}) {
  const [showLow, setShowLow] = useState(false);

  const critical = findings.filter(f => f.severity === 'CRITICAL');
  const high = findings.filter(f => f.severity === 'RED');
  const medium = findings.filter(f => f.severity === 'AMBER');
  const lowAndInfo = findings.filter(f => f.severity === 'GREEN' || f.severity === 'INFO');

  const renderSection = (
    id: string,
    label: string,
    items: RiskItem[],
    defaultExpanded = true,
  ) => {
    if (items.length === 0) return null;
    return (
      <div id={id} className="scroll-mt-8 space-y-3">
        <div className="text-[10px] font-bold uppercase tracking-widest text-slate-600 px-1">
          {label} ({items.length})
        </div>
        {items.map((f, i) => (
          <div key={i} data-severity={f.severity}>
            <RiskCard
              finding={f}
              visualWeight={severityToWeight(f.severity)}
              onFixClick={onFixClick}
            />
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-8">
      <SmartSummaryBar findings={findings} />

      {renderSection('findings-critical', '🔴 Critical — Fix Immediately', critical)}
      {renderSection('findings-high', '🟠 High — Fix This Week', high)}

      {/* AMBER — collapsed by default */}
      {medium.length > 0 && (
        <div id="findings-medium" className="scroll-mt-8 space-y-3">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-600 px-1">
            🟡 Medium — Address This Month ({medium.length})
          </div>
          {medium.map((f, i) => (
            <div key={i} data-severity={f.severity}>
              <RiskCard
                finding={f}
                visualWeight="medium"
                onFixClick={onFixClick}
              />
            </div>
          ))}
        </div>
      )}

      {/* Low + Info — hidden behind toggle */}
      {lowAndInfo.length > 0 && (
        <div className="scroll-mt-8">
          <button
            onClick={() => setShowLow(s => !s)}
            className="flex items-center gap-2 text-xs font-medium text-slate-600 hover:text-slate-400 transition-colors mb-3 px-1"
          >
            {showLow
              ? <ChevronUp className="w-3.5 h-3.5" />
              : <ChevronDown className="w-3.5 h-3.5" />}
            {showLow ? 'Hide' : 'Show'} {lowAndInfo.length} lower-priority findings
          </button>
          {showLow && (
            <div className="space-y-2">
              {lowAndInfo.map((f, i) => (
                <div key={i} data-severity={f.severity}>
                  <RiskCard
                    finding={f}
                    visualWeight={f.severity === 'INFO' ? 'info' : 'low'}
                    onFixClick={onFixClick}
                  />
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main ReportPage ──────────────────────────────────────────────────────────

export default function ReportPage({ params }: { params: { scanId: string } }) {
  const [report, setReport] = useState<FullReport | null>(null);
  const [roadmap, setRoadmapData] = useState<RoadmapType | null>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [brandThreats, setBrandThreats] = useState<any>(null);
  const [enterpriseData, setEnterpriseData] = useState<any>(null);
  const [aspmData, setAspmData] = useState<ASPMReport | null>(null);
  const [enterpriseLoading, setEnterpriseLoading] = useState(true);
  const [isLoading, setIsLoading] = useState(true);
  const [activeModal, setActiveModal] = useState<RiskItem | null>(null);
  const [role, setRole] = useRole();
  const { reportJWT } = useScanStore();
  const router = useRouter();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [rep, road, comp, brand] = await Promise.allSettled([
          getFullReport(params.scanId, ''),
          getRoadmap(params.scanId, ''),
          getComplianceReport(params.scanId),
          getBrandThreats(params.scanId),
        ]);
        if (rep.status === 'fulfilled')   setReport(rep.value);
        if (road.status === 'fulfilled')  setRoadmapData(road.value);
        if (comp.status === 'fulfilled')  setCompliance(comp.value);
        if (brand.status === 'fulfilled') setBrandThreats(brand.value);
      } catch (err) {
        console.error('Failed to fetch report data:', err);
      } finally {
        setIsLoading(false);
      }

      try {
        setEnterpriseLoading(true);
        const [entResult, aspmResult] = await Promise.allSettled([
          getEnterpriseData(params.scanId),
          getASPMScore(params.scanId),
        ]);
        if (entResult.status === 'fulfilled' && entResult.value) {
          setEnterpriseData(entResult.value.enterprise || entResult.value);
          if (entResult.value.aspm) setAspmData(entResult.value.aspm);
        }
        if (aspmResult.status === 'fulfilled' && aspmResult.value) {
          setAspmData(aspmResult.value);
        }
      } catch (err) {
        console.error('Failed to fetch enterprise data:', err);
      } finally {
        setEnterpriseLoading(false);
      }
    };
    fetchData();
  }, [params.scanId]);

  const handleFixClick = useCallback((finding: RiskItem) => {
    setActiveModal(finding);
  }, []);

  const handleMarkFixed = useCallback(async (findingId: string) => {
    await submitFindingFeedback(params.scanId, findingId, 'mark_fixed');
  }, [params.scanId]);

  const handleFalsePositive = useCallback(async (findingId: string) => {
    await submitFindingFeedback(params.scanId, findingId, 'false_positive');
  }, [params.scanId]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#030303] gap-4">
        <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        <p className="text-slate-500 text-sm animate-pulse">Loading your security report…</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#030303] text-slate-300">
        <div className="text-center">
          <ShieldAlert className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold mb-2">Failed to load report</h2>
          <p className="text-slate-500 text-sm">The scan may still be running or the report was not found.</p>
        </div>
      </div>
    );
  }

  // Flatten all findings into a stable array
  const allFindings: RiskItem[] = [
    ...(report.critical_risks || []),
    ...(report.high_risks || []),
    ...(report.medium_risks || []),
    ...(report.low_risks || []),
    ...(report.info_risks || []),
    ...(report.findings || report.risk_items || []),
  ];

  // Deduplicate by title
  const seen = new Set<string>();
  const findings = allFindings.filter(f => {
    if (seen.has(f.title)) return false;
    seen.add(f.title);
    return true;
  });

  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;

  // Module status from enterprise or ASPM data
  const modules = enterpriseData?.module_status || aspmData?.modules_tested?.map((m: string) => ({
    name: m,
    display_name: m.replace(/_check$|_security$/, '').replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()),
    status: 'success' as const,
  })) || [];

  return (
    <>
      <Navbar />
      <main className="flex-1 bg-[#030303] pb-20 print:bg-white print:text-black">
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-10 flex flex-col lg:flex-row gap-10">

          {/* ─── LEFT SIDEBAR ─────────────────────────────────────────── */}
          <div className="hidden lg:block w-60 shrink-0 print:hidden">
            <div className="sticky top-8 flex flex-col gap-1">
              <h3 className="text-[10px] text-slate-600 font-bold uppercase tracking-widest mb-3">Sections</h3>
              {NAV_SECTIONS.map(section => (
                <a
                  key={section.id}
                  href={`#${section.id}`}
                  className="text-xs font-medium text-slate-500 hover:text-slate-200 py-1.5 px-3 rounded-lg hover:bg-slate-900/50 transition-colors"
                >
                  {section.label}
                </a>
              ))}
              <button
                onClick={() => window.print()}
                className="mt-6 flex items-center gap-2 text-xs font-bold text-blue-400 hover:text-blue-300 p-3 bg-blue-950/20 rounded-xl transition-colors border border-blue-900/30"
              >
                <Download className="w-3.5 h-3.5" /> Download PDF
              </button>
            </div>
          </div>

          {/* ─── MAIN CONTENT ─────────────────────────────────────────── */}
          <div className="flex-1 min-w-0 flex flex-col gap-14">

            {/* ── OVERVIEW ── */}
            <section id="overview" className="scroll-mt-8">
              <h1 className="text-2xl font-black text-slate-100 mb-6 border-b border-slate-800/60 pb-4">
                Security Report
              </h1>

              {/* Module Status */}
              {(modules.length > 0 || aspmData) && (
                <div className="mb-6">
                  <ScanModuleStatus
                    modules={modules}
                    totalModules={20}
                  />
                </div>
              )}

              <div className="grid md:grid-cols-2 gap-6">
                {/* Score Ring + explainer */}
                <div className="flex flex-col items-center gap-3">
                  <ScoreRing score={report.overall_score} severity={report.overall_severity} />
                  <div className="flex items-center gap-1 text-xs text-slate-500">
                    <span>Security Score</span>
                    <ScoreExplainer
                      score={report.overall_score}
                      breakdown={report.score_breakdown as any}
                      epssAdjustments={(aspmData as any)?.epss_adjustments}
                      wafAdjustments={(aspmData as any)?.waf_adjustments}
                      label="Security Score"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-4">
                  {/* Executive summary */}
                  <div className="bg-[#09090b] p-5 rounded-2xl border border-slate-800/50 flex-1">
                    <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">AI Executive Summary</h4>
                    <p className="text-sm text-slate-300 leading-relaxed">{report.executive_summary}</p>
                  </div>

                  {/* Finding count pills */}
                  <div className="grid grid-cols-4 gap-2">
                    {[
                      { label: 'Critical', value: report.critical_count || 0, cls: 'text-red-400 bg-red-950/30 border-red-800/40' },
                      { label: 'High',     value: report.high_count    || 0, cls: 'text-orange-400 bg-orange-950/20 border-orange-900/30' },
                      { label: 'Medium',   value: report.medium_count  || 0, cls: 'text-amber-400 bg-amber-950/20 border-amber-800/30' },
                      { label: 'Low',      value: report.low_count     || 0, cls: 'text-slate-500 bg-slate-900/30 border-slate-800/40' },
                    ].map(stat => (
                      <div key={stat.label} className={`rounded-xl border p-3 text-center ${stat.cls}`}>
                        <div className="text-2xl font-black">{stat.value}</div>
                        <div className="text-[10px] font-bold uppercase opacity-70">{stat.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* ALE total */}
                  {(report.total_ale_reduction_inr || aspmData?.total_ale_reduction_inr) && (
                    <div className="bg-[#09090b] p-4 rounded-2xl border border-slate-800/50">
                      <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">Total Risk Reduction Available</div>
                      <div className={`text-xl font-black ${
                        (report.total_ale_reduction_inr || 0) >= 5_000_000 ? 'text-red-400' :
                        (report.total_ale_reduction_inr || 0) >= 1_000_000 ? 'text-amber-400' : 'text-blue-400'
                      }`}>
                        {report.total_ale_display || aspmData?.total_ale_display || '—'}
                      </div>
                      <div className="text-xs text-slate-600 mt-0.5">if all findings remediated</div>
                    </div>
                  )}
                </div>
              </div>
            </section>

            {/* ── ROLE SELECTOR + ROLE VIEW ── */}
            <section id="role-view" className="scroll-mt-8">
              <div className="flex items-center justify-between mb-6 border-b border-slate-800/60 pb-4">
                <h2 className="text-xl font-black text-slate-100">
                  {role === 'ciso' ? 'Executive Risk View' :
                   role === 'analyst' ? 'Threat Intelligence View' : 'Developer Fix View'}
                </h2>
                <RoleSelector value={role} onChange={setRole} />
              </div>

              {role === 'ciso' && (
                <CISOView report={report} aspmData={aspmData || undefined} />
              )}
              {role === 'analyst' && (
                <AnalystView report={report} aspmData={aspmData || undefined} enterpriseData={enterpriseData} />
              )}
              {role === 'developer' && (
                <DeveloperView report={report} aspmData={aspmData || undefined} onFixClick={handleFixClick} />
              )}
            </section>

            {/* ── ASPM POSTURE ── */}
            {enterpriseLoading && !aspmData ? (
              <section id="aspm-posture" className="scroll-mt-8">
                <div className="bg-[#09090b] border border-slate-800/50 rounded-2xl p-8 flex items-center gap-4">
                  <Loader2 className="w-6 h-6 text-blue-500 animate-spin shrink-0" />
                  <div>
                    <div className="text-slate-300 font-bold text-sm">Running Enterprise Security Analysis…</div>
                    <div className="text-slate-600 text-xs mt-1">ASPM Score · OWASP Coverage · Dependencies · AI/LLM Security</div>
                  </div>
                </div>
              </section>
            ) : (
              <>
                <ASPMScorePanel data={aspmData as any} />
                <EnterpriseRemediation
                  roadmap={aspmData?.remediation_roadmap as any}
                  quickWins={aspmData?.quick_wins as any}
                  immediateActions={aspmData?.immediate_actions as any}
                />
                <OWASPCoverageMap
                  coverage={aspmData?.owasp_coverage as any}
                  coveredCount={aspmData?.owasp_covered_count}
                />
                <DependencyScanPanel data={enterpriseData?.dependency} />
                <LLMSecurityPanel data={enterpriseData?.llm_security} />
              </>
            )}

            {/* ── LEGACY ROADMAP ── */}
            <RemediationRoadmap roadmap={roadmap} />

            {/* ── COMPLIANCE ── */}
            <ComplianceReport data={compliance} />

            {/* ── BRAND THREATS ── */}
            <BrandThreatCard data={brandThreats} />

            {/* ── EMAIL SECURITY ── */}
            <section id="email-security" className="scroll-mt-8">
              <h2 className="text-xl font-black text-slate-100 mb-5 border-b border-slate-800/60 pb-3">Email Security</h2>
              <EmailSecurityGrade
                grade={(report as any).domain_reports?.email?.grade || 'N/A'}
                details={(report as any).domain_reports?.email}
              />
            </section>

            {/* ── TECH INVENTORY ── */}
            <section id="technology-stack" className="scroll-mt-8">
              <h2 className="text-xl font-black text-slate-100 mb-5 border-b border-slate-800/60 pb-3">Technology Stack & CVEs</h2>
              <TechInventory inventory={(report as any).tech_inventory || (report as any).domain_reports?.tech || []} />
            </section>

            {/* ── ALL FINDINGS (progressive disclosure) ── */}
            <section id="all-findings" className="scroll-mt-8">
              <h2 className="text-xl font-black text-slate-100 mb-2 border-b border-slate-800/60 pb-3">
                All Security Findings
                <span className="ml-3 text-sm font-normal text-slate-500">({findings.length})</span>
              </h2>
              <p className="text-xs text-slate-600 mb-6">
                Critical and high severity findings are shown prominently. Lower-priority findings are collapsed to reduce cognitive load.
              </p>
              {findings.length === 0 ? (
                <div className="text-center py-16 text-slate-500">
                  <CheckCircle2 className="w-10 h-10 text-green-400 mx-auto mb-3" />
                  <p>No findings to display.</p>
                </div>
              ) : (
                <FindingsList findings={findings} onFixClick={handleFixClick} />
              )}
            </section>

          </div>
        </div>
      </main>

      {/* ── Alert Fatigue Guard ── */}
      <AlertFatigueGuard criticalCount={criticalCount} />

      {/* ── Fix Now Modal ── */}
      {activeModal && (
        <FixNowModal
          finding={activeModal}
          onClose={() => setActiveModal(null)}
          onMarkFixed={handleMarkFixed}
          onFalsePositive={handleFalsePositive}
        />
      )}

      <DisclaimerBanner />
      <Footer />
    </>
  );
}
