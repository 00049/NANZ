'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getFullReport, getRoadmap, getComplianceReport, getBrandThreats } from '@/lib/api';
import { useScanStore } from '@/store/scanStore';
import { FullReport, RemediationRoadmap as RoadmapType } from '@/types';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ScoreRing from '@/components/ScoreRing';
import RiskCard from '@/components/RiskCard';
import TechInventory from '@/components/TechInventory';
import RemediationRoadmap from '@/components/RemediationRoadmap';
import EmailSecurityGrade from '@/components/EmailSecurityGrade';
import DisclaimerBanner from '@/components/DisclaimerBanner';
import ComplianceReport from '@/components/ComplianceReport';
import BrandThreatCard from '@/components/BrandThreatCard';
import { Loader2, Download, Shield, ShieldAlert, CheckCircle2, TrendingUp } from 'lucide-react';

const NAV_SECTIONS = [
  { id: 'overview',       label: 'Overview' },
  { id: 'roadmap',        label: 'Remediation Roadmap' },
  { id: 'compliance',     label: 'Compliance' },
  { id: 'brand-threats',  label: 'Brand Protection' },
  { id: 'email-security', label: 'Email Security' },
  { id: 'technology-stack', label: 'Technology Stack' },
  { id: 'all-findings',   label: 'All Findings' },
];

export default function ReportPage({ params }: { params: { scanId: string } }) {
  const [report, setReport] = useState<FullReport | null>(null);
  const [roadmap, setRoadmapData] = useState<RoadmapType | null>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [brandThreats, setBrandThreats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { reportJWT, isPaid } = useScanStore();
  const router = useRouter();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [rep, road, comp, brand] = await Promise.allSettled([
          getFullReport(params.scanId, ""),
          getRoadmap(params.scanId, ""),
          getComplianceReport(params.scanId),
          getBrandThreats(params.scanId),
        ]);

        if (rep.status === 'fulfilled')   setReport(rep.value);
        if (road.status === 'fulfilled')  setRoadmapData(road.value);
        if (comp.status === 'fulfilled')  setCompliance(comp.value);
        if (brand.status === 'fulfilled') setBrandThreats(brand.value);
      } catch (err) {
        console.error("Failed to fetch report data:", err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [params.scanId]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-background gap-4">
        <Loader2 className="w-10 h-10 text-primary animate-spin" />
        <p className="text-text-muted text-sm animate-pulse">Loading your security report…</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background text-text-primary">
        <div className="text-center">
          <ShieldAlert className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold mb-2">Failed to load report</h2>
          <p className="text-text-muted text-sm">The scan may still be running or the report was not found.</p>
        </div>
      </div>
    );
  }

  const findings = report.findings || (report as any).risk_items || [];

  return (
    <>
      <Navbar />
      <main className="flex-1 bg-background pb-20 print:bg-white print:text-black">
        <div className="max-w-7xl mx-auto px-6 py-12 flex flex-col lg:flex-row gap-12">

          {/* LEFT SIDEBAR */}
          <div className="hidden lg:block w-64 shrink-0 print:hidden">
            <div className="sticky top-8 flex flex-col gap-1">
              <h3 className="text-text-muted font-bold uppercase tracking-widest text-xs mb-4">Report Sections</h3>
              {NAV_SECTIONS.map((section) => (
                <a
                  key={section.id}
                  href={`#${section.id}`}
                  className="text-sm font-medium text-text-primary hover:text-primary py-2 px-3 rounded-md hover:bg-surface transition-colors"
                >
                  {section.label}
                </a>
              ))}
              <button
                onClick={() => window.print()}
                className="mt-8 flex items-center gap-2 text-sm font-bold text-primary hover:text-blue-400 p-3 bg-primary/10 rounded-btn transition-colors border border-primary/20"
              >
                <Download className="w-4 h-4" /> Download PDF Report
              </button>
            </div>
          </div>

          {/* MAIN CONTENT */}
          <div className="flex-1 flex flex-col gap-16">

            {/* OVERVIEW */}
            <section id="overview" className="scroll-mt-8">
              <h1 className="text-3xl font-bold text-text-primary mb-8 border-b border-card-border pb-4">Executive Overview</h1>
              <div className="grid md:grid-cols-2 gap-8">
                <ScoreRing score={report.overall_score} severity={report.overall_severity} />

                <div className="flex flex-col gap-4">
                  <div className="bg-surface p-6 rounded-card border border-card-border h-full">
                    <h4 className="text-sm font-bold uppercase tracking-widest text-text-muted mb-3">AI Executive Summary</h4>
                    <p className="text-text-primary leading-relaxed text-sm">{report.executive_summary}</p>
                  </div>

                  {/* Finding counts */}
                  <div className="grid grid-cols-4 gap-2">
                    {[
                      { label: 'Critical', value: report.critical_count || 0, color: 'text-red-400 bg-red-500/10 border-red-500/20' },
                      { label: 'High', value: report.high_count || 0, color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
                      { label: 'Medium', value: report.medium_count || 0, color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
                      { label: 'Low', value: report.low_count || 0, color: 'text-green-400 bg-green-500/10 border-green-500/20' },
                    ].map((stat) => (
                      <div key={stat.label} className={`rounded-card border p-3 text-center ${stat.color}`}>
                        <div className="text-2xl font-black">{stat.value}</div>
                        <div className="text-[10px] font-bold uppercase opacity-70">{stat.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* DPDP legacy score */}
                  {((report as any).dpdp_compliance_score !== undefined) && (
                    <div className="bg-surface p-4 rounded-card border border-card-border">
                      <h4 className="font-bold text-text-primary mb-2 flex justify-between items-center text-sm">
                        DPDP Compliance Readiness
                        <span className="text-primary font-black">{(report as any).dpdp_compliance_score}/100</span>
                      </h4>
                      <div className="w-full bg-background rounded-full h-2 overflow-hidden">
                        <div className="bg-primary h-2 rounded-full transition-all" style={{ width: `${(report as any).dpdp_compliance_score}%` }} />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </section>

            {/* REMEDIATION ROADMAP */}
            <RemediationRoadmap roadmap={roadmap} />

            {/* COMPLIANCE REPORT */}
            <ComplianceReport data={compliance} />

            {/* BRAND THREATS */}
            <BrandThreatCard data={brandThreats} />

            {/* EMAIL SECURITY */}
            <section id="email-security" className="scroll-mt-8">
              <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2">Email Security Grade</h2>
              <EmailSecurityGrade
                grade={(report as any).domain_reports?.email?.grade || 'N/A'}
                details={(report as any).domain_reports?.email}
              />
            </section>

            {/* TECH INVENTORY */}
            <section id="technology-stack" className="scroll-mt-8">
              <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2">Technology Inventory & CVEs</h2>
              <TechInventory inventory={(report as any).tech_inventory || (report as any).domain_reports?.tech || []} />
            </section>

            {/* ALL FINDINGS */}
            <section id="all-findings" className="scroll-mt-8">
              <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2">
                All Security Findings
                <span className="ml-3 text-sm font-normal text-text-muted">({findings.length} total)</span>
              </h2>
              {findings.length === 0 ? (
                <div className="text-center py-12 text-text-muted">
                  <CheckCircle2 className="w-10 h-10 text-green-400 mx-auto mb-3" />
                  <p>No findings to display.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {findings.map((finding: any, idx: number) => (
                    <RiskCard
                      key={idx}
                      title={finding.title}
                      severity={finding.severity}
                      business_impact={finding.business_impact}
                    />
                  ))}
                </div>
              )}
            </section>

          </div>
        </div>
      </main>
      <DisclaimerBanner />
      <Footer />
    </>
  );
}
