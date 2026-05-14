"use client";

import { useEffect, useState } from "react";
import { Shield, AlertTriangle, CheckCircle2, AlertOctagon } from "lucide-react";
import { useParams } from "next/navigation";
import { useAuthStore } from "@/store/authStore";
import { getComplianceReport, getFullReport } from "@/lib/api";

export default function DPDPExportPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const token = useAuthStore((state) => state.token);
  
  const [data, setData] = useState<{report: any, dpdp: any} | null>(null);

  useEffect(() => {
    if (token && scanId) {
      Promise.all([
        getFullReport(scanId, token),
        getComplianceReport(scanId)
      ]).then(([report, compliance]) => {
        setData({ report, dpdp: compliance?.dpdp });
        // Auto-print after a small delay to ensure fonts render
        setTimeout(() => window.print(), 800);
      }).catch(err => console.error(err));
    }
  }, [token, scanId]);

  if (!data) return <div className="p-10 font-sans text-center text-gray-500">Generating report...</div>;

  const { report, dpdp } = data;
  if (!dpdp) return <div className="p-10 text-center">No DPDP data available.</div>;

  // Grade calculation A-F based on readiness score
  const getGrade = (score: number) => {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  };
  const grade = getGrade(dpdp.readiness_score);

  // Formatting currency INR
  const formatINR = (value: number) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      maximumFractionDigits: 0
    }).format(value);
  };

  // DPDP max penalty is up to 250 Crores per violation. We can show exposure based on severity.
  // Using ALE reduction from report as a proxy, or hardcode typical DPDP penalties.
  const criticalCount = dpdp.violated_clauses.filter((c: any) => c.severity === 'CRITICAL').length;
  const highCount = dpdp.violated_clauses.filter((c: any) => c.severity === 'HIGH').length;
  // DPDP Section 8(4) non-compliance can attract penalty up to ₹250 Crore
  const estimatedPenaltyExposure = (criticalCount * 250_00_00_000) + (highCount * 50_00_00_000);

  // Remediation Priority List (Top 5 violated clauses mapped to risk items)
  // We can just use the violated clauses as the priority list.
  const priorityList = [...dpdp.violated_clauses].sort((a: any, b: any) => {
    const sevScore = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return (sevScore[b.severity as keyof typeof sevScore] || 0) - (sevScore[a.severity as keyof typeof sevScore] || 0);
  }).slice(0, 5);

  return (
    <div className="bg-white min-h-screen text-black font-sans p-8 print:p-0 print:bg-white print:m-0 mx-auto max-w-4xl" style={{ printColorAdjust: 'exact', WebkitPrintColorAdjust: 'exact' }}>
      
      {/* Header */}
      <div className="flex justify-between items-end border-b-2 border-gray-900 pb-4 mb-6">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-gray-900 uppercase">DPDP Act Compliance Audit</h1>
          <p className="text-gray-600 mt-1 font-medium">Digital Personal Data Protection Act, 2023</p>
        </div>
        <div className="text-right">
          <p className="text-sm font-bold text-gray-800">Target: {report.domain}</p>
          <p className="text-xs text-gray-500 mt-0.5">Date: {new Date().toLocaleDateString('en-IN')}</p>
          <p className="text-xs text-gray-500 mt-0.5">Report ID: {report.scan_id.split('-')[0].toUpperCase()}</p>
        </div>
      </div>

      {/* Top Metrics Row */}
      <div className="flex gap-4 mb-8">
        <div className="flex-1 bg-gray-50 p-5 rounded-lg border border-gray-200 text-center">
          <div className="text-xs font-bold uppercase tracking-wider text-gray-500 mb-1">Compliance Score</div>
          <div className="text-5xl font-black text-gray-900">{dpdp.readiness_score}%</div>
        </div>
        <div className="flex-1 bg-gray-50 p-5 rounded-lg border border-gray-200 text-center flex flex-col justify-center items-center">
          <div className="text-xs font-bold uppercase tracking-wider text-gray-500 mb-1">Overall Risk Rating</div>
          <div className={`text-5xl font-black ${grade === 'A' || grade === 'B' ? 'text-green-600' : grade === 'C' ? 'text-amber-500' : 'text-red-600'}`}>
            {grade}
          </div>
        </div>
        <div className="flex-1 bg-red-50 p-5 rounded-lg border border-red-200 text-center">
          <div className="text-xs font-bold uppercase tracking-wider text-red-600 mb-1">Max Penalty Exposure</div>
          <div className="text-2xl font-black text-red-700 mt-2">{estimatedPenaltyExposure > 0 ? formatINR(estimatedPenaltyExposure) : '₹0'}</div>
          <div className="text-[10px] text-red-500 mt-1">Based on Sec 33 (Up to ₹250 Cr)</div>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="mb-8">
        <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-3">Executive Summary</h2>
        <p className="text-sm text-gray-700 leading-relaxed font-medium">
          {dpdp.summary} This audit evaluates {report.domain}'s adherence to the security safeguards mandated by Section 8(4) of the DPDP Act. The system is currently operating with <strong className="text-red-600">{criticalCount} CRITICAL</strong> and <strong className="text-amber-600">{highCount} HIGH</strong> severity non-compliance issues that must be addressed immediately to mitigate regulatory action by the Data Protection Board.
        </p>
      </div>

      {/* Violated Sections */}
      <div className="mb-8">
        <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-4">DPDP Act Violations Detected</h2>
        {dpdp.violated_clauses.length === 0 ? (
          <div className="flex items-center gap-2 text-green-700 bg-green-50 p-4 rounded-md border border-green-200 font-medium">
            <CheckCircle2 className="w-5 h-5" /> No DPDP Act violations detected in external perimeter.
          </div>
        ) : (
          <div className="grid gap-3">
            {dpdp.violated_clauses.map((clause: any, i: number) => (
              <div key={i} className="flex items-start gap-3 border border-gray-200 rounded-md p-3 bg-white">
                <div className="pt-0.5">
                  {clause.severity === 'CRITICAL' ? <AlertOctagon className="w-5 h-5 text-red-600" /> : <AlertTriangle className="w-5 h-5 text-amber-500" />}
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-bold text-sm text-gray-900">{clause.clause_id}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${clause.severity === 'CRITICAL' ? 'bg-red-100 text-red-700' : clause.severity === 'HIGH' ? 'bg-amber-100 text-amber-700' : 'bg-gray-100 text-gray-700'}`}>
                      {clause.severity}
                    </span>
                  </div>
                  <div className="text-sm font-semibold text-gray-800">{clause.clause_title}</div>
                  <div className="text-xs text-gray-600 mt-1">{clause.description}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Remediation Priority List */}
      <div className="mb-8 page-break-inside-avoid">
        <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-4">Remediation Priority List</h2>
        <table className="w-full text-left text-sm border-collapse">
          <thead>
            <tr className="bg-gray-100 text-gray-700">
              <th className="p-2 border border-gray-300 font-bold w-16">Priority</th>
              <th className="p-2 border border-gray-300 font-bold">Clause Violation</th>
              <th className="p-2 border border-gray-300 font-bold w-32">Est. Fix Time</th>
            </tr>
          </thead>
          <tbody>
            {priorityList.map((clause: any, i: number) => (
              <tr key={i} className="bg-white">
                <td className="p-2 border border-gray-300 text-center font-bold text-gray-900">#{i + 1}</td>
                <td className="p-2 border border-gray-300">
                  <span className="font-bold">{clause.clause_id}</span>: {clause.clause_title}
                </td>
                <td className="p-2 border border-gray-300 text-gray-600">
                  {clause.severity === 'CRITICAL' ? '< 24 Hours' : clause.severity === 'HIGH' ? '< 7 Days' : '< 30 Days'}
                </td>
              </tr>
            ))}
            {priorityList.length === 0 && (
              <tr>
                <td colSpan={3} className="p-4 text-center border border-gray-300 text-gray-500">All prioritized controls are passing.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="mt-12 pt-4 border-t border-gray-300 flex justify-between text-[10px] text-gray-400 uppercase tracking-wider font-bold">
        <div>NANZ Enterprise Security</div>
        <div>CONFIDENTIAL — FOR INTERNAL LEGAL/IT USE ONLY</div>
      </div>

      {/* CSS to hide non-print elements and fix print styles */}
      <style dangerouslySetInnerHTML={{__html: `
        @media print {
          body { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: white; }
          .page-break-inside-avoid { page-break-inside: avoid; }
          @page { margin: 10mm; size: A4; }
        }
      `}} />
    </div>
  );
}
