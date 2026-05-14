"use client";

import { useEffect, useState } from "react";
import { Shield, FileText, Download, CheckCircle2, AlertTriangle, XCircle, TrendingUp, TrendingDown, Minus, Loader2, ArrowRight } from "lucide-react";
import Link from "next/link";
import { useAuthStore } from "@/store/authStore";
import { listScans, getComplianceReport } from "@/lib/api";

type ComplianceData = {
  dpdp: any;
  gdpr: any;
  pci_dss: any;
  soc2: any;
  dora: any;
};

export default function ComplianceDashboard() {
  const token = useAuthStore((state) => state.token);
  const [loading, setLoading] = useState(true);
  const [latestScan, setLatestScan] = useState<any>(null);
  const [compliance, setCompliance] = useState<ComplianceData | null>(null);
  const [prevCompliance, setPrevCompliance] = useState<ComplianceData | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        const scansRes = await listScans(10, 0);
        const completeScans = scansRes.scans.filter(s => s.status === 'complete');
        
        if (completeScans.length > 0) {
          const latest = completeScans[0];
          setLatestScan(latest);
          
          const compData = await getComplianceReport(latest.id);
          setCompliance(compData);

          if (completeScans.length > 1) {
            const prev = completeScans[1];
            const prevCompData = await getComplianceReport(prev.id);
            setPrevCompliance(prevCompData);
          }
        }
      } catch (err) {
        console.error("Failed to load compliance data", err);
      } finally {
        setLoading(false);
      }
    }
    
    if (token) loadData();
  }, [token]);

  if (loading) {
    return <div className="h-64 flex items-center justify-center"><Loader2 className="w-8 h-8 text-nanz-400 animate-spin" /></div>;
  }

  if (!latestScan || !compliance) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <Shield className="w-12 h-12 mb-4" style={{ color: '#2A2A2A' }} />
        <h2 className="text-xl font-bold text-text-primary mb-2">No Compliance Data Available</h2>
        <p className="text-text-muted mb-6">Run a complete scan to generate enterprise compliance reports.</p>
        <Link href="/dashboard/new-scan" className="px-6 py-3 rounded-btn bg-nanz-gradient text-white font-medium hover:opacity-90 transition-opacity">
          Start New Scan
        </Link>
      </div>
    );
  }

  const frameworks = [
    { key: "dpdp", data: compliance.dpdp },
    { key: "gdpr", data: compliance.gdpr },
    { key: "pci_dss", data: compliance.pci_dss },
    { key: "soc2", data: compliance.soc2 },
  ];

  const getDelta = (key: string) => {
    if (!prevCompliance || !prevCompliance[key as keyof ComplianceData]) return null;
    return compliance[key as keyof ComplianceData].readiness_score - prevCompliance[key as keyof ComplianceData].readiness_score;
  };

  const scoreColor = (score: number) => {
    if (score >= 85) return "#22C55E";
    if (score >= 60) return "#F59E0B";
    return "#EF4444";
  };

  return (
    <div className="space-y-8 pb-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-headline text-text-primary">Compliance Posture</h1>
          <p className="text-text-secondary mt-1">Aggregate readiness across regulatory frameworks for {latestScan.domain}</p>
        </div>
        <div className="flex items-center gap-3">
          <Link href={`/dashboard/compliance/dpdp-export/${latestScan.id}`} target="_blank" className="px-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm font-medium hover:bg-surface-hover hover:border-nanz-400 transition-all flex items-center gap-2 text-text-primary group">
            <FileText className="w-4 h-4 text-nanz-400 group-hover:text-nanz-300 transition-colors" />
            Export DPDP Report (PDF)
          </Link>
        </div>
      </div>

      {/* Aggregate Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {frameworks.map(({ key, data }) => {
          const delta = getDelta(key);
          const color = scoreColor(data.readiness_score);
          const passingCount = data.compliant_controls.length;
          const failingCount = data.violated_clauses.length;

          return (
            <div key={key} className="rounded-card border border-card-border bg-card p-5 hover:bg-card-hover transition-all">
              <div className="flex items-center justify-between mb-4">
                <span className="text-sm font-bold text-text-primary">{data.full_name.split('—')[0].trim()}</span>
                <Shield className="w-4 h-4" style={{ color }} />
              </div>
              
              <div className="flex items-end justify-between mb-2">
                <span className="text-3xl font-bold" style={{ color }}>{data.readiness_score}%</span>
                {delta !== null && (
                  <span className="flex items-center gap-1 text-xs font-medium mb-1">
                    {delta > 0 ? (
                      <><TrendingUp className="w-3.5 h-3.5 text-success" /><span className="text-success">+{delta}%</span></>
                    ) : delta < 0 ? (
                      <><TrendingDown className="w-3.5 h-3.5 text-critical" /><span className="text-critical">{delta}%</span></>
                    ) : (
                      <><Minus className="w-3.5 h-3.5 text-text-muted" /><span className="text-text-muted">0%</span></>
                    )}
                  </span>
                )}
              </div>
              
              <div className="w-full h-1.5 rounded-sm bg-surface-border mb-4 overflow-hidden">
                <div className="h-full rounded-sm transition-all duration-1000" style={{ width: `${data.readiness_score}%`, backgroundColor: color }} />
              </div>
              
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5 text-success">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>{passingCount} Passing</span>
                </div>
                <div className="flex items-center gap-1.5 text-critical">
                  <XCircle className="w-3.5 h-3.5" />
                  <span>{failingCount} Failing</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Detailed DPDP Section (Since DPDP is the main pitch) */}
      <div className="mt-8 rounded-card border border-card-border bg-card overflow-hidden">
        <div className="p-6 border-b border-card-border bg-surface/50">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-text-primary flex items-center gap-2">
              <Shield className="w-5 h-5 text-nanz-400" /> DPDP Act Deep Dive
            </h2>
            <div className="text-sm text-text-secondary">
              Based on {latestScan.domain} scan at {new Date(latestScan.completed_at || latestScan.created_at).toLocaleString()}
            </div>
          </div>
          <p className="text-sm text-text-muted mt-2">{compliance.dpdp.summary}</p>
        </div>
        
        <div className="p-0">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-card-border bg-surface-hover/30">
                <th className="p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">Clause</th>
                <th className="p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">Description</th>
                <th className="p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">Severity</th>
                <th className="p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-card-border">
              {compliance.dpdp.violated_clauses.map((clause: any, i: number) => (
                <tr key={i} className="hover:bg-surface-hover/50 transition-colors">
                  <td className="p-4 align-top whitespace-nowrap">
                    <span className="inline-flex items-center px-2 py-1 rounded bg-surface border border-surface-border text-xs font-medium text-text-primary">
                      {clause.clause_id}
                    </span>
                  </td>
                  <td className="p-4 align-top">
                    <div className="text-sm font-medium text-text-primary mb-1">{clause.clause_title}</div>
                    <div className="text-xs text-text-muted leading-relaxed">{clause.description}</div>
                  </td>
                  <td className="p-4 align-top">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium
                      ${clause.severity === 'CRITICAL' ? 'bg-critical/10 text-critical border border-critical/20' : 
                        clause.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20' : 
                        'bg-blue-500/10 text-blue-500 border border-blue-500/20'}`}>
                      {clause.severity === 'CRITICAL' ? <AlertTriangle className="w-3.5 h-3.5" /> : <Minus className="w-3.5 h-3.5" />}
                      {clause.severity}
                    </span>
                  </td>
                  <td className="p-4 align-top">
                    <Link href={`/report/${latestScan.id}`} className="inline-flex items-center gap-1 text-xs font-semibold text-nanz-400 hover:text-nanz-300">
                      View Fix <ArrowRight className="w-3 h-3" />
                    </Link>
                  </td>
                </tr>
              ))}
              {compliance.dpdp.violated_clauses.length === 0 && (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-sm text-text-muted">
                    <CheckCircle2 className="w-8 h-8 text-success mx-auto mb-3" />
                    No DPDP violations detected.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
