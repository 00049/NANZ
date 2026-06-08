'use client';

import { useState, useMemo, useEffect } from 'react';
import { Zap, Copy, CheckCircle2, Download, ChevronDown, ChevronUp, ArrowUpDown } from 'lucide-react';
import { FullReport, ASPMReport, RiskItem, SBOMFormat, formatALE } from '@/types';
import { downloadSBOM } from '@/lib/api';
import { normalizeSeverity } from '@/lib/severity';

// ─── Quick Win Card ───────────────────────────────────────────────────────────

function QuickWinCard({ finding, onFix }: { finding: RiskItem; onFix: (f: RiskItem) => void }) {
  const [copied, setCopied] = useState(false);

  const handleCopyStep = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#09090e] border border-blue-900/40 rounded-xl p-4 hover:border-blue-700/50 transition-all">
      <div className="flex items-start gap-3 mb-3">
        <Zap className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-bold text-slate-200 leading-snug mb-1">{finding.title}</h4>
          {finding.ale_reduction_inr !== undefined && finding.ale_reduction_inr > 0 && (
            <div className={`text-xs font-semibold mb-2 ${
              finding.ale_reduction_inr >= 5_000_000 ? 'text-red-400' :
              finding.ale_reduction_inr >= 1_000_000 ? 'text-amber-400' : 'text-blue-400'
            }`}>
              {finding.ale_display || formatALE(finding.ale_reduction_inr)} risk reduced
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-green-950/40 border border-green-800/40 text-green-500 font-medium">
              Easy fix
            </span>
            {finding.estimated_fix_time && (
              <span className="text-[10px] text-slate-600">{finding.estimated_fix_time}</span>
            )}
          </div>
        </div>
      </div>
      <button
        onClick={() => onFix(finding)}
        className="w-full py-2 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-bold transition-colors flex items-center justify-center gap-1.5"
      >
        <Zap className="w-3 h-3" />
        Fix Now — {finding.estimated_fix_time || 'Quick'}
      </button>
    </div>
  );
}

// ─── Tech Group ──────────────────────────────────────────────────────────────

function TechGroup({ tech, findings, onFix }: { tech: string; findings: RiskItem[]; onFix: (f: RiskItem) => void }) {
  const [open, setOpen] = useState(false);
  const hasCritical = findings.some(f => f.severity === 'CRITICAL');

  return (
    <div className={`rounded-xl border ${hasCritical ? 'border-red-800/40' : 'border-slate-800/40'} overflow-hidden`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between p-4 bg-[#09090b] hover:bg-slate-900/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="text-sm font-bold text-slate-200">{tech}</span>
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
            hasCritical ? 'bg-red-950/40 border border-red-800/40 text-red-400' :
            'bg-slate-900/40 border border-slate-700/40 text-slate-500'
          }`}>
            {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </span>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </button>
      {open && (
        <div className="border-t border-slate-800/40 p-4 space-y-3 bg-[#07070a]">
          {findings.map((f, i) => (
            <div key={i} className="flex items-start gap-3 py-2">
              <div className={`w-2 h-2 rounded-full shrink-0 mt-1.5 ${
                normalizeSeverity(f.severity) === 'CRITICAL' ? 'bg-red-500' :
                normalizeSeverity(f.severity) === 'HIGH' ? 'bg-red-400' :
                normalizeSeverity(f.severity) === 'MEDIUM' ? 'bg-amber-400' : 'bg-green-500'
              }`} />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-slate-300 mb-1">{f.title}</div>
                {f.technical_detail && (
                  <p className="text-xs text-slate-500 leading-relaxed mb-2">{f.technical_detail}</p>
                )}
                <button
                  onClick={() => onFix(f)}
                  className="text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors"
                >
                  View fix steps →
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Developer Finding Card ───────────────────────────────────────────────────

function DevFindingCard({ finding, onFix, forceExpand }: { finding: RiskItem; onFix: (f: RiskItem) => void; forceExpand?: boolean }) {
  const [open, setOpen] = useState(finding.severity === 'CRITICAL');
  const [copiedStep, setCopiedStep] = useState<number | null>(null);

  useEffect(() => {
    if (forceExpand !== undefined) {
      setOpen(forceExpand);
    }
  }, [forceExpand]);

  const fixSteps = finding.fix_action
    ? finding.fix_action.split(/\d+\.|•|\n/).filter(s => s.trim().length > 0)
    : [finding.fix_action];

  const copyStep = (step: string, i: number) => {
    navigator.clipboard.writeText(step.trim());
    setCopiedStep(i);
    setTimeout(() => setCopiedStep(null), 2000);
  };

  return (
    <div className={`rounded-xl border p-4 ${
      finding.severity === 'CRITICAL' ? 'bg-[#1a0505] border-red-800/50' :
      normalizeSeverity(finding.severity) === 'HIGH' ? 'bg-[#120505] border-red-900/30' :
      'bg-[#09090b] border-slate-800/40'
    }`}>
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-start justify-between gap-3 text-left mb-1">
        <h4 className="text-sm font-bold text-slate-200">{finding.title}</h4>
        {open ? <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" /> : <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />}
      </button>

      {finding.affected_file && (
        <div className="text-[10px] font-mono text-blue-400 mb-2">📁 {finding.affected_file}</div>
      )}

      {open && (
        <div className="mt-3 space-y-3">
          {finding.technical_detail && (
            <p className="text-xs text-slate-400 leading-relaxed">{finding.technical_detail}</p>
          )}

          <div>
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">Fix Steps</div>
            {fixSteps.map((step, i) => (
              <div key={i} className="flex items-start gap-2 mb-2">
                <span className="shrink-0 w-5 h-5 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-bold text-slate-400">
                  {i + 1}
                </span>
                <p className="flex-1 text-xs text-slate-300 leading-relaxed">{step.trim()}</p>
                <button
                  onClick={() => copyStep(step, i)}
                  className="shrink-0 p-1 rounded text-slate-600 hover:text-slate-300 transition-colors"
                >
                  {copiedStep === i
                    ? <CheckCircle2 className="w-3 h-3 text-green-400" />
                    : <Copy className="w-3 h-3" />}
                </button>
              </div>
            ))}

            <div className="mt-4 p-3 bg-blue-950/20 border border-blue-900/30 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-blue-400 shrink-0" />
                <span className="text-xs text-blue-200 font-medium">Need detailed code snippets or context-aware remediation?</span>
              </div>
              <button onClick={() => onFix(finding)} className="shrink-0 text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 px-3 py-1.5 rounded transition-colors flex items-center gap-1.5 justify-center">
                <Zap className="w-3 h-3" /> Generate AI Fix
              </button>
            </div>
          </div>

          {finding.references && finding.references.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-2 border-t border-slate-800/40">
              {finding.references.slice(0, 3).map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                  className="text-[10px] text-blue-400 hover:underline truncate max-w-[200px]">
                  {ref.replace('https://', '')}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Dependency CVE Table ─────────────────────────────────────────────────────

function DepTable({ findings }: { findings: RiskItem[] }) {
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const depFindings = findings.filter(f => f.cve_id && (f.check_type?.includes('depend') || f.module?.includes('depend') || f.check_domain === 'dependency'));

  if (depFindings.length === 0) return null;

  const inferFixCmd = (f: RiskItem) => {
    const name = f.title.toLowerCase();
    if (name.includes('npm') || name.includes('node') || name.includes('js')) {
      return `npm install ${f.title.split(' ')[0]}@latest`;
    }
    if (name.includes('pip') || name.includes('python')) {
      return `pip install --upgrade ${f.title.split(' ')[0]}`;
    }
    if (name.includes('composer') || name.includes('php')) {
      return `composer update ${f.title.split(' ')[0]}`;
    }
    return 'Update to latest version';
  };

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800/50">
      <table className="w-full text-xs">
        <thead className="bg-[#0d0d10]">
          <tr>
            <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">Package / Finding</th>
            <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">CVE</th>
            <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 cursor-pointer" onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}>
              EPSS <ArrowUpDown className="inline w-2.5 h-2.5 ml-0.5" />
            </th>
            <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">Fix Command</th>
          </tr>
        </thead>
        <tbody>
          {depFindings.map((f, i) => (
            <tr key={i} className="border-t border-slate-800/30 hover:bg-slate-800/20">
              <td className="px-3 py-2.5 font-medium text-slate-300">{f.title}</td>
              <td className="px-3 py-2.5">
                <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noopener noreferrer"
                  className="font-mono text-blue-400 hover:underline text-[10px]">{f.cve_id}</a>
              </td>
              <td className="px-3 py-2.5">
                {f.epss_score !== undefined ? (
                  <span className={f.epss_score >= 0.5 ? 'text-red-400 font-bold' : f.epss_score >= 0.3 ? 'text-amber-400' : 'text-slate-500'}>
                    {(f.epss_score * 100).toFixed(1)}%
                  </span>
                ) : '—'}
              </td>
              <td className="px-3 py-2.5">
                <FixCommandCell cmd={inferFixCmd(f)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FixCommandCell({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <code className="text-[10px] font-mono text-green-400 bg-green-950/20 px-2 py-1 rounded">{cmd}</code>
      <button onClick={() => { navigator.clipboard.writeText(cmd); setCopied(true); setTimeout(() => setCopied(false), 2000); }}>
        {copied ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3 text-slate-600 hover:text-slate-300" />}
      </button>
    </div>
  );
}

// ─── SBOM Download ────────────────────────────────────────────────────────────

function SBOMDownload({ scanId }: { scanId: string }) {
  const [format, setFormat] = useState<SBOMFormat>('cyclonedx');
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const data = await downloadSBOM(scanId, format);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sbom-${scanId}-${format}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert('SBOM generation failed. Please retry.');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="bg-[#09090b] rounded-2xl border border-slate-800/50 p-6">
      <h3 className="text-base font-bold text-slate-200 mb-1 flex items-center gap-2">
        <Download className="w-4 h-4 text-blue-400" />
        Software Bill of Materials (SBOM)
      </h3>
      <p className="text-xs text-slate-500 mb-4">
        Required for SOC 2, DPDP, and supply chain compliance. No payment required.
      </p>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1 bg-slate-900/60 border border-slate-800/60 rounded-lg p-1">
          {(['cyclonedx', 'spdx'] as SBOMFormat[]).map(f => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                format === f ? 'bg-blue-700 text-white' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {f === 'cyclonedx' ? 'CycloneDX 1.4' : 'SPDX 2.3'}
            </button>
          ))}
        </div>
        <button
          onClick={handleDownload}
          disabled={downloading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-700 hover:bg-blue-600 disabled:opacity-50 text-white text-xs font-bold transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          {downloading ? 'Generating…' : 'Download SBOM'}
        </button>
      </div>
    </div>
  );
}

// ─── Main DeveloperView ───────────────────────────────────────────────────────

interface DeveloperViewProps {
  report: FullReport;
  aspmData?: ASPMReport;
  onFixClick?: (finding: RiskItem) => void;
}

export default function DeveloperView({ report, aspmData, onFixClick }: DeveloperViewProps) {
  const [forceExpandAll, setForceExpandAll] = useState<boolean>(false);

  const allFindings: RiskItem[] = useMemo(() => [
    ...(report.critical_risks || []),
    ...(report.high_risks || []),
    ...(report.medium_risks || []),
    ...(report.low_risks || []),
    ...(report.findings || report.risk_items || []),
  ], [report]);

  const handleFix = (f: RiskItem) => onFixClick?.(f);

  // Quick wins: Easy + high ALE
  const quickWins = useMemo(() =>
    [...allFindings]
      .filter(f => f.fix_difficulty === 'Easy')
      .sort((a, b) => (b.ale_reduction_inr || 0) - (a.ale_reduction_inr || 0))
      .slice(0, 6),
    [allFindings]
  );

  // Group by tech
  const techGroups = useMemo(() => {
    const groups: Record<string, RiskItem[]> = {};
    for (const f of allFindings) {
      const tech = f.check_domain || f.module || 'General';
      const label = tech.replace(/_check$|_security$/, '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      if (!groups[label]) groups[label] = [];
      groups[label].push(f);
    }
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [allFindings]);

  return (
    <div className="space-y-10">

      {/* Section 1 — Quick Wins */}
      {quickWins.length > 0 && (
        <section>
          <h2 className="text-xl font-black text-slate-200 mb-1 flex items-center gap-2">
            <Zap className="w-5 h-5 text-blue-400" />
            Fix These First
          </h2>
          <p className="text-sm text-slate-500 mb-5">Most financial impact for least developer effort.</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {quickWins.map((f, i) => <QuickWinCard key={i} finding={f} onFix={handleFix} />)}
          </div>
        </section>
      )}

      {/* Section 2 — By Technology */}
      <section>
        <h2 className="text-xl font-black text-slate-200 mb-5">Findings by Technology</h2>
        <div className="space-y-2">
          {techGroups.map(([tech, findings]) => (
            <TechGroup key={tech} tech={tech} findings={findings} onFix={handleFix} />
          ))}
        </div>
      </section>

      {/* Section 3 — All Findings with Code Context */}
      <section>
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-xl font-black text-slate-200">
            All Findings — Code Context
            <span className="ml-3 text-sm font-normal text-slate-500">({allFindings.length} total)</span>
          </h2>
          <button
            onClick={() => setForceExpandAll(prev => !prev)}
            className="text-xs font-semibold text-slate-400 hover:text-slate-200 transition-colors bg-slate-900/50 px-3 py-1.5 rounded-lg border border-slate-800"
          >
            {forceExpandAll ? 'Collapse All' : 'Expand All'}
          </button>
        </div>
        <div className="space-y-3">
          {allFindings
            .filter(f => normalizeSeverity(f.severity) === 'CRITICAL' || normalizeSeverity(f.severity) === 'HIGH')
            .map((f, i) => <DevFindingCard key={i} finding={f} onFix={handleFix} forceExpand={forceExpandAll} />)}
          {allFindings
            .filter(f => normalizeSeverity(f.severity) !== 'CRITICAL' && normalizeSeverity(f.severity) !== 'HIGH')
            .map((f, i) => <DevFindingCard key={i} finding={f} onFix={handleFix} forceExpand={forceExpandAll} />)}
        </div>
      </section>

      {/* Section 4 — Dependency CVE Table */}
      <section>
        <h2 className="text-xl font-black text-slate-200 mb-5">Dependency Vulnerabilities</h2>
        <DepTable findings={allFindings} />
      </section>

      {/* Section 5 — SBOM */}
      <section>
        <SBOMDownload scanId={report.scan_id} />
      </section>
    </div>
  );
}
