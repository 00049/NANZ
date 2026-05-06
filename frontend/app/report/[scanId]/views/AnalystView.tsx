'use client';

import { useState, useMemo } from 'react';
import { ArrowRight, Shield, Zap, ChevronDown, ChevronUp, AlertTriangle, CheckCircle2, XCircle, MinusCircle } from 'lucide-react';
import { motion } from 'framer-motion';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { FullReport, ASPMReport, RiskItem, OWASPCategory } from '@/types';

// ─── EPSS Distribution Chart ──────────────────────────────────────────────────

function EPSSDistributionChart({ findings }: { findings: RiskItem[] }) {
  const enriched = findings.filter(f => f.epss_score !== undefined);
  if (enriched.length === 0) return null;

  const data = [
    { name: 'Critical (≥0.5)', value: enriched.filter(f => (f.epss_score || 0) >= 0.5).length, color: '#dc2626' },
    { name: 'High (0.3–0.5)', value: enriched.filter(f => (f.epss_score || 0) >= 0.3 && (f.epss_score || 0) < 0.5).length, color: '#f59e0b' },
    { name: 'Low (<0.3)', value: enriched.filter(f => (f.epss_score || 0) < 0.3).length, color: '#3b82f6' },
  ].filter(d => d.value > 0);

  return (
    <div className="bg-[#09090b] rounded-2xl border border-slate-800/50 p-5">
      <h3 className="text-sm font-bold text-slate-300 mb-4">EPSS Exploit Probability Distribution</h3>
      <div className="flex items-center gap-6">
        <ResponsiveContainer width={140} height={140}>
          <PieChart>
            <Pie data={data} cx="50%" cy="50%" innerRadius={40} outerRadius={65} paddingAngle={3} dataKey="value">
              {data.map((entry, i) => <Cell key={i} fill={entry.color} />)}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#0d0d10', border: '1px solid #1e293b', borderRadius: 8, fontSize: 11 }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="space-y-2">
          {data.map((d, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: d.color }} />
              <span className="text-slate-400">{d.name}</span>
              <span className="font-bold text-slate-200 ml-auto pl-4">{d.value}</span>
            </div>
          ))}
          <div className="pt-1 border-t border-slate-800/50 text-[10px] text-slate-600">
            {enriched.length} of {findings.length} findings have EPSS data
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Attack Path Card ─────────────────────────────────────────────────────────

function AttackPathCard({ finding }: { finding: RiskItem }) {
  const steps = [
    { label: 'Entry Point', value: 'Public Internet', icon: '🌐' },
    { label: 'Vulnerability', value: finding.title, icon: '⚠️' },
    { label: 'Impact', value: finding.business_impact.split('.')[0], icon: '💥' },
  ];

  return (
    <div className="bg-[#150505] border border-red-900/40 rounded-xl p-5">
      <div className="text-[10px] font-bold uppercase tracking-widest text-red-500 mb-4">
        🚨 Attack Path — {finding.title}
      </div>
      <div className="flex items-stretch gap-2 overflow-x-auto pb-2">
        {steps.map((step, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.15 }}
            className="flex items-center gap-2"
          >
            <div className="shrink-0 bg-red-950/60 border border-red-800/40 rounded-xl p-3 min-w-[120px]">
              <div className="text-lg mb-1">{step.icon}</div>
              <div className="text-[10px] font-bold uppercase tracking-widest text-red-500 mb-1">{step.label}</div>
              <div className="text-xs text-slate-300 leading-snug">{step.value}</div>
            </div>
            {i < steps.length - 1 && (
              <ArrowRight className="w-4 h-4 text-red-600 shrink-0" />
            )}
          </motion.div>
        ))}
      </div>
    </div>
  );
}

// ─── Analyst Findings Table ───────────────────────────────────────────────────

type SortKey = 'epss_score' | 'cvss_score' | 'ale_reduction_inr' | 'severity';

function AnalystFindingsTable({ findings }: { findings: RiskItem[] }) {
  const [sortKey, setSortKey] = useState<SortKey>('epss_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [search, setSearch] = useState('');

  const sorted = useMemo(() => {
    let list = [...findings];
    if (severityFilter !== 'ALL') list = list.filter(f => f.severity === severityFilter);
    if (search) list = list.filter(f =>
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.cve_id?.toLowerCase().includes(search.toLowerCase())
    );
    list.sort((a, b) => {
      const av = (a[sortKey] as number) || 0;
      const bv = (b[sortKey] as number) || 0;
      return sortDir === 'desc' ? bv - av : av - bv;
    });
    return list;
  }, [findings, sortKey, sortDir, severityFilter, search]);

  const toggle = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  const SortTh = ({ k, label }: { k: SortKey; label: string }) => (
    <th
      className="px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 cursor-pointer hover:text-slate-300 whitespace-nowrap"
      onClick={() => toggle(k)}
    >
      {label} {sortKey === k ? (sortDir === 'desc' ? '↓' : '↑') : ''}
    </th>
  );

  const SEVERITY_COLORS: Record<string, string> = {
    CRITICAL: 'text-red-400', RED: 'text-orange-400', AMBER: 'text-amber-400',
    GREEN: 'text-green-500', INFO: 'text-slate-500',
  };

  return (
    <div>
      {/* Controls */}
      <div className="flex flex-wrap gap-3 mb-4">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search findings, CVEs…"
          className="flex-1 min-w-[180px] bg-[#0a0a0d] border border-slate-800/60 rounded-lg px-3 py-1.5 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-blue-700"
        />
        {['ALL', 'CRITICAL', 'RED', 'AMBER', 'GREEN'].map(s => (
          <button
            key={s}
            onClick={() => setSeverityFilter(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              severityFilter === s
                ? 'bg-blue-700 text-white'
                : 'bg-slate-900/50 border border-slate-800/50 text-slate-500 hover:text-slate-300'
            }`}
          >
            {s === 'RED' ? 'HIGH' : s === 'AMBER' ? 'MED' : s}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800/50">
        <table className="w-full text-xs">
          <thead className="bg-[#0d0d10]">
            <tr>
              <th className="px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">Finding</th>
              <SortTh k="severity" label="Severity" />
              <SortTh k="epss_score" label="EPSS" />
              <SortTh k="cvss_score" label="CVSS" />
              <SortTh k="ale_reduction_inr" label="ALE Reduced" />
              <th className="px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">CVE</th>
              <th className="px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">KEV</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f, i) => (
              <tr key={i} className="border-t border-slate-800/30 hover:bg-slate-800/20 transition-colors">
                <td className="px-3 py-2.5 max-w-[280px]">
                  <div className="font-medium text-slate-300 truncate">{f.title}</div>
                  {f.module && <div className="text-[10px] text-slate-600 font-mono">{f.module}</div>}
                </td>
                <td className="px-3 py-2.5">
                  <span className={`font-bold ${SEVERITY_COLORS[f.severity] || 'text-slate-500'}`}>
                    {f.severity === 'RED' ? 'HIGH' : f.severity === 'AMBER' ? 'MED' : f.severity}
                  </span>
                </td>
                <td className="px-3 py-2.5">
                  {f.epss_score !== undefined ? (
                    <span className={`font-mono font-bold ${
                      f.epss_score >= 0.5 ? 'text-red-400' :
                      f.epss_score >= 0.3 ? 'text-amber-400' : 'text-slate-500'
                    }`}>
                      {(f.epss_score * 100).toFixed(1)}%
                    </span>
                  ) : <span className="text-slate-700">—</span>}
                </td>
                <td className="px-3 py-2.5 font-mono text-slate-400">
                  {f.cvss_score?.toFixed(1) || '—'}
                </td>
                <td className="px-3 py-2.5">
                  {f.ale_reduction_inr ? (
                    <span className={f.ale_reduction_inr >= 5_000_000 ? 'text-red-400 font-bold' :
                      f.ale_reduction_inr >= 1_000_000 ? 'text-amber-400' : 'text-blue-400'}>
                      {f.ale_display || '₹'+f.ale_reduction_inr.toLocaleString('en-IN')}
                    </span>
                  ) : <span className="text-slate-700">—</span>}
                </td>
                <td className="px-3 py-2.5">
                  {f.cve_id ? (
                    <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noopener noreferrer"
                      className="font-mono text-blue-400 hover:underline text-[10px]">{f.cve_id}</a>
                  ) : <span className="text-slate-700">—</span>}
                </td>
                <td className="px-3 py-2.5">
                  {f.cisa_kev ? (
                    <span className="text-xs text-red-400 font-bold">🚨 YES</span>
                  ) : <span className="text-slate-700 text-[10px]">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {sorted.length === 0 && (
          <div className="text-center py-8 text-slate-600 text-sm">No findings match your filter.</div>
        )}
      </div>
    </div>
  );
}

// ─── OWASP Grid ───────────────────────────────────────────────────────────────

function OWASPGrid({ categories }: { categories: Record<string, OWASPCategory> | OWASPCategory[] }) {
  const cats: OWASPCategory[] = Array.isArray(categories) ? categories : Object.values(categories);
  if (!cats.length) return null;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
      {cats.map(cat => {
        const status = cat.status || (cat.findings_count > 0 ? 'PARTIAL' : 'TESTED');
        const bg =
          status === 'NOT_TESTED' ? 'bg-slate-900/30 border-slate-800/30' :
          cat.findings_count === 0 ? 'bg-green-950/20 border-green-900/30' :
          cat.findings_count > 0 && (cat.highest_severity === 'CRITICAL' || cat.highest_severity === 'RED')
            ? 'bg-red-950/30 border-red-800/40'
            : 'bg-amber-950/20 border-amber-800/30';
        const icon =
          status === 'NOT_TESTED' ? <MinusCircle className="w-3.5 h-3.5 text-slate-600" /> :
          cat.findings_count === 0 ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> :
          <XCircle className="w-3.5 h-3.5 text-red-400" />;

        return (
          <div key={cat.id} className={`rounded-xl border p-3 ${bg}`}>
            <div className="flex items-center gap-1.5 mb-1.5">{icon}
              <span className="text-[10px] font-bold text-blue-400">{cat.id}</span>
            </div>
            <div className="text-[11px] font-semibold text-slate-300 leading-snug mb-1">{cat.name}</div>
            <div className="text-[10px] text-slate-500">
              {status === 'NOT_TESTED' ? 'Not tested' :
               cat.findings_count > 0 ? `${cat.findings_count} finding${cat.findings_count !== 1 ? 's' : ''}` : 'Clean'}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main AnalystView ─────────────────────────────────────────────────────────

interface AnalystViewProps {
  report: FullReport;
  aspmData?: ASPMReport;
  enterpriseData?: any;
}

export default function AnalystView({ report, aspmData, enterpriseData }: AnalystViewProps) {
  const allFindings: RiskItem[] = [
    ...(report.critical_risks || []),
    ...(report.high_risks || []),
    ...(report.medium_risks || []),
    ...(report.low_risks || []),
    ...(report.findings || report.risk_items || []),
  ];

  const criticalFindings = allFindings.filter(f => f.severity === 'CRITICAL');
  const kevFindings = allFindings.filter(f => f.cisa_kev);

  const owaspCategories = aspmData?.owasp_top10_structured?.categories ||
    (aspmData?.owasp_coverage ? Object.fromEntries((aspmData.owasp_coverage as any[]).map(c => [c.id, c])) : {});

  const llmCategories = aspmData?.owasp_llm_structured?.categories;
  const llmDetected = aspmData?.owasp_llm_structured?.llm_detected;

  // Module status from enterprise data
  const modules = enterpriseData?.modules_tested || aspmData?.modules_tested || [];
  const modulesFailed = enterpriseData?.modules_failed || [];

  return (
    <div className="space-y-10">

      {/* Section 1 — Threat Intel */}
      <section>
        <h2 className="text-xl font-black text-slate-200 mb-5">Threat Intelligence</h2>
        <div className="grid md:grid-cols-2 gap-4 mb-6">
          <EPSSDistributionChart findings={allFindings} />

          {/* KEV findings */}
          <div className="bg-[#09090b] rounded-2xl border border-slate-800/50 p-5">
            <h3 className="text-sm font-bold text-slate-300 mb-4">
              🚨 CISA KEV Findings
              <span className="ml-2 text-[10px] font-normal text-slate-600">(Actively Exploited in Wild)</span>
            </h3>
            {kevFindings.length === 0 ? (
              <div className="flex items-center gap-2 text-green-400 text-sm">
                <CheckCircle2 className="w-4 h-4" />
                No CISA KEV findings detected
              </div>
            ) : (
              <div className="space-y-2">
                {kevFindings.map((f, i) => (
                  <div key={i} className="flex items-start gap-2 p-2.5 bg-red-950/30 rounded-lg border border-red-800/40">
                    <Zap className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-semibold text-red-300">{f.title}</div>
                      {f.cve_id && <div className="text-[10px] font-mono text-slate-500">{f.cve_id}</div>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Section 2 — Attack Paths */}
      {criticalFindings.length > 0 && (
        <section>
          <h2 className="text-xl font-black text-slate-200 mb-2">Attack Path Analysis</h2>
          <p className="text-sm text-slate-500 mb-5">One visualized attack chain per critical finding.</p>
          <div className="space-y-4">
            {criticalFindings.slice(0, 3).map((f, i) => (
              <AttackPathCard key={i} finding={f} />
            ))}
          </div>
        </section>
      )}

      {/* Section 3 — All Findings Table */}
      <section>
        <h2 className="text-xl font-black text-slate-200 mb-5">
          All Findings
          <span className="ml-3 text-sm font-normal text-slate-500">({allFindings.length} total)</span>
        </h2>
        <AnalystFindingsTable findings={allFindings} />
      </section>

      {/* Section 5 — OWASP Coverage */}
      <section>
        <h2 className="text-xl font-black text-slate-200 mb-5">OWASP Top 10 — 2021 Coverage</h2>
        {Object.keys(owaspCategories).length > 0 ? (
          <OWASPGrid categories={owaspCategories} />
        ) : (
          aspmData?.owasp_coverage && Array.isArray(aspmData.owasp_coverage) ? (
            <OWASPGrid categories={aspmData.owasp_coverage} />
          ) : (
            <p className="text-slate-600 text-sm">OWASP coverage data unavailable.</p>
          )
        )}

        {llmDetected && llmCategories && Object.keys(llmCategories).length > 0 && (
          <div className="mt-8">
            <h3 className="text-base font-bold text-slate-300 mb-4 flex items-center gap-2">
              🤖 OWASP LLM Top 10 — 2025
              <span className="text-xs font-normal text-blue-400 px-2 py-0.5 rounded-full bg-blue-950/40 border border-blue-800/40">LLM endpoints detected</span>
            </h3>
            <OWASPGrid categories={llmCategories} />
          </div>
        )}
      </section>
    </div>
  );
}
