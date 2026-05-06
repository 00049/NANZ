'use client';

import { useState } from 'react';
import { BarChart3, Code2, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';

const tabs = [
  { id: 'ciso', label: 'Business Owner / CISO', icon: BarChart3 },
  { id: 'dev', label: 'Developer View', icon: Code2 },
  { id: 'compliance', label: 'Compliance View', icon: ShieldCheck },
];

export default function InteractiveReportPreview() {
  const [active, setActive] = useState(0);

  return (
    <div>
      {/* Tab Bar */}
      <div className="flex items-center gap-1 p-1 rounded-btn bg-surface border border-surface-border w-fit mx-auto mb-8">
        {tabs.map((tab, i) => (
          <button
            key={tab.id}
            onClick={() => setActive(i)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded text-sm font-medium transition-colors ${
              active === i
                ? 'bg-surface-active text-text-primary'
                : 'text-text-muted hover:text-text-secondary'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            <span className="hidden sm:inline">{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto rounded-panel border border-card-border bg-card p-6 md:p-8 nanz-glow-sm">

        {/* CISO View */}
        {active === 0 && (
          <div className="space-y-6">
            {/* Score Ring Mock */}
            <div className="flex flex-col sm:flex-row items-center gap-8">
              <div className="relative w-36 h-36 flex-shrink-0">
                <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                  <circle cx="60" cy="60" r="52" fill="none" stroke="#1E1E24" strokeWidth="8" />
                  <circle cx="60" cy="60" r="52" fill="none" stroke="url(#scoreGrad)" strokeWidth="8"
                    strokeDasharray={`${(38 / 100) * 327} 327`} strokeLinecap="round" />
                  <defs><linearGradient id="scoreGrad"><stop stopColor="#FF6B6B" /><stop offset="1" stopColor="#FFB84D" /></linearGradient></defs>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-bold text-high">38</span>
                  <span className="text-xs text-text-muted">/ 100</span>
                </div>
              </div>
              <div className="flex-1 space-y-3">
                <div className="rounded-card border border-high/20 bg-high/5 p-4">
                  <div className="text-xs text-text-muted mb-1">Total Financial Exposure</div>
                  <div className="text-xl font-bold text-high">₹4.2 Crore/year</div>
                  <div className="text-xs text-text-secondary mt-0.5">Across 14 high-impact findings</div>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <div className="rounded-btn bg-surface p-3 border border-surface-border text-center">
                    <div className="text-lg font-bold text-critical">3</div>
                    <div className="text-[10px] text-text-muted">Critical</div>
                  </div>
                  <div className="rounded-btn bg-surface p-3 border border-surface-border text-center">
                    <div className="text-lg font-bold text-high">7</div>
                    <div className="text-[10px] text-text-muted">High</div>
                  </div>
                  <div className="rounded-btn bg-surface p-3 border border-surface-border text-center">
                    <div className="text-lg font-bold text-medium">12</div>
                    <div className="text-[10px] text-text-muted">Medium</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Top Findings */}
            <div>
              <h4 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-3">Top 3 Risk Findings</h4>
              {[
                { sev: 'CRITICAL', title: 'DPDP S.8(4) — No encryption on data collection forms', ale: '₹1.8 Cr/yr' },
                { sev: 'HIGH', title: 'Missing HSTS — downgrade attacks possible', ale: '₹42 lakh/yr' },
                { sev: 'HIGH', title: 'DMARC p=none — anyone can spoof your domain emails', ale: '₹28 lakh/yr' },
              ].map((f) => (
                <div key={f.title} className="flex items-start gap-3 py-3 border-b border-surface-border last:border-0">
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase mt-0.5 ${f.sev === 'CRITICAL' ? 'bg-critical/20 text-critical' : 'bg-high/20 text-high'}`}>{f.sev}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-text-primary font-medium">{f.title}</p>
                    <p className="text-xs text-text-muted mt-0.5">Annual Loss Expectancy: <span className="text-high font-semibold">{f.ale}</span></p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Developer View */}
        {active === 1 && (
          <div className="space-y-6">
            {/* Tech Inventory */}
            <div>
              <h4 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-3">Technology Inventory</h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {['React 18.2.0', 'Next.js 14.1', 'nginx/1.24', 'Node.js 20.x', 'jQuery 3.5.1 ⚠️', 'Bootstrap 5.3', 'Cloudflare CDN', 'Google Analytics'].map((t) => (
                  <div key={t} className="rounded-btn bg-surface border border-surface-border px-3 py-2 text-xs text-text-secondary font-mono">{t}</div>
                ))}
              </div>
            </div>

            {/* CVE Table */}
            <div>
              <h4 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-3">Dependency Vulnerabilities</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-surface-border">
                      <th className="text-left py-2 text-text-muted font-medium">CVE</th>
                      <th className="text-left py-2 text-text-muted font-medium">Package</th>
                      <th className="text-left py-2 text-text-muted font-medium">EPSS</th>
                      <th className="text-left py-2 text-text-muted font-medium">Fix</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { cve: 'CVE-2024-21538', pkg: 'jQuery 3.5.1', epss: '0.72', fix: 'Upgrade to 3.7.1' },
                      { cve: 'CVE-2023-44487', pkg: 'nginx/1.24', epss: '0.91', fix: 'Upgrade to 1.25.3' },
                      { cve: 'CVE-2024-29041', pkg: 'express 4.18', epss: '0.34', fix: 'Upgrade to 4.19.2' },
                    ].map((r) => (
                      <tr key={r.cve} className="border-b border-surface-border/50">
                        <td className="py-2.5 font-mono text-nanz-400">{r.cve}</td>
                        <td className="py-2.5 text-text-secondary">{r.pkg}</td>
                        <td className="py-2.5"><span className={`font-semibold ${parseFloat(r.epss) > 0.5 ? 'text-critical' : 'text-medium'}`}>{r.epss}</span></td>
                        <td className="py-2.5 text-text-muted">{r.fix}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Fix Command */}
            <div className="rounded-card bg-surface border border-surface-border p-4">
              <div className="text-xs text-text-muted mb-2">Quick fix command:</div>
              <code className="text-xs font-mono text-nanz-400">npm update jquery@3.7.1 express@4.19.2</code>
            </div>
          </div>
        )}

        {/* Compliance View */}
        {active === 2 && (
          <div className="space-y-6">
            {/* Compliance Scores */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { name: 'DPDP', score: 34, color: 'text-high' },
                { name: 'GDPR', score: 52, color: 'text-medium' },
                { name: 'PCI DSS', score: 68, color: 'text-medium' },
                { name: 'SOC 2', score: 45, color: 'text-high' },
              ].map((c) => (
                <div key={c.name} className="rounded-card bg-surface border border-surface-border p-4 text-center">
                  <div className="text-xs text-text-muted mb-1">{c.name}</div>
                  <div className={`text-2xl font-bold ${c.color}`}>{c.score}%</div>
                </div>
              ))}
            </div>

            {/* DPDP Violations */}
            <div>
              <h4 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-3">DPDP Act Violations Found</h4>
              {[
                { section: 'S.8(4)', violation: 'Personal data transmitted without encryption', penalty: '₹250 Crore' },
                { section: 'S.8(6)', violation: '3 employee emails found in breach databases', penalty: '₹200 Crore' },
                { section: 'S.4', violation: 'No visible consent mechanism on data collection forms', penalty: '₹50 Crore' },
              ].map((v) => (
                <div key={v.section} className="flex items-start gap-3 py-3 border-b border-surface-border last:border-0">
                  <AlertTriangle className="w-4 h-4 text-high flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs font-bold text-high">{v.section}</span>
                      <span className="text-sm text-text-primary font-medium">{v.violation}</span>
                    </div>
                    <p className="text-xs text-text-muted">Max penalty: <span className="text-high font-semibold">{v.penalty}</span></p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
