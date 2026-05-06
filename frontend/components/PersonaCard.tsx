'use client';

import { useState } from 'react';
import { Store, Code2, ShieldCheck } from 'lucide-react';

const personas = [
  {
    id: 'business',
    icon: Store,
    tab: 'Small Business Owner',
    pain: "You heard about DPDP fines. You don't know if your site is safe. You don't have an IT team.",
    gets: [
      'DPDP compliance score mapped to exact sections you violate',
      'Plain-English risk explanations — no jargon',
      '₹499 fix-it report with step-by-step remediation',
      'No technical knowledge needed — just paste your URL',
    ],
    cta: 'Check My Site Free',
    ctaHref: '#hero',
  },
  {
    id: 'developer',
    icon: Code2,
    tab: 'Developer / Agency',
    pain: "Your clients ask if their site is secure. You need proof — CVE references, OWASP coverage, tech stack audit.",
    gets: [
      'CVE IDs with EPSS exploit probability scores',
      'SBOM export in CycloneDX and SPDX formats',
      'OWASP Top 10 2021 coverage map for every finding',
      'SCA dependency table with fix commands',
      'Full technology inventory with EOL detection',
    ],
    cta: 'Run Technical Audit',
    ctaHref: '#hero',
  },
  {
    id: 'ciso',
    icon: ShieldCheck,
    tab: 'Security Team / CISO',
    pain: "You need compliance evidence for DPDP/GDPR audits. You need financial risk quantification for your board report.",
    gets: [
      'ALE financial exposure per finding (Annual Loss Expectancy)',
      'Compliance matrix: DPDP + GDPR + PCI DSS + SOC 2',
      'CISA KEV integration — "Actively Exploited" badges',
      'EPSS-enriched risk scores (real exploit probability)',
      'BYOS ingestion: import Semgrep, Snyk, Trivy results',
      'Role-based CISO dashboard with executive summary',
    ],
    cta: 'View Enterprise Features',
    ctaHref: '#features',
  },
];

export default function PersonaCards() {
  const [active, setActive] = useState(0);
  const persona = personas[active];

  return (
    <div>
      {/* Tab Bar */}
      <div className="flex items-center gap-1 p-1 rounded-btn bg-surface border border-surface-border w-fit mx-auto mb-8">
        {personas.map((p, i) => (
          <button
            key={p.id}
            onClick={() => setActive(i)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded text-sm font-medium transition-colors ${
              active === i
                ? 'bg-surface-active text-text-primary'
                : 'text-text-muted hover:text-text-secondary'
            }`}
          >
            <p.icon className="w-4 h-4" />
            <span className="hidden sm:inline">{p.tab}</span>
          </button>
        ))}
      </div>

      {/* Card */}
      <div className="max-w-2xl mx-auto rounded-panel border border-card-border bg-card p-8">
        <div className="flex items-center gap-3 mb-5">
          <div className="w-11 h-11 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center">
            <persona.icon className="w-5 h-5 text-nanz-400" />
          </div>
          <h3 className="text-lg font-semibold text-text-primary">{persona.tab}</h3>
        </div>

        <div className="bg-surface/50 border border-surface-border rounded-card p-4 mb-6">
          <p className="text-sm text-text-secondary italic leading-relaxed">
            &ldquo;{persona.pain}&rdquo;
          </p>
        </div>

        <h4 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-3">What you get</h4>
        <ul className="space-y-2.5 mb-6">
          {persona.gets.map((item) => (
            <li key={item} className="flex items-start gap-2.5 text-sm text-text-secondary">
              <span className="w-1.5 h-1.5 rounded-full bg-nanz-400 mt-1.5 flex-shrink-0" />
              {item}
            </li>
          ))}
        </ul>

        <a
          href={persona.ctaHref}
          className="inline-flex items-center gap-2 px-6 py-3 rounded-btn bg-nanz-gradient text-white text-sm font-semibold hover:opacity-90 transition-opacity"
        >
          {persona.cta}
        </a>
      </div>
    </div>
  );
}
