'use client';

import { useState } from 'react';
import {
  Shield, Globe, Server, Lock, Eye, Wifi, Code2, FileSearch,
  Cookie, Bug, AlertTriangle, Cpu, BarChart3, Brain, Fingerprint,
  Search, Network, Database, Boxes, KeyRound, Bot, BookOpen,
  Radar, Activity, FileCode, Container, Layers, Gauge, ShieldAlert,
  Zap, CheckCircle2
} from 'lucide-react';

// ─── TAB 1: Security Checks ───
const moduleGroups = [
  {
    group: 'Infrastructure',
    modules: [
      { icon: Lock, name: 'SSL/TLS Deep Analysis', desc: 'SSLyze, cipher suites, Heartbleed, ROBOT, CT logs' },
      { icon: Globe, name: 'DNS & Email Security', desc: 'SPF, DMARC, DKIM, DNSSEC, CAA, zone transfer' },
      { icon: Server, name: 'Port & Service Scan', desc: '23 ports, Shodan + Nmap, service fingerprinting' },
      { icon: Shield, name: 'HTTP Security Headers', desc: '13 headers, A+ to F grade, redirect chain analysis' },
      { icon: Wifi, name: 'WAF & CDN Detection', desc: 'Cloudflare, AWS, Akamai, Imperva, Sucuri detection' },
    ]
  },
  {
    group: 'Web Application',
    modules: [
      { icon: FileSearch, name: 'Web Application Security', desc: 'Observatory, Nuclei, .env/.git exposure' },
      { icon: Network, name: 'CORS Misconfiguration', desc: 'Wildcard, reflected origin, null origin bypass' },
      { icon: Bug, name: 'HTTP Methods Audit', desc: 'TRACE, PUT/DELETE exposure, XST confirmation' },
      { icon: Search, name: 'GraphQL Security', desc: 'Introspection, depth attacks, batch/alias abuse' },
      { icon: Eye, name: 'Cloud Storage Exposure', desc: 'Public S3 buckets, Azure Blob, GCP enumeration' },
    ]
  },
  {
    group: 'Code & Dependencies',
    modules: [
      { icon: Code2, name: 'JavaScript Source Analysis', desc: 'Hardcoded secrets, source maps, debug code' },
      { icon: Layers, name: 'Software Composition (SCA)', desc: 'Dependency CVEs, SRI integrity, Magecart detect' },
      { icon: Container, name: 'IaC & Container Exposure', desc: 'Terraform state, Dockerfile, K8s manifest leaks' },
      { icon: FileCode, name: 'Crawl Intelligence', desc: 'robots.txt secrets, sitemap IDOR, security.txt' },
      { icon: Gauge, name: 'Performance & DDoS', desc: 'TTFB, CDN presence, open DNS resolver detection' },
    ]
  },
  {
    group: 'Identity & Auth',
    modules: [
      { icon: KeyRound, name: 'JWT & OAuth/OIDC Audit', desc: 'Algorithm confusion, none alg, PKCE enforcement' },
      { icon: Cookie, name: 'Cookie & Session Security', desc: 'HttpOnly, Secure, SameSite, session fixation' },
      { icon: ShieldAlert, name: 'API Security (OWASP API)', desc: 'BOLA, mass assignment, shadow APIs, OpenAPI spec' },
      { icon: Fingerprint, name: 'Business Logic Analysis', desc: 'IDOR, workflow bypass, race conditions, tampering' },
    ]
  },
  {
    group: 'AI & Intelligence',
    modules: [
      { icon: Bot, name: 'LLM / AI Security', desc: 'OWASP LLM 2025 Top 10, prompt injection, agency' },
      { icon: Radar, name: 'OAST Detection', desc: 'Blind SSRF, header injection, Log4Shell detection' },
      { icon: Activity, name: 'IAST Behavioral Analysis', desc: 'Stack traces, timing anomalies, error verbosity' },
      { icon: Database, name: 'CVE Intelligence', desc: 'NVD lookup, EPSS scores, CISA KEV cross-reference' },
      { icon: Cpu, name: 'Technology Inventory', desc: 'Full stack map, EOL detection, trackers, payments' },
    ]
  },
  {
    group: 'Brand & Reputation',
    modules: [
      { icon: AlertTriangle, name: 'Reputation & Threat Intel', desc: 'VirusTotal 70+ vendors, Safe Browsing, LeakIX' },
      { icon: Boxes, name: 'CMS & Plugin Security', desc: 'WPScan, 8 CMS types, plugin CVEs, outdated core' },
      { icon: Brain, name: 'Brand Protection', desc: 'Typosquatting, IDN homoglyph, dark web mentions' },
      { icon: Globe, name: 'Infrastructure & Subdomain', desc: 'Subfinder, subdomain takeover, IP reputation' },
      { icon: BookOpen, name: 'Email Security Deep Scan', desc: 'SPF strictness, DMARC enforcement, MX STARTTLS' },
    ]
  },
];

// ─── TAB 2: Intelligence Engine ───
const intelligenceCards = [
  {
    icon: BarChart3,
    title: 'EPSS-Enriched Risk Scores',
    desc: "We don't just give you a severity label. Every CVE finding is enriched with the EPSS score — the real-world probability that it will be exploited in the next 30 days.",
    badge: 'EPSS 0.87 — Actively Exploited',
    badgeColor: 'bg-critical/10 text-critical border-critical/20',
  },
  {
    icon: Shield,
    title: 'CISA KEV Integration',
    desc: 'We cross-reference every finding against the CISA Known Exploited Vulnerabilities catalog. If attackers are actively using a vulnerability right now, you\'ll know.',
    badge: '🚨 In CISA KEV Catalog',
    badgeColor: 'bg-high/10 text-high border-high/20',
  },
  {
    icon: Gauge,
    title: 'Financial Quantification (ALE)',
    desc: "Every finding shows the estimated Annual Loss Expectancy — how much a breach could cost your business per year. Based on DPDP penalty exposure and industry averages.",
    badge: 'Fixing this prevents ~₹38 lakh/year',
    badgeColor: 'bg-success/10 text-success border-success/20',
  },
  {
    icon: Radar,
    title: 'Out-of-Band Detection (OAST)',
    desc: "We deploy out-of-band listeners to catch blind vulnerabilities that other scanners miss — like SSRF that only reveals itself through DNS callbacks.",
    badge: '⚡ Active blind detection — running during scan',
    badgeColor: 'bg-nanz-600/10 text-nanz-400 border-nanz-600/20',
  },
];

// ─── TAB 3: Compliance ───
const complianceBadges = [
  { name: 'DPDP Act 2023 (India)', desc: 'Section-by-section violation mapping with penalty exposure', flag: '🇮🇳' },
  { name: 'GDPR (EU)', desc: 'Art. 25, 32, 33 technical controls assessment', flag: '🇪🇺' },
  { name: 'PCI DSS v4.0', desc: 'Payment security requirements for card data', flag: '💳' },
  { name: 'SOC 2 Type II', desc: 'Trust service criteria mapping and evidence', flag: '🔒' },
  { name: 'OWASP Top 10 2021', desc: 'All 10 categories with finding coverage map', flag: '🛡️' },
  { name: 'OWASP LLM 2025', desc: 'All 10 AI/LLM risk categories — unique to ShieldCheck', flag: '🤖' },
];

// ─── TAB 4: AI & LLM ───
const llmRisks = [
  { id: 'LLM01', name: 'Prompt Injection', desc: 'Entry points where users can override AI instructions' },
  { id: 'LLM06', name: 'Excessive Agency', desc: 'AI taking unauthorized actions without confirmation' },
  { id: 'LLM07', name: 'System Prompt Leakage', desc: 'Exposing internal instructions to end users' },
  { id: 'LLM10', name: 'Unbounded Consumption', desc: 'Cost explosion risk from unthrottled AI API calls' },
];

const tabs = ['Security Checks (29)', 'Intelligence Engine', 'Compliance', 'AI & LLM Security'];

export default function FeatureTabPanel() {
  const [activeTab, setActiveTab] = useState(0);

  return (
    <div>
      {/* Tab Navigation */}
      <div className="flex flex-wrap items-center gap-1 p-1 rounded-btn bg-surface border border-surface-border w-fit mx-auto mb-10">
        {tabs.map((tab, i) => (
          <button
            key={tab}
            onClick={() => setActiveTab(i)}
            className={`px-4 py-2.5 rounded text-sm font-medium transition-colors whitespace-nowrap ${
              activeTab === i
                ? 'bg-surface-active text-text-primary'
                : 'text-text-muted hover:text-text-secondary'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* TAB 1: Security Checks */}
      {activeTab === 0 && (
        <div className="space-y-8">
          {moduleGroups.map((grp) => (
            <div key={grp.group}>
              <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-3">{grp.group}</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {grp.modules.map((mod) => (
                  <div key={mod.name} className="rounded-card border border-card-border bg-card p-4 hover:border-surface-border-light transition-colors group">
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center flex-shrink-0">
                        <mod.icon className="w-4 h-4 text-nanz-400" />
                      </div>
                      <div className="min-w-0">
                        <h4 className="text-sm font-semibold text-text-primary leading-tight">{mod.name}</h4>
                        <p className="text-xs text-text-muted mt-0.5 leading-relaxed">{mod.desc}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 2: Intelligence Engine */}
      {activeTab === 1 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-4xl mx-auto">
          {intelligenceCards.map((card) => (
            <div key={card.title} className="rounded-panel border border-card-border bg-card p-6">
              <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center mb-4">
                <card.icon className="w-5 h-5 text-nanz-400" />
              </div>
              <h3 className="text-base font-semibold text-text-primary mb-2">{card.title}</h3>
              <p className="text-sm text-text-secondary leading-relaxed mb-4">{card.desc}</p>
              <div className={`inline-block text-xs font-semibold px-3 py-1.5 rounded-full border ${card.badgeColor}`}>
                {card.badge}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 3: Compliance */}
      {activeTab === 2 && (
        <div className="max-w-4xl mx-auto">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
            {complianceBadges.map((badge) => (
              <div key={badge.name} className="rounded-card border border-card-border bg-card p-5 text-center hover:border-surface-border-light transition-colors">
                <div className="text-2xl mb-2">{badge.flag}</div>
                <h4 className="text-sm font-semibold text-text-primary mb-1">{badge.name}</h4>
                <p className="text-xs text-text-muted leading-relaxed">{badge.desc}</p>
              </div>
            ))}
          </div>
          <div className="rounded-card border border-surface-border bg-surface/30 p-5 text-center">
            <p className="text-sm text-text-secondary">
              ShieldCheck generates audit-ready compliance evidence logs. Export your compliance status for auditor review.
            </p>
          </div>
        </div>
      )}

      {/* TAB 4: AI & LLM Security */}
      {activeTab === 3 && (
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-8">
            <h3 className="text-title text-text-primary mb-2">The Only ₹499 Tool That Audits Your AI Stack</h3>
            <p className="text-sm text-text-secondary max-w-lg mx-auto">
              If your website uses ChatGPT, Claude, Gemini, or any AI API — we scan it for OWASP LLM Top 10 2025 risks.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
            {llmRisks.map((risk) => (
              <div key={risk.id} className="rounded-card border border-card-border bg-card p-4">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-nanz-600/15 text-nanz-400">{risk.id}</span>
                  <span className="text-sm font-semibold text-text-primary">{risk.name}</span>
                </div>
                <p className="text-xs text-text-muted">{risk.desc}</p>
              </div>
            ))}
          </div>

          <div className="space-y-2 mb-6">
            {[
              'Unauthenticated AI endpoints',
              'Missing rate limiting on LLM APIs',
              'Model version exposure',
            ].map((item) => (
              <div key={item} className="flex items-center gap-2.5 text-sm text-text-secondary">
                <CheckCircle2 className="w-4 h-4 text-nanz-400 flex-shrink-0" />
                {item}
              </div>
            ))}
          </div>

          {/* Sample Finding Card */}
          <div className="rounded-card border border-critical/30 bg-critical/[0.03] p-5">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-critical/20 text-critical uppercase">Critical</span>
              <span className="text-sm font-semibold text-text-primary">LLM06:2025 — Excessive Agency</span>
            </div>
            <p className="text-sm text-text-secondary mb-1">&ldquo;Your AI assistant can take actions without user confirmation&rdquo;</p>
            <p className="text-xs text-text-muted">&ldquo;Anyone can trigger your AI to execute arbitrary commands&rdquo;</p>
          </div>
        </div>
      )}
    </div>
  );
}
