'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  Search, ArrowRight, ChevronDown, Shield, ShieldCheck,
  Mail, CheckCircle2, Zap, Clock, FileText, Globe
} from 'lucide-react';
import { startScan } from '@/lib/api';
import { useScanStore } from '@/store/scanStore';
import { useAuthStore } from '@/store/authStore';
import { scanUrlSchema } from '@/lib/validations';
import { NanzLogo } from '@/components/ui/NanzLogo';
import Navbar from '@/components/Navbar';
import Link from 'next/link';
import { useEffect } from 'react';

// Lazy-loaded interactive sections
import AnimatedCounter from '@/components/AnimatedCounter';
import HeroScanPreview from '@/components/HeroScanPreview';
import PersonaCards from '@/components/PersonaCard';
import DPDPAlertSection from '@/components/DPDPAlertSection';
import FeatureTabPanel from '@/components/FeatureTabPanel';
import InteractiveReportPreview from '@/components/InteractiveReportPreview';
import PricingCards from '@/components/PricingCard';

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } }
};
const stagger = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } }
};

// ─── FAQ ───
const faqs = [
  {
    q: 'Is scanning passive? Will it harm my website?',
    a: "Yes — 100% passive. We make standard HTTP GET requests, DNS queries, and public API lookups. No payloads, no form submissions, no brute force. The same type of traffic Google's crawler sends."
  },
  {
    q: 'What is the DPDP Act and why does it matter?',
    a: "India's Digital Personal Data Protection Act 2023 mandates data security for all businesses processing Indian users' data. Penalties reach ₹250 Crore per violation of Section 8(4) — the security safeguards clause. ShieldCheck maps every finding to the specific DPDP sections you're violating, so you know your exact legal exposure."
  },
  {
    q: 'What is EPSS and why is it better than CVSS?',
    a: 'CVSS scores measure theoretical severity in a vacuum. EPSS (Exploit Prediction Scoring System) measures the real-world probability that a vulnerability will be actively exploited in the next 30 days. We use both — CVSS tells you how bad it could be, EPSS tells you how likely it is right now.'
  },
  {
    q: "What does 'out-of-band detection' mean?",
    a: "Some vulnerabilities — like blind SSRF — don't show up in normal HTTP responses. Our OAST (Out-of-Band Application Security Testing) infrastructure detects these by listening for DNS and HTTP callbacks that prove a vulnerability exists, even when the application doesn't show a visible response."
  },
  {
    q: 'What is an SBOM and do I need one?',
    a: 'A Software Bill of Materials lists every library and framework your site uses, including versions and known vulnerabilities. DPDP Act, PCI DSS, and SOC 2 auditors increasingly require SBOMs. ShieldCheck generates one in CycloneDX and SPDX formats from your paid report.'
  },
  {
    q: 'Can I import results from other scanners?',
    a: 'Yes. ShieldCheck accepts SARIF (Semgrep, CodeQL), Snyk JSON, Trivy JSON, and Semgrep JSON via our BYOS (Bring Your Own Scanner) API. We normalize, deduplicate, and enrich external findings with EPSS scores, CISA KEV status, and compliance mapping.'
  },
  {
    q: 'If I get a clean result, am I definitely secure?',
    a: 'No tool guarantees complete security — including us. ShieldCheck is a risk indicator and compliance baseline tool. A clean result means we found no detectable issues in 29 passive checks. It does not replace penetration testing or manual code review. Every report includes this disclaimer.'
  },
];

// ─── How It Works Steps ───
const steps = [
  {
    step: '01',
    title: 'Paste Your URL',
    time: '10 seconds',
    desc: 'No signup. No browser extension. No code changes. Just your website address.',
  },
  {
    step: '02',
    title: '29 Modules Run Simultaneously',
    time: '60-90 seconds',
    desc: 'SSL analysis, port scanning, AI security audit, DPDP compliance mapping — all run concurrently.',
  },
  {
    step: '03',
    title: 'Intelligence Engine Processes',
    time: 'Automatic',
    desc: 'EPSS scores fetched. CISA KEV checked. ALE calculated. Compliance violations mapped. Findings deduplicated.',
  },
  {
    step: '04',
    title: 'Plain English Report Delivered',
    time: 'Instant',
    desc: 'Every finding explained in business language. Financial impact. Compliance clause. Fix steps. Prioritized by urgency.',
  },
];

export default function HomePage() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const router = useRouter();
  const { initScan } = useScanStore();
  const { token, user, setPendingScanUrl } = useAuthStore();

  // Check URL for scan param
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);

      const scanParam = params.get('scan');
      if (scanParam) {
        setUrl(scanParam);
      }
    }
  }, []);

  const handleScan = async () => {
    setError('');
    let inputUrl = url.trim();
    if (inputUrl && !inputUrl.startsWith('http://') && !inputUrl.startsWith('https://')) {
      inputUrl = 'https://' + inputUrl;
    }
    const parsed = scanUrlSchema.safeParse({ url: inputUrl });
    if (!parsed.success) { setError('Please enter a valid URL (e.g., https://example.com)'); return; }

    const scanRoute = `/scan?url=${encodeURIComponent(parsed.data.url)}`;
    if (!token) {
      router.push(`/auth/login?redirect=${encodeURIComponent(scanRoute)}`);
      return;
    }

    router.push(scanRoute);
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />

      {/* ═══════════════════ SECTION 1: HERO ═══════════════════ */}
      <section id="hero" className="relative pt-28 pb-16 lg:pt-36 lg:pb-24 overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-20" />
        <div className="absolute top-20 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-nanz-600/8 rounded-full blur-[150px]" />

        <div className="relative z-10 max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            {/* Left: Copy + Input */}
            <motion.div initial="hidden" animate="visible" variants={stagger}>
              <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-surface-border bg-surface/50 text-xs font-medium text-text-secondary mb-6 backdrop-blur-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                29 Modules · DPDP · EPSS · OWASP
              </motion.div>

              <motion.h1 variants={fadeUp} className="text-4xl md:text-5xl lg:text-display font-bold text-text-primary leading-tight mb-5">
                Your Website&apos;s Security Audit.
                <br />
                <span className="text-gradient-blue">DPDP-Compliant.</span>{' '}Results in 90 Seconds.
              </motion.h1>

              <motion.p variants={fadeUp} className="text-lg text-text-secondary max-w-lg mb-8">
                29 security checks run automatically. Every finding explained in plain English with the exact fix. DPDP Act violations flagged by section number. Starts free — full report from Rs. 299.
              </motion.p>

              {/* Scan Input */}
              <motion.div variants={fadeUp} className="max-w-xl">
                <div className="flex items-center gap-2 p-2 rounded-xl border border-surface-border bg-surface/80 backdrop-blur-sm nanz-glow-sm">
                  <div className="relative flex-1">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                    <input
                      autoFocus
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                      placeholder="Enter your website URL to get your free report"
                      className="w-full pl-11 pr-4 py-3.5 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
                    />
                  </div>
                  <button
                    onClick={handleScan}
                    disabled={loading}
                    className="px-6 py-3.5 rounded-btn bg-nanz-gradient text-white text-sm font-semibold flex items-center gap-2 hover:opacity-90 transition-opacity disabled:opacity-60 flex-shrink-0"
                  >
                    {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <>Get Your Security Report <ArrowRight className="w-4 h-4" /></>}
                  </button>
                </div>
                {error && <p className="text-xs text-critical mt-3">{error}</p>}

                {/* Trust Chips */}
                <div className="flex flex-wrap items-center gap-3 mt-5">
                  {[
                    { icon: Shield, text: '29 scan modules' },
                    { icon: FileText, text: 'DPDP compliance included' },
                    { icon: Zap, text: 'Report ready in 90 seconds' },
                  ].map((chip) => (
                    <div key={chip.text} className="flex items-center gap-1.5 text-xs text-text-muted">
                      <chip.icon className="w-3.5 h-3.5 text-nanz-400" />
                      {chip.text}
                    </div>
                  ))}
                </div>
              </motion.div>
            </motion.div>

            {/* Right: Animated Scan Preview (desktop only) */}
            <motion.div
              initial={{ opacity: 0, x: 40 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
              className="hidden lg:block"
            >
              <HeroScanPreview />
            </motion.div>
          </div>
        </div>
      </section>

      {/* ═══════════════════ SECTION 2: TRUST BAR ═══════════════════ */}
      <section className="py-14 border-y border-surface-border bg-surface/20">
        <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-5 gap-8">
          <AnimatedCounter end={28} label="Scan Modules" />
          <AnimatedCounter end={140} suffix="+" label="Finding Types" />
          <AnimatedCounter end={4} label="Compliance Frameworks" />
          <AnimatedCounter end={90} suffix="s" label="Avg Scan Time" />
          <AnimatedCounter end={499} prefix="₹" label="One-Time Price" />
        </div>
      </section>

      {/* ═══════════════════ SECTION 3: WHO IS THIS FOR ═══════════════════ */}
      <section className="py-20 lg:py-28">
        <div className="max-w-6xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-12">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">Who Is This For?</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">
              Whether you run a Shopify store or manage enterprise SOC — ShieldCheck speaks your language.
            </motion.p>
          </motion.div>
          <PersonaCards />
        </div>
      </section>

      {/* ═══════════════════ SECTION 4: DPDP ACT HOOK ═══════════════════ */}
      <DPDPAlertSection />

      {/* ═══════════════════ SECTION 5: FEATURES ═══════════════════ */}
      <section id="features" className="py-20 lg:py-28 bg-surface/20 border-y border-surface-border">
        <div className="max-w-6xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-12">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">What We Check — Every Single Thing</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">
              29 security modules, an intelligence engine, 6 compliance frameworks, and dedicated AI/LLM security auditing.
            </motion.p>
          </motion.div>
          <FeatureTabPanel />
        </div>
      </section>

      {/* ═══════════════════ SECTION 6: HOW IT WORKS ═══════════════════ */}
      <section className="py-20 lg:py-28">
        <div className="max-w-5xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-14">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">From URL to Enterprise Security Report in 90 Seconds</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">Four steps. No agents. No signup. Just paste and go.</motion.p>
          </motion.div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {steps.map((item) => (
              <motion.div key={item.step} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}
                className="rounded-card border border-card-border bg-card p-6 hover:border-surface-border-light transition-all group relative">
                <div className="flex items-center justify-between mb-4">
                  <div className="text-3xl font-bold text-nanz-400/20">{item.step}</div>
                  <div className="flex items-center gap-1 text-[10px] text-text-muted">
                    <Clock className="w-3 h-3" />
                    {item.time}
                  </div>
                </div>
                <h3 className="text-sm font-semibold text-text-primary mb-2">{item.title}</h3>
                <p className="text-xs text-text-secondary leading-relaxed">{item.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════ SECTION 7: SAMPLE REPORT PREVIEW ═══════════════════ */}
      <section className="py-20 lg:py-28 bg-surface/20 border-y border-surface-border">
        <div className="max-w-6xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-12">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">This Is What Your Report Looks Like</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">
              Three views for three audiences. Same data, tailored for your role.
            </motion.p>
          </motion.div>
          <InteractiveReportPreview />
          <div className="text-center mt-10">
            <p className="text-text-secondary mb-4">Want to see YOUR site&apos;s report? It takes 90 seconds.</p>
            <a href="#hero" className="inline-flex items-center gap-2 px-6 py-3 rounded-btn bg-nanz-gradient text-white text-sm font-semibold hover:opacity-90 transition-opacity">
              Get Your Security Report <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </div>
      </section>

      {/* ═══════════════════ SECTION 8: FREE TOOLS ═══════════════════ */}
      <section className="py-20 lg:py-28">
        <div className="max-w-4xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-12">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">Free Security Tools — No Scan Required</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">
              Quick checks you can run right now, no account needed.
            </motion.p>
          </motion.div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Headers Checker */}
            <div className="rounded-panel border border-card-border bg-card p-6 hover:border-surface-border-light transition-colors">
              <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center mb-4">
                <ShieldCheck className="w-5 h-5 text-nanz-400" />
              </div>
              <h3 className="text-base font-semibold text-text-primary mb-2">Check Your Security Headers Grade</h3>
              <p className="text-sm text-text-secondary mb-4">
                See your A+ to F grade instantly. Checks all 13 security headers including HSTS, CSP, X-Frame-Options, and Content-Security-Policy.
              </p>
              <Link href="/tools/headers" className="inline-flex items-center gap-1.5 text-sm font-semibold text-nanz-400 hover:text-nanz-300 transition-colors">
                Check Headers Free <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
            {/* Email Checker */}
            <div className="rounded-panel border border-card-border bg-card p-6 hover:border-surface-border-light transition-colors">
              <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center mb-4">
                <Mail className="w-5 h-5 text-nanz-400" />
              </div>
              <h3 className="text-base font-semibold text-text-primary mb-2">Check Your Email Security Score</h3>
              <p className="text-sm text-text-secondary mb-4">
                SPF, DMARC, DKIM, MX security, BIMI — full email security grade in seconds. If DMARC is p=none, anyone can impersonate your domain.
              </p>
              <Link href="/tools/email" className="inline-flex items-center gap-1.5 text-sm font-semibold text-nanz-400 hover:text-nanz-300 transition-colors">
                Check Email Security Free <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════ SECTION 9: PRICING ═══════════════════ */}
      <section id="pricing" className="py-20 lg:py-28 bg-surface/20 border-y border-surface-border">
        <div className="max-w-6xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-12">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">Simple Pricing. No Subscriptions.</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">
              Scan free. Pay only if you want the full report with fix instructions.
            </motion.p>
          </motion.div>
          <PricingCards />
        </div>
      </section>

      {/* ═══════════════════ SECTION 10: FAQ ═══════════════════ */}
      <section className="py-20 lg:py-28">
        <div className="max-w-3xl mx-auto px-6">
          <motion.h2 initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp} className="text-headline text-text-primary text-center mb-12">
            Frequently Asked Questions
          </motion.h2>
          <div className="space-y-3">
            {faqs.map((faq, i) => (
              <motion.div key={i} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}
                className="rounded-card border border-card-border bg-card overflow-hidden">
                <button onClick={() => setOpenFaq(openFaq === i ? null : i)} className="w-full flex items-center justify-between px-5 py-4 text-left">
                  <span className="text-sm font-medium text-text-primary pr-4">{faq.q}</span>
                  <ChevronDown className={`w-4 h-4 text-text-muted flex-shrink-0 transition-transform duration-200 ${openFaq === i && 'rotate-180'}`} />
                </button>
                {openFaq === i && (
                  <div className="px-5 pb-4">
                    <p className="text-sm text-text-secondary leading-relaxed">{faq.a}</p>
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════ FINAL CTA ═══════════════════ */}
      <section className="py-20 lg:py-28 bg-surface/20 border-t border-surface-border">
        <div className="max-w-3xl mx-auto px-6 text-center">
          <NanzLogo size="xl" className="justify-center mb-8" />
          <h2 className="text-headline text-text-primary mb-4">29 Checks. Plain English. From Rs. 299.</h2>
          <p className="text-text-secondary max-w-lg mx-auto mb-8">
            Your website&apos;s security audit — DPDP-compliant, results in 90 seconds. Start with a free scan.
          </p>
          <a href="#hero" className="inline-flex items-center gap-2 px-8 py-4 rounded-btn bg-nanz-gradient text-white text-sm font-semibold hover:opacity-90 transition-opacity">
            Get Your Security Report <ArrowRight className="w-4 h-4" />
          </a>
        </div>
      </section>

      {/* ═══════════════════ SECTION 11: FOOTER ═══════════════════ */}
      <footer className="border-t border-surface-border bg-surface/30 mt-auto">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-10">
            <div className="col-span-2 md:col-span-1">
              <NanzLogo size="sm" />
              <p className="text-xs text-text-muted mt-3 max-w-[220px]">Enterprise security intelligence. Indian price.</p>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-text-primary uppercase tracking-wider mb-3">Tools</h4>
              <div className="space-y-2">
                <Link href="/tools/headers" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Free Headers Checker</Link>
                <Link href="/tools/email" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Free Email Checker</Link>
                <Link href="#hero" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Full Security Scan</Link>
                <Link href="/docs" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">API Documentation</Link>
              </div>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-text-primary uppercase tracking-wider mb-3">Compliance</h4>
              <div className="space-y-2">
                <Link href="/compliance" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">DPDP Act Coverage</Link>
                <Link href="/compliance" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">GDPR Coverage</Link>
                <Link href="/compliance" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">PCI DSS Coverage</Link>
                <Link href="/compliance" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">SOC 2 Coverage</Link>
              </div>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-text-primary uppercase tracking-wider mb-3">Company</h4>
              <div className="space-y-2">
                <Link href="/privacy" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Privacy Policy</Link>
                <Link href="/security" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Terms of Service</Link>
                <Link href="/contact-sales" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Contact</Link>
                <Link href="/.well-known/security.txt" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Security.txt</Link>
              </div>
            </div>
          </div>
          <div className="border-t border-surface-border pt-6">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
              <p className="text-xs text-text-muted">Made in India 🇮🇳 for Indian businesses and beyond.</p>
              <p className="text-[10px] text-text-muted/60 max-w-md text-center sm:text-right">
                ShieldCheck is a risk indicator. Results are not a guarantee of security. By scanning, you confirm you own or have permission to scan the target domain.
              </p>
            </div>
            <div className="flex items-center justify-center gap-4 mt-4">
              <Link href="/privacy" className="text-xs text-text-muted hover:text-text-secondary transition-colors">Privacy</Link>
              <Link href="/security" className="text-xs text-text-muted hover:text-text-secondary transition-colors">Terms</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
