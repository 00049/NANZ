'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import { Shield, Search, ArrowRight, CheckCircle2, ChevronDown, Check, Activity, Globe, Zap, Server, Lock, Eye, Cpu, BarChart3, FileText, Users, Star, ExternalLink } from 'lucide-react';
import { startScan } from '@/lib/api';
import { useScanStore } from '@/store/scanStore';
import { scanUrlSchema } from '@/lib/validations';
import { NanzLogo } from '@/components/ui/NanzLogo';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { plans } from '@/lib/mock-data';
import { cn } from '@/lib/utils';
import Link from 'next/link';

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } }
};
const stagger = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } }
};

// ─── Features ───
const features = [
  { icon: Shield, title: "SSL & TLS Analysis", desc: "Deep certificate inspection, protocol version checks, and cipher suite analysis" },
  { icon: Globe, title: "DNS Intelligence", desc: "SPF, DKIM, DMARC, DNSSEC, zone transfer detection, and typosquatting alerts" },
  { icon: Server, title: "Port & Service Scan", desc: "Detect exposed database ports, admin panels, and dangerous services" },
  { icon: Lock, title: "Security Headers", desc: "CSP, HSTS, X-Frame-Options, and comprehensive header policy scoring" },
  { icon: Eye, title: "Cloud Exposure", desc: "Detect publicly accessible S3 buckets, Azure blobs, and GCP storage" },
  { icon: Cpu, title: "Tech Stack CVEs", desc: "Identify CMS versions, frameworks, and map them to known vulnerabilities" },
  { icon: Activity, title: "Continuous Monitoring", desc: "Daily, weekly, or monthly automated scans with instant alert triggers" },
  { icon: BarChart3, title: "DPDP Compliance", desc: "India's Digital Personal Data Protection readiness assessment" },
  { icon: FileText, title: "AI-Powered Reports", desc: "Plain-English executive summaries with prioritized remediation roadmaps" },
];

// ─── Stats ───
const stats = [
  { value: "15,000+", label: "Domains Scanned" },
  { value: "500+", label: "Businesses Protected" },
  { value: "99.9%", label: "Platform Uptime" },
  { value: "< 60s", label: "Avg Scan Time" },
];

// ─── FAQ ───
const faqs = [
  { q: "Is NANZ safe to use on production websites?", a: "Yes. NANZ performs only passive and non-intrusive checks. We never exploit vulnerabilities, inject payloads, or modify your website. All scans are read-only reconnaissance." },
  { q: "What does the security score mean?", a: "The NANZ Risk Score (0-100) is a weighted composite of SSL health, header security, DNS configuration, port exposure, cloud posture, and compliance readiness. Higher is better." },
  { q: "How does continuous monitoring work?", a: "Once you add a domain and set a schedule (daily/weekly/monthly), NANZ automatically re-scans and alerts you via email, Slack, or Discord if your score drops or new vulnerabilities appear." },
  { q: "Do you support compliance frameworks?", a: "Yes. NANZ currently assesses DPDP (India) compliance readiness and provides actionable gap analysis. SOC 2 and ISO 27001 mapping is on our roadmap." },
  { q: "Can I use NANZ for client websites?", a: "Absolutely. Our Agency plan includes white-label reports, unlimited domains, and client management features designed for MSSPs and security consultancies." },
];

export default function HomePage() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [annual, setAnnual] = useState(false);
  const router = useRouter();
  const { initScan } = useScanStore();

  const handleScan = async () => {
    setError('');
    const parsed = scanUrlSchema.safeParse({ url });
    if (!parsed.success) { setError('Please enter a valid URL (e.g., https://example.com)'); return; }
    setLoading(true);
    try {
      const res = await startScan(parsed.data.url);
      initScan(res.scan_id, parsed.data.url);
      router.push(`/scan/${res.scan_id}`);
    } catch { setError('Failed to start scan. Please try again.'); }
    finally { setLoading(false); }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />

      {/* ─── HERO ─── */}
      <section className="relative pt-32 pb-20 lg:pt-40 lg:pb-28 overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-20" />
        <div className="absolute top-20 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-nanz-600/8 rounded-full blur-[150px]" />

        <motion.div initial="hidden" animate="visible" variants={stagger} className="relative z-10 max-w-4xl mx-auto px-6 text-center">
          <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-surface-border bg-surface/50 text-xs font-medium text-text-secondary mb-8 backdrop-blur-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
            AI-Powered Security Intelligence
          </motion.div>

          <motion.h1 variants={fadeUp} className="text-4xl md:text-6xl lg:text-display font-bold text-text-primary leading-tight mb-6">
            Protect What You Build<br />
            <span className="text-gradient-blue">with NANZ</span>
          </motion.h1>

          <motion.p variants={fadeUp} className="text-lg text-text-secondary max-w-2xl mx-auto mb-10">
            Enterprise security scanning, continuous monitoring, vulnerability reporting, and compliance readiness — all in one platform.
          </motion.p>

          {/* Scan Input */}
          <motion.div variants={fadeUp} className="max-w-xl mx-auto">
            <div className="flex items-center gap-2 p-2 rounded-xl border border-surface-border bg-surface/80 backdrop-blur-sm nanz-glow-sm">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                  placeholder="Enter your website URL..."
                  className="w-full pl-11 pr-4 py-3.5 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
                />
              </div>
              <button
                onClick={handleScan}
                disabled={loading}
                className="px-6 py-3.5 rounded-btn bg-nanz-gradient text-white text-sm font-semibold flex items-center gap-2 hover:opacity-90 transition-opacity disabled:opacity-60 flex-shrink-0"
              >
                {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <>Scan Free <ArrowRight className="w-4 h-4" /></>}
              </button>
            </div>
            {error && <p className="text-xs text-critical mt-3">{error}</p>}
            <p className="text-xs text-text-muted mt-4">Free scan · No signup required · Results in 60 seconds</p>
          </motion.div>
        </motion.div>
      </section>

      {/* ─── STATS ─── */}
      <section className="py-16 border-y border-surface-border bg-surface/20">
        <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8">
          {stats.map((s) => (
            <div key={s.label} className="text-center">
              <div className="text-3xl font-bold text-text-primary">{s.value}</div>
              <div className="text-xs text-text-muted mt-1 uppercase tracking-wider">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ─── HOW IT WORKS ─── */}
      <section className="py-20 lg:py-28">
        <div className="max-w-5xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-14">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">How NANZ Works</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">Three steps to enterprise-grade security visibility</motion.p>
          </motion.div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              { step: "01", title: "Enter your domain", desc: "Type any URL. No signup, no installation, no agents required." },
              { step: "02", title: "AI scans everything", desc: "19 security modules analyze SSL, DNS, ports, headers, cloud exposure, and more." },
              { step: "03", title: "Get actionable results", desc: "Plain-English report with prioritized fixes, severity scores, and compliance status." },
            ].map((item) => (
              <motion.div key={item.step} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}
                className="rounded-card border border-card-border bg-card p-6 hover:border-surface-border-light transition-all group">
                <div className="text-3xl font-bold text-nanz-400/30 mb-4">{item.step}</div>
                <h3 className="text-base font-semibold text-text-primary mb-2">{item.title}</h3>
                <p className="text-sm text-text-secondary">{item.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── FEATURES BENTO ─── */}
      <section id="features" className="py-20 lg:py-28 bg-surface/20 border-y border-surface-border">
        <div className="max-w-6xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-14">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">What NANZ Checks</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">19 security modules powered by AI intelligence</motion.p>
          </motion.div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {features.map((f) => (
              <motion.div key={f.title} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}
                className="rounded-card border border-card-border bg-card p-5 hover:border-surface-border-light hover:bg-card-hover transition-all group">
                <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center mb-4">
                  <f.icon className="w-5 h-5 text-nanz-400" />
                </div>
                <h3 className="text-sm font-semibold text-text-primary mb-1.5">{f.title}</h3>
                <p className="text-xs text-text-secondary leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── DASHBOARD PREVIEW ─── */}
      <section className="py-20 lg:py-28">
        <div className="max-w-5xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-14">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">Your Security Command Center</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto">Monitor all your domains from a single, elegant dashboard</motion.p>
          </motion.div>
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}
            className="rounded-panel border border-card-border bg-card p-6 nanz-glow">
            {/* Mock dashboard */}
            <div className="grid grid-cols-4 gap-3 mb-6">
              {[
                { label: "Domains", value: "4", color: "text-nanz-400" },
                { label: "Avg Score", value: "72", color: "text-success" },
                { label: "Critical", value: "2", color: "text-critical" },
                { label: "Trend", value: "+12%", color: "text-nanz-400" },
              ].map((m) => (
                <div key={m.label} className="rounded-btn bg-surface p-4 border border-surface-border">
                  <div className="text-xs text-text-muted mb-1">{m.label}</div>
                  <div className={cn("text-xl font-bold", m.color)}>{m.value}</div>
                </div>
              ))}
            </div>
            <div className="h-40 rounded-btn bg-surface border border-surface-border flex items-end px-6 pb-4 gap-3">
              {[40, 55, 48, 62, 58, 72, 68, 75, 82, 87].map((h, i) => (
                <div key={i} className="flex-1 rounded-t bg-nanz-gradient" style={{ height: `${h}%`, opacity: 0.4 + (i * 0.06) }} />
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* ─── PRICING ─── */}
      <section id="pricing" className="py-20 lg:py-28 bg-surface/20 border-y border-surface-border">
        <div className="max-w-6xl mx-auto px-6">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={stagger} className="text-center mb-10">
            <motion.h2 variants={fadeUp} className="text-headline text-text-primary mb-4">Simple, Transparent Pricing</motion.h2>
            <motion.p variants={fadeUp} className="text-text-secondary max-w-lg mx-auto mb-6">Start free. Scale as you grow.</motion.p>
            <motion.div variants={fadeUp} className="flex items-center justify-center gap-2 bg-surface rounded-btn p-1 w-fit mx-auto border border-surface-border">
              <button onClick={() => setAnnual(false)} className={cn("px-4 py-2 rounded text-sm font-medium transition-colors", !annual ? "bg-surface-active text-text-primary" : "text-text-muted")}>Monthly</button>
              <button onClick={() => setAnnual(true)} className={cn("px-4 py-2 rounded text-sm font-medium transition-colors flex items-center gap-1.5", annual ? "bg-surface-active text-text-primary" : "text-text-muted")}>
                Yearly <span className="text-[10px] text-success font-bold">SAVE 20%</span>
              </button>
            </motion.div>
          </motion.div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {plans.map((plan) => {
              const price = annual ? plan.yearlyPrice : plan.monthlyPrice;
              return (
                <motion.div key={plan.id} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}
                  className={cn("rounded-card border p-6 transition-all", plan.popular ? "border-nanz-600/40 bg-nanz-600/5 nanz-glow-sm" : "border-card-border bg-card hover:border-surface-border-light")}>
                  {plan.popular && <div className="text-[10px] font-bold text-nanz-400 uppercase tracking-widest mb-3">Most Popular</div>}
                  <h3 className="text-lg font-semibold text-text-primary">{plan.name}</h3>
                  <div className="mt-3 mb-5">
                    <span className="text-3xl font-bold text-text-primary">${price}</span>
                    {price > 0 && <span className="text-sm text-text-muted">/mo</span>}
                  </div>
                  <ul className="space-y-2.5 mb-6">
                    {plan.features.map((f) => (
                      <li key={f} className="flex items-start gap-2 text-xs text-text-secondary">
                        <Check className="w-3.5 h-3.5 text-nanz-400 mt-0.5 flex-shrink-0" /> {f}
                      </li>
                    ))}
                  </ul>
                  <Link href="/auth/register" className={cn("block w-full py-2.5 rounded-btn text-sm font-medium text-center transition-all", plan.popular ? "bg-nanz-gradient text-white hover:opacity-90" : "border border-surface-border text-text-secondary hover:text-text-primary hover:bg-surface-hover")}>
                    {price === 0 ? "Start Free" : "Get Started"}
                  </Link>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ─── FAQ ─── */}
      <section className="py-20 lg:py-28">
        <div className="max-w-3xl mx-auto px-6">
          <motion.h2 initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp} className="text-headline text-text-primary text-center mb-12">Frequently Asked Questions</motion.h2>
          <div className="space-y-3">
            {faqs.map((faq, i) => (
              <motion.div key={i} initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp}
                className="rounded-card border border-card-border bg-card overflow-hidden">
                <button onClick={() => setOpenFaq(openFaq === i ? null : i)} className="w-full flex items-center justify-between px-5 py-4 text-left">
                  <span className="text-sm font-medium text-text-primary pr-4">{faq.q}</span>
                  <ChevronDown className={cn("w-4 h-4 text-text-muted flex-shrink-0 transition-transform", openFaq === i && "rotate-180")} />
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

      {/* ─── FINAL CTA ─── */}
      <section className="py-20 lg:py-28 bg-surface/20 border-t border-surface-border">
        <div className="max-w-3xl mx-auto px-6 text-center">
          <NanzLogo size="xl" className="justify-center mb-8" />
          <h2 className="text-headline text-text-primary mb-4">Ready to secure your business?</h2>
          <p className="text-text-secondary max-w-lg mx-auto mb-8">Join 500+ businesses using NANZ to protect their digital assets.</p>
          <div className="flex items-center justify-center gap-3">
            <Link href="/auth/register" className="px-6 py-3 rounded-btn bg-nanz-gradient text-white text-sm font-semibold hover:opacity-90 transition-opacity flex items-center gap-2">
              Get Started Free <ArrowRight className="w-4 h-4" />
            </Link>
            <Link href="/contact-sales" className="px-6 py-3 rounded-btn border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors">
              Contact Sales
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}
