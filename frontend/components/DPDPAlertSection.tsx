'use client';

import { AlertTriangle, CheckCircle2 } from 'lucide-react';

const penalties = [
  { amount: '₹250 Crore', section: 'S.8(4)', desc: 'Failure to implement security safeguards' },
  { amount: '₹200 Crore', section: 'S.8(6)', desc: 'Failure to report a data breach' },
  { amount: '₹50 Crore', section: 'S.8(1)', desc: 'Failure to maintain data accuracy' },
];

const checks = [
  { section: 'Section 8(4)', desc: 'Security safeguards — SSL, headers, exposed data' },
  { section: 'Section 8(6)', desc: 'Breach detection — HIBP domain breach scan' },
  { section: 'Section 4', desc: 'Lawful processing — rate limiting, consent signals' },
  { section: 'Section 9', desc: "Children's data safeguards" },
  { section: 'Classification', desc: 'Data Fiduciary vs Processor classification' },
];

export default function DPDPAlertSection() {
  return (
    <section className="py-20 lg:py-28 relative overflow-hidden">
      {/* Dark dramatic background */}
      <div className="absolute inset-0 bg-gradient-to-b from-background via-high/[0.03] to-background" />
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-high/30 to-transparent" />
      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-high/30 to-transparent" />

      <div className="relative z-10 max-w-6xl mx-auto px-6">
        <div className="text-center mb-14">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-high/20 bg-high/5 text-xs font-semibold text-high mb-5">
            <AlertTriangle className="w-3.5 h-3.5" />
            Compliance Alert
          </div>
          <h2 className="text-headline text-text-primary mb-4">
            Is Your Business Ready for India&apos;s DPDP Act?
          </h2>
          <p className="text-text-secondary max-w-xl mx-auto">
            The Digital Personal Data Protection Act 2023 is now enforced. Every business processing Indian users&apos; data must comply.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left: Penalties */}
          <div>
            <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-5">
              Maximum Penalties Per Violation
            </h3>
            <div className="space-y-4">
              {penalties.map((p) => (
                <div key={p.section} className="rounded-card border border-high/20 bg-high/[0.03] p-5">
                  <div className="flex items-baseline gap-3 mb-1.5">
                    <span className="text-2xl font-bold text-high">{p.amount}</span>
                    <span className="text-xs font-semibold text-high/60 uppercase">{p.section}</span>
                  </div>
                  <p className="text-sm text-text-secondary">{p.desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Right: What ShieldCheck checks */}
          <div>
            <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-5">
              What ShieldCheck Checks for DPDP
            </h3>
            <div className="rounded-panel border border-card-border bg-card p-6">
              <div className="space-y-4">
                {checks.map((c) => (
                  <div key={c.section} className="flex items-start gap-3">
                    <CheckCircle2 className="w-4 h-4 text-success mt-0.5 flex-shrink-0" />
                    <div>
                      <span className="text-sm font-semibold text-text-primary">{c.section}</span>
                      <span className="text-sm text-text-muted"> — </span>
                      <span className="text-sm text-text-secondary">{c.desc}</span>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-6 pt-5 border-t border-surface-border">
                <a
                  href="#hero"
                  className="inline-flex items-center gap-2 px-6 py-3 rounded-btn bg-nanz-gradient text-white text-sm font-semibold hover:opacity-90 transition-opacity"
                >
                  Get Your DPDP Score Free
                </a>
                <p className="text-[11px] text-text-muted mt-3">
                  ShieldCheck maps every security finding to the specific DPDP Act section you are violating, providing a clear legal risk roadmap for your DPO and legal team.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
