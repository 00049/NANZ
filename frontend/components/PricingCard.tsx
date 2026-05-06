'use client';

import { Check, ArrowRight } from 'lucide-react';

export default function PricingCards() {
  return (
    <div className="flex flex-wrap justify-center gap-6">
      {/* Free Card */}
      <div className="w-full max-w-[340px] rounded-panel border border-card-border bg-card p-6 flex flex-col">
        <div className="mb-6">
          <h3 className="text-lg font-bold text-text-primary">Free Preview</h3>
          <div className="mt-2">
            <span className="text-3xl font-black text-text-primary">₹0</span>
            <span className="text-xs text-text-muted ml-1">/ scan</span>
          </div>
          <p className="text-sm text-text-muted mt-2">Test the engine. See your score.</p>
        </div>
        <ul className="space-y-3 mb-8 flex-1">
          <PricingFeature text="Overall Risk Score (0-100)" />
          <PricingFeature text="A+ to F Letter Grade" />
          <PricingFeature text="Top 3 Vulnerability Titles" />
          <PricingFeature text="Financial Risk (ALE) Estimate" />
          <PricingFeature text="DPDP Compliance Score" />
          <PricingFeature text="Public Identity Breach Scan" excluded={false} />
        </ul>
        <a href="#hero" className="w-full py-3 rounded-btn border border-surface-border text-sm font-semibold text-text-secondary hover:bg-surface-hover transition-colors text-center">
          Start Free Scan
        </a>
      </div>

      {/* Paid Card */}
      <div className="w-full max-w-[340px] rounded-panel border-2 border-nanz-600/40 bg-nanz-600/[0.03] p-6 flex flex-col relative nanz-glow-sm scale-[1.05] z-10">
        <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-nanz-gradient text-white text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-widest">
          Most Popular
        </div>
        <div className="mb-6">
          <h3 className="text-lg font-bold text-text-primary">Full Security Audit</h3>
          <div className="mt-2">
            <span className="text-3xl font-black text-text-primary">₹499</span>
            <span className="text-xs text-text-muted ml-1">/ scan</span>
          </div>
          <p className="text-sm text-text-muted mt-2">The complete intelligence report.</p>
        </div>
        <ul className="space-y-3 mb-8 flex-1">
          <PricingFeature text="Every Finding Explained" />
          <PricingFeature text="AI-Powered Fix Instructions" />
          <PricingFeature text="Full DPDP Compliance Mapping" />
          <PricingFeature text="CycloneDX SBOM Generation" />
          <PricingFeature text="Detailed ALE Breakdown" />
          <PricingFeature text="Enterprise Remediation View" />
          <PricingFeature text="Remediation SLA Roadmap" />
        </ul>
        <a href="#hero" className="w-full py-3 rounded-btn bg-nanz-gradient text-white text-sm font-bold flex items-center justify-center gap-2 hover:opacity-90 transition-opacity">
          Unlock Full Report <ArrowRight className="w-4 h-4" />
        </a>
      </div>
    </div>
  );
}

function PricingFeature({ text, excluded = false }: { text: string; excluded?: boolean }) {
  return (
    <li className="flex items-center gap-2.5 text-sm">
      <Check className="w-4 h-4 text-nanz-400 shrink-0" />
      <span className="text-text-secondary">{text}</span>
    </li>
  );
}
