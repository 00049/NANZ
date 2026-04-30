'use client';

import { Lock, ArrowRight } from 'lucide-react';
import Link from 'next/link';

export default function PaywallSection({ lockedCount, scanId }: { lockedCount: number, scanId: string }) {
  return (
    <div className="relative mt-8">
      {/* Background elements to suggest more cards */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-background/80 to-background z-10 rounded-xl" />
      
      <div className="relative z-20 bg-surface/90 backdrop-blur-md border border-primary/30 rounded-card p-8 shadow-2xl shadow-primary/10 max-w-2xl mx-auto text-center transform -translate-y-8">
        <div className="w-16 h-16 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-primary/30">
          <Lock className="w-8 h-8 text-primary" />
        </div>
        
        <h3 className="text-2xl font-bold text-text-primary mb-2">
          {lockedCount} More Security Issues Found
        </h3>
        <p className="text-text-muted mb-6">
          Unlock the full enterprise-grade report to secure your business and comply with the DPDP Act.
        </p>
        
        <div className="text-left bg-background border border-card-border rounded-lg p-5 mb-8 inline-block mx-auto">
          <h4 className="font-semibold text-text-primary mb-3">Your full report includes:</h4>
          <ul className="space-y-2 text-sm text-text-muted">
            <li className="flex items-center gap-2">✅ <span className="text-text-primary">Step-by-step fix instructions</span> for every issue</li>
            <li className="flex items-center gap-2">✅ <span className="text-text-primary">Prioritized Remediation Roadmap</span> (Fix Today vs Next Week)</li>
            <li className="flex items-center gap-2">✅ <span className="text-text-primary">Technology Inventory & CVE Mapping</span></li>
            <li className="flex items-center gap-2">✅ <span className="text-text-primary">DPDP Compliance Assessment Score</span></li>
            <li className="flex items-center gap-2">✅ <span className="text-text-primary">Deep Email Security Grade</span> (SPF/DMARC/DKIM)</li>
          </ul>
        </div>
        
        <div className="flex flex-col items-center justify-center">
          <div className="mb-4">
            <span className="text-xl font-bold text-nanz-500">Premium Account Active</span>
            <span className="text-text-muted ml-2">All reports unlocked</span>
          </div>
          
          <Link href={`/report/${scanId}`} className="w-full sm:w-auto bg-primary hover:bg-primary-hover text-primary-foreground font-semibold py-3 px-8 rounded-btn transition-colors flex items-center justify-center gap-2">
            View Full Detailed Report <ArrowRight className="w-4 h-4" />
          </Link>
          
          <p className="text-xs text-text-muted mt-4">
            Full access granted for premium users.
          </p>
        </div>
      </div>
    </div>
  );
}
