"use client";

import Link from "next/link";
import { NanzLogo } from "@/components/ui/NanzLogo";

export default function Footer() {
  return (
    <footer className="border-t border-surface-border bg-surface/30 mt-auto">
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-10">
          <div className="col-span-2 md:col-span-1">
            <NanzLogo size="sm" />
            <p className="text-xs text-text-muted mt-3 max-w-[200px]">AI-powered security intelligence for modern businesses.</p>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-text-primary uppercase tracking-wider mb-3">Product</h4>
            <div className="space-y-2">
              <Link href="#features" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Features</Link>
              <Link href="#pricing" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Pricing</Link>
              <Link href="/status" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Status</Link>
              <Link href="/docs" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">API Docs</Link>
            </div>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-text-primary uppercase tracking-wider mb-3">Company</h4>
            <div className="space-y-2">
              <Link href="/security" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Security</Link>
              <Link href="/privacy" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Privacy</Link>
              <Link href="/compliance" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Compliance</Link>
              <Link href="/contact-sales" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Contact</Link>
            </div>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-text-primary uppercase tracking-wider mb-3">Support</h4>
            <div className="space-y-2">
              <Link href="/help" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Help Center</Link>
              <Link href="/contact-sales" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Contact Sales</Link>
              <Link href="/contact-sales" className="block text-sm text-text-muted hover:text-text-secondary transition-colors">Book Demo</Link>
            </div>
          </div>
        </div>
        <div className="border-t border-surface-border pt-6 flex items-center justify-between">
          <p className="text-xs text-text-muted">© {new Date().getFullYear()} NANZ. All rights reserved.</p>
          <div className="flex items-center gap-4">
            <Link href="/privacy" className="text-xs text-text-muted hover:text-text-secondary transition-colors">Privacy</Link>
            <Link href="/security" className="text-xs text-text-muted hover:text-text-secondary transition-colors">Terms</Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
