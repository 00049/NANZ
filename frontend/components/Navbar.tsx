"use client";

import Link from "next/link";
import { NanzLogo } from "@/components/ui/NanzLogo";

export default function Navbar() {
  return (
    <nav className="fixed top-0 inset-x-0 z-50 h-16 border-b border-surface-border bg-background/70 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto h-full flex items-center justify-between px-6">
        <Link href="/">
          <NanzLogo size="sm" />
        </Link>
        <div className="hidden md:flex items-center gap-8">
          <Link href="#features" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Features</Link>
          <Link href="#pricing" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Pricing</Link>
          <Link href="/status" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Status</Link>
          <Link href="/docs" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Docs</Link>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/auth/login" className="text-sm text-text-secondary hover:text-text-primary transition-colors font-medium">Sign in</Link>
          <Link href="/auth/register" className="px-4 py-2 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">Get Started</Link>
        </div>
      </div>
    </nav>
  );
}
