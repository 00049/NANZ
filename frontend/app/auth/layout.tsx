"use client";

import { NanzLogo } from "@/components/ui/NanzLogo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex">
      {/* Left Panel — Brand */}
      <div className="hidden lg:flex lg:w-[45%] bg-surface relative overflow-hidden flex-col justify-between p-12">
        <div className="absolute inset-0 bg-grid-pattern opacity-30" />
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-nanz-600/10 rounded-full blur-[120px]" />
        
        <div className="relative z-10">
          <NanzLogo size="lg" />
        </div>

        <div className="relative z-10 space-y-6">
          <h1 className="text-4xl font-bold leading-tight text-text-primary">
            Enterprise Security<br />Intelligence
          </h1>
          <p className="text-lg text-text-secondary max-w-md">
            AI-powered scanning, continuous monitoring, and compliance readiness for modern businesses.
          </p>
          <div className="flex items-center gap-8 pt-4">
            <div>
              <div className="text-2xl font-bold text-text-primary">15K+</div>
              <div className="text-xs text-text-muted">Domains Scanned</div>
            </div>
            <div className="w-px h-10 bg-surface-border" />
            <div>
              <div className="text-2xl font-bold text-text-primary">99.9%</div>
              <div className="text-xs text-text-muted">Uptime</div>
            </div>
            <div className="w-px h-10 bg-surface-border" />
            <div>
              <div className="text-2xl font-bold text-text-primary">500+</div>
              <div className="text-xs text-text-muted">Businesses</div>
            </div>
          </div>
        </div>

        <div className="relative z-10 text-xs text-text-muted">
          © {new Date().getFullYear()} NANZ. All rights reserved.
        </div>
      </div>

      {/* Right Panel — Form */}
      <div className="flex-1 flex items-center justify-center p-6 lg:p-12">
        <div className="w-full max-w-[420px]">
          <div className="lg:hidden mb-10">
            <NanzLogo size="lg" />
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}
