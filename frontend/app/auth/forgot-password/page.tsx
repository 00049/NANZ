"use client";

import { useState } from "react";
import Link from "next/link";
import { Mail, ArrowLeft, ArrowRight, CheckCircle2 } from "lucide-react";

export default function ForgotPasswordPage() {
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setTimeout(() => { setSent(true); setLoading(false); }, 1000);
  };

  if (sent) {
    return (
      <div className="space-y-8 text-center">
        <div className="w-16 h-16 rounded-2xl bg-success/10 border border-success/20 flex items-center justify-center mx-auto">
          <CheckCircle2 className="w-8 h-8 text-success" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Check your email</h1>
          <p className="text-text-secondary mt-2 max-w-sm mx-auto">We&apos;ve sent a password reset link to your email address. The link will expire in 1 hour.</p>
        </div>
        <Link href="/auth/login" className="inline-flex items-center gap-2 text-sm text-nanz-400 hover:text-nanz-300 transition-colors font-medium">
          <ArrowLeft className="w-4 h-4" /> Back to sign in
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <Link href="/auth/login" className="inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-secondary transition-colors mb-6">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to sign in
        </Link>
        <h1 className="text-2xl font-bold text-text-primary">Reset password</h1>
        <p className="text-text-secondary mt-2">Enter your email and we&apos;ll send you a reset link.</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-text-secondary mb-2">Email address</label>
          <div className="relative">
            <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input id="email" type="email" required placeholder="you@company.com" className="w-full pl-11 pr-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 focus:ring-1 focus:ring-nanz-500/30 outline-none transition-all" />
          </div>
        </div>
        <button type="submit" disabled={loading} className="w-full py-3 rounded-btn bg-nanz-gradient text-white text-sm font-semibold flex items-center justify-center gap-2 hover:opacity-90 transition-opacity disabled:opacity-60">
          {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <>Send reset link <ArrowRight className="w-4 h-4" /></>}
        </button>
      </form>
    </div>
  );
}
