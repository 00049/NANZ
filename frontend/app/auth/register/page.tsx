"use client";

import { useState } from "react";
import Link from "next/link";
import { Eye, EyeOff, Mail, Lock, User, ArrowRight } from "lucide-react";
import { registerUser } from "@/lib/api";
import { useAuthStore } from "@/store/authStore";

export default function RegisterPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await registerUser({ name, email, password, company: "NANZ User" });
      useAuthStore.getState().setToken(res.token.access_token);
      useAuthStore.getState().setUser(res.user);
      
      window.location.href = "/dashboard";
    } catch (err: any) {
      let msg = err.message;
      if (msg === "Failed to fetch") {
        msg = "Unable to connect to the backend server. Please ensure the API is running (start.sh).";
      }
      setError(msg || "Failed to create account. Email may already be in use.");
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Create your account</h1>
        <p className="text-text-secondary mt-2">Start securing your websites with NANZ</p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <button className="flex items-center justify-center gap-2.5 px-4 py-3 rounded-btn border border-surface-border bg-surface hover:bg-surface-hover text-sm font-medium text-text-primary transition-colors">
          <svg className="w-4 h-4" viewBox="0 0 24 24"><path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
          Google
        </button>
        <button className="flex items-center justify-center gap-2.5 px-4 py-3 rounded-btn border border-surface-border bg-surface hover:bg-surface-hover text-sm font-medium text-text-primary transition-colors">
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          GitHub
        </button>
      </div>

      <div className="relative">
        <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-surface-border" /></div>
        <div className="relative flex justify-center text-xs"><span className="bg-background px-3 text-text-muted">or continue with email</span></div>
      </div>

      {error && (
        <div className="bg-high/10 border border-high/30 p-3 rounded-btn text-sm text-high text-center">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        <div>
          <label htmlFor="name" className="block text-sm font-medium text-text-secondary mb-2">Full name</label>
          <div className="relative">
            <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input id="name" type="text" value={name} onChange={e => setName(e.target.value)} required placeholder="Your full name" className="w-full pl-11 pr-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 focus:ring-1 focus:ring-nanz-500/30 outline-none transition-all" />
          </div>
        </div>
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-text-secondary mb-2">Work email</label>
          <div className="relative">
            <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input id="email" type="email" value={email} onChange={e => setEmail(e.target.value)} required placeholder="you@company.com" className="w-full pl-11 pr-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 focus:ring-1 focus:ring-nanz-500/30 outline-none transition-all" />
          </div>
        </div>
        <div>
          <label htmlFor="password" className="block text-sm font-medium text-text-secondary mb-2">Password</label>
          <div className="relative">
            <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input id="password" type={showPassword ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)} required placeholder="Min. 8 characters" className="w-full pl-11 pr-11 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 focus:ring-1 focus:ring-nanz-500/30 outline-none transition-all" />
            <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors">
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <button type="submit" disabled={loading} className="w-full py-3 rounded-btn bg-nanz-gradient text-white text-sm font-semibold flex items-center justify-center gap-2 hover:opacity-90 transition-opacity disabled:opacity-60">
          {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <>Create account <ArrowRight className="w-4 h-4" /></>}
        </button>
      </form>

      <p className="text-xs text-text-muted text-center">
        By creating an account, you agree to our{" "}
        <Link href="/privacy" className="text-text-secondary hover:text-text-primary transition-colors underline">Privacy Policy</Link>{" "}
        and <Link href="/security" className="text-text-secondary hover:text-text-primary transition-colors underline">Terms of Service</Link>.
      </p>

      <p className="text-sm text-text-secondary text-center">
        Already have an account?{" "}
        <a href="/auth/login" onClick={(e) => { e.preventDefault(); window.location.href = `/auth/login${window.location.search}`; }} className="text-nanz-400 hover:text-nanz-300 font-medium transition-colors cursor-pointer">Sign in</a>
      </p>
    </div>
  );
}
