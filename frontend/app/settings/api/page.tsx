"use client";

import { useState } from "react";
import { Key, Plus, Copy, Trash2, Code, ExternalLink, Mail } from "lucide-react";
import { toast } from "sonner";

const exampleCode = `curl -X POST https://api.shieldcheck.com/v1/scans \\
  -H "Authorization: Bearer sc_live_sk_..." \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com"}'`;

export default function APIPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const handleJoinWaitlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    
    setLoading(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/waitlist/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email })
      });
      
      if (res.ok) {
        toast.success("Successfully joined the API waitlist!");
        setEmail("");
      } else {
        const data = await res.json();
        toast.error(data.message || "Failed to join waitlist");
      }
    } catch (err) {
      toast.error("An error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-title text-text-primary">API Access</h1>
        <p className="text-sm text-text-secondary mt-1">Manage API keys for programmatic access to ShieldCheck</p>
      </div>

      {/* Waitlist Form */}
      <div className="rounded-card border border-nanz-600/30 bg-nanz-gradient-subtle p-8 text-center max-w-2xl mx-auto">
        <div className="w-12 h-12 bg-nanz-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
          <Key className="w-6 h-6 text-nanz-400" />
        </div>
        <h2 className="text-xl font-bold text-text-primary mb-2">API access coming soon</h2>
        <p className="text-sm text-text-secondary mb-6">We're rolling out programmatic access to the ShieldCheck scanning engine. Join the waitlist to get early access.</p>
        
        <form onSubmit={handleJoinWaitlist} className="flex flex-col sm:flex-row gap-3 max-w-md mx-auto">
          <div className="relative flex-1">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input 
              type="email" 
              placeholder="Enter your email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all"
            />
          </div>
          <button disabled={loading} type="submit" className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity whitespace-nowrap">
            {loading ? "Joining..." : "Join Waitlist"}
          </button>
        </form>
      </div>

      {/* Example */}
      <div className="rounded-card border border-card-border bg-card p-5">
        <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2 mb-4"><Code className="w-4 h-4 text-nanz-400" /> Example Request</h3>
        <pre className="bg-background rounded-btn p-4 text-xs text-text-secondary font-mono overflow-x-auto border border-surface-border">{exampleCode}</pre>
        <div className="mt-4 flex items-center gap-4">
          <span className="text-xs text-text-muted">Rate limit: 100 requests/min (Pro), 500/min (Business)</span>
        </div>
      </div>
    </div>
  );
}
