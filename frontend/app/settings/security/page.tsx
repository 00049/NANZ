"use client";

import { Lock, Smartphone, Monitor, Globe } from "lucide-react";

const sessions = [
  { id: "s1", device: "Chrome on macOS", location: "Mumbai, India", ip: "103.45.xx.xx", current: true, lastActive: "Active now" },
  { id: "s2", device: "Safari on iPhone", location: "Mumbai, India", ip: "103.45.xx.xx", current: false, lastActive: "2 hours ago" },
];

export default function SecurityPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-title text-text-primary">Security</h1>
        <p className="text-sm text-text-secondary mt-1">Manage your account security settings</p>
      </div>

      {/* Password */}
      <div className="rounded-card border border-card-border bg-card p-6 space-y-5">
        <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2"><Lock className="w-4 h-4 text-nanz-400" /> Change Password</h3>
        <div className="space-y-4 max-w-sm">
          <div>
            <label className="block text-sm text-text-secondary mb-2">Current password</label>
            <input type="password" placeholder="••••••••" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" />
          </div>
          <div>
            <label className="block text-sm text-text-secondary mb-2">New password</label>
            <input type="password" placeholder="Min. 8 characters" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" />
          </div>
          <button className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">Update Password</button>
        </div>
      </div>

      {/* 2FA */}
      <div className="rounded-card border border-card-border bg-card p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-surface flex items-center justify-center"><Smartphone className="w-5 h-5 text-text-muted" /></div>
            <div>
              <h3 className="text-sm font-semibold text-text-primary">Two-Factor Authentication</h3>
              <p className="text-xs text-text-muted mt-0.5">Add an extra layer of security to your account</p>
            </div>
          </div>
          <button className="px-4 py-2 rounded-btn border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors">Enable 2FA</button>
        </div>
      </div>

      {/* Sessions */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="px-6 py-4 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-text-primary">Active Sessions</h3>
        </div>
        <div className="divide-y divide-surface-border">
          {sessions.map((s) => (
            <div key={s.id} className="flex items-center justify-between px-6 py-4">
              <div className="flex items-center gap-3">
                <Monitor className="w-4 h-4 text-text-muted" />
                <div>
                  <div className="text-sm text-text-primary font-medium">{s.device} {s.current && <span className="text-xs text-success ml-1">(This device)</span>}</div>
                  <div className="text-xs text-text-muted">{s.location} · {s.ip} · {s.lastActive}</div>
                </div>
              </div>
              {!s.current && <button className="text-xs text-critical hover:text-critical/80 transition-colors font-medium">Revoke</button>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
