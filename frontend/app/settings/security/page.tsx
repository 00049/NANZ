"use client";

import { useState, useEffect } from "react";
import { Lock, Smartphone, Monitor } from "lucide-react";
import { toast } from "sonner";
import { useAuthStore } from "@/store/authStore";

const sessions = [
  { id: "s1", device: "Current Device", location: "Unknown", ip: "-", current: true, lastActive: "Active now" }
];

export default function SecurityPage() {
  const { token } = useAuthStore();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [lastLogin, setLastLogin] = useState<string | null>(null);

  useEffect(() => {
    async function fetchMe() {
      if (!token) return;
      try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/auth/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          if (data.last_login_at) {
            setLastLogin(new Date(data.last_login_at).toLocaleString());
          }
        }
      } catch (err) {
        console.error(err);
      }
    }
    fetchMe();
  }, [token]);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    if (newPassword.length < 8) {
      toast.error("New password must be at least 8 characters");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/auth/change-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
      });
      if (res.ok) {
        toast.success("Password updated successfully!");
        setCurrentPassword("");
        setNewPassword("");
      } else {
        const errData = await res.json();
        toast.error(errData.detail || "Failed to update password");
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
        <h1 className="text-title text-text-primary">Security</h1>
        <p className="text-sm text-text-secondary mt-1">Manage your account security settings</p>
      </div>

      {/* Password */}
      <div className="rounded-card border border-card-border bg-card p-6 space-y-5">
        <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2"><Lock className="w-4 h-4 text-nanz-400" /> Change Password</h3>
        <form className="space-y-4 max-w-sm" onSubmit={handleChangePassword}>
          <div>
            <label className="block text-sm text-text-secondary mb-2">Current password</label>
            <input 
              type="password" 
              placeholder="••••••••" 
              value={currentPassword}
              onChange={e => setCurrentPassword(e.target.value)}
              required
              className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" 
            />
          </div>
          <div>
            <label className="block text-sm text-text-secondary mb-2">New password</label>
            <input 
              type="password" 
              placeholder="Min. 8 characters" 
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              required
              minLength={8}
              className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" 
            />
          </div>
          <button disabled={loading} type="submit" className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">
            {loading ? "Updating..." : "Update Password"}
          </button>
        </form>
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
        <div className="px-6 py-4 border-b border-surface-border flex justify-between items-center">
          <h3 className="text-sm font-semibold text-text-primary">Active Sessions</h3>
          {lastLogin && <span className="text-xs text-text-muted">Last login: {lastLogin}</span>}
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
