"use client";

import { useState, useEffect } from "react";
import { Camera } from "lucide-react";
import { toast } from "sonner";
import { useAuthStore } from "@/store/authStore";

export default function ProfilePage() {
  const { token } = useAuthStore();
  const [profile, setProfile] = useState({ name: "", email: "", company: "" });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function fetchProfile() {
      if (!token) return;
      try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/auth/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setProfile({ name: data.name || "", email: data.email || "", company: data.company || "" });
        }
      } catch (err) {
        console.error("Failed to load profile", err);
      }
    }
    fetchProfile();
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setLoading(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/auth/me`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ name: profile.name, company: profile.company })
      });
      if (res.ok) {
        toast.success("Profile updated successfully!");
      } else {
        toast.error("Failed to update profile.");
      }
    } catch (err) {
      toast.error("An error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-title text-text-primary">Profile</h1>
        <p className="text-sm text-text-secondary mt-1">Manage your personal information</p>
      </div>

      {/* Avatar */}
      <div className="flex items-center gap-5">
        <div className="relative group">
          <div className="w-20 h-20 rounded-2xl bg-nanz-gradient flex items-center justify-center text-2xl font-bold text-white">
            {profile.name ? profile.name.split(" ").map(n => n[0]).join("").slice(0, 2).toUpperCase() : "?"}
          </div>
          <button className="absolute inset-0 bg-black/50 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
            <Camera className="w-5 h-5 text-white" />
          </button>
        </div>
        <div>
          <div className="text-lg font-semibold text-text-primary">{profile.name || "Your Name"}</div>
          <div className="text-sm text-text-muted">{profile.email}</div>
        </div>
      </div>

      {/* Form */}
      <form className="space-y-6" onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Full name</label>
            <input 
              value={profile.name} 
              onChange={e => setProfile({...profile, name: e.target.value})}
              className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" 
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Email address</label>
            <input 
              value={profile.email} 
              disabled
              type="email" 
              className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary opacity-50 cursor-not-allowed outline-none transition-all" 
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Company</label>
            <input 
              value={profile.company} 
              onChange={e => setProfile({...profile, company: e.target.value})}
              className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" 
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Timezone</label>
            <select className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all appearance-none">
              <option>Asia/Kolkata (IST)</option>
              <option>America/New_York (EST)</option>
              <option>Europe/London (GMT)</option>
            </select>
          </div>
        </div>
        <div className="flex justify-end pt-2">
          <button disabled={loading} type="submit" className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">
            {loading ? "Saving..." : "Save Changes"}
          </button>
        </div>
      </form>

      {/* Danger Zone */}
      <div className="rounded-card border border-critical/20 bg-critical/5 p-6">
        <h3 className="text-sm font-semibold text-critical mb-2">Danger Zone</h3>
        <p className="text-xs text-text-muted mb-4">Permanently delete your account and all associated data. This action cannot be undone.</p>
        <button className="px-4 py-2 rounded-btn border border-critical/30 text-critical text-sm font-medium hover:bg-critical/10 transition-colors">
          Delete Account
        </button>
      </div>
    </div>
  );
}
