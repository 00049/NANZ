"use client";

import { currentUser } from "@/lib/mock-data";
import { Camera } from "lucide-react";

export default function ProfilePage() {
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
            {currentUser.name.split(" ").map(n => n[0]).join("")}
          </div>
          <button className="absolute inset-0 bg-black/50 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
            <Camera className="w-5 h-5 text-white" />
          </button>
        </div>
        <div>
          <div className="text-lg font-semibold text-text-primary">{currentUser.name}</div>
          <div className="text-sm text-text-muted">{currentUser.email}</div>
        </div>
      </div>

      {/* Form */}
      <form className="space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Full name</label>
            <input defaultValue={currentUser.name} className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Email address</label>
            <input defaultValue={currentUser.email} type="email" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Company</label>
            <input defaultValue={currentUser.company} className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all" />
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
          <button type="button" className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">
            Save Changes
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
