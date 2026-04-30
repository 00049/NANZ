"use client";

import { teamMembers } from "@/lib/mock-data";
import { getRoleLabel, getRoleBadgeColor } from "@/lib/rbac";
import { cn } from "@/lib/utils";
import { Users, Plus, MoreHorizontal, Mail } from "lucide-react";
import Link from "next/link";
import { NanzLogo } from "@/components/ui/NanzLogo";

export default function WorkspacePage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Simple top bar */}
      <header className="flex items-center justify-between h-16 px-6 border-b border-surface-border">
        <div className="flex items-center gap-4">
          <Link href="/dashboard" className="text-text-muted hover:text-text-secondary text-sm">← Dashboard</Link>
          <div className="w-px h-6 bg-surface-border" />
          <NanzLogo size="sm" />
        </div>
      </header>

      <div className="max-w-4xl mx-auto p-6 lg:p-10 space-y-8">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-title text-text-primary flex items-center gap-2"><Users className="w-5 h-5 text-nanz-400" /> Workspace</h1>
            <p className="text-sm text-text-secondary mt-1">Manage team members and roles</p>
          </div>
          <button className="px-4 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2">
            <Plus className="w-4 h-4" /> Invite Member
          </button>
        </div>

        {/* Members */}
        <div className="rounded-card border border-card-border bg-card overflow-hidden">
          <div className="grid grid-cols-[1fr_120px_140px_48px] gap-4 px-5 py-3 border-b border-surface-border text-xs font-medium text-text-muted uppercase tracking-wider">
            <span>Member</span><span>Role</span><span>Joined</span><span />
          </div>
          {teamMembers.map((member) => (
            <div key={member.id} className="grid grid-cols-[1fr_120px_140px_48px] gap-4 px-5 py-4 border-b border-surface-border last:border-b-0 hover:bg-surface-hover/50 transition-colors items-center">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-full bg-nanz-gradient flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
                  {member.name.split(" ").map(n => n[0]).join("")}
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-text-primary truncate">{member.name}</div>
                  <div className="text-xs text-text-muted truncate">{member.email}</div>
                </div>
              </div>
              <div>
                <span className={cn("inline-block px-2 py-1 rounded text-xs font-medium border", getRoleBadgeColor(member.role))}>
                  {getRoleLabel(member.role)}
                </span>
              </div>
              <div className="text-xs text-text-muted">{new Date(member.createdAt).toLocaleDateString()}</div>
              <button className="p-1.5 rounded hover:bg-surface transition-colors text-text-muted hover:text-text-secondary">
                <MoreHorizontal className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
