"use client";

import { useState } from "react";
import { Key, Plus, Copy, Trash2, Code, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";

const mockKeys = [
  { id: "key_01", name: "Production API Key", prefix: "nanz_live_", lastUsed: "2 hours ago", created: "2026-03-15", status: "active" },
  { id: "key_02", name: "Development Key", prefix: "nanz_test_", lastUsed: "5 days ago", created: "2026-04-01", status: "active" },
];

const exampleCode = `curl -X POST https://api.nanz.ai/v1/scans \\
  -H "Authorization: Bearer nanz_live_sk_..." \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com"}'`;

export default function APIPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-title text-text-primary">API Keys</h1>
        <p className="text-sm text-text-secondary mt-1">Manage API keys for programmatic access to NANZ</p>
      </div>

      {/* Keys */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-text-primary">Active Keys</h3>
          <button className="px-3 py-1.5 rounded-btn bg-nanz-gradient text-white text-xs font-medium hover:opacity-90 transition-opacity flex items-center gap-1.5"><Plus className="w-3.5 h-3.5" /> Generate Key</button>
        </div>
        <div className="divide-y divide-surface-border">
          {mockKeys.map((key) => (
            <div key={key.id} className="flex items-center justify-between px-5 py-4">
              <div className="flex items-center gap-3">
                <Key className="w-4 h-4 text-text-muted" />
                <div>
                  <div className="text-sm font-medium text-text-primary">{key.name}</div>
                  <div className="text-xs text-text-muted font-mono">{key.prefix}••••••••••</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-text-muted">Last used {key.lastUsed}</span>
                <button className="p-1.5 rounded hover:bg-surface transition-colors text-text-muted hover:text-text-secondary"><Copy className="w-3.5 h-3.5" /></button>
                <button className="p-1.5 rounded hover:bg-critical/10 transition-colors text-text-muted hover:text-critical"><Trash2 className="w-3.5 h-3.5" /></button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Example */}
      <div className="rounded-card border border-card-border bg-card p-5">
        <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2 mb-4"><Code className="w-4 h-4 text-nanz-400" /> Example Request</h3>
        <pre className="bg-background rounded-btn p-4 text-xs text-text-secondary font-mono overflow-x-auto border border-surface-border">{exampleCode}</pre>
        <div className="mt-4 flex items-center gap-4">
          <a href="#" className="text-xs text-nanz-400 hover:text-nanz-300 transition-colors flex items-center gap-1">Full documentation <ExternalLink className="w-3 h-3" /></a>
          <span className="text-xs text-text-muted">Rate limit: 100 requests/min (Pro), 500/min (Business)</span>
        </div>
      </div>
    </div>
  );
}
