'use client';

import { useScanStore } from '../store/scanStore';
import { Loader2, CheckCircle2, AlertTriangle, Circle } from 'lucide-react';
import { useEffect, useState } from 'react';

const MODULES = [
  { key: 'waf_check', label: 'WAF & CDN Detection' },
  { key: 'ssl_check', label: 'SSL Certificate Analysis' },
  { key: 'headers_check', label: 'Security Headers Check' },
  { key: 'dns_check', label: 'DNS & Email Security' },
  { key: 'port_check', label: 'Open Port Scanning' },
  { key: 'breach_check', label: 'Data Breach History' },
  { key: 'cms_check', label: 'CMS & Plugin Security' },
  { key: 'cookie_check', label: 'Cookie Security' },
  { key: 'webapp_check', label: 'Web Application Security' },
  { key: 'reputation_check', label: 'Threat Intelligence' },
  { key: 'javascript_check', label: 'JavaScript Source Analysis' },
  { key: 'cors_check', label: 'CORS Configuration' },
  { key: 'http_methods_check', label: 'HTTP Methods Check' },
  { key: 'cloud_exposure_check', label: 'Cloud Storage Exposure' },
  { key: 'email_security_check', label: 'Email Security Deep Scan' }
];

export default function ScanProgress() {
  const { progress } = useScanStore();

  // Normalize status — backend writes 'complete', some paths write 'completed'
  const norm = (s?: string) => {
    if (s === 'complete' || s === 'completed') return 'done';
    return s || 'pending';
  };

  const getModStatus = (key: string) => {
    const s = progress[key];
    if (s === 'queued' || s === 'retrying') return 'pending';
    return s || 'pending';
  };
  
  const getStatusIcon = (raw?: string) => {
    const status = norm(raw);
    switch(status) {
      case 'done': return <CheckCircle2 className="text-low w-5 h-5" />;
      case 'failed': return <AlertTriangle className="text-medium w-5 h-5" />;
      case 'running': return <Loader2 className="text-primary w-5 h-5 animate-spin" />;
      case 'pending':
      default: return <Circle className="text-card-border w-5 h-5" />;
    }
  };

  const getStatusText = (raw?: string) => {
    const status = norm(raw);
    switch(status) {
      case 'done': return 'Complete';
      case 'failed': return 'Degraded';
      case 'running': return 'Running...';
      case 'pending':
      default: return 'Pending';
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto bg-surface border border-card-border rounded-card p-6 shadow-2xl">
      <h3 className="text-lg font-semibold mb-4 text-text-primary border-b border-card-border pb-2">Running 15 Security Modules</h3>
      <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
        {MODULES.map(mod => {
          const status = getModStatus(mod.key);
          const n = norm(status);
          return (
            <div key={mod.key} className="flex items-center justify-between p-3 rounded-md bg-background border border-card-border transition-colors hover:border-primary/50">
              <div className="flex items-center gap-3">
                {getStatusIcon(status)}
                <span className={`font-medium ${n === 'done' ? 'text-text-primary' : 'text-text-muted'}`}>
                  {mod.label}
                </span>
              </div>
              <span className={`text-xs font-semibold px-2 py-1 rounded-full ${
                n === 'done' ? 'bg-low/10 text-low' : 
                n === 'failed' ? 'bg-medium/10 text-medium' :
                n === 'running' ? 'bg-primary/10 text-primary animate-pulse' :
                'bg-card-border/50 text-text-muted'
              }`}>
                {getStatusText(status).toUpperCase()}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
