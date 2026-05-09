"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight } from "lucide-react";
import { toast } from "sonner";
import { URLInputCard } from "./components/URLInputCard";
import { ScanOptionsCard, ScanOptions } from "./components/ScanOptionsCard";
import { RecentDomainsCard } from "./components/RecentDomainsCard";
import { WhatWeCheckCard } from "./components/WhatWeCheckCard";
import { startScan, listScans } from "@/lib/api";
import { useScanStore } from "@/store/scanStore";

export default function NewScanPage() {
  const router = useRouter();
  const { initScan } = useScanStore();
  const [url, setUrl] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [options, setOptions] = useState<ScanOptions>({
    oast: true,
    llm: true,
    dpdp: true,
    cve: true,
    graphql: true,
  });

  const [recentScans, setRecentScans] = useState<any[]>([]);

  useEffect(() => {
    // Fetch recent scans
    listScans(10, 0)
      .then((data) => setRecentScans(data.scans || []))
      .catch((err) => console.error("Failed to fetch recent scans:", err));
  }, []);

  const handleDomainSelect = (domainUrl: string) => {
    setUrl(domainUrl);
    setError(null);
  };

  const handleScan = async () => {
    setError(null);

    if (!url) {
      setError("Please enter a URL");
      return;
    }

    if (!url.startsWith("https://") && !url.startsWith("http://")) {
      setError("Must start with https://");
      return;
    }

    // Basic private IP check
    const isPrivateIP = /^(https?:\/\/)?(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|localhost)/.test(url);
    if (isPrivateIP) {
      setError("Cannot scan private addresses");
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await startScan(url, options);
      
      initScan(response.scan_id, url);

      // Store in localStorage as requested
      localStorage.setItem("shieldcheck_active_scan", JSON.stringify({
        scanId: response.scan_id,
        url,
        options,
        timestamp: new Date().toISOString()
      }));

      // Navigate to scan progress page (same as landing page)
      router.push(`/scan/${response.scan_id}`);
    } catch (err: any) {
      console.error(err);
      toast.error("Failed to start scan. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12">
      {/* Page Header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <div className="text-[12px] text-text-muted mb-1">
            Dashboard / <span className="text-white">New Scan</span>
          </div>
          <h1 className="text-white text-[28px] font-bold">New Scan</h1>
          <p className="text-[#9CA3AF] text-[14px] mt-1">
            Configure and launch a security audit across 29 modules
          </p>
        </div>
        <Link 
          href="/dashboard/history"
          className="text-[#00A8FF] hover:text-[#1AB5FF] text-[14px] font-medium transition-colors flex items-center gap-1.5 pt-4"
        >
          View Scan History <ArrowRight className="w-4 h-4" />
        </Link>
      </div>

      {/* Main Content Area */}
      <div className="space-y-6">
        {/* URL Input Card */}
        <URLInputCard
          url={url}
          setUrl={(val) => { setUrl(val); setError(null); }}
          onScan={handleScan}
          isSubmitting={isSubmitting}
          error={error}
        />

        {/* Grid for Options and Recent Domains */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          <div className="lg:col-span-3">
            <ScanOptionsCard options={options} onOptionsChange={setOptions} />
          </div>
          <div className="lg:col-span-2">
            <RecentDomainsCard scans={recentScans} onDomainSelect={handleDomainSelect} />
          </div>
        </div>

        {/* What We Check Card */}
        <WhatWeCheckCard />
      </div>
    </div>
  );
}
