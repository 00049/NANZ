"use client";

import { useState } from "react";
import { Globe, ArrowRight, Shield, Clock, Lock, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface URLInputCardProps {
  url: string;
  setUrl: (url: string) => void;
  onScan: () => void;
  isSubmitting: boolean;
  error?: string | null;
}

export function URLInputCard({ url, setUrl, onScan, isSubmitting, error }: URLInputCardProps) {
  const [isFocused, setIsFocused] = useState(false);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !isSubmitting) {
      onScan();
    }
  };

  const isValidFormat = url.length > 0 && url.startsWith("https://");

  return (
    <div className={cn(
      "bg-[#111111] border rounded-xl p-8 transition-colors",
      isFocused ? "border-[#00A8FF]/30 shadow-[0_0_0_1px_rgba(0,168,255,0.25)]" : "border-[#1E1E1E]"
    )}>
      {/* Label Row */}
      <div className="flex items-center justify-between mb-4">
        <label className="text-white text-sm font-medium">Target URL</label>
        <div className="flex items-center gap-1.5 bg-[#0D0D0D] px-2.5 py-1 rounded-full border border-[#1E1E1E]">
          <div className="w-1.5 h-1.5 rounded-full bg-[#00E5A0]" />
          <span className="text-[12px] text-text-muted">29 modules will run</span>
        </div>
      </div>

      {/* Input Field */}
      <div className="relative mb-3">
        <div className="absolute left-4 top-1/2 -translate-y-1/2 text-text-muted">
          <Globe className="w-4.5 h-4.5" />
        </div>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          onKeyDown={handleKeyDown}
          disabled={isSubmitting}
          placeholder="https://yourwebsite.com"
          className="w-full h-[52px] bg-[#0D0D0D] border border-[#2A2A2A] focus:border-[#00A8FF] focus:bg-[#0F1117] rounded-lg pl-11 pr-11 text-[16px] text-white placeholder:text-text-muted transition-colors outline-none disabled:opacity-50"
        />
        {url.length > 0 && (
          <div className="absolute right-4 top-1/2 -translate-y-1/2">
            {isValidFormat ? (
              <CheckCircle2 className="w-4.5 h-4.5 text-[#00E5A0]" />
            ) : (
              <XCircle className="w-4.5 h-4.5 text-critical" />
            )}
          </div>
        )}
      </div>

      {/* Error Message */}
      {error && (
        <div className="text-critical text-sm mb-3 flex items-center gap-1.5">
          <XCircle className="w-4 h-4" />
          {error}
        </div>
      )}

      {/* Protocol Hints */}
      <div className="flex items-center gap-2 mb-6">
        <button
          onClick={() => setUrl("https://" + url.replace(/^https?:\/\//, ""))}
          className="text-[12px] text-text-muted hover:text-white hover:bg-[#1E1E1E] px-2 py-1 rounded transition-colors"
        >
          https://
        </button>
        <button
          onClick={() => setUrl("http://" + url.replace(/^https?:\/\//, ""))}
          className="text-[12px] text-text-muted hover:text-white hover:bg-[#1E1E1E] px-2 py-1 rounded transition-colors"
        >
          http://
        </button>
      </div>

      {/* Scan Button */}
      <button
        onClick={onScan}
        disabled={isSubmitting || (!isValidFormat && url.length > 0)}
        className="w-full h-[48px] bg-[#00A8FF] hover:bg-[#1AB5FF] text-white rounded-lg font-semibold text-[15px] flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {isSubmitting ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Preparing scan...
          </>
        ) : (
          <>
            Launch Security Audit <ArrowRight className="w-4 h-4" />
          </>
        )}
      </button>

      {/* Trust Row */}
      <div className="flex items-center justify-center gap-6 mt-5 text-[12px] text-text-muted">
        <div className="flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5" />
          <span>Passive scan only</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5" />
          <span>~60–90 seconds</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Lock className="w-3.5 h-3.5" />
          <span>No data stored after 90 days</span>
        </div>
      </div>
    </div>
  );
}
