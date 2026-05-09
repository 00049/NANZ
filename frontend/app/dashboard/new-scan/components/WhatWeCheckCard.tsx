"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

const modules = [
  // Infrastructure (blue dot)
  { name: "SSL/TLS Analysis", category: "Infrastructure", color: "bg-[#00A8FF]" },
  { name: "Security Headers", category: "Infrastructure", color: "bg-[#00A8FF]" },
  { name: "DNS & Email", category: "Infrastructure", color: "bg-[#00A8FF]" },
  { name: "Port & Service Scan", category: "Infrastructure", color: "bg-[#00A8FF]" },
  { name: "WAF & CDN Detection", category: "Infrastructure", color: "bg-[#00A8FF]" },
  { name: "Email Security Deep Scan", category: "Infrastructure", color: "bg-[#00A8FF]" },
  { name: "Performance & DDoS", category: "Infrastructure", color: "bg-[#00A8FF]" },

  // Web Security (blue dot)
  { name: "Web Application Security", category: "Web Security", color: "bg-[#00A8FF]" },
  { name: "CORS Misconfiguration", category: "Web Security", color: "bg-[#00A8FF]" },
  { name: "HTTP Methods Audit", category: "Web Security", color: "bg-[#00A8FF]" },
  { name: "Cookie & Session Security", category: "Web Security", color: "bg-[#00A8FF]" },
  { name: "JavaScript Source Analysis", category: "Web Security", color: "bg-[#00A8FF]" },
  { name: "Cloud Storage Exposure", category: "Web Security", color: "bg-[#00A8FF]" },

  // Application (blue dot)
  { name: "OWASP API Top 10", category: "Application", color: "bg-[#00A8FF]" },
  { name: "GraphQL Security", category: "Application", color: "bg-[#00A8FF]" },
  { name: "Business Logic Analysis", category: "Application", color: "bg-[#00A8FF]" },
  { name: "IaC & Container Exposure", category: "Application", color: "bg-[#00A8FF]" },
  { name: "Software Composition (SCA)", category: "Application", color: "bg-[#00A8FF]" },
  { name: "JWT & OAuth Audit", category: "Application", color: "bg-[#00A8FF]" },
  { name: "Crawl Intelligence", category: "Application", color: "bg-[#00A8FF]" },
  { name: "Technology Inventory", category: "Application", color: "bg-[#00A8FF]" },
  { name: "Subdomain & Infrastructure", category: "Application", color: "bg-[#00A8FF]" },

  // Intelligence (amber dot)
  { name: "CVE Intelligence (NVD)", category: "Intelligence", color: "bg-[#F59E0B]" },
  { name: "EPSS Risk Scoring", category: "Intelligence", color: "bg-[#F59E0B]" },
  { name: "CISA KEV Catalog", category: "Intelligence", color: "bg-[#F59E0B]" },
  { name: "Threat Intelligence", category: "Intelligence", color: "bg-[#F59E0B]" },
  { name: "Brand Protection", category: "Intelligence", color: "bg-[#F59E0B]" },
  { name: "OAST Detection", category: "Intelligence", color: "bg-[#F59E0B]" },
  { name: "IAST Behavioral Analysis", category: "Intelligence", color: "bg-[#F59E0B]" },

  // AI / Compliance (pink + purple dots)
  { name: "LLM / AI Security (OWASP LLM 2025)", category: "AI / Compliance", color: "bg-[#EC4899]" },
  { name: "DPDP Act 2023 Compliance", category: "AI / Compliance", color: "bg-[#8B5CF6]" },
];

export function WhatWeCheckCard() {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="bg-[#111111] border border-[#1E1E1E] rounded-xl overflow-hidden">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between p-6 text-left hover:bg-[#1E1E1E]/50 transition-colors"
      >
        <span className="text-white text-[15px] font-medium">
          {isExpanded ? "Hide details" : "What does this scan check?"}
        </span>
        {isExpanded ? (
          <ChevronUp className="w-5 h-5 text-text-muted" />
        ) : (
          <ChevronDown className="w-5 h-5 text-text-muted" />
        )}
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="p-6 pt-0 border-t border-[#1E1E1E]">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mt-6">
                {modules.map((module, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2.5 bg-[#0D0D0D] border border-[#1E1E1E] px-3 py-2 rounded-md"
                  >
                    <div className={cn("w-2 h-2 rounded-full shrink-0", module.color)} />
                    <span className="text-text-muted text-[13px] truncate" title={module.name}>
                      {module.name}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
