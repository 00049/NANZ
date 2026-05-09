"use client";

import * as Switch from "@radix-ui/react-switch";
import { cn } from "@/lib/utils";

export interface ScanOptions {
  oast: boolean;
  llm: boolean;
  dpdp: boolean;
  cve: boolean;
  graphql: boolean;
}

interface ScanOptionsCardProps {
  options: ScanOptions;
  onOptionsChange: (options: ScanOptions) => void;
}

const optionItems = [
  {
    id: "oast" as keyof ScanOptions,
    label: "Include OAST Detection",
    description: "Out-of-band blind vulnerability detection"
  },
  {
    id: "llm" as keyof ScanOptions,
    label: "LLM / AI Security Audit",
    description: "Detect OWASP LLM Top 10 risks"
  },
  {
    id: "dpdp" as keyof ScanOptions,
    label: "DPDP Compliance Mapping",
    description: "Map findings to DPDP Act sections"
  },
  {
    id: "cve" as keyof ScanOptions,
    label: "CVE Intelligence (NVD)",
    description: "Enrich findings with EPSS + CISA KEV data"
  },
  {
    id: "graphql" as keyof ScanOptions,
    label: "GraphQL Security Scan",
    description: "Detect GraphQL endpoint vulnerabilities"
  }
];

export function ScanOptionsCard({ options, onOptionsChange }: ScanOptionsCardProps) {
  const handleToggle = (id: keyof ScanOptions, checked: boolean) => {
    onOptionsChange({ ...options, [id]: checked });
  };

  return (
    <div className="bg-[#111111] border border-[#1E1E1E] rounded-xl p-6 lg:p-8 h-full flex flex-col">
      <div className="mb-6">
        <h2 className="text-white text-lg font-semibold">Scan Configuration</h2>
        <p className="text-text-muted text-sm mt-1">All options are set to maximum coverage by default</p>
      </div>

      <div className="space-y-4 flex-1">
        {optionItems.map((item) => (
          <div key={item.id} className="flex items-start justify-between py-2">
            <div className="flex items-start gap-3 pr-4">
              <div className="mt-1">
                <div className={cn(
                  "w-1.5 h-1.5 rounded-full",
                  options[item.id] ? "bg-[#00A8FF]" : "bg-[#2A2A2A]"
                )} />
              </div>
              <div>
                <div className="text-white text-[15px] font-medium">{item.label}</div>
                <div className="text-text-muted text-[13px] mt-0.5">{item.description}</div>
              </div>
            </div>
            <Switch.Root
              checked={options[item.id]}
              onCheckedChange={(checked) => handleToggle(item.id, checked)}
              className={cn(
                "w-[42px] h-[24px] rounded-full relative transition-colors focus:outline-none focus:ring-2 focus:ring-[#00A8FF] focus:ring-offset-2 focus:ring-offset-[#111111]",
                options[item.id] ? "bg-[#00A8FF]" : "bg-[#2A2A2A]"
              )}
            >
              <Switch.Thumb
                className={cn(
                  "block w-[18px] h-[18px] bg-white rounded-full transition-transform",
                  options[item.id] ? "translate-x-[21px]" : "translate-x-[3px]"
                )}
              />
            </Switch.Root>
          </div>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t border-[#1E1E1E]">
        <p className="text-[12px] text-text-muted">
          Pro tip: All modules enabled gives the most comprehensive results. Disabling modules speeds up the scan.
        </p>
      </div>
    </div>
  );
}
