"use client";

import { cn } from "@/lib/utils";

interface NanzLogoProps {
  size?: "sm" | "md" | "lg" | "xl";
  showText?: boolean;
  className?: string;
}

export function NanzLogo({ size = "md", showText = true, className }: NanzLogoProps) {
  const sizes = {
    sm: { icon: "w-6 h-6", text: "text-base" },
    md: { icon: "w-8 h-8", text: "text-lg" },
    lg: { icon: "w-10 h-10", text: "text-xl" },
    xl: { icon: "w-14 h-14", text: "text-2xl" },
  };

  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      {/* Geometric shield icon inspired by the NANZ logo */}
      <div className={cn("relative flex-shrink-0", sizes[size].icon)}>
        <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
          {/* Outer shield shape */}
          <path
            d="M20 2L4 10V22C4 30 10 36 20 38C30 36 36 30 36 22V10L20 2Z"
            fill="url(#nanz-gradient)"
            fillOpacity="0.15"
            stroke="url(#nanz-gradient)"
            strokeWidth="1.5"
          />
          {/* Inner N letterform */}
          <path
            d="M13 28V14L20 22V14M20 14V28L27 20V28"
            stroke="url(#nanz-gradient)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Center glow dot */}
          <circle cx="20" cy="34" r="1.5" fill="#0A8CFF" opacity="0.8" />
          <defs>
            <linearGradient id="nanz-gradient" x1="4" y1="2" x2="36" y2="38" gradientUnits="userSpaceOnUse">
              <stop stopColor="#38BDF8" />
              <stop offset="1" stopColor="#0A8CFF" />
            </linearGradient>
          </defs>
        </svg>
      </div>
      {showText && (
        <span className={cn("font-bold tracking-[0.15em] text-gradient-chrome", sizes[size].text)}>
          NANZ
        </span>
      )}
    </div>
  );
}
