"use client";

import Image from "next/image";
import { cn } from "@/lib/utils";

interface NanzLogoProps {
  size?: "sm" | "md" | "lg" | "xl";
  /** When true, shows only the N icon mark (for collapsed sidebars). */
  showText?: boolean;
  className?: string;
}

/**
 * NanzLogo — renders the official NAANZ logo image.
 *
 * The source PNG (1774 × 887px) has black background padding around the content.
 * We scale the image larger than its container and use overflow:hidden +
 * absolute positioning to crop away the padding — producing a tight,
 * professional logo exactly like real companies display theirs.
 *
 * When `showText={false}` (collapsed sidebar), only the left N-icon is shown.
 *
 * Size reference (visible container height):
 *   sm  → 36px   – navbars, sidebars, compact headers
 *   md  → 44px   – standard headers
 *   lg  → 56px   – auth pages, marketing sections
 *   xl  → 72px   – hero / onboarding
 */
export function NanzLogo({ size = "md", showText = true, className }: NanzLogoProps) {
  const containerH: Record<string, number> = {
    sm: 36,
    md: 44,
    lg: 56,
    xl: 72,
  };

  const h = containerH[size] ?? 44;

  // ── Full wordmark mode ─────────────────────────────────────────────────────
  // The logo content occupies ~68% of the image height and ~88% of the width.
  // Scale the image up so content fills the container height, then clip padding.
  if (showText) {
    const scale = 1 / 0.68;
    const imgH = Math.round(h * scale);
    const imgW = imgH * 2; // image is 1774×887 ≈ 2:1
    const containerW = Math.round(imgW * 0.82); // clip right padding too

    return (
      <div
        className={cn("flex-shrink-0", className)}
        style={{ width: containerW, height: h, overflow: "hidden", position: "relative" }}
      >
        <Image
          src="/naanz-logo.png"
          alt="NAANZ"
          width={imgW}
          height={imgH}
          priority
          style={{
            width: imgW,
            height: imgH,
            position: "absolute",
            top: Math.round(-imgH * 0.13),  // trim top black padding
            left: Math.round(-imgW * 0.05), // trim left black padding
          }}
          className="select-none pointer-events-none"
        />
      </div>
    );
  }

  // ── Icon-only mode (collapsed sidebar) ────────────────────────────────────
  // The N icon mark occupies the left ~28% of the image width.
  // Show a square container that crops to just the icon.
  const iconSize = h;
  const imgH = Math.round(h / 0.68);
  const imgW = imgH * 2;

  return (
    <div
      className={cn("flex-shrink-0", className)}
      style={{ width: iconSize, height: iconSize, overflow: "hidden", position: "relative" }}
    >
      <Image
        src="/naanz-logo.png"
        alt="NAANZ"
        width={imgW}
        height={imgH}
        priority
        style={{
          width: imgW,
          height: imgH,
          position: "absolute",
          top: Math.round(-imgH * 0.13),
          left: Math.round(-imgW * 0.05),
        }}
        className="select-none pointer-events-none"
      />
    </div>
  );
}
