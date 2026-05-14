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

  // The logo content occupies exactly 50.6% of the image height.
  // Scale the image up so the content exactly fills the container height `h`.
  const scale = 1 / 0.506;
  const imgH = h * scale;
  const imgW = imgH * 2; // Image is 1774x887 (2:1)
  
  // Trimming offsets based on exact bounding box
  const topOffset = Math.round(-imgH * 0.291);
  const leftOffset = Math.round(-imgW * 0.0705);

  if (showText) {
    // Content width is 0.8545
    const containerW = Math.round(imgW * 0.8545);

    return (
      <div
        className={cn("flex-shrink-0 flex items-center justify-center", className)}
        style={{ width: containerW, height: h, overflow: "hidden", position: "relative" }}
      >
        <Image
          src="/naanz-logo.png"
          alt="NAANZ"
          width={Math.round(imgW)}
          height={Math.round(imgH)}
          priority
          style={{
            width: Math.round(imgW),
            height: Math.round(imgH),
            maxWidth: "none",
            position: "absolute",
            top: topOffset,
            left: leftOffset,
            mixBlendMode: "screen",
          }}
          className="select-none pointer-events-none"
        />
      </div>
    );
  }

  // Icon-only mode (collapsed sidebar)
  // Reduced from 0.244 to 0.235 to eliminate the small line bleed from the next letter
  const iconW = Math.round(imgW * 0.235);

  return (
    <div
      className={cn("flex-shrink-0 flex items-center justify-center", className)}
      style={{ width: iconW, height: h, overflow: "hidden", position: "relative" }}
    >
      <Image
        src="/naanz-logo.png"
        alt="NAANZ"
        width={Math.round(imgW)}
        height={Math.round(imgH)}
        priority
        style={{
          width: Math.round(imgW),
          height: Math.round(imgH),
          maxWidth: "none",
          position: "absolute",
          top: topOffset,
          left: leftOffset,
          mixBlendMode: "screen",
        }}
        className="select-none pointer-events-none"
      />
    </div>
  );
}
