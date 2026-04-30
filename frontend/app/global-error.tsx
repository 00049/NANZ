"use client";

import { NanzLogo } from "@/components/ui/NanzLogo";

export default function GlobalError({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col items-center justify-center p-6 text-center bg-[#030303] text-[#F0F0F5]">
        <NanzLogo size="lg" className="justify-center mb-10" />
        <div className="text-[80px] font-bold leading-none opacity-10">500</div>
        <h1 className="text-2xl font-bold mt-4">Something went wrong</h1>
        <p className="text-[#8B8B9E] mt-2 max-w-md text-sm">An unexpected error occurred. Our team has been notified.</p>
        <button onClick={reset} className="mt-8 px-5 py-2.5 rounded-lg bg-gradient-to-r from-[#0A8CFF] to-[#38BDF8] text-white text-sm font-medium hover:opacity-90 transition-opacity">
          Try Again
        </button>
      </body>
    </html>
  );
}
