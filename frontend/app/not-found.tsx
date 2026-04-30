import Link from "next/link";
import { NanzLogo } from "@/components/ui/NanzLogo";

export default function NotFound() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 text-center bg-background relative">
      <div className="absolute inset-0 bg-grid-pattern opacity-20" />
      <div className="relative z-10">
        <NanzLogo size="lg" className="justify-center mb-10" />
        <div className="text-[120px] font-bold leading-none text-gradient-chrome opacity-20">404</div>
        <h1 className="text-2xl font-bold text-text-primary mt-4">Page not found</h1>
        <p className="text-text-secondary mt-2 max-w-md">The page you&apos;re looking for doesn&apos;t exist or has been moved.</p>
        <div className="flex items-center gap-3 justify-center mt-8">
          <Link href="/" className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">Go Home</Link>
          <Link href="/dashboard" className="px-5 py-2.5 rounded-btn border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors">Dashboard</Link>
        </div>
      </div>
    </div>
  );
}
