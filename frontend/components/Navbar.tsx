"use client";

import Link from "next/link";
import { useState, useRef, useEffect } from "react";
import { usePathname } from "next/navigation";
import { NanzLogo } from "@/components/ui/NanzLogo";
import { useAuthStore } from "@/store/authStore";
import ScanRecoveryBanner from "@/components/ScanRecoveryBanner";
import { LogOut, User as UserIcon, LayoutDashboard } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export default function Navbar() {
  const { user, signOut } = useAuthStore();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const pathname = usePathname();

  // Hide nav links on report/scan pages — keep it minimal
  const isReportPage = pathname.startsWith('/report/') || pathname.startsWith('/scan/');

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <>
      <nav className="fixed top-0 inset-x-0 z-50 h-16 border-b border-surface-border bg-background/70 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto h-full flex items-center justify-between px-6">
          <Link href="/">
            <NanzLogo size="sm" />
          </Link>

          {/* Nav links — hidden on report/scan pages */}
          {!isReportPage && (
            <div className="hidden md:flex items-center gap-8">
              <Link href="/#features" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Features</Link>
              <Link href="/#pricing" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Pricing</Link>
              <Link href="/status" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Status</Link>
              <Link href="/docs" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Docs</Link>
            </div>
          )}

          <div className="flex items-center gap-3">
            {user ? (
              <div className="relative" ref={dropdownRef}>
                <button
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                  className="w-9 h-9 rounded-full bg-nanz-500/20 border border-nanz-500/50 flex items-center justify-center text-nanz-300 font-bold hover:bg-nanz-500/30 transition-colors"
                >
                  {user.email ? user.email.charAt(0).toUpperCase() : <UserIcon className="w-4 h-4" />}
                </button>

                <AnimatePresence>
                  {dropdownOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: 10, scale: 0.95 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: 10, scale: 0.95 }}
                      transition={{ duration: 0.15 }}
                      className="absolute right-0 mt-2 w-56 bg-[#0A0A0C] border border-[#1E1E24] rounded-xl shadow-2xl overflow-hidden py-1"
                    >
                      <div className="px-4 py-3 border-b border-[#1E1E24] mb-1">
                        <p className="text-sm font-medium text-slate-200 truncate">{user.full_name || 'User'}</p>
                        <p className="text-xs text-slate-500 truncate mt-0.5">{user.email}</p>
                      </div>

                      <Link
                        href="/dashboard"
                        onClick={() => setDropdownOpen(false)}
                        className="flex items-center gap-2 px-4 py-2.5 text-sm text-slate-300 hover:bg-[#131316] hover:text-slate-100 transition-colors"
                      >
                        <LayoutDashboard className="w-4 h-4 text-slate-400" />
                        My Scans
                      </Link>

                      <button
                        onClick={() => {
                          signOut();
                          setDropdownOpen(false);
                        }}
                        className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-red-400 hover:bg-red-950/30 hover:text-red-300 transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ) : (
              !isReportPage && (
                <>
                  <Link href="/auth/login" className="text-sm text-text-secondary hover:text-text-primary transition-colors font-medium">Sign in</Link>
                  <Link href="/auth/register" className="px-4 py-2 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">Get Started</Link>
                </>
              )
            )}
          </div>
        </div>
      </nav>
      <ScanRecoveryBanner />
    </>
  );
}
