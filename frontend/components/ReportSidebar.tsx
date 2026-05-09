// WHAT THIS FILE DOES: Enterprise-grade fixed sidebar for the report page. Uses
// IntersectionObserver to highlight the active section.
// KEY DEPENDENCIES: react, lucide-react, framer-motion
// MOCKED DATA: None.

'use client';

import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, Server, Shield, Globe, HardDrive, Key, Activity, Users, CheckSquare, List, ServerCog
} from 'lucide-react';

interface ReportSidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

const SECTIONS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'role-view', label: 'Role View', icon: Users },
  { id: 'aspm-posture', label: 'ASPM Posture', icon: Activity },
  { id: 'owasp-coverage', label: 'OWASP Coverage', icon: Shield },
  { id: 'dependency-scan', label: 'Dependencies', icon: Server },
  { id: 'llm-security', label: 'AI/LLM Security', icon: ServerCog },
  { id: 'compliance', label: 'Compliance', icon: CheckSquare },
  { id: 'brand-threats', label: 'Brand Protection', icon: Globe },
  { id: 'email-security', label: 'Email Security', icon: Key },
  { id: 'technology-stack', label: 'Tech Stack', icon: HardDrive },
  { id: 'all-findings', label: 'All Findings', icon: List },
];

export default function ReportSidebar({ isOpen, onClose }: ReportSidebarProps) {
  const [activeSection, setActiveSection] = useState('overview');

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const intersecting = entries.filter((entry) => entry.isIntersecting);
        if (intersecting.length > 0) {
          intersecting.sort((a, b) => b.intersectionRatio - a.intersectionRatio);
          setActiveSection(intersecting[0].target.id);
        }
      },
      { rootMargin: '-80px 0px -40% 0px', threshold: [0, 0.25, 0.5, 0.75, 1] }
    );

    SECTIONS.forEach((section) => {
      const el = document.getElementById(section.id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, []);

  const handleNavClick = (id: string) => {
    setActiveSection(id);
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
    onClose();
  };

  const SidebarContent = (
    <div className="h-full flex flex-col py-4">
      <div className="px-4 mb-4">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Report Navigation</h3>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 space-y-1">
        {SECTIONS.map((section) => {
          const isActive = activeSection === section.id;
          const Icon = section.icon;
          return (
            <button
              key={section.id}
              onClick={() => handleNavClick(section.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${isActive
                  ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent'
                }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
              {section.label}
            </button>
          );
        })}
      </nav>
    </div>
  );

  return (
    <>
      {/* Mobile Overlay */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-40 lg:hidden"
          />
        )}
      </AnimatePresence>

      {/* Desktop Sidebar — always visible */}
      <aside className="hidden lg:flex fixed top-16 bottom-0 left-0 w-[260px] bg-[#060608] border-r border-[#1E1E24] z-30 flex-col">
        {SidebarContent}
      </aside>

      {/* Mobile Sidebar — slide in/out */}
      <AnimatePresence>
        {isOpen && (
          <motion.aside
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed top-16 bottom-0 left-0 w-[260px] bg-[#060608] border-r border-[#1E1E24] z-50 lg:hidden flex flex-col"
          >
            {SidebarContent}
          </motion.aside>
        )}
      </AnimatePresence>
    </>
  );
}
