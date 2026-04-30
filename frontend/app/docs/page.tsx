import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Book, Code, Zap, Globe, Shield, BarChart3, FileText, Bell, ExternalLink } from "lucide-react";
import Link from "next/link";

const docCategories = [
  { icon: Zap, title: "Getting Started", desc: "Quick start guide, first scan, and dashboard setup", links: ["Quick Start Guide", "Running Your First Scan", "Understanding Your Score", "Dashboard Overview"] },
  { icon: Code, title: "API Reference", desc: "REST API documentation for programmatic access", links: ["Authentication", "Scan Endpoints", "Report Endpoints", "Webhooks", "Rate Limits"] },
  { icon: Globe, title: "Domain Management", desc: "Adding, verifying, and managing your domains", links: ["Adding Domains", "DNS Verification", "Monitoring Configuration", "Domain Groups"] },
  { icon: Shield, title: "Security Modules", desc: "Deep dive into each scanning module", links: ["SSL/TLS Analysis", "DNS Security", "Port Scanning", "Header Analysis", "Cloud Exposure", "CMS CVE Detection"] },
  { icon: BarChart3, title: "Reports & Analytics", desc: "Understanding and sharing reports", links: ["Reading Reports", "Export PDF", "Share Public Link", "Trend Analysis", "Compliance Reports"] },
  { icon: Bell, title: "Integrations", desc: "Connect NANZ to your workflow", links: ["Slack Integration", "Discord Webhooks", "Email Alerts", "API Webhooks", "Zapier (Coming Soon)"] },
];

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />
      <div className="max-w-5xl mx-auto px-6 pt-32 pb-20">
        <div className="text-center mb-14">
          <h1 className="text-headline text-text-primary mb-4">Documentation</h1>
          <p className="text-text-secondary max-w-lg mx-auto">Everything you need to get the most out of NANZ</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {docCategories.map((cat) => (
            <div key={cat.title} className="rounded-card border border-card-border bg-card p-5 hover:border-surface-border-light transition-all group">
              <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center mb-4">
                <cat.icon className="w-5 h-5 text-nanz-400" />
              </div>
              <h3 className="text-sm font-semibold text-text-primary mb-1">{cat.title}</h3>
              <p className="text-xs text-text-muted mb-4">{cat.desc}</p>
              <div className="space-y-1.5">
                {cat.links.map((link) => (
                  <div key={link} className="text-xs text-text-secondary hover:text-nanz-400 transition-colors cursor-pointer flex items-center gap-1.5">
                    <FileText className="w-3 h-3" /> {link}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
      <Footer />
    </div>
  );
}
