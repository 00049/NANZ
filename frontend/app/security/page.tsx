import { NanzLogo } from "@/components/ui/NanzLogo";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Shield, Lock, Server, Eye, Globe, FileText, CheckCircle2 } from "lucide-react";
import Link from "next/link";

const sections = [
  { icon: Lock, title: "Data Encryption", items: ["AES-256 encryption at rest", "TLS 1.3 for all data in transit", "End-to-end encrypted scan results", "Encrypted backups with 30-day retention"] },
  { icon: Server, title: "Infrastructure Security", items: ["SOC 2 compliant cloud infrastructure", "Isolated scan environments per customer", "Automatic security patching", "DDoS protection and WAF enabled", "Multi-region redundancy"] },
  { icon: Eye, title: "Access Controls", items: ["Role-based access control (RBAC)", "Multi-factor authentication support", "Session management and audit logging", "IP allowlisting for API access", "SSO integration (SAML 2.0)"] },
  { icon: Globe, title: "Scan Safety", items: ["All scans are passive and non-intrusive", "No exploitation or payload injection", "Read-only reconnaissance only", "Respects robots.txt directives", "Rate-limited to prevent target impact"] },
  { icon: FileText, title: "Compliance", items: ["GDPR-ready data handling", "DPDP Act compliant processing", "SOC 2 Type II (in progress)", "ISO 27001 alignment", "Annual third-party penetration testing"] },
];

export default function SecurityPage() {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />
      <div className="max-w-4xl mx-auto px-6 pt-32 pb-20">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-nanz-400" />
          </div>
          <h1 className="text-headline text-text-primary">Security</h1>
        </div>
        <p className="text-lg text-text-secondary mb-12 max-w-2xl">
          Security is foundational to everything we build at NANZ. We protect your data with enterprise-grade controls, transparency, and continuous improvement.
        </p>

        <div className="space-y-8">
          {sections.map((s) => (
            <div key={s.title} className="rounded-card border border-card-border bg-card p-6">
              <div className="flex items-center gap-3 mb-4">
                <s.icon className="w-5 h-5 text-nanz-400" />
                <h2 className="text-base font-semibold text-text-primary">{s.title}</h2>
              </div>
              <ul className="space-y-2.5">
                {s.items.map((item) => (
                  <li key={item} className="flex items-start gap-2.5 text-sm text-text-secondary">
                    <CheckCircle2 className="w-4 h-4 text-success mt-0.5 flex-shrink-0" /> {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="rounded-card border border-card-border bg-card p-6 mt-8">
          <h2 className="text-base font-semibold text-text-primary mb-3">Responsible Disclosure</h2>
          <p className="text-sm text-text-secondary mb-4">
            Found a vulnerability? We welcome responsible security disclosures. Report issues to <span className="text-nanz-400 font-medium">security@nanz.ai</span> and we&apos;ll respond within 24 hours.
          </p>
          <Link href="/contact-sales" className="text-sm text-nanz-400 hover:text-nanz-300 font-medium transition-colors">Contact our security team →</Link>
        </div>
      </div>
      <Footer />
    </div>
  );
}
