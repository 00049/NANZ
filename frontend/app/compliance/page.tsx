import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Shield, CheckCircle2, Clock, AlertTriangle } from "lucide-react";

const frameworks = [
  { name: "DPDP Act", status: "active", description: "India's Digital Personal Data Protection Act compliance assessment built into every scan." },
  { name: "GDPR", status: "active", description: "General Data Protection Regulation readiness checks for EU-facing applications." },
  { name: "SOC 2 Type II", status: "in-progress", description: "Service Organization Controls audit for our own infrastructure. Target: Q3 2026." },
  { name: "ISO 27001", status: "planned", description: "Information Security Management System certification. Target: Q4 2026." },
  { name: "PCI DSS", status: "planned", description: "Payment Card Industry compliance assessment modules. On roadmap." },
  { name: "HIPAA", status: "planned", description: "Healthcare data protection readiness scanning. On roadmap." },
];

const statusConfig = {
  active: { label: "Active", icon: CheckCircle2, cls: "text-success" },
  "in-progress": { label: "In Progress", icon: Clock, cls: "text-medium" },
  planned: { label: "Planned", icon: AlertTriangle, cls: "text-text-muted" },
};

export default function CompliancePage() {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />
      <div className="max-w-4xl mx-auto px-6 pt-32 pb-20">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-nanz-400" />
          </div>
          <h1 className="text-headline text-text-primary">Compliance</h1>
        </div>
        <p className="text-lg text-text-secondary mb-12 max-w-2xl">
          NANZ helps organizations meet regulatory requirements through automated compliance assessments and continuous monitoring.
        </p>

        <div className="space-y-4">
          {frameworks.map((fw) => {
            const st = statusConfig[fw.status as keyof typeof statusConfig];
            return (
              <div key={fw.name} className="rounded-card border border-card-border bg-card p-6 flex items-start justify-between gap-6">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h2 className="text-base font-semibold text-text-primary">{fw.name}</h2>
                    <span className={`flex items-center gap-1 text-xs font-medium ${st.cls}`}>
                      <st.icon className="w-3.5 h-3.5" /> {st.label}
                    </span>
                  </div>
                  <p className="text-sm text-text-secondary">{fw.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
      <Footer />
    </div>
  );
}
