import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Shield, CheckCircle2 } from "lucide-react";

const sections = [
  { title: "Information We Collect", items: [
    "Domain URLs you submit for scanning",
    "Account information (name, email) when you register",
    "Usage analytics to improve our platform",
    "Payment information processed securely via Stripe/Razorpay",
  ]},
  { title: "How We Use Your Data", items: [
    "To perform security scans on domains you submit",
    "To generate security reports and track score changes",
    "To send notifications you've configured (alerts, digests)",
    "To improve our scanning algorithms and platform reliability",
  ]},
  { title: "Data Retention", items: [
    "Scan results are retained for the duration of your subscription",
    "Free tier scans are retained for 30 days",
    "Deleted accounts have all data purged within 14 business days",
    "Backups are encrypted and retained for 30 days maximum",
  ]},
  { title: "Your Rights", items: [
    "Access: Request a copy of all data we hold about you",
    "Deletion: Request permanent deletion of your account and data",
    "Portability: Export your scan data in standard formats (JSON/CSV)",
    "Correction: Update or correct your personal information anytime",
    "Objection: Opt out of analytics and non-essential processing",
  ]},
  { title: "Third-Party Services", items: [
    "Cloud infrastructure: AWS (SOC 2 compliant)",
    "Payment processing: Stripe / Razorpay (PCI DSS Level 1)",
    "Analytics: Privacy-first analytics (no third-party cookies)",
    "Email: Transactional emails via SendGrid",
  ]},
];

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />
      <div className="max-w-4xl mx-auto px-6 pt-32 pb-20">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-nanz-400" />
          </div>
          <h1 className="text-headline text-text-primary">Privacy Policy</h1>
        </div>
        <p className="text-text-muted text-sm mb-12">Last updated: April 28, 2026</p>
        <p className="text-lg text-text-secondary mb-12 max-w-2xl">
          NANZ is committed to protecting your privacy. This policy explains what data we collect, how we use it, and your rights as a user.
        </p>

        <div className="space-y-8">
          {sections.map((s) => (
            <div key={s.title} className="rounded-card border border-card-border bg-card p-6">
              <h2 className="text-base font-semibold text-text-primary mb-4">{s.title}</h2>
              <ul className="space-y-2.5">
                {s.items.map((item) => (
                  <li key={item} className="flex items-start gap-2.5 text-sm text-text-secondary">
                    <CheckCircle2 className="w-4 h-4 text-nanz-400 mt-0.5 flex-shrink-0" /> {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <p className="text-sm text-text-muted mt-8">
          Questions? Contact us at <span className="text-nanz-400 font-medium">privacy@nanz.ai</span>
        </p>
      </div>
      <Footer />
    </div>
  );
}
