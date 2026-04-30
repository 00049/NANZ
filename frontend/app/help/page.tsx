import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { HelpCircle, Book, MessageSquare, Mail, ExternalLink } from "lucide-react";
import Link from "next/link";

const helpTopics = [
  { title: "Account & Billing", desc: "Manage your subscription, invoices, and team seats", items: ["Reset password", "Change plan", "Cancel subscription", "Download invoices", "Add team members"] },
  { title: "Scanning & Reports", desc: "Learn how to run scans and interpret results", items: ["Start a scan", "Understanding severity levels", "Export reports as PDF", "Share public report links", "Compare scan results"] },
  { title: "Monitoring & Alerts", desc: "Set up continuous monitoring and notifications", items: ["Configure scan schedules", "Set up Slack alerts", "Email digest settings", "Custom alert triggers", "Pause monitoring"] },
  { title: "Technical & Integrations", desc: "API access, webhooks, and integrations", items: ["Generate API keys", "Webhook setup", "Rate limits", "Troubleshooting scan errors", "Browser compatibility"] },
];

export default function HelpPage() {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />
      <div className="max-w-5xl mx-auto px-6 pt-32 pb-20">
        <div className="text-center mb-14">
          <h1 className="text-headline text-text-primary mb-4">Help Center</h1>
          <p className="text-text-secondary max-w-lg mx-auto">Find answers to common questions and get support</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-12">
          {helpTopics.map((topic) => (
            <div key={topic.title} className="rounded-card border border-card-border bg-card p-6 hover:border-surface-border-light transition-all">
              <h3 className="text-base font-semibold text-text-primary mb-1">{topic.title}</h3>
              <p className="text-xs text-text-muted mb-4">{topic.desc}</p>
              <div className="space-y-2">
                {topic.items.map((item) => (
                  <div key={item} className="text-sm text-text-secondary hover:text-nanz-400 transition-colors cursor-pointer">→ {item}</div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="rounded-card border border-card-border bg-card p-8 text-center">
          <MessageSquare className="w-8 h-8 text-nanz-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-text-primary mb-2">Still need help?</h3>
          <p className="text-sm text-text-secondary mb-6 max-w-md mx-auto">Our support team typically responds within 2 hours during business hours.</p>
          <div className="flex items-center justify-center gap-3">
            <Link href="/contact-sales" className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity">Contact Support</Link>
            <Link href="/docs" className="px-5 py-2.5 rounded-btn border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary transition-colors">View Docs</Link>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}
