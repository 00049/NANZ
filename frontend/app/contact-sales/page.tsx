"use client";

import { useState } from "react";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { NanzLogo } from "@/components/ui/NanzLogo";
import { ArrowRight, CheckCircle2, Building2, Users, Globe } from "lucide-react";

export default function ContactSalesPage() {
  const [submitted, setSubmitted] = useState(false);

  if (submitted) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="text-center max-w-md">
            <div className="w-16 h-16 rounded-2xl bg-success/10 border border-success/20 flex items-center justify-center mx-auto mb-6">
              <CheckCircle2 className="w-8 h-8 text-success" />
            </div>
            <h1 className="text-2xl font-bold text-text-primary mb-3">Message received!</h1>
            <p className="text-text-secondary mb-8">Our team will reach out within 1 business day to schedule a personalized demo.</p>
            <a href="/" className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity inline-flex items-center gap-2">Back to Home <ArrowRight className="w-4 h-4" /></a>
          </div>
        </div>
        <Footer />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />
      <div className="max-w-5xl mx-auto px-6 pt-32 pb-20">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
          {/* Left - Info */}
          <div>
            <h1 className="text-headline text-text-primary mb-4">Talk to Sales</h1>
            <p className="text-text-secondary mb-10">
              Get a personalized demo, discuss enterprise pricing, or learn how NANZ can secure your organization.
            </p>

            <div className="space-y-6">
              {[
                { icon: Building2, title: "Enterprise Plans", desc: "Custom pricing, SLAs, and dedicated account management for large organizations" },
                { icon: Users, title: "Team Onboarding", desc: "White-glove setup, training, and migration support for your security team" },
                { icon: Globe, title: "Custom Integrations", desc: "Connect NANZ to your existing SIEM, ticketing, and DevOps workflows" },
              ].map((item) => (
                <div key={item.title} className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-lg bg-surface flex items-center justify-center flex-shrink-0">
                    <item.icon className="w-5 h-5 text-nanz-400" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-text-primary mb-1">{item.title}</h3>
                    <p className="text-xs text-text-secondary">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right - Form */}
          <div className="rounded-card border border-card-border bg-card p-6">
            <form onSubmit={(e) => { e.preventDefault(); setSubmitted(true); }} className="space-y-5">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-text-secondary mb-2">First name</label>
                  <input required placeholder="Jane" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all" />
                </div>
                <div>
                  <label className="block text-sm text-text-secondary mb-2">Last name</label>
                  <input required placeholder="Smith" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all" />
                </div>
              </div>
              <div>
                <label className="block text-sm text-text-secondary mb-2">Work email</label>
                <input type="email" required placeholder="jane@company.com" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all" />
              </div>
              <div>
                <label className="block text-sm text-text-secondary mb-2">Company</label>
                <input required placeholder="Acme Corp" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all" />
              </div>
              <div>
                <label className="block text-sm text-text-secondary mb-2">Number of domains</label>
                <select className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary focus:border-nanz-500 outline-none transition-all appearance-none">
                  <option>1-10</option><option>11-50</option><option>51-200</option><option>200+</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-text-secondary mb-2">Message</label>
                <textarea rows={4} placeholder="Tell us about your security needs..." className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all resize-none" />
              </div>
              <button type="submit" className="w-full py-3 rounded-btn bg-nanz-gradient text-white text-sm font-semibold hover:opacity-90 transition-opacity flex items-center justify-center gap-2">
                Send Message <ArrowRight className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}
