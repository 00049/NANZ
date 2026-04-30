"use client";

import { useState } from "react";
import { NanzLogo } from "@/components/ui/NanzLogo";
import { cn } from "@/lib/utils";
import { ArrowRight, Globe, Shield, Activity, Users, CheckCircle2, Search, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { createDomain } from "@/lib/api";
import { useAuthStore } from "@/store/authStore";

const steps = [
  { title: "Welcome to NANZ", description: "Enterprise security intelligence starts here", icon: Shield },
  { title: "Add your first domain", description: "Enter the domain you want to secure", icon: Globe },
  { title: "Run your first scan", description: "We'll analyze your domain for vulnerabilities", icon: Search },
  { title: "Enable monitoring", description: "Get alerted when your security posture changes", icon: Activity },
  { title: "Invite your team", description: "Collaborate on security with your colleagues", icon: Users },
  { title: "You're all set!", description: "Your security command center is ready", icon: CheckCircle2 },
];

export default function OnboardingPage() {
  const [step, setStep] = useState(0);
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const token = useAuthStore(state => state.token);

  const current = steps[step];

  const handleComplete = async () => {
    if (domain && token) {
      setLoading(true);
      try {
        await createDomain(token, domain);
      } catch (err) {
        console.error("Failed to create domain during onboarding", err);
      }
    }
    router.push("/dashboard");
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-background relative">
      <div className="absolute inset-0 bg-grid-pattern opacity-20" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-nanz-600/5 rounded-full blur-[120px]" />

      <div className="relative z-10 w-full max-w-lg">
        <div className="text-center mb-10">
          <NanzLogo size="lg" className="justify-center mb-8" />
          {/* Progress */}
          <div className="flex items-center justify-center gap-2 mb-8">
            {steps.map((_, i) => (
              <div key={i} className={cn("h-1 rounded-full transition-all", i <= step ? "bg-nanz-500 w-8" : "bg-surface-border w-4")} />
            ))}
          </div>
        </div>

        <div className="rounded-panel border border-card-border bg-card p-8 text-center">
          <div className="w-14 h-14 rounded-2xl bg-nanz-gradient-subtle border border-nanz-600/20 flex items-center justify-center mx-auto mb-6">
            <current.icon className="w-7 h-7 text-nanz-400" />
          </div>
          <h2 className="text-xl font-bold text-text-primary mb-2">{current.title}</h2>
          <p className="text-sm text-text-secondary mb-8">{current.description}</p>

          {/* Step content */}
          {step === 1 && (
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all mb-6 text-center"
            />
          )}
          {step === 3 && (
            <div className="flex items-center justify-center gap-3 mb-6">
              {["Daily", "Weekly", "Monthly"].map((freq) => (
                <button key={freq} className="px-4 py-2 rounded-btn border border-surface-border text-sm text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors">{freq}</button>
              ))}
            </div>
          )}
          {step === 4 && (
            <input placeholder="colleague@company.com" className="w-full px-4 py-3 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all mb-6 text-center" />
          )}

          <div className="flex items-center justify-center gap-3">
            {step > 0 && step < steps.length - 1 && (
              <button onClick={() => setStep(step - 1)} className="px-5 py-2.5 rounded-btn border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary transition-colors">Back</button>
            )}
            {step < steps.length - 1 ? (
              <button onClick={() => setStep(step + 1)} className="px-6 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2">
                {step === 0 ? "Get Started" : "Continue"} <ArrowRight className="w-4 h-4" />
              </button>
            ) : (
              <button onClick={handleComplete} disabled={loading} className="px-6 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2">
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <>Go to Dashboard <ArrowRight className="w-4 h-4" /></>}
              </button>
            )}
          </div>

          {step > 0 && step < steps.length - 1 && (
            <button onClick={() => setStep(step + 1)} className="text-xs text-text-muted hover:text-text-secondary transition-colors mt-4 block mx-auto">Skip this step</button>
          )}
        </div>
      </div>
    </div>
  );
}
