"use client";

import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { plans, currentSubscription } from "@/lib/mock-data";
import { Check, Zap, Download, CreditCard, AlertTriangle } from "lucide-react";
import { useAuthStore } from "@/store/authStore";

export default function BillingPage() {
  const { token } = useAuthStore();
  const [annual, setAnnual] = useState(false);
  const [invoices, setInvoices] = useState<any[]>([]);
  const currentPlan = plans.find(p => p.id === currentSubscription.planId)!;

  useEffect(() => {
    async function fetchHistory() {
      if (!token) return;
      try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/payments/history`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setInvoices(data);
        }
      } catch (err) {
        console.error("Failed to fetch payment history", err);
      }
    }
    fetchHistory();
  }, [token]);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-title text-text-primary">Billing</h1>
        <p className="text-sm text-text-secondary mt-1">Manage your subscription and payment methods</p>
      </div>

      {/* Current Plan */}
      <div className="rounded-card border border-nanz-600/30 bg-nanz-gradient-subtle p-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Zap className="w-4 h-4 text-nanz-400" />
              <span className="text-xs font-medium text-nanz-400 uppercase tracking-wider">Current Plan</span>
            </div>
            <h2 className="text-2xl font-bold text-text-primary">{currentPlan.name}</h2>
            <p className="text-sm text-text-secondary mt-1">${currentPlan.monthlyPrice}/month · Renews {new Date(currentSubscription.currentPeriodEnd).toLocaleDateString()}</p>
          </div>
          <button className="px-4 py-2.5 rounded-btn border border-surface-border bg-surface text-sm font-medium text-text-secondary hover:text-text-primary transition-colors">Manage Subscription</button>
        </div>
      </div>

      {/* Usage */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          { label: "Scans Used", used: currentSubscription.scansUsed, limit: currentSubscription.scansLimit, unit: "scans" },
          { label: "Domains", used: currentSubscription.domainsUsed, limit: currentSubscription.domainsLimit, unit: "domains" },
          { label: "Team Seats", used: currentSubscription.seatsUsed, limit: currentSubscription.seatsLimit, unit: "seats" },
        ].map((item) => {
          const pct = (item.used / item.limit) * 100;
          const isOver = pct > 100;
          return (
            <div key={item.label} className="rounded-card border border-card-border bg-card p-5">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium text-text-muted">{item.label}</span>
                {isOver && <AlertTriangle className="w-3.5 h-3.5 text-medium" />}
              </div>
              <div className="text-lg font-bold text-text-primary">{item.used} <span className="text-text-muted font-normal text-sm">/ {item.limit}</span></div>
              <div className="mt-3 h-1.5 rounded-full bg-surface overflow-hidden">
                <div className={cn("h-full rounded-full transition-all", isOver ? "bg-medium" : pct > 80 ? "bg-medium" : "bg-nanz-500")} style={{ width: `${Math.min(pct, 100)}%` }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Plans */}
      <div>
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-sm font-semibold text-text-primary">Available Plans</h3>
          <div className="flex items-center gap-2 bg-surface rounded-btn p-1">
            <button onClick={() => setAnnual(false)} className={cn("px-3 py-1.5 rounded text-xs font-medium transition-colors", !annual ? "bg-surface-active text-text-primary" : "text-text-muted")}>Monthly</button>
            <button onClick={() => setAnnual(true)} className={cn("px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1", annual ? "bg-surface-active text-text-primary" : "text-text-muted")}>
              Yearly <span className="text-success text-[10px]">Save 20%</span>
            </button>
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {plans.map((plan) => {
            const isCurrent = plan.id === currentSubscription.planId;
            const price = annual ? plan.yearlyPrice : plan.monthlyPrice;
            return (
              <div key={plan.id} className={cn("rounded-card border p-5 transition-all", isCurrent ? "border-nanz-600/40 bg-nanz-600/5" : "border-card-border bg-card hover:border-surface-border-light")}>
                {plan.popular && <div className="text-[10px] font-bold text-nanz-400 uppercase tracking-wider mb-2">Most Popular</div>}
                <h4 className="text-base font-semibold text-text-primary">{plan.name}</h4>
                <div className="mt-2 mb-4">
                  <span className="text-2xl font-bold text-text-primary">${price}</span>
                  {price > 0 && <span className="text-sm text-text-muted">/mo</span>}
                </div>
                <ul className="space-y-2 mb-5">
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-start gap-2 text-xs text-text-secondary">
                      <Check className="w-3.5 h-3.5 text-nanz-400 mt-0.5 flex-shrink-0" /> {f}
                    </li>
                  ))}
                </ul>
                <button className={cn("w-full py-2.5 rounded-btn text-sm font-medium transition-all", isCurrent ? "bg-surface border border-surface-border text-text-muted cursor-default" : "bg-nanz-gradient text-white hover:opacity-90")}>
                  {isCurrent ? "Current Plan" : "Upgrade"}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Invoices */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-text-primary">Invoice History</h3>
        </div>
        <div className="divide-y divide-surface-border">
          {invoices.length === 0 ? (
            <div className="px-5 py-4 text-sm text-text-muted">No payment history found.</div>
          ) : invoices.map((inv) => (
            <div key={inv.order_id} className="flex items-center justify-between px-5 py-4">
              <div className="flex items-center gap-4">
                <CreditCard className="w-4 h-4 text-text-muted" />
                <div>
                  <div className="text-sm text-text-primary">{inv.created_at ? new Date(inv.created_at).toLocaleDateString("en-US", { month: "long", year: "numeric", day: "numeric" }) : "N/A"}</div>
                  <div className="text-xs text-text-muted">Full Report · ₹{inv.amount} · {inv.domain}</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={cn("text-xs font-medium px-2 py-1 rounded", inv.status === "paid" ? "bg-success/10 text-success" : "bg-medium/10 text-medium")}>
                  {inv.status}
                </span>
                <button className="text-text-muted hover:text-text-secondary transition-colors"><Download className="w-4 h-4" /></button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
