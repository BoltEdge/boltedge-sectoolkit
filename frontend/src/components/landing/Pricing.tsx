import Link from "next/link";
import { Check, Sparkles } from "lucide-react";

const plans = [
  {
    name: "Free", price: "$0", period: "/forever", desc: "Perfect for individual security professionals",
    features: ["All 91+ security tools", "Self-hosted engines", "Client-side processing", "Export to JSON/CSV", "Rate limited to fair use", "Community support"],
    cta: "Launch Toolkit", href: "/tools", style: "amber" as const,
  },
  {
    name: "Pro", price: "$29", period: "/mo", desc: "For teams and power users", popular: true,
    features: ["Everything in Free", "Bulk lookup mode", "API access", "Lookup history", "Team sharing", "Priority support", "No rate limits", "Custom integrations"],
    cta: "Get Started", href: "/register", style: "gradient" as const,
  },
  {
    name: "Enterprise", price: "Custom", period: "", desc: "For organisations with advanced needs",
    features: ["Everything in Pro", "On-premise deployment", "Custom tool development", "SLA guarantees", "Dedicated support", "Training & onboarding", "SSO & advanced security", "Custom data retention"],
    cta: "Contact Sales", href: "#contact", style: "outline" as const,
  },
];

export function Pricing() {
  return (
    <section id="pricing" className="relative z-10 px-6 py-24 text-center">
      <div className="mx-auto max-w-[1200px]">
        <div className="eyebrow mb-4">Pricing</div>
        <h2 className="text-[clamp(30px,4vw,44px)] font-bold text-white tracking-tight mb-4">Simple, transparent pricing</h2>
        <p className="text-base text-[#94a3b8] max-w-[560px] mx-auto">Start free, upgrade as you grow. No hidden fees.</p>
        <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-5 items-start">
          {plans.map(p => (
            <div key={p.name} className={`relative card-base p-9 text-left ${p.popular ? "border-[#d97706]/20 bg-[#d97706]/[0.015]" : ""}`}>
              {p.popular && (
                <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 inline-flex items-center gap-1.5 bg-[#d97706] text-white text-xs font-bold px-4 py-1 rounded-full whitespace-nowrap">
                  <Sparkles size={14} /> Most Popular
                </div>
              )}
              <div className="text-lg font-bold text-white mb-2">{p.name}</div>
              <div className="text-[40px] font-extrabold text-white tracking-tight leading-none mb-1">
                {p.price} <span className="text-base font-medium text-[#64748b]">{p.period}</span>
              </div>
              <div className="text-[13.5px] text-[#94a3b8] mb-7">{p.desc}</div>
              <ul className="space-y-3.5 mb-8">
                {p.features.map(f => (
                  <li key={f} className="flex items-start gap-2.5 text-sm text-[#94a3b8]">
                    <Check size={18} className="text-[#d97706] flex-shrink-0 mt-0.5" /> {f}
                  </li>
                ))}
              </ul>
              <Link href={p.href} className={`block w-full text-center py-3.5 rounded-xl text-sm font-semibold transition-all ${
                p.style === "amber" ? "bg-[#d97706] text-white hover:bg-[#f59e0b]" :
                p.style === "gradient" ? "bg-gradient-to-r from-[#d97706] to-[#f59e0b] text-white hover:shadow-[0_4px_20px_rgba(217,119,6,0.25)]" :
                "border border-[#d97706]/30 text-[#d97706] hover:bg-[#d97706]/[0.06]"
              }`}>
                {p.cta}
              </Link>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
