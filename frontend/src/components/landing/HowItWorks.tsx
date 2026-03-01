import { ClipboardList, Cpu, Eye, Share2 } from "lucide-react";

const steps = [
  { icon: <ClipboardList size={28} />, title: "Paste any input", desc: "IP, domain, hash, URL, or email" },
  { icon: <Cpu size={28} />, title: "Engine processes it", desc: "Self-hosted or client-side analysis" },
  { icon: <Eye size={28} />, title: "See structured results", desc: "Clean tables and visualisations" },
  { icon: <Share2 size={28} />, title: "Export and share", desc: "JSON, CSV, or copy to clipboard" },
];

export function HowItWorks() {
  return (
    <section id="features" className="relative z-10 px-6 py-24 text-center">
      <div className="mx-auto max-w-[1200px]">
        <div className="eyebrow mb-4">How It Works</div>
        <h2 className="text-[clamp(30px,4vw,44px)] font-bold text-white tracking-tight">Simple. Fast. Powerful.</h2>
        <div className="mt-14 flex flex-col md:flex-row items-start justify-center gap-0">
          {steps.map((s, i) => (
            <div key={i} className="relative flex-1 max-w-[240px] text-center">
              <div className="relative z-10 mx-auto mb-5 w-[72px] h-[72px] rounded-[18px] border border-[#d97706]/15 bg-[#d97706]/[0.06] flex items-center justify-center text-[#d97706]">
                {s.icon}
              </div>
              {i < steps.length - 1 && (
                <div className="hidden md:block absolute top-[36px] left-[calc(50%+36px)] w-[calc(100%-72px)] h-px bg-[#d97706]/15 z-0" />
              )}
              <div className="text-[15px] font-semibold text-white mb-1.5">{s.title}</div>
              <div className="text-[13px] text-[#94a3b8] leading-relaxed">{s.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
