import Link from "next/link";
import { ArrowRight, Mail } from "lucide-react";

export function CtaBand() {
  return (
    <section className="relative z-10 px-6 py-20">
      <div className="mx-auto max-w-[1440px] px-12">
        <div
          className="rounded-3xl border border-white/[0.08] p-16 text-center relative overflow-hidden"
          style={{
            background: "radial-gradient(ellipse at 50% 30%, rgba(249,115,22,0.06), transparent 65%), rgba(255,255,255,0.01)",
          }}
        >
          <h2 className="text-[clamp(24px,3vw,36px)] font-bold text-white tracking-tight mb-4">
            Stop juggling 15 browser tabs.
          </h2>
          <p className="text-[15px] text-[#94a3b8] mb-8">
            Get all your security tools in one place. No signup required. Start analyzing now.
          </p>
          <div className="flex flex-wrap gap-4 justify-center">
            <Link
              href="/tools"
              className="inline-flex items-center gap-2.5 rounded-[16px] bg-[#f97316] px-10 py-[16px] text-[15px] font-semibold text-white transition-all hover:bg-[#fb923c] hover:shadow-[0_4px_20px_rgba(249,115,22,0.25)]"
            >
              Launch Toolkit <ArrowRight size={18} />
            </Link>
            <a
              href="#contact"
              className="inline-flex items-center gap-2 rounded-[16px] border border-white/20 px-10 py-[16px] text-[15px] font-semibold text-white hover:border-white/35 hover:bg-white/5 transition-all"
            >
              <Mail size={18} /> Contact Sales
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}