import Link from "next/link";
import { ArrowRight } from "lucide-react";

export function Hero() {
  return (
    <section className="relative z-10 px-6 pt-[180px] pb-[120px] text-center">
      <div className="mx-auto max-w-[1440px] px-12">
        <div className="mb-10 inline-flex items-center gap-2.5 rounded-full border border-[#f97316]/20 bg-[#f97316]/[0.05] px-6 py-2.5">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping-slow rounded-full bg-[#f97316] opacity-75"></span>
            <span className="relative inline-flex h-2 w-2 rounded-full bg-[#f97316]"></span>
          </span>
          <span className="text-[14px] font-medium text-[#f97316] tracking-wide">Now Available</span>
        </div>

        <h1 className="mx-auto mb-7 max-w-[750px] text-[clamp(32px,3.5vw,48px)] font-bold leading-[1.2] tracking-[-0.02em] text-white">
          Stop juggling 15 browser tabs.
        </h1>

        <p className="mx-auto mb-12 max-w-[560px] text-[17px] leading-[1.7] text-[#94a3b8]">
          Get all your security tools in one place. No signup required. Start analysing now.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-5">
          <Link
            href="/tools"
            className="inline-flex items-center gap-2.5 rounded-[16px] bg-[#f97316] px-12 py-[18px] text-[16px] font-semibold text-white transition-all hover:bg-[#fb923c] hover:shadow-[0_4px_20px_rgba(249,115,22,0.25)] hover:-translate-y-px"
          >
            Launch Toolkit <ArrowRight size={18} />
          </Link>
          <a
            href="#contact"
            className="inline-flex items-center gap-2 rounded-[16px] border border-white/20 px-12 py-[18px] text-[16px] font-semibold text-white transition-all hover:border-white/35 hover:bg-white/5"
          >
            Contact Sales
          </a>
        </div>

        <div className="flex gap-24 justify-center mt-16">
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight">91+ tools</div>
            <div className="label-mono mt-2">Security Tools</div>
          </div>
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight">10</div>
            <div className="label-mono mt-2">Categories</div>
          </div>
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight italic">Free</div>
            <div className="label-mono mt-2">To Use</div>
          </div>
        </div>
      </div>
    </section>
  );
}