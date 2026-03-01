"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { Logo } from "@/components/ui/Logo";
import { ArrowUpRight } from "lucide-react";

const links = [
  { label: "Features", href: "/#features" },
  { label: "Tools", href: "/#tools" },
  { label: "Pricing", href: "/#pricing" },
  { label: "API Docs", href: "/docs" },
];

export function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const h = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", h);
    return () => window.removeEventListener("scroll", h);
  }, []);

  return (
    <nav className={`fixed top-0 left-0 right-0 z-50 px-6 transition-all duration-300 border-b ${scrolled ? "border-white/[0.06] bg-[#060b18]/88 backdrop-blur-xl" : "border-transparent bg-transparent"}`}>
      <div className="mx-auto flex h-[64px] max-w-[1440px] px-12 items-center justify-between">
        <Logo />
        <div className="hidden md:flex items-center gap-9">
          {links.map(l => (
            <Link key={l.label} href={l.href} className="text-[14px] font-medium text-[#94a3b8] hover:text-white transition-colors">{l.label}</Link>
          ))}
        </div>
        <Link href="/tools" className="hidden md:inline-flex items-center gap-2 rounded-xl bg-[#f97316] px-6 py-2.5 text-[13px] font-semibold text-white transition-all hover:bg-[#fb923c] hover:shadow-[0_4px_20px_rgba(249,115,22,0.25)] hover:-translate-y-px">
          Launch Toolkit <ArrowUpRight size={14} strokeWidth={2.5} />
        </Link>
      </div>
    </nav>
  );
}