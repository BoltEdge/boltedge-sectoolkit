import { Logo } from "@/components/ui/Logo";
import Link from "next/link";

export function Footer() {
  return (
    <footer className="relative z-10 border-t border-white/[0.06] pt-16 pb-8">
      <div className="mx-auto max-w-[1200px] px-6">
        <div className="grid grid-cols-1 md:grid-cols-[2fr_1fr_1fr] gap-12 mb-12">
          <div>
            <Logo />
            <p className="mt-4 text-sm text-[#94a3b8] max-w-[380px] leading-relaxed">The security toolkit built for analysts, by analysts. 91+ tools, custom engines, one dashboard.</p>
            <p className="mt-3 text-[13px] text-[#64748b]">A product by <a href="https://sectoolkit101.com" className="text-[#d97706] hover:underline">SecToolkit 101</a></p>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-white mb-4">Products</h4>
            <a href="https://easm.sectoolkit101.com" className="block text-sm text-[#94a3b8] hover:text-white mb-2.5">SecToolkit 101 EASM</a>
            <a href="https://sectoolkit101.com/#services" className="block text-sm text-[#94a3b8] hover:text-white mb-2.5">Security Services</a>
            <Link href="/tools" className="block text-sm text-[#94a3b8] hover:text-white">SecToolkit</Link>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-white mb-4">Support</h4>
            <Link href="/docs" className="block text-sm text-[#94a3b8] hover:text-white mb-2.5">API Docs</Link>
            <a href="mailto:contact@sectoolkit101.com" className="block text-sm text-[#94a3b8] hover:text-white mb-2.5">support@sectoolkit101.com</a>
            <a href="#contact" className="block text-sm text-[#94a3b8] hover:text-white">Contact Us</a>
          </div>
        </div>
        <div className="flex justify-between items-center pt-6 border-t border-white/[0.06] text-[13px] text-[#64748b]">
          <span>&copy; 2026 SecToolkit 101. All rights reserved.</span>
          <div className="flex gap-6">
            <Link href="/privacy" className="hover:text-[#94a3b8]">Privacy</Link>
            <Link href="/terms" className="hover:text-[#94a3b8]">Terms</Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
