import Link from "next/link";
import { categories } from "@/lib/constants";
import { Globe, Globe2, Lock, Link as LinkIcon, Mail, Hash, Code, Wifi, Shield, KeyRound } from "lucide-react";

const iconMap: Record<string, React.ReactNode> = {
  Globe: <Globe size={20} />, Globe2: <Globe2 size={20} />, Lock: <Lock size={20} />,
  Link: <LinkIcon size={20} />, Mail: <Mail size={20} />, Hash: <Hash size={20} />,
  Code: <Code size={20} />, Wifi: <Wifi size={20} />, Shield: <Shield size={20} />,
  KeyRound: <KeyRound size={20} />,
};

export function ToolCategories() {
  return (
    <section id="tools" className="relative z-10 px-6 py-24">
      <div className="mx-auto max-w-[1200px] text-center">
        <h2 className="text-[clamp(30px,4vw,44px)] font-bold text-white tracking-tight leading-tight">Every tool you need. One place.</h2>
        <div className="mt-14 grid grid-cols-1 md:grid-cols-2 gap-5">
          {categories.map(cat => {
            const shown = cat.tools.slice(0, 6);
            const more = cat.tools.length - shown.length;
            return (
              <Link key={cat.id} href={`/tools/${cat.id}`} className="card-base card-hover p-7 text-left block group">
                <div className="flex items-center gap-3.5 mb-1.5">
                  <div className="w-[42px] h-[42px] rounded-[11px] flex items-center justify-center" style={{ background: `${cat.color}15`, color: cat.color }}>
                    {iconMap[cat.icon]}
                  </div>
                  <div>
                    <div className="text-[18px] font-bold text-white">{cat.name}</div>
                    <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: cat.color }}>{cat.tools.length} TOOLS</div>
                  </div>
                  <span className="ml-auto font-mono text-[11px] font-semibold rounded-lg px-2.5 py-0.5" style={{ background: `${cat.color}15`, color: cat.color }}>{cat.tools.length}</span>
                </div>
                <div className="flex flex-wrap gap-2 mt-4">
                  {shown.map(t => (
                    <span key={t.id} className="text-[12.5px] font-medium text-[#94a3b8] bg-white/[0.03] border border-white/[0.06] px-3 py-1.5 rounded-lg transition-colors group-hover:border-white/[0.1]">{t.name}</span>
                  ))}
                  {more > 0 && <span className="text-[12.5px] font-medium text-[#64748b] bg-white/[0.03] border border-white/[0.06] px-3 py-1.5 rounded-lg">+{more} more</span>}
                </div>
              </Link>
            );
          })}
        </div>
      </div>
    </section>
  );
}
