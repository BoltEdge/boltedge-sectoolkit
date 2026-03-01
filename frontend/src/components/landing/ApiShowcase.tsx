import Link from "next/link";
import { ArrowRight, Code } from "lucide-react";

export function ApiShowcase() {
  return (
    <section id="api" className="relative z-10 px-6 py-24 text-center">
      <div className="mx-auto max-w-[1200px]">
        <div className="eyebrow mb-4">API Access</div>
        <h2 className="text-[clamp(30px,4vw,44px)] font-bold text-white tracking-tight mb-4">Programmatic Access</h2>
        <p className="text-base text-[#94a3b8] max-w-[560px] mx-auto">Integrate SecToolkit into your security workflows with our REST API.</p>
        <div className="mt-12 grid grid-cols-1 md:grid-cols-2 gap-5">
          <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-2xl p-6 text-left overflow-hidden">
            <div className="flex items-center gap-2 mb-5">
              <Code size={16} className="text-[#d97706]" />
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-[#d97706]">Request</span>
            </div>
            <pre className="font-mono text-[13px] leading-[1.8] text-[#94a3b8] whitespace-pre-wrap break-all">
{`curl -X POST https://api.sectoolkit.boltedge.co/v1/ip/geolocation \\
  -H `}<span className="text-[#d97706]">{`"Authorization: Bearer YOUR_API_KEY"`}</span>{` \\
  -H `}<span className="text-[#d97706]">{`"Content-Type: application/json"`}</span>{` \\
  -d `}<span className="text-[#d97706]">{`'{"ip": "8.8.8.8"}'`}</span></pre>
          </div>
          <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-2xl p-6 text-left overflow-hidden">
            <div className="flex items-center gap-2 mb-5">
              <Code size={16} className="text-[#d97706]" />
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-[#d97706]">Response</span>
            </div>
            <pre className="font-mono text-[13px] leading-[1.8] text-[#94a3b8] whitespace-pre-wrap">
<span className="text-[#64748b]">{"{"}</span>{`
  `}<span className="text-[#06b6d4]">{`"ip"`}</span>{`: `}<span className="text-[#d97706]">{`"8.8.8.8"`}</span>{`,
  `}<span className="text-[#06b6d4]">{`"location"`}</span>{`: `}<span className="text-[#d97706]">{`"Mountain View, California, United States"`}</span>{`,
  `}<span className="text-[#06b6d4]">{`"coordinates"`}</span>{`: `}<span className="text-[#d97706]">{`"37.4056,-122.0775"`}</span>{`,
  `}<span className="text-[#06b6d4]">{`"asn"`}</span>{`: `}<span className="text-[#d97706]">{`"AS15169"`}</span>{`,
  `}<span className="text-[#06b6d4]">{`"organization"`}</span>{`: `}<span className="text-[#d97706]">{`"Google LLC"`}</span>{`,
  `}<span className="text-[#06b6d4]">{`"timezone"`}</span>{`: `}<span className="text-[#d97706]">{`"America/Los_Angeles"`}</span>{`,
  `}<span className="text-[#06b6d4]">{`"threat_level"`}</span>{`: `}<span className="text-[#d97706]">{`"low"`}</span>{`
`}<span className="text-[#64748b]">{"}"}</span></pre>
          </div>
        </div>
        <Link href="/docs" className="inline-flex items-center gap-2 mt-8 text-[15px] font-semibold text-[#d97706] hover:text-[#f59e0b] transition-colors">
          View API Docs <ArrowRight size={18} />
        </Link>
      </div>
    </section>
  );
}
