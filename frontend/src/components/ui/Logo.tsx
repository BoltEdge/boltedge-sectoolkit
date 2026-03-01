import Link from "next/link";

export function Logo({ size = "md" }: { size?: "sm" | "md" | "lg" }) {
  return (
    <Link href="/" className="flex items-center gap-2.5 no-underline">
      <div className="w-[36px] h-[36px] rounded-[10px] bg-[#d97706]/20 flex items-center justify-center flex-shrink-0">
        <svg width="18" height="18" viewBox="0 0 32 32" fill="none">
          <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#d97706" />
        </svg>
      </div>
      <span className="text-[18px] font-bold tracking-tight">
        <span className="text-white">Bolt</span>
        <span className="text-[#d97706]">Edge</span>
      </span>
      <span className="ml-1 rounded-[5px] border border-[#d97706]/25 bg-[#d97706]/[0.08] px-2.5 py-[3px] font-mono text-[9px] font-semibold uppercase tracking-[0.08em] text-[#d97706]">
        SecToolkit
      </span>
    </Link>
  );
}