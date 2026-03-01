"use client";

import dynamic from "next/dynamic";

const InvestigationWorkspace = dynamic(
  () => import("@/components/tools/InvestigationWorkspace").then((m) => ({ default: m.InvestigationWorkspace })),
  { ssr: false }
);

export default function ToolsPage() {
  return (
    <div className="h-full w-full overflow-hidden bg-[#060a14]">
      <InvestigationWorkspace />
    </div>
  );
}