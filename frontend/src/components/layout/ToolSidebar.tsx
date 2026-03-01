"use client";
import { useState, useRef, useCallback } from "react";
import { Search, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import type { ToolCategory } from "@/lib/constants";

interface ToolSidebarProps {
  category: ToolCategory;
  activeTool: string;
  onSelectTool: (id: string) => void;
}

export function ToolSidebar({ category, activeTool, onSelectTool }: ToolSidebarProps) {
  const [search, setSearch] = useState("");
  const [collapsed, setCollapsed] = useState(false);
  const [width, setWidth] = useState(280);
  const isResizing = useRef(false);

  const filtered = category.tools.filter(
    (t) =>
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase())
  );

  const handleMouseDown = useCallback(() => {
    isResizing.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing.current) return;
      const sidebar = document.getElementById("tool-sidebar");
      if (!sidebar) return;
      const rect = sidebar.getBoundingClientRect();
      const newWidth = Math.min(Math.max(e.clientX - rect.left, 200), 450);
      setWidth(newWidth);
    };

    const handleMouseUp = () => {
      isResizing.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
  }, []);

  if (collapsed) {
    return (
      <div className="w-[40px] flex-shrink-0 border-r border-white/[0.06] bg-[#060b18]/50 flex flex-col items-center pt-4 h-screen sticky top-0">
        <button
          onClick={() => setCollapsed(false)}
          className="w-7 h-7 rounded-md flex items-center justify-center text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.04] transition-all"
          title="Expand tool list"
        >
          <PanelLeftOpen size={14} />
        </button>
      </div>
    );
  }

  return (
    <div
      id="tool-sidebar"
      className="relative flex-shrink-0 border-r border-white/[0.06] bg-[#060b18]/50 h-screen sticky top-0 flex flex-col overflow-hidden"
      style={{ width }}
    >
      {/* Header */}
      <div className="px-4 pt-4 pb-3 border-b border-white/[0.06]">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2.5">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: `${category.color}15`, color: category.color }}
            >
              <span className="text-sm font-bold">{category.name[0]}</span>
            </div>
            <div>
              <div className="text-sm font-bold text-white">{category.name}</div>
              <div className="text-[11px] text-[#64748b]">{category.tools.length} tools</div>
            </div>
          </div>
          <button
            onClick={() => setCollapsed(true)}
            className="w-7 h-7 rounded-md flex items-center justify-center text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.04] transition-all"
          >
            <PanelLeftClose size={14} />
          </button>
        </div>
        {/* Search */}
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search tools..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-white/[0.03] border border-white/[0.06] rounded-lg pl-8 pr-3 py-2 text-[13px] text-[#94a3b8] placeholder-[#475569] outline-none focus:border-[#f97316]/30 transition-colors"
          />
        </div>
      </div>

      {/* Tool list */}
      <div className="flex-1 overflow-y-auto py-2">
        {filtered.map((tool) => {
          const isActive = activeTool === tool.id;
          return (
            <button
              key={tool.id}
              onClick={() => onSelectTool(tool.id)}
              className={`w-full text-left px-4 py-3 transition-all border-l-2 ${
                isActive
                  ? "border-l-[#f97316] bg-[#f97316]/[0.06]"
                  : "border-l-transparent hover:bg-white/[0.02]"
              }`}
            >
              <div className={`text-[13px] font-semibold truncate ${isActive ? "text-[#f97316]" : "text-white"}`}>
                {tool.name}
              </div>
              <div className="text-[11px] text-[#64748b] leading-snug mt-0.5 truncate">
                {tool.description}
              </div>
            </button>
          );
        })}
        {filtered.length === 0 && (
          <div className="px-4 py-8 text-center text-[13px] text-[#64748b]">
            No tools match &ldquo;{search}&rdquo;
          </div>
        )}
      </div>

      {/* Resize handle */}
      <div
        onMouseDown={handleMouseDown}
        className="absolute top-0 right-0 w-[4px] h-full cursor-col-resize hover:bg-[#f97316]/20 transition-colors z-10"
      />
    </div>
  );
}