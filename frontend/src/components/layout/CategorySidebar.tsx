"use client";
import { useState, useRef, useCallback } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { categories } from "@/lib/constants";
import type { Tool, ToolCategory } from "@/lib/constants";
import {
  Globe, Globe2, Lock, Link as LinkIcon, Mail, Hash, Code, Wifi, Shield, KeyRound,
  User, BookOpen, ExternalLink, PanelLeftClose, PanelLeftOpen, Search, X,
} from "lucide-react";

const iconMap: Record<string, React.ReactNode> = {
  Globe: <Globe size={18} />, Globe2: <Globe2 size={18} />, Lock: <Lock size={18} />,
  Link: <LinkIcon size={18} />, Mail: <Mail size={18} />, Hash: <Hash size={18} />,
  Code: <Code size={18} />, Wifi: <Wifi size={18} />, Shield: <Shield size={18} />,
  KeyRound: <KeyRound size={18} />,
};

/* ──────────────────────────────────────────────
   Draggable Tool Item
   ────────────────────────────────────────────── */

function DraggableToolItem({
  tool, category, isActive,
}: {
  tool: Tool; category: ToolCategory; isActive: boolean;
}) {
  return (
    <Link
      href={`/tools/${category.id}/${tool.id}`}
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData(
          "application/sectoolkit",
          JSON.stringify({
            categoryId: category.id, toolId: tool.id,
            categoryColor: category.color, categoryName: category.name,
          })
        );
        e.dataTransfer.effectAllowed = "copy";
        const ghost = document.createElement("div");
        ghost.textContent = tool.name;
        ghost.style.cssText = `
          position: fixed; top: -100px; left: -100px;
          padding: 6px 12px; border-radius: 8px;
          background: #0c1222; border: 1px solid ${category.color}40;
          color: #fff; font-size: 12px; font-weight: 500;
          box-shadow: 0 8px 24px rgba(0,0,0,0.4);
          pointer-events: none; white-space: nowrap;
        `;
        document.body.appendChild(ghost);
        e.dataTransfer.setDragImage(ghost, 0, 0);
        requestAnimationFrame(() => document.body.removeChild(ghost));
      }}
      className={`flex items-center gap-2.5 px-3 py-2 rounded-lg transition-all cursor-grab active:cursor-grabbing ${
        isActive
          ? "bg-white/[0.06] text-white"
          : "text-[#94a3b8] hover:text-white hover:bg-white/[0.03]"
      }`}
    >
      <span
        className="w-1.5 h-1.5 rounded-full flex-shrink-0"
        style={{ background: category.color, opacity: isActive ? 1 : 0.4 }}
      />
      <div className="flex-1 min-w-0">
        <span className="text-[12px] font-medium block truncate">{tool.name}</span>
        <span className="text-[10px] text-[#475569] block truncate leading-tight">{tool.description}</span>
      </div>
    </Link>
  );
}

/* ──────────────────────────────────────────────
   Tools Panel (second sidebar)
   ────────────────────────────────────────────── */

function ToolsPanel({
  category, activeTool, isWorkspace, onClose, width, onResizeStart,
}: {
  category: ToolCategory;
  activeTool: string;
  isWorkspace: boolean;
  onClose: () => void;
  width: number;
  onResizeStart: () => void;
}) {
  const [search, setSearch] = useState("");
  const filtered = search
    ? category.tools.filter((t) => t.name.toLowerCase().includes(search.toLowerCase()))
    : category.tools;

  return (
    <div
      className="relative flex-shrink-0 border-r border-white/[0.06] bg-[#070d1c] flex flex-col h-screen"
      style={{ width }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-3 border-b border-white/[0.06]">
        <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: category.color }} />
        <div className="flex-1 min-w-0">
          <span className="text-[13px] font-semibold text-white block truncate">{category.name}</span>
          <span className="text-[10px] text-[#475569] font-mono">{category.tools.length} tools</span>
        </div>
        <button
          onClick={onClose}
          className="w-6 h-6 rounded-md flex items-center justify-center text-[#64748b] hover:text-white hover:bg-white/[0.06] transition-all"
        >
          <X size={14} />
        </button>
      </div>

      {/* Search */}
      <div className="px-3 py-2 border-b border-white/[0.04]">
        <div className="relative">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#475569]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search tools..."
            className="w-full bg-white/[0.03] border border-white/[0.06] rounded-lg pl-8 pr-3 py-1.5
                       text-[12px] text-white placeholder-[#3b4559] outline-none
                       focus:border-[#f97316]/20 transition-colors"
          />
        </div>
      </div>

      {/* Drag hint on workspace */}
      {isWorkspace && (
        <div className="px-3 pt-2 pb-1">
          <span className="text-[9px] font-mono uppercase tracking-wider text-[#475569]">
            Drag to workspace
          </span>
        </div>
      )}

      {/* Tool list */}
      <div className="flex-1 overflow-y-auto px-2 py-1 space-y-0.5 scrollbar-thin scrollbar-thumb-white/10">
        {filtered.map((tool) => (
          <DraggableToolItem
            key={tool.id}
            tool={tool}
            category={category}
            isActive={activeTool === tool.id}
          />
        ))}
        {search && filtered.length === 0 && (
          <p className="text-[11px] text-[#475569] px-3 py-4 text-center">No matching tools</p>
        )}
      </div>

      {/* Resize handle */}
      <div
        onMouseDown={(e) => { e.preventDefault(); onResizeStart(); }}
        className="absolute top-0 right-0 w-[4px] h-full cursor-col-resize hover:bg-[#f97316]/20 transition-colors z-10"
      />
    </div>
  );
}

/* ──────────────────────────────────────────────
   CategorySidebar
   ────────────────────────────────────────────── */

export function CategorySidebar() {
  const pathname = usePathname();
  const pathParts = pathname.split("/");
  const activeCategory = pathParts[2] || "";
  const activeTool = pathParts[3] || "";
  const isWorkspace = pathname === "/tools" || pathname === "/tools/";

  const [collapsed, setCollapsed] = useState(false);
  const [mainWidth, setMainWidth] = useState(180);
  const [toolsPanelWidth, setToolsPanelWidth] = useState(240);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(activeCategory || null);
  const isResizingMain = useRef(false);
  const isResizingTools = useRef(false);

  /* Resize — main sidebar */
  const handleMainResizeStart = useCallback(() => {
    isResizingMain.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    const onMove = (e: MouseEvent) => {
      if (!isResizingMain.current) return;
      setMainWidth(Math.min(Math.max(e.clientX, 140), 280));
    };
    const onUp = () => {
      isResizingMain.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, []);

  /* Resize — tools panel */
  const handleToolsResizeStart = useCallback(() => {
    isResizingTools.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    const onMove = (e: MouseEvent) => {
      if (!isResizingTools.current) return;
      setToolsPanelWidth(Math.min(Math.max(e.clientX - mainWidth, 180), 400));
    };
    const onUp = () => {
      isResizingTools.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [mainWidth]);

  const toggleCategory = (catId: string) => {
    setSelectedCategory(selectedCategory === catId ? null : catId);
  };

  const selectedCat = selectedCategory ? categories.find((c) => c.id === selectedCategory) : null;

  /* ── Collapsed state ── */
  if (collapsed) {
    return (
      <div className="flex h-screen sticky top-0">
        <div className="w-[52px] flex-shrink-0 border-r border-white/[0.06] bg-[#060b18] flex flex-col items-center">
          <button onClick={() => setCollapsed(false)}
            className="w-9 h-9 mt-4 mb-4 rounded-lg bg-[#f97316]/10 flex items-center justify-center text-[#f97316] hover:bg-[#f97316]/20 transition-all">
            <PanelLeftOpen size={16} />
          </button>
          <div className="flex flex-col items-center gap-1 flex-1 py-2">
            {categories.map((cat) => {
              const isActive = activeCategory === cat.id || selectedCategory === cat.id;
              return (
                <button key={cat.id} onClick={() => { setCollapsed(false); setSelectedCategory(cat.id); }}
                  title={cat.name}
                  className={`w-9 h-9 rounded-lg flex items-center justify-center transition-all ${
                    isActive ? "bg-[#f97316]/15 text-[#f97316]" : "text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.04]"
                  }`}>
                  {iconMap[cat.icon]}
                </button>
              );
            })}
          </div>
          <div className="flex flex-col items-center gap-1 py-3 border-t border-white/[0.06]">
            <Link href="/account" title="Account" className="w-9 h-9 rounded-lg flex items-center justify-center text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.04] transition-all">
              <User size={18} />
            </Link>
            <Link href="/docs" title="API Docs" className="w-9 h-9 rounded-lg flex items-center justify-center text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.04] transition-all">
              <BookOpen size={18} />
            </Link>
          </div>
        </div>
      </div>
    );
  }

  /* ── Expanded state ── */
  return (
    <div className="flex h-screen sticky top-0">
      {/* Main sidebar — categories */}
      <div className="relative flex-shrink-0 border-r border-white/[0.06] bg-[#060b18] flex flex-col" style={{ width: mainWidth }}>
        {/* Logo + collapse */}
        <div className="flex items-center justify-between px-4 py-4 border-b border-white/[0.06]">
          <Link href="/" className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-[#f97316]/15 flex items-center justify-center flex-shrink-0">
              <svg width="16" height="16" viewBox="0 0 32 32" fill="none">
                <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#f97316" />
              </svg>
            </div>
            <div className="min-w-0">
              <div className="text-[13px] font-bold text-white leading-none truncate">
                Sec<span className="text-[#f97316]">Toolkit</span>
              </div>
              <div className="text-[9px] font-mono font-semibold uppercase tracking-[0.08em] text-[#64748b] mt-0.5">
                SecToolkit
              </div>
            </div>
          </Link>
          <button onClick={() => setCollapsed(true)}
            className="w-7 h-7 rounded-md flex items-center justify-center text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.04] transition-all flex-shrink-0">
            <PanelLeftClose size={15} />
          </button>
        </div>

        {/* Categories */}
        <div className="flex-1 overflow-y-auto py-3 scrollbar-thin scrollbar-thumb-white/10">
          <div className="px-4 mb-2">
            <span className="text-[10px] font-mono font-semibold uppercase tracking-[0.1em] text-[#475569]">
              Categories
            </span>
          </div>
          {categories.map((cat) => {
            const isActive = activeCategory === cat.id;
            const isSelected = selectedCategory === cat.id;
            return (
              <button
                key={cat.id}
                onClick={() => toggleCategory(cat.id)}
                className={`flex items-center gap-3 px-4 py-2.5 mx-2 rounded-lg transition-all w-full text-left ${
                  isSelected
                    ? "bg-[#f97316]/10 text-[#f97316]"
                    : isActive
                      ? "bg-white/[0.04] text-white"
                      : "text-[#94a3b8] hover:text-white hover:bg-white/[0.03]"
                }`}
              >
                <span className="flex-shrink-0" style={{ color: isSelected ? "#f97316" : undefined }}>
                  {iconMap[cat.icon]}
                </span>
                <span className="text-[13px] font-medium truncate flex-1">{cat.name}</span>
                <span
                  className="text-[11px] font-mono font-semibold rounded px-1.5 py-0.5 flex-shrink-0"
                  style={{
                    background: isSelected ? `${cat.color}15` : "rgba(255,255,255,0.04)",
                    color: isSelected ? cat.color : "#64748b",
                  }}
                >
                  {cat.tools.length}
                </span>
              </button>
            );
          })}
        </div>

        {/* Bottom */}
        <div className="border-t border-white/[0.06] py-3">
          <Link href="/account" className="flex items-center gap-3 px-4 py-2.5 mx-2 rounded-lg text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.03] transition-all">
            <User size={18} /><span className="text-[13px] font-medium">Account</span>
          </Link>
          <Link href="/docs" className="flex items-center gap-3 px-4 py-2.5 mx-2 rounded-lg text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.03] transition-all">
            <BookOpen size={18} /><span className="text-[13px] font-medium">API Docs</span>
          </Link>
          <a href="https://sectoolkit101.com" target="_blank" rel="noopener" className="flex items-center gap-3 px-4 py-2.5 mx-2 rounded-lg text-[#64748b] hover:text-[#94a3b8] hover:bg-white/[0.03] transition-all">
            <ExternalLink size={18} /><span className="text-[13px] font-medium">sectoolkit101.com</span>
          </a>
        </div>

        {/* Resize handle */}
        <div
          onMouseDown={(e) => { e.preventDefault(); handleMainResizeStart(); }}
          className="absolute top-0 right-0 w-[4px] h-full cursor-col-resize hover:bg-[#f97316]/20 transition-colors z-10"
        />
      </div>

      {/* Tools panel — slides out when a category is selected */}
      {selectedCat && (
        <ToolsPanel
          category={selectedCat}
          activeTool={activeTool}
          isWorkspace={isWorkspace}
          onClose={() => setSelectedCategory(null)}
          width={toolsPanelWidth}
          onResizeStart={handleToolsResizeStart}
        />
      )}
    </div>
  );
}