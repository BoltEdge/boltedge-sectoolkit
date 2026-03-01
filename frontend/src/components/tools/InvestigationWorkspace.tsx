"use client";
import { useState, useRef, useCallback } from "react";
import {
  Search,
  X,
  Loader2,
  Copy,
  Download,
  Maximize2,
  Minimize2,
  RotateCcw,
  Target,
  ChevronDown,
  AlertCircle,
  Play,
  Plus,
} from "lucide-react";
import { categories, getCategoryById } from "@/lib/constants";
import type { Tool, ToolCategory } from "@/lib/constants";
import { getEndpoint } from "@/lib/endpoints";

/* ──────────────────────────────────────────────
   Types
   ────────────────────────────────────────────── */

interface PanelState {
  id: string;
  categoryId: string;
  toolId: string;
  tool: Tool;
  categoryColor: string;
  categoryName: string;
  localTarget: string;
  loading: boolean;
  result: Record<string, any> | null;
  error: string | null;
  executionTime: number | null;
  expanded: boolean;
  /** Width as percentage of canvas (10–100) */
  widthPct: number;
  /** Height in pixels (min 200) */
  heightPx: number;
}

/* ──────────────────────────────────────────────
   Constants
   ────────────────────────────────────────────── */

const DEFAULT_PANELS: { categoryId: string; toolId: string }[] = [
  { categoryId: "ip", toolId: "whois" },
  { categoryId: "domain", toolId: "dns-lookup" },
  { categoryId: "email", toolId: "spf-check" },
  { categoryId: "ssl", toolId: "certificate-checker" },
  { categoryId: "hash", toolId: "hash-generator" },
  { categoryId: "url", toolId: "url-scanner" },
];

const MAX_PANELS = 12;
const MIN_W_PCT = 15;
const MAX_W_PCT = 100;
const MIN_H_PX = 200;
const GAP = 10;

/* ──────────────────────────────────────────────
   Helpers
   ────────────────────────────────────────────── */

function uid() { return Math.random().toString(36).slice(2, 10); }

function flattenObject(obj: any, prefix = ""): Record<string, any> {
  const result: Record<string, any> = {};
  for (const key in obj) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    const value = obj[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value, fullKey));
    } else {
      result[fullKey] = value;
    }
  }
  return result;
}

function safeString(val: any): string {
  if (val === null || val === undefined) return "\u2014";
  if (typeof val === "boolean") return val ? "Yes" : "No";
  if (Array.isArray(val)) {
    if (val.length === 0) return "\u2014";
    return val.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ");
  }
  if (typeof val === "object") return JSON.stringify(val);
  return String(val);
}

function makePanelFromDef(def: { categoryId: string; toolId: string }, totalCount: number, canvasH: number): PanelState | null {
  const cat = getCategoryById(def.categoryId);
  if (!cat) return null;
  const tool = cat.tools.find((t) => t.id === def.toolId);
  if (!tool) return null;
  const cols = Math.min(totalCount, 3);
  const rows = Math.ceil(totalCount / cols);
  return {
    id: uid(), categoryId: def.categoryId, toolId: def.toolId, tool,
    categoryColor: cat.color, categoryName: cat.name, localTarget: "",
    loading: false, result: null, error: null, executionTime: null,
    expanded: false,
    widthPct: 100 / cols,
    heightPx: Math.max(MIN_H_PX, Math.floor((canvasH - (rows - 1) * GAP - 24) / rows)),
  };
}

/* ──────────────────────────────────────────────
   Add Tool Dropdown
   ────────────────────────────────────────────── */

function AddToolDropdown({
  onAdd, disabled,
}: {
  onAdd: (categoryId: string, toolId: string, categoryColor: string, categoryName: string) => void;
  disabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [expandedCat, setExpandedCat] = useState<string | null>(null);

  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)} disabled={disabled}
        className="flex items-center gap-1.5 rounded-lg border border-white/[0.06] bg-white/[0.03]
                   px-3 py-2 text-[12px] font-medium text-[#94a3b8]
                   hover:bg-white/[0.06] hover:text-white transition-all
                   disabled:opacity-30 disabled:cursor-not-allowed">
        <Plus size={13} /> Add Tool
        <ChevronDown size={11} className={`transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => { setOpen(false); setExpandedCat(null); }} />
          <div className="absolute top-full left-0 mt-1 z-50 w-[260px] max-h-[420px] overflow-y-auto
                          rounded-xl border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl
                          shadow-2xl shadow-black/60 py-1.5 scrollbar-thin scrollbar-thumb-white/10">
            {categories.map((cat: ToolCategory) => (
              <div key={cat.id}>
                <button onClick={() => setExpandedCat(expandedCat === cat.id ? null : cat.id)}
                  className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.04] transition-colors">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: cat.color }} />
                  <span className="text-[12px] font-medium text-[#94a3b8] flex-1 text-left truncate">{cat.name}</span>
                  <span className="text-[10px] text-[#475569] font-mono">{cat.tools.length}</span>
                  <ChevronDown size={11} className={`text-[#475569] transition-transform duration-200 ${expandedCat === cat.id ? "rotate-180" : ""}`} />
                </button>
                {expandedCat === cat.id && (
                  <div className="pb-1">
                    {cat.tools.map((tool: Tool) => (
                      <button key={tool.id}
                        onClick={() => { onAdd(cat.id, tool.id, cat.color, cat.name); setOpen(false); setExpandedCat(null); }}
                        className="w-full flex items-center gap-2 px-5 py-1.5 text-left hover:bg-white/[0.06] transition-colors group">
                        <span className="w-1.5 h-1.5 rounded-full flex-shrink-0 opacity-50 group-hover:opacity-100" style={{ background: cat.color }} />
                        <span className="text-[11px] text-[#64748b] group-hover:text-white truncate transition-colors">{tool.name}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/* ──────────────────────────────────────────────
   Resizable Panel
   ────────────────────────────────────────────── */

function ResizablePanel({
  panel, globalTarget, canvasWidth,
  onRemove, onRun, onToggleExpand, onSetLocalTarget, onResize,
}: {
  panel: PanelState;
  globalTarget: string;
  canvasWidth: number;
  onRemove: (id: string) => void;
  onRun: (id: string) => void;
  onToggleExpand: (id: string) => void;
  onSetLocalTarget: (id: string, val: string) => void;
  onResize: (id: string, widthPct: number, heightPx: number) => void;
}) {
  const resizeRef = useRef<{ startX: number; startY: number; origW: number; origH: number } | null>(null);

  const effectiveTarget = panel.localTarget.trim() || globalTarget.trim();
  const hasTarget = effectiveTarget.length > 0;
  const isUsingLocal = panel.localTarget.trim().length > 0;

  /* ── Resize handler ── */
  const handleResizeDown = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    resizeRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      origW: panel.widthPct,
      origH: panel.heightPx,
    };
    const onMove = (ev: MouseEvent) => {
      if (!resizeRef.current) return;
      const dxPct = ((ev.clientX - resizeRef.current.startX) / (canvasWidth || 800)) * 100;
      const dy = ev.clientY - resizeRef.current.startY;
      const newW = Math.min(MAX_W_PCT, Math.max(MIN_W_PCT, resizeRef.current.origW + dxPct));
      const newH = Math.max(MIN_H_PX, resizeRef.current.origH + dy);
      onResize(panel.id, newW, newH);
    };
    const onUp = () => {
      resizeRef.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    document.body.style.cursor = "se-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  /* ── Export helpers ── */
  const handleCopyJson = () => {
    if (panel.result) navigator.clipboard.writeText(JSON.stringify(panel.result, null, 2));
  };

  const handleExportCsv = () => {
    if (!panel.result) return;
    const rows = Object.entries(panel.result).map(
      ([k, v]) => `"${k}","${safeString(v).replace(/"/g, '""')}"`
    );
    const csv = "key,value\n" + rows.join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${panel.categoryId}-${panel.toolId}-results.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* ── Expanded overlay ── */
  if (panel.expanded) {
    return (
      <>
        <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={() => onToggleExpand(panel.id)} />
        <div className="fixed inset-4 z-50 rounded-xl border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl shadow-2xl shadow-black/60 flex flex-col overflow-hidden">
          {renderTitleBar(true)}
          {renderInputBar()}
          {renderBody()}
        </div>
      </>
    );
  }

  /* ── Shared sub-renders ── */
  function renderTitleBar(isExpanded: boolean) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/[0.06] bg-white/[0.02] flex-shrink-0">
        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: panel.categoryColor }} />
        <span className="text-[12px] font-semibold text-white truncate flex-1">{panel.tool.name}</span>
        <span className="text-[10px] text-[#475569] font-mono mr-1">{panel.categoryName}</span>
        <div className="flex items-center gap-0.5">
          <button onClick={() => onToggleExpand(panel.id)}
            className="p-1 rounded hover:bg-white/[0.06] text-[#64748b] hover:text-white transition-colors"
            title={isExpanded ? "Restore" : "Maximize"}>
            {isExpanded ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
          <button onClick={() => onRemove(panel.id)}
            className="p-1 rounded hover:bg-red-500/20 text-[#64748b] hover:text-red-400 transition-colors" title="Remove">
            <X size={12} />
          </button>
        </div>
      </div>
    );
  }

  function renderInputBar() {
    return (
      <div className="px-3 py-2 border-b border-white/[0.04] flex items-center gap-2 flex-shrink-0">
        <input type="text" value={panel.localTarget}
          onChange={(e) => onSetLocalTarget(panel.id, e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onRun(panel.id)}
          placeholder={globalTarget ? `\u25B8 ${globalTarget}` : (panel.tool.inputPlaceholder || "Enter target...")}
          className="flex-1 bg-[#080d1a] border border-white/[0.06] rounded-lg px-3 py-1.5
                     text-[12px] text-white placeholder-[#3b4559] outline-none
                     focus:border-[#f97316]/30 transition-colors font-mono" />
        {isUsingLocal && (
          <span className="text-[9px] font-mono uppercase tracking-wider text-[#f97316] flex-shrink-0 px-1">local</span>
        )}
        <button onClick={() => onRun(panel.id)}
          disabled={panel.loading || !hasTarget}
          className="flex items-center gap-1 rounded-lg bg-white/[0.04] border border-white/[0.06]
                     px-2.5 py-1.5 text-[11px] font-medium text-white
                     hover:bg-white/[0.08] hover:border-[#f97316]/20 transition-all
                     disabled:opacity-30 disabled:cursor-not-allowed flex-shrink-0">
          {panel.loading ? <Loader2 size={12} className="animate-spin" /> : <Play size={11} className="text-[#f97316]" />}
          Run
        </button>
        {panel.executionTime !== null && (
          <span className="text-[10px] text-[#475569] font-mono flex-shrink-0">{panel.executionTime}ms</span>
        )}
      </div>
    );
  }

  function renderBody() {
    return (
      <div className="flex-1 overflow-auto min-h-0">
        {panel.error && (
          <div className="m-2.5 rounded-lg border border-red-500/20 bg-red-500/[0.05] px-3 py-2 flex items-start gap-2">
            <AlertCircle size={13} className="text-red-400 mt-0.5 flex-shrink-0" />
            <p className="text-[11px] text-red-300 leading-relaxed break-all">{String(panel.error)}</p>
          </div>
        )}
        {panel.result ? (
          <div>
            <div className="flex items-center justify-end gap-2 px-3 py-1 border-b border-white/[0.04]">
              <button onClick={handleCopyJson} className="flex items-center gap-1 text-[10px] text-[#64748b] hover:text-white transition-colors">
                <Copy size={10} /> JSON
              </button>
              <button onClick={handleExportCsv} className="flex items-center gap-1 text-[10px] text-[#64748b] hover:text-white transition-colors">
                <Download size={10} /> CSV
              </button>
            </div>
            <div className="divide-y divide-white/[0.03]">
              {Object.entries(panel.result).map(([key, val]) => (
                <div key={key} className="flex px-3 py-1.5 gap-3">
                  <span className="w-[140px] flex-shrink-0 text-[11px] font-medium text-[#64748b] truncate" title={key}>{key}</span>
                  <span className="text-[11px] text-white font-mono break-all leading-relaxed">{safeString(val)}</span>
                </div>
              ))}
            </div>
          </div>
        ) : !panel.loading && !panel.error ? (
          <div className="flex flex-col items-center justify-center h-full opacity-40">
            <Search size={18} className="mb-2" style={{ color: panel.categoryColor }} />
            <span className="text-[11px] text-[#64748b]">{hasTarget ? "Click Run to query" : (panel.tool.inputPlaceholder || "Enter a target")}</span>
          </div>
        ) : null}
        {panel.loading && (
          <div className="flex flex-col items-center justify-center h-full">
            <Loader2 size={20} className="animate-spin mb-2" style={{ color: panel.categoryColor }} />
            <span className="text-[11px] text-[#64748b]">{"Running " + panel.tool.name + "..."}</span>
          </div>
        )}
      </div>
    );
  }

  /* ── Normal (grid cell) render ── */
  return (
    <div
      className="rounded-xl border border-white/[0.08] bg-[#0c1222]/95 backdrop-blur-xl
                 shadow-lg shadow-black/30 flex flex-col overflow-hidden relative group/panel"
      style={{
        width: `calc(${panel.widthPct}% - ${GAP * (1 - panel.widthPct / 100)}px)`,
        height: panel.heightPx,
        flexShrink: 0,
        flexGrow: 0,
      }}
    >
      {renderTitleBar(false)}
      {renderInputBar()}
      {renderBody()}

      {/* Resize handle — bottom-right corner */}
      <div
        onMouseDown={handleResizeDown}
        className="absolute bottom-0 right-0 w-5 h-5 cursor-se-resize z-10
                   opacity-0 group-hover/panel:opacity-100 transition-opacity"
        title="Drag to resize"
      >
        <svg viewBox="0 0 20 20" className="w-full h-full">
          <path d="M18 18L10 18" stroke="#f97316" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
          <path d="M18 18L18 10" stroke="#f97316" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
          <path d="M18 18L13 18" stroke="#f97316" strokeWidth="2" strokeLinecap="round" opacity="0.8" />
          <path d="M18 18L18 13" stroke="#f97316" strokeWidth="2" strokeLinecap="round" opacity="0.8" />
        </svg>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────
   Main Workspace
   ────────────────────────────────────────────── */

export function InvestigationWorkspace() {
  const [panels, setPanels] = useState<PanelState[]>([]);
  const [globalTarget, setGlobalTarget] = useState("");
  const canvasRef = useRef<HTMLDivElement>(null);

  const addPanel = useCallback(
    (categoryId: string, toolId: string, categoryColor: string, categoryName: string) => {
      if (panels.length >= MAX_PANELS) return;
      const cat = getCategoryById(categoryId);
      if (!cat) return;
      const tool = cat.tools.find((t) => t.id === toolId);
      if (!tool) return;
      const newTotal = panels.length + 1;
      const cols = Math.min(newTotal, 3);
      const canvasH = canvasRef.current?.clientHeight ?? 600;
      const rows = Math.ceil(newTotal / cols);
      setPanels((prev) => [...prev, {
        id: uid(), categoryId, toolId, tool, categoryColor, categoryName,
        localTarget: "", loading: false, result: null, error: null,
        executionTime: null, expanded: false,
        widthPct: 100 / cols,
        heightPx: Math.max(MIN_H_PX, Math.floor((canvasH - (rows - 1) * GAP - 24) / rows)),
      }]);
    },
    [panels.length]
  );

  const runPanel = useCallback(
    async (panelId: string) => {
      const panel = panels.find((p) => p.id === panelId);
      if (!panel) return;
      const target = panel.localTarget.trim() || globalTarget.trim();
      if (!target) return;
      setPanels((prev) => prev.map((p) => p.id === panelId ? { ...p, loading: true, error: null, result: null, executionTime: null } : p));

      const endpoint = getEndpoint(panel.categoryId, panel.toolId);
      const startTime = performance.now();
      try {
        const response = await fetch("/api" + endpoint, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target }),
        });
        const elapsed = Math.round(performance.now() - startTime);
        const data = await response.json();
        if (!response.ok) {
          const errMsg = typeof data.error === "object" ? JSON.stringify(data.error) : String(data.error || data.message || "HTTP " + response.status);
          setPanels((prev) => prev.map((p) => p.id === panelId ? { ...p, loading: false, error: errMsg, executionTime: elapsed } : p));
          return;
        }
        let resultData: Record<string, any>;
        if (data.data) { resultData = flattenObject(data.data); }
        else {
          const { success, tool: _t, target: _tgt, timestamp, execution_time_ms, ...rest } = data;
          resultData = flattenObject(rest);
        }
        setPanels((prev) => prev.map((p) => p.id === panelId ? { ...p, loading: false, result: resultData, executionTime: elapsed } : p));
      } catch (err: any) {
        setPanels((prev) => prev.map((p) => p.id === panelId ? { ...p, loading: false, error: String(err?.message || "Connection failed"), executionTime: null } : p));
      }
    },
    [panels, globalTarget]
  );

  const runAll = useCallback(() => {
    panels.forEach((p) => {
      const target = p.localTarget.trim() || globalTarget.trim();
      if (target) runPanel(p.id);
    });
  }, [panels, globalTarget, runPanel]);

  const resetToDefaults = useCallback(() => {
    const canvasH = canvasRef.current?.clientHeight ?? 600;
    const initial: PanelState[] = [];
    DEFAULT_PANELS.forEach((def) => { const p = makePanelFromDef(def, DEFAULT_PANELS.length, canvasH); if (p) initial.push(p); });
    setPanels(initial);
  }, []);

  const handleCanvasDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const raw = e.dataTransfer.getData("application/sectoolkit");
    if (!raw) return;
    try {
      const { categoryId, toolId, categoryColor, categoryName } = JSON.parse(raw);
      addPanel(categoryId, toolId, categoryColor, categoryName);
    } catch {}
  };

  const removePanel = (id: string) => setPanels((prev) => prev.filter((p) => p.id !== id));
  const toggleExpand = (id: string) => setPanels((prev) => prev.map((p) => (p.id === id ? { ...p, expanded: !p.expanded } : p)));
  const setLocalTarget = (id: string, val: string) => setPanels((prev) => prev.map((p) => (p.id === id ? { ...p, localTarget: val } : p)));
  const resizePanel = (id: string, widthPct: number, heightPx: number) => {
    setPanels((prev) => prev.map((p) => (p.id === id ? { ...p, widthPct, heightPx } : p)));
  };

  const canvasWidth = canvasRef.current?.clientWidth ?? 1200;

  return (
    <div className="flex flex-col h-full w-full bg-[#060a14] text-white overflow-hidden">
      {/* ── Toolbar ── */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/[0.06] bg-[#0a0f1e]/60 backdrop-blur-sm flex-shrink-0">
        <div className="flex items-center gap-2 flex-shrink-0">
          <Target size={15} className="text-[#f97316]" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#64748b]">Target</span>
        </div>
        <input type="text" value={globalTarget}
          onChange={(e) => setGlobalTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runAll()}
          placeholder="Shared target \u2014 e.g. google.com, 8.8.8.8, CVE-2024-1234 ..."
          className="flex-1 bg-[#060a14] border border-white/[0.06] rounded-lg px-4 py-2
                     text-[13px] text-white placeholder-[#3b4559] outline-none
                     focus:border-[#f97316]/30 transition-colors font-mono" />
        <button onClick={runAll} disabled={panels.length === 0}
          className="flex items-center gap-2 rounded-lg bg-[#f97316]/10 border border-[#f97316]/20
                     px-4 py-2 text-[12px] font-semibold text-[#f97316]
                     hover:bg-[#f97316]/20 transition-all disabled:opacity-30 disabled:cursor-not-allowed">
          <Search size={13} /> Run All
        </button>
        <div className="w-px h-6 bg-white/[0.06]" />
        <AddToolDropdown onAdd={(catId, toolId, color, name) => addPanel(catId, toolId, color, name)} disabled={panels.length >= MAX_PANELS} />
        <span className="text-[10px] text-[#475569] font-mono">{panels.length}/{MAX_PANELS}</span>
        <button onClick={resetToDefaults}
          className="p-2 rounded-lg border border-white/[0.06] hover:bg-white/[0.04] text-[#64748b] hover:text-white transition-colors"
          title="Reset to default panels">
          <RotateCcw size={13} />
        </button>
      </div>

      {/* ── Canvas — flex wrap ── */}
      <div
        ref={canvasRef}
        onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }}
        onDrop={handleCanvasDrop}
        className="flex-1 min-h-0 overflow-auto p-3"
        style={{
          backgroundImage: "radial-gradient(circle, #2d3f59 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }}
      >
        {panels.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center">
            <div className="w-20 h-20 rounded-2xl border-2 border-dashed border-white/[0.18] flex items-center justify-center mb-5">
              <Plus size={32} className="text-white/30" />
            </div>
            <p className="text-[17px] font-semibold text-white/50 mb-2">Investigation Workspace</p>
            <p className="text-[14px] text-white/35 max-w-md text-center leading-relaxed">
              Drag &amp; drop tools from the sidebar to start investigating, or use{" "}
              <span className="text-[#f97316] font-medium">+ Add Tool</span> above.
            </p>
            <p className="text-[12px] text-white/20 mt-3">
              Click <span className="text-white/35 font-medium">Reset</span> to load default panels.
            </p>
          </div>
        ) : (
          <div
            className="flex flex-wrap content-start"
            style={{ gap: `${GAP}px` }}
          >
            {panels.map((panel) => (
              <ResizablePanel
                key={panel.id}
                panel={panel}
                globalTarget={globalTarget}
                canvasWidth={canvasWidth}
                onRemove={removePanel}
                onRun={runPanel}
                onToggleExpand={toggleExpand}
                onSetLocalTarget={setLocalTarget}
                onResize={resizePanel}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}