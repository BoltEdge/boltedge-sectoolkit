"use client";
import { useState } from "react";
import { Search, Copy, Download, Loader2, CheckCircle, AlertCircle } from "lucide-react";
import type { Tool } from "@/lib/constants";
import { getEndpoint } from "@/lib/endpoints";

interface ToolContentProps {
  tool: Tool;
  categoryId: string;
  categoryColor: string;
}

export function ToolContent({ tool, categoryId, categoryColor }: ToolContentProps) {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<null | Record<string, any>>(null);
  const [error, setError] = useState<string | null>(null);
  const [executionTime, setExecutionTime] = useState<number | null>(null);

  const handleLookup = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setExecutionTime(null);

    const endpoint = getEndpoint(categoryId, tool.id);
    const startTime = performance.now();

    try {
      const response = await fetch("/api" + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: input.trim() }),
      });

      const elapsed = Math.round(performance.now() - startTime);
      setExecutionTime(elapsed);

      const data = await response.json();

      if (!response.ok) {
        const rawErr = data.error || data.message || "Request failed";
        setError(typeof rawErr === "string" ? rawErr : (rawErr.message || JSON.stringify(rawErr)));
        return;
      }

      // Flatten result data for display
      if (data.data) {
        setResult(flattenObject(data.data));
      } else {
        // If no wrapper, show raw response
        const { success, tool: _t, target: _tgt, timestamp, execution_time_ms, ...rest } = data;
        setResult(flattenObject(rest));
      }
    } catch (err: any) {
      setError(err.message || "Failed to connect to backend. Is Flask running on port 5003?");
    } finally {
      setLoading(false);
    }
  };

  const handleCopyJson = () => {
    if (result) {
      navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    }
  };

  const handleExportCsv = () => {
    if (!result) return;
    const rows = Object.entries(result).map(([k, v]) => '"' + k + '","' + String(v).replace(/"/g, '""') + '"');
    const csv = "key,value\n" + rows.join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = categoryId + "-" + tool.id + "-results.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-[900px] mx-auto p-8">
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white mb-1.5">{tool.name}</h1>
            <p className="text-[15px] text-[#94a3b8]">{tool.description}</p>
          </div>
          <span className="flex-shrink-0 font-mono text-[9px] font-semibold uppercase tracking-widest text-[#d97706] border border-[#d97706]/15 bg-[#d97706]/[0.04] px-3 py-1.5 rounded-lg whitespace-nowrap">
            &#9670; Powered by BoltEdge
          </span>
        </div>

        {/* Input */}
        {tool.inputType !== "none" && (
          <div className="mb-6">
            {tool.inputLabel && (
              <label className="block font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-[#475569] mb-2">
                {tool.inputLabel}
              </label>
            )}
            <div className="flex gap-3">
              <input
                type="text"
                placeholder={tool.inputPlaceholder || "Enter target..."}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleLookup()}
                className="flex-1 bg-[#0a0f1e] border border-white/[0.06] rounded-xl px-4 py-3.5 text-[14px] text-white placeholder-[#475569] outline-none focus:border-[#d97706]/30 transition-colors"
              />
              <button
                onClick={handleLookup}
                disabled={loading || !input.trim()}
                className="flex items-center gap-2 rounded-xl bg-white/[0.04] border border-white/[0.06] px-6 py-3.5 text-[14px] font-medium text-white hover:bg-white/[0.06] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
                Lookup
              </button>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="mb-6 rounded-xl border border-red-500/20 bg-red-500/[0.05] px-5 py-4 flex items-start gap-3">
            <AlertCircle size={18} className="text-red-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-[14px] text-red-300">{error}</p>
            </div>
          </div>
        )}

        {/* Results area */}
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.01] min-h-[300px]">
          {result ? (
            <div>
              {/* Result header */}
              <div className="flex items-center justify-between px-6 py-3 border-b border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <span className="text-[12px] font-medium text-[#64748b]">Results</span>
                  {executionTime !== null && (
                    <span className="text-[11px] text-[#475569]">({executionTime}ms)</span>
                  )}
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={handleCopyJson}
                    className="flex items-center gap-1.5 text-[12px] text-[#64748b] hover:text-white transition-colors"
                  >
                    <Copy size={13} /> Copy JSON
                  </button>
                  <button
                    onClick={handleExportCsv}
                    className="flex items-center gap-1.5 text-[12px] text-[#64748b] hover:text-white transition-colors"
                  >
                    <Download size={13} /> Export CSV
                  </button>
                </div>
              </div>
              {/* Result table */}
              <div className="divide-y divide-white/[0.04]">
                {Object.entries(result).map(([key, val]) => (
                  <div key={key} className="flex px-6 py-3">
                    <span className="w-[180px] flex-shrink-0 text-[13px] font-medium text-[#64748b]">{key}</span>
                    <span className="text-[13px] text-white font-mono break-all">{formatValue(val)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20">
              <div className="w-14 h-14 rounded-2xl border border-white/[0.06] bg-white/[0.02] flex items-center justify-center mb-4" style={{ color: categoryColor }}>
                <Search size={24} />
              </div>
              <div className="text-[15px] font-semibold text-white mb-1">No results yet</div>
              <div className="text-[13px] text-[#64748b]">Enter a target and click Lookup to see results</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


/** Flatten nested objects for table display */
function flattenObject(obj: any, prefix = ""): Record<string, any> {
  const result: Record<string, any> = {};
  for (const key in obj) {
    const fullKey = prefix ? prefix + "." + key : key;
    const value = obj[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value, fullKey));
    } else {
      result[fullKey] = value;
    }
  }
  return result;
}


/** Format a value for display */
function formatValue(val: any): string {
  if (val === null || val === undefined) return "—";
  if (typeof val === "boolean") return val ? "Yes" : "No";
  if (Array.isArray(val)) {
    if (val.length === 0) return "—";
    return val.join(", ");
  }
  return String(val);
}