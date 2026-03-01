"use client";
import { useState } from "react";
import { ToolSidebar } from "@/components/layout/ToolSidebar";
import { ToolContent } from "@/components/tools/ToolContent";
import type { ToolCategory } from "@/lib/constants";
export function CategoryPage({ category }: { category: ToolCategory }) {
  const [activeTool, setActiveTool] = useState(category.tools[0]?.id || "");
  const tool = category.tools.find(t => t.id === activeTool) || category.tools[0];
  return (
    <div className="flex flex-1 min-h-screen">
      <ToolSidebar category={category} activeTool={activeTool} onSelectTool={setActiveTool} />
      <ToolContent tool={tool} categoryId={category.id} categoryColor={category.color} />
    </div>
  );
}