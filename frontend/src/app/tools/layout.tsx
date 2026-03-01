import { CategorySidebar } from "@/components/layout/CategorySidebar";

export default function ToolsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative z-10 flex h-screen overflow-hidden">
      <CategorySidebar />
      <main className="flex-1 min-w-0 h-full overflow-hidden">
        {children}
      </main>
    </div>
  );
}