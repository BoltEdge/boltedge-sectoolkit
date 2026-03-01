import { getCategoryById } from "@/lib/constants";
import { CategoryPage } from "@/components/tools/CategoryPage";
import { notFound } from "next/navigation";

export default function Page() {
  const category = getCategoryById("url");
  if (!category) notFound();
  return <CategoryPage category={category} />;
}
