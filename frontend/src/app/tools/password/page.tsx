import { getCategoryById } from "@/lib/constants";
import { CategoryPage } from "@/components/tools/CategoryPage";
import { notFound } from "next/navigation";

export default function Page() {
  const category = getCategoryById("password");
  if (!category) notFound();
  return <CategoryPage category={category} />;
}
