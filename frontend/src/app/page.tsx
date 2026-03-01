import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { Hero } from "@/components/landing/Hero";
import { ToolCategories } from "@/components/landing/ToolCategories";
import { HowItWorks } from "@/components/landing/HowItWorks";
import { ApiShowcase } from "@/components/landing/ApiShowcase";
import { Pricing } from "@/components/landing/Pricing";
import { CtaBand } from "@/components/landing/CtaBand";

export default function LandingPage() {
  return (
    <>
      <Navbar />
      <Hero />
      <ToolCategories />
      <HowItWorks />
      <ApiShowcase />
      <Pricing />
      <CtaBand />
      <Footer />
    </>
  );
}
