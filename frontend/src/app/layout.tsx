import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const jetbrains = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains" });

export const metadata: Metadata = {
  title: "BoltEdge SecToolkit — 91+ Security Tools. One Dashboard.",
  icons: {
    icon: "/favicon.svg",
  },
  description: "The security toolkit built for analysts. IP, DNS, SSL, email, URL, hash analysis and more.",
};


export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable}`}>
      <body className={inter.className}>{children}</body>
    </html>
  );
}
