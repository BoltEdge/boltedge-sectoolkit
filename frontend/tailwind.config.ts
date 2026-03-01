import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          dark: "#060b18",
          card: "#0a0f1e",
          "card-alt": "#0d1325",
          // Primary amber palette
          amber: "#d97706",
          "amber-bright": "#f59e0b",
          "amber-dim": "#b45309",
          "amber-muted": "#92400e",
          // Secondary accents (used sparingly for category icons etc)
          cyan: "#06b6d4",
          teal: "#14b8a6",
        },
        // Category icon colours
        cat: {
          ip: "#d97706",
          domain: "#06b6d4",
          ssl: "#22c55e",
          url: "#a855f7",
          email: "#d97706",
          hash: "#ef4444",
          encode: "#3b82f6",
          network: "#ec4899",
          threat: "#f97316",
          password: "#8b5cf6",
        },
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "JetBrains Mono", "monospace"],
      },
      borderRadius: {
        xl: "12px",
        "2xl": "16px",
        "3xl": "20px",
      },
    },
  },
  plugins: [],
};
export default config;
