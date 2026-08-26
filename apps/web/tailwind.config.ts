import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "#050811",
        carbon: "#0A0F1D",
        elevated: "#10172A",
        surface: "#151F36",
        line: "#1E2B45",
        "line-bright": "#2E4166",
        cobalt: {
          300: "#8CA6FF",
          400: "#6F8FFF",
          500: "#5276FF",
          600: "#3D5FE6",
        },
        cyan: {
          300: "#67E8F9",
          400: "#22D3EE",
          500: "#06B6D4",
        },
        mineral: "#82EBC5",
        emerald: {
          400: "#34D399",
          500: "#10B981",
        },
        ember: "#FFB03A",
        danger: "#FF5271",
        paper: "#F8FAFC",
        muted: "#8A99AD",
      },
      fontFamily: {
        sans: ["Manrope Variable", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono Variable", "ui-monospace", "monospace"],
      },
      boxShadow: {
        cobalt: "0 18px 80px -28px rgba(82, 118, 255, 0.65)",
        cyan: "0 18px 80px -28px rgba(6, 182, 212, 0.6)",
        emerald: "0 18px 80px -28px rgba(16, 185, 129, 0.5)",
        panel: "0 24px 70px -40px rgba(0, 0, 0, 0.95)",
        card: "0 10px 30px -10px rgba(0, 0, 0, 0.8)",
        glow: "0 0 35px -5px rgba(82, 118, 255, 0.35)",
      },
      backgroundImage: {
        "hero-glow":
          "radial-gradient(circle at 68% 12%, rgba(82, 118, 255, 0.28), transparent 38%), radial-gradient(circle at 14% 65%, rgba(6, 182, 212, 0.18), transparent 32%), radial-gradient(circle at 85% 85%, rgba(130, 235, 197, 0.12), transparent 28%)",
        "card-gradient":
          "linear-gradient(135deg, rgba(16, 23, 42, 0.9) 0%, rgba(10, 15, 29, 0.95) 100%)",
        "glass-panel":
          "linear-gradient(180deg, rgba(255, 255, 255, 0.04) 0%, rgba(255, 255, 255, 0.01) 100%)",
      },
      keyframes: {
        "rail-pulse": {
          "0%, 100%": { opacity: "0.35", transform: "scaleX(0.7)" },
          "50%": { opacity: "1", transform: "scaleX(1)" },
        },
        "soft-rise": {
          from: { opacity: "0", transform: "translateY(16px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-glow": {
          "0%, 100%": { opacity: "0.6", transform: "scale(1)" },
          "50%": { opacity: "1", transform: "scale(1.05)" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
      },
      animation: {
        "rail-pulse": "rail-pulse 3s ease-in-out infinite",
        "soft-rise": "soft-rise 500ms cubic-bezier(0.16, 1, 0.3, 1) both",
        "pulse-glow": "pulse-glow 3s ease-in-out infinite",
        shimmer: "shimmer 2s infinite",
      },
    },
  },
  plugins: [],
};

export default config;
