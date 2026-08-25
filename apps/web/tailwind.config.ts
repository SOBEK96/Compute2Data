import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "#070A12",
        carbon: "#0D1220",
        elevated: "#121A2A",
        line: "#202A3D",
        cobalt: {
          300: "#8CA6FF",
          400: "#6F8FFF",
          500: "#5276FF",
          600: "#3D5FE6",
        },
        mineral: "#82EBC5",
        ember: "#FFCC7A",
        danger: "#FF6F87",
        paper: "#F6F7FB",
        muted: "#8D99AE",
      },
      fontFamily: {
        sans: ["Manrope Variable", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono Variable", "ui-monospace", "monospace"],
      },
      boxShadow: {
        cobalt: "0 18px 80px -28px rgba(82, 118, 255, 0.55)",
        panel: "0 24px 70px -40px rgba(0, 0, 0, 0.9)",
      },
      backgroundImage: {
        "hero-glow":
          "radial-gradient(circle at 72% 18%, rgba(82,118,255,0.22), transparent 34%), radial-gradient(circle at 12% 70%, rgba(130,235,197,0.08), transparent 28%)",
      },
      keyframes: {
        "rail-pulse": {
          "0%, 100%": { opacity: "0.42", transform: "scaleX(0.74)" },
          "50%": { opacity: "1", transform: "scaleX(1)" },
        },
        "soft-rise": {
          from: { opacity: "0", transform: "translateY(12px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "rail-pulse": "rail-pulse 2.8s ease-in-out infinite",
        "soft-rise": "soft-rise 500ms ease-out both",
      },
    },
  },
  plugins: [],
};

export default config;
