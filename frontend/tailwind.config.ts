import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // NANZ Core Palette
        background: "#030303",
        surface: {
          DEFAULT: "#0A0A0C",
          hover: "#131316",
          active: "#1A1A1F",
          border: "#1E1E24",
          "border-light": "#2A2A32",
        },
        card: {
          DEFAULT: "#08080A",
          hover: "#0E0E12",
          border: "#1A1A20",
        },
        sidebar: {
          DEFAULT: "#060608",
          hover: "#0F0F13",
          active: "#141418",
          border: "#1A1A1F",
        },
        // Electric blue accent system
        nanz: {
          50: "#EFF8FF",
          100: "#D0ECFF",
          200: "#A8DBFF",
          300: "#6EC4FF",
          400: "#38A9FF",
          500: "#0A8CFF",
          600: "#006AFF",
          700: "#0055E0",
          800: "#0048B5",
          900: "#003D8F",
          950: "#002660",
        },
        primary: {
          DEFAULT: "#0A8CFF",
          glow: "rgba(10, 140, 255, 0.4)",
          muted: "rgba(10, 140, 255, 0.15)",
          foreground: "#FFFFFF",
        },
        accent: {
          DEFAULT: "#38BDF8",
          glow: "rgba(56, 189, 248, 0.3)",
          foreground: "#FFFFFF",
        },
        chrome: {
          DEFAULT: "#C0C8D4",
          muted: "#8A94A6",
          dark: "#5A6478",
        },
        // Severity system
        critical: { DEFAULT: "#FF2D55", bg: "rgba(255, 45, 85, 0.1)", border: "rgba(255, 45, 85, 0.2)" },
        high: { DEFAULT: "#FF6B6B", bg: "rgba(255, 107, 107, 0.1)", border: "rgba(255, 107, 107, 0.2)" },
        medium: { DEFAULT: "#FFB84D", bg: "rgba(255, 184, 77, 0.1)", border: "rgba(255, 184, 77, 0.2)" },
        low: { DEFAULT: "#34D399", bg: "rgba(52, 211, 153, 0.1)", border: "rgba(52, 211, 153, 0.2)" },
        info: { DEFAULT: "#60A5FA", bg: "rgba(96, 165, 250, 0.1)", border: "rgba(96, 165, 250, 0.2)" },
        success: { DEFAULT: "#10B981", bg: "rgba(16, 185, 129, 0.1)", border: "rgba(16, 185, 129, 0.2)" },
        // Typography
        text: {
          primary: "#F0F0F5",
          secondary: "#8B8B9E",
          muted: "#5C5C6F",
          inverse: "#030303",
        },
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
      },
      fontSize: {
        "display": ["3.5rem", { lineHeight: "1.1", letterSpacing: "-0.025em", fontWeight: "700" }],
        "headline": ["2.25rem", { lineHeight: "1.15", letterSpacing: "-0.02em", fontWeight: "700" }],
        "title": ["1.5rem", { lineHeight: "1.3", letterSpacing: "-0.015em", fontWeight: "600" }],
        "body-lg": ["1.125rem", { lineHeight: "1.6", fontWeight: "400" }],
      },
      borderRadius: {
        card: "12px",
        btn: "8px",
        panel: "16px",
      },
      backgroundImage: {
        "radial-glow": "radial-gradient(circle at center, var(--tw-gradient-stops))",
        "glass-gradient": "linear-gradient(145deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%)",
        "nanz-gradient": "linear-gradient(135deg, #0A8CFF 0%, #38BDF8 100%)",
        "nanz-gradient-subtle": "linear-gradient(135deg, rgba(10,140,255,0.15) 0%, rgba(56,189,248,0.05) 100%)",
      },
      boxShadow: {
        glow: "0 0 40px -10px var(--tw-shadow-color)",
        "nanz-glow": "0 0 60px -15px rgba(10, 140, 255, 0.3)",
        glass: "inset 0 1px 0 0 rgba(255, 255, 255, 0.06)",
        card: "0 1px 3px 0 rgba(0, 0, 0, 0.3), 0 1px 2px -1px rgba(0, 0, 0, 0.3)",
        "card-hover": "0 4px 12px 0 rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3)",
      },
      animation: {
        "fade-in-up": "fadeInUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "fade-in": "fadeIn 0.4s ease-out forwards",
        "slide-in-right": "slideInRight 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "pulse-slow": "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        float: "float 6s ease-in-out infinite",
        shimmer: "shimmer 2s linear infinite",
        "spin-slow": "spin 8s linear infinite",
      },
      keyframes: {
        fadeInUp: {
          "0%": { opacity: "0", transform: "translateY(16px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideInRight: {
          "0%": { opacity: "0", transform: "translateX(-8px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-8px)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
    },
  },
  plugins: [],
};
export default config;
