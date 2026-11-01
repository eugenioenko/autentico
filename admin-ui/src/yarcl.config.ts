import { defineConfig } from "@yarcl/react/define";
import defaults from "@yarcl/react/defaults";

export default defineConfig({
  ...defaults,
  colors: {
    ...defaults.colors,
    neutral: { light: "#525252", dark: "#a6a6a6" },
    primary: { light: "#0958d9", dark: "#4096ff" },
    purple: { light: "#7e22ce", dark: "#c084fc" },
    cyan: { light: "#0e7490", dark: "#22d3ee" },
    brand: { light: "#c2410c", dark: "#ff7b00", on: { light: "#ffffff", dark: "#1c1917" } },
  },
  neutrals: {
    bg: { light: "#fafafa", dark: "#0f0f0f" },
    surface: { light: "#ffffff", dark: "#1a1a1a" },
    text: { light: "#1f1f1f", dark: "#e6e6e6" },
    muted: { light: "#666666", dark: "#8c8c8c" },
    border: { light: "#e5e5e5", dark: "#303030" },
  },
  typography: {
    ...defaults.typography,
    families: {
      ...defaults.typography.families,
      sans: '"Roboto Variable", Roboto, -apple-system, "Segoe UI", sans-serif',
    },
  },
  widths: { ...defaults.widths, sidebar: "12.5rem" },
  sizes: {
    sm: { height: "1.625rem", paddingX: "0.625rem", fontSize: "0.8125rem", iconSize: "0.875rem" },
    md: { height: "2rem", paddingX: "0.75rem", fontSize: "0.875rem", iconSize: "1rem" },
    lg: { height: "2.5rem", paddingX: "1rem", fontSize: "1rem", iconSize: "1.25rem" },
  },
  components: {
    ...defaults.components,
    AppLayout: { padding: "md" },
    NavSection: { gap: "xs" },
  },
});
