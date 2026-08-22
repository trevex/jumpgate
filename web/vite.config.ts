import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    exclude: ["e2e/**"],
  },
  server: {
    port: 5173,
    proxy: {
      "/jumpgate.": {
        target: "http://localhost:8080",
        changeOrigin: false,
      },
      "/healthz": {
        target: "http://localhost:8080",
        changeOrigin: false,
      },
    },
  },
});
