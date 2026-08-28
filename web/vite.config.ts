import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The husk localhost UI. In dev, `npm run dev` serves the front-end with HMR and
// proxies /api to the Rust backend running `husk web --dev` (default :6789). In
// production the Rust binary embeds the `dist/` build and serves it itself.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  // Relative base so the embedded build works regardless of the served path.
  base: "./",
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    host: "127.0.0.1",
    port: 5181,
    strictPort: true,
    proxy: {
      "/api": `http://127.0.0.1:${process.env.HUSK_PORT ?? 6789}`,
    },
  },
});
