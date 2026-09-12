import { fileURLToPath, URL } from "node:url";

import { defineConfig } from "vite";

// The FastAPI server mounts this build at "/" (darkforce/api.py: app.mount("/", StaticFiles(web))),
// so the base is "/" and every /api/* fetch is same-origin. No proxy, no CORS at runtime.
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // lucide-react 1.x ships only the upstream name; our shim src/lib/lucide-react.tsx restores
      // the brand icons and re-exports the rest. Vite must resolve "lucide-react" to the shim.
      "lucide-react": fileURLToPath(new URL("./src/lib/lucide-react.tsx", import.meta.url)),
    },
  },
  esbuild: {
    jsx: "automatic",
  },
  build: {
    outDir: fileURLToPath(new URL("../web", import.meta.url)),
    emptyOutDir: true,
    target: "es2020",
    // Keep paths absolute so static serving works at "/" from the FastAPI mount.
    base: "/",
  },
});