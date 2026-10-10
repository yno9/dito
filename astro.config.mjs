import { defineConfig } from "astro/config";
import react from "@astrojs/react";

// Kept apart from the existing wallet build: own srcDir/publicDir/outDir so
// public/ and dist/ (compiled binaries) are untouched.
export default defineConfig({
  srcDir: "./web",
  publicDir: "./web/public",
  outDir: "./build/astro",
  integrations: [react()],
});
