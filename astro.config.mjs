// ABOUTME: Configures FoxLift's static Astro website and canonical production URL.
// ABOUTME: Keeps the output deployable as static assets without an SSR adapter.
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://foxlift.dev",
  output: "static",
  trailingSlash: "always",
  build: {
    format: "directory",
    inlineStylesheets: "always",
  },
});
