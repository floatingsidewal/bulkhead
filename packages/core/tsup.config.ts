import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  // bert-worker.ts must be built separately as it runs in a worker thread
  // and cannot be bundled into the main entry
  noExternal: [],
});
