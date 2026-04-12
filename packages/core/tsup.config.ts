import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts", "src/cascade/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    clean: true,
    sourcemap: true,
    noExternal: [],
  },
  {
    entry: ["src/cascade/bert-worker.ts"],
    format: ["cjs"],
    outDir: "dist/cascade",
    clean: false,
    sourcemap: true,
    external: ["@huggingface/transformers"],
  },
]);
