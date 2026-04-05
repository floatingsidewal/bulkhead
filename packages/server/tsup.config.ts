import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/main.ts", "src/mcp/index.ts"],
  format: ["cjs"],
  clean: true,
  sourcemap: true,
  target: "node18",
});
