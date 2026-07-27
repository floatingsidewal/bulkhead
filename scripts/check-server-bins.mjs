import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(
  await readFile(new URL("../packages/server/package.json", import.meta.url), "utf8"),
);

for (const [name, relativePath] of Object.entries(manifest.bin)) {
  const contents = await readFile(
    new URL(`../packages/server/${relativePath}`, import.meta.url),
    "utf8",
  );
  assert.equal(
    contents.split(/\r?\n/, 1)[0],
    "#!/usr/bin/env node",
    `${name} must start with a Node shebang`,
  );
}

console.log("Server package binaries have executable Node shebangs.");
