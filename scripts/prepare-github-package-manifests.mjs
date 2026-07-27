import { readFile, writeFile } from "node:fs/promises";
import { toGitHubCore, toGitHubServer } from "./package-identities.mjs";

async function transform(path, transformManifest) {
  const manifest = JSON.parse(await readFile(path, "utf8"));
  await writeFile(path, `${JSON.stringify(transformManifest(manifest), null, 2)}\n`);
}

await transform("packages/core/package.json", toGitHubCore);
await transform("packages/server/package.json", toGitHubServer);
