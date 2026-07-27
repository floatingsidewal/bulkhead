import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  GITHUB_CORE,
  GITHUB_SERVER,
  PUBLIC_CORE,
  PUBLIC_SERVER,
  toGitHubCore,
  toGitHubServer,
} from "./package-identities.mjs";

async function readJson(path) {
  return JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));
}

const core = await readJson("../packages/core/package.json");
const server = await readJson("../packages/server/package.json");
const vscode = await readJson("../packages/vscode/package.json");

assert.equal(core.name, PUBLIC_CORE);
assert.equal(server.name, PUBLIC_SERVER);
assert.equal(server.dependencies[PUBLIC_CORE], `^${core.version}`);
assert.equal(vscode.dependencies[PUBLIC_CORE], `^${core.version}`);
assert.equal(server.bin["bulkhead-server"], "dist/main.js");
assert.equal(server.bin["bulkhead-mcp"], "dist/mcp/index.js");
assert.equal(core.publishConfig.registry, "https://registry.npmjs.org/");
assert.equal(server.publishConfig.registry, "https://registry.npmjs.org/");

const githubCore = toGitHubCore(core);
const githubServer = toGitHubServer(server);
assert.equal(githubCore.name, GITHUB_CORE);
assert.equal(githubServer.name, GITHUB_SERVER);
assert.equal(
  githubServer.dependencies[PUBLIC_CORE],
  `npm:${GITHUB_CORE}@^${core.version}`,
);
assert.equal(githubServer.dependencies[GITHUB_CORE], undefined);
assert.equal(githubCore.publishConfig.registry, "https://npm.pkg.github.com");
assert.equal(githubServer.publishConfig.registry, "https://npm.pkg.github.com");

console.log(`Package identities are canonical at ${core.version}.`);
