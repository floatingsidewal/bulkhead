export const PUBLIC_CORE = "@bulkhead-ai/core";
export const PUBLIC_SERVER = "@bulkhead-ai/server";
export const GITHUB_CORE = "@floatingsidewal/bulkhead-core";
export const GITHUB_SERVER = "@floatingsidewal/bulkhead-server";

export function toGitHubCore(source) {
  return {
    ...source,
    name: GITHUB_CORE,
    publishConfig: {
      access: "public",
      registry: "https://npm.pkg.github.com",
    },
  };
}

export function toGitHubServer(source) {
  const dependencies = { ...source.dependencies };
  dependencies[PUBLIC_CORE] = `npm:${GITHUB_CORE}@${dependencies[PUBLIC_CORE]}`;
  return {
    ...source,
    name: GITHUB_SERVER,
    dependencies,
    publishConfig: {
      access: "public",
      registry: "https://npm.pkg.github.com",
    },
  };
}
