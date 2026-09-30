#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

const input = resolve(process.argv[2] ?? "evidence-download/behavioral");
const output = resolve(process.argv[3] ?? "compatibility-evidence-v1.json");
const releaseCommit = process.env.GITHUB_SHA ?? process.env.OATH_RELEASE_COMMIT;
if (!/^[a-f0-9]{40}$/.test(releaseCommit ?? "")) {
  throw new Error("GITHUB_SHA or OATH_RELEASE_COMMIT must be an exact lowercase Git commit");
}

async function filesUnder(root) {
  const files = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (basename(path) === "behavioral-summary.json") files.push(path);
    }
  }
  await walk(root);
  return files.sort();
}

const manifest = JSON.parse(await readFile(new URL("../contracts/npm-compatibility-manifest-v2.json", import.meta.url), "utf8"));
const reports = await Promise.all((await filesUnder(input)).map(async (path) => JSON.parse(await readFile(path, "utf8"))));
const commands = reports.flatMap((report) => report.results.map((result) => ({
  case: result.id,
  command: result.command,
  args: result.args ?? [],
  platform: report.platform,
  node_version: report.node_version,
  npm_exit_code: result.npm?.status ?? null,
  oath_exit_code: result.oath?.status ?? null,
  npm_tree_digest: result.npm?.tree_sha256 ? `sha256:${result.npm.tree_sha256}` : null,
  oath_tree_digest: result.oath?.tree_sha256 ? `sha256:${result.oath.tree_sha256}` : null,
  equivalent: result.equivalent === true,
  reason: result.equivalent === true ? null : result.stderr ?? result.oath?.stderr ?? "npm/Oath behavior differed",
})));
const platforms = [...new Set(reports.map((report) => report.platform))].sort();
const nodeVersions = [...new Set(reports.map((report) => report.node_version))].sort();
const observedCommands = new Set(commands.filter((result) => result.equivalent).map((result) => result.command));
const requiredCombinations = ["linux", "darwin", "win32"].flatMap((platform) => ["22", "24"].map((node) => `${platform}:${node}`));
const observedCombinations = new Set(reports.map((report) => `${report.platform}:${String(report.node_version).replace(/^v/, "").split(".")[0]}`));
const requiredCommands = manifest.commands
  .filter((command) => command.replacement_required)
  .map((command) => command.name);
const allRequiredCommands = requiredCommands.every((command) => observedCommands.has(command));
const allRequiredCombinations = requiredCombinations.every((combination) => observedCombinations.has(combination));
const npmVersions = [...new Set(reports.map((report) => report.reference_npm))];

const evidence = {
  schema_version: 1,
  evidence_type: "CompatibilityEvidence",
  generated_at: new Date().toISOString(),
  release_commit: releaseCommit,
  reference: {
    npm_version: npmVersions.length === 1 ? npmVersions[0] : npmVersions.join(","),
    manifest_version: manifest.schema_version,
  },
  platforms,
  node_versions: nodeVersions,
  commands,
  intentional_exceptions: manifest.intentional_exceptions.map((exception) => ({ command: "*", ...exception })),
  summary: {
    executed: commands.length,
    equivalent: commands.filter((result) => result.equivalent).length,
    failed: commands.filter((result) => !result.equivalent).length,
    exceptions: manifest.intentional_exceptions.length,
  },
  qualifies_for_cli_ga: commands.length > 0 && commands.every((result) => result.equivalent) && allRequiredCommands && allRequiredCombinations,
};

await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(evidence, null, 2)}\n`);
console.log(JSON.stringify({ output, reports: reports.length, commands: commands.length, qualifies_for_cli_ga: evidence.qualifies_for_cli_ga }, null, 2));
