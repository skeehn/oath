#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

const contract = JSON.parse(await readFile(new URL("../tests/compat/behavioral-contract.json", import.meta.url), "utf8"));
const output = resolve(process.env.OATH_COMPAT_RESULTS ?? "compat-results/ga");
const execute = process.argv.includes("--execute");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const npmVersionRun = spawnSync(npmCommand, ["--version"], {
  encoding: "utf8",
  shell: process.platform === "win32",
});
if (npmVersionRun.status !== 0 || !npmVersionRun.stdout) {
  throw new Error(`unable to execute npm reference: ${npmVersionRun.error?.message ?? npmVersionRun.stderr ?? "unknown error"}`);
}
const npmVersion = npmVersionRun.stdout.trim();
const results = [];

await mkdir(output, { recursive: true });
if (execute) {
  for (const behavior of contract.behaviors) {
    const fixture = resolve("tests/compat/fixtures", behavior.fixture);
    const run = spawnSync(process.execPath, [resolve("scripts/npm-parity.mjs"), fixture], {
      encoding: "utf8",
      timeout: Number(process.env.OATH_COMPAT_FIXTURE_TIMEOUT_MS ?? 900_000),
      killSignal: "SIGKILL",
      env: {
        ...process.env,
        OATH_COMPAT_MODE: behavior.mode ?? "clean",
        OATH_COMPAT_COMMAND: behavior.command ?? "install",
      },
      maxBuffer: 64 * 1024 * 1024,
    });
    let comparison;
    try { comparison = JSON.parse(run.stdout); }
    catch { comparison = { equivalent: false, stdout: run.stdout, stderr: run.stderr }; }
    results.push({
      id: behavior.id,
      workflow_slice: behavior.workflow_slice,
      fixture: behavior.fixture,
      command: behavior.command ?? "install",
      mode: behavior.mode ?? "clean",
      ...comparison,
    });
  }
}

const report = {
  schema_version: 1,
  evidence_class: "independent_behavioral",
  generated_at: new Date().toISOString(),
  release_commit: process.env.GITHUB_SHA ?? null,
  platform: process.platform,
  architecture: process.arch,
  node_version: process.version,
  reference_npm: npmVersion,
  independent_behavior_target: contract.behaviors.length,
  executed: results.length,
  equivalent: results.filter(result => result.equivalent).length,
  failed: results.filter(result => !result.equivalent).length,
  results,
};
await writeFile(join(output, "behavioral-summary.json"), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
if (execute && report.failed) process.exitCode = 1;
