#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync, execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const allowedTypes = new Set([
  "backup_restore", "dependency_outage", "key_compromise", "object_corruption",
  "process_kill", "regional_failover", "revocation_cache_outage", "split_view",
  "tenant_isolation", "webhook_replay",
]);
const separator = process.argv.indexOf("--");
const options = separator === -1 ? process.argv.slice(2) : process.argv.slice(2, separator);
const command = separator === -1 ? [] : process.argv.slice(separator + 1);
const value = (name) => {
  const index = options.indexOf(name);
  return index === -1 ? null : options[index + 1];
};
const type = value("--type");
const assertionsPath = value("--assertions");
const output = resolve(value("--output") ?? `operational-drill-${type ?? "unknown"}.json`);
if (!allowedTypes.has(type) || !assertionsPath || command.length === 0) {
  throw new Error("usage: run-operational-drill.mjs --type <type> --assertions <json> [--output <json>] -- <executable> [args...]");
}

const provider = process.env.OATH_DRILL_PROVIDER;
const regions = (process.env.OATH_DRILL_REGIONS ?? "").split(",").map((item) => item.trim()).filter(Boolean);
const deploymentDigest = process.env.OATH_DRILL_DEPLOYMENT_DIGEST;
if (!provider || regions.length === 0 || !/^sha256:[0-9a-f]{64}$/.test(deploymentDigest ?? "")) {
  throw new Error("OATH_DRILL_PROVIDER, OATH_DRILL_REGIONS, and a sha256 OATH_DRILL_DEPLOYMENT_DIGEST are required");
}

const assertions = JSON.parse(await readFile(resolve(assertionsPath), "utf8"));
if (!Array.isArray(assertions) || assertions.length === 0 || assertions.some((item) =>
  typeof item?.name !== "string" || typeof item?.passed !== "boolean" || typeof item?.observed !== "string"
)) {
  throw new Error("assertions must be a non-empty array of {name, passed, observed}");
}

const startedAt = new Date().toISOString();
const result = spawnSync(command[0], command.slice(1), {
  encoding: "utf8",
  env: process.env,
  maxBuffer: 64 * 1024 * 1024,
});
const finishedAt = new Date().toISOString();
const log = Buffer.from([
  `command=${JSON.stringify(command)}`,
  `exit_code=${result.status ?? "signal"}`,
  `signal=${result.signal ?? ""}`,
  "--- stdout ---", result.stdout ?? "",
  "--- stderr ---", result.stderr ?? "",
  result.error ? `spawn_error=${result.error.message}` : "",
].join("\n"));
const logPath = `${output}.log`;
await mkdir(dirname(output), { recursive: true });
await writeFile(logPath, log);

const releaseCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const allAssertionsPassed = assertions.every((item) => item.passed === true);
const report = {
  schema_version: 2,
  evidence_class: "operational-drill",
  release_commit: releaseCommit,
  drill_id: process.env.OATH_DRILL_ID ?? `${type}-${startedAt}`,
  drill_type: type,
  started_at: startedAt,
  finished_at: finishedAt,
  status: result.status === 0 && allAssertionsPassed ? "passed" : "failed",
  environment: { provider, regions: [...new Set(regions)], deployment_digest: deploymentDigest },
  assertions,
  artifacts: [{
    uri: process.env.OATH_DRILL_LOG_URI ?? logPath,
    sha256: createHash("sha256").update(log).digest("hex"),
  }],
  limitations: (process.env.OATH_DRILL_LIMITATIONS ?? "").split("|").filter(Boolean),
};
if (type === "backup_restore") {
  report.rpo_minutes = Number(process.env.OATH_DRILL_RPO_MINUTES);
  report.rto_minutes = Number(process.env.OATH_DRILL_RTO_MINUTES);
  if (!Number.isFinite(report.rpo_minutes) || !Number.isFinite(report.rto_minutes)) {
    throw new Error("backup_restore requires numeric OATH_DRILL_RPO_MINUTES and OATH_DRILL_RTO_MINUTES");
  }
}
await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ output, log: logPath, status: report.status }, null, 2));
if (report.status !== "passed") process.exit(1);
