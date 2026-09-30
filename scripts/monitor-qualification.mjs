#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validation } from "./qualification-ledger.mjs";

function option(args, name, fallback) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}

function monitor(ledger, { now = new Date(), maxAgeHours = 36, allowPending = false } = {}) {
  const result = validation(ledger, { requireSignature: true, now });
  const alerts = [...result.errors];
  if (!allowPending && ["pending", "reset"].includes(ledger.state)) alerts.push(`qualification window is ${ledger.state}`);
  if (ledger.state === "running" && (result.latest_observation_age_hours === null || result.latest_observation_age_hours > maxAgeHours)) alerts.push(`latest observation exceeds ${maxAgeHours} hours`);
  if (ledger.state === "completed" && !result.qualifies_for_ga) alerts.push("completed ledger does not qualify for GA");
  return { evidence_class: "qualification-monitor", checked_at: now.toISOString(), track: ledger.track, state: ledger.state, healthy: alerts.length === 0, alerts, ledger: result };
}

async function selfTest() {
  const invalid = monitor({ state: "pending" }, { now: new Date("2030-01-01T00:00:00Z") });
  if (invalid.healthy || !invalid.alerts.some(alert => alert.includes("pending"))) throw new Error("qualification monitor self-test failed");
  return { self_test: "passed", synthetic_only: true };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) return console.log(JSON.stringify(await selfTest(), null, 2));
  const path = args[0];
  if (!path) throw new Error("usage: monitor-qualification.mjs <ledger.json> [--max-age-hours 36] [--allow-pending]");
  const ledger = JSON.parse(await readFile(resolve(path), "utf8"));
  const report = monitor(ledger, { maxAgeHours: Number(option(args, "--max-age-hours", "36")), allowPending: args.includes("--allow-pending") });
  console.log(JSON.stringify(report, null, 2));
  if (!report.healthy) process.exitCode = 1;
}

export { monitor };

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error.stack ?? error.message);
    process.exitCode = 1;
  });
}
