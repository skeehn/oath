#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const REQUIRED_DRILLS = [
  "backup_restore",
  "dependency_outage",
  "key_compromise",
  "object_corruption",
  "process_kill",
  "regional_failover",
  "revocation_cache_outage",
  "split_view",
  "tenant_isolation",
  "webhook_replay",
];
const REQUIRED_AUDITS = ["architecture_review", "penetration_test", "sandbox_escape_review"];

function isoDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function validate(ledger) {
  const errors = [];
  if (ledger?.schema_version !== 1) errors.push("schema_version must equal 1");
  if (ledger?.evidence_class !== "production-beta") {
    errors.push("evidence_class must equal production-beta");
  }
  if (!/^[0-9a-f]{40}$/.test(ledger?.release_commit ?? "")) {
    errors.push("release_commit must be a full lowercase Git commit");
  }
  const days = Array.isArray(ledger?.daily_observations) ? ledger.daily_observations : [];
  if (days.length < 60) errors.push(`daily_observations has ${days.length}; at least 60 required`);
  const dates = days.map((day) => day?.date);
  if (dates.some((date) => !isoDate(date))) errors.push("every observation needs an ISO UTC date");
  if (new Set(dates).size !== dates.length) errors.push("daily observation dates must be unique");
  const sorted = [...dates].sort();
  for (let index = 1; index < sorted.length; index += 1) {
    const previous = Date.parse(`${sorted[index - 1]}T00:00:00Z`);
    const current = Date.parse(`${sorted[index]}T00:00:00Z`);
    if (current - previous !== 86_400_000) {
      errors.push(`daily observations are not consecutive at ${sorted[index - 1]} -> ${sorted[index]}`);
      break;
    }
  }
  for (const day of days) {
    const prefix = `daily_observations[${day?.date ?? "unknown"}]`;
    const metrics = day?.metrics ?? {};
    if (!(metrics.metadata_latency_p95_ms <= 150)) errors.push(`${prefix} metadata p95 exceeds 150 ms`);
    if (!(metrics.tarball_availability >= 0.9995)) errors.push(`${prefix} tarball availability below 99.95%`);
    if (!(metrics.control_plane_availability >= 0.999)) errors.push(`${prefix} control-plane availability below 99.9%`);
    if (!(metrics.revocation_propagation_p95_seconds <= 60)) errors.push(`${prefix} revocation p95 exceeds 60 seconds`);
    if ((day?.unresolved_high_or_critical ?? -1) !== 0) errors.push(`${prefix} has unresolved high/critical findings`);
    if (!Array.isArray(day?.evidence) || day.evidence.length === 0) errors.push(`${prefix} has no evidence references`);
    for (const evidence of day?.evidence ?? []) {
      if (typeof evidence?.uri !== "string" || evidence.uri.length === 0 || !/^[0-9a-f]{64}$/.test(evidence?.sha256 ?? "")) {
        errors.push(`${prefix} has an invalid evidence reference`);
      }
    }
  }

  const drills = Array.isArray(ledger?.drills) ? ledger.drills : [];
  for (const type of REQUIRED_DRILLS) {
    const drill = drills.find((candidate) => candidate?.type === type && candidate?.status === "passed");
    if (!drill) errors.push(`missing passed drill: ${type}`);
    else if (!isoDate(drill.date) || !/^[0-9a-f]{64}$/.test(drill.evidence_sha256 ?? "")) {
      errors.push(`drill ${type} has invalid date or evidence checksum`);
    } else if (!Array.isArray(drill.assertions) || drill.assertions.length === 0 ||
      drill.assertions.some((assertion) => assertion?.passed !== true)) {
      errors.push(`drill ${type} has missing or failed assertions`);
    }
  }
  const restore = drills.find((drill) => drill?.type === "backup_restore");
  if (!(restore?.rpo_minutes <= 5)) errors.push("backup_restore RPO exceeds five minutes");
  if (!(restore?.rto_minutes <= 60)) errors.push("backup_restore RTO exceeds 60 minutes");

  const audits = Array.isArray(ledger?.independent_audits) ? ledger.independent_audits : [];
  for (const type of REQUIRED_AUDITS) {
    const audit = audits.find((candidate) => candidate?.type === type && candidate?.status === "passed");
    if (!audit) errors.push(`missing passed independent audit: ${type}`);
    else if ((audit.open_critical ?? -1) !== 0 || (audit.open_high ?? -1) !== 0) {
      errors.push(`${type} has unresolved critical/high findings`);
    }
  }
  return {
    schema_version: 1,
    evidence_class: "beta-ledger-validation",
    release_commit: ledger?.release_commit ?? null,
    observed_days: days.length,
    consecutive_days: errors.every((error) => !error.includes("not consecutive")),
    required_drills: REQUIRED_DRILLS.length,
    passed_drills: REQUIRED_DRILLS.filter((type) => drills.some((drill) => drill?.type === type && drill?.status === "passed")).length,
    required_audits: REQUIRED_AUDITS.length,
    passed_audits: REQUIRED_AUDITS.filter((type) => audits.some((audit) => audit?.type === type && audit?.status === "passed")).length,
    qualifies_for_ga: errors.length === 0,
    errors,
  };
}

function selfTestLedger() {
  const checksum = "a".repeat(64);
  const start = Date.parse("2030-01-01T00:00:00Z");
  return {
    schema_version: 1,
    evidence_class: "production-beta",
    release_commit: "b".repeat(40),
    daily_observations: Array.from({ length: 60 }, (_, index) => ({
      date: new Date(start + index * 86_400_000).toISOString().slice(0, 10),
      metrics: {
        metadata_latency_p95_ms: 149,
        tarball_availability: 0.9995,
        control_plane_availability: 0.999,
        revocation_propagation_p95_seconds: 60,
      },
      unresolved_high_or_critical: 0,
      evidence: [{ uri: `synthetic://day/${index}`, sha256: checksum }],
    })),
    drills: REQUIRED_DRILLS.map((type) => ({
      type,
      date: "2030-02-01",
      status: "passed",
      evidence_sha256: checksum,
      assertions: [{ name: `${type}_safety_invariant`, passed: true }],
      ...(type === "backup_restore" ? { rpo_minutes: 5, rto_minutes: 60 } : {}),
    })),
    independent_audits: REQUIRED_AUDITS.map((type) => ({
      type,
      status: "passed",
      open_critical: 0,
      open_high: 0,
    })),
  };
}

if (process.argv.includes("--self-test")) {
  const passing = validate(selfTestLedger());
  const broken = selfTestLedger();
  broken.daily_observations.splice(10, 1);
  const failing = validate(broken);
  if (!passing.qualifies_for_ga || failing.qualifies_for_ga) {
    throw new Error("beta ledger validator self-test failed");
  }
  console.log(JSON.stringify({ self_test: "passed", synthetic_only: true }, null, 2));
  process.exit(0);
}

const input = process.argv[2];
if (!input) throw new Error("usage: validate-beta-ledger.mjs <ledger.json> or --self-test");
const result = validate(JSON.parse(await readFile(input, "utf8")));
console.log(JSON.stringify(result, null, 2));
if (!result.qualifies_for_ga) process.exit(1);
