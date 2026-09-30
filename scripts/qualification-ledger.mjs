#!/usr/bin/env node
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TRACKS = {
  cli: {
    days: 30,
    prerequisites: ["exact_commit_compatibility", "cross_platform_performance", "containment_audit", "release_candidate_deployed"],
    resetRules: ["resolution", "lockfile", "lifecycle", "containment", "artifact_verification"],
  },
  registry: {
    days: 60,
    prerequisites: ["external_audits", "operational_drills", "hosted_failover", "release_candidate_deployed"],
    resetRules: ["architecture", "security_policy", "signing", "replication", "schema"],
  },
};

function option(args, name, fallback = null) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}

function options(args, name) {
  return args.flatMap((value, index) => value === name ? [args[index + 1]] : []).filter(Boolean);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

function signingPayload(ledger) {
  const copy = structuredClone(ledger);
  if (copy.signature) copy.signature.value_base64 = "";
  return Buffer.from(JSON.stringify(canonical(copy)));
}

function exactCommit(value) {
  if (!/^[0-9a-f]{40}$/.test(value ?? "")) throw new Error("release commit must be an exact lowercase 40-character Git commit");
  return value;
}

function digestReference(value, label) {
  const separator = value?.lastIndexOf("=") ?? -1;
  const name = value?.slice(0, separator);
  const sha256 = value?.slice(separator + 1);
  if (!name || !/^[0-9a-f]{64}$/.test(sha256 ?? "")) throw new Error(`${label} must be name-or-uri=<64 lowercase hex sha256>`);
  return { name, sha256 };
}

function dateOnly(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value ?? "") || Number.isNaN(Date.parse(`${value}T00:00:00Z`))) throw new Error("date must be YYYY-MM-DD");
  return value;
}

function candidateId(ledger) {
  return `${ledger.release_commit}:${ledger.artifact_digests.map(item => item.sha256).sort().join(":")}`;
}

function unsigned(ledger) {
  ledger.signature = null;
  return ledger;
}

function validation(ledger, { requireSignature = true, now = new Date() } = {}) {
  const errors = [];
  const track = TRACKS[ledger?.track];
  if (ledger?.schema_version !== 1 || ledger?.evidence_class !== "qualification-ledger") errors.push("invalid ledger identity");
  if (!track) errors.push("track must be cli or registry");
  if (!/^[0-9a-f]{40}$/.test(ledger?.release_commit ?? "")) errors.push("invalid release commit");
  if (ledger?.required_days !== track?.days) errors.push("required_days does not match track");
  if (!Array.isArray(ledger?.artifact_digests) || ledger.artifact_digests.length === 0 || ledger.artifact_digests.some(item => !item?.name || !/^[0-9a-f]{64}$/.test(item?.sha256 ?? ""))) errors.push("invalid artifact digests");
  const prerequisites = ledger?.prerequisites ?? [];
  for (const id of track?.prerequisites ?? []) {
    if (!prerequisites.some(item => item.id === id && item.status === "passed" && item.evidence?.uri && /^[0-9a-f]{64}$/.test(item.evidence?.sha256 ?? ""))) errors.push(`open prerequisite: ${id}`);
  }
  const observations = ledger?.window?.observations ?? [];
  const dates = observations.map(item => item.date);
  if (new Set(dates).size !== dates.length) errors.push("observation dates must be unique");
  const sorted = [...observations].sort((left, right) => left.date.localeCompare(right.date));
  for (let index = 0; index < sorted.length; index += 1) {
    const item = sorted[index];
    if (item.candidate_id !== ledger?.window?.candidate_id) errors.push(`candidate changed on ${item.date}`);
    if (item.healthy !== true || item.unresolved_critical !== 0) errors.push(`unhealthy observation on ${item.date}`);
    if (!Array.isArray(item.evidence) || item.evidence.length === 0 || item.evidence.some(ref => !ref.uri || !/^[0-9a-f]{64}$/.test(ref.sha256 ?? ""))) errors.push(`invalid observation evidence on ${item.date}`);
    if (index > 0 && Date.parse(`${item.date}T00:00:00Z`) - Date.parse(`${sorted[index - 1].date}T00:00:00Z`) !== 86_400_000) errors.push(`non-consecutive observations at ${sorted[index - 1].date} -> ${item.date}`);
  }
  if (["running", "completed"].includes(ledger?.state) && ledger?.window?.candidate_id !== candidateId(ledger)) errors.push("window candidate does not match commit and artifacts");
  if (ledger?.state === "completed" && observations.length < (track?.days ?? Infinity)) errors.push("completed ledger has too few observations");
  let signatureValid = false;
  if (ledger?.signature?.algorithm === "Ed25519") {
    try {
      signatureValid = verify(null, signingPayload(ledger), ledger.signature.public_key_pem, Buffer.from(ledger.signature.value_base64, "base64"));
    } catch {
      signatureValid = false;
    }
  }
  if (requireSignature && !signatureValid) errors.push("missing or invalid Ed25519 signature");
  const latest = sorted.at(-1)?.date ?? null;
  const ageHours = latest ? (now.getTime() - Date.parse(`${latest}T23:59:59Z`)) / 3_600_000 : null;
  const qualifies = errors.length === 0 && ledger.state === "completed" && observations.length >= track.days;
  return { valid: errors.length === 0, qualifies_for_ga: qualifies, signature_valid: signatureValid, track: ledger?.track ?? null, state: ledger?.state ?? null, observed_days: observations.length, required_days: track?.days ?? null, latest_observation: latest, latest_observation_age_hours: ageHours, errors };
}

async function readLedger(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

async function saveLedger(path, ledger) {
  await writeFile(resolve(path), `${JSON.stringify(ledger, null, 2)}\n`);
}

async function mutate(args, operation) {
  const input = args[1];
  if (!input) throw new Error(`${args[0]} requires a ledger path`);
  const ledger = await readLedger(input);
  await operation(unsigned(ledger));
  await saveLedger(option(args, "--output", input), ledger);
  return ledger;
}

async function selfTest() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const checksum = "a".repeat(64);
  const ledger = {
    schema_version: 1,
    evidence_class: "qualification-ledger",
    track: "cli",
    release_commit: "b".repeat(40),
    artifact_digests: [{ name: "oath", sha256: checksum }],
    required_days: 30,
    state: "completed",
    prerequisites: TRACKS.cli.prerequisites.map(id => ({ id, status: "passed", evidence: { uri: `synthetic://${id}`, sha256: checksum } })),
    reset_rules: TRACKS.cli.resetRules,
    window: {
      candidate_id: `${"b".repeat(40)}:${checksum}`,
      started_at: "2030-01-01T00:00:00.000Z",
      observations: Array.from({ length: 30 }, (_, index) => ({ date: new Date(Date.parse("2030-01-01T00:00:00Z") + index * 86_400_000).toISOString().slice(0, 10), candidate_id: `${"b".repeat(40)}:${checksum}`, healthy: true, unresolved_critical: 0, evidence: [{ uri: `synthetic://day/${index}`, sha256: checksum }] })),
      resets: [],
    },
    signature: { algorithm: "Ed25519", public_key_pem: publicKey.export({ type: "spki", format: "pem" }), signed_at: "2030-01-31T00:00:00.000Z", value_base64: "" },
  };
  ledger.signature.value_base64 = sign(null, signingPayload(ledger), privateKey).toString("base64");
  const passing = validation(ledger, { now: new Date("2030-01-31T00:00:00Z") });
  ledger.window.observations[0].healthy = false;
  const tampered = validation(ledger, { now: new Date("2030-01-31T00:00:00Z") });
  if (!passing.qualifies_for_ga || tampered.signature_valid || tampered.qualifies_for_ga) throw new Error("qualification ledger self-test failed");
  return { self_test: "passed", synthetic_only: true };
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  if (command === "--self-test") return console.log(JSON.stringify(await selfTest(), null, 2));
  if (command === "init") {
    const trackName = option(args, "--track");
    const track = TRACKS[trackName];
    if (!track) throw new Error("--track must be cli or registry");
    const artifacts = options(args, "--artifact").map(value => digestReference(value, "artifact"));
    if (!artifacts.length) throw new Error("at least one --artifact name=sha256 is required");
    const ledger = { schema_version: 1, evidence_class: "qualification-ledger", track: trackName, release_commit: exactCommit(option(args, "--commit")), artifact_digests: artifacts, required_days: track.days, state: "pending", prerequisites: track.prerequisites.map(id => ({ id, status: "open", evidence: null })), reset_rules: track.resetRules, window: { candidate_id: null, started_at: null, observations: [], resets: [] }, signature: null };
    const output = option(args, "--output");
    if (!output) throw new Error("--output is required");
    await saveLedger(output, ledger);
    return console.log(JSON.stringify({ output: resolve(output), track: trackName, state: "pending" }, null, 2));
  }
  if (command === "prerequisite") {
    const ledger = await mutate(args, async value => {
      const id = option(args, "--id");
      const target = value.prerequisites.find(item => item.id === id);
      if (!target) throw new Error(`unknown prerequisite: ${id}`);
      const evidence = digestReference(option(args, "--evidence"), "evidence");
      target.status = "passed";
      target.evidence = { uri: evidence.name, sha256: evidence.sha256 };
    });
    return console.log(JSON.stringify({ state: ledger.state, signature_invalidated: true }, null, 2));
  }
  if (command === "start") {
    const ledger = await mutate(args, async value => {
      const open = value.prerequisites.filter(item => item.status !== "passed" || !item.evidence);
      if (open.length) throw new Error(`cannot start; open prerequisites: ${open.map(item => item.id).join(", ")}`);
      value.state = "running";
      value.window.candidate_id = candidateId(value);
      value.window.started_at = option(args, "--at", new Date().toISOString());
      value.window.observations = [];
    });
    return console.log(JSON.stringify({ state: ledger.state, candidate_id: ledger.window.candidate_id }, null, 2));
  }
  if (command === "observe") {
    const ledger = await mutate(args, async value => {
      if (value.state !== "running") throw new Error("observations require a running window");
      const date = dateOnly(option(args, "--date"));
      if (value.window.observations.some(item => item.date === date)) throw new Error(`observation already exists: ${date}`);
      const evidence = options(args, "--evidence").map(item => digestReference(item, "evidence")).map(item => ({ uri: item.name, sha256: item.sha256 }));
      if (!evidence.length) throw new Error("at least one --evidence uri=sha256 is required");
      value.window.observations.push({ date, candidate_id: value.window.candidate_id, healthy: true, unresolved_critical: 0, evidence });
      value.window.observations.sort((left, right) => left.date.localeCompare(right.date));
      if (value.window.observations.length >= value.required_days && validation(value, { requireSignature: false }).errors.length === 0) value.state = "completed";
    });
    return console.log(JSON.stringify({ state: ledger.state, observed_days: ledger.window.observations.length, signature_invalidated: true }, null, 2));
  }
  if (command === "reset") {
    const ledger = await mutate(args, async value => {
      const rule = option(args, "--rule");
      const reason = option(args, "--reason");
      if (!value.reset_rules.includes(rule)) throw new Error(`unknown reset rule: ${rule}`);
      if (!reason) throw new Error("--reason is required");
      value.window.resets.push({ at: option(args, "--at", new Date().toISOString()), rule, reason, previous_candidate_id: value.window.candidate_id });
      value.window.candidate_id = null;
      value.window.started_at = null;
      value.window.observations = [];
      value.state = "reset";
      for (const prerequisite of value.prerequisites) {
        prerequisite.status = "open";
        prerequisite.evidence = null;
      }
      const commit = option(args, "--commit");
      if (commit) value.release_commit = exactCommit(commit);
      const artifacts = options(args, "--artifact");
      if (artifacts.length) value.artifact_digests = artifacts.map(item => digestReference(item, "artifact"));
    });
    return console.log(JSON.stringify({ state: ledger.state, resets: ledger.window.resets.length, signature_invalidated: true }, null, 2));
  }
  if (command === "sign") {
    const input = args[1];
    const keyPath = option(args, "--key");
    if (!input || !keyPath) throw new Error("sign requires ledger path and --key private-key.pem");
    const ledger = unsigned(await readLedger(input));
    const privateKey = createPrivateKey(await readFile(keyPath));
    const publicKey = createPublicKey(privateKey).export({ type: "spki", format: "pem" });
    ledger.signature = { algorithm: "Ed25519", public_key_pem: publicKey, signed_at: new Date().toISOString(), value_base64: "" };
    ledger.signature.value_base64 = sign(null, signingPayload(ledger), privateKey).toString("base64");
    await saveLedger(option(args, "--output", input), ledger);
    return console.log(JSON.stringify({ signed: true, algorithm: "Ed25519" }, null, 2));
  }
  if (["verify", "status"].includes(command)) {
    const ledger = await readLedger(args[1]);
    const result = validation(ledger, { requireSignature: command === "verify" });
    console.log(JSON.stringify(result, null, 2));
    if (command === "verify" && !result.valid) process.exitCode = 1;
    return;
  }
  throw new Error("usage: qualification-ledger.mjs init|prerequisite|start|observe|reset|sign|verify|status|--self-test");
}

export { TRACKS, validation };

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error.stack ?? error.message);
    process.exitCode = 1;
  });
}
