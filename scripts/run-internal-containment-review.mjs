#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const outputIndex = process.argv.indexOf("--output");
const output = resolve(outputIndex === -1 ? "internal-containment-review.json" : process.argv[outputIndex + 1]);
const oath = resolve(process.env.OATH_BIN ?? "target/debug/oath");
// Portable scratch space: /private/tmp only exists on macOS, so derive from
// the OS temp dir instead of hardcoding it.
const scratch = process.env.OATH_CONTAINMENT_REVIEW_DIR ?? join(tmpdir(), "oath-containment-review");
const target = process.env.CARGO_TARGET_DIR ?? join(scratch, "target");
const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const dirty = execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim().length > 0;

const reviews = [
  { id: "static-adversarial-analysis", command: "cargo", args: ["test", "--locked", "-p", "oath-analyze", "--test", "analysis"], threats: ["dormant payload", "delayed execution", "obfuscation", "token discovery", "exfiltration", "large file", "invalid UTF-8", "parser failure"] },
  { id: "sandbox-policy-and-adversarial", command: "cargo", args: ["test", "--locked", "-p", "oath-sandbox", "--test", "sandbox"], threats: ["secret environment", "outside write", "network", "process credentials", "Unix socket", "child process", "timeout"] },
  { id: "cli-fail-closed-selection", command: "cargo", args: ["test", "--locked", "-p", "oath-cli", "exec_auto_"], threats: ["unavailable backend", "degraded backend", "explicit portable fallback"] },
  { id: "analysis-worker-authentication", command: "cargo", args: ["test", "--locked", "-p", "oath-registry", "analysis_backend::tests"], threats: ["unauthenticated worker access", "worker readiness"] },
];

function execute(review) {
  const started = new Date();
  const result = spawnSync(review.command, review.args, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, CARGO_TARGET_DIR: target },
  });
  const combined = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const ignored = [...combined.matchAll(/(\d+) ignored/g)].reduce((total, match) => total + Number(match[1]), 0);
  return {
    ...review,
    status: result.status,
    passed: result.status === 0,
    ignored_tests_reported: ignored,
    started_at: started.toISOString(),
    duration_ms: Date.now() - started.getTime(),
    stdout_sha256: createHash("sha256").update(result.stdout ?? "").digest("hex"),
    stderr_sha256: createHash("sha256").update(result.stderr ?? "").digest("hex"),
    output_tail: combined.trim().split("\n").slice(-20),
  };
}

const results = reviews.map(execute);
let capabilities = null;
const capabilityResult = spawnSync(oath, ["capabilities", "--json"], { encoding: "utf8", env: { ...process.env, OATH_HOME: process.env.OATH_CONTAINMENT_REVIEW_HOME ?? join(scratch, "home") } });
try {
  capabilities = JSON.parse(capabilityResult.stdout);
} catch {
  capabilities = { parse_error: true, stdout: capabilityResult.stdout, stderr: capabilityResult.stderr };
}

const report = {
  schema_version: 1,
  evidence_class: "internal-containment-review",
  generated_at: new Date().toISOString(),
  release_commit: commit,
  dirty,
  platform: process.platform,
  architecture: process.arch,
  external_audit: false,
  qualifies_as_external_audit: false,
  capability_command_status: capabilityResult.status,
  capabilities,
  reviews: results,
  summary: { executed: results.length, passed: results.filter(item => item.passed).length, failed: results.filter(item => !item.passed).length, ignored_tests_reported: results.reduce((total, item) => total + item.ignored_tests_reported, 0) },
  limitations: [
    "This is an engineering self-review, not an independent containment audit.",
    "Native release tests reported as ignored require their dedicated operating-system runners.",
    "A signed external report and sealed-corpus qualification remain mandatory GA inputs.",
  ],
};
await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ output, ...report.summary, capability_command_status: capabilityResult.status, external_audit: false }, null, 2));
if (report.summary.failed > 0 || capabilityResult.status !== 0) process.exitCode = 1;
