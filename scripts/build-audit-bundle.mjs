#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const output = resolve(process.argv[2] ?? "audit-dist");
const allowDirty = process.argv.includes("--allow-dirty");
const internalReviewIndex = process.argv.indexOf("--internal-review");
const internalReview = internalReviewIndex === -1 ? null : resolve(process.argv[internalReviewIndex + 1]);
const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const dirtyLines = execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim().split("\n").filter(Boolean);
if (dirtyLines.length && !allowDirty) throw new Error("audit bundles must be built from a clean exact commit");

const inputs = [
  ".github/workflows/ci.yml",
  ".github/workflows/release.yml",
  "Cargo.lock",
  "Cargo.toml",
  "crates/oath-analyze/Cargo.toml",
  "crates/oath-cli/Cargo.toml",
  "crates/oath-registry/Cargo.toml",
  "crates/oath-resolve/Cargo.toml",
  "crates/oath-sandbox/Cargo.toml",
  "crates/oath-store/Cargo.toml",
  "contracts/exec-assessment-v3.schema.json",
  "contracts/compatibility-evidence-v1.schema.json",
  "contracts/npm-compatibility-manifest-v2.json",
  "contracts/publish-assessment-v2.schema.json",
  "contracts/registry-verdict-v1.schema.json",
  "contracts/detection-evidence-v2.schema.json",
  "contracts/independent-audit-report-v1.schema.json",
  "contracts/operational-drill-report-v2.schema.json",
  "contracts/performance-evidence-v1.schema.json",
  "contracts/performance-evidence-v2.schema.json",
  "contracts/production-deployment-evidence-v1.schema.json",
  "contracts/qualification-ledger-v1.schema.json",
  "contracts/transparency-checkpoint-v3.schema.json",
  "crates/oath-analyze/examples/detection_gate.rs",
  "docs/BETA_EVIDENCE.md",
  "docs/EXTERNAL_AUDIT_SCOPE.md",
  "docs/GA_GATE_TRACKER.md",
  "docs/INCIDENT_RESPONSE.md",
  "docs/NPM_COMPATIBILITY_CONTRACT.md",
  "docs/QUALIFICATION_OPERATIONS.md",
  "docs/REGISTRY_OPERATIONS.md",
  "docs/SCANNER_THREAT_MODEL.md",
  "docs/SERVICE_LEVEL_OBJECTIVES.md",
  "docs/SUPPORTED_PLATFORMS.md",
  "tests/detection/corpus-metadata.schema.json",
  "tests/compat/behavioral-contract.json",
  "tests/compat/command-surface-contract.json",
  "tests/compat/projects.lock.json",
  "scripts/compat-scale.mjs",
  "scripts/compat-behavioral.mjs",
  "scripts/compat-command-surface.mjs",
  "scripts/compat-pty.py",
  "scripts/compat-registry-fixture.mjs",
  "scripts/benchmark-installers.mjs",
  "scripts/benchmark-installers.test.mjs",
  "scripts/generate-ga-evidence.mjs",
  "scripts/project-corpus.mjs",
  "scripts/qualification-ledger.mjs",
  "scripts/monitor-qualification.mjs",
  "scripts/run-internal-containment-review.mjs",
  "scripts/run-operational-drill.mjs",
  "scripts/validate-beta-ledger.mjs",
  "crates/oath-registry/migrations/0001_registry.sql",
  "crates/oath-registry/migrations/0002_ga_foundation.sql",
  "crates/oath-registry/migrations/0003_limits.sql",
  "crates/oath-registry/migrations/0004_outbox_leases.sql",
  "crates/oath-registry/migrations/0005_tenant_rls.sql",
].map((path) => path === "docs/SCANNER_THREAT_MODEL.md" ? "docs/scanner-threat-model.md" : path);

const auditedPrefixes = [
  "crates/oath-analyze/src/",
  "crates/oath-analyze/tests/",
  "crates/oath-cli/src/",
  "crates/oath-resolve/src/",
  "crates/oath-sandbox/src/",
  "crates/oath-sandbox/tests/",
  "crates/oath-store/src/",
  "crates/oath-registry/src/",
  "deploy/",
];
const trackedAuditedSources = execFileSync("git", ["ls-files", ...auditedPrefixes], { encoding: "utf8" }).trim().split("\n").filter(Boolean);
const uniqueInputs = [...new Set([...inputs, ...trackedAuditedSources])].sort();

await rm(output, { recursive: true, force: true });
const artifacts = [];
for (const source of uniqueInputs) {
  const bytes = await readFile(source);
  const destination = join(output, "inputs", source);
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination);
  artifacts.push({
    path: source,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
}
if (internalReview) {
  const bytes = await readFile(internalReview);
  const source = "generated/internal-containment-review.json";
  const destination = join(output, "inputs", source);
  await mkdir(dirname(destination), { recursive: true });
  await cp(internalReview, destination);
  artifacts.push({ path: source, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
}
const manifest = {
  schema_version: 1,
  evidence_class: "external-audit-input-bundle",
  commit,
  dirty: dirtyLines.length > 0,
  qualifying_input_bundle: dirtyLines.length === 0,
  generated_at: new Date().toISOString(),
  limitations: [
    "This bundle prepares review inputs; it is not an independent audit result.",
    "External reviewers must issue and sign their own reports and findings ledger.",
  ],
  artifacts,
};
await writeFile(join(output, "audit-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
const checksums = artifacts.map(({ sha256, path }) => `${sha256}  inputs/${path}`);
const manifestBytes = await readFile(join(output, "audit-manifest.json"));
checksums.push(`${createHash("sha256").update(manifestBytes).digest("hex")}  audit-manifest.json`);
await writeFile(join(output, "SHA256SUMS"), `${checksums.join("\n")}\n`);
console.log(JSON.stringify({ output, commit, dirty: manifest.dirty, artifacts: artifacts.length }, null, 2));
