import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const generator = fileURLToPath(new URL("./generate-ga-evidence.mjs", import.meta.url));

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function generateEvidence({ workflows, projects, executions, extraReports = [] }) {
  const root = await mkdtemp(join(tmpdir(), "oath-ga-evidence-"));
  const input = join(root, "input");
  const output = join(root, "manifest.json");

  for (let platform = 0; platform < 3; platform += 1) {
    await writeJson(join(input, `platform-${platform}`, "behavioral-summary.json"), {
      executed: workflows,
      equivalent: workflows,
      failed: 0,
    });
  }
  await writeJson(join(input, "projects", "project-summary.json"), {
    target: projects,
    exact_equivalents: projects,
    failures: [],
  });
  await writeJson(join(input, "stress", "generated.json"), {
    evidence_class: "generated_stress",
    results: Array.from({ length: executions }, () => ({ equivalent: true })),
  });
  for (const [index, report] of extraReports.entries()) {
    await writeJson(join(input, "extra", `${index}.json`), report);
  }

  await execFileAsync(process.execPath, [generator, input, output], {
    env: { ...process.env, GITHUB_SHA: "a".repeat(40) },
  });
  return JSON.parse(await readFile(output, "utf8"));
}

test("moves satisfied measured gates out of the open list", async () => {
  const manifest = await generateEvidence({ workflows: 100, projects: 250, executions: 10000 });

  assert.deepEqual(manifest.ga_gate.open_evidence_gates, [
    "qualifying detection thresholds",
    "cross-platform npm/npx compatibility manifest",
    "cross-platform performance v2 thresholds",
    "witnessed transparency checkpoint",
    "independent architecture, penetration, and sandbox reviews",
    "60-day production SLO and disaster-drill ledger",
    "multi-region production registry deployment",
    "registry release candidate deployment identity",
  ]);
  assert.equal(manifest.ga_gate.technical_ready, false);
  assert.deepEqual(manifest.ga_gate.completed_evidence_gates, [
    "100 independent workflows across required platforms",
    "250 pinned real projects",
    "10000 generated executions",
  ]);
  assert.equal(manifest.ga_gate.open_external_gates.includes("250 pinned real projects"), false);
  assert.equal(manifest.ga_gate.ready, false);
});

test("fails closed when a detection report claims pass with incomplete scans", async () => {
  const measurement = {
    dataset_digest: `sha256:${"b".repeat(64)}`,
    discovered: 10,
    scanned: 9,
    blocked: 9,
    rate: 1,
    wilson_95: { lower: 0.7, upper: 1 },
    exclusions: [],
    scan_errors: [],
  };
  const report = {
    schema_version: 2,
    evidence_class: "detection-quality",
    qualification: "qualifying",
    release_commit: "a".repeat(40),
    qualifies_for_ga: true,
    errors: [],
    corpora: {
      known_malware: measurement,
      benign: { ...measurement, rate: 0, blocked: 0 },
      private_holdout: {
        ...measurement,
        family_separated: true,
        time_separated: true,
        labels_independently_held: true,
      },
      secret_exfiltration: measurement,
    },
  };
  const manifest = await generateEvidence({ workflows: 100, projects: 250, executions: 10000, extraReports: [report] });
  assert.equal(manifest.ga_gate.open_evidence_gates.includes("qualifying detection thresholds"), true);
});

test("accepts performance only after every supported OS passes on the exact commit", async () => {
  const performance = (platform) => ({
    schema_version: 2,
    evidence_type: "PerformanceEvidence",
    generated_at: new Date().toISOString(),
    environment: { platform, git_commit: "a".repeat(40) },
    integrity: { tree_equivalent: true },
    configuration: {
      minimum_qualifying_samples: {
        cold_install: 200,
        warm_install: 200,
        warm_noop: 200,
        cached_assessment: 1000,
        cached_exec: 200,
      },
    },
    gates: {
      cold_install: { status: "pass" },
      warm_install: { status: "pass" },
      warm_noop: { status: "pass" },
      phase_regression: { status: "pass" },
      cached_assessment: { status: "pass" },
      cached_exec: { status: "pass" },
      overall: { status: "pass" },
    },
  });
  const manifest = await generateEvidence({
    workflows: 100,
    projects: 250,
    executions: 10000,
    extraReports: [performance("linux"), performance("darwin"), performance("win32")],
  });
  assert.equal(manifest.ga_gate.completed_evidence_gates.includes("cross-platform performance v2 thresholds"), true);
  assert.equal(manifest.release_tracks.cli.completed_evidence_gates.includes("cross-platform performance v2 thresholds"), true);
});

test("keeps CLI and Registry readiness independent", async () => {
  const compatibility = {
    schema_version: 1,
    evidence_type: "CompatibilityEvidence",
    generated_at: new Date().toISOString(),
    release_commit: "a".repeat(40),
    platforms: ["linux", "darwin", "win32"],
    node_versions: ["20", "22", "24"],
    commands: [{}],
    summary: { executed: 10, equivalent: 10, failed: 0 },
    qualifies_for_cli_ga: true,
  };
  const manifest = await generateEvidence({ workflows: 100, projects: 250, executions: 10000, extraReports: [compatibility] });
  assert.equal(manifest.release_tracks.cli.completed_evidence_gates.includes("cross-platform npm/npx compatibility manifest"), true);
  assert.equal(manifest.release_tracks.registry.completed_evidence_gates.includes("cross-platform npm/npx compatibility manifest"), false);
});

test("keeps under-threshold measured gates open", async () => {
  const manifest = await generateEvidence({ workflows: 99, projects: 249, executions: 9999 });

  assert.deepEqual(manifest.ga_gate.completed_evidence_gates, []);
  assert.deepEqual(manifest.ga_gate.open_evidence_gates.slice(0, 3), [
    "100 independent workflows across required platforms",
    "250 pinned real projects",
    "10000 generated executions",
  ]);
});
