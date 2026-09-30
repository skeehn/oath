import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { evaluateGates, parseConfiguration, percentile, summarizeSamples, validatePerformanceEvidence } from "./benchmark-installers.mjs";

function summary(values, failures = 0) {
  return summarizeSamples([
    ...values.map((elapsed_ms, index) => ({ index, elapsed_ms, status: 0, timed_out: false })),
    ...Array.from({ length: failures }, (_, index) => ({ index: values.length + index, elapsed_ms: 1, status: 1, timed_out: false })),
  ]);
}

function config(overrides = {}) {
  return {
    minimumInstallSamples: 3,
    minimumAssessmentSamples: 3,
    minimumExecSamples: 3,
    coldRatioLimit: 1.2,
    warmRatioLimit: 1,
    assessmentP95LimitMs: 100,
    execP95LimitMs: 2000,
    ...overrides,
  };
}

function benchmarks({ npm = [100, 110, 120], oath = [100, 120, 140], assessment = [50, 60, 70], exec = [500, 600, 700] } = {}) {
  return {
    cold_install: { tools: { npm: summary(npm), oath: summary(oath) } },
    warm_install: { tools: { npm: summary(npm), oath: summary(oath) } },
    cached_assessment: { tools: { oath: summary(assessment) } },
    cached_exec: { tools: { oath: summary(exec) } },
  };
}

test("nearest-rank percentiles and summaries retain raw samples", () => {
  assert.equal(percentile([5, 1, 4, 2, 3], 0.5), 3);
  assert.equal(percentile(Array.from({ length: 20 }, (_, index) => index + 1), 0.95), 19);
  assert.equal(percentile([], 0.95), null);
  const result = summary([3, 1, 2], 1);
  assert.equal(result.p50_ms, 2);
  assert.equal(result.p95_ms, 3);
  assert.equal(result.successful, 3);
  assert.equal(result.failed, 1);
  assert.equal(result.raw_samples.length, 4);
});

test("sampling and thresholds are configurable from CLI arguments", () => {
  const parsed = parseConfiguration([
    "--install-samples", "7",
    "--assessment-samples=11",
    "--exec-samples", "9",
    "--minimum-install-samples", "5",
    "--cold-ratio-limit", "1.15",
    "--include-bun",
  ]);
  assert.equal(parsed.installSamples, 7);
  assert.equal(parsed.assessmentSamples, 11);
  assert.equal(parsed.execSamples, 9);
  assert.equal(parsed.minimumInstallSamples, 5);
  assert.equal(parsed.coldRatioLimit, 1.15);
  assert.equal(parsed.includeBun, true);
  assert.throws(() => parseConfiguration(["--install-samples", "0"]), /positive integer/);
});

test("all four gates pass only with sufficient successful evidence", () => {
  const gates = evaluateGates(benchmarks(), config(), { treeEquivalent: true, versionsComplete: true });
  assert.equal(gates.cold_install.status, "pass");
  assert.equal(gates.warm_install.status, "fail");
  assert.equal(gates.cached_assessment.status, "pass");
  assert.equal(gates.cached_exec.status, "pass");
  assert.equal(gates.overall.status, "fail");
});

test("too few samples, failed commands, tree mismatch, and missing versions are insufficient", () => {
  const tooFew = benchmarks({ npm: [100, 110], oath: [100, 110], assessment: [50, 60], exec: [500, 600] });
  const gates = evaluateGates(tooFew, config(), { treeEquivalent: false, versionsComplete: false });
  for (const name of ["cold_install", "warm_install", "cached_assessment", "cached_exec"]) {
    assert.equal(gates[name].status, "insufficient");
    assert.ok(gates[name].reasons.length > 0);
  }
  assert.equal(gates.overall.status, "insufficient");
});

test("PerformanceEvidence v1 schema and runtime validator require the complete evidence surface", async () => {
  const schemaPath = fileURLToPath(new URL("../contracts/performance-evidence-v1.schema.json", import.meta.url));
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.properties.schema_version.const, 1);
  assert.deepEqual(schema.properties.benchmarks.required, ["cold_install", "warm_install", "cached_assessment", "cached_exec"]);
  assert.deepEqual(schema.properties.gates.required, ["cold_install", "warm_install", "cached_assessment", "cached_exec", "overall"]);

  const errors = validatePerformanceEvidence({
    schema_version: 1,
    evidence_type: "PerformanceEvidence",
    environment: { node_version: process.version },
    tools: { npm: { version: "11.0.0" }, oath: { version: "0.3.0" } },
    benchmarks: Object.fromEntries(["cold_install", "warm_install", "cached_assessment", "cached_exec"].map((key) => [key, {}])),
    gates: { ...Object.fromEntries(["cold_install", "warm_install", "cached_assessment", "cached_exec"].map((key) => [key, {}])), overall: { status: "pass" } },
  });
  assert.deepEqual(errors, []);
  assert.ok(validatePerformanceEvidence({}).length >= 7);
});

test("PerformanceEvidence v2 requires warm no-op and phase regression evidence", async () => {
  const schemaPath = fileURLToPath(new URL("../contracts/performance-evidence-v2.schema.json", import.meta.url));
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  assert.equal(schema.properties.schema_version.const, 2);
  assert.ok(schema.properties.benchmarks.required.includes("warm_noop"));
  assert.ok(schema.properties.gates.required.includes("phase_regression"));

  const errors = validatePerformanceEvidence({
    schema_version: 2,
    evidence_type: "PerformanceEvidence",
    environment: { node_version: process.version, source_tree_clean: true },
    tools: { npm: { version: "11.12.1", binary_sha256: "a".repeat(64) }, oath: { version: "0.3.0", binary_sha256: "b".repeat(64) } },
    integrity: { input_lock_sha256: "c".repeat(64) },
    benchmarks: Object.fromEntries(["cold_install", "warm_install", "warm_noop", "cached_assessment", "cached_exec"].map((key) => [key, {}])),
    phase_catalog: schema.properties.phase_catalog.items.enum,
    gates: { ...Object.fromEntries(["cold_install", "warm_install", "warm_noop", "cached_assessment", "cached_exec", "phase_regression"].map((key) => [key, {}])), overall: { status: "pass" } },
  });
  assert.deepEqual(errors, []);
});

test("phase_regression gate requires a baseline or an explicit waiver", async () => {
  const { mkdtemp, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");

  const withPhases = (phases) => ({
    ...benchmarks(),
    warm_noop: { tools: { npm: summary([100, 110, 120]), oath: summary([100, 120, 140]) } },
    warm_install: {
      tools: {
        npm: summary([100, 110, 120]),
        oath: {
          ...summary([100, 120, 140]),
          raw_samples: [{ status: 0, timed_out: false, phase_timings_ms: phases }],
        },
      },
    },
  });

  // No baseline and no waiver -> insufficient, not a silent pass.
  const gates = evaluateGates(withPhases({ resolve: 10 }), config(), { treeEquivalent: true, versionsComplete: true });
  assert.equal(gates.phase_regression.status, "insufficient");
  assert.ok(gates.phase_regression.reasons.some((reason) => reason.includes("baseline")));

  // Explicit waiver -> pass with the waiver recorded.
  const waived = evaluateGates(
    withPhases({ resolve: 10 }),
    config({ phaseWaiverReason: "first run, no accepted baseline yet" }),
    { treeEquivalent: true, versionsComplete: true },
  );
  assert.equal(waived.phase_regression.status, "pass");
  assert.ok(waived.phase_regression.requirement.waiver.includes("first run"));

  // Baseline with no regression -> pass.
  const dir = await mkdtemp(join(tmpdir(), "oath-phase-baseline-"));
  const baselinePath = join(dir, "baseline.json");
  await writeFile(baselinePath, JSON.stringify({
    benchmarks: {
      warm_install: {
        tools: { oath: { raw_samples: [{ status: 0, timed_out: false, phase_timings_ms: { resolve: 100 } }] } },
      },
    },
  }));
  const passing = evaluateGates(
    withPhases({ resolve: 105 }),
    config({ phaseBaseline: baselinePath }),
    { treeEquivalent: true, versionsComplete: true },
  );
  assert.equal(passing.phase_regression.status, "pass");

  // Baseline with >10% regression -> fail.
  const failing = evaluateGates(
    withPhases({ resolve: 120 }),
    config({ phaseBaseline: baselinePath }),
    { treeEquivalent: true, versionsComplete: true },
  );
  assert.equal(failing.phase_regression.status, "fail");
  assert.ok(failing.phase_regression.reasons.some((reason) => reason.includes("resolve")));
});
