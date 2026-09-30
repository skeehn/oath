#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { cp, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { arch, cpus, freemem, homedir, hostname, platform, release, tmpdir, totalmem } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { installedTree } from "./tree-evidence.mjs";

const DEFAULT_MANIFEST = {
  name: "oath-installer-benchmark",
  version: "1.0.0",
  private: true,
  dependencies: {
    chalk: "5.6.2",
    express: "5.1.0",
    "is-number": "7.0.0",
    typescript: "5.9.3",
    vite: "7.3.1",
  },
};

const DEFAULTS = Object.freeze({
  installSamples: 200,
  assessmentSamples: 1000,
  execSamples: 200,
  minimumInstallSamples: 200,
  minimumAssessmentSamples: 1000,
  minimumExecSamples: 200,
  timeoutMs: 10 * 60 * 1000,
  coldRatioLimit: 1,
  warmRatioLimit: 1,
  warmNoopRatioLimit: 0.5,
  assessmentP95LimitMs: 100,
  execP95LimitMs: 2000,
  packageSpec: "prettier@3.7.4",
});

function integer(value, name, fallback) {
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(String(value)) || Number(value) < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return Number(value);
}

function number(value, name, fallback) {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`${name} must be a positive number`);
  return parsed;
}

function readOption(argv, name) {
  const equals = argv.find((arg) => arg.startsWith(`${name}=`));
  if (equals) return equals.slice(name.length + 1);
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  if (argv[index + 1] === undefined || argv[index + 1].startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return argv[index + 1];
}

function option(argv, name, envName, fallback) {
  return readOption(argv, name) ?? process.env[envName] ?? fallback;
}

export function parseConfiguration(argv = process.argv.slice(2)) {
  const installSamples = integer(option(argv, "--install-samples", "OATH_BENCHMARK_INSTALL_SAMPLES"), "install samples", DEFAULTS.installSamples);
  const assessmentSamples = integer(option(argv, "--assessment-samples", "OATH_BENCHMARK_ASSESSMENT_SAMPLES"), "assessment samples", DEFAULTS.assessmentSamples);
  const execSamples = integer(option(argv, "--exec-samples", "OATH_BENCHMARK_EXEC_SAMPLES"), "exec samples", DEFAULTS.execSamples);
  return {
    output: resolve(option(argv, "--output", "OATH_BENCHMARK_OUTPUT", "compat-results/benchmarks/performance-evidence-v2.json")),
    oath: resolve(option(argv, "--oath-bin", "OATH_BIN", "target/release/oath")),
    npm: option(argv, "--npm-bin", "OATH_BENCHMARK_NPM_BIN", "npm"),
    bun: option(argv, "--bun-bin", "OATH_BENCHMARK_BUN_BIN", "bun"),
    includeBun: argv.includes("--include-bun") || process.env.OATH_BENCHMARK_INCLUDE_BUN === "1",
    keep: argv.includes("--keep") || process.env.OATH_BENCHMARK_KEEP === "1",
    installSamples,
    assessmentSamples,
    execSamples,
    minimumInstallSamples: integer(option(argv, "--minimum-install-samples", "OATH_BENCHMARK_MIN_INSTALL_SAMPLES"), "minimum install samples", DEFAULTS.minimumInstallSamples),
    minimumAssessmentSamples: integer(option(argv, "--minimum-assessment-samples", "OATH_BENCHMARK_MIN_ASSESSMENT_SAMPLES"), "minimum assessment samples", DEFAULTS.minimumAssessmentSamples),
    minimumExecSamples: integer(option(argv, "--minimum-exec-samples", "OATH_BENCHMARK_MIN_EXEC_SAMPLES"), "minimum exec samples", DEFAULTS.minimumExecSamples),
    timeoutMs: integer(option(argv, "--timeout-ms", "OATH_BENCHMARK_TIMEOUT_MS"), "timeout", DEFAULTS.timeoutMs),
    coldRatioLimit: number(option(argv, "--cold-ratio-limit", "OATH_BENCHMARK_COLD_RATIO_LIMIT"), "cold ratio limit", DEFAULTS.coldRatioLimit),
    warmRatioLimit: number(option(argv, "--warm-ratio-limit", "OATH_BENCHMARK_WARM_RATIO_LIMIT"), "warm ratio limit", DEFAULTS.warmRatioLimit),
    warmNoopRatioLimit: number(option(argv, "--warm-noop-ratio-limit", "OATH_BENCHMARK_WARM_NOOP_RATIO_LIMIT"), "warm no-op ratio limit", DEFAULTS.warmNoopRatioLimit),
    assessmentP95LimitMs: number(option(argv, "--assessment-p95-limit-ms", "OATH_BENCHMARK_ASSESSMENT_P95_LIMIT_MS"), "assessment p95 limit", DEFAULTS.assessmentP95LimitMs),
    execP95LimitMs: number(option(argv, "--exec-p95-limit-ms", "OATH_BENCHMARK_EXEC_P95_LIMIT_MS"), "exec p95 limit", DEFAULTS.execP95LimitMs),
    packageSpec: option(argv, "--package", "OATH_BENCHMARK_PACKAGE", DEFAULTS.packageSpec),
    phaseWaiverReason: option(argv, "--phase-waiver-reason", "OATH_PHASE_WAIVER_REASON", null),
    phaseBaseline: option(argv, "--phase-baseline", "OATH_PHASE_BASELINE", null),
  };
}

export function percentile(values, quantile) {
  if (!Array.isArray(values) || values.length === 0) return null;
  if (!(quantile > 0 && quantile <= 1)) throw new Error("quantile must be greater than 0 and at most 1");
  const sorted = values.toSorted((a, b) => a - b);
  return sorted[Math.ceil(quantile * sorted.length) - 1];
}

export function summarizeSamples(samples) {
  const successful = samples.filter((sample) => sample.status === 0 && !sample.timed_out);
  const elapsed = successful.map((sample) => sample.elapsed_ms);
  return {
    requested: samples.length,
    successful: successful.length,
    failed: samples.length - successful.length,
    p50_ms: percentile(elapsed, 0.5),
    p95_ms: percentile(elapsed, 0.95),
    min_ms: elapsed.length ? Math.min(...elapsed) : null,
    max_ms: elapsed.length ? Math.max(...elapsed) : null,
    raw_samples: samples,
  };
}

function insufficient(name, reasons, observed, requirement) {
  return { name, status: "insufficient", observed, requirement, reasons };
}

/// Per-phase p95 timings from raw benchmark samples that recorded Oath phase
/// timings. Returns a map of phase name -> p95 milliseconds.
function phaseP95ByPhase(rawSamples) {
  const byPhase = new Map();
  for (const sample of rawSamples ?? []) {
    if (sample.status !== 0 || sample.timed_out) continue;
    const phases = sample.phase_timings_ms;
    if (!phases || typeof phases !== "object") continue;
    for (const [phase, ms] of Object.entries(phases)) {
      if (typeof ms !== "number" || !Number.isFinite(ms)) continue;
      if (!byPhase.has(phase)) byPhase.set(phase, []);
      byPhase.get(phase).push(ms);
    }
  }
  const result = {};
  for (const [phase, values] of byPhase) {
    result[phase] = percentile(values, 0.95);
  }
  return result;
}

/// Real phase-regression gate: compare current per-phase p95 timings against
/// an accepted baseline PerformanceEvidence document. Passes when no phase
/// regresses by more than 10%. An explicit waiver still passes with the waiver
/// recorded; with neither a baseline nor a waiver the gate is insufficient
/// rather than silently passing.
function phaseRegressionGate(benchmarks, config) {
  const name = "phase_regression";
  const requirement = {
    metric: "maximum warm_install per-phase oath p95 regression vs accepted baseline",
    maximum: 1.1,
  };
  if (config.phaseWaiverReason) {
    return {
      name,
      status: "pass",
      observed: null,
      requirement: { ...requirement, waiver: config.phaseWaiverReason },
      reasons: [`explicit waiver: ${config.phaseWaiverReason}`],
    };
  }
  if (!config.phaseBaseline) {
    return insufficient(
      name,
      ["no accepted phase baseline was supplied (use --phase-baseline <evidence.json>)"],
      null,
      requirement,
    );
  }
  let baseline;
  try {
    baseline = JSON.parse(readFileSync(config.phaseBaseline, "utf8"));
  } catch (error) {
    return insufficient(name, [`cannot read phase baseline: ${error.message}`], null, requirement);
  }
  const baselineP95 = phaseP95ByPhase(baseline?.benchmarks?.warm_install?.tools?.oath?.raw_samples);
  const currentP95 = phaseP95ByPhase(benchmarks?.warm_install?.tools?.oath?.raw_samples);
  const baselinePhases = Object.keys(baselineP95).filter((phase) => baselineP95[phase] > 0);
  const missing = baselinePhases.filter((phase) => typeof currentP95[phase] !== "number");
  if (missing.length > 0) {
    return insufficient(
      name,
      [`current run lacks baseline phases: ${missing.join(", ")}`],
      null,
      requirement,
    );
  }
  const phases = baselinePhases;
  if (phases.length === 0) {
    return insufficient(
      name,
      ["baseline or current run has no usable per-phase timings"],
      null,
      requirement,
    );
  }
  let worst = 0;
  let worstPhase = "";
  const regressions = [];
  for (const phase of phases) {
    const ratio = currentP95[phase] / baselineP95[phase];
    if (ratio > worst) {
      worst = ratio;
      worstPhase = phase;
    }
    if (ratio > requirement.maximum) regressions.push(`${phase}: ${ratio.toFixed(3)}x`);
  }
  return {
    name,
    status: worst <= requirement.maximum ? "pass" : "fail",
    observed: worst,
    requirement: { ...requirement, baseline: config.phaseBaseline, phases: phases.length },
    reasons:
      worst <= requirement.maximum
        ? []
        : [
            `phase regressions exceed 10% over ${phases.length} phases: ${regressions.join(", ")} (worst: ${worstPhase} ${worst.toFixed(3)}x)`,
          ],
  };
}

function ratioGate(name, oathSummary, npmSummary, minimum, limit) {
  const reasons = [];
  if (oathSummary.successful < minimum) reasons.push(`oath has ${oathSummary.successful} successful samples; ${minimum} required`);
  if (npmSummary.successful < minimum) reasons.push(`npm has ${npmSummary.successful} successful samples; ${minimum} required`);
  if (oathSummary.failed > 0) reasons.push(`oath has ${oathSummary.failed} failed samples`);
  if (npmSummary.failed > 0) reasons.push(`npm has ${npmSummary.failed} failed samples`);
  if (oathSummary.p95_ms === null || npmSummary.p95_ms === null || npmSummary.p95_ms === 0) reasons.push("a finite non-zero p95 is required for both tools");
  if (reasons.length) return insufficient(name, reasons, null, { metric: "oath_p95 / npm_p95", maximum: limit, minimum_samples_per_tool: minimum });
  const observed = oathSummary.p95_ms / npmSummary.p95_ms;
  return {
    name,
    status: observed <= limit ? "pass" : "fail",
    observed,
    requirement: { metric: "oath_p95 / npm_p95", maximum: limit, minimum_samples_per_tool: minimum },
    reasons: observed <= limit ? [] : [`observed ratio ${observed.toFixed(4)} exceeds ${limit}`],
  };
}

function absoluteGate(name, summary, minimum, limitMs) {
  const reasons = [];
  if (summary.successful < minimum) reasons.push(`${summary.successful} successful samples; ${minimum} required`);
  if (summary.failed > 0) reasons.push(`${summary.failed} samples failed`);
  if (summary.p95_ms === null) reasons.push("p95 is unavailable");
  if (reasons.length) return insufficient(name, reasons, summary.p95_ms, { metric: "p95_ms", maximum: limitMs, minimum_samples: minimum });
  return {
    name,
    status: summary.p95_ms <= limitMs ? "pass" : "fail",
    observed: summary.p95_ms,
    requirement: { metric: "p95_ms", maximum: limitMs, minimum_samples: minimum },
    reasons: summary.p95_ms <= limitMs ? [] : [`observed p95 ${summary.p95_ms.toFixed(3)} ms exceeds ${limitMs} ms`],
  };
}

export function evaluateGates(benchmarks, config, integrity = {}) {
  const gates = {
    cold_install: ratioGate("cold_install", benchmarks.cold_install.tools.oath, benchmarks.cold_install.tools.npm, config.minimumInstallSamples, config.coldRatioLimit),
    warm_install: ratioGate("warm_install", benchmarks.warm_install.tools.oath, benchmarks.warm_install.tools.npm, config.minimumInstallSamples, config.warmRatioLimit),
    cached_assessment: absoluteGate("cached_assessment", benchmarks.cached_assessment.tools.oath, config.minimumAssessmentSamples, config.assessmentP95LimitMs),
    cached_exec: absoluteGate("cached_exec", benchmarks.cached_exec.tools.oath, config.minimumExecSamples, config.execP95LimitMs),
  };
  if (benchmarks.warm_noop) {
    gates.warm_noop = ratioGate("warm_noop", benchmarks.warm_noop.tools.oath, benchmarks.warm_noop.tools.npm, config.minimumInstallSamples, config.warmNoopRatioLimit);
    gates.phase_regression = phaseRegressionGate(benchmarks, config);
  }
  if (integrity.treeEquivalent === false) {
    for (const key of ["cold_install", "warm_install"]) {
      gates[key] = insufficient(key, ["npm and Oath produced different node_modules trees"], gates[key].observed, gates[key].requirement);
    }
  }
  if (integrity.versionsComplete === false) {
    for (const gate of Object.values(gates)) {
      gate.status = "insufficient";
      gate.reasons = [...gate.reasons, "exact npm and Oath versions were not captured"];
    }
  }
  const statuses = Object.values(gates).map((gate) => gate.status);
  return {
    ...gates,
    overall: {
      status: statuses.every((status) => status === "pass") ? "pass" : statuses.includes("fail") ? "fail" : "insufficient",
      reasons: Object.values(gates).flatMap((gate) => gate.reasons.map((reason) => `${gate.name}: ${reason}`)),
    },
  };
}

function commandVersion(command, args, cwd, home, timeoutMs) {
  const result = run(command, args, cwd, home, timeoutMs, "version_probe", 0);
  return result.status === 0 ? result.stdout_tail.trim().split(/\r?\n/).at(-1) || null : null;
}

function fileSha256(path) {
  try {
    const direct = isAbsolute(path) || path.includes("/") || path.includes("\\");
    const extensions = process.platform === "win32"
      ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";")
      : [""];
    const candidates = direct
      ? [path]
      : (process.env.PATH ?? "").split(delimiter).flatMap(directory => extensions.map(extension => join(directory, `${path}${extension}`)));
    const executable = candidates.find(candidate => existsSync(candidate));
    if (!executable) return null;
    return createHash("sha256").update(readFileSync(executable)).digest("hex");
  } catch {
    return null;
  }
}

function sourceTreeClean() {
  const result = spawnSync("git", ["status", "--porcelain"], { cwd: process.cwd(), encoding: "utf8" });
  return result.status === 0 && result.stdout.trim() === "";
}

function run(command, args, cwd, home, timeoutMs, cacheState, sampleIndex) {
  const timingPath = join(cwd, `.oath-phase-timings-${process.pid}-${sampleIndex}.json`);
  const started = process.hrtime.bigint();
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: timeoutMs,
    windowsHide: true,
    env: {
      ...process.env,
      CI: "1",
      HOME: home,
      OATH_HOME: join(home, ".oath"),
      npm_config_cache: join(home, ".npm"),
      BUN_INSTALL_CACHE_DIR: join(home, ".bun-cache"),
      OATH_TIMINGS_FILE: timingPath,
    },
  });
  let phaseTimings = null;
  if (existsSync(timingPath)) {
    try {
      phaseTimings = JSON.parse(readFileSync(timingPath, "utf8")).phases_ms ?? null;
    } finally {
      rmSync(timingPath, { force: true });
    }
  }
  return {
    index: sampleIndex,
    elapsed_ms: Number(process.hrtime.bigint() - started) / 1e6,
    status: result.status,
    signal: result.signal,
    timed_out: result.error?.code === "ETIMEDOUT",
    error: result.error ? `${result.error.name}: ${result.error.message}` : null,
    cache_state: cacheState,
    stdout_tail: (result.stdout ?? "").slice(-1000),
    stderr_tail: (result.stderr ?? "").slice(-1000),
    phase_timings_ms: phaseTimings,
  };
}

async function treeDigest(dir) {
  const entries = await installedTree(join(dir, "node_modules"));
  return { entries: entries.length, sha256: createHash("sha256").update(entries.join("\n")).digest("hex") };
}

async function installSamples({ installer, seed, root, count, cacheState, timeoutMs }) {
  const samples = [];
  const sharedHome = join(root, `${installer.name}-${cacheState}-home`);
  await mkdir(sharedHome, { recursive: true });
  if (cacheState === "warm_shared_cache_no_node_modules") {
    const primeCwd = join(root, `${installer.name}-warm-prime`);
    await cp(seed, primeCwd, { recursive: true });
    const prime = run(installer.command, installer.args, primeCwd, sharedHome, timeoutMs, "untimed_cache_prime", 0);
    await rm(primeCwd, { recursive: true, force: true });
    if (prime.status !== 0) {
      return Array.from({ length: count }, (_, index) => ({ ...prime, index, cache_state: cacheState }));
    }
  }
  for (let index = 0; index < count; index += 1) {
    const cwd = join(root, `${installer.name}-${cacheState}-${index}`);
    const home = cacheState === "cold_empty_cache" ? join(root, `${installer.name}-cold-home-${index}`) : sharedHome;
    await cp(seed, cwd, { recursive: true });
    await mkdir(home, { recursive: true });
    const sample = run(installer.command, installer.args, cwd, home, timeoutMs, cacheState, index);
    sample.tree = await treeDigest(cwd);
    samples.push(sample);
    await rm(cwd, { recursive: true, force: true });
    if (cacheState === "cold_empty_cache") await rm(home, { recursive: true, force: true });
  }
  return samples;
}

async function noOpSamples({ installer, seed, root, count, timeoutMs }) {
  const cwd = join(root, `${installer.name}-warm-noop-project`);
  const home = join(root, `${installer.name}-warm-noop-home`);
  await cp(seed, cwd, { recursive: true });
  await mkdir(home, { recursive: true });
  const prime = run(installer.command, installer.args, cwd, home, timeoutMs, "warm_noop_prime", 0);
  if (prime.status !== 0) {
    return Array.from({ length: count }, (_, index) => ({ ...prime, index, cache_state: "warm_verified_noop" }));
  }
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    const sample = run(installer.command, installer.args, cwd, home, timeoutMs, "warm_verified_noop", index);
    sample.tree = await treeDigest(cwd);
    samples.push(sample);
  }
  return samples;
}

async function repeatedSamples({ command, args, cwd, home, count, timeoutMs, cacheState }) {
  const samples = [];
  for (let index = 0; index < count; index += 1) samples.push(run(command, args, cwd, home, timeoutMs, cacheState, index));
  return samples;
}

function captureEnvironment() {
  const processors = cpus();
  return {
    platform: platform(),
    architecture: arch(),
    os_release: release(),
    hostname_hash: createHash("sha256").update(hostname()).digest("hex"),
    cpu_model: processors[0]?.model ?? "unknown",
    logical_cpu_count: processors.length,
    total_memory_bytes: totalmem(),
    free_memory_bytes_at_start: freemem(),
    node_version: process.version,
    ci: process.env.CI ?? null,
    github_run_id: process.env.GITHUB_RUN_ID ?? null,
    git_commit: process.env.GITHUB_SHA ?? commandVersion("git", ["rev-parse", "HEAD"], process.cwd(), homedir(), 10_000),
    source_tree_clean: sourceTreeClean(),
  };
}

export function validatePerformanceEvidence(evidence) {
  const errors = [];
  if (![1, 2].includes(evidence?.schema_version) || evidence?.evidence_type !== "PerformanceEvidence") errors.push("schema identity is invalid");
  for (const key of ["cold_install", "warm_install", "cached_assessment", "cached_exec"]) {
    if (!evidence?.benchmarks?.[key]) errors.push(`missing benchmark ${key}`);
    if (!evidence?.gates?.[key]) errors.push(`missing gate ${key}`);
  }
  if (evidence?.schema_version === 2) {
    for (const key of ["warm_noop", "phase_regression"]) {
      if (!evidence?.benchmarks?.[key] && key === "warm_noop") errors.push(`missing benchmark ${key}`);
      if (!evidence?.gates?.[key]) errors.push(`missing gate ${key}`);
    }
    if (!Array.isArray(evidence?.phase_catalog) || evidence.phase_catalog.length < 12) errors.push("complete phase catalog is required");
    if (evidence?.environment?.source_tree_clean !== true) errors.push("performance evidence must be generated from a clean source tree");
    if (!/^[a-f0-9]{64}$/.test(evidence?.integrity?.input_lock_sha256 ?? "")) errors.push("exact input lockfile digest is required");
    for (const tool of ["npm", "oath"]) {
      if (!/^[a-f0-9]{64}$/.test(evidence?.tools?.[tool]?.binary_sha256 ?? "")) errors.push(`${tool} binary digest is required`);
    }
  }
  if (!evidence?.tools?.npm?.version || !evidence?.tools?.oath?.version) errors.push("exact npm and Oath versions are required");
  if (!evidence?.environment?.node_version) errors.push("environment.node_version is required");
  if (!evidence?.gates?.overall?.status) errors.push("overall gate status is required");
  return errors;
}

async function main() {
  const config = parseConfiguration();
  const root = await mkdtemp(join(tmpdir(), "oath-performance-evidence-"));
  try {
    const seed = join(root, "seed");
    const seedHome = join(root, "seed-home");
    await mkdir(seed);
    await mkdir(seedHome);
    await writeFile(join(seed, "package.json"), JSON.stringify(DEFAULT_MANIFEST, null, 2));
    const lock = run(config.npm, ["install", "--package-lock-only", "--ignore-scripts", "--no-audit"], seed, seedHome, config.timeoutMs, "lock_generation", 0);
    if (lock.status !== 0) throw new Error(`lock generation failed: ${lock.stderr_tail || lock.error}`);

    const installers = [
      { name: "npm", command: config.npm, args: ["install", "--ignore-scripts", "--no-audit", "--package-lock=true"] },
      { name: "oath", command: config.oath, args: ["install", "--ignore-scripts"] },
    ];
    if (config.includeBun) installers.push({ name: "bun", command: config.bun, args: ["install", "--ignore-scripts"] });

    const cold = {};
    const warm = {};
    const warmNoop = {};
    for (const installer of installers) {
      cold[installer.name] = summarizeSamples(await installSamples({ installer, seed, root, count: config.installSamples, cacheState: "cold_empty_cache", timeoutMs: config.timeoutMs }));
      warm[installer.name] = summarizeSamples(await installSamples({ installer, seed, root, count: config.installSamples, cacheState: "warm_shared_cache_no_node_modules", timeoutMs: config.timeoutMs }));
      warmNoop[installer.name] = summarizeSamples(await noOpSamples({ installer, seed, root, count: config.installSamples, timeoutMs: config.timeoutMs }));
    }

    const runtimeHome = join(root, "oath-runtime-home");
    const runtimeCwd = join(root, "oath-runtime-project");
    await mkdir(runtimeHome);
    await mkdir(runtimeCwd);
    await writeFile(join(runtimeCwd, "package.json"), JSON.stringify({ name: "oath-runtime-benchmark", version: "1.0.0", private: true }));
    const prime = run(config.oath, ["exec", "--dry-run", "--json", config.packageSpec], runtimeCwd, runtimeHome, config.timeoutMs, "prime_oath_cache", 0);
    const assessment = prime.status === 0
      ? await repeatedSamples({ command: config.oath, args: ["exec", "--dry-run", "--json", config.packageSpec], cwd: runtimeCwd, home: runtimeHome, count: config.assessmentSamples, timeoutMs: config.timeoutMs, cacheState: "cached_package_and_assessment_inputs" })
      : Array.from({ length: config.assessmentSamples }, (_, index) => ({ ...prime, index }));
    const exec = prime.status === 0
      ? await repeatedSamples({ command: config.oath, args: ["exec", "--yes", config.packageSpec, "--", "--version"], cwd: runtimeCwd, home: runtimeHome, count: config.execSamples, timeoutMs: config.timeoutMs, cacheState: "cached_package_and_prior_assessment" })
      : Array.from({ length: config.execSamples }, (_, index) => ({ ...prime, index }));

    const benchmarks = {
      cold_install: { unit: "milliseconds", cache_state: "fresh isolated cache and no node_modules for every sample", tools: cold },
      warm_install: { unit: "milliseconds", cache_state: "shared primed cache and no node_modules for every sample", tools: warm },
      warm_noop: { unit: "milliseconds", cache_state: "unchanged manifest, lockfile, policy, cache, lifecycle state, and node_modules", tools: warmNoop },
      cached_assessment: { unit: "milliseconds", cache_state: "package and assessment inputs cached after an untimed prime", tools: { oath: summarizeSamples(assessment) } },
      cached_exec: { unit: "milliseconds", cache_state: "package and assessment cached; measured command executes --version", tools: { oath: summarizeSamples(exec) } },
    };
    const tools = {
      npm: { command: config.npm, version: commandVersion(config.npm, ["--version"], root, seedHome, config.timeoutMs), binary_sha256: fileSha256(config.npm) },
      oath: { command: config.oath, version: commandVersion(config.oath, ["--version"], root, runtimeHome, config.timeoutMs), binary_sha256: fileSha256(config.oath) },
      ...(config.includeBun ? { bun: { command: config.bun, version: commandVersion(config.bun, ["--version"], root, seedHome, config.timeoutMs) } } : {}),
    };
    const npmTrees = new Set([...cold.npm.raw_samples, ...warm.npm.raw_samples].filter((sample) => sample.status === 0).map((sample) => sample.tree.sha256));
    const oathTrees = new Set([...cold.oath.raw_samples, ...warm.oath.raw_samples].filter((sample) => sample.status === 0).map((sample) => sample.tree.sha256));
    const integrity = { tree_equivalent: npmTrees.size === 1 && oathTrees.size === 1 && [...npmTrees][0] === [...oathTrees][0], npm_tree_digests: [...npmTrees], oath_tree_digests: [...oathTrees], input_lock_sha256: fileSha256(join(seed, "package-lock.json")) };
    const gates = evaluateGates(benchmarks, config, { treeEquivalent: integrity.tree_equivalent, versionsComplete: Boolean(tools.npm.version && tools.oath.version) });
    const evidence = {
      schema_version: 2,
      evidence_type: "PerformanceEvidence",
      generated_at: new Date().toISOString(),
      environment: captureEnvironment(),
      tools,
      configuration: {
        requested_samples: { cold_install: config.installSamples, warm_install: config.installSamples, warm_noop: config.installSamples, cached_assessment: config.assessmentSamples, cached_exec: config.execSamples },
        minimum_qualifying_samples: { cold_install: config.minimumInstallSamples, warm_install: config.minimumInstallSamples, warm_noop: config.minimumInstallSamples, cached_assessment: config.minimumAssessmentSamples, cached_exec: config.minimumExecSamples },
        thresholds: { cold_install_oath_to_npm_p95_maximum: config.coldRatioLimit, warm_install_oath_to_npm_p95_maximum: config.warmRatioLimit, warm_noop_oath_to_npm_p95_maximum: config.warmNoopRatioLimit, maximum_phase_p95_regression: 0.1, cached_assessment_p95_ms_maximum: config.assessmentP95LimitMs, cached_exec_p95_ms_maximum: config.execP95LimitMs },
        timeout_ms: config.timeoutMs,
        package_spec: config.packageSpec,
        dependency_manifest: DEFAULT_MANIFEST.dependencies,
        phase_regression_waiver: config.phaseWaiverReason,
        phase_regression_baseline: config.phaseBaseline,
      },
      methodology: {
        percentile: "nearest-rank over successful samples; rank = ceil(q * n)",
        process_timing: "monotonic process.hrtime.bigint around spawnSync, including process startup and shutdown",
        lifecycle_scripts: "disabled for installer measurements",
        npm_audit: "disabled",
        oath_scanner: "enabled",
        sample_order: "tools measured sequentially: npm, oath, then optional bun",
        exclusions: [],
      },
      integrity,
      phase_catalog: ["noop_validation", "resolve", "metadata", "download", "integrity", "extraction", "analysis", "policy", "link", "lifecycle", "lockfile", "cleanup"],
      benchmarks,
      gates,
    };
    const validationErrors = validatePerformanceEvidence(evidence);
    if (validationErrors.length) {
      evidence.gates.overall = { status: "insufficient", reasons: validationErrors };
    }
    await mkdir(dirname(config.output), { recursive: true });
    await writeFile(config.output, `${JSON.stringify(evidence, null, 2)}\n`);
    console.log(JSON.stringify(evidence, null, 2));
    if (evidence.gates.overall.status !== "pass") process.exitCode = 1;
  } finally {
    if (!config.keep) await rm(root, { recursive: true, force: true });
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`performance benchmark failed: ${error.stack ?? error.message}`);
    process.exitCode = 1;
  });
}
