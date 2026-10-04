#!/usr/bin/env node
// Exec parity: run every case in tests/compat/exec-fixtures.json with npx
// (npm 11) and with `oath x`, each in a fresh HOME, and compare exit code and
// normalized stdout. Oath's own messages go to stderr, so stdout is the
// program's output in both tools.
//
//   OATH_BIN=target/debug/oath node scripts/exec-parity.mjs
//   OATH_EXEC_PARITY_ONLY=cowsay-hello,tsc-version node scripts/exec-parity.mjs
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { compareRuns, expandArgs, npxArgs, oathArgs } from "./exec-parity-lib.mjs";

const referenceNpmMajor = 11;
const fixtureFile = new URL("../tests/compat/exec-fixtures.json", import.meta.url);
const fixturesRoot = resolve("tests/compat/exec-fixtures");
const oath = resolve(process.env.OATH_BIN ?? "target/debug/oath");
const output = resolve(process.env.OATH_EXEC_PARITY_RESULTS ?? "compat-results/exec-parity");
const only = process.env.OATH_EXEC_PARITY_ONLY ? new Set(process.env.OATH_EXEC_PARITY_ONLY.split(",")) : null;
const windows = process.platform === "win32";
const npmCommand = windows ? "npm.cmd" : "npm";
const npxCommand = windows ? "npx.cmd" : "npx";
const timeout = Number(process.env.OATH_EXEC_PARITY_TIMEOUT_MS ?? 600_000);

function run(command, args, cwd, home, extraEnv = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout,
    killSignal: "SIGKILL",
    shell: windows && command.toLowerCase().endsWith(".cmd"),
    env: {
      ...process.env,
      CI: "1",
      HOME: home,
      USERPROFILE: home,
      OATH_HOME: join(home, ".oath"),
      npm_config_cache: join(home, ".npm"),
      npm_config_update_notifier: "false",
      npm_config_fund: "false",
      npm_config_audit: "false",
      NO_COLOR: "1",
      ...extraEnv
    }
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    elapsed_ms: Date.now() - started,
    ...(result.error ? { error: { code: result.error.code, message: result.error.message } } : {})
  };
}

const npmVersion = run(npmCommand, ["--version"], process.cwd(), tmpdir()).stdout.trim();
if (Number(npmVersion.split(".")[0]) !== referenceNpmMajor) {
  throw new Error(`npm ${referenceNpmMajor}.x is the exec parity reference; found ${npmVersion}`);
}

const contract = JSON.parse(await readFile(fixtureFile, "utf8"));
const results = [];
await mkdir(output, { recursive: true });

for (const testCase of contract.cases) {
  if (only && !only.has(testCase.id)) continue;
  if (testCase.platforms && !testCase.platforms.includes(process.platform)) {
    results.push({ id: testCase.id, skipped: `not for ${process.platform}`, optional: Boolean(testCase.optional) });
    continue;
  }
  const root = await mkdtemp(join(tmpdir(), "oath-exec-parity-"));
  try {
    const fixtures = name => join(fixturesRoot, name);
    const dirs = {};
    for (const tool of ["npx", "oath"]) {
      const cwd = join(root, tool, "work");
      const home = join(root, tool, "home");
      await mkdir(cwd, { recursive: true });
      await mkdir(home, { recursive: true });
      if (testCase.fixture) {
        await cp(fixtures(testCase.fixture), cwd, { recursive: true });
      }
      dirs[tool] = { cwd, home };
    }
    let setup = { npx: null, oath: null };
    if (testCase.setup === "install") {
      // Each tool installs the fixture's dependencies with its own installer
      // so the local-bin case runs from a tree the tool itself produced.
      setup = {
        npx: run(npmCommand, ["install", "--ignore-scripts"], dirs.npx.cwd, dirs.npx.home),
        oath: run(oath, ["install", "--ignore-scripts"], dirs.oath.cwd, dirs.oath.home)
      };
    }
    const repeat = testCase.repeat ?? 1;
    let npxResult = null;
    let oathResult = null;
    const timings = [];
    for (let i = 0; i < repeat; i += 1) {
      npxResult = run(npxCommand, expandArgs(npxArgs(testCase), { fixtures, cwd: dirs.npx.cwd }), dirs.npx.cwd, dirs.npx.home, testCase.env ?? {});
      oathResult = run(oath, expandArgs(oathArgs(testCase), { fixtures, cwd: dirs.oath.cwd }), dirs.oath.cwd, dirs.oath.home, testCase.env ?? {});
      timings.push({ npx_ms: npxResult.elapsed_ms, oath_ms: oathResult.elapsed_ms });
    }
    const comparison = compareRuns(npxResult, oathResult, testCase, { root, replace: testCase.replace ?? [] });
    results.push({
      id: testCase.id,
      optional: Boolean(testCase.optional),
      compare: testCase.compare ?? "stdout",
      ...comparison,
      npx: { status: npxResult.status, stderr: npxResult.stderr.slice(-2000), ...(npxResult.error ? { error: npxResult.error } : {}) },
      oath: { status: oathResult.status, stderr: oathResult.stderr.slice(-2000), ...(oathResult.error ? { error: oathResult.error } : {}) },
      setup: setup.npx ? { npx_status: setup.npx.status, oath_status: setup.oath.status } : null,
      timings
    });
    const last = results[results.length - 1];
    console.error(`${last.equivalent ? "ok  " : "FAIL"} ${testCase.id}${testCase.optional ? " (optional)" : ""}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const required = results.filter(r => !r.optional && !r.skipped);
const report = {
  schema_version: 1,
  evidence_class: "exec_parity",
  reference_npm: npmVersion,
  platform: process.platform,
  node: process.version,
  cases: results.length,
  required: required.length,
  equivalent: required.filter(r => r.equivalent).length,
  failed: required.filter(r => !r.equivalent).length,
  optional_failed: results.filter(r => r.optional && !r.skipped && !r.equivalent).length,
  results
};
await writeFile(join(output, "exec-parity-summary.json"), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ ...report, results: undefined }, null, 2));
if (report.failed) process.exitCode = 1;
