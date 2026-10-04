#!/usr/bin/env node
import { mkdtemp, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { analyzeLockMutation } from "./lock-mutation.mjs";
import { installedTree } from "./tree-evidence.mjs";

const referenceNpmMajor = 11;
const fixture = resolve(process.argv[2] ?? "tests/compat/fixtures/basic");
const oath = resolve(process.env.OATH_BIN ?? "target/debug/oath");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const pinnedLockPath = process.env.OATH_PINNED_LOCK_PATH ? resolve(process.env.OATH_PINNED_LOCK_PATH) : null;
const expectedPinnedLockSha256 = process.env.OATH_PINNED_LOCK_SHA256 ?? null;
const command = process.env.OATH_COMPAT_COMMAND ?? "install";
if (!new Set(["install", "ci"]).has(command)) {
  throw new Error(`unsupported compatibility command: ${command}`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function run(command, args, cwd, home = process.env.HOME ?? process.env.USERPROFILE ?? tmpdir(), extraEnv = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: Number(process.env.OATH_COMPAT_TIMEOUT_MS ?? 600_000),
    killSignal: "SIGKILL",
    shell: process.platform === "win32" && command.toLowerCase().endsWith(".cmd"),
    env: { ...process.env, CI: "1", HOME: home, OATH_HOME: join(home, ".oath"), npm_config_cache: join(home, ".npm"), ...extraEnv }
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    ...(result.error ? { error: { code: result.error.code, message: result.error.message } } : {})
  };
}

function treeEvidence(entries, includeTree) {
  return {
    tree_count: entries.length,
    tree_sha256: createHash("sha256").update(entries.join("\n")).digest("hex"),
    ...(includeTree ? { tree: entries } : {})
  };
}

const npmVersion = run(npmCommand, ["--version"], process.cwd()).stdout.trim();
if (Number(npmVersion.split(".")[0]) !== referenceNpmMajor) {
  throw new Error(`npm ${referenceNpmMajor}.x is the parity reference; found ${npmVersion}`);
}

const root = await mkdtemp(join(tmpdir(), "oath-parity-"));
try {
  const mode = process.env.OATH_COMPAT_MODE ?? "clean";
  const npmDir = join(root, "npm");
  const oathDir = join(root, "oath");
  const lockDir = join(root, "lock");
  await cp(fixture, npmDir, { recursive: true });
  await cp(fixture, oathDir, { recursive: true });
  await cp(fixture, lockDir, { recursive: true });
  const home = join(root, "home");
  // Compare materialization semantics against the same registry snapshot. A
  // package published between the two sequential installs is resolution-time
  // drift, not a placement difference. npm's generated lock pins the exact
  // versions and integrities that Oath must reproduce. Force lock creation for
  // projects such as Express that disable package-lock in their checked-in npmrc.
  let lockResult;
  let lockSha256 = null;
  let pinnedLockSha256 = null;
  let pinnedLockBytes = null;
  if (pinnedLockPath) {
    pinnedLockBytes = gunzipSync(await readFile(pinnedLockPath));
    pinnedLockSha256 = sha256(pinnedLockBytes);
    if (!expectedPinnedLockSha256) throw new Error("OATH_PINNED_LOCK_SHA256 is required with OATH_PINNED_LOCK_PATH");
    if (pinnedLockSha256 !== expectedPinnedLockSha256) {
      throw new Error(`pinned lock digest mismatch: expected ${expectedPinnedLockSha256}, found ${pinnedLockSha256}`);
    }
    await writeFile(join(lockDir, "package-lock.json"), pinnedLockBytes);
    await writeFile(join(npmDir, "package-lock.json"), pinnedLockBytes);
    await writeFile(join(oathDir, "package-lock.json"), pinnedLockBytes);
    lockResult = { status: 0, stdout: "", stderr: "" };
    lockSha256 = pinnedLockSha256;
  } else {
    lockResult = run(npmCommand, ["install", "--package-lock-only", "--ignore-scripts", "--package-lock=true"], lockDir, home);
    lockSha256 = lockResult.status === 0 ? sha256(await readFile(join(lockDir, "package-lock.json"))) : null;
    if (lockResult.status === 0) {
      await cp(join(lockDir, "package-lock.json"), join(npmDir, "package-lock.json"));
      await cp(join(lockDir, "package-lock.json"), join(oathDir, "package-lock.json"));
    }
  }
  const npmArgs = (offline = false) => [command, "--ignore-scripts", "--package-lock=true", ...(offline ? ["--offline"] : [])];
  const oathArgs = command === "ci" ? ["ci"] : ["install", "--ignore-scripts"];
  let npmResult = lockResult.status === 0
    ? run(npmCommand, npmArgs(), npmDir, home)
    : lockResult;
  if (npmResult.status === 0 && mode !== "clean") {
    if (mode !== "repeat") await rm(join(npmDir, "node_modules"), { recursive: true, force: true });
    const offline = mode === "offline";
    npmResult = run(npmCommand, npmArgs(offline), npmDir, home);
  }
  let lockMutation = null;
  if (npmResult.status === 0) {
    const npmLockBytes = await readFile(join(npmDir, "package-lock.json"));
    lockSha256 = sha256(npmLockBytes);
    if (pinnedLockBytes) lockMutation = analyzeLockMutation(pinnedLockBytes, npmLockBytes);
  }
  const pinnedLockPreserved = !pinnedLockPath || lockSha256 === pinnedLockSha256;
  const pinnedLockAccepted = !pinnedLockPath || lockMutation?.explained === true;
  const npmTree = npmResult.status === 0 ? await installedTree(join(npmDir, "node_modules")) : [];

  // Real repositories can materialize tens of gigabytes. Persist the reference
  // tree in memory, then remove npm's node_modules before Oath starts so peak
  // disk is one materialized tree instead of two. The ordered entry list and
  // SHA-256 remain the exact comparison contract.
  await rm(join(npmDir, "node_modules"), { recursive: true, force: true });

  let oathResult = { status: null, stdout: "", stderr: "skipped: reference npm rejected the project" };
  if (npmResult.status === 0) {
    if (command === "ci") {
      const bootstrap = run(oath, ["install", "--ignore-scripts"], oathDir, home);
      if (bootstrap.status === 0) {
        await rm(join(oathDir, "node_modules"), { recursive: true, force: true });
        oathResult = run(oath, oathArgs, oathDir, home);
      } else {
        oathResult = bootstrap;
      }
    } else {
      oathResult = run(oath, oathArgs, oathDir, home);
    }
  }
  if (npmResult.status === 0 && oathResult.status === 0 && mode !== "clean") {
    if (mode !== "repeat") await rm(join(oathDir, "node_modules"), { recursive: true, force: true });
    if (mode === "interrupted") {
      const stage = join(oathDir, ".oath-node_modules-stage");
      await mkdir(stage, { recursive: true });
      await writeFile(join(stage, "partial"), "interrupted");
    }
    const offline = mode === "offline";
    oathResult = run(oath, oathArgs, oathDir, home, offline ? { npm_config_offline: "true" } : {});
  }
  const oathTree = oathResult.status === 0 ? await installedTree(join(oathDir, "node_modules")) : [];
  // Neither installer may rewrite package.json on a plain install or ci: the
  // fixture's bytes must survive both runs unchanged.
  const fixtureManifest = await readFile(join(fixture, "package.json"), "utf8");
  const manifestStable = {
    npm: npmResult.status !== 0 || (await readFile(join(npmDir, "package.json"), "utf8")) === fixtureManifest,
    oath: oathResult.status !== 0 || (await readFile(join(oathDir, "package.json"), "utf8")) === fixtureManifest
  };
  // Optional interop probe: after Oath materializes the tree, npm must find
  // nothing to do. Opt in with OATH_COMPAT_INTEROP=1; it is reported, not yet
  // required, until Oath writes package-lock.json itself.
  let interop = null;
  if (process.env.OATH_COMPAT_INTEROP === "1" && oathResult.status === 0 && command === "install") {
    const before = oathTree;
    const npmAfterOath = run(npmCommand, [...npmArgs(), "--no-audit", "--no-fund"], oathDir, home);
    const after = npmAfterOath.status === 0 ? await installedTree(join(oathDir, "node_modules")) : [];
    interop = {
      status: npmAfterOath.status,
      tree_unchanged: npmAfterOath.status === 0 && JSON.stringify(before) === JSON.stringify(after),
      stdout_tail: npmAfterOath.stdout.slice(-400),
      stderr_tail: npmAfterOath.stderr.slice(-400)
    };
  }
  const npmSet = new Set(npmTree);
  const oathSet = new Set(oathTree);
  const includeTree = process.env.OATH_COMPAT_INCLUDE_TREES === "1";
  const artifact = {
    schema_version: 1,
    reference: {
      npm: npmVersion,
      command,
      lock_sha256: lockSha256,
      ...(pinnedLockPath ? {
        pinned_lock_sha256: pinnedLockSha256,
        pinned_lock_preserved: pinnedLockPreserved,
        lock_mutation: lockMutation
      } : {})
    },
    fixture,
    mode,
    classification: npmResult.status !== 0 ? "reference_rejected" : pinnedLockAccepted ? "compared" : "pinned_lock_mutated",
    npm: { ...npmResult, ...treeEvidence(npmTree, includeTree) },
    oath: { ...oathResult, ...treeEvidence(oathTree, includeTree) },
    manifest_stable: manifestStable,
    ...(interop ? { interop } : {}),
    differences: {
      npm_only_count: npmTree.filter(entry => !oathSet.has(entry)).length,
      oath_only_count: oathTree.filter(entry => !npmSet.has(entry)).length,
      npm_only_sample: npmTree.filter(entry => !oathSet.has(entry)).slice(0, 100),
      oath_only_sample: oathTree.filter(entry => !npmSet.has(entry)).slice(0, 100)
    },
    equivalent: npmResult.status === 0 && oathResult.status === 0 && pinnedLockAccepted && manifestStable.npm && manifestStable.oath && JSON.stringify(npmTree) === JSON.stringify(oathTree)
  };
  console.log(JSON.stringify(artifact, null, 2));
  if (!artifact.equivalent) process.exitCode = 1;
} finally {
  if (process.env.OATH_COMPAT_KEEP_FAILURE === "1" && process.exitCode) {
    console.error(`preserved failed comparison at ${root}`);
  } else {
    await rm(root, { recursive: true, force: true });
  }
}
