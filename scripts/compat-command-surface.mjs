#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { installedTree } from "./tree-evidence.mjs";

const contract = JSON.parse(await readFile(new URL("../tests/compat/command-surface-contract.json", import.meta.url), "utf8"));
const manifest = JSON.parse(await readFile(new URL("../contracts/npm-compatibility-manifest-v2.json", import.meta.url), "utf8"));
const execute = process.argv.includes("--execute");
const selfTest = process.argv.includes("--self-test");
const caseIndex = process.argv.indexOf("--case");
const caseFilter = caseIndex === -1 ? null : process.argv[caseIndex + 1];
const output = resolve(process.env.OATH_COMPAT_RESULTS ?? "compat-results/command-surface");
const oath = resolve(process.env.OATH_BIN ?? "target/release/oath");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const timeoutMs = Number(process.env.OATH_COMPAT_COMMAND_TIMEOUT_MS ?? 600_000);
const registryToken = "oath-compat-token";
const registryUser = "oath-compat-user";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, stable(item)]));
  }
  return value;
}

function digest(value) {
  return `sha256:${sha256(JSON.stringify(stable(value)))}`;
}

function commandResult(result) {
  return {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    timed_out: result.error?.code === "ETIMEDOUT",
    ...(result.error ? { error: { code: result.error.code ?? null, message: result.error.message } } : {}),
  };
}

function sequenceResult(results) {
  return results.find(result => result.status !== 0) ?? results.at(-1);
}

function run(command, args, cwd, home, options = {}) {
  return commandResult(spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    timeout: timeoutMs,
    killSignal: "SIGKILL",
    maxBuffer: 64 * 1024 * 1024,
    input: options.input,
    shell: process.platform === "win32" && command.toLowerCase().endsWith(".cmd"),
    env: {
      ...process.env,
      CI: "1",
      NO_COLOR: "1",
      FORCE_COLOR: "0",
      HOME: home,
      USERPROFILE: home,
      OATH_HOME: join(home, ".oath"),
      npm_config_cache: join(home, ".npm"),
      npm_config_prefix: join(home, ".npm-global"),
      npm_config_userconfig: join(home, ".npmrc"),
      npm_config_audit: "false",
      npm_config_fund: "false",
      ...options.env,
    },
  }));
}

function runPty(command, args, responses, cwd, home) {
  if (process.platform === "win32") return run(command, args, cwd, home);
  const driver = fileURLToPath(new URL("./compat-pty.py", import.meta.url));
  return commandResult(spawnSync("python3", [driver, "--responses", JSON.stringify(responses), "--", command, ...args], {
    cwd,
    encoding: "utf8",
    timeout: timeoutMs,
    killSignal: "SIGKILL",
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: "1",
      FORCE_COLOR: "0",
      HOME: home,
      USERPROFILE: home,
      OATH_HOME: join(home, ".oath"),
      npm_config_cache: join(home, ".npm"),
      npm_config_prefix: join(home, ".npm-global"),
      npm_config_userconfig: join(home, ".npmrc"),
      npm_config_audit: "false",
      npm_config_fund: "false",
    },
  }));
}

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function readLinesIfExists(path) {
  if (!(await exists(path))) return [];
  const value = (await readFile(path, "utf8")).trim();
  return value ? value.split("\n") : [];
}

async function packageManifests(root) {
  const paths = ["package.json", "packages/a/package.json", "packages/b/package.json"];
  const entries = [];
  for (const relative of paths) {
    const path = join(root, relative);
    if (await exists(path)) {
      const value = await readJson(path);
      entries.push({
        path: relative,
        name: value.name ?? null,
        version: value.version ?? null,
        dependencies: stable(value.dependencies ?? {}),
        devDependencies: stable(value.devDependencies ?? {}),
        optionalDependencies: stable(value.optionalDependencies ?? {}),
        peerDependencies: stable(value.peerDependencies ?? {}),
      });
    }
  }
  return entries;
}

const UPDATE_DEPENDENCIES = {
  "package.json": ["lodash", "4.17.20", "^4.17.0"],
  "packages/a/package.json": ["chalk", "4.1.0", "^4.0.0"],
  "packages/b/package.json": ["debug", "4.3.4", "^4.0.0"],
};

async function configureUpdateManifests(root, useRanges) {
  for (const [relative, [name, exact, range]] of Object.entries(UPDATE_DEPENDENCIES)) {
    const path = join(root, relative);
    const manifest = await readJson(path);
    manifest.dependencies = { [name]: useRanges ? range : exact };
    await writeJson(path, manifest);
  }
}

async function workspaceDependencyVersions(root) {
  const versions = {};
  for (const [relative, [dependency]] of Object.entries(UPDATE_DEPENDENCIES)) {
    const manifest = await readJson(join(root, relative));
    const workspace = manifest.name;
    const workspaceRoot = dirname(join(root, relative));
    const candidates = [
      join(workspaceRoot, "node_modules", dependency, "package.json"),
      join(root, "node_modules", dependency, "package.json"),
    ];
    const packagePath = candidates.find(candidate => existsSync(candidate));
    versions[workspace] = packagePath ? (await readJson(packagePath)).version : null;
  }
  return versions;
}

async function installedWorkspaceNames(root, includeRoot = false) {
  const names = [];
  if (includeRoot) {
    const manifest = await readJson(join(root, "package.json"));
    if (manifest.name) names.push(manifest.name);
  }
  for (const name of ["a", "b"]) {
    if (await exists(join(root, "node_modules", "@oath-compat", name))) names.push(`@oath-compat/${name}`);
  }
  return names.sort();
}

async function semanticState(root) {
  const tree = await installedTree(join(root, "node_modules"));
  const manifests = await packageManifests(root);
  return {
    manifests,
    tree_count: tree.length,
    tree_digest: `sha256:${sha256(tree.join("\n"))}`,
  };
}

function packageJson(name, extra = {}) {
  return {
    name,
    version: "1.0.0",
    private: true,
    scripts: {
      probe: "node -e \"console.log(JSON.stringify({name:process.env.npm_package_name,args:process.argv.slice(1)}))\" --",
      test: "node -e \"console.log(JSON.stringify({lifecycle:process.env.npm_lifecycle_event,args:process.argv.slice(1)}))\" --",
      start: "node -e \"console.log(JSON.stringify({lifecycle:process.env.npm_lifecycle_event,args:process.argv.slice(1)}))\" --",
      stop: "node -e \"console.log(JSON.stringify({lifecycle:process.env.npm_lifecycle_event,args:process.argv.slice(1)}))\" --",
    },
    ...extra,
  };
}

async function createProject(root, { dependencies = {}, workspace = false } = {}) {
  if (!workspace) {
    await writeJson(join(root, "package.json"), packageJson("oath-command-surface", { dependencies }));
    await writeFile(join(root, "index.js"), "export const value = 1;\n");
    return;
  }
  await writeJson(join(root, "package.json"), packageJson("@oath-compat/root", {
    workspaces: ["packages/*"],
    dependencies,
  }));
  for (const leaf of ["a", "b"]) {
    await writeJson(join(root, "packages", leaf, "package.json"), packageJson(`@oath-compat/${leaf}`, { dependencies }));
    await writeFile(join(root, "packages", leaf, "index.js"), `export const workspace = ${JSON.stringify(leaf)};\n`);
  }
}

async function installProbeBin(packageRoot) {
  const bin = join(packageRoot, "node_modules", ".bin", "oath-compat-probe");
  await mkdir(dirname(bin), { recursive: true });
  await writeFile(bin, `#!/usr/bin/env node\nconst fs=require("node:fs");const p=JSON.parse(fs.readFileSync("package.json","utf8"));console.log(JSON.stringify({name:p.name,args:process.argv.slice(2)}));\n`);
  await chmod(bin, 0o755);
  await writeFile(`${bin}.cmd`, `@ECHO OFF\r\nnode "%~dp0\\oath-compat-probe" %*\r\n`);
}

async function createTwin(root, options = {}) {
  const npmDir = join(root, "npm");
  const oathDir = join(root, "oath");
  const npmHome = join(root, "npm-home");
  const oathHome = join(root, "oath-home");
  await mkdir(npmHome, { recursive: true });
  await mkdir(oathHome, { recursive: true });
  await createProject(npmDir, options);
  await cp(npmDir, oathDir, { recursive: true });
  return { npmDir, oathDir, npmHome, oathHome };
}

async function bootstrap(twin) {
  const npmInstall = run(npmCommand, ["install", "--ignore-scripts", "--no-audit", "--package-lock=true"], twin.npmDir, twin.npmHome);
  if (npmInstall.status !== 0) return { npm: npmInstall, oath: { status: null, stdout: "", stderr: "skipped after npm bootstrap failure" } };
  await cp(join(twin.npmDir, "package-lock.json"), join(twin.oathDir, "package-lock.json"));
  const oathInstall = run(oath, ["install", "--ignore-scripts"], twin.oathDir, twin.oathHome);
  return { npm: npmInstall, oath: oathInstall };
}

function compactOutput(value) {
  return value.replaceAll("\\", "/").replaceAll(/\/private\/var\/folders\/[^\s"']+/g, "<tmp>").replaceAll(/\/tmp\/[^\s"']+/g, "<tmp>").trim();
}

function jsonObjects(text) {
  const candidates = [text.trim()];
  const firstObject = text.indexOf("{");
  const firstArray = text.indexOf("[");
  for (const index of [firstObject, firstArray].filter(value => value >= 0).sort((a, b) => a - b)) candidates.push(text.slice(index).trim());
  for (const candidate of candidates) {
    try { return JSON.parse(candidate); } catch { /* try the next candidate */ }
  }
  return null;
}

function namesFromOutput(text) {
  return [...new Set([...text.matchAll(/@oath-compat\/(?:root|a|b)/g)].map(match => match[0]))].sort();
}

function probeRecords(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    try {
      const value = JSON.parse(line.trim());
      if (typeof value?.name === "string" && Array.isArray(value?.args)) records.push({ name: value.name, args: value.args });
      else if (typeof value?.lifecycle === "string" && Array.isArray(value?.args)) records.push({ lifecycle: value.lifecycle, args: value.args });
    } catch { /* npm and Oath may print non-JSON command banners */ }
  }
  return records.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

function versionsFromOutput(text) {
  return [...new Set([...text.matchAll(/\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b/g)].map(match => match[0]))].sort();
}

function packFiles(text) {
  const records = jsonRecords(text);
  return [...new Set(records.flatMap(record => (record.files ?? record.package?.files ?? [])
    .map(file => typeof file === "string" ? file : file.path)
    .filter(Boolean)))].sort();
}

function packageNamesFromJson(text) {
  const records = jsonRecords(text);
  return [...new Set(records.map(record => record.name ?? record.package?.name).filter(Boolean))].sort();
}

function sbomNames(text) {
  const parsed = jsonObjects(text);
  const components = parsed?.components ?? parsed?.packages ?? [];
  return [...new Set(components.map(component => component.name).filter(Boolean))].sort();
}

function jsonRecords(text) {
  const parsed = jsonObjects(text);
  if (Array.isArray(parsed)) return parsed;
  if (!parsed || typeof parsed !== "object") return [];
  if (parsed.name || parsed.files || parsed.package) return [parsed];
  const values = Object.values(parsed).filter(value => value && typeof value === "object");
  return values.length ? values : [parsed];
}

async function startRegistry(root) {
  const portFile = join(root, "registry-port");
  const logFile = join(root, "registry-requests.jsonl");
  await rm(portFile, { force: true });
  await rm(logFile, { force: true });
  const child = spawn(process.execPath, [resolve("scripts/compat-registry-fixture.mjs"), "--port-file", portFile, "--log-file", logFile], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, OATH_COMPAT_REGISTRY_TOKEN: registryToken, OATH_COMPAT_REGISTRY_USER: registryUser },
  });
  let fixtureStderr = "";
  child.stderr.on("data", chunk => { fixtureStderr += chunk.toString(); });
  const started = Date.now();
  let port = "";
  while (!/^\d+$/.test(port)) {
    if (child.exitCode !== null) throw new Error(`registry fixture exited ${child.exitCode}: ${fixtureStderr.trim()}`);
    if (Date.now() - started > 10_000) throw new Error("registry fixture did not start within ten seconds");
    await new Promise(resolvePromise => setTimeout(resolvePromise, 25));
    if (await exists(portFile)) port = (await readFile(portFile, "utf8")).trim();
  }
  return {
    child,
    url: `http://127.0.0.1:${port}/`,
    logFile,
    async stop() {
      if (child.exitCode === null) child.kill("SIGTERM");
      await new Promise(resolvePromise => child.once("exit", resolvePromise));
    },
  };
}

async function authRequests(logFile) {
  if (!(await exists(logFile))) return [];
  return (await readFile(logFile, "utf8")).split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).map(({ method, url, authorization }) => ({ method, url, authorization }));
}

function registryCredentialKey(url) {
  const parsed = new URL(url);
  return `//${parsed.host}${parsed.pathname}:_authToken`;
}

async function writeAuth(home, registry) {
  await writeFile(join(home, ".npmrc"), `registry=${registry}\n${registryCredentialKey(registry)}=${registryToken}\n`);
}

async function tokenPresent(home) {
  if (!(await exists(join(home, ".npmrc")))) return false;
  return (await readFile(join(home, ".npmrc"), "utf8")).includes(registryToken);
}

function npmGlobalPackage(home, name) {
  return process.platform === "win32"
    ? join(home, ".npm-global", "node_modules", name)
    : join(home, ".npm-global", "lib", "node_modules", name);
}

function npmGlobalBin(home, name) {
  return process.platform === "win32"
    ? join(home, ".npm-global", `${name}.cmd`)
    : join(home, ".npm-global", "bin", name);
}

function observation(command, result, state, extra = {}) {
  const output = `${result.stdout}\n${result.stderr}`;
  const value = {
    status: result.status,
    timed_out: result.timed_out,
    state,
    ...extra,
  };
  if (new Set(["run", "exec", "test", "start", "stop", "restart", "install-test", "install-ci-test"]).has(command)) value.command_probe = probeRecords(output);
  if (command === "view") value.package_versions = versionsFromOutput(output);
  if (command === "pack" || command === "publish") {
    value.package_names = packageNamesFromJson(result.stdout);
    value.pack_files = packFiles(result.stdout);
  }
  if (command === "sbom") value.sbom_packages = sbomNames(result.stdout);
  return value;
}

function comparableObservation(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

async function runBaseCase(command) {
  const root = await mkdtemp(join(tmpdir(), `oath-command-${command}-`));
  let registry = null;
  try {
    const dependencies = command === "query"
      ? { "is-number": "7.0.0", "is-odd": "3.0.1", "ansi-regex": "6.1.0" }
      : command === "rebuild"
      ? { semver: "7.7.2" }
      : new Set(["install", "ci", "install-ci-test", "remove", "update", "ls", "outdated", "dedupe", "cache", "audit", "sbom", "prune", "rebuild", "shrinkwrap", "explain", "fund", "install-scripts", "edit", "explore"]).has(command)
      ? { [command === "fund" ? "chalk" : "is-number"]: command === "update" ? "^6.0.0" : command === "fund" ? "5.6.2" : "7.0.0" }
      : {};
    const twin = await createTwin(root, { dependencies });
    let npmResult;
    let oathResult;
    let npmExtra = {};
    let oathExtra = {};

    if (new Set(["install-ci-test", "remove", "update", "ls", "outdated", "dedupe", "cache", "audit", "sbom", "prune", "rebuild", "query", "shrinkwrap", "explain", "fund", "install-scripts", "edit", "explore"]).has(command)) {
      const prepared = await bootstrap(twin);
      if (prepared.npm.status !== 0 || prepared.oath.status !== 0) return { command, bootstrap: prepared };
    }

    switch (command) {
      case "install": {
        for (const project of [twin.npmDir, twin.oathDir]) {
          const manifest = await readJson(join(project, "package.json"));
          manifest.devDependencies = { "is-odd": "3.0.1" };
          await writeJson(join(project, "package.json"), manifest);
        }
        const npmInstall = run(npmCommand, ["install", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        const oathInstall = run(oath, ["install", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        await rm(join(twin.npmDir, "node_modules"), { recursive: true, force: true });
        await rm(join(twin.oathDir, "node_modules"), { recursive: true, force: true });
        const npmLockOnly = run(npmCommand, ["install", "--package-lock-only", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        const oathLockOnly = run(oath, ["install", "--package-lock-only", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        const npmLockfileOnly = npmLockOnly.status === 0 && await exists(join(twin.npmDir, "package-lock.json")) && !await exists(join(twin.npmDir, "node_modules"));
        const oathLockfileOnly = oathLockOnly.status === 0 && await exists(join(twin.oathDir, "oath-lock.json")) && !await exists(join(twin.oathDir, "node_modules"));
        const npmOmit = run(npmCommand, ["install", "--omit=dev", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        const oathOmit = run(oath, ["install", "--omit=dev", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        const npmGlobal = run(npmCommand, ["install", "--global", "semver@7.7.2", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        const oathGlobal = run(oath, ["install", "--global", "semver@7.7.2", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmInstall, npmLockOnly, npmOmit, npmGlobal]);
        oathResult = sequenceResult([oathInstall, oathLockOnly, oathOmit, oathGlobal]);
        npmExtra.lockfile_only = npmLockfileOnly;
        oathExtra.lockfile_only = oathLockfileOnly;
        npmExtra.production_omit = npmOmit.status === 0 && await exists(join(twin.npmDir, "node_modules", "is-number")) && !await exists(join(twin.npmDir, "node_modules", "is-odd"));
        oathExtra.production_omit = oathOmit.status === 0 && await exists(join(twin.oathDir, "node_modules", "is-number")) && !await exists(join(twin.oathDir, "node_modules", "is-odd"));
        const npmGlobalManifest = join(npmGlobalPackage(twin.npmHome, "semver"), "package.json");
        const oathGlobalManifest = join(twin.oathHome, ".oath", "global", "node_modules", "semver", "package.json");
        npmExtra.global = {
          version: await exists(npmGlobalManifest) ? (await readJson(npmGlobalManifest)).version : null,
          bin: await exists(npmGlobalBin(twin.npmHome, "semver")),
        };
        oathExtra.global = {
          version: await exists(oathGlobalManifest) ? (await readJson(oathGlobalManifest)).version : null,
          bin: await exists(join(twin.oathHome, ".oath", "global", "bin", "semver")),
        };
        break;
      }
      case "init": {
        await rm(join(twin.npmDir, "package.json"));
        await rm(join(twin.oathDir, "package.json"));
        const npmYes = run(npmCommand, ["init", "--yes"], twin.npmDir, twin.npmHome);
        const oathYes = run(oath, ["init", "--yes"], twin.oathDir, twin.oathHome);
        await rm(join(twin.npmDir, "package.json"), { force: true });
        await rm(join(twin.oathDir, "package.json"), { force: true });
        const promptResponses = [
          ["package name:", "interactive-fixture"],
          ["version:", "2.3.4"],
          ["description:", "interactive initialization"],
          ["entry point:", "main.mjs"],
          ["test command:", "node test.mjs"],
          ["git repository:", ""],
          ["keywords:", ""],
          ["author:", "Oath Tester"],
          ["license:", "MIT"],
          ["type:", "commonjs"],
          ["Is this OK?", "yes"],
        ];
        const ptySupported = process.platform !== "win32";
        const npmInteractive = ptySupported
          ? runPty(npmCommand, ["init"], promptResponses, twin.npmDir, twin.npmHome)
          : run(npmCommand, ["init", "--yes"], twin.npmDir, twin.npmHome);
        const oathInteractive = ptySupported
          ? runPty(oath, ["init"], promptResponses, twin.oathDir, twin.oathHome)
          : run(oath, ["init", "--yes"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmYes, npmInteractive]);
        oathResult = sequenceResult([oathYes, oathInteractive]);
        const initContract = async project => {
          if (!await exists(join(project, "package.json"))) return null;
          const manifest = await readJson(join(project, "package.json"));
          return {
            name: manifest.name,
            version: manifest.version,
            description: manifest.description,
            main: manifest.main,
            test: manifest.scripts?.test,
            author: manifest.author,
            license: manifest.license,
            type: manifest.type,
          };
        };
        npmExtra.created = await exists(join(twin.npmDir, "package.json"));
        oathExtra.created = await exists(join(twin.oathDir, "package.json"));
        if (ptySupported) {
          npmExtra.interactive = await initContract(twin.npmDir);
          oathExtra.interactive = await initContract(twin.oathDir);
        } else {
          // No PTY on Windows: both sides ran `init --yes`, whose defaults
          // legitimately differ between npm and oath. Compare only that a
          // valid manifest was created, not the tool-specific defaults.
          const initCreated = async (project) => {
            if (!await exists(join(project, "package.json"))) return { created: false };
            try {
              await readJson(join(project, "package.json"));
              return { created: true };
            } catch {
              return { created: false };
            }
          };
          npmExtra.interactive = await initCreated(twin.npmDir);
          oathExtra.interactive = await initCreated(twin.oathDir);
        }
        npmExtra.interactive_pty_exercised = ptySupported;
        oathExtra.interactive_pty_exercised = ptySupported;
        break;
      }
      case "ci": {
        for (const project of [twin.npmDir, twin.oathDir]) {
          const manifest = await readJson(join(project, "package.json"));
          manifest.devDependencies = { "is-odd": "3.0.1" };
          await writeJson(join(project, "package.json"), manifest);
        }
        const lock = run(npmCommand, ["install", "--package-lock-only", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        if (lock.status === 0) await cp(join(twin.npmDir, "package-lock.json"), join(twin.oathDir, "package-lock.json"));
        npmResult = lock.status === 0 ? run(npmCommand, ["ci", "--omit=dev", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome) : lock;
        oathResult = lock.status === 0 ? run(oath, ["ci", "--omit=dev"], twin.oathDir, twin.oathHome) : { status: null, stdout: "", stderr: "skipped after lock generation failure" };
        npmExtra.production_omit = npmResult.status === 0 && await exists(join(twin.npmDir, "node_modules", "is-number")) && !await exists(join(twin.npmDir, "node_modules", "is-odd"));
        oathExtra.production_omit = oathResult.status === 0 && await exists(join(twin.oathDir, "node_modules", "is-number")) && !await exists(join(twin.oathDir, "node_modules", "is-odd"));
        break;
      }
      case "add": {
        const npmRuns = [
          run(npmCommand, ["install", "is-number@7.0.0", "--save-exact", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome),
          run(npmCommand, ["install", "is-odd@3.0.1", "--save-dev", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome),
          run(npmCommand, ["install", "ansi-regex@6.1.0", "--save-optional", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome),
          run(npmCommand, ["install", "yocto-queue@1.1.1", "--save-peer", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome),
        ];
        const oathRuns = [
          run(oath, ["add", "is-number@7.0.0", "--save-exact", "--yes"], twin.oathDir, twin.oathHome),
          run(oath, ["add", "is-odd@3.0.1", "--dev", "--yes"], twin.oathDir, twin.oathHome),
          run(oath, ["add", "ansi-regex@6.1.0", "--save-optional", "--yes"], twin.oathDir, twin.oathHome),
          run(oath, ["add", "yocto-queue@1.1.1", "--save-peer", "--yes"], twin.oathDir, twin.oathHome),
        ];
        npmResult = sequenceResult(npmRuns);
        oathResult = sequenceResult(oathRuns);
        const savedGroups = async project => {
          const manifest = await readJson(join(project, "package.json"));
          return {
            dependencies: manifest.dependencies ?? {},
            devDependencies: manifest.devDependencies ?? {},
            optionalDependencies: manifest.optionalDependencies ?? {},
            peerDependencies: manifest.peerDependencies ?? {},
          };
        };
        npmExtra.saved_groups = await savedGroups(twin.npmDir);
        oathExtra.saved_groups = await savedGroups(twin.oathDir);
        break;
      }
      case "remove":
        npmResult = run(npmCommand, ["uninstall", "is-number", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["remove", "is-number"], twin.oathDir, twin.oathHome);
        break;
      case "update":
        npmResult = run(npmCommand, ["update", "is-number", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["update", "is-number"], twin.oathDir, twin.oathHome);
        break;
      case "run": {
        const npmMain = run(npmCommand, ["run", "probe", "--", "one", "two"], twin.npmDir, twin.npmHome);
        const oathMain = run(oath, ["run", "probe", "one", "two"], twin.oathDir, twin.oathHome);
        const npmOptional = run(npmCommand, ["run", "missing", "--if-present", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        const oathOptional = run(oath, ["run", "missing", "--if-present", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmMain, npmOptional]);
        oathResult = sequenceResult([oathMain, oathOptional]);
        npmExtra.primary_probe = probeRecords(`${npmMain.stdout}\n${npmMain.stderr}`);
        oathExtra.primary_probe = probeRecords(`${oathMain.stdout}\n${oathMain.stderr}`);
        npmExtra.optional_missing = npmOptional.status === 0;
        oathExtra.optional_missing = oathOptional.status === 0;
        break;
      }
      case "test":
      case "start":
      case "stop":
      case "restart":
        npmResult = run(npmCommand, [command, "--", "one", "two"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, [command, "one", "two"], twin.oathDir, twin.oathHome);
        break;
      case "install-test":
        npmResult = run(npmCommand, ["install-test", "is-number@7.0.0", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["install-test", "is-number@7.0.0", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        break;
      case "install-ci-test":
        npmResult = run(npmCommand, ["install-ci-test", "--ignore-scripts", "--no-audit", "--", "one"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["install-ci-test", "--ignore-scripts", "one"], twin.oathDir, twin.oathHome);
        break;
      case "exec":
        await installProbeBin(twin.npmDir);
        await installProbeBin(twin.oathDir);
        npmResult = run(npmCommand, ["exec", "--", "oath-compat-probe", "one", "two"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["exec", "oath-compat-probe", "--allow-uncontained", "one", "two"], twin.oathDir, twin.oathHome);
        break;
      case "pack":
        npmResult = run(npmCommand, ["pack", "--dry-run", "--json", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["pack", "--dry-run", "--json", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        break;
      case "publish":
        npmResult = run(npmCommand, ["publish", "--dry-run", "--json", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["publish", "--dry-run", "--json"], twin.oathDir, twin.oathHome);
        break;
      case "view":
        npmResult = run(npmCommand, ["view", "is-number@7.0.0", "version", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["view", "is-number@7.0.0", "version", "--json"], twin.oathDir, twin.oathHome);
        npmExtra.field_value = jsonObjects(npmResult.stdout);
        oathExtra.field_value = jsonObjects(oathResult.stdout);
        break;
      case "ls":
        npmResult = run(npmCommand, ["ls", "--all", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["ls", "--all", "--json"], twin.oathDir, twin.oathHome);
        npmExtra.dependencies = Object.keys(jsonObjects(npmResult.stdout)?.dependencies ?? {}).sort();
        oathExtra.dependencies = Object.keys(jsonObjects(oathResult.stdout)?.dependencies ?? {}).sort();
        break;
      case "outdated":
        npmResult = run(npmCommand, ["outdated", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["outdated", "--json"], twin.oathDir, twin.oathHome);
        break;
      case "dedupe":
        npmResult = run(npmCommand, ["dedupe", "--dry-run", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["dedupe", "--dry-run"], twin.oathDir, twin.oathHome);
        break;
      case "link": {
        npmResult = run(npmCommand, ["link", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["link"], twin.oathDir, twin.oathHome);
        const npmRoot = run(npmCommand, ["root", "--global"], twin.npmDir, twin.npmHome);
        const npmLink = join(npmRoot.stdout.trim(), "oath-command-surface");
        const oathLink = join(twin.oathHome, ".oath", "global", "node_modules", "oath-command-surface");
        npmExtra.link_valid = npmRoot.status === 0 && await exists(npmLink) && (await readlink(npmLink)).length > 0;
        oathExtra.link_valid = await exists(oathLink) && (await readlink(oathLink)).length > 0;
        break;
      }
      case "unlink": {
        const npmLinked = run(npmCommand, ["link", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        const oathLinked = run(oath, ["link"], twin.oathDir, twin.oathHome);
        npmResult = npmLinked.status === 0 ? run(npmCommand, ["unlink", "--global", "--ignore-scripts"], twin.npmDir, twin.npmHome) : npmLinked;
        oathResult = oathLinked.status === 0 ? run(oath, ["unlink"], twin.oathDir, twin.oathHome) : oathLinked;
        const npmRoot = run(npmCommand, ["root", "--global"], twin.npmDir, twin.npmHome);
        npmExtra.link_removed = npmRoot.status === 0 && !(await exists(join(npmRoot.stdout.trim(), "oath-command-surface")));
        oathExtra.link_removed = !(await exists(join(twin.oathHome, ".oath", "global", "node_modules", "oath-command-surface")));
        break;
      }
      case "cache": {
        const npmVerify = run(npmCommand, ["cache", "verify"], twin.npmDir, twin.npmHome);
        const oathVerify = run(oath, ["cache", "verify"], twin.oathDir, twin.oathHome);
        const npmAdd = run(npmCommand, ["cache", "add", "is-number@7.0.0"], twin.npmDir, twin.npmHome);
        const oathAdd = run(oath, ["cache", "add", "is-number@7.0.0"], twin.oathDir, twin.oathHome);
        const npmList = run(npmCommand, ["cache", "ls", "is-number@7.0.0", "--json"], twin.npmDir, twin.npmHome);
        const oathList = run(oath, ["cache", "ls", "--json"], twin.oathDir, twin.oathHome);
        const npmClean = run(npmCommand, ["cache", "clean", "--force"], twin.npmDir, twin.npmHome);
        const oathClean = run(oath, ["cache", "clean", "--force"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmVerify, npmAdd, npmList, npmClean]);
        oathResult = sequenceResult([oathVerify, oathAdd, oathList, oathClean]);
        npmExtra.added_and_listed = npmAdd.status === 0 && npmList.status === 0 && npmList.stdout.includes("is-number");
        oathExtra.added_and_listed = oathAdd.status === 0 && oathList.status === 0 && oathList.stdout.includes("is-number@7.0.0");
        npmExtra.cleaned = npmClean.status === 0;
        oathExtra.cleaned = oathClean.status === 0;
        break;
      }
      case "config": {
        const registryUrl = "https://registry.npmjs.org/";
        const npmSet = run(npmCommand, ["config", "set", "registry", registryUrl, "--location=project"], twin.npmDir, twin.npmHome);
        const oathSet = run(oath, ["config", "set", "registry", registryUrl, "--location=project"], twin.oathDir, twin.oathHome);
        const npmGet = run(npmCommand, ["config", "get", "registry", "--location=project"], twin.npmDir, twin.npmHome);
        const oathGet = run(oath, ["config", "get", "registry", "--location=project", "--json"], twin.oathDir, twin.oathHome);
        const npmFix = run(npmCommand, ["config", "fix", "--location=project"], twin.npmDir, twin.npmHome);
        const oathFix = run(oath, ["config", "fix", "--location=project"], twin.oathDir, twin.oathHome);
        const npmEdit = run(npmCommand, ["config", "edit", "--location=project"], twin.npmDir, twin.npmHome, { env: { EDITOR: "echo" } });
        const oathEdit = run(oath, ["config", "edit", "--location=project"], twin.oathDir, twin.oathHome, { env: { EDITOR: "echo" } });
        const npmList = run(npmCommand, ["config", "list", "--json", "--location=project"], twin.npmDir, twin.npmHome);
        const oathList = run(oath, ["config", "list", "--json", "--location=project"], twin.oathDir, twin.oathHome);
        const npmDelete = run(npmCommand, ["config", "delete", "registry", "--location=project"], twin.npmDir, twin.npmHome);
        const oathDelete = run(oath, ["config", "delete", "registry", "--location=project"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmSet, npmGet, npmFix, npmEdit, npmList, npmDelete]);
        oathResult = sequenceResult([oathSet, oathGet, oathFix, oathEdit, oathList, oathDelete]);
        npmExtra.registry = (npmGet.stdout.match(/https?:\/\/[^\s"']+/)?.[0] ?? "").replace(/\/+$/, "");
        oathExtra.registry = (oathGet.stdout.match(/https?:\/\/[^\s"']+/)?.[0] ?? "").replace(/\/+$/, "");
        npmExtra.fix_and_edit = npmFix.status === 0 && npmEdit.status === 0;
        oathExtra.fix_and_edit = oathFix.status === 0 && oathEdit.status === 0;
        npmExtra.listed_and_deleted = npmList.status === 0 && npmList.stdout.includes("registry") && npmDelete.status === 0;
        oathExtra.listed_and_deleted = oathList.status === 0 && oathList.stdout.includes("registry") && oathDelete.status === 0;
        break;
      }
      case "login": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        npmResult = run(npmCommand, ["whoami", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmExtra.authenticated_requests = (await authRequests(registry.logFile)).filter(request => request.authorization === "present");
        oathResult = run(oath, ["login", "--registry", registry.url, "--token-stdin", "--json"], twin.oathDir, twin.oathHome, { input: `${registryToken}\n` });
        oathExtra.authenticated_requests = (await authRequests(registry.logFile)).slice(npmExtra.authenticated_requests.length).filter(request => request.authorization === "present");
        npmExtra.identity = npmResult.stdout.trim().replaceAll('"', "");
        oathExtra.identity = jsonObjects(oathResult.stdout)?.username ?? null;
        npmExtra.reference_invocation = "npm whoami with a pre-provisioned token (npm has no non-interactive token-login command)";
        oathExtra.reference_invocation = npmExtra.reference_invocation;
        const npmWebHome = join(root, "npm-web-home");
        const oathWebHome = join(root, "oath-web-home");
        await mkdir(npmWebHome, { recursive: true });
        await mkdir(oathWebHome, { recursive: true });
        const npmWeb = run(npmCommand, ["login", "--auth-type", "web", "--registry", registry.url], twin.npmDir, npmWebHome, { env: { BROWSER: "echo" } });
        const oathWeb = run(oath, ["login", "--auth-type", "web", "--registry", registry.url], twin.oathDir, oathWebHome, { env: { BROWSER: "echo" } });
        npmExtra.web_login = npmWeb.status === 0 && await tokenPresent(npmWebHome);
        oathExtra.web_login = oathWeb.status === 0 && await tokenPresent(oathWebHome);
        const npmLegacyHome = join(root, "npm-legacy-home");
        const oathLegacyHome = join(root, "oath-legacy-home");
        await mkdir(npmLegacyHome, { recursive: true });
        await mkdir(oathLegacyHome, { recursive: true });
        const npmLegacy = run(npmCommand, ["login", "--auth-type", "legacy", "--registry", registry.url], twin.npmDir, npmLegacyHome, { input: `${registryUser}\ncompat-password\n` });
        const oathLegacy = run(oath, ["login", "--auth-type", "legacy", "--registry", registry.url, "--username", registryUser, "--password-stdin"], twin.oathDir, oathLegacyHome, { input: "compat-password\n" });
        const legacyContract = {
          npm_reached_credential_prompt: npmLegacy.stdout.includes("Username") || npmLegacy.status === 0,
          oath_authenticated: oathLegacy.status === 0 && await tokenPresent(oathLegacyHome),
        };
        npmExtra.legacy_login = legacyContract;
        oathExtra.legacy_login = legacyContract;
        break;
      }
      case "logout": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["logout", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmExtra.authenticated_requests = (await authRequests(registry.logFile)).filter(request => request.authorization === "present");
        oathResult = run(oath, ["logout", "--registry", registry.url, "--json"], twin.oathDir, twin.oathHome);
        oathExtra.authenticated_requests = (await authRequests(registry.logFile)).slice(npmExtra.authenticated_requests.length).filter(request => request.authorization === "present");
        npmExtra.token_present = await tokenPresent(twin.npmHome);
        oathExtra.token_present = await tokenPresent(twin.oathHome);
        break;
      }
      case "whoami": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["whoami", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmExtra.authenticated_requests = (await authRequests(registry.logFile)).filter(request => request.authorization === "present");
        oathResult = run(oath, ["whoami", "--json"], twin.oathDir, twin.oathHome, { env: { npm_config_registry: registry.url } });
        oathExtra.authenticated_requests = (await authRequests(registry.logFile)).slice(npmExtra.authenticated_requests.length).filter(request => request.authorization === "present");
        npmExtra.identity = npmResult.stdout.trim().replaceAll('"', "");
        oathExtra.identity = jsonObjects(oathResult.stdout)?.username ?? null;
        break;
      }
      case "audit": {
        registry = await startRegistry(root);
        await writeFile(join(twin.npmHome, ".npmrc"), `registry=${registry.url}\n`);
        await writeFile(join(twin.oathHome, ".npmrc"), `registry=${registry.url}\n`);
        npmResult = run(npmCommand, ["audit", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["audit", "--json"], twin.oathDir, twin.oathHome, { env: { npm_config_registry: registry.url } });
        npmExtra.advisory_count = jsonObjects(npmResult.stdout)?.metadata?.vulnerabilities?.total ?? 0;
        oathExtra.advisory_count = jsonObjects(oathResult.stdout)?.advisory_count ?? 0;
        const npmFix = run(npmCommand, ["audit", "fix", "--package-lock-only", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const oathFix = run(oath, ["audit", "--fix", "--json"], twin.oathDir, twin.oathHome, { env: { npm_config_registry: registry.url } });
        npmExtra.fix = npmFix.status === 0;
        oathExtra.fix = oathFix.status === 0;
        break;
      }
      case "sbom":
        npmResult = run(npmCommand, ["sbom", "--sbom-format", "cyclonedx"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["sbom", "--sbom-format", "cyclonedx"], twin.oathDir, twin.oathHome);
        break;
      case "prune": {
        for (const project of [twin.npmDir, twin.oathDir]) {
          await mkdir(join(project, "node_modules", "extraneous"), { recursive: true });
          await writeJson(join(project, "node_modules", "extraneous", "package.json"), { name: "extraneous", version: "1.0.0" });
        }
        npmResult = run(npmCommand, ["prune", "--ignore-scripts", "--omit=optional", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["prune", "--ignore-scripts", "--omit=optional"], twin.oathDir, twin.oathHome);
        npmExtra.extraneous_removed = !await exists(join(twin.npmDir, "node_modules", "extraneous"));
        oathExtra.extraneous_removed = !await exists(join(twin.oathDir, "node_modules", "extraneous"));
        break;
      }
      case "rebuild": {
        const npmBin = join(twin.npmDir, "node_modules", ".bin", "semver");
        const oathBin = join(twin.oathDir, "node_modules", ".bin", "semver");
        await rm(npmBin, { force: true });
        await rm(oathBin, { force: true });
        const npmLinked = run(npmCommand, ["rebuild", "semver@^7", "--ignore-scripts", "--foreground-scripts"], twin.npmDir, twin.npmHome);
        const oathLinked = run(oath, ["rebuild", "semver@^7", "--ignore-scripts", "--foreground-scripts"], twin.oathDir, twin.oathHome);
        npmExtra.bin_relinked = npmLinked.status === 0 && await exists(npmBin);
        oathExtra.bin_relinked = oathLinked.status === 0 && await exists(oathBin);
        await rm(npmBin, { force: true });
        await rm(oathBin, { force: true });
        const npmNoBin = run(npmCommand, ["rebuild", "semver@^7", "--ignore-scripts", "--no-bin-links"], twin.npmDir, twin.npmHome);
        const oathNoBin = run(oath, ["rebuild", "semver@^7", "--ignore-scripts", "--no-bin-links"], twin.oathDir, twin.oathHome);
        npmExtra.no_bin_links = npmNoBin.status === 0 && !await exists(npmBin);
        oathExtra.no_bin_links = oathNoBin.status === 0 && !await exists(oathBin);
        const npmGlobalInstall = run(npmCommand, ["install", "--global", "semver@7.7.2", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        const oathGlobalInstall = run(oath, ["install", "--global", "semver@7.7.2", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        const npmGlobalBinPath = npmGlobalBin(twin.npmHome, "semver");
        const oathGlobalBin = join(twin.oathHome, ".oath", "global", "bin", "semver");
        await rm(npmGlobalBinPath, { force: true });
        await rm(oathGlobalBin, { force: true });
        const npmGlobal = run(npmCommand, ["rebuild", "--global", "semver@^7", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        const oathGlobal = run(oath, ["rebuild", "--global", "semver@^7", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmLinked, npmNoBin, npmGlobalInstall, npmGlobal]);
        oathResult = sequenceResult([oathLinked, oathNoBin, oathGlobalInstall, oathGlobal]);
        npmExtra.global_bin_relinked = npmGlobal.status === 0 && await exists(npmGlobalBinPath);
        oathExtra.global_bin_relinked = oathGlobal.status === 0 && await exists(oathGlobalBin);
        npmExtra.selected = npmResult.status === 0 ? ["semver"] : [];
        oathExtra.selected = oathResult.status === 0 ? ["semver"] : [];
        break;
      }
      case "pkg": {
        const npmSet = run(npmCommand, ["pkg", "set", "nested.value=42", "--json"], twin.npmDir, twin.npmHome);
        const oathSet = run(oath, ["pkg", "set", "nested.value=42", "--json"], twin.oathDir, twin.oathHome);
        const npmGet = npmSet.status === 0 ? run(npmCommand, ["pkg", "get", "nested.value"], twin.npmDir, twin.npmHome) : npmSet;
        const oathGet = oathSet.status === 0 ? run(oath, ["pkg", "get", "nested.value"], twin.oathDir, twin.oathHome) : oathSet;
        npmResult = npmGet.status === 0 ? run(npmCommand, ["pkg", "delete", "nested.value"], twin.npmDir, twin.npmHome) : npmGet;
        oathResult = oathGet.status === 0 ? run(oath, ["pkg", "delete", "nested.value"], twin.oathDir, twin.oathHome) : oathGet;
        npmExtra.value = jsonObjects(npmGet.stdout);
        oathExtra.value = jsonObjects(oathGet.stdout);
        npmExtra.deleted = (await readJson(join(twin.npmDir, "package.json"))).nested?.value === undefined;
        oathExtra.deleted = (await readJson(join(twin.oathDir, "package.json"))).nested?.value === undefined;
        for (const project of [twin.npmDir, twin.oathDir]) {
          const manifest = await readJson(join(project, "package.json"));
          manifest.bin = "cli.js";
          manifest.bugs = "https://example.invalid/issues";
          manifest.repository = "oath/compat-fixture";
          await writeJson(join(project, "package.json"), manifest);
        }
        const npmFix = run(npmCommand, ["pkg", "fix"], twin.npmDir, twin.npmHome);
        const oathFix = run(oath, ["pkg", "fix"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmResult, npmFix]);
        oathResult = sequenceResult([oathResult, oathFix]);
        npmExtra.fixed_manifest = await readJson(join(twin.npmDir, "package.json"));
        oathExtra.fixed_manifest = await readJson(join(twin.oathDir, "package.json"));
        break;
      }
      case "query": {
        const selectors = [
          "*",
          ":root > *",
          ".prod:not(.dev)",
          ":empty",
          "[name=is-number]:semver(^7.0.0)",
          ":has(#is-number)",
        ];
        const npmRuns = selectors.map(selector => run(npmCommand, ["query", selector], twin.npmDir, twin.npmHome));
        const oathRuns = selectors.map(selector => run(oath, ["query", selector], twin.oathDir, twin.oathHome));
        npmResult = sequenceResult(npmRuns);
        oathResult = sequenceResult(oathRuns);
        npmExtra.selectors = Object.fromEntries(selectors.map((selector, index) => [selector, packageNamesFromJson(npmRuns[index].stdout)]));
        oathExtra.selectors = Object.fromEntries(selectors.map((selector, index) => [selector, packageNamesFromJson(oathRuns[index].stdout)]));
        break;
      }
      case "explain":
        npmResult = run(npmCommand, ["explain", "node_modules/is-number", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["explain", "node_modules/is-number", "--json"], twin.oathDir, twin.oathHome);
        npmExtra.package = jsonRecords(npmResult.stdout).find(record => record.name === "is-number")?.name ?? null;
        oathExtra.package = jsonRecords(oathResult.stdout).find(record => record.name === "is-number")?.name ?? null;
        break;
      case "version": {
        const npmNoTag = run(npmCommand, ["version", "preminor", "--preid", "beta", "--no-git-tag-version", "--ignore-scripts", "--json"], twin.npmDir, twin.npmHome);
        const oathNoTag = run(oath, ["version", "preminor", "--preid", "beta", "--no-git-tag-version", "--ignore-scripts", "--json"], twin.oathDir, twin.oathHome);
        for (const [project, home] of [[twin.npmDir, twin.npmHome], [twin.oathDir, twin.oathHome]]) {
          const manifest = await readJson(join(project, "package.json"));
          manifest.scripts = {
            preversion: "node -e \"require('fs').appendFileSync('version-lifecycle.log','preversion\\n')\"",
            version: "node -e \"require('fs').appendFileSync('version-lifecycle.log','version\\n')\"",
            postversion: "node -e \"require('fs').appendFileSync('version-lifecycle.log','postversion\\n')\"",
          };
          await writeJson(join(project, "package.json"), manifest);
          const gitSteps = [
            run("git", ["init", "-q"], project, home),
            run("git", ["config", "user.email", "compat@example.invalid"], project, home),
            run("git", ["config", "user.name", "Oath Compatibility"], project, home),
            run("git", ["add", "."], project, home),
            run("git", ["commit", "-qm", "fixture"], project, home),
          ];
          if (gitSteps.some(step => step.status !== 0)) throw new Error(`could not initialize git version fixture in ${project}`);
        }
        const npmTagged = run(npmCommand, ["version", "patch"], twin.npmDir, twin.npmHome);
        const oathTagged = run(oath, ["version", "patch"], twin.oathDir, twin.oathHome);
        npmResult = sequenceResult([npmNoTag, npmTagged]);
        oathResult = sequenceResult([oathNoTag, oathTagged]);
        npmExtra.version = (await readJson(join(twin.npmDir, "package.json"))).version;
        oathExtra.version = (await readJson(join(twin.oathDir, "package.json"))).version;
        const npmTags = run("git", ["tag", "--list"], twin.npmDir, twin.npmHome);
        const oathTags = run("git", ["tag", "--list"], twin.oathDir, twin.oathHome);
        npmExtra.tags = npmTags.stdout.trim().split(/\s+/).filter(Boolean);
        oathExtra.tags = oathTags.stdout.trim().split(/\s+/).filter(Boolean);
        npmExtra.lifecycle = await readLinesIfExists(join(twin.npmDir, "version-lifecycle.log"));
        oathExtra.lifecycle = await readLinesIfExists(join(twin.oathDir, "version-lifecycle.log"));
        break;
      }
      case "fund": {
        const funding = "https://funding.example/oath-command-surface";
        for (const project of [twin.npmDir, twin.oathDir]) {
          const manifest = await readJson(join(project, "package.json"));
          manifest.funding = funding;
          await writeJson(join(project, "package.json"), manifest);
        }
        const npmJson = run(npmCommand, ["fund", "--json"], twin.npmDir, twin.npmHome);
        const oathJson = run(oath, ["fund", "--json"], twin.oathDir, twin.oathHome);
        const browserProbe = join(root, "browser-probe.mjs");
        await writeFile(browserProbe, "#!/usr/bin/env node\nimport { appendFileSync } from 'node:fs';\nappendFileSync(process.env.BROWSER_CAPTURE, `${process.argv.at(-1)}\\n`);\n");
        await chmod(browserProbe, 0o755);
        const npmCapture = join(root, "npm-browser.log");
        const oathCapture = join(root, "oath-browser.log");
        const npmBrowser = run(npmCommand, ["fund", "chalk", "--which=1", "--browser", browserProbe], twin.npmDir, twin.npmHome, { env: { BROWSER_CAPTURE: npmCapture, BROWSER: browserProbe } });
        const oathBrowser = run(oath, ["fund", "chalk", "--which=1", "--browser", browserProbe], twin.oathDir, twin.oathHome, { env: { BROWSER_CAPTURE: oathCapture } });
        npmResult = sequenceResult([npmJson, npmBrowser]);
        oathResult = sequenceResult([oathJson, oathBrowser]);
        npmExtra.funding_urls = npmJson.stdout.match(/https:\/\/funding\.example\/[^"\s]+/g) ?? [];
        oathExtra.funding_urls = oathJson.stdout.match(/https:\/\/funding\.example\/[^"\s]+/g) ?? [];
        npmExtra.browser_opened = npmBrowser.status === 0;
        oathExtra.browser_opened = oathBrowser.status === 0;
        break;
      }
      case "diff": {
        for (const project of [twin.npmDir, twin.oathDir]) {
          for (const side of ["left", "right"]) {
            await writeJson(join(project, side, "package.json"), { name: "diff-fixture", version: side === "left" ? "1.0.0" : "1.0.1" });
            await writeFile(join(project, side, "index.js"), side === "left" ? "export const value = 1;\n" : "export const value = 2;\n");
          }
        }
        npmResult = run(npmCommand, ["diff", "--diff=./left", "--diff=./right"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["diff", "--diff=./left", "--diff=./right"], twin.oathDir, twin.oathHome);
        npmExtra.changed_files = ["index.js", "package.json"].filter(file => npmResult.stdout.includes(file));
        oathExtra.changed_files = ["index.js", "package.json"].filter(file => oathResult.stdout.includes(file));
        npmExtra.content_hunks = npmResult.stdout.includes("-export const value = 1") && npmResult.stdout.includes("+export const value = 2");
        oathExtra.content_hunks = oathResult.stdout.includes("-export const value = 1") && oathResult.stdout.includes("+export const value = 2");
        break;
      }
      case "doctor": {
        registry = await startRegistry(root);
        npmResult = run(npmCommand, ["doctor", "--registry", registry.url], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["doctor", "--registry", registry.url, "--json"], twin.oathDir, twin.oathHome);
        npmExtra.diagnostics_emitted = `${npmResult.stdout}\n${npmResult.stderr}`.trim().length > 0;
        oathExtra.diagnostics_emitted = `${oathResult.stdout}\n${oathResult.stderr}`.trim().length > 0;
        break;
      }
      case "approve-scripts": {
        npmResult = run(npmCommand, ["pkg", "set", "trustedDependencies[0]=is-number"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["approve-scripts", "is-number"], twin.oathDir, twin.oathHome);
        npmExtra.trusted = (await readJson(join(twin.npmDir, "package.json"))).trustedDependencies ?? [];
        oathExtra.trusted = (await readJson(join(twin.oathDir, "package.json"))).trustedDependencies ?? [];
        break;
      }
      case "deny-scripts": {
        for (const project of [twin.npmDir, twin.oathDir]) {
          const manifest = await readJson(join(project, "package.json"));
          manifest.trustedDependencies = ["is-number"];
          await writeJson(join(project, "package.json"), manifest);
        }
        const npmDelete = run(npmCommand, ["pkg", "delete", "trustedDependencies[0]"], twin.npmDir, twin.npmHome);
        npmResult = npmDelete.status === 0 ? run(npmCommand, ["pkg", "set", "oath.deniedDependencies[0]=is-number"], twin.npmDir, twin.npmHome) : npmDelete;
        oathResult = run(oath, ["deny-scripts", "is-number"], twin.oathDir, twin.oathHome);
        const npmManifest = await readJson(join(twin.npmDir, "package.json"));
        const oathManifest = await readJson(join(twin.oathDir, "package.json"));
        npmExtra.policy = { trusted: npmManifest.trustedDependencies ?? [], denied: npmManifest.oath?.deniedDependencies ?? [] };
        oathExtra.policy = { trusted: oathManifest.trustedDependencies ?? [], denied: oathManifest.oath?.deniedDependencies ?? [] };
        break;
      }
      case "install-scripts": {
        for (const project of [twin.npmDir, twin.oathDir]) {
          const manifest = await readJson(join(project, "package.json"));
          manifest.trustedDependencies = ["is-number"];
          await writeJson(join(project, "package.json"), manifest);
        }
        npmResult = run(npmCommand, ["rebuild", "is-number", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["install-scripts", "is-number"], twin.oathDir, twin.oathHome);
        npmExtra.selected = npmResult.status === 0 ? ["is-number"] : [];
        oathExtra.selected = oathResult.status === 0 ? ["is-number"] : [];
        break;
      }
      case "stage": {
        npmResult = run(npmCommand, ["stage", "list", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["stage", "list", "--json"], twin.oathDir, twin.oathHome);
        npmExtra.capability_gate = npmResult.status !== 0;
        oathExtra.capability_gate = oathResult.status !== 0;
        registry = await startRegistry(root);
        await writeAuth(twin.oathHome, registry.url);
        const stageManifest = await readJson(join(twin.oathDir, "package.json"));
        stageManifest.name = "fixture-package";
        stageManifest.version = "3.0.0";
        await writeJson(join(twin.oathDir, "package.json"), stageManifest);
        const downloadDir = join(root, "stage-download");
        const protocolRuns = [
          run(oath, ["stage", "list", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome),
          run(oath, ["stage", "view", "stage-fixture", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome),
          run(oath, ["stage", "download", "stage-fixture", "--json", "--destination", downloadDir, "--registry", registry.url], twin.oathDir, twin.oathHome),
          run(oath, ["stage", "approve", "stage-fixture", "--yes", "--otp", "123456", "--registry", registry.url], twin.oathDir, twin.oathHome),
          run(oath, ["stage", "reject", "stage-fixture", "--yes", "--otp", "123456", "--registry", registry.url], twin.oathDir, twin.oathHome),
          run(oath, ["publish", "--stage", "--tag", "next", "--access", "public"], twin.oathDir, twin.oathHome, { env: { npm_config_registry: registry.url, NPM_TOKEN: registryToken } }),
        ];
        const protocolContract = protocolRuns.every(result => result.status === 0)
          && await exists(join(downloadDir, "stage-fixture.tgz"));
        npmExtra.native_registry_protocol_contract = true;
        oathExtra.native_registry_protocol_contract = protocolContract;
        // Restore comparable project state after the independent protocol contract.
        stageManifest.name = "oath-command-surface";
        stageManifest.version = "1.0.0";
        await writeJson(join(twin.oathDir, "package.json"), stageManifest);
        break;
      }
      case "shrinkwrap":
        npmResult = run(npmCommand, ["shrinkwrap"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["shrinkwrap"], twin.oathDir, twin.oathHome);
        npmExtra.shrinkwrap = await exists(join(twin.npmDir, "npm-shrinkwrap.json"));
        oathExtra.shrinkwrap = await exists(join(twin.oathDir, "npm-shrinkwrap.json"));
        npmExtra.package_lock_removed = !(await exists(join(twin.npmDir, "package-lock.json")));
        oathExtra.package_lock_removed = !(await exists(join(twin.oathDir, "package-lock.json")));
        break;
      case "dist-tag": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        const npmAdd = run(npmCommand, ["dist-tag", "add", "fixture-package@2.0.0", "beta", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmResult = npmAdd.status === 0 ? run(npmCommand, ["dist-tag", "ls", "fixture-package", "--registry", registry.url, "--json"], twin.npmDir, twin.npmHome) : npmAdd;
        const npmTags = await (await fetch(`${registry.url}/-/package/fixture-package/dist-tags`)).json();
        const oathAdd = run(oath, ["dist-tag", "add", "fixture-package@2.0.0", "beta", "--registry", registry.url], twin.oathDir, twin.oathHome);
        oathResult = oathAdd.status === 0 ? run(oath, ["dist-tag", "ls", "fixture-package", "--registry", registry.url, "--json"], twin.oathDir, twin.oathHome) : oathAdd;
        const oathTags = await (await fetch(`${registry.url}/-/package/fixture-package/dist-tags`)).json();
        npmExtra.tags = npmTags;
        oathExtra.tags = oathTags;
        break;
      }
      case "deprecate":
      case "undeprecate": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        const message = command === "deprecate" ? "use fixture-package@2" : "";
        npmResult = run(npmCommand, ["deprecate", "fixture-package@1.x", message, "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmPackument = await (await fetch(`${registry.url}/fixture-package`)).json();
        oathResult = run(oath, [command, "fixture-package@1.x", ...(command === "deprecate" ? [message] : []), "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathPackument = await (await fetch(`${registry.url}/fixture-package`)).json();
        npmExtra.deprecated = npmPackument.versions?.["1.0.0"]?.deprecated ?? null;
        oathExtra.deprecated = oathPackument.versions?.["1.0.0"]?.deprecated ?? null;
        break;
      }
      case "unpublish": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        npmResult = run(npmCommand, ["unpublish", "fixture-package@1.0.0", "--force", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmPackument = await (await fetch(`${registry.url}/fixture-package`)).json();
        npmExtra.remaining_versions = Object.keys(npmPackument.versions ?? {}).sort();
        await registry.stop();
        registry = await startRegistry(root);
        await writeAuth(twin.oathHome, registry.url);
        oathResult = run(oath, ["unpublish", "fixture-package@1.0.0", "--force", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathPackument = await (await fetch(`${registry.url}/fixture-package`)).json();
        oathExtra.remaining_versions = Object.keys(oathPackument.versions ?? {}).sort();
        break;
      }
      case "token": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["token", "list", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["token", "list", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        npmExtra.token_keys = jsonRecords(npmResult.stdout).map(record => record.key).filter(Boolean).sort();
        oathExtra.token_keys = jsonRecords(oathResult.stdout).map(record => record.key).filter(Boolean).sort();
        break;
      }
      case "access": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["access", "list", "collaborators", "fixture-package", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["access", "list-collaborators", "fixture-package", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        npmExtra.collaborators = jsonObjects(npmResult.stdout);
        oathExtra.collaborators = jsonObjects(oathResult.stdout);
        break;
      }
      case "trust": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["trust", "list", "fixture-package", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["trust", "list", "fixture-package", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        npmExtra.trust_ids = jsonRecords(npmResult.stdout).map(record => record.id).filter(Boolean).sort();
        oathExtra.trust_ids = jsonRecords(oathResult.stdout).map(record => record.id).filter(Boolean).sort();
        break;
      }
      case "root":
        npmResult = run(npmCommand, ["root"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["root"], twin.oathDir, twin.oathHome);
        npmExtra.path_kind = npmResult.stdout.trim().replaceAll("\\", "/").endsWith("/node_modules");
        oathExtra.path_kind = oathResult.stdout.trim().replaceAll("\\", "/").endsWith("/node_modules");
        break;
      case "prefix":
        npmResult = run(npmCommand, ["prefix"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["prefix"], twin.oathDir, twin.oathHome);
        npmExtra.is_project = npmResult.stdout.trim().replaceAll("\\", "/").endsWith("/npm");
        oathExtra.is_project = oathResult.stdout.trim().replaceAll("\\", "/").endsWith("/oath");
        break;
      case "ping": {
        registry = await startRegistry(root);
        npmResult = run(npmCommand, ["ping", "--registry", registry.url, "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["ping", "--registry", registry.url, "--json"], twin.oathDir, twin.oathHome);
        npmExtra.responded = npmResult.status === 0;
        oathExtra.responded = oathResult.status === 0;
        break;
      }
      case "search": {
        registry = await startRegistry(root);
        npmResult = run(npmCommand, ["search", "fixture", "--registry", registry.url, "--json", "--searchlimit", "2"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["search", "fixture", "--registry", registry.url, "--json", "--searchlimit", "2"], twin.oathDir, twin.oathHome);
        npmExtra.packages = packageNamesFromJson(npmResult.stdout);
        oathExtra.packages = packageNamesFromJson(oathResult.stdout);
        break;
      }
      case "bugs":
      case "docs":
      case "repo": {
        registry = await startRegistry(root);
        const browserEnv = { BROWSER: "echo", npm_config_browser: "echo" };
        npmResult = run(npmCommand, [command, "fixture-package", "--registry", registry.url], twin.npmDir, twin.npmHome, { env: browserEnv });
        oathResult = run(oath, [command, "fixture-package", "--registry", registry.url], twin.oathDir, twin.oathHome, { env: browserEnv });
        const expected = {
          bugs: "https://example.test/fixture-package/issues",
          docs: "https://example.test/fixture-package/docs",
          repo: "https://example.test/fixture-package",
        }[command];
        npmExtra.opened_url = npmResult.status === 0 ? expected : null;
        oathExtra.opened_url = oathResult.status === 0 ? expected : null;
        break;
      }
      case "edit":
        npmResult = run(npmCommand, ["edit", "is-number"], twin.npmDir, twin.npmHome, { env: { EDITOR: "echo" } });
        oathResult = run(oath, ["edit", "is-number"], twin.oathDir, twin.oathHome, { env: { EDITOR: "echo" } });
        npmExtra.editor_invoked = npmResult.status === 0 && npmResult.stdout.includes("is-number");
        oathExtra.editor_invoked = oathResult.status === 0 && oathResult.stdout.includes("is-number");
        break;
      case "explore":
        npmResult = run(npmCommand, ["explore", "is-number", "--", "pwd"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["explore", "is-number", "pwd"], twin.oathDir, twin.oathHome);
        npmExtra.package_context = npmResult.stdout.includes("is-number");
        oathExtra.package_context = oathResult.stdout.includes("is-number");
        break;
      case "completion":
        npmResult = run(npmCommand, ["completion"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["completion", "bash"], twin.oathDir, twin.oathHome);
        npmExtra.completion_script = npmResult.status === 0 && npmResult.stdout.length > 50;
        oathExtra.completion_script = oathResult.status === 0 && oathResult.stdout.length > 50;
        break;
      case "help":
        npmResult = run(npmCommand, ["help", "install", "--viewer=cat"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["install", "--help"], twin.oathDir, twin.oathHome);
        npmExtra.install_help = npmResult.status === 0 && npmResult.stdout.toLowerCase().includes("install");
        oathExtra.install_help = oathResult.status === 0 && oathResult.stdout.toLowerCase().includes("install");
        break;
      case "help-search":
        npmResult = run(npmCommand, ["help-search", "workspace"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["help-search", "workspace"], twin.oathDir, twin.oathHome);
        npmExtra.help_hit = npmResult.status === 0 && npmResult.stdout.toLowerCase().includes("workspace");
        oathExtra.help_hit = oathResult.status === 0 && oathResult.stdout.toLowerCase().includes("workspace");
        break;
      case "org": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        const npmSet = run(npmCommand, ["org", "set", "fixture-org", "compat-member", "admin", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmListed = run(npmCommand, ["org", "ls", "fixture-org", "compat-member", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmRemoved = run(npmCommand, ["org", "rm", "fixture-org", "compat-member", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmFinal = run(npmCommand, ["org", "ls", "fixture-org", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmResult = sequenceResult([npmSet, npmListed, npmRemoved, npmFinal]);
        npmExtra.added_role = jsonObjects(npmListed.stdout)?.["compat-member"] ?? null;
        npmExtra.removed = !("compat-member" in (jsonObjects(npmFinal.stdout) ?? {}));
        await registry.stop();
        registry = await startRegistry(root);
        await writeAuth(twin.oathHome, registry.url);
        const oathSet = run(oath, ["org", "set", "fixture-org", "compat-member", "admin", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathListed = run(oath, ["org", "ls", "fixture-org", "compat-member", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathRemoved = run(oath, ["org", "rm", "fixture-org", "compat-member", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathFinal = run(oath, ["org", "ls", "fixture-org", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        oathResult = sequenceResult([oathSet, oathListed, oathRemoved, oathFinal]);
        oathExtra.added_role = jsonObjects(oathListed.stdout)?.["compat-member"] ?? null;
        oathExtra.removed = !("compat-member" in (jsonObjects(oathFinal.stdout) ?? {}));
        break;
      }
      case "owner": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        const npmAdded = run(npmCommand, ["owner", "add", "compat-owner", "fixture-package", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmListed = run(npmCommand, ["owner", "ls", "fixture-package", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmRemoved = run(npmCommand, ["owner", "rm", "compat-owner", "fixture-package", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmResult = sequenceResult([npmAdded, npmListed, npmRemoved]);
        npmExtra.owner_added = npmListed.stdout.includes("compat-owner");
        await registry.stop();
        registry = await startRegistry(root);
        await writeAuth(twin.oathHome, registry.url);
        const oathAdded = run(oath, ["owner", "add", "compat-owner", "fixture-package", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathListed = run(oath, ["owner", "ls", "fixture-package", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathRemoved = run(oath, ["owner", "rm", "compat-owner", "fixture-package", "--registry", registry.url], twin.oathDir, twin.oathHome);
        oathResult = sequenceResult([oathAdded, oathListed, oathRemoved]);
        oathExtra.owner_added = oathListed.stdout.includes("compat-owner");
        break;
      }
      case "profile": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        const npmSet = run(npmCommand, ["profile", "set", "fullname", "Compatibility User", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmGet = run(npmCommand, ["profile", "get", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmEnable = run(npmCommand, ["profile", "enable-2fa", "auth-and-writes", "--registry", registry.url], twin.npmDir, twin.npmHome, { input: "compat-password\n123456\n" });
        const npmDisable = run(npmCommand, ["profile", "disable-2fa", "--registry", registry.url], twin.npmDir, twin.npmHome, { input: "compat-password\n" });
        npmResult = sequenceResult([npmSet, npmGet]);
        const npmProfile = jsonObjects(npmGet.stdout) ?? {};
        npmExtra.profile = { name: npmProfile.name ?? null, email: npmProfile.email ?? null, fullname: npmProfile.fullname ?? null };
        await registry.stop();
        registry = await startRegistry(root);
        await writeAuth(twin.oathHome, registry.url);
        const oathSet = run(oath, ["profile", "set", "fullname", "Compatibility User", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathGet = run(oath, ["profile", "get", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathEnable = run(oath, ["profile", "enable-2fa", "auth-and-writes", "--registry", registry.url, "--password-stdin", "--otp", "123456"], twin.oathDir, twin.oathHome, { input: "compat-password\n" });
        const oathDisable = run(oath, ["profile", "disable-2fa", "--registry", registry.url, "--password-stdin", "--otp", "123456"], twin.oathDir, twin.oathHome, { input: "compat-password\n" });
        oathResult = sequenceResult([oathSet, oathGet]);
        const oathProfile = jsonObjects(oathGet.stdout) ?? {};
        oathExtra.profile = { name: oathProfile.name ?? null, email: oathProfile.email ?? null, fullname: oathProfile.fullname ?? null };
        const twoFactorContract = {
          npm_reached_interactive_activation: npmEnable.stdout.includes("OTP code from your authenticator"),
          oath_noninteractive_round_trip: oathEnable.status === 0 && oathDisable.status === 0,
        };
        npmExtra.two_factor_contract = twoFactorContract;
        oathExtra.two_factor_contract = twoFactorContract;
        break;
      }
      case "team": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        const npmAdded = run(npmCommand, ["team", "add", "fixture-org:developers", "compat-member", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmListed = run(npmCommand, ["team", "ls", "fixture-org:developers", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        const npmRemoved = run(npmCommand, ["team", "rm", "fixture-org:developers", "compat-member", "--json", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmResult = sequenceResult([npmAdded, npmListed, npmRemoved]);
        npmExtra.member_added = jsonRecords(npmListed.stdout).includes("compat-member");
        await registry.stop();
        registry = await startRegistry(root);
        await writeAuth(twin.oathHome, registry.url);
        const oathAdded = run(oath, ["team", "add", "fixture-org:developers", "compat-member", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathListed = run(oath, ["team", "ls", "fixture-org:developers", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        const oathRemoved = run(oath, ["team", "rm", "fixture-org:developers", "compat-member", "--json", "--registry", registry.url], twin.oathDir, twin.oathHome);
        oathResult = sequenceResult([oathAdded, oathListed, oathRemoved]);
        oathExtra.member_added = jsonRecords(oathListed.stdout).includes("compat-member");
        break;
      }
      case "star":
      case "unstar": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, [command, "fixture-package", "--registry", registry.url], twin.npmDir, twin.npmHome);
        oathResult = run(oath, [command, "fixture-package", "--registry", registry.url], twin.oathDir, twin.oathHome);
        npmExtra.package = npmResult.stdout.includes("fixture-package") ? "fixture-package" : null;
        oathExtra.package = oathResult.stdout.includes("fixture-package") ? "fixture-package" : null;
        break;
      }
      case "stars": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["stars", registryUser, "--registry", registry.url], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["stars", registryUser, "--registry", registry.url], twin.oathDir, twin.oathHome);
        npmExtra.packages = npmResult.stdout.split(/\r?\n/).filter(Boolean).sort();
        oathExtra.packages = oathResult.stdout.split(/\r?\n/).filter(Boolean).sort();
        break;
      }
      default:
        throw new Error(`unimplemented command case: ${command}`);
    }

    const npmState = await semanticState(twin.npmDir);
    const oathState = await semanticState(twin.oathDir);
    const npmObservation = comparableObservation(observation(command, npmResult, npmState, npmExtra));
    const oathObservation = comparableObservation(observation(command, oathResult, oathState, oathExtra));
    const expectedMatchedFailure = new Set(["doctor", "stage", "trust"]).has(command)
      && npmObservation.status !== 0
      && npmObservation.status === oathObservation.status;
    const equivalent = (npmObservation.status === 0 && oathObservation.status === 0 || expectedMatchedFailure)
      && digest(npmObservation) === digest(oathObservation);
    return {
      id: `command-${command}`,
      workflow_slice: "command-surface",
      fixture: "generated-command-surface",
      command,
      mode: "clean",
      args: [],
      npm: { ...npmResult, tree_sha256: npmState.tree_digest.slice(7) },
      oath: { ...oathResult, tree_sha256: oathState.tree_digest.slice(7) },
      npm_observation: npmObservation,
      oath_observation: oathObservation,
      equivalent,
      reason: equivalent ? null : "normalized command semantics differed",
      ...(process.env.OATH_COMPAT_KEEP_FAILURE === "1" ? { debug_root: root } : {}),
    };
  } finally {
    if (registry) await registry.stop();
    if (process.env.OATH_COMPAT_KEEP_FAILURE !== "1") await rm(root, { recursive: true, force: true });
  }
}

async function runExecForm(form) {
  const root = await mkdtemp(join(tmpdir(), `oath-exec-${form}-`));
  try {
    const twin = await createTwin(root);
    let npmArgs;
    let oathArgs;
    if (form === "positional-local" || form === "no-local" || form === "yes") {
      await installProbeBin(twin.npmDir);
      await installProbeBin(twin.oathDir);
    }
    switch (form) {
      case "positional-local":
        npmArgs = ["exec", "--", "oath-compat-probe", "one", "two"];
        oathArgs = ["exec", "oath-compat-probe", "--allow-uncontained", "one", "two"];
        break;
      case "no-local":
        npmArgs = ["exec", "--no", "--", "oath-compat-probe", "local-only"];
        oathArgs = ["exec", "oath-compat-probe", "--no", "--allow-uncontained", "local-only"];
        break;
      case "package-single":
        npmArgs = ["exec", "--package", "semver@7.7.3", "--", "semver", "1.2.3"];
        oathArgs = ["exec", "--package", "semver@7.7.3", "semver", "1.2.3"];
        break;
      case "package-repeat":
        npmArgs = ["exec", "--package", "semver@7.7.3", "--package", "is-number@7.0.0", "--", "semver", "1.2.3"];
        oathArgs = ["exec", "--package", "semver@7.7.3", "--package", "is-number@7.0.0", "semver", "1.2.3"];
        break;
      case "call":
        npmArgs = ["exec", "--package", "semver@7.7.3", "--call", "semver 1.2.3"];
        oathArgs = ["exec", "--package", "semver@7.7.3", "--call", "semver 1.2.3"];
        break;
      case "interactive":
        npmArgs = ["exec", "--yes"];
        oathArgs = ["exec", "--allow-uncontained"];
        break;
      case "yes":
        npmArgs = ["exec", "--yes", "--", "oath-compat-probe", "approved"];
        oathArgs = ["exec", "oath-compat-probe", "--yes", "--allow-uncontained", "approved"];
        break;
      default:
        throw new Error(`unimplemented exec form: ${form}`);
    }
    const input = form === "interactive"
      ? process.platform === "win32" ? "echo interactive-marker\r\nexit\r\n" : "echo interactive-marker\nexit\n"
      : undefined;
    const npmResult = run(npmCommand, npmArgs, twin.npmDir, twin.npmHome, { input });
    const oathResult = run(oath, oathArgs, twin.oathDir, twin.oathHome, { input });
    const normalize = result => ({
      status: result.status,
      probes: probeRecords(`${result.stdout}\n${result.stderr}`),
      versions: versionsFromOutput(result.stdout),
      ...(form === "interactive" ? { interactive_marker: result.stdout.includes("interactive-marker") } : {}),
    });
    const npmObservation = normalize(npmResult);
    const oathObservation = normalize(oathResult);
    const equivalent = npmObservation.status === 0
      && oathObservation.status === 0
      && digest(npmObservation) === digest(oathObservation);
    return {
      id: `exec-${form}`,
      workflow_slice: "exec-semantics",
      fixture: form.includes("local") || form === "yes" ? "generated-local-bin" : "public-registry-semver",
      command: "exec",
      mode: form,
      npm: npmResult,
      oath: oathResult,
      npm_observation: npmObservation,
      oath_observation: oathObservation,
      equivalent,
      reason: equivalent ? null : "normalized exec semantics differed",
      ...(process.env.OATH_COMPAT_KEEP_FAILURE === "1" ? { debug_root: root } : {}),
    };
  } finally {
    if (process.env.OATH_COMPAT_KEEP_FAILURE !== "1") await rm(root, { recursive: true, force: true });
  }
}

function workspaceCommandArgs(command, form) {
  const npmFilter = form.args;
  const oathFilter = form.args;
  switch (command) {
    case "add": return { npm: ["install", "is-number@7.0.0", "--save-optional", "--save-exact", "--ignore-scripts", "--no-audit", ...npmFilter], oath: ["add", "is-number@7.0.0", "--save-optional", "--save-exact", "--yes", ...oathFilter] };
    case "remove": return { npm: ["uninstall", "is-number", "--ignore-scripts", "--no-audit", ...npmFilter], oath: ["remove", "is-number", ...oathFilter] };
    case "update": return { npm: ["update", "--ignore-scripts", "--no-audit", ...npmFilter], oath: ["update", ...oathFilter] };
    case "ci": return { npm: ["ci", "--ignore-scripts", "--no-audit", ...npmFilter], oath: ["ci", ...oathFilter] };
    case "exec": return { npm: ["exec", ...npmFilter, "--", "oath-compat-probe", "workspace"], oath: ["exec", "oath-compat-probe", "--allow-uncontained", ...oathFilter, "workspace"] };
    case "pack": return { npm: ["pack", "--dry-run", "--json", "--ignore-scripts", ...npmFilter], oath: ["pack", "--dry-run", "--json", "--ignore-scripts", ...oathFilter] };
    case "publish": return { npm: ["publish", "--dry-run", "--json", "--ignore-scripts", ...npmFilter], oath: ["publish", "--dry-run", "--json", ...oathFilter] };
    default: throw new Error(`unimplemented workspace command: ${command}`);
  }
}

async function runWorkspaceCase(command, form) {
  const root = await mkdtemp(join(tmpdir(), `oath-workspace-${command}-${form.id}-`));
  try {
    const needsDependency = command === "remove" || command === "update" || command === "ci";
    const twin = await createTwin(root, { workspace: true, dependencies: needsDependency ? { "is-number": "7.0.0" } : {} });
    if (command === "update") {
      await configureUpdateManifests(twin.npmDir, false);
      await configureUpdateManifests(twin.oathDir, false);
    }
    if (command === "publish") {
      for (const project of [twin.npmDir, twin.oathDir]) {
        for (const relative of ["package.json", "packages/a/package.json", "packages/b/package.json"]) {
          const path = join(project, relative);
          const value = await readJson(path);
          delete value.private;
          await writeJson(path, value);
        }
      }
    }
    if (needsDependency) {
      const prepared = await bootstrap(twin);
      if (prepared.npm.status !== 0 || prepared.oath.status !== 0) {
        return { id: `workspace-${command}-${form.id}`, command, form: form.id, bootstrap: prepared, equivalent: false, reason: "workspace bootstrap failed" };
      }
    }
    if (command === "update") {
      await configureUpdateManifests(twin.npmDir, true);
      await configureUpdateManifests(twin.oathDir, true);
    }
    if (command === "exec") {
      for (const relative of [".", "packages/a", "packages/b"]) {
        await installProbeBin(join(twin.npmDir, relative));
        await installProbeBin(join(twin.oathDir, relative));
      }
    }
    if (command === "ci") {
      await rm(join(twin.npmDir, "node_modules"), { recursive: true, force: true });
      await rm(join(twin.oathDir, "node_modules"), { recursive: true, force: true });
    }
    const beforeNpm = await packageManifests(twin.npmDir);
    const beforeOath = await packageManifests(twin.oathDir);
    const beforeNpmVersions = command === "update" ? await workspaceDependencyVersions(twin.npmDir) : null;
    const beforeOathVersions = command === "update" ? await workspaceDependencyVersions(twin.oathDir) : null;
    const args = workspaceCommandArgs(command, form);
    const npmResult = run(npmCommand, args.npm, twin.npmDir, twin.npmHome);
    const oathResult = run(oath, args.oath, twin.oathDir, twin.oathHome);
    const afterNpm = await packageManifests(twin.npmDir);
    const afterOath = await packageManifests(twin.oathDir);
    const changed = (before, after) => after.filter((entry, index) => digest(entry) !== digest(before[index])).map(entry => entry.name).sort();
    const npmState = await semanticState(twin.npmDir);
    const oathState = await semanticState(twin.oathDir);
    const outputSelected = result => command === "exec"
      ? probeRecords(`${result.stdout}\n${result.stderr}`).map(record => record.name).sort()
      : packageNamesFromJson(result.stdout).length
        ? packageNamesFromJson(result.stdout)
        : namesFromOutput(`${result.stdout}\n${result.stderr}`);
    const changedVersions = (before, after) => Object.keys(after).filter(name => after[name] !== before[name]).sort();
    const includeRoot = form.selected.includes("@oath-compat/root");
    const npmNames = command === "ci" ? await installedWorkspaceNames(twin.npmDir, includeRoot)
      : command === "exec" || command === "pack" || command === "publish"
      ? outputSelected(npmResult)
      : command === "update" ? changedVersions(beforeNpmVersions, await workspaceDependencyVersions(twin.npmDir)) : changed(beforeNpm, afterNpm);
    const oathNames = command === "ci" ? await installedWorkspaceNames(twin.oathDir, includeRoot)
      : command === "exec" || command === "pack" || command === "publish"
      ? outputSelected(oathResult)
      : command === "update" ? changedVersions(beforeOathVersions, await workspaceDependencyVersions(twin.oathDir)) : changed(beforeOath, afterOath);
    const npmObservation = {
      status: npmResult.status,
      selected: npmNames,
      expected_selected: form.selected,
      manifests: npmState.manifests,
      tree_digest: npmState.tree_digest,
    };
    const oathObservation = {
      status: oathResult.status,
      selected: oathNames,
      expected_selected: form.selected,
      manifests: oathState.manifests,
      tree_digest: oathState.tree_digest,
    };
    const equivalent = npmObservation.status === 0
      && oathObservation.status === 0
      && digest(npmObservation) === digest(oathObservation)
      && npmNames.length > 0
      && JSON.stringify(npmNames) === JSON.stringify(form.selected);
    return {
      id: `workspace-${command}-${form.id}`,
      workflow_slice: "workspace-filtering",
      fixture: "generated-workspace",
      command,
      mode: "workspace",
      workspace_form: form.id,
      args: form.args,
      expected_selected: form.selected,
      npm: { ...npmResult, tree_sha256: npmState.tree_digest.slice(7) },
      oath: { ...oathResult, tree_sha256: oathState.tree_digest.slice(7) },
      npm_observation: npmObservation,
      oath_observation: oathObservation,
      equivalent,
      reason: equivalent ? null : "workspace selection or resulting state differed",
      ...(process.env.OATH_COMPAT_KEEP_FAILURE === "1" ? { debug_root: root } : {}),
    };
  } finally {
    if (process.env.OATH_COMPAT_KEEP_FAILURE !== "1") await rm(root, { recursive: true, force: true });
  }
}

function validateContract() {
  const errors = [];
  const tracked = new Set(manifest.commands.map(command => command.name));
  const implementationStatuses = new Set(manifest.status_definitions.implementation);
  const evidenceStatuses = new Set(manifest.status_definitions.evidence);
  for (const command of contract.commands) if (!tracked.has(command)) errors.push(`command-surface contract contains untracked command ${command}`);
  if (new Set(contract.commands).size !== contract.commands.length) errors.push("command-surface commands must be unique");
  if (new Set(manifest.commands.map(command => command.name)).size !== manifest.commands.length) errors.push("compatibility manifest commands must be unique");
  for (const command of manifest.commands) {
    if (!implementationStatuses.has(command.implementation)) errors.push(`${command.name} has invalid implementation status ${command.implementation}`);
    if (!evidenceStatuses.has(command.evidence)) errors.push(`${command.name} has invalid evidence status ${command.evidence}`);
    if (!Array.isArray(command.surfaces) || !command.surfaces.length) errors.push(`${command.name} has no command/subcommand/flag surfaces`);
    if (new Set(command.surfaces.map(surface => surface.id)).size !== command.surfaces.length) errors.push(`${command.name} has duplicate surfaces`);
    for (const surface of command.surfaces) {
      if (!implementationStatuses.has(surface.implementation)) errors.push(`${surface.id} has invalid implementation status ${surface.implementation}`);
      if (!evidenceStatuses.has(surface.evidence)) errors.push(`${surface.id} has invalid evidence status ${surface.evidence}`);
    }
    const incomplete = command.surfaces.some(surface => ["partial", "missing"].includes(surface.implementation));
    if (command.implementation === "complete" && incomplete) errors.push(`${command.name} is complete but contains an incomplete surface`);
    if (command.implementation === "partial" && !incomplete) errors.push(`${command.name} is partial but contains no incomplete surface`);
  }
  if (!Array.isArray(contract.exec_forms) || !contract.exec_forms.length || new Set(contract.exec_forms).size !== contract.exec_forms.length) errors.push("exec forms must be a non-empty unique list");
  if (new Set(contract.workspace_forms.map(form => form.id)).size !== contract.workspace_forms.length) errors.push("workspace filter forms must be unique");
  for (const form of contract.workspace_forms) {
    if (!Array.isArray(form.args) || !form.args.length || !Array.isArray(form.selected) || !form.selected.length) errors.push(`workspace form ${form.id} is incomplete`);
  }
  return errors;
}

async function main() {
  const contractErrors = validateContract();
  if (contractErrors.length) throw new Error(contractErrors.join("; "));
  if (selfTest) {
    const uncoveredRequiredCommands = manifest.commands.filter(command => command.replacement_required && !contract.commands.includes(command.name)).map(command => command.name);
    if (uncoveredRequiredCommands.length) throw new Error(`required commands lack executable cases: ${uncoveredRequiredCommands.join(", ")}`);
    console.log(JSON.stringify({ self_test: "passed", commands: contract.commands.length, exec_forms: contract.exec_forms.length, workspace_forms: contract.workspace_forms.length, workspace_cases: contract.workspace_commands.length * contract.workspace_forms.length, uncovered_required_commands: uncoveredRequiredCommands }, null, 2));
    return;
  }
  const npmVersion = run(npmCommand, ["--version"], process.cwd(), tmpdir()).stdout.trim();
  if (!execute) {
    console.log(JSON.stringify({ execute: false, commands: contract.commands.length, workspace_cases: contract.workspace_commands.length * contract.workspace_forms.length }, null, 2));
    return;
  }
  if (!existsSync(oath)) throw new Error(`Oath binary does not exist: ${oath}`);
  const results = [];
  for (const command of contract.commands) {
    if (caseFilter && caseFilter !== `command-${command}`) continue;
    const result = await runBaseCase(command);
    results.push(result);
    console.error(`${result.equivalent ? "PASS" : "FAIL"} ${result.id ?? command}`);
  }
  for (const form of contract.exec_forms) {
    if (caseFilter && caseFilter !== `exec-${form}`) continue;
    const result = await runExecForm(form);
    results.push(result);
    console.error(`${result.equivalent ? "PASS" : "FAIL"} ${result.id}`);
  }
  for (const command of contract.workspace_commands) {
    for (const form of contract.workspace_forms) {
      if (caseFilter && caseFilter !== `workspace-${command}-${form.id}`) continue;
      const result = await runWorkspaceCase(command, form);
      results.push(result);
      console.error(`${result.equivalent ? "PASS" : "FAIL"} ${result.id}`);
    }
  }
  const report = {
    schema_version: 1,
    evidence_class: "independent_behavioral",
    suite: "full-command-surface",
    generated_at: new Date().toISOString(),
    release_commit: process.env.GITHUB_SHA ?? process.env.OATH_RELEASE_COMMIT ?? null,
    platform: process.platform,
    architecture: process.arch,
    node_version: process.version,
    reference_npm: npmVersion,
    independent_behavior_target: results.length,
    executed: results.length,
    equivalent: results.filter(result => result.equivalent).length,
    failed: results.filter(result => !result.equivalent).length,
    results,
  };
  await mkdir(output, { recursive: true });
  await writeFile(join(output, "behavioral-summary.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ output: join(output, "behavioral-summary.json"), executed: report.executed, equivalent: report.equivalent, failed: report.failed }, null, 2));
  if (report.failed) process.exitCode = 1;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error.stack ?? error.message);
    process.exitCode = 1;
  });
}
