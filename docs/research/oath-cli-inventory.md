<!-- Code-reading inventory of the oath CLI at commit 5d71c0a (v0.2.5 line), gathered 2026-10-04 for docs/FULL_REPLACEMENT_ROADMAP.md. Line numbers drift; re-verify before citing in code changes. Claims marked (code-reading) were inferred without executing the binary. -->

# Oath CLI inventory (v0.2.5, as of the current checkout)

This inventory comes from reading the code only. No binary was built or run. Claims marked **(code-reading)** are inferences that were not executed.

Path shorthand (all under the repository root):
- `main.rs` = `crates/oath-cli/src/main.rs`
- `placement.rs` = `crates/oath-resolve/src/placement.rs`
- `plan.cjs` = `crates/oath-resolve/src/arborist-plan.cjs`
- `linker.rs` = `crates/oath-store/src/linker.rs`
- `client.rs` = `crates/oath-fetch/src/client.rs`
- `npmrc.rs` = `crates/oath-fetch/src/npmrc.rs`
- `cas.rs` = `crates/oath-store/src/cas.rs`

---

## 0. Subcommand table (clap enum at `main.rs:150-330`, dispatch at `main.rs:342-531`)

| Command | Args / flags | What it actually does |
|---|---|---|
| `install [pkgs…]` | `-D/--dev` (alias `--save-dev`), `--dry-run`, `--no-audit`, `-y/--yes`, `--run-scripts`, `--ignore-scripts`, `--min-age <7d/24h/2w>`, `-g/--global`, `--frozen-lockfile` (alias `--ci`) (`main.rs:152-179`) | Plans the tree by running bundled npm Arborist under `node`. Then downloads the missing tarballs, hardlinks them from `~/.oath/store` into `node_modules` atomically, and writes `oath-lock.json` and `.oath/placement-plan.json`. Dependency install scripts are blocked by default. New packages are scanned after linking (`main.rs:539-1115`). |
| `ci` | no flags at all (`main.rs:181`) | Frozen clean install from `oath-lock.json` plus the persisted or re-planned placement. It runs no scripts and no scan (`main.rs:1119-1188`). |
| `add <pkg>` | one package only, `-D`, `-y` (`main.rs:183-189`) | Thin wrapper over `install [pkg]` with audit on (`main.rs:1539-1553`). |
| `update [pkgs…]` | positional only (`main.rs:191`) | Arborist `update` plan, then download, link and lock write. No scripts, no scan, no transparency log, `package.json` untouched (`main.rs:1555-1586`). |
| `remove`/`uninstall`/`rm` | `[pkgs…]` (`main.rs:193-194`) | Deletes the entries from `dependencies`/`devDependencies`, re-plans with Arborist `rm`, relinks and rewrites the lock. If no deps remain it deletes `node_modules` outright (`main.rs:4056-4151`). |
| `run [script] [args…]` | no flags (`main.rs:196-199`) | With no name it lists scripts. Otherwise runs `pre<x>`, `<x>`, `post<x>` via `sh -c` (`main.rs:1650-1750`). |
| `exec`/`x <pkg[@spec]> [args…]` | `-y`, `--min-age`, `--json`, `--schema-version 2/3`, `--require-grade A-F`, `--dry-run`, `--sandbox`, `--sandbox-mode off/node/native/auto`, `--deny-network`, `--allow-degraded-sandbox`, `--remember` (`main.rs:202-239`) | npx-like: plans, downloads, scans and grades the package, optionally sandboxes it, then runs its bin with `node` (`main.rs:3226-3766`). |
| `scan`/`audit` | `--production`, `--verbose` (`main.rs:241-248`) | Static behavioral scan of **every package in the global store**, not the project tree. Exits 1 if any finding is critical (`main.rs:1356-1469`). |
| `perms <pkg>` | | Scans every stored version of that package name in the global store and prints capabilities (`main.rs:1473-1535`). |
| `init [name]` | | Writes a fixed `package.json` with license `UNLICENSED`. It **overwrites any existing file without checking** (`main.rs:1800-1822`). |
| `why <pkg>` | | Reverse-dependency search over `oath-lock.json` keys, plus a scan (`main.rs:1826-1944`). |
| `licenses` | | Counts licenses across the **entire global store** and flags GPL-family and UNKNOWN (`main.rs:1986-2086`). |
| `verify` | | Re-hashes each lock entry's store directory against its BLAKE3 manifest. Exits 1 on missing or tampered entries. Checks the store only, not `node_modules` (`main.rs:2090-2150`). |
| `graph` | `--depth N` (default 3) | ASCII tree built from `oath-lock.json` (`main.rs:2154-2334`). |
| `score <pkg[@spec]>` | | Fetches from the registry, downloads into the store, scans, and prints a 0-100 / A-F score using npmjs weekly downloads (`main.rs:3770-3916`). |
| `info <pkg>` | | Maintainers, downloads, version count, license and repo from registry.npmjs.org and api.npmjs.org. Any version part is ignored (`main.rs:3920-3974`). |
| `publish` | `--tag`, `--access`, `--dry-run`, `--json` (requires `--dry-run`), `--schema-version 1/2`, `--stage` (`main.rs:270-289`) | See §4 (`main.rs:4556-4861`). |
| `stage list/view/download/approve/reject` | `--json`, `--registry`, `--destination`, `--yes`, `--otp` (`main.rs:52-101`) | Pass-through to `npm stage …`. Requires npm ≥ 11.15 and Node ≥ 22.14 (`main.rs:4261-4386`). |
| `transfer create/verify` | `--output`, `--tag`, `--access`, `--json`, `--trusted-public-key` (`main.rs:104-125`) | Builds or verifies a signed transfer capsule (`main.rs:4388-4443`, `package_transfer.rs`). |
| `log` | `-n/--tail` (default 10) | Prints recent transparency-log entries with raw unix timestamps (`main.rs:5012-5061`). |
| `sandbox-info` | `--json` | Prints `verified_native_capabilities()` (`main.rs:473-491`). |
| `__sandbox-launch` (hidden) | `--plan --program -- args` | Linux-only inner launcher (`main.rs:492-509`). |
| `__sandbox-native-run` (hidden) | same | Runs a sandbox plan on Linux/Windows. Errors on other platforms (`main.rs:510-529`). |

There are no global flags such as `--registry`, `--prefix`, `--loglevel` or `--workspace`; the `Cli` struct is at `main.rs:138-147`.

---

## 1. Install family

### Placement is delegated to npm's Arborist
- By default `install`, `add`, `update`, `remove`, `exec`, `install -g` and `ci` (when there is no persisted plan) all run `ArboristPlanner`. It spawns `node` on the embedded `plan.cjs` with `reify({dryRun:true, ignoreScripts:true})` (`placement.rs:211-240`, `plan.cjs:34-51`).
- `OATH_RESOLVER=legacy` switches to the old Rust resolver (`main.rs:641`, `main.rs:667-721`).
- The plan's node keys are `node_modules/...` locations (`placement.rs:103-127`), so `oath-lock.json` keys are locations too (see `website/oath-lock.json`).

### Frozen-lockfile semantics
**`oath ci`:**
1. Requires `oath-lock.json` (`main.rs:1121-1124`).
2. Requires an exact string match of the root `dependencies`/`devDependencies` snapshot (`main.rs:1126-1132`, `lockfile.rs:171-178`). `optionalDependencies` and `peerDependencies` are not part of that snapshot.
3. Uses `.oath/placement-plan.json` if it exists, otherwise re-plans with Arborist (`main.rs:1135-1140`).
4. Rebuilds a lock from the plan and compares with `lockfiles_match_for_frozen` (`main.rs:1143-1152`). That comparison ignores one-sided optional entries, `name`, and `hasInstallScript` (`main.rs:2355-2415`).
5. Links with `link_placement_plan_clean`, which removes stale entries (`main.rs:1170`, `linker.rs:227-233`).
6. Never writes the lock. Runs **no lifecycle scripts and no scan**.

**`install --frozen-lockfile` / `--ci`:**
- Refuses package arguments (`main.rs:558-560`) and needs a lock (`main.rs:563-565`).
- Plans normally and bails if the regenerated lock differs (`main.rs:750-755`).
- Then proceeds as a normal, non-clean install with scripts and scan, but skips the lock write (`main.rs:893-895`).

**Caveat:** `oath-lock.json` is **not an input to Arborist**. If there is no `package-lock.json` (and no `node_modules`), Arborist re-resolves against the live registry, so frozen checks can fail on registry drift. The parity harness always seeds an npm-generated `package-lock.json` into the Oath directory (`scripts/npm-parity.mjs:83-93`).

**Workspaces + ci (code-reading):** the workspace install writes the lock with *merged external deps of all workspaces*, name `"workspace"`, and an empty dev snapshot (`main.rs:1292-1299`). `oath ci` compares that against the root `package.json` deps only (`main.rs:1126-1131`). So `ci` likely fails whenever the workspace members declare deps the root does not. The parity fixture hides this because root and member both declare only `is-number@7.0.0` (`tests/compat/fixtures/workspace`).

### `package-lock.json`
- **Never written** by Oath.
- **Read implicitly by Arborist**: `loadVirtual` honors `package-lock.json` / `npm-shrinkwrap.json`.
- The explicit Rust importer `import_npm_lockfile` (lockfileVersion 2/3 only; v1 rejected at `import.rs:23-26`, os/cpu filter at `import.rs:187-193`) is reached **only** in legacy-resolver mode. It is the `else if` after the Arborist branch at `main.rs:696-703`.
- `oath-lock.json` (lockfileVersion 2, `lockfile.rs:13`) is Oath's only lock artifact.
- The planner reads only the project `.npmrc` (`plan.cjs:18-27`).

### Dependency types
- **devDependencies:** always installed. There is no `--omit`, `--production` or `--include` flag anywhere in `main.rs:152-179`.
- **optionalDependencies:** platform skip comes from Arborist. A failed optional download aborts the whole install, because `res??` propagates errors (`main.rs:2540-2541`). npm tolerates these.
- **peerDependencies:** auto-installed per npm 7+ via Arborist. `legacy-peer-deps` and `strict-peer-deps` are read from the project `.npmrc` only (`plan.cjs:38-39`). Peer warnings are effectively dead in Arborist mode:
  - `to_dep_graph` leaves `peer_report` empty (`graph.rs:96`).
  - The plan's `invalid_edges` are never consumed (`placement.rs:27`; grep finds no reader).
  - The warnings at `main.rs:902-930` print only in legacy mode.
- **bundleDependencies:** nodes with `inDepBundle` are excluded from planning; their contents come from the parent tarball. Root bundles are installed from the registry like npm (`plan.cjs:59-68`).
- **os/cpu/libc:** handled only by Arborist via pinned `npm-install-checks` 8.0.0 (`placement.rs:14`). There is no Rust filter in the default path; `resolver.rs:22` is legacy only. The legacy importer filters os/cpu only, not libc (`import.rs:190-193`).
- **overrides:** honored only because Arborist reads `package.json` overrides (covered by the `override` fixture). There is no Rust handling. `resolutions` (yarn) is not supported anywhere; grep finds nothing.
- **engines:** not checked or surfaced. `engine-strict` is not passed (`plan.cjs:34-43`) and Arborist logs are discarded (only JSON goes to stdout).

### Specifiers
- **Git:** `github:`, `gitlab:`, `bitbucket:`, `git+https`, `git+ssh`, `ssh`, `git://` (`git.rs:27-35`, `51-156`).
  - GitHub goes through the unauthenticated GitHub tarball API (`git.rs:214-264`).
  - Other hosts use `git clone --depth 1 --branch <ref>` (`git.rs:266-307`), so a commit SHA cannot work as a ref for non-GitHub hosts (code-reading).
  - Content is re-packed through the pinned npm-packlist (`git.rs:302-304`, `319-321`).
  - `#semver:` is rejected (`git.rs:194-202`).
  - The git `prepare` script is never run.
  - Tarballs are cached at `~/.oath/git-cache/` (`main.rs:2578-2597`).
- **`file:`:** directories are packed via `pack_local_package`; tarball files are copied (`main.rs:2686-2724`). With npm's default `install-links=false`, Arborist emits them as links, which Oath symlinks only if the target is inside the project root (`linker.rs:163-207`). So `file:../sibling` would error with "workspace link escapes project", whereas npm allows it (code-reading).
- **Tarball URL:** fetched via `fetch_tarball_to_file`. Integrity is verified only when present (`client.rs:331-334`), so URL and git deps without SRI go unverified at download.
- **Alias `npm:`:** Arborist `install_name != name` becomes `DepNode.alias` (`placement.rs:107`); the spec is preserved in `package.json` (`main.rs:2743-2754`).
- **Bugs when adding packages (code-reading):**
  - `parse_package_spec` splits on `@` (`main.rs:2726-2741`), so `oath install github:u/r`, `./dir` or a URL writes a bogus `package.json` key such as `"github:u/r": "latest"` (`main.rs:608-612`, `899`).
  - `package.json` is rewritten with serde_json without `preserve_order`, so **all keys are re-sorted alphabetically** and the trailing newline is dropped (`main.rs:899`, `4112`, `4139`).
  - Added deps are saved as `^<resolved version>` (`main.rs:2752`). There is no `--save-exact`, `--save-optional`, `--save-peer` or `--no-save`.

### Workspaces
- The root is detected by walking up from cwd: `pnpm-workspace.yaml` first, then `package.json#workspaces` (`oath-workspace/src/lib.rs:112-160`).
- Plain `oath install` anywhere inside installs the whole root (`main.rs:568-579`).
- There are **no `-w/--workspace`, `--filter`, `-r` or `--workspaces` flags**.
- The workspace path (`main.rs:1199-1352`) skips a lot:
  - **No scan**: it is a stub that only prints, with the comment "(same logic as single-pkg install; abbreviated here)" at `main.rs:1331-1335`.
  - **No lifecycle scripts**: `_yes_flag` and `_run_scripts` are unused (`main.rs:1203-1204`).
  - No `--frozen-lockfile` check and no min-age.
- `oath install <pkg>` inside a workspace falls through to single-package mode (`main.rs:580`).
- pnpm `workspace:` specs are parsed by `oath-workspace` but planning goes through npm Arborist, which does not support that protocol (inference).

### Global installs (`-g`)
- Installs into `~/.oath/global/{package.json,node_modules,bin}` (`main.rs:4867-5008`). It does no scan and runs no scripts.
- Bins are relative symlinks only for directly requested packages (`main.rs:4934-4993`). On Windows they are `symlink_file` with no `.cmd` shims (`main.rs:38-41`).
- The user must add `~/.oath/global/bin` to PATH. There is no `remove -g` and no global listing.

### `.bin` linking
- Placement path: bins go into `<destination parent>/.bin` (`linker.rs:329-346`). For a scoped package at `node_modules/@scope/pkg` the parent is `node_modules/@scope`, so **bins land in `node_modules/@scope/.bin` instead of `node_modules/.bin`**. The parity tree comparison excludes `.bin` (`scripts/tree-evidence.mjs:9`), so it is not caught.
- Bin conflicts: first writer wins (`if !link.exists()`).
- The placement path never chmods the bin target; it relies on tar-mode preservation (`tarball.rs:248-254`). The legacy `link_all` does chmod (`linker.rs:735-744`).
- `directories.bin` is ignored ("skip for now", `linker.rs:902-908`).
- Windows: `.bin` entries are `symlink_file` (`linker.rs:109-112`), which needs Developer Mode or privilege. There are no cmd/ps1 shims. Directory links are `cmd.exe mklink /J` junctions (`linker.rs:75-102`).

### Lifecycle scripts
**Root project scripts:**
- `preinstall` runs before download (`main.rs:762-766`). `install`, `postinstall`, `prepare` run at the end (`main.rs:1090-1096`).
- They run only on plain `oath install` with no package args, and are skipped by `--ignore-scripts`. They never run in `ci`, `update`, `remove`, workspace or global installs.
- Execution is `sh -c` with `PATH=./node_modules/.bin:$PATH` (relative, `:` separator), `npm_lifecycle_event`, `npm_lifecycle_script`, and `npm_package_<top-level scalar>` (`main.rs:1593-1648`).
- A failure **only warns** (`main.rs:1640-1646`).

**Dependency scripts:**
- **Blocked by default** and counted (`main.rs:1004-1013`).
- Run without a prompt if the name is in `package.json#trustedDependencies` or `-y` is passed (`main.rs:621-633`, `968-974`).
- `--run-scripts` scans the package, then prompts y/N/always; "always" appends to `oath-policy.toml` (`main.rs:976-1002`, `prompts.rs:58-113`).
- `run_install_script` runs `preinstall` → `install` → `postinstall` via `sh -c`, with cwd set to the package dir, `npm_lifecycle_event` and `npm_package_*` set, **no PATH augmentation, no `npm_config_*`**, and **unsandboxed** (`main.rs:2887-2928`). Failure only warns.
- Ordering problems:
  - Iteration is over `graph.nodes`, a HashMap, so order is effectively random rather than dependency order (`graph.rs:12`).
  - The loop runs over **all** nodes on every install, not just changed ones (`main.rs:937`).
  - The script directory is `node_modules/<install_name>` (top level) or falls back to the **global store directory** (`main.rs:954-966`). Nested copies can therefore run in the wrong directory or mutate the shared CAS (code-reading).
- Policy interaction:
  - Only `banned_packages` (skips the script, not the install, `main.rs:943-949`) and `allow_install_scripts` (only on the `--run-scripts` prompt path, `prompts.rs:67`) are used.
  - `banned_licenses`, `max_risk_level`, `require_approval` and `block_install_scripts` from `oath-core/src/policy.rs:33-45` are **never read by the CLI**.
- Static analysis runs **after** scripts (`main.rs:1015-1088`) and never fails the install.
- When anything was downloaded, the scan covers **every** graph node, not just the new ones (`main.rs:1020-1038`).

### `.npmrc`
`npmrc.rs` supports only:
- `registry=`
- `@scope:registry=`
- `//host/…:_authToken=`
- `${VAR}` expansion

It reads `~/.npmrc` and then `./.npmrc`, and `OATH_REGISTRY` / `npm_config_registry` override the default registry (`npmrc.rs:1-88`). Tokens are keyed by **host only**; the path and port are dropped (`npmrc.rs:96-105`).

There is no support for `_auth`, username/password, `always-auth`, `proxy`/`https-proxy`, `noproxy`, `strict-ssl`, `cafile`/`ca`, `certfile`, or `omit`. TLS is `reqwest` with `rustls-tls` and `default-features=false` (`Cargo.toml:51`), meaning bundled webpki roots and no custom CA. Env-var proxies are probably picked up by reqwest's defaults (unverified).

**The Arborist planner gets none of the registry or auth config** (`plan.cjs:34-43`), so private or scoped registries likely fail at planning (code-reading). Arborist also uses its default `~/.npm/_cacache`.

`publish` has its own separate token reader (§4).

---

## 2. `oath run`
- **Pre/post hooks:** yes, and a hook failure exits with its code (`main.rs:1716-1743`).
- **Env vars:** `npm_lifecycle_event`, `npm_lifecycle_script`, and `npm_package_*` for top-level scalar fields only (`main.rs:1593-1607`, `1702-1709`). There is no `npm_config_*`, `npm_execpath`, `npm_node_execpath`, `INIT_CWD` or `npm_package_json`.
- **PATH:** the relative `./node_modules/.bin` is prepended with a hardcoded `:` (`main.rs:1687-1690`). Ancestor `.bin` directories are not walked. It uses cwd, not the package root.
- **Shell:** always `sh -c`, so it breaks on Windows without sh.
- **Missing flags:** no `--if-present`, `--workspaces`/`--filter`, or `--silent`. There are no `test`/`start` shortcuts.
- **Argument passthrough:** extra args are POSIX-quoted and appended (`main.rs:1726-1730`, `1752-1796`). `args` has no `trailing_var_arg`/`allow_hyphen_values` (`main.rs:196-199`), so `oath run test --watch` is likely rejected by clap and `oath run test -- --watch` is required (code-reading).
- **Listing:** with no name it prints the scripts (`main.rs:1657-1675`).
- **Timing:** prints "Done in Xs".

---

## 3. `oath exec` vs npx
- **Package and bin selection:**
  - `parse_package_spec` splits `pkg@spec` (`main.rs:3251`). Only registry packages are supported because it calls `fetch_packument(name)` (`main.rs:3272-3277`).
  - `resolve_version` handles dist-tags, ranges and `npm:` (`resolve.rs:23-58`).
  - The bin is `preferred_bin_path`: a bin named after the package or its basename, else the first alphabetically (`main.rs:2788-2796`). The fallback is `cli.js`, `bin/index.js`, `index.js`, `bin.js` (`main.rs:3737-3750`).
  - **No `-p/--package` and no `-c/--call`**, so there is no way to pick another bin.
  - The bin is always run as `node <bin>` (`main.rs:3203-3222`), so non-JS bins are unsupported.
- **`--` handling:** `trailing_var_arg` is set but `allow_hyphen_values` is not (`main.rs:203-205`), so the first hyphen arg after the package likely needs `--` (code-reading).
- **Install location and caching:**
  - A fresh `tempfile::tempdir()` with a synthetic `package.json` is planned by Arborist, then downloaded and linked (`main.rs:3427-3447`).
  - Tarballs are cached in `~/.oath/store`. Packuments are cached in `~/.oath/cache/registry/*.json` with a 5-minute TTL plus an ETag sidecar (`client.rs:27`, `151-233`).
  - The temp directory leaks, because `std::process::exit` skips `TempDir` drop (`main.rs:3765`).
  - Dependencies' lifecycle scripts are **never run** in exec.
- **Already in local `node_modules`:** if `./node_modules/.bin/<pkg_name>` exists (cwd only, matched by package name, not bin name), it runs directly **without scanning**, ignoring any version spec. This happens only when the sandbox is off and `--dry-run` is not set (`main.rs:3255-3266`).
- **Prompt:**
  - It prompts "run anyway? [y/N]" **only** when there are High/Critical findings and none of `--yes`, a prior approval, or `OATH_ALLOW_ALL` applies (`main.rs:3712-3725`). Otherwise it runs without prompting, unlike npx's install prompt.
  - `--json` never prompts. It prints the verdict and then **still executes** unless `--dry-run` is set or the grade gate trips, so stdout mixes the JSON with program output (`main.rs:3610-3661`).
  - Exit codes: 10 = grade block, 11 = too new, 13 = user denied (`main.rs:2932-2934`).
- **`--dry-run`:** still downloads, links and scans, then returns before running.
- **`--min-age`:** checked before download using full packument time (`main.rs:3319-3423`).
- **Sandbox modes:**
  - `--sandbox` means `auto` (`main.rs:3035-3045`). `OATH_AGENT_MODE=1` forces `auto` plus deny-network (`main.rs:3026-3045`, `3253`).
  - `native` needs all four controls (fs, net, process, resources) or it errors. `node` needs `--allow-degraded-sandbox` and Node `--permission` support. `auto` uses native, else node only with that flag, else errors (`main.rs:3069-3125`).
  - Node mode grants fs-read on cwd, exec dir and tmp, and fs-write on cwd and tmp (`main.rs:3203-3214`).
  - The native plan is `SandboxPlan::strict(pkg, exec_dir)`: read/write **only the temp install dir** (the user's project is not visible), env allowlist of PATH and TERM, 30 s timeout, 64 processes (`policy.rs:28-37`, `55-87`).
  - Network is inherited only if static analysis saw network use and deny is not set (`main.rs:3516-3523`).
  - Linux runs a hardcoded `/usr/bin/node` (`main.rs:3164`) inside bwrap, which binds only `/usr`, `/bin`, `/lib`, `/lib64` (`linux.rs:91-110`), so nvm or Volta nodes are not usable (code-reading).
  - macOS resolves the active node and grants it (`main.rs:3181-3202`).
  - Windows refuses any plan that allows network (`windows.rs:155-158`).
- **`--deny-network`:** keeps `NetworkMode::Deny` (bwrap `--unshare-net`, `linux.rs:84-86`) and is recorded in the approval and policy digest.
- **Approvals:** stored in `~/.oath/exec-approvals.json` as `{package, version, integrity, capabilities, sandbox_backend, deny_network}` with exact-match lookup (`approvals.rs:5-66`). Written only with `--remember`, and only when integrity is present (`main.rs:3728-3734`). An approval only suppresses the prompt.
- **Assessment:** signed v3 with a `~/.oath/decision-signing.key` Ed25519 key (`exec_assessment.rs:144-148`). The registry is recorded as hardcoded `https://registry.npmjs.org` (`main.rs:3355`, `3544`).

---

## 4. Publish, stage, transfer, auth
- **`publish` flow (`main.rs:4556-4861`):**
  1. Oath's own collector runs as a cross-check (`main.rs:4628-4633`). Then **`npm pack --dry-run --json --ignore-scripts` is the authoritative packlist** (`main.rs:4171-4213`, `4634`), so `npm` is required even for `--dry-run`.
  2. `publish_assessment::assess` blocks on secret paths or contents (`publish_assessment.rs:259-385`) and attaches a previous-release diff.
  3. `--json` requires `--dry-run`.
  4. Non-dry runs write signed evidence, an SPDX-2.3 SBOM and an in-toto statement to `.oath/publish-assessments/…` (`publish_assessment.rs:61-99`, `170-205`). The statement explicitly says it is "not source-build provenance" (`publish_assessment.rs:96`). The key is `~/.oath/publish-signing.key`.
  5. `--stage` runs `npm stage publish --tag` with `NPM_CONFIG_PROVENANCE=true` (`main.rs:4695-4708`). **That is the only provenance path.**
  6. Direct publish builds the tarball in memory with `tar::Builder` (not normalized or reproducible: real mtime and uid), computes sha512 and sha1, GETs `https://registry.npmjs.org/<name>` to reject duplicate versions, and **PUTs to a hardcoded `https://registry.npmjs.org`** (`main.rs:4710-4860`).
- **Direct publish gaps:** no OTP/2FA, no `publishConfig`, no `prepublishOnly`/`prepack`/`prepare`/`postpublish` scripts, no README in the payload.
- **Auth:** `NPM_TOKEN` env, or the `//registry.npmjs.org/:_authToken=` line in `~/.npmrc` only, with no `${VAR}` expansion (`main.rs:4780-4795`).
- The CLI never talks to the Oath registry directly; it is reachable only as a generic npm registry via `registry=`.
- **There is no `oath login`, `logout`, `whoami` or `token`.**
- **`stage`:** pure `npm stage` pass-through; approve and reject require `--yes` (`main.rs:4288-4386`).
- **`transfer create`:** npm packlist, then assess, then a signed capsule. **`transfer verify`:** checks hashes and signatures and reports `abstain` unless a trusted key is given (`main.rs:4388-4443`, `package_transfer.rs:225-381`).

---

## 5. Other commands (detail beyond the table)
- **`scan`:** walks `~/.oath/store/<name>/<ver>`. `--production` only drops devDeps from the "direct deps" count and emptiness check; the scan itself still covers the whole store (`main.rs:1356-1388`).
- **`why` and `graph` (code-reading):** both match lock keys as `name` or `name@…` (`main.rs:1844-1851`, `1864`, `2200-2203`, `2257-2260`). Arborist-mode keys are `node_modules/<name>` locations, so **`why <pkg>` reports "not found"** and **`graph` prints only root locations with no resolvable children**. Both appear broken on current locks.
- **`verify`:** validates the store BLAKE3 manifest per lock entry (`cas.rs:392-462`), not the materialized `node_modules`.
- **`score` / `info`:** `info` and the popularity context use hardcoded registry.npmjs.org and api.npmjs.org and ignore `.npmrc` (`oath-fetch/src/metadata.rs:47`, `141`).
- **`log`:** reads `~/.oath/transparency.log`, written by install, ci and workspace install (`main.rs:1101-1112`). Prints raw timestamps (`main.rs:5025-5038`).
- **`sandbox-info`:** verified probe (`oath-sandbox/src/lib.rs:59-100`).

---

## 6. npm commands Oath lacks

Grep of the `Commands` enum (`main.rs:150-330`) and the aliases (`main.rs:154`, `177`, `193`, `201`, `241`):

| npm command | Oath status |
|---|---|
| `audit` | Alias of `scan`. Behavioral scan of the global store, **not** an advisory/CVE audit. No `audit fix`. |
| `outdated` | Missing |
| `dedupe` | Missing |
| `prune` | Missing as a command (Arborist removals happen implicitly) |
| `link` | Missing |
| `pack` | Missing (`npm pack` is used only internally) |
| `view`/`show`/`info` | Partial: `info` shows latest version, fixed fields, no field selector |
| `search` | Missing (`RegistryClient::search` exists but is unused, `client.rs:398-420`) |
| `cache` | Missing (`DiskCache` in `cache.rs` is dead code with zero references) |
| `config`, `get`/`set` | Missing |
| `login`, `logout`, `whoami`, `token`, `adduser`, `profile` | Missing |
| `version` (bump) | Missing (only `oath --version`) |
| `dist-tag`, `deprecate`, `owner`, `access`, `unpublish`, `team`, `org`, `star`, `hook` | Missing |
| `ping`, `doctor` | Missing |
| `explain` | ≈ `why` (broken per §5) |
| `ls`/`list` | Missing (`graph` is a partial substitute) |
| `rebuild` | Missing |
| `test`/`t`, `start`, `stop`, `restart` | Missing as aliases (must use `oath run`) |
| `exec` alias `x` | Present |
| `run-script`, `rum`, `urn` aliases | Missing |
| `set-script`, `pkg` | Missing |
| `query` | Missing |
| `sbom` | Missing as a command (SPDX only for your own package during publish) |
| `fund` | Missing |
| `i`, `in`, `isntall` aliases | Missing (`add` is a separate command; `install --ci` exists) |
| `clean-install`, `ic`, `install-clean`, `install-test`/`it`, `cit` | Missing |
| `update` aliases `up`/`upgrade` | Missing |
| `uninstall`, `rm` | Present; `un`, `r`, `unlink` missing |
| `init <initializer>` / `create-*`, `init -y` | Missing |
| `shrinkwrap`, `diff`, `edit`, `explore`, `docs`, `repo`, `bugs`, `completion`, `prefix`, `root`, `bin`, `help-search` | Missing |
| `stage` | Present, as a wrapper requiring host npm ≥ 11.15 |

Missing install flags: `--omit`, `--include`, `--production`, `--save-exact`/`-E`, `--save-optional`/`-O`, `--save-peer`, `--no-save`, `--workspace`/`-w`, `--workspaces`, `--prefix`, `--registry`, `--legacy-peer-deps` (`.npmrc` only), `--strict-peer-deps` (`.npmrc` only), `--force`, `--offline`/`--prefer-offline`, `--foreground-scripts`, `--install-links`, `--package-lock-only`.

---

## 7. TODO / FIXME / "future" / "unsupported" / `bail!` markers in `crates/`

There are **no** `TODO`, `FIXME`, `todo!()` or `unimplemented!()` occurrences in `crates/`. The hits:

| Location | Message |
|---|---|
| `crates/oath-store/src/linker.rs:907` | `// Would need to list files in that dir - skip for now` (`directories.bin` ignored) |
| `crates/oath-cli/src/main.rs:1334` | `// (same logic as single-pkg install; abbreviated here)` (workspace scan is a no-op) |
| `crates/oath-resolve/src/lib.rs:7` | `//! Future: upgrade to PubGrub for better conflict resolution.` |
| `crates/oath-analyze/src/behavior.rs:527` | `let _ = looks_base64ish; // reserved for a future blob-entropy signal` |
| `crates/oath-resolve/src/git.rs:200` | `git semver selector `{range}` is not supported yet; pin an exact tag or commit instead` |
| `crates/oath-resolve/src/import.rs:24` | `package-lock.json has no `packages` map (lockfileVersion 1 is unsupported; run `npm install` once with npm 7+ to upgrade it)` |
| `crates/oath-sandbox/src/windows.rs:158` | `Windows AppContainer outbound network grants are not implemented; refusing degraded execution` |
| `crates/oath-sandbox/src/lib.rs:97` | `unsupported platform` |
| `crates/oath-cli/src/main.rs:507` | `internal sandbox launcher is Linux-only` |
| `crates/oath-cli/src/main.rs:528` | `native sandbox backend is unavailable on this platform` |
| `crates/oath-cli/src/main.rs:559` | `cannot add packages with --frozen-lockfile/--ci` |
| `crates/oath-cli/src/main.rs:564`, `1123` | `no lockfile found, run oath install first` |
| `crates/oath-cli/src/main.rs:753` | `lockfile would be modified, refusing (--frozen-lockfile)` |
| `crates/oath-cli/src/main.rs:1131` | `package.json does not match oath-lock.json, run oath install first` |
| `crates/oath-cli/src/main.rs:1151` | `placement plan does not match oath-lock.json, run oath install first` |
| `crates/oath-cli/src/main.rs:2649` | `git dep {name}@{version} not in cache and no tarball URL available` (`score` path) |
| `crates/oath-cli/src/main.rs:2692`, `2717` | `unsupported local dependency URL` / `unsupported local dependency: {}` |
| `crates/oath-cli/src/main.rs:3096` | `Node permissions do not provide process or resource isolation; pass --allow-degraded-sandbox only when policy explicitly accepts that limitation` |
| `crates/oath-cli/src/main.rs:3100` | `Node permission sandbox is unavailable on this Node runtime` |
| `crates/oath-cli/src/main.rs:3110-3121` | `verified native containment is unavailable: …; Oath refused to downgrade automatically` |
| `crates/oath-cli/src/main.rs:3249` | `unsupported exec assessment schema {v}; supported versions are 2 and 3` |
| `crates/oath-cli/src/main.rs:3746` | `oath exec: could not find binary for {pkg}` |
| `crates/oath-cli/src/main.rs:4178` | `npm 11 is required to compute the authoritative publish packlist` |
| `crates/oath-cli/src/main.rs:4266-4276` | `oath stage requires npm >= 11.15.0` / `requires Node >= 22.14.0` |
| `crates/oath-cli/src/main.rs:4340` | `oath stage approve requires --yes after reviewing …` |
| `crates/oath-cli/src/main.rs:4353` | `oath stage reject is permanent and requires --yes` |
| `crates/oath-cli/src/main.rs:4463`, `4471`, `4497` | `refusing symlink` / `out-of-root path` / `non-regular file` |
| `crates/oath-cli/src/main.rs:4572` | `oath publish --json is an assessment-only interface and requires --dry-run…` |
| `crates/oath-cli/src/main.rs:4576` | `unsupported publish assessment schema {v}; supported versions are 1 and 2` |
| `crates/oath-cli/src/main.rs:4773` | `{name}@{ver} is already published. Bump the version…` |
| `crates/oath-cli/src/main.rs:4794` | `no npm auth token found. Set NPM_TOKEN … or ~/.npmrc` |
| `crates/oath-cli/src/main.rs:4869` | `oath install -g: please specify at least one package…` |
| `crates/oath-cli/src/package_transfer.rs:316` | `unsupported Oath transfer format` |
| `crates/oath-fetch/src/tarball.rs:258` | `unsupported tar entry type {:?}`. Only Regular and Directory are accepted, so tarballs with symlink or hardlink entries hard-fail where pacote skips them. |
| `crates/oath-fetch/src/tarball.rs:104` | `SRI metadata contains no supported digest` |
| `crates/oath-store/src/cas.rs:433` | `unsupported store manifest schema {}` |
| `crates/oath-store/src/cas.rs:576` | `refusing special file in store` |
| `crates/oath-store/src/linker.rs:175`, `186`, `202` | `workspace link escapes project` / `workspace link has no existing project ancestor` |
| `crates/oath-resolve/src/placement.rs:234`, `389` | `unsupported placement plan version` |
| `crates/oath-sandbox/src/macos.rs:47`, `55` | `sandbox paths containing control characters are unsupported`, `unsupported sandbox plan version` |
| `crates/oath-sandbox/src/linux.rs:73-77` | `native Linux sandbox unavailable: install bubblewrap; Oath will not silently fall back` |
| `crates/oath-registry/src/object_backend.rs:128`, `183` | `unsupported object backend` / `unsupported replica object backend` |
| `crates/oath-registry/src/assessment.rs:38` | `archive contains unsupported link or special entry` |
| `crates/oath-contracts/src/lib.rs:240-243` | `unsupported signature algorithm` / `unsupported signature canonicalization` |

Approximation comments:
- `main.rs:4003` — ISO age is approximate ("good enough").
- `main.rs:5033` — "Approximate date (not perfect…)".
- `oath-fetch/src/metadata.rs:173`, `189-191` — approximate days-since-epoch.

---

## 8. What the docs say is out of scope, failing or planned

- **`docs/NPM_COMPATIBILITY_CONTRACT.md`:**
  - Targets npm 11 parity for install, ci, add/remove, run, exec, workspaces, lock import, registry auth, peers, overrides, aliases, git/file/tarball deps, lifecycle and exit status.
  - "Registry administration commands are outside this contract."
  - The parity comparator excludes `.package-lock.json`, `.oath`, store manifests and empty directories.
  - The 250-project claim "remains open until an exact-candidate parity run passes".
  - `npm ci` is not inferred from the install corpus.
  - Intentional fail-closed divergence: git `#semver:` is rejected, and exact tag-range resolution is "outside the current supported slice".
  - Practical note: the harness only exercises `install` and `ci` with `--ignore-scripts` (`scripts/npm-parity.mjs:96-97`), so scripts, run, exec, aliases-as-commands and `.bin` are not parity-tested.
- **`docs/SUPPORTED_PLATFORMS.md`:**
  - Baseline: npm 11.12.1; Node 22.14+/24; Ubuntu 24.04 strict and 22.04 fail-closed; macOS 15 Seatbelt (deprecated `sandbox-exec`); Windows Server 2022/2025; registry on PostgreSQL 17.
  - "Uncovered workflows are documented; no silent npm fallback."
  - External review of all 100 workflows is still a GA gate.
  - Incompatibilities are classified as fail-closed, explicit compatibility mode, or planned incompatibility.
- **`docs/GA_GATE_TRACKER.md`:** nothing is complete. Open items: 100-workflow independent review; 10k executions on the exact commit; 250-project parity on the exact commit; **detection quality ("historical quality still failing")**; native containment evidence ("partial"); **performance ("Open; current sample loses")**; registry HA/KMS/CDN drills; Rekor and witnesses; 60-day SLO window; external security review; legal; 50 design partners.
- **`docs/RELEASE_READINESS.md`:**
  - v0.2.5 is a developer preview, "not GA".
  - The registry is a business beta for design partners.
  - Installer benchmarks: "Oath measured slower than npm and Bun for both cold and warm installs."
  - Scanner baseline is 57.5% malware recall and 0.6% false positives on the old v0.1.6 engine, not rerun on current source.
  - macOS signing/notarization and external escape review are open; the governance gate is a single maintainer.
- **`docs/VISION.md`:**
  - Aspirations not implemented in the CLI: threshold revocation, pay-to-audit (AI review of each release), anti-squatting and name handover, pay-per-audit scripts, private-registry-by-default pull/publish, npx as a shared executable layer.
  - Its "Where Oath stands" section says detection, performance, code signing, public registry/CDN, anti-squatting, external review, SLOs and adoption remain open, and v0.2.5 is "not a production-wide npm replacement".
- **`docs/workspace-research.md`:** a stale design doc. Its planned features are mostly **not implemented**: `--filter` / `-F` / `--recursive` / `--parallel`; an `oath workspace list/run/install` subcommand; topological parallel script runs; a `workspaces` section in `oath-lock.json`. Only root detection and whole-root install exist.
- **`docs/peer-dependencies-research.md`:** a stale pre-Arborist doc. It says the resolver "does NOT process peer deps", lists MVP vs post-MVP work (`--strict-peer-deps`, auto-install peers, peer-keyed store), and flags a `pathdiff_relative` bug that is now fixed (`linker.rs:1044`). Peers are now handled by Arborist, but Oath surfaces no peer warnings (§1).
- **`BENCHMARKS.md`:**
  - The v0.2.0-RC snapshot (darwin-arm64, 5-dependency manifest) has npm at 728/428 ms, Bun at 406/23 ms, and Oath at **2,683/1,243 ms** (cold/warm).
  - "This sample does not support a speed claim."
  - The older v0.1.x tables are historical (Oath slower than Bun, mixed against npm; exec ≈ npx).
- **`CHANGELOG.md`:**
  - 0.2.5: macOS runtime-probed Seatbelt; init writes `UNLICENSED`; `OATH_VERSION` installer pin.
  - 0.2.4: Apache-2.0; macOS native was still unavailable and fail-closed at that point.
  - 0.2.3: evidence-manifest gate derivation fix.
  - 0.2.2: OCI/K8s registry; cross-language verifiers; linking fixes for dangling workspace links, quoted npmrc booleans, `v`-prefixed versions, Windows drive case.
  - All say "remains a developer preview"; `[Unreleased]` is empty.

---

## 9. Platform and runtime facts
- **`node` is required at runtime** for `install`, `add`, `update`, `remove`, `exec`, `install -g`, and `ci` when no `.oath/placement-plan.json` exists (`placement.rs:216`). It is also needed for packing git dependencies (`placement.rs:264`) and node-permission or native exec.
  - This contradicts README.md:369-370 ("the Oath binary itself does not require Node for its baseline commands").
  - Node-free commands: `scan`, `perms`, `why`, `licenses`, `verify`, `graph`, `score`, `info`, `log`, `sandbox-info`.
- **`npm` is required** for `publish` (including `--dry-run`, `main.rs:4173`), `transfer create` (`main.rs:4398`) and `stage` (`main.rs:4261-4279`). It is *not* required for planning, because the bundled Arborist is used and `npm root -g` is only a fallback if the bundled require fails (`plan.cjs:6-11`).
- **Other tools:** `git` for non-GitHub git deps (`git.rs:274-291`). `sh` for every script. bubblewrap on Linux native (`linux.rs:73-77`).
- **Vendored:** `crates/oath-resolve/vendor/npm-11.12.1.tgz` (2,833,345 bytes). It is `include_bytes!`'d into the binary with a pinned SHA-256 (`placement.rs:16-17`), extracted to a tempdir on every plan, and checked for `@npmcli/arborist` 9.4.2, `npm-install-checks` 8.0.0 and `npm-packlist` 10.0.4 (`placement.rs:12-15`, `322-351`).
- **Windows:**
  - x64/ARM64 release binaries exist; parity CI runs on Windows with `--ignore-scripts` only.
  - Directory links are junctions via `cmd.exe mklink /J` (`linker.rs:75-102`); `.bin` entries are file symlinks with no cmd shims (`linker.rs:109-112`).
  - Scripts use `sh -c` (`main.rs:1632`, `1702`, `2907`) with a `:` PATH separator (`main.rs:1627`, `1688`).
  - `npm.cmd` is used for npm (`main.rs:4215-4224`).
  - The AppContainer sandbox cannot grant network (`windows.rs:155-158`).
  - The planner strips `\\?\` prefixes (`placement.rs:190-199`).

---

## 10. Performance notes
- **Benchmarks:** `compat-results/benchmarks/installers.json` (2026-07-12, darwin-arm64, Node 26, npm 11.12.1, Bun 1.2.20, chalk/express/is-number/typescript/vite, scripts off, Oath scanner on):

  | Installer | Cold | Warm |
  |---|---:|---:|
  | npm | 728 ms | 428 ms |
  | Bun | 406 ms | 23 ms |
  | Oath | 2,683 ms | 1,243 ms |

  - Oath's own stdout breakdown (cold): download 0.8 s and link 0.4 s out of a 2.5 s total, leaving roughly 1.3 s for the Arborist plan plus the scan of 84 packages.
  - Warm: link 0.3 s out of 1.2 s, leaving roughly 0.9 s for planning plus store re-verification.
  - The Oath tree had 1,240 entries vs npm's 1,157.
- **Where the time goes (code):**
  - Every plan extracts the embedded 2.8 MB npm tarball, spawns `node`, and runs an Arborist reify dry-run that does its own registry/pacote fetching (`placement.rs:211-240`, `322-335`).
  - `missing_store_nodes` serially **re-hashes every file of every package with BLAKE3** on each install (`main.rs:2431-2457`, `cas.rs:458+`, `573`).
  - Downloads are spawned all at once in a `JoinSet` **with no concurrency cap**. Extraction and the store write then run serially in the join loop on the async thread (`main.rs:2522-2558`).
  - The linker hardlinks the **entire existing `node_modules`** into a stage dir before applying the plan (`linker.rs:245-251`), hardlinks file by file with a copy fallback and no reflink/clonefile (`linker.rs:915-933`), then swaps with renames and `remove_dir_all` of the backup (`linker.rs:352-363`).
  - The scan uses rayon across all graph nodes whenever anything was downloaded (`main.rs:1016-1038`).
  - The legacy resolver uses level-parallel BFS (`resolver.rs:3`, `212`).
- **HTTP client:**
  - reqwest with gzip, `tcp_nodelay`, `pool_max_idle_per_host(32)` (keep-alive pooling), 10 s timeout, 120 s for tarballs, 3 attempts with backoff (`client.rs:27-31`, `123-130`).
  - The `http2` feature is not enabled, so HTTP/1.1 only (`Cargo.toml:51`).
  - Abbreviated packument Accept header (`client.rs:22-23`).
  - Packument disk cache: 5-minute TTL plus ETag (`client.rs:151-233`). In the default path it is mostly bypassed because Arborist fetches metadata itself.
  - `crates/oath-fetch/src/cache.rs` (`DiskCache`) is **unused dead code**.

---

## Other code-vs-docs discrepancies worth noting
- CLAUDE.md says "Lifecycle scripts never run before this gate". In code, trusted, `-y` and `--run-scripts` dependency scripts run before the batch scan (`main.rs:937-1013` vs `1015`), and scan results never block an install.
- `oath init` silently overwrites an existing `package.json` (`main.rs:1818`).
- `oath remove` deletes `node_modules` completely when the last dependency is removed (`main.rs:4103-4111`).
