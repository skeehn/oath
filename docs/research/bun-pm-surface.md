<!-- Research snapshot gathered 2026-10-04 from bun.com docs, bun.com/blog, oven-sh/bun, pnpm.io, and npm/yarn changelogs. Point-in-time reference for docs/FULL_REPLACEMENT_ROADMAP.md; verify against current upstream docs before relying on a detail. -->

# Bun package manager — complete user-facing surface (as of 2026-10-04)

**Context on versions.** Current stable is Bun **1.4.x** (1.4.0 released 2026-08-20, 1.4.1 on 2026-09-04, 1.4.2 on 2026-09-05). Bun 1.4 "rewrites Bun from Zig to Rust" (official 1.4 post: https://bun.com/blog/bun-v1.4). Official docs now live at bun.com/docs (bun.sh redirects); the package-manager section is under `/docs/pm/...` (index: https://bun.com/docs/llms.txt). Everything below was read from bun.com docs, bun.com/blog release posts, or oven-sh/bun source on 2026-10-04.

**Feature-introduction timeline (for "when added" questions)**

| Feature | Version / date | Source |
|---|---|---|
| `bun pm trust` / `untrusted` / `default-trusted`, `bun add --trust` | v1.0.31 (2024-03-14) | https://bun.com/blog/bun-v1.0.31 |
| `bun patch` / `patchedDependencies` | v1.1.14 (2024-06-19) | https://bun.sh/blog/bun-v1.1.14 |
| `.npmrc` support (project) | v1.1.18 (2024-07-03) | https://bun.com/blog/bun-v1.1.18 |
| `bun outdated` | v1.1.22-era (Aug 2024) | https://bun.com/blog (listing) |
| `bun publish`, `bun pm whoami`, `--registry` flag, `$HOME/.npmrc` | v1.1.30 (2024-10-08) | https://bun.com/blog/bun-v1.1.30 |
| `bun pm pack` | Sept/Oct 2024 (v1.1.2x; listed with `bun publish` in Bun 1.2 post) | https://bun.com/blog/bun-v1.2 |
| `npm_lifecycle_script`, `npm_command` env vars | v1.1.37 (2024-11-26) | https://bun.com/blog/release-notes/bun-v1.1.37 |
| Text lockfile `bun.lock` (opt-in `--save-text-lockfile`) | v1.1.39 (2024-12-17) | https://bun.com/blog/bun-lock-text-lockfile |
| `bun install --filter`, `--lockfile-only`, `bun add --peer` | v1.1.43 (Jan 2025) | https://bun.com/blog (listing) |
| `bun.lock` default, `--omit`, `--ca/--cafile`, `bun run --filter`, 30% faster install | Bun 1.2 (2025-01-22) | https://bun.com/blog/bun-v1.2 |
| `bun install --analyze <files>` | ~v1.2.3 (Feb 2025, PR #17035) | https://github.com/oven-sh/bun/pull/17035 |
| Catalogs (`catalog:`) | v1.2.14 (2025-05-21) | https://bun.com/blog/bun-v1.2.14 |
| `bun audit`, `bun pm view` | v1.2.15 (2025-05-28) | https://bun.com/blog/bun-v1.2.15 |
| `install.linkWorkspacePackages`, `bun outdated` catalogs | v1.2.16 (2025-06-11) | https://bun.com/blog/bun-v1.2.16 |
| `--linker isolated`, `bun why`, `bun pm pkg`, `bun update --interactive` | v1.2.19 (2025-07-19) | https://bun.com/blog/bun-v1.2.19 |
| `bun pm version` | v1.2.20 (Aug 2025) | https://bun.com/blog (listing) |
| Security Scanner API (`[install.security] scanner`), `bun audit --audit-level/--prod/--ignore` | v1.2.21 (2025-08-25), launched publicly with Socket in 1.3 | https://bun.com/blog/bun-v1.2.21 , https://github.com/oven-sh/bun/commit/efdbe3b |
| Automatic `pnpm-lock.yaml` migration | v1.2.23 (2025-09-28) | https://bun.sh/blog/bun-v1.2.23 |
| Isolated default for workspaces, `minimumReleaseAge`, `bun info`, `--cpu/--os`, `--lockfile-only` manifest-only | Bun 1.3 (2025-10-10) | https://bun.com/blog/bun-v1.3 |
| `configVersion` in lockfile (isolated default only for *new* workspaces), `bun list` alias, `nativeDependencies`/`ignoreScripts` fields | v1.3.2 (2025-11-08) | https://bun.sh/blog/bun-v1.3.2 |
| Default-trusted list only applies to npm-registry packages; `.npmrc` `${VAR?}` | v1.3.5 (2025-12-17) | https://bun.com/blog/bun-v1.3.5 |
| `bun run --parallel` / `--sequential` / `--no-exit-on-error` | v1.3.9 (2026-02-08) | https://bun.com/blog/bun-v1.3.9 |
| SHA-512 integrity for GitHub/tarball deps in `bun.lock` | v1.3.10 | https://bun.com/blog/bun-v1.4 (changelog) |
| Global virtual store (`install.globalStore`) | v1.3.14 | https://bun.com/blog/bun-v1.4 |
| `bun audit fix`, `bun dedupe`, `bun prune`, `bun pm licenses`, `bun pm diff`, `bun update` transitive, `bun add --filter`, `bun add --catalog`, nested/version-scoped overrides, `lockfileVersion: 2`, Rust rewrite | Bun 1.4.0 (2026-08-20) | https://bun.com/blog/bun-v1.4 |
| `bun install --offline`, `--prefer-offline` | v1.4.1 (2026-09-04) | https://bun.com/blog/bun-v1.4.1 |

---

## 1. Every package-manager subcommand and flag (one line each; **[D]** = daily use, **[R]** = rare)

Sources: https://bun.com/docs/pm/cli/install , /pm/cli/add , /pm/cli/remove , /pm/cli/update , /pm/cli/outdated , /pm/cli/pm , /pm/cli/link , /pm/cli/patch , /pm/cli/publish , /pm/cli/audit , /pm/cli/why , /pm/cli/info , /pm/cli/dedupe , /pm/cli/prune , /pm/bunx , /pm/filter , /runtime/templating/init , /runtime/templating/create

### `bun install` (alias `bun i`) [D]
- `bun install` — install all deps (dependencies, devDependencies, optionalDependencies, and peerDependencies by default), run the *project's* `{pre,post}install`/`{pre,post}prepare`, write `bun.lock`. [D]
- `bun install <pkg>[@ver|@tag]` — same as `bun add`. [D]
- `-c, --config <path>` — path to bunfig.toml. [R]
- `--cwd <dir>` — run as if in that directory. [R]
- `-p, --production` — don't install devDependencies; **implies `--frozen-lockfile`**; already-installed devDeps stay (use `bun prune --production`). [D in CI]
- `--no-save` — don't update package.json or write a lockfile. [R]
- `--save` — write to package.json (default true). [R]
- `--omit <dev|optional|peer>` (repeatable) — exclude dependency types. [D in CI]
- `--only-missing` — only add deps to package.json if not already present. [R]
- `-d, --dev` / `--optional` / `--peer` — dependency group for added packages. [D]
- `-E, --exact` — write exact version instead of `^range`. [D]
- `-y, --yarn` — also write a yarn v1 `yarn.lock`. [R]
- `--frozen-lockfile` — fail if package.json and `bun.lock` disagree; never write lockfile. [D in CI]
- `--save-text-lockfile` — write `bun.lock` instead of legacy `bun.lockb` (default since 1.2). [R]
- `--lockfile-only` — resolve and write lockfile without installing to node_modules (fetches manifests only, 1.3+). [R]
- `--ca <cert>` / `--cafile <path>` — CA certificate (inline or file). [R]
- `--registry <url>` — override registry (beats .npmrc, bunfig, env); scoped registries still win for their scope. [R]
- `--dry-run` — resolve but don't install/write (project's own lifecycle scripts still run). [R]
- `-f, --force` — always re-request latest manifests and reinstall everything. [R]
- `-g, --global` — install into global dir (`~/.bun/install/global`), link bins to `~/.bun/bin`. [D for CLIs]
- `--backend <clonefile|hardlink|symlink|copyfile|clonefile_each_dir>` — file-materialization strategy. [R]
- `--linker <hoisted|isolated>` — node_modules layout. [D for monorepos]
- `-F, --filter <pattern>` (repeatable) — install only for matching workspaces. [D in monorepos]
- `-a, --analyze <files...>` — scan source files with the bundler for imports and install the missing packages. [R]
- `--cache-dir <path>` — cache location. [R]
- `--no-cache` — ignore manifest cache entirely. [R]
- `--silent` / `--verbose` / `--no-progress` / `--no-summary` — output control. [R]
- `--no-verify` — skip integrity verification of newly downloaded tarballs. [R, discouraged]
- `--trust` — add packages to `trustedDependencies` and run their scripts. [D when needed]
- `--concurrent-scripts <n>` — max concurrent lifecycle scripts (default 2× CPU count). [R]
- `--network-concurrency <n>` — max concurrent network requests (**default 48**). [R]
- `--ignore-scripts` — skip *all* lifecycle scripts, including the project's own and trusted deps. [D in CI]
- `--cpu <arch>` / `--os <os>` — select platform-specific optionalDependencies for another target (values listed in docs; `*` for all). [R]
- `--minimum-release-age <seconds|"3d">` — cooldown gate (seconds; ms-style strings per PR #30529). [R but recommended]
- `--prefer-offline` — use cached metadata regardless of age; fetch only what's missing (1.4.1). [R]
- `--offline` — never touch network; missing cache entry is an error (1.4.1). [R]
- `-h, --help`.
- `bun ci` — exact alias of `bun install --frozen-lockfile` (docs: https://bun.com/docs/pm/cli/install#ci-cd). [D in CI]

### `bun add` [D] — all `bun install` flags plus:
- `bun add <pkg>[@version|@range|@tag]`, git (`git@github.com:org/repo.git`, `github:user/repo`, `git+https://`, `git+ssh://`), tarball URL (`zod@https://.../zod-3.21.4.tgz`, credentials in URL become Basic auth), `npm:` alias, local folder (`./vendor/x`).
- `-d/-D/--dev/--development`, `--optional`, `--peer`, `-E/--exact`, `--only-missing`, `--trust`, `-g/--global`.
- `--catalog` / `--catalog=<name>` — write version into root `workspaces.catalog[s]` and `"catalog:"` in the current package (1.4). [D in monorepos]
- `-F, --filter <pattern>` — add to matching workspaces instead of cwd (1.4); `*` excludes root; not combinable with `--global`. [D in monorepos]
- `-a, --analyze`.

### `bun remove` (aliases `bun rm`, `bun uninstall`, `bun r`) [D]
- Removes from every dependency group listing it; `--filter` for workspaces (1.4); same install flags (`--no-save`, `--frozen-lockfile`, `--dry-run`, `--ignore-scripts`, `-g`, ...).

### `bun update` (alias `bun up`) [D]
- `bun update` — update every dependency (direct **and transitive**, 1.4) to newest allowed by ranges; rewrites package.json ranges preserving operator; never widens ranges. [D]
- `bun update <name|pattern> ['!exclude']` — update specific packages/globs everywhere in `bun.lock`. [D]
- `-L, --latest` — ignore declared ranges for direct deps; rewrite ranges same style. [D]
- `-i, --interactive` — TUI selection (Space/Enter/a/n/i/l keys; l toggles latest). [D]
- `-r, --recursive` — update every workspace's package.json; `-F, --filter` for subset. [D in monorepos]
- `-D, --dev` / `-P, --prod` / `--no-optional` — restrict which groups to update. [R]
- `-g, --global` — update global packages. [R]
- `--dry-run`, `--no-save`, `--force`, `--frozen-lockfile`, `--lockfile-only`, `--ignore-scripts`, `--trust`, `--backend`, `--cache-dir`, `--no-cache`, `--ca/--cafile`, `--registry`, `--network-concurrency`, `--concurrent-scripts`, `--omit`, `--yarn`, logging flags.

### `bun outdated` [D]
- `bun outdated [name|glob|'!glob']` — table of Current / Update (within range) / Latest. `-F, --filter <ws>`, `-r, --recursive` (adds Workspace column; shows catalog deps). Read-only (`--dry-run` is a no-op). Other install flags accepted but irrelevant. [D]

### `bun audit` [D in CI]
- `bun audit` — reads `bun.lock` (no node_modules needed), POSTs to the registry's npm advisory bulk endpoint (scoped registries get their own request; registries without endpoint → packages "skipped"). Never modifies files. Exit 1 if vulns remain.
- `--audit-level=<low|moderate|high|critical>`, `--prod`/`-p`/`-P`/`--production`, `--omit=<dev|optional|peer>`, `--ignore <GHSA-id|numeric id>` (repeatable; CVE IDs don't match), `--json` (raw registry JSON; filters affect only exit code).
- `bun audit fix` (1.4) — upgrade each vulnerable package to the lowest safe version every dependent's range allows, then install; rewrites exact pins in package.json/catalog; reports `blocked by a dependent's range` and `no published version fixes`; re-audits after install; `--latest` lets it cross majors by rewriting your own ranges; `--dry-run`, `--json`, `--ignore-scripts`; rejects `--prod`, `--frozen-lockfile`, `--no-save`; honors configured security scanner.

### `bun why <pkg|glob>` [D] — dependency chain explaining why a package is installed; `--top`, `--depth <n>`.
### `bun info <pkg>[@ver] [field]` (alias `bun pm view`) [D] — registry metadata; `--json`; dotted property access (`repository.url`).
### `bun link` / `bun unlink` [R]
- `bun link` (in package dir) registers it globally; `bun link <name>` symlinks into cwd's node_modules; `--save` writes `"name": "link:name"`; `bun unlink` unregisters. Accepts the normal install flags.
### `bun patch` [R]
- `bun patch <pkg>[@ver] | node_modules/<pkg>` — materialize an unlinked copy in node_modules safe to edit.
- `bun patch --commit <pkg> [--patches-dir=<dir>]` — generate `patches/<name>@<ver>.patch`, add to `patchedDependencies`, update lockfile; `bun patch-commit` alias for pnpm compat.
### `bun publish` [R] — see section 8.
### `bun dedupe` (1.4) [R] — collapse duplicate versions in `bun.lock` to the smallest set of already-locked versions; `--check` (exit 1 if dupes), `--dry-run`, `--lockfile-only`; never touches package.json or network.
### `bun prune` (1.4) [R] — delete node_modules entries not in `bun.lock` (including stale isolated-store entries); `--production`, `--omit`, `--dry-run`, `--filter`, `--linker`, `--os/--cpu`; `--global` unsupported.
### `bun pm <subcommand>` (utilities)
- `bun pm pack` [D for publishers] — npm-compatible tarball; `--dry-run`, `--destination <dir>`, `--filename <name>` (mutually exclusive), `--ignore-scripts` (skip pre/postpack, prepare), `--gzip-level 0-9` (default 9), `--quiet` (print only filename).
- `bun pm bin [-g]` [R] — print local `node_modules/.bin` or global bin dir.
- `bun pm ls [--all] [--trusted]` (alias `bun list`) [D] — list installed packages from lockfile; `--trusted` shows what may run scripts.
- `bun pm licenses [ls]` (1.4) [R] — group by license; `--json`, `--long`, `--prod`, `--dev`, `--omit`, `--filter`; needs lockfile + node_modules.
- `bun pm diff [a] [b] [paths]` (1.4) [R] — semantic diff between two versions/folders/tarballs; flags `--raw/--unformatted`, `--minify`, `--unminify`, `-w/--ignore-space`, `--stat`, `--name-only`, `-U/--unified <n>`, `--diff <spec>` (npm-compatible), `--json`; summary flags new install scripts, new `child_process`/`fs`/`net`/`vm` imports, eval growth, escape sequences.
- `bun pm whoami` [R] — print npm username from configured credentials.
- `bun pm hash` / `hash-string` / `hash-print` [R] — compute lockfile hash / show string hashed / print stored hash.
- `bun pm cache` / `bun pm cache rm` [R] — print path / clear global cache (also clears bunx caches and global virtual store).
- `bun pm migrate` [R] — convert another PM's lockfile to `bun.lock` without installing.
- `bun pm untrusted` [D when debugging native deps] — list deps whose lifecycle scripts were blocked.
- `bun pm trust <names...> | --all` [D when needed] — run blocked scripts and add names to `trustedDependencies`.
- `bun pm default-trusted` [R] — print built-in allow list.
- `bun pm version [patch|minor|major|prepatch|preminor|premajor|prerelease|from-git|x.y.z]` [R] — bump version, git commit+tag by default; `--no-git-tag-version`, `--allow-same-version`, `-m/--message`, `--preid`, `-f/--force`; runs pre/post version scripts.
- `bun pm pkg get|set|delete|fix` [R] — edit package.json with dot/bracket paths; `--json` for set.
- `bun pm scan` [R] — run the configured security scanner over the whole lockfile (needs `[install.security] scanner`); exit 1 on advisories (source: https://github.com/oven-sh/bun/pull/22193 ; help text in src/install/PackageManager.rs).
- `bun pm view` [R] — alias of `bun info`.
### `bunx` / `bun x` [D] — see section 7 (`--bun`, `-p/--package`, `--no-install`, `--verbose`, `--silent`).
### `bun init [folder] [-y|--yes] [-m|--minimal] [--react[=tailwind|shadcn]]` [D] — scaffold (templates Blank/React/Library), writes package.json/tsconfig/README/entry, agent rule files (`CLAUDE.md`, `.cursor/rules`; disable with `BUN_AGENT_RULE_DISABLED=1`), then runs `bun install` for `@types/bun`.
### `bun create <template|user/repo|./Component.tsx> [dest]` [R] — `create-<template>` from npm via bunx, GitHub repo tarball, local template in `~/.bun-create/`, or React component → full app; flags `--force`, `--no-install`, `--no-git`, `--open`; env `GITHUB_API_DOMAIN`, `GITHUB_TOKEN`; template `"bun-create": {preinstall, postinstall, start}`.
### `bun run` [D] — see section 6 (`--filter`, `--workspaces`, `--parallel`, `--sequential`, `--no-exit-on-error`, `--if-present`, `--elide-lines`, `--bun`, `--shell`, `--silent`, `-e`, `-p`).

---

## 2. Lockfile

Sources: https://bun.com/docs/pm/lockfile , https://bun.com/blog/bun-lock-text-lockfile , https://bun.com/blog/bun-v1.4#bun-lock-is-now-lockfileversion-2 , https://bun.com/docs/pm/cli/install#pnpm-migration

- **`bun.lock`** (JSONC text; "like tsconfig.json") introduced v1.1.39 behind `--save-text-lockfile`; **default since Bun 1.2** (2025-01-22). Structure: `lockfileVersion`, `configVersion` (1.3.2+: 0 = legacy hoisted defaults, 1 = new defaults), `workspaces` (per-workspace deps incl. `catalog:`/`workspace:` specifiers), `catalog`/`catalogs`, `packages` (`"name": ["name@resolution", {deps/peer meta}, "sha512-..."]`), `overrides`, `patchedDependencies`, `trustedDependencies`. Importable at runtime as a module. GitHub renders diffs; Dependabot/Renovate-friendly.
- **`lockfileVersion` history**: 0 (1.2), 1, 2 (Bun 1.4: integrity required for npm packages resolved outside the configured registry; git entries validated against path traversal), **3** when nested/version-scoped overrides are used (older Bun can't read it). v1.3.10 added SHA-512 integrity for GitHub/tarball deps.
- **`bun.lockb`** (binary, pre-1.2) still read; Bun keeps updating a `bun.lockb` if that's what the project has. `install.saveTextLockfile = false` makes new projects write `bun.lockb`. Migrate with `bun install --save-text-lockfile --frozen-lockfile --lockfile-only` then delete `bun.lockb`.
- **`--frozen-lockfile`**: install exactly what's locked; error if package.json disagrees; with no lockfile at all it installs from package.json without writing one; works on pruned monorepo checkouts (missing workspace package.json → skipped with a note). Not auto-enabled in CI (unlike npm ci / yarn); use `bun ci`. `--production` implies it. `--frozen-lockfile --dry-run` validates without installing.
- **`--lockfile-only`**: write lockfile without installing (still populates cache with metadata; 1.3 optimized to fetch manifests only). `--no-save` installs without writing a lockfile. `BUN_CONFIG_SKIP_SAVE_LOCKFILE` / `BUN_CONFIG_SKIP_LOAD_LOCKFILE` env vars.
- **`--yarn` / `[install.lockfile] print = "yarn"`** — additionally emit a yarn v1 `yarn.lock` (only "yarn" supported). `[install.lockfile] save = false` disables lockfile generation.
- **Automatic migration** when no `bun.lock` exists: `yarn.lock` (v1 only), `package-lock.json` (lockfileVersion 2/3/4; npm 6's v1 is *not* migrated — warning, resolve from package.json), `pnpm-lock.yaml` (v7–9, incl. pnpm 11 multi-document; migrates `pnpm-workspace.yaml` packages/catalogs/overrides/patchedDependencies into package.json `workspaces`/`overrides`/`patchedDependencies`; named registries; injected workspaces; skips `runtime:` entries; limitations: workspace packages need `name`, relative `link:` and git sub-directory deps unsupported; no opt-out flag). Originals are preserved. `bun pm migrate` performs the conversion without installing.
- **Platform independence**: lockfile stores normalized `os`/`cpu` for every package, so it doesn't change across platforms.

---

## 3. Install semantics

Sources: https://bun.com/docs/pm/cli/install , https://bun.com/docs/pm/isolated-installs , https://bun.com/docs/pm/global-cache , https://bun.com/docs/pm/global-store , https://bun.com/docs/runtime/auto-install , https://bun.com/docs/runtime/bunfig

- **Hoisted vs isolated**: `--linker hoisted` = flat npm/yarn-style node_modules. `--linker isolated` (added v1.2.19, July 2025) = pnpm-style: central store `node_modules/.bun/<name>@<version>[_peer@ver]/node_modules/<name>/`, top-level symlinks, peer-dependency sets encoded in store dir names, dedup by package id + peer set, workspaces symlinked to source. `node_modules/.bun/node_modules` is a hoisted fallback layer (controls: `install.hoist = false` for strict, `install.hoistPattern`, `install.publicHoistPattern`; `.npmrc` `hoist`, `hoist-pattern`, `public-hoist-pattern`, `node-linker=isolated|hoisted|pnpm|node-modules`, `install-strategy=hoisted|linked`). **Default**: Bun 1.3.0 made isolated the default for all workspaces; **1.3.2 narrowed it**: `configVersion = 1` (new lockfiles) + workspaces → isolated; single-package projects and any pre-1.3.2 lockfile (`configVersion = 0`) → hoisted; pnpm migrations get configVersion 1, npm/yarn migrations get 0. Store path names are capped (63 bytes + hash) for Windows path limits. `bun prune` removes stale store entries.
- **Global virtual store** (`install.globalStore = true` or `BUN_INSTALL_GLOBAL_STORE=1`; isolated linker only; off by default; v1.3.14): materialize each `(package, version, resolved-dep-closure)` once under `~/.bun/install/cache/links/<name>@<ver>-<hash>/` and symlink `node_modules/.bun/<entry>` into it; warm installs ~7× faster (124.8 ms vs 823.9 ms hoisted on a 1,400-package fixture); patched, trusted (scripts may mutate), and workspace/file/link-dependent entries stay project-local.
- **Global cache**: `~/.bun/install/cache/` (override `BUN_INSTALL_CACHE_DIR`, `--cache-dir`, `[install.cache] dir`). Packages at `<name>@<version>` (pre/build tags replaced by a hash). Manifests cached as binary `~/.bun/install/cache/<hash(name)>.npm`. `bun pm cache rm` clears.
- **`--backend`**: `hardlink` default on Linux/Windows; `clonefile` (APFS copy-on-write) default on macOS; `clonefile_each_dir` (macOS, slower); `copyfile` fallback (`fcopyfile()`/`copy_file_range()`); `symlink` (mostly internal for `file:` deps; requires `--preserve-symlinks` in node/bun). Clone/hardlink fall back to copy on error. Self-contained workspaces (`installConfig.hoistingLimits: "workspaces"` or `workspaces.selfContained`) are materialized as real copies.
- **Install-skip logic**: if node_modules exists, Bun reads each package's `package.json` with a parser that stops at `name`/`version` and skips packages already correct; with an unchanged lockfile missing tarballs are fetched lazily; without lockfile tarballs are fetched eagerly during resolution.
- **Flags semantics**: `--production` (no devDeps + frozen lockfile; `bun add/remove/update` fail when `install.production = true`); `--omit dev|optional|peer` (applies to root and workspaces; transitive devDeps never installed anyway); `--dry-run`; `--ignore-scripts` (also skips the project's own scripts and trusted deps); `--no-save`; `--exact`; `--peer`/`--optional`/`--dev`; `--trust`; `--concurrent-scripts` (default 2× CPU/GOMAXPROCS); `--network-concurrency` (default 48); `--registry`; `--ca`/`--cafile`; `--verbose`; `--analyze` (bundler-driven import scan). Peer deps are installed automatically (Yarn-like); optional peers (`peerDependenciesMeta`) reuse an existing install if available.
- **Offline**: `--prefer-offline` / `install.prefer = "offline"` (use cache regardless of staleness); `--offline` / `install.offline = true` (no network at all); `--prefer-latest` / `install.prefer = "latest"` (always check registry).
- **Env overrides**: `BUN_CONFIG_REGISTRY`, `BUN_CONFIG_TOKEN`, `NPM_CONFIG_REGISTRY`, `NPM_CONFIG_TOKEN`, `BUN_CONFIG_YARN_LOCKFILE`, `BUN_CONFIG_SKIP_SAVE_LOCKFILE`, `BUN_CONFIG_SKIP_LOAD_LOCKFILE`, `BUN_CONFIG_SKIP_INSTALL_PACKAGES`, `BUN_INSTALL_CACHE_DIR`, `BUN_INSTALL_GLOBAL_DIR`, `BUN_INSTALL_BIN`, `BUN_INSTALL_GLOBAL_STORE`, `BUN_FEATURE_FLAG_DISABLE_NATIVE_DEPENDENCY_LINKER`, `BUN_FEATURE_FLAG_DISABLE_IGNORE_SCRIPTS`.
- **Auto-install (runtime feature)**: when `bun file.ts` finds no `node_modules` anywhere up the tree, Bun switches to "Bun-style resolution" and installs imports on the fly into the global cache (same cache as `bun install`). Version: `bun.lock` → nearest package.json range → `latest` (re-checked if `latest` cached >24h ago). Inline specifiers `import x from "zod@3.0.0"`. Controlled by `install.auto = "auto"|"force"|"disable"|"fallback"` and runtime flags `--no-install`, `--install=auto|fallback|force`, `-i`, `--prefer-offline`, `--prefer-latest`. Disabled automatically when a security scanner is configured. Limitations: no IDE types, no patch support.

---

## 4. Security model

Sources: https://bun.com/docs/pm/lifecycle , https://bun.com/docs/pm/cli/pm#untrusted , https://bun.com/docs/pm/cli/audit , https://bun.com/docs/pm/security-scanner-api , https://bun.com/blog/bun-v1.0.31 , https://bun.com/blog/bun-v1.3.5 , https://github.com/oven-sh/bun/blob/main/src/install/default-trusted-dependencies.txt

- **Lifecycle scripts blocked by default** for *installed dependencies* (`preinstall`, `install`, `postinstall`, `prepare`, etc.) — "default-secure", since Bun 1.0. The *root project's* own `{pre,post}install` and `{pre,post}prepare` always run (unless `--ignore-scripts`). `bun install` prints a note listing blocked packages.
- **`trustedDependencies`** (package.json array): names whose scripts may run. Semantics (precise, from docs): omitted → built-in default list applies (npm-registry packages only); `["a","b"]` → *only* those (the default list is **replaced, not extended** — re-add `esbuild`, `sharp` etc. if you need them); `[]` → nobody. Since v1.3.5 the default list applies only to packages resolved from the npm registry; `file:`/`link:`/`git:`/`github:` deps need explicit listing (prevents name spoofing). Since 1.4, trust matches the *resolved* package name, not the alias; names compared by full bytes. Transitive deps of a trusted package are not automatically trusted (`bun add --trust` adds the package *and* its transitive deps that have scripts). `bun pm ls --trusted` shows effective set.
- **Default-trusted list**: ~400 popular packages with native builds (esbuild, sharp, bcrypt, better-sqlite3, puppeteer, playwright-*, prisma, electron, cypress, node-gyp users, etc.). Full list: https://github.com/oven-sh/bun/blob/main/src/install/default-trusted-dependencies.txt ; print with `bun pm default-trusted`.
- **Postinstall optimizer** (v1.3.2): for packages that ship prebuilt binaries as per-platform optionalDependencies (default: `esbuild`, `@anthropic-ai/claude-code`), Bun links the right binary instead of running `postinstall`; `sharp >= 0.33` scripts are ignored by default. Configure via package.json `nativeDependencies: [...]` and `ignoreScripts: [...]` (the latter wins even over `trustedDependencies`); disable with `BUN_FEATURE_FLAG_DISABLE_NATIVE_DEPENDENCY_LINKER=1` / `BUN_FEATURE_FLAG_DISABLE_IGNORE_SCRIPTS=1` (source: https://github.com/oven-sh/bun/blob/main/src/install/postinstall_optimizer.zig , https://bun.com/blog/bun-v1.4#nativedependencies-and-ignorescripts).
- **`bun pm untrusted`** lists blocked packages and the exact scripts; **`bun pm trust <names> | --all`** runs them now and appends to `trustedDependencies`; **`bun add --trust <pkg>`** trusts on add. `--ignore-scripts` / `install.ignoreScripts = true` / `.npmrc ignore-scripts=true` disables everything. Scripts run in parallel (`--concurrent-scripts`), each with the root package.json's `npm_package_*` env (1.4.1 regression being fixed in PR #40717).
- **`bun audit`** (v1.2.15, May 2025): same bulk-advisory endpoint as npm; reads `bun.lock` only; severity/prod/ignore filters (v1.2.21); `--json`; exit code 1 on findings; **`bun audit fix`** (1.4) with `--latest`, `--dry-run`, `--json`.
- **Security Scanner API** (v1.2.21 / launched Bun 1.3 with Socket's `@socketsecurity/bun-security-scanner`): `[install.security] scanner = "<npm pkg or local path>"`; runs on install/add/update/remove/audit fix and `bun pm scan`; advisories at `fatal` (abort, non-zero exit) or `warn` (prompt in TTY, fail in CI); auto-install disabled when configured; authoring template https://github.com/oven-sh/security-scanner-template .
- **Minimum release age** (Bun 1.3): `--minimum-release-age <sec>` / `[install] minimumReleaseAge` + `minimumReleaseAgeExcludes`; filters direct and transitive resolution; existing lockfile entries untouched; "stability check" skips rapid-fire patch releases just outside the gate (searches up to 7 days past); exact versions still gated; missing `time` passes. ms-style strings (`"3d"`) accepted in 1.4.x (PR #30529); a 2-day default for new projects was proposed and closed. `bun audit fix` can install fixes newer than the gate and marks them.
- **Integrity**: SHA-512 for npm tarballs; GitHub/tarball deps hashed since v1.3.10; lockfileVersion 2 requires integrity for off-registry resolutions and validates git entries; `--no-verify` opts out. Registry credentials are host-scoped (never sent cross-origin or downgraded to http; not printed in verbose output) since 1.3.5. Tarball extraction hardening in v1.3.6. `bun pm diff` highlights new install scripts / dangerous imports in updates.
- **Token handling**: `NPM_CONFIG_TOKEN`, `BUN_CONFIG_TOKEN`, `.npmrc` `_authToken`/`_auth`/`username`+`_password`, bunfig `token`/`username`/`password` with `$ENV` expansion.

---

## 5. package.json features Bun honors

Sources: https://bun.com/docs/pm/workspaces , /pm/catalogs , /pm/overrides , /pm/cli/patch , /pm/cli/install , /pm/cli/add

- **`workspaces`**: array of globs or `{ packages: [...], catalog, catalogs, selfContained }`; full glob syntax incl. negations (`"!packages/**/test/**"`); each workspace needs its own package.json (and `name` for pnpm migration). `--filter` selects workspaces for install/add/remove/update/outdated/prune/licenses/run.
- **`workspace:` protocol**: `workspace:*`, `workspace:^`, `workspace:~`, `workspace:1.0.2`; rewritten on publish/pack to the real version. `install.linkWorkspacePackages = false` installs workspace deps from the registry instead (but `workspace:` is still linked).
- **`catalog` / `catalogs`** (v1.2.14): inside `workspaces` or top-level; referenced as `"catalog:"` / `"catalog:<name>"` (`catalog:default` ≡ `catalog:`); allowed in dependencies/devDependencies/optionalDependencies/peerDependencies and as override values; replaced with real ranges on publish/pack; `bun add --catalog[=name]`; `bun update`/`outdated`/`audit fix` operate on catalog entries; tracked in `bun.lock`.
- **`overrides` (npm) / `resolutions` (yarn)**: root-only; apply to peerDependencies too; values may be ranges, `npm:` aliases, `catalog:`, or `"$name"` (reuse own declared range); **nested** (`{"micromatch": {".": "^4", "picomatch": "^2.3.2"}}`, `"micromatch>picomatch"`, `"micromatch@^4>picomatch"`, yarn `"a/b"` and `"**/a/**/b"`) and **version-scoped** (`"semver@<7.5.2": "7.5.2"`) forms since 1.4 (one parent level only; pnpm `"pkg@"` and `"-"` unsupported; writes lockfileVersion 3).
- **`patchedDependencies`** + `bun patch` (v1.1.14): `{"name@version": "patches/name@version.patch"}`; patches applied on install, cached in the global cache under a patch-hash folder; `bun update` holds patched versions unless `--latest`/`audit fix`; `bun dedupe` never removes them.
- **`peerDependencies` / `peerDependenciesMeta`**: peers auto-installed; `optional: true` peers satisfied by whatever is already installed; an implicit `*` optional peer is synthesized for names only in `peerDependenciesMeta` (pnpm/yarn behavior).
- **`optionalDependencies`**, **`os` / `cpu`** (npm values; normalized and stored in lockfile; `--os/--cpu` override; `--omit optional`).
- **`bin` / `directories.bin`**: linked into `node_modules/.bin`; `bun pm pack` always includes bins even if not in `files`.
- **`trustedDependencies`**, **`nativeDependencies`**, **`ignoreScripts`** — see section 4.
- **`bundleDependencies`/`bundledDependencies`** (array or `true`) honored by pack/publish (v1.1.44).
- **`publishConfig`**: `access`, `tag`, `registry` honored by `bun publish`.
- **`config`**: exported as `npm_package_config_*` env vars in scripts.
- **`installConfig.hoistingLimits: "workspaces"`** (yarn key) / `workspaces.selfContained` — self-contained workspace with no hoisting above it (hoisted linker only).
- **`packageManager` field**: Bun does **not** enforce or auto-update it (Corepack has no Bun support); Bun tooling (`oven-sh/setup-bun` v2.1+) reads `packageManager`/`engines.bun` to pick a version; open feature requests: https://github.com/oven-sh/bun/issues/5846 (engines), https://github.com/oven-sh/bun/issues/23573 , https://github.com/oven-sh/bun/issues/23994 . `engines` is likewise informational only.
- **Specifiers**: `npm:` aliases (`"bun-types": "npm:@types/bun"`, `npm:@jsr/std__semver@1.0.5`), `github:user/repo[#ref]`, `git+https://`, `git+ssh://`, `git@github.com:org/repo.git`, tarball URLs (with optional basic-auth credentials), `file:` (symlink backend for out-of-project paths), `link:` (single symlink), `workspace:`, `catalog:`, dist-tags (`latest`, `next`).

---

## 6. `bun run` details

Sources: https://bun.com/docs/cli/run , https://bun.com/docs/runtime/bunfig#bun-run , https://bun.com/docs/pm/filter , https://bun.com/blog/bun-v1.3.9 , source https://github.com/oven-sh/bun/blob/main/src/runtime/cli/run_command.rs

- **Resolution order**: `bun run <x>`: (1) package.json script, (2) source file, (3) binary in `node_modules/.bin`, (4) system command (only with explicit `run`). Bare `bun <x>`: built-in commands win over scripts; a name with a source extension resolves to the file. Absolute/`./` paths are always files. `bun run` with no args lists scripts. `bun run -` reads a script from stdin.
- **Shell**: Linux/macOS use the first of `bash`, `sh`, `zsh` found; **Windows uses the Bun Shell** (bash-like syntax). Override with `--shell=bun|system` or `[run] shell`. `bun run` rewrites `npm run`/`yarn [run]`/`pnpm run`/`npx`/`pnpx` invocations inside script text to `bun run`/`bun x` (source comment in run_command.rs).
- **pre/post hooks: YES** — `bun run build` runs `prebuild`, `build`, `postbuild`; if `pre` fails the main script is not run; extra CLI args go only to the main script (fixed v1.0.15); no `--ignore-scripts` for `bun run` yet (issue #25542).
- **Env vars set for scripts**: `npm_lifecycle_event`, `npm_lifecycle_script`, `npm_command` (`run-script`/`publish`/`pack`), `npm_config_user_agent` (`bun/<ver> npm/? node/v<reported> <os> <arch>`), `npm_execpath`, `npm_package_name`, `npm_package_version`, `npm_package_json`, `npm_config_local_prefix`, `npm_package_config_*`; `node_modules/.bin` prepended to `PATH`; `.env` files auto-loaded (`--env-file`, `--no-env-file`).
- **`--bun` / `-b`**: prepend a `node`→`bun` symlink dir to PATH so scripts and `#!/usr/bin/env node` shebangs run under Bun (recursively); default on when no `node` is on PATH; `[run] bun = true`. Since 1.4, Bun invoked as `node` does *not* auto-load `.env`.
- **Flags**: `--silent` (don't echo command; `[run] silent`), `--if-present` (exit 0 if script/entry missing), `-F/--filter <pattern>` (run in matching workspaces, in dependency order, TUI-interleaved output; `--elide-lines` / `[run] elide-lines`), `--workspaces` (all workspaces), `--parallel` / `--sequential` / `--no-exit-on-error` (1.3.9; Foreman-style prefixed output; glob script names like `"build:*"`; pre/post grouped; no dependency ordering), `--shell`, `-e/--eval`, `-p/--print`, `--watch`, `--hot`, `--no-clear-screen`, `--smol`, `--console-depth`, `--preload`, `--install`, `--no-install`, `-i`, `--prefer-offline`, `--prefer-latest`, `--cwd`, `-c/--config`, `--no-orphans` (1.4; `[run] noOrphans`). Bun flags must come *before* `run`; flags after the script name are passed through. `BUN_OPTIONS` env prepends args.
- **Shorthand**: `bun <script>` works unless it collides with a built-in; `bun run` beats same-named files.

---

## 7. `bunx` / `bun x` precisely

Sources: https://bun.com/docs/pm/bunx , source https://github.com/oven-sh/bun/blob/main/src/runtime/cli/bunx_command.rs , https://github.com/oven-sh/bun/pull/8921 , https://github.com/oven-sh/bun/issues/4989 , https://github.com/oven-sh/bun/issues/12245

- **Resolution**: (1) look for a matching `bin` in the enclosing project's package.json / `node_modules/.bin` (locally installed packages run with no network — "~100× faster than npx" claim); (2) otherwise install into a per-user bunx cache and run the bin. Bin name defaults to the package name; `-p/--package <pkg>` when the bin name differs (`bunx -p @angular/cli ng`). `bunx pkg@version` / `pkg@tag` supported. Bin names containing `/` or `\` are rejected (hardening).
- **Cache location**: `<tmpdir>/bunx-<uid>-<package[@version]>/node_modules/.bin/<bin>` (e.g. `/tmp/bunx-1000-cowsay/`), installed via an internal `bun add` into that temp project; packages themselves come from the global cache `~/.bun/install/cache`. `bun pm cache rm` also clears bunx caches. Cached binaries created by another uid are refused (re-install instead).
- **TTL**: `SECONDS_CACHE_VALID = 60*60*24` (1 day) — a cached bunx install whose `package.json`/bin mtime is older than 24 h is deleted and re-installed (checks registry for newer `latest`). Any dist-tag spec (`pkg@latest`, `pkg@next`) **always bypasses the cache** (`bun add pkg@tag --no-cache --force`). A pinned `pkg@1.2.3` is cached indefinitely. Known complaint: no per-package `--no-cache`; issue #12245 open.
- **Flags**: `--bun` (run with Bun even if shebang says node; must precede the package name), `-p/--package`, `--no-install` (fail if not already installed), `--verbose`, `--silent`. There is **no `bunx --shell`**; shell selection exists only for `bun run --shell=bun|system`. `bunx` is a symlink/alias of `bun x`; shebang `#!/usr/bin/env bun` forces Bun.
- **Trust/scripts**: the bunx-installed package's own lifecycle scripts follow the same trusted-deps rules (a `--trust` crash with global installs was fixed in 1.2.22).

---

## 8. `bun publish`, `bun pm pack`, `bun pm whoami`, auth, OTP, provenance

Source: https://bun.com/docs/pm/cli/publish , https://bun.com/blog/bun-v1.1.30 , https://bun.com/docs/pm/cli/pm#pack

- **`bun publish [dir|tarball.tgz]`** (v1.1.30): packs (same rules as `npm pack`: `files`, `.npmignore`/`.gitignore` in nested dirs, `bin`, `bundleDependencies`), strips `workspace:` and `catalog:` protocols (resolving versions), publishes to the registry from `.npmrc`/`bunfig.toml`/`--registry` (scoped registry for the package's scope wins). Runs `prepublishOnly/prepack/prepare/postpack/publish/postpublish` only when it packs itself (not with a tarball path). Flags: `--access public|restricted` (also `publishConfig.access`; unscoped are always public), `--tag <t>` (default `latest`; first version always also tagged latest; `publishConfig.tag`), `--dry-run`, `--tolerate-republish` (exit 0 if version exists), `--gzip-level 0-9`, `--auth-type web|legacy` (2FA: browser flow default, or CLI OTP prompt), `--otp <code>`, `--registry`, `--ca/--cafile`, `--ignore-scripts`, `--trust`, `--no-save`, `--frozen-lockfile`, `--yarn`, `--backend`, `--network-concurrency`, `--concurrent-scripts`, `--silent/--verbose/--no-progress/--no-summary`. Honors `NPM_CONFIG_TOKEN` env (GitHub Actions use).
- **Provenance / trusted publishing**: **not documented as shipped** on the current publish page. Tracking issue https://github.com/oven-sh/bun/issues/15601 ; PRs https://github.com/oven-sh/bun/pull/30522 (`--provenance`/`--no-provenance`/`--provenance-file`, Sigstore keyless via Fulcio/Rekor, `publishConfig.provenance`, `NPM_CONFIG_PROVENANCE`) and PR #29374 (OIDC trusted publishing) exist; OIDC issue https://github.com/oven-sh/bun/issues/22423 . Workaround in the wild: `bun pm pack` + `bunx npm publish --provenance`. Bun's own release workflow switched to npm trusted publishing via `npm publish` (PR #32049). A package-manager replacement should treat provenance/OIDC as "Bun lacks it today".
- **`bun pm pack`**: flags in section 1; prints shasum, integrity, sizes; `--quiet` for `$(...)`.
- **`bun pm whoami`**: prints npm username; requires credentials in `.npmrc` or `bunfig.toml` (`bunx npm login` to obtain — Bun has no `login` command).
- **Auth precedence** (https://bun.com/docs/pm/npmrc): `~/.npmrc` (or `$XDG_CONFIG_HOME/.npmrc`) → `./.npmrc` → bunfig (global then project) → `BUN_CONFIG_REGISTRY`/`NPM_CONFIG_REGISTRY`, `BUN_CONFIG_TOKEN`/`NPM_CONFIG_TOKEN` → CLI flags. `.npmrc` credentials are matched to registries by host+path even when the registry URL is set in bunfig.

---

## 9. `.npmrc` compatibility and full `bunfig.toml` `[install]` / `[run]` key list

**`.npmrc`** (added v1.1.18 for project file; `$HOME/.npmrc` v1.1.30; docs https://bun.com/docs/pm/npmrc). Honored keys: `registry`, `@scope:registry`, `//host/path/:_authToken`, `:username`, `:_password` (base64), `:_auth` (base64 user:pass), `:email`, `link-workspace-packages`, `save-exact`, `ignore-scripts`, `dry-run`, `cache` (dir or `false`), `ca`, `ca[]`, `cafile`, `omit`/`omit[]`, `include`, `install-strategy` (`hoisted`|`linked`), `node-linker` (`isolated`|`hoisted`|`pnpm`|`node-modules`), `public-hoist-pattern[]`, `hoist-pattern[]`, `hoist=false`. `${VAR}` and `${VAR?}` expansion (quoted values too, v1.3.5). Bun recommends migrating to bunfig. Not honored: npm-only keys such as `legacy-peer-deps`, `engine-strict`, `fund`, `audit`, `provenance`, `min-release-age` (use bunfig equivalents).

**`bunfig.toml`** (https://bun.com/docs/runtime/bunfig). Global file `$HOME/.bunfig.toml` or `$XDG_CONFIG_HOME/.bunfig.toml` is read only by package-manager commands; local overrides global; CLI flags override both.

`[install]`: `optional` (true), `dev` (true), `peer` (true), `production` (false), `exact` (false), `ignoreScripts` (false), `concurrentScripts` (2× CPU), `saveTextLockfile` (true since 1.2), `auto` (`"auto"|"force"|"disable"|"fallback"`), `prefer` (`"online"|"offline"|"latest"`), `offline` (false), `frozenLockfile` (false), `dryRun` (false), `globalDir` (`~/.bun/install/global`; env `BUN_INSTALL_GLOBAL_DIR`), `globalBinDir` (`~/.bun/bin`; env `BUN_INSTALL_BIN`), `registry` (string, `{ url, token }`, or `https://user:pass@host`), `linkWorkspacePackages` (true), `ca`, `cafile`, `linker` (`"hoisted"|"isolated"`), `globalStore` (false), `publicHoistPattern` ([]), `hoistPattern` (["*"]), `hoist` (true), `logLevel` (`debug|warn|error`), `minimumReleaseAge` (seconds or `"3d"`; null), `minimumReleaseAgeExcludes` ([]).
`[install.scopes]`: `"@myorg" = "https://user:pass@…"` or `{ url, username, password = "$ENV" }` or `{ url, token = "$ENV" }`.
`[install.cache]`: `dir` (`~/.bun/install/cache`), `disable` (false), `disableManifest` (false — always resolve latest from registry).
`[install.lockfile]`: `save` (true), `print = "yarn"` (only value).
`[install.security]`: `scanner = "<pkg>"`.
`[run]`: `shell` (`"bun"` default on Windows, `"system"` elsewhere), `bun` (alias node→bun; default true only if node absent), `silent`, `elide-lines` (10), `noOrphans`. Only the *project* bunfig is read for `bun run`.
(Other bunfig sections — top-level `preload`, `jsx*`, `smol`, `logLevel`, `define`, `loader`, `telemetry`, `env`, `console.depth`, `[serve]`, `[test]` — are runtime/test-runner config, out of PM scope.)

---

## 10. Performance claims, techniques, public benchmarks

Sources: https://bun.com/package-manager , https://bun.com/blog/bun-v1.4#bun-install , https://bun.com/blog/behind-the-scenes-of-bun-install , https://bun.com/blog/bun-lock-text-lockfile , https://bun.com/docs/pm/global-store , https://bun.com/docs/pm/cli/install#npm-registry-metadata

**Techniques (as stated by Bun):**
- Implementation language: originally **Zig** (and C++ for JSC bindings); **Bun 1.4 (Aug 2026) is a Rust rewrite** — docs still cite "written in Zig/Rust" depending on page; the install crate is `bun_install` (Rust). Structure-of-arrays data layout with index-based references instead of pointer graphs; small-string optimization (8-byte inline `semver.String`); careful syscall selection (`clonefile`, `sendfile`, `faccessat`, `memfd_create`, `O_TMPFILE`+`linkat`/`renameat` for atomic cache writes).
- **Binary manifest cache**: packuments parsed once into binary `.npm` files in `~/.bun/install/cache/`, loaded without JSON parsing; **ETag `If-None-Match` / `If-Modified-Since` revalidation** with 304 reuse; entries considered fresh for ~5 minutes (Bun ignores the `Age` header, "may be about 5 minutes behind"); abbreviated manifest `Accept: application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*` (extended manifest `application/json` when `time` data needed for minimumReleaseAge).
- **Parallel resolution + download**: thread pool, async HTTP with `--network-concurrency` default 48; tarballs fetched eagerly during resolution when the lockfile is missing/changed, lazily otherwise; lifecycle scripts run in parallel (2× CPU).
- **Global cache + hardlink/clonefile materialization** instead of copying; `node_modules` package verification via a `name`/`version`-only JSON parser; isolated-linker global virtual store (one `symlink()` per package on warm path; 95% of warm-install time was `clonefileat` before).
- Text lockfile made cached installs 30% faster than binary (45.8 ms vs 60.4 ms no-op install) because the binary lockfile "was never the reason it was fast".

**Public numbers (Bun's own, Linux x64 EPYC 9R14, T3-stack Next.js app, 25 direct deps, ~220 packages, medians of 3, bench/install in oven-sh/bun):**

| Scenario | bun 1.4 | npm 12.0.2 | pnpm 11.21.0 | yarn 1.22.22 |
|---|---|---|---|---|
| First install (no cache/lockfile/node_modules) | 1.41 s (376 MB) | 18.1 s | 13.5 s (1.8 GB) | 20.5 s |
| Fresh checkout, warm cache, no lockfile | 251 ms | 7.61 s | 2.38 s | 1.83 s |
| CI without cache (lockfile committed) | 951 ms | 4.92 s | 11.7 s | 17.6 s |
| CI with warm cache, node_modules rebuilt | 210 ms (12 MB) | 4.45 s | 1.92 s (1.4 GB) | 1.76 s |
| node_modules present, cache gone | 12 ms | 384 ms | 399 ms | 212 ms |
| No-op reinstall | 12 ms | 337 ms | 400 ms | 211 ms |

Other claims: "up to 25×/30× faster than npm"; Remix monorepo install ~500 ms (28× npm, 12× yarn v1, 8× pnpm) (https://bun.com/docs/pm/workspaces); Dec-2024 hyperfine run: cold install 1.59 s vs yarn 6.37 s, npm 8.31 s, pnpm 11.30 s; cached 45.8 ms vs yarn 243 ms, pnpm 710 ms, npm 1.53 s; global store warm installs 6.7× faster, real-world cold→warm cal.com 37.4 s → 4.7 s, remix 23.1 s → 2.0 s (macOS arm64). `bunx` "roughly 100× faster than npx for locally installed packages"; `bun run` startup 6 ms vs `npm run` ~170 ms. Third-party corroboration (Appwrite, 2026-08): Bun 1.4 builds vs Node 26 + npm on a 640-package Next.js app (https://appwrite.io/blog/post/announcing-bun-1-4-runtime).

---

## 11. Package manager vs. the rest of Bun (what a PM-only replacement can declare out of scope)

**Package manager surface (in scope)** — everything in sections 1–10: `bun install/add/remove/update/outdated/audit/why/info/link/patch/publish/dedupe/prune/ci`, `bun pm *`, `bunx`, lockfile, cache, linkers, workspaces/catalogs/overrides/patches, trusted deps, scanner API, minimum release age, `.npmrc`/bunfig `[install]`, `bun run <script>` script execution semantics (pre/post, env vars, `--filter/--parallel`), `bun init`/`bun create` scaffolding. Bun markets `bun install` as "a standalone tool you can use with Node.js" — it works in any `package.json` project with no Bun runtime involvement.

**Runtime (out of scope)** — `bun <file>.ts`, on-the-fly TypeScript/JSX transpiling, JavaScriptCore engine, Node.js-compat layer (`node:*` modules, N-API, Node 26 API level in 1.4), `Bun.serve` (HTTP/1–3, WebSockets, routes, static files, fullstack dev server/HMR), `Bun.sql`/`bun:sqlite`/MySQL/Redis/S3 clients, `Bun.file`, `Bun.spawn`, `Bun.$` shell, `Bun.Image/WebView/markdown/cron/Terminal/Archive/YAML/TOML/JSON5/XML`, FFI/C compiler, `--watch`/`--hot`, debugger, REPL, auto-install-on-import, `--bun` node shim, `.env` loading, `bun run -e/-p`, `[serve]`/top-level bunfig keys, `bun upgrade`, `bun repl`.
**Bundler (out of scope)** — `bun build` (incl. `--compile` single-file executables, bytecode, HTML/CSS bundling, macros, plugins, minifier, metafile), `[bundler]`-related bunfig/plugins, `bun create` React-component mode (uses bundler), `bun install --analyze` *depends on the bundler* (mark as partial/out of scope).
**Test runner (out of scope)** — `bun test` and `[test]` bunfig section.
**Shell (partially in scope)** — Bun Shell is a runtime API (`Bun.$`) but `bun run` uses it as the script shell on Windows (`--shell=bun`); a PM replacement must pick its own cross-platform script shell story.
**Templating** — `bun init`/`bun create` are PM-adjacent CLI; `bun create ./Component.tsx` needs the bundler.

---

## 12. pnpm features worth matching + npm/pnpm/yarn 2026 supply-chain features

Sources: https://pnpm.io/settings , https://pnpm.io/settings/build , https://pnpm.io/settings/dependency-resolution , https://pnpm.io/settings/other , https://pnpm.io/supply-chain-security , https://pnpm.io/cli/audit , https://pnpm.io/cli/dlx , https://pnpm.io/cli/patch , https://pnpm.io/catalogs , https://pnpm.io/pnpmfile , https://pnpm.io/cli/deploy , https://pnpm.io/cli/licenses

**pnpm (v11/v12 era) features to match:**
- **Catalogs** (`catalog`/`catalogs` in pnpm-workspace.yaml; `catalog:`/`catalog:name`; `workspace:` ranges (v12.2) and `file:`/`link:` (v12.6) in catalogs; `catalogMode: manual|strict|prefer`; `catalogPrune`; `pnpx codemod pnpm/catalog`). Bun has catalogs but not `catalogMode`/`catalogPrune`.
- **`pnpm patch` / `patch-commit`** with `patchedDependencies` keyed by exact version, range, or name (priority exact > range > name), `allowUnusedPatches`; failures always error in v11. Bun: exact `name@version` keys only.
- **`pnx` / `pnpm dlx` / `pnpx`**: `--package` (multiple), `--allow-build`, `-c/--shell-mode`, `--silent`, `dlxCacheMaxAge`, `catalog:` specs, provisioning real package managers/runtimes (`pnx node@22`, v12); honors minimumReleaseAge/trustPolicy since v11.
- **`overrides`** (pnpm-workspace.yaml; `pkg@<range>` selectors, `parent>child`, `$name` references, `-` to remove, `pkg@` empty), `packageExtensions`, `allowedDeprecatedVersions`, `peerDependencyRules`, `supportedArchitectures`, `ignoredOptionalDependencies`.
- **Build-script policy (pnpm 10 → 11/12)**: default-deny of dependency install scripts (pnpm 10, 2025); `onlyBuiltDependencies`/`neverBuiltDependencies`/`ignoredBuiltDependencies` **replaced in v11 by `allowBuilds`** (map name/`name@range`/git-URL → true|false; auto-placeholders written to pnpm-workspace.yaml); `strictDepBuilds` (fail on unreviewed scripts, default true); `pnpm approve-builds`; `dangerouslyAllowAllBuilds`; `ignoreScripts`; `childConcurrency` (5); `unsafePerm`.
- **Supply-chain settings**: `minimumReleaseAge` (minutes; **default 1440 since v11**), `minimumReleaseAgeExclude` (names, globs, exact versions), `minimumReleaseAgeExcludePrune`, `minimumReleaseAgeIgnoreMissingTime`, `minimumReleaseAgeStrict`; `trustPolicy: no-downgrade` (fail if a release has weaker provenance/trusted-publisher evidence than an earlier one; v10.21), `trustPolicyExclude`, `trustPolicyIgnoreAfter`, `trustPolicyExcludePrune`, `trustLockfile`; `blockExoticSubdeps` (default true: transitive git/tarball deps blocked); named registries recorded in lockfile keys (v11.20) so a package can't be substituted from another registry.
- **`pnpm audit`**: bulk advisory endpoint, GHSA-based `audit.ignore`/`--ignore`, `--ignore-unfixable`, `--audit-level`, `--prod/--dev/--no-optional`, `--json`, `--fix` (adds overrides) and `--fix=update` (v11), `--interactive` (v11), `audit.ignorePrune` (v12), `--ignore-registry-errors`; **`pnpm audit signatures`** (v11.1) verifies ECDSA registry signatures against `/-/npm/v1/keys`.
- **`.pnpmfile.mjs/.cjs` hooks**: `readPackage`, `afterAllResolved`, `beforePacking` (v10.28), `updateConfig` (v10.8; used by `@pnpm/plugin-better-defaults`), `preResolution`, custom `resolvers`/`fetchers`; `configDependencies`. Bun has no hook mechanism (only the scanner API).
- **Side-effects cache** (`sideEffectsCache` with `read`/`write`/`remote` org tier) caches postinstall build output in the store so native builds run once per machine/org.
- **`verifyDepsBeforeRun`** (`install|warn|prompt|error|false`, default `install`) checks node_modules freshness before `pnpm run`/`exec`. Bun has nothing equivalent for `bun run`.
- **`shellEmulator`** (JS bash-like shell for cross-platform scripts; Bun's Windows answer is the Bun Shell), `scriptShell`, `enablePrePostScripts` (pnpm does **not** run pre/post by default; Bun does).
- **`pnpm deploy`** (self-contained workspace package with pruned lockfile; `--prod`, `--legacy`, `deployAllFiles`) — Bun's closest is `installConfig.hoistingLimits`/`selfContained` plus `bun prune --production`.
- **`pnpm licenses list`** (`--json`, `--long`, `--prod/--dev`, `--recursive`, named-registry attribution). Bun 1.4 has `bun pm licenses`.
- Also: `pnpm dedupe --check`, `pnpm prune`, `pnpm why`, `pnpm outdated`/`update -i -r`, injected workspace deps (`dependenciesMeta.*.injected`), global virtual store (`enableGlobalVirtualStore`), `optimisticRepeatInstall`, `resolutionMode: lowest-direct|time-based`, `packageConfigs` per-workspace settings (v11), `devEngines.packageManager`/`packageManager` self-pinning via lockfile, Node.js version management (`runtime:` entries, `pnpm env`), `pnpm stage publish`.

**npm (2025–2026):**
- **Trusted publishing (OIDC)** since npm CLI 11.5.1 / Node 22.14 (GitHub Actions, GitLab CI, CircleCI; up to 10 publishers per package; automatic provenance for public repos; `npm stage publish` staged-publishing flow with "allowed actions"; "disallow tokens" setting) — https://docs.npmjs.com/trusted-publishers .
- **Token hardening (Sep–Nov 2025)**: classic tokens revoked, granular write tokens default 7-day / max 90-day lifetime, TOTP 2FA setup disabled in favor of WebAuthn — https://github.blog/changelog/2025-09-29-strengthening-npm-security-important-changes-to-authentication-and-token-management/ . npm 12 also deprecates granular tokens that bypass 2FA (InfoQ, Aug 2026).
- **`npm audit signatures`**: verifies registry ECDSA signatures and provenance attestations; `--json --include-attestations` — https://docs.npmjs.com/cli/v11/commands/npm-audit .
- **Cooldown**: `min-release-age` (days; npm 11.10.0, Feb 2026, implemented as a relative `before`), `min-release-age-exclude` (later 11.x), audit-fix warns when blocked; `npm trust` command — https://docs.npmjs.com/cli/v11/using-npm/config/#min-release-age , https://github.com/npm/cli/pull/8965 .
- **npm 12.0.0 (2026-07-08)**: dependency `preinstall/install/postinstall` (and implicit `node-gyp rebuild`, `prepare` of git/file/link deps) **blocked by default** unless listed in package.json `allowScripts` (manage with `npm install-scripts ls|approve|...`, formerly `npm approve-scripts`/`deny-scripts`; `npm rebuild` afterwards; `allow-scripts` config for global/npx); `allow-git=none` and `allow-remote=none` defaults (git and https-tarball deps opt-in); root `preinstall` runs before deps; strict unknown-flag errors (`strict-npmrc` opt-in) — https://github.com/npm/cli/releases/tag/v12.0.0 , https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/ . Node's Release WG declined to bundle npm 12 into Node 22/24/26 (https://github.com/nodejs/Release/issues/1161).

**Yarn (Berry):** 4.10.0 (2025-09-18) added `npmMinimalAgeGate` (minutes or `"3d"`), `npmPreapprovedPackages` (exclusions by name, exact locator, or micromatch glob on descriptors), catalogs, and OIDC auth for GitHub Actions/GitLab — https://github.com/yarnpkg/berry/releases/tag/%40yarnpkg/cli/4.10.0 , https://github.com/yarnpkg/berry/pull/6901 . Yarn has long blocked nothing by default but supports `enableScripts: false` and per-package `dependenciesMeta.<pkg>.built: false`; `yarn npm audit` uses the bulk endpoint and reports deprecations.

**Cross-ecosystem convergence to note for a new PM**: (1) default-deny install scripts with a committed allow-list (pnpm 10, Bun since 1.0, npm 12, Deno); (2) release-age cooldown with exclusions (pnpm default 1 day, Bun opt-in, npm opt-in, Yarn opt-in); (3) OIDC trusted publishing + Sigstore provenance (npm, Yarn 4.10, pnpm `pnpm stage publish`; **Bun still missing**); (4) registry signature/provenance verification (`npm audit signatures`, `pnpm audit signatures`; Bun none); (5) blocking exotic transitive sources (pnpm `blockExoticSubdeps`, npm `allow-git/allow-remote`; Bun none); (6) trust-downgrade detection (pnpm `trustPolicy`); (7) semantic update diffs (`bun pm diff`).