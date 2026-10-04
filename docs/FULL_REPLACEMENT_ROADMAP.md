# Oath: roadmap to a full npm, npx, and Bun replacement

Prepared 2026-10-04 from a read of the current source (`v0.2.5` line, commit
`5d71c0a`) and from current public documentation for npm 11/12, npx, Bun 1.4,
pnpm 11, and Yarn 4. The three evidence reports behind this document are
checked in next to it:

- [`research/oath-cli-inventory.md`](research/oath-cli-inventory.md): what every
  `oath` subcommand actually does today, with `file:line` citations.
- [`research/npm-11-npx-surface.md`](research/npm-11-npx-surface.md): the full
  npm 11 and npx user-facing contract, plus what npm 12 changed.
- [`research/bun-pm-surface.md`](research/bun-pm-surface.md): the full Bun
  package-manager and `bunx` contract, plus pnpm/Yarn supply-chain features.

Everything in this document that describes Oath's current behavior was
verified against the source. Everything that describes npm or Bun cites those
reports. Estimates are planning targets for one to two engineers, not
commitments.

---

## 0. Executive summary

**Where Oath is.** The install core is real and unusually well-evidenced:
npm Arborist plans the tree, Oath fetches and integrity-verifies every tarball,
scans it, blocks dependency scripts by default, links `node_modules`
atomically from a BLAKE3 content store, and records signed, versioned
decisions. The `install`/`ci` path matches npm 11.12.1 on 100 reviewed
workflows, 250 pinned real projects, and 10,000 generated runs on three
operating systems, but only with `--ignore-scripts` and only for `install`
and `ci`. Exec has a native sandbox on Linux, macOS, and Windows that fails
closed. The registry, staging, signed contracts, and transparency log exist.

**Why it is not yet a replacement.** Measured against what a developer does
every day, Oath is missing or broken in ways that would make them leave:

| Area | Status today |
| --- | --- |
| npm commands | Of ~70 npm commands, Oath implements roughly 20. No `ls`, `outdated`, `audit` (advisory), `pack`, `version`, `link`, `login`, `whoami`, `view`, `dedupe`, `prune`, `rebuild`, `dist-tag`, `deprecate`, `cache`, `config`. |
| Install flags | No `--omit`/`--production`, `--save-exact`, `--save-peer`, `--no-save`, `--workspace`, `--registry`, `--prefix`, `--offline`, `--legacy-peer-deps` as a flag. `oath add` takes exactly one package. |
| Lockfile | Oath writes only `oath-lock.json`, never `package-lock.json`. Arborist does not read `oath-lock.json`, so frozen installs can fail on registry drift unless an npm lockfile is also present. |
| Scripts | Dependency scripts run unsandboxed, in random order, over every node on every install, without `PATH` or `npm_config_*`. All scripts run through `sh -c`, so Windows needs a POSIX shell. |
| Workspaces | Whole-root install only. The workspace path skips scanning (a stub), lifecycle scripts, and frozen checks. No `-w`, `--filter`, `--workspaces`. |
| Correctness | Scoped packages get bins in `node_modules/@scope/.bin`. `why` and `graph` cannot read the current lockfile key format. `package.json` keys are re-sorted on every write. `init` overwrites an existing `package.json`. `add github:u/r` writes a bogus dependency. |
| Config and auth | `.npmrc` supports four keys. No proxy, CA, `_auth`, username/password, scoped auth paths. The Arborist planner receives no registry or auth configuration at all, so private registries fail at planning. |
| Publish | Hardcoded to `registry.npmjs.org`, no OTP, no `publishConfig`, no `prepublishOnly`, requires host `npm` even for `--dry-run`. Provenance only via `npm stage`. |
| exec/npx | No `--package`, no `--call`, bins always run with `node`, a locally installed bin bypasses scanning, `--json` output is mixed with program output, temp dirs leak. |
| Runtime deps | `node` on `PATH` is required for every install and exec, and `npm` for publish. The README claims otherwise. |
| Speed | Cold install is 3.7x slower than npm and 6.6x slower than Bun; warm install is 2.9x slower than npm and 54x slower than Bun on the checked-in benchmark. |

**What "full replacement" means here.** Three tiers, in priority order:

1. **npm daily surface.** `install`, `ci`, `add`, `remove`, `update`, `run`,
   `test`/`start`, `exec`, `ls`, `outdated`, `audit`, `pack`, `publish`,
   `version`, `login`/`whoami`, workspaces flags, `.npmrc`, `package-lock.json`.
   Exit codes, tree shape, and lockfile must match npm 11; security
   divergences must be explicit and documented, as the compatibility contract
   already requires.
2. **npx and bunx.** Same resolution rules, same cache semantics, same flags,
   plus Oath's assessment and sandbox. This is the hero product and has the
   simplest contract.
3. **Bun package-manager surface.** `bun install/add/remove/update/outdated/
   audit/why/info/link/patch/publish/dedupe/prune`, `bun pm *`, `bun run`
   (`--filter`, `--parallel`), `bun.lock` import, `trustedDependencies`,
   catalogs, isolated linker, security scanner API. Bun's runtime, bundler,
   test runner, and shell are out of scope and must be stated as such.

**The market moved while Oath was being built.** npm 12 (July 2026) blocks
dependency install scripts by default behind an `allowScripts` allow-list,
defaults git and remote-tarball dependencies to off, adds `min-release-age`,
and ships trusted publishing. pnpm 11 defaults to a one-day cooldown and
`allowBuilds`. Bun 1.4 is a Rust rewrite with `audit fix`, `pm diff`, a
security-scanner plugin API, and an opt-in cooldown. "Blocks postinstall" is
no longer a differentiator. Oath's durable differentiators are: pre-execution
assessment with signed, agent-readable verdicts; a verified native sandbox for
`exec`; hash-bound approvals; evidence-gated claims; and a registry with
staging, revocation, and transparency. The roadmap below protects those while
closing the parity gap.

**Four strategic decisions this roadmap recommends.**

1. **Make `package-lock.json` v3 the canonical lockfile** that Oath reads and
   writes, and treat `oath-lock.json` as a derived evidence sidecar. This is
   what npm, Dependabot, Renovate, GitHub diff views, and Arborist itself
   understand, and it removes the current frozen-install drift problem.
2. **Keep Arborist as the planner through Phase 2, then replace it with a
   native Rust planner validated against Arborist as an oracle** using the
   differential harness that already exists. This is the only way to remove
   the `node` runtime requirement, close most of the speed gap, and stop
   re-extracting a 2.8 MB tarball on every command.
3. **Ship `oath x` (npx/bunx parity) before the rest of the npm surface.**
   It is the strongest security story, the simplest contract, and the piece
   that agents and `skill.md` files call.
4. **Extend the differential harness before adding features.** Today it covers
   `install`/`ci` with scripts off. Every phase below adds the harness slices
   first (scripts, `run`, `exec`, `.bin`, workspaces, flags, `npm ci` after
   `oath install`, and the reverse), so parity is proven rather than assumed.

---

## 1. Current state in detail

See [`research/oath-cli-inventory.md`](research/oath-cli-inventory.md) for the
full inventory. The items below are the ones that drive the plan.

### 1.1 What works and is evidenced

- Arborist dry-run planning with a vendored, hash-pinned npm 11.12.1 runtime
  (`crates/oath-resolve/src/placement.rs`), producing exact `node_modules`
  locations including nested conflicts, aliases, peers, overrides, bundled
  deps, and `os`/`cpu`/`libc` filtering.
- Integrity-verified tarball fetch with bounded unpack, retries, and
  resumable bodies (`crates/oath-fetch`).
- BLAKE3 content store with per-package manifests and a transactional linker
  with staged swap and rollback (`crates/oath-store`).
- Dependency scripts blocked by default with `trustedDependencies` and
  interactive approval that persists to `oath-policy.toml`.
- AST-based behavioral scanner with low false-positive rate and a published,
  honest threat model.
- `oath exec` with signed `ExecAssessment v3`, grade gates, `--min-age`,
  hash-bound `--remember` approvals, and native sandboxes on three OSes.
- Signed `PublishAssessment v2`, SPDX SBOM, transfer capsules, `npm stage`
  wrapper.
- PostgreSQL registry with staging, roles, OIDC identity, revocation, signed
  verdicts, transparency checkpoints, and a Kubernetes deployment contract.

### 1.2 Correctness bugs (fix before anything else)

| ID | Bug | Where |
| --- | --- | --- |
| B-01 | Bins for scoped packages are linked into `node_modules/@scope/.bin` instead of `node_modules/.bin`. The parity comparator excludes `.bin`, so CI never caught it. | `crates/oath-store/src/linker.rs:329-346` |
| B-02 | `why` and `graph` match lock keys as `name@version`, but Arborist-mode locks key by `node_modules/...` location. Both commands are effectively broken on every current lockfile. | `crates/oath-cli/src/main.rs:1844-1851`, `2200-2260` |
| B-03 | `package.json` is rewritten through `serde_json` without `preserve_order`, so every `add`/`remove` re-sorts keys alphabetically and drops the trailing newline. | `main.rs:899`, `4112`, `4139` |
| B-04 | `oath init` overwrites an existing `package.json` without checking. | `main.rs:1818` |
| B-05 | `oath install github:u/r`, `./dir`, or a URL writes a bogus key such as `"github:u/r": "latest"` into `package.json`. | `main.rs:608-612`, `2726-2741` |
| B-06 | Dependency install scripts iterate a `HashMap`, so they run in random order, for every node on every install, and may run inside the shared content store for nested copies. | `main.rs:937-966`, `graph.rs:12` |
| B-07 | A failed optional dependency download aborts the whole install; npm tolerates it. | `main.rs:2540-2541` |
| B-08 | Tarballs containing symlink or hardlink entries hard-fail; pacote skips them. | `crates/oath-fetch/src/tarball.rs:258` |
| B-09 | `exec` with a locally installed bin runs it without scanning and ignores the version spec. | `main.rs:3255-3266` |
| B-10 | `exec --json` prints the verdict and then still runs the program on the same stdout. | `main.rs:3610-3661` |
| B-11 | `exec` temp dirs leak because `process::exit` skips `TempDir` drop. | `main.rs:3765` |
| B-12 | `oath ci` in a workspace compares the merged workspace lock snapshot against root `package.json` only, so it fails whenever members declare deps the root does not. | `main.rs:1126-1131`, `1292-1299` |
| B-13 | `file:../sibling` outside the project root errors with "workspace link escapes project"; npm allows it. | `linker.rs:163-207` |
| B-14 | Linux native exec hardcodes `/usr/bin/node`, so nvm, Volta, fnm, and Homebrew-on-Linux users cannot use native mode. | `main.rs:3164`, `linux.rs:91-110` |
| B-15 | `oath remove` deletes `node_modules` entirely when the last dependency is removed. | `main.rs:4103-4111` |
| B-16 | Policy fields `banned_licenses`, `max_risk_level`, `require_approval`, and `block_install_scripts` are parsed but never read by the CLI. | `crates/oath-core/src/policy.rs:33-45` |
| B-17 | README says the binary does not need Node for baseline commands; every install and exec spawns `node`. | `README.md:369-370` |

### 1.3 Structural limits

- **Arborist dependency.** Every plan extracts the embedded npm tarball to a
  temp dir, spawns `node`, and lets pacote fetch metadata into `~/.npm`. This
  costs roughly a second per command, duplicates Oath's own packument cache,
  and makes `node` a hard runtime requirement.
- **Lockfile split-brain.** `oath-lock.json` is written but never consumed by
  the planner. `package-lock.json` is consumed implicitly by Arborist but never
  written. Frozen installs are therefore only stable when an npm lockfile
  happens to exist.
- **Re-hashing on every install.** `missing_store_nodes` BLAKE3-hashes every
  file of every stored package serially on each install.
- **No concurrency cap on downloads**, and extraction plus store writes run
  serially on the async thread.
- **Scripts via `sh -c` only**, with a relative `./node_modules/.bin` and a
  hardcoded `:` separator. Windows has no `cmd.exe` path and no `.cmd`/`.ps1`
  shims.
- **No HTTP/2**, no custom CA, no proxy configuration beyond reqwest defaults.
- **Dead code**: `DiskCache` in `oath-fetch/src/cache.rs` and
  `RegistryClient::search` are unreferenced.

---

## 2. Target definition

### 2.1 Tier A: npm daily surface (must match npm 11; track npm 12 defaults)

Commands: `install` and all its aliases, `ci`, `uninstall`/`rm`/`remove`,
`update`/`up`, `run` (+ `test`, `start`, `stop`, `restart`), `exec`/`x`,
`init` (+ `create-*`), `ls`/`list`, `explain`/`why`, `outdated`, `audit`
(advisory bulk endpoint, `audit fix`, `audit signatures`), `dedupe`,
`find-dupes`, `prune`, `rebuild`, `link`, `pack`, `publish`, `version`,
`view`/`info`, `search`, `login`, `logout`, `whoami`, `token`, `dist-tag`,
`deprecate`/`undeprecate`, `access`, `owner`, `ping`, `doctor`, `cache`,
`config`/`get`/`set`, `pkg`, `query`, `sbom`, `fund`, `diff`, `prefix`,
`root`, `bin`, `install-scripts`/`approve-scripts`, `trust`, `stage`.

Flags: every install flag in the npm report §2, workspace flags on every
workspace-aware command, the global flags (`--registry`, `--prefix`,
`--loglevel`, `--json`, `--dry-run`, `--force`, `--userconfig`).

Inputs: `package-lock.json` v1/v2/v3 and `npm-shrinkwrap.json`, the hidden
`node_modules/.package-lock.json`, `.npmrc` at all four levels with
`${VAR}`/`${VAR?}` substitution, `npm_config_*` env, every `package.json`
field in the npm report §2 including `overrides` (nested, `$ref`, `@range`),
`peerDependenciesMeta`, `bundleDependencies`, `os`/`cpu`/`libc`, `engines` +
`engine-strict`, `devEngines`, `directories.bin`, `publishConfig`, `config`,
`allowScripts`.

Specifiers: every `npm-package-arg` form including `#semver:` git ranges,
`#pull/N`, `gist:`, `git+file:`, SCP-style, local tarballs, remote tarballs,
directories with `--install-links`.

### 2.2 Tier B: npx and bunx

The exact libnpmexec algorithm (npm report §4): project `bin` match, walk-up
`node_modules/.bin`, global bin, then package spec; `--package` (repeatable),
`--call`, `--yes`/`--no`, prompt only on a TTY outside CI, cache keyed by the
sha512 of sorted specs under `<cache>/_npx/<hash>`, `getBinFromManifest` bin
selection rule, `prefer-online` revalidation, `npm init foo` to
`create-foo`, `cache npx ls|rm|info`. Plus bunx semantics: local-bin fast
path, 24-hour cache TTL, dist-tag specs bypass cache, `--no-install`,
`-p/--package`.

Oath additions that must survive: dry-run JSON assessment on a reserved
stdout, grade gates, min-age, hash-bound approvals, sandbox modes, and a
prompt that shows size, publisher, last-change, score, and requested
capabilities instead of "Ok to proceed? (y)".

### 2.3 Tier C: Bun package-manager surface

From the Bun report §1, §5, §6, §7: `bun.lock` and `bun.lockb` import,
`trustedDependencies` semantics (replace-not-extend, registry-only default
list, resolved-name matching), `nativeDependencies`/`ignoreScripts`,
`catalog`/`catalogs`, `patchedDependencies` + `patch`/`patch --commit`,
`--linker isolated` with the pnpm-style `.bun`-equivalent store,
`--filter`/`--workspaces`/`--parallel`/`--sequential` on `run`,
`--minimum-release-age`, `audit fix`, `pm diff`, `pm licenses`, `pm ls
--trusted`, `pm untrusted`/`trust`, `pm pack`, `pm version`, `pm pkg`,
`pm cache`, `pm migrate`, `--backend clonefile|hardlink|copyfile`,
`--network-concurrency`, `--concurrent-scripts`, `--lockfile-only`,
`--offline`/`--prefer-offline`, the Security Scanner plugin API, `bunfig.toml`
`[install]` keys, `BUN_CONFIG_*`/`NPM_CONFIG_*` env.

Out of scope, stated plainly in docs: Bun runtime, transpiler, `bun build`,
`bun test`, `Bun.*` APIs, `--bun` node shim, auto-install-on-import,
`bun install --analyze` (needs the bundler), Corepack.

### 2.4 Compatibility contract extension

The existing contract ("same exit status, lock snapshot, and materialized
tree, or a reviewed security divergence with a stable reason code") stays. It
must be widened to cover: lifecycle script execution and ordering, script
environment, `.bin` contents and shims, `run` output and exit codes, `exec`
resolution, workspace filtering, `package-lock.json` byte-equivalence after
normalization, and interop in both directions (`npm install` after `oath
install` and vice versa must be a no-op).

---

## 3. Gap matrix

Status: **OK** implemented and evidenced, **Partial** exists with gaps,
**Missing**, **Bug**. Work item IDs reference §5.

### 3.1 Install semantics

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| Hoisted placement with nested conflicts | yes | yes | OK (Arborist) | P-03 (native) |
| Isolated/linked layout | `--install-strategy=linked` | `--linker isolated` default for new workspaces | Missing | C-05 |
| devDependencies omit | `--omit=dev`, `NODE_ENV` | `--production`, `--omit` | Missing | I-01 |
| optional/peer omit, `--include` | yes | `--omit` | Missing | I-01 |
| Failed optional dep tolerated | yes | yes | Bug B-07 | I-02 |
| `--save-exact/-E`, `--save-peer`, `--save-optional`, `--no-save`, `--save-prefix` | yes | `-E`, `--peer`, `--optional`, `--no-save` | Missing | I-03 |
| `add` multiple packages | yes | yes | Bug (one only) | I-03 |
| `--legacy-peer-deps`, `--strict-peer-deps` flags | yes | n/a | `.npmrc` only | I-04 |
| Peer warnings surfaced | yes | yes | Missing (`invalid_edges` never read) | I-04 |
| `engines` + `engine-strict`, `devEngines` | yes | informational | Missing | I-05 |
| `--prefer-offline`, `--offline`, `--prefer-online` | yes | 1.4.1 | Missing | I-06 |
| `--package-lock-only` / `--lockfile-only` | yes | yes | Missing | L-03 |
| `--dry-run` | yes | yes | Partial | I-01 |
| `--force` | yes | yes | Missing | I-01 |
| `--registry`, `--prefix`, `--userconfig`, `--loglevel`, `--json` globals | yes | `--registry`, `--cwd` | Missing | C-01 |
| `--cpu/--os/--libc` overrides | yes | `--cpu/--os` | Missing | I-07 |
| `--min-release-age` / `--minimum-release-age` on install | 11.10 | 1.3 | `--min-age` on single-package path only | S-02 |
| `--before` | yes | no | Missing | I-07 |
| `--install-links` | yes | n/a | Missing | I-08 |
| `--bin-links`, `--no-bin-links` | yes | n/a | Missing | I-08 |
| `--foreground-scripts` | yes | n/a | n/a (scripts are foreground) | R-01 |
| `-g` global install with bins | yes | yes | Partial (no shims, no `remove -g`, no listing) | G-01 |
| Interrupted-install recovery | yes | yes | OK | — |
| Hidden lockfile `node_modules/.package-lock.json` | yes | n/a | Missing | L-02 |
| `--network-concurrency`, `--concurrent-scripts` | `maxsockets` | yes | Missing (unbounded) | P-01 |
| `--backend clonefile/hardlink/copyfile` | n/a | yes | hardlink + copy fallback only | P-02 |

### 3.2 Specifiers and package.json fields

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| `npm:` alias | yes | yes | OK | — |
| git with `#commit`/`#tag`/`#branch` | yes | yes | Partial (non-GitHub needs `--branch`, so SHA refs fail) | I-09 |
| git `#semver:range` | yes | yes | Rejected by design | I-09 (implement exact-tag range) |
| git `prepare` on install | yes | yes | Missing | I-09 |
| `#pull/N`, `gist:`, `git+file:`, SCP form | yes | partial | Missing | I-09 |
| `file:` directory inside project | symlink | symlink | OK | — |
| `file:` directory outside project | symlink | symlink | Bug B-13 | I-08 |
| local tarball `file:x.tgz` | yes | yes | OK | — |
| remote tarball URL | yes | yes | Partial (no integrity verification) | S-05 |
| `workspace:` | no (EUNSUPPORTEDPROTOCOL) | yes | parsed, not planned | W-01 |
| `catalog:` | no | yes | Missing | C-02 |
| `patch:` / `patchedDependencies` | npm 12 `npm patch` | yes | Missing | C-03 |
| `overrides` incl. nested, `$ref`, `pkg@range` | yes | yes (1.4) | via Arborist only | P-03 |
| `resolutions` (yarn) | no | yes | Missing | C-04 |
| `bundleDependencies` | yes | yes | OK | — |
| `directories.bin` | yes | yes | Missing ("skip for now") | I-08 |
| `allowScripts` (npm 11.16+/12) | yes | n/a | Missing | S-01 |
| `trustedDependencies` | n/a | yes | Partial (names only; no replace/registry-only/resolved-name semantics) | S-01 |
| `nativeDependencies`, `ignoreScripts` (Bun 1.3.2) | n/a | yes | Missing | S-01 |
| `packageManager` / `devEngines.packageManager` | devEngines only | reads for tooling | Missing | D-04 |
| `config` → `npm_package_config_*` | yes | yes | Missing | R-01 |

### 3.3 Lockfiles

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| Read `package-lock.json` v2/v3 | yes | migrates | Arborist implicit; Rust importer legacy-only | L-01 |
| Read v1 | converts | warns | rejected | L-01 |
| Write `package-lock.json` v3 | yes | no | Missing | L-01 |
| Read `npm-shrinkwrap.json` | yes | no | Missing | L-01 |
| Import `yarn.lock` v1 | hints only | yes | Missing | L-04 |
| Import `pnpm-lock.yaml` v7–9 (+ workspace yaml) | no | yes (1.2.23) | Missing | L-04 |
| Import `bun.lock` / `bun.lockb` | no | native | Missing | L-04 |
| Own lockfile consumed by planner | yes | yes | No (`oath-lock.json` ignored by Arborist) | L-01 |
| `--frozen-lockfile` stable without network drift | yes | yes | Only with an npm lock present | L-01 |
| Lockfile records registry host per package | `resolved` | 1.4 named registries | location keys only | L-01 |
| Platform-independent lock (`os`/`cpu` recorded) | yes | yes | n/a | L-01 |

### 3.4 Lifecycle scripts and `run`

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| Root `preinstall/install/postinstall/prepare` | yes | yes | Partial (plain `install` only; failure only warns) | R-01 |
| `prepublishOnly/prepack/prepare/postpack/publish/postpublish` | yes | yes | Missing | A-03 |
| `preversion/version/postversion` | yes | yes | Missing | A-04 |
| `predependencies/dependencies/postdependencies` | yes | no | Missing | R-01 |
| Dependency scripts in dependency order, once per change | yes | yes (parallel) | Bug B-06 | R-02 |
| Dependency scripts sandboxed | no | no | Missing (Oath's differentiator) | S-03 |
| Default `node-gyp rebuild` when `binding.gyp` present | yes | yes | Missing | R-02 |
| Script env: `npm_package_*` flattened, `npm_config_*`, `npm_execpath`, `npm_node_execpath`, `INIT_CWD`, `npm_command`, `npm_package_json`, `NODE_ENV` | yes | subset | Missing (only lifecycle_event/script and top-level scalars) | R-01 |
| `PATH` with every ancestor `.bin` plus `node-gyp-bin` | yes | yes | relative `./node_modules/.bin` only | R-01 |
| `cmd.exe`/`ComSpec` on Windows, `script-shell` | yes | Bun shell | `sh -c` only | R-03 |
| `--if-present`, `--silent`, `--ignore-scripts` on run | yes | yes | Missing | R-01 |
| `oath run x --flag` without `--` | yes | yes | Likely rejected by clap | R-01 |
| `test`/`start`/`stop`/`restart` shortcuts | yes | n/a | Missing | R-01 |
| `run --workspaces`/`-w`/`--filter`/`--parallel` | `-w`, `--ws` | `--filter`, `--parallel` | Missing | W-02 |
| `.env` auto-load | no | yes | n/a (document) | — |

### 3.5 `exec` / npx / bunx

| Capability | npx | bunx | Oath | Work item |
| --- | --- | --- | --- | --- |
| `--package`/`-p` (repeatable), `--call`/`-c` | yes | `-p` | Missing | X-01 |
| libnpmexec resolution order (project bin, walk-up `.bin`, global bin, spec) | yes | similar | Partial (cwd `.bin` by package name only, unscanned) | X-01 |
| Bin selection rule (`getBinFromManifest`) | yes | yes | Different (first alphabetical fallback) | X-01 |
| Non-JS bins, shebang parsing | yes | yes | Missing (always `node <bin>`) | X-01 |
| Cache keyed by spec hash under npm cache | yes | tmpdir per pkg, 24h TTL | temp dir per run | X-02 |
| `cache npx ls|rm|info` | 11.2 | `pm cache rm` | Missing | X-02 |
| Prompt only on TTY and not in CI; `--yes/--no` | yes | n/a | Different (prompts only on High/Critical) | X-03 |
| Rich prompt (size, publisher, score, capabilities) | no | no | Partial (findings only) | X-03 |
| `npm init foo` → `create-foo` | yes | `bun create` | Missing | X-04 |
| git/dir/tarball specs for exec | yes | yes | Missing (registry only) | X-01 |
| Reserved stdout for `--json` | n/a | n/a | Bug B-10 | X-05 |
| Dependency scripts of the exec'd package | run | per trust rules | never run (breaks packages needing them) | X-06 |
| Native sandbox with any Node on PATH | n/a | n/a | Bug B-14 | X-07 |
| Agent mode defaults | n/a | n/a | OK | — |

### 3.6 Workspaces

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| Detect `package.json#workspaces` globs with negation | yes | yes | Partial | W-01 |
| `pnpm-workspace.yaml` | no | migration only | detected | W-01 |
| `-w/--workspace`, `--workspaces`, `--include-workspace-root` on install/run/exec/version/publish/ls/outdated/audit | yes | `--filter` | Missing | W-02 |
| Workspace install runs scan, scripts, frozen checks | yes | yes | Stub | W-01 |
| `oath ci` in a workspace | yes | yes | Bug B-12 | W-01 |
| Workspace `prepare` concurrency | yes | yes | Missing | W-01 |
| Catalogs | no | yes | Missing | C-02 |
| Topological `run --filter` | no | yes | Missing | W-02 |

### 3.7 Config, registry, auth

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| `.npmrc` four-level precedence + builtin | yes | user+project | user+project | C-01 |
| `${VAR}` and `${VAR?}` | yes | yes | `${VAR}` | C-01 |
| `npm_config_*` env overrides | yes | `NPM_CONFIG_*` subset | `npm_config_registry` only | C-01 |
| `//host/path/:_authToken`, `_auth`, `username`+`_password`, `email`, `certfile`/`keyfile` | yes | yes | token keyed by host only | C-01 |
| `proxy`, `https-proxy`, `noproxy` | yes | env | reqwest defaults | C-01 |
| `strict-ssl`, `ca`, `cafile` | yes | `--ca/--cafile` | Missing (rustls webpki only) | C-01 |
| Scoped registry routing for planner, metadata, score, info | yes | yes | Fetch only; planner, `info`, `score` hardcode npmjs | C-01 |
| `config get/set/list/edit/fix`, `--location` | yes | bunfig | Missing | C-01 |
| `bunfig.toml [install]` keys | n/a | yes | Missing | C-06 |
| `login` (web auth, legacy, OTP), `logout`, `whoami`, `token create/list/revoke` | yes | `pm whoami` only | Missing | A-01 |
| `ping`, `doctor` | yes | no | Missing | Q-05 |

### 3.8 Publish and registry operations

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| `pack` (`--dry-run`, `--json`, `--pack-destination`, reproducible tarball) | yes | `pm pack` | Internal only, non-reproducible | A-02 |
| `publish` to configured/scoped registry, `publishConfig` | yes | yes | Hardcoded npmjs | A-03 |
| OTP/2FA (`--otp`, web OTP flow) | yes | yes | Missing | A-03 |
| Prerelease requires `--tag`; no implicit `latest` below highest | 11.0 | n/a | Missing | A-03 |
| Provenance (`--provenance`, Sigstore) and OIDC trusted publishing | yes | not shipped | via `npm stage` only | A-05 |
| `version` with git commit/tag and hooks | yes | `pm version` | Missing | A-04 |
| `dist-tag`, `deprecate`/`undeprecate`, `unpublish`, `access`, `owner`, `team`, `org` | yes | no | Missing | A-06 |
| `trust`, `stage` | 11.10+/11.17+ | no | `stage` wrapper only | A-05 |
| Native `oath-registry` client paths (stage, approve, private verdicts) | n/a | n/a | Only via generic npm protocol | A-07 |

### 3.9 Inspection and maintenance

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| `ls`/`list` (`--all`, `--depth`, `--json`, `--parseable`, extraneous/missing/invalid) | yes | `pm ls` | Missing (`graph` partial and broken) | Q-01 |
| `explain`/`why` | yes | yes | Bug B-02 | Q-01 |
| `outdated` | yes | yes | Missing | Q-02 |
| `update` with `--save`, `--latest`, `-i` | yes | yes | Partial (no save, no latest, no scripts/scan) | Q-02 |
| `audit` against `/-/npm/v1/security/advisories/bulk`, `audit fix`, `--audit-level`, `--ignore` | yes | yes | `audit` is an alias of the behavioral scan | Q-03 |
| `audit signatures` (ECDSA + attestations) | yes | no | Missing | Q-03 |
| `dedupe`, `find-dupes`, `prune`, `rebuild` | yes | 1.4 | Missing | Q-04 |
| `view`/`info` with field selectors and `--json` | yes | yes | Partial | Q-05 |
| `search` | yes | no | Missing (client exists) | Q-05 |
| `query` selectors | yes | no | Missing | Q-06 |
| `sbom` for the project tree | yes | no | Only own package at publish | Q-06 |
| `licenses` for the project tree | no | 1.4 | Global store only | Q-04 |
| `cache ls/verify/clean` | yes | `pm cache` | Missing | Q-04 |
| `pm diff` semantic update diff | no | 1.4 | Missing | Q-07 |
| `scan`/`perms` scoped to the project tree | n/a | n/a | Global store only | Q-04 |
| `fund` | yes | no | Missing | Q-05 |

### 3.10 Security features (the differentiator surface)

| Capability | npm 12 | pnpm 11 | Bun 1.4 | Oath | Work item |
| --- | --- | --- | --- | --- | --- |
| Dependency scripts default-deny with committed allow-list | `allowScripts` | `allowBuilds` | `trustedDependencies` | prompt/`-y`/`trustedDependencies` | S-01 (read all three) |
| Release-age cooldown with excludes, on install and exec | `min-release-age` | default 1 day | opt-in | exec and single-package only | S-02 |
| Sandboxed dependency scripts | no | no | no | Missing | S-03 |
| Block exotic transitive sources (`allow-git/remote`, `blockExoticSubdeps`) | yes | yes | no | Missing | S-04 |
| Integrity for git/tarball deps | sha512 | sha512 | 1.3.10 | not verified | S-05 |
| Trust-downgrade detection (`trustPolicy: no-downgrade`) | no | yes | no | Missing | S-06 |
| Registry signature + attestation verification | `audit signatures` | yes | no | Missing | Q-03 |
| Security scanner plugin API | no | hooks | yes | Missing (Oath is the scanner; expose it) | S-07 |
| Manifest-confusion check (tarball vs registry) | no | no | no | Missing | S-08 |
| Signed decision contracts for agents | no | no | no | OK | — |
| Native sandbox for exec | no | no | no | OK | — |
| Secret-scan on publish | no | no | no | OK | — |

### 3.11 Platform and distribution

| Capability | npm | Bun | Oath | Work item |
| --- | --- | --- | --- | --- |
| Runs without Node on PATH | n/a | yes | no | P-03 |
| Windows: `.cmd`/`.ps1`/sh shims, `cmd.exe` scripts, junctions without Developer Mode | yes | yes | symlinks + `sh` | D-01 |
| Signed/notarized binaries | n/a | yes | Missing | D-02 |
| Distribution channels (installer, Homebrew, npm package `oath`, winget, scoop, GitHub Action) | n/a | all | installer + Homebrew | D-03 |
| Self-update (`bun upgrade`) | n/a | yes | Missing | D-03 |
| Shell completions | yes | yes | Missing | D-03 |
| `packageManager`-style version pinning | Corepack (removed in Node 25) | setup-bun | Missing | D-04 |

---

## 4. Performance plan

Checked-in benchmark (darwin-arm64, 84 packages, scanner on, scripts off):

| Installer | Cold | Warm |
| --- | ---: | ---: |
| npm 11.12.1 | 728 ms | 428 ms |
| Bun 1.2.20 | 406 ms | 23 ms |
| Oath 0.2.x | 2,683 ms | 1,243 ms |

Oath's own breakdown on the cold run: download 0.8 s, link 0.4 s, which
leaves about 1.3 s for Arborist planning plus scanning 84 packages. On the
warm run, link is 0.3 s of 1.2 s, leaving about 0.9 s for planning plus
store re-verification.

Targets already set in `RELEASE_COMPLETE_PLAN.md`: warm install no slower
than npm at p95, cold install at most 20% slower than npm with scanning,
cached assessment under 100 ms p95. Bun-class warm installs (tens of
milliseconds) require the no-op fast path and a global virtual store; they
are a stretch goal, not a gate.

Ordered by expected payoff per effort:

| ID | Change | Expected effect |
| --- | --- | --- |
| P-00 | **No-op and frozen fast path.** When `package-lock.json` (or the hidden lockfile) matches `package.json` and `node_modules` is consistent, skip planning entirely: verify lock, diff against `node_modules/.package-lock.json`, link only the delta. This is how Bun gets 12 ms no-op installs. | Warm/no-op from ~1.2 s to under 100 ms. |
| P-01 | Bound download concurrency (default 48 like Bun, honor `maxsockets`), move extraction and store writes off the async thread into a rayon pool, stream-verify during download. | Cold download phase 2–3x faster on large trees. |
| P-02 | Stop re-hashing the whole store on every install. Trust the manifest when mtime/size match and `verify` is not requested; add `--verify-store`. Use `clonefile` on APFS, `copy_file_range`/reflink on btrfs/XFS, hardlink elsewhere. | Warm from ~0.9 s overhead to near zero. |
| P-03 | **Native Rust planner** (see §5 Phase 4): port Arborist's `build-ideal-tree`/`place-dep` with `package-lock.json` as the input and output, validated against Arborist through the differential harness on every fixture, every pinned project, and the 10,000 generated runs. Keep Arborist behind `OATH_RESOLVER=arborist` as the oracle and canary. | Removes ~1 s per command and the Node requirement. |
| P-04 | Packument cache as a binary, ETag-revalidated store (Bun's `.npm` files); HTTP/2 via reqwest `http2`; abbreviated packuments by default, full only when `time` is needed. | Cold resolution network time halved. |
| P-05 | Scan cache keyed by tarball integrity plus rule-bundle digest, so a package is scanned once per machine; parallelize scan with download instead of after link. | Cold overhead from scanning drops to new packages only, overlapped with I/O. |
| P-06 | Global virtual store for the isolated linker (Bun 1.3.14 `globalStore`): materialize each package once, symlink per project. | Warm installs 5–7x faster for isolated layouts. |
| P-07 | Startup: avoid extracting the 2.8 MB npm tarball per command (cache once per binary hash under `~/.oath/runtime/<sha256>/`) until P-03 lands. | Saves ~100–200 ms per command immediately. |

Every performance change lands with the benchmark script
(`scripts/benchmark-installers.mjs`) re-run on the declared hardware and the
JSON checked in, so the public claim stays honest.

---

## 5. Phased roadmap

Phases overlap. Each phase lists work items, the harness slices it must add,
and an exit gate. Effort is in engineer-weeks (ew) for one experienced Rust
engineer; halve the calendar time with two.

### Phase 0: truth and correctness (weeks 0–3, ~3 ew)

Goal: nothing Oath does silently corrupts a project, and the docs match the
binary.

- Fix B-01 through B-17. B-03 needs `serde_json` `preserve_order` (indexmap is
  already in the lock graph) and newline preservation. B-06 needs a
  topological order from the placement plan and a "changed nodes only" set.
- T-01: extend `scripts/tree-evidence.mjs` to include `.bin` contents and
  link targets, and add a `package.json` byte-stability check after
  `add`/`remove`.
- T-02: add an `npm install` after `oath install` (and reverse) no-op
  interop fixture.
- D-00: fix README/CLAUDE.md claims about Node, and document every known
  divergence in `NPM_COMPATIBILITY_CONTRACT.md`.

Exit gate: all fixtures pass with `.bin` included; `why`/`graph` work on a
current lock; `package.json` round-trips byte-for-byte.

### Phase 1: `oath x` as a complete npx and bunx replacement (weeks 2–8, ~6 ew)

Goal: anyone can alias `npx=oath x` and `bunx=oath x` and nothing breaks,
while getting assessment and sandboxing.

- X-01: libnpmexec resolution algorithm, `--package` (repeatable), `--call`,
  `getBinFromManifest` bin rule, shebang parsing for non-JS bins, git/dir/
  tarball specs, scoped bins, walk-up `.bin` and global bin lookups that still
  pass through assessment (hash the local bin's package and look up or compute
  its verdict).
- X-02: persistent exec cache under `<cache>/_npx/<sha512-prefix>` with
  npm-compatible layout, 24-hour TTL for tag specs like bunx, `oath cache npx
  ls|rm|info`, `--no-install`, `--prefer-offline`.
- X-03: npm's prompt rule (TTY and not CI) with Oath's rich prompt: name,
  exact version and integrity, publish date and age, publisher and last
  change, size, download count, score, requested capabilities, sandbox plan.
  `--yes` keeps its npm meaning; agent mode remains noninteractive.
- X-04: `oath init <name>` → `create-<name>` and `@scope` → `@scope/create`.
- X-05: `--json` reserves stdout (program output to stderr or `--json
  --dry-run` only, plus a `--json-file`).
- X-06: run the exec'd package's own install scripts under the same trust
  rules as install, inside the sandbox when native is available.
- X-07: resolve `node` from `PATH` and bind-mount its real location into the
  Linux sandbox; grant it by canonical path on macOS (already done there).
- S-02: `--min-release-age` with excludes on exec, default from config, and
  `min-release-age` from `.npmrc`.
- T-03: an exec parity fixture set (npx vs `oath x` for 25 common CLIs:
  `create-next-app`, `tsc`, `prettier`, `eslint`, `vite`, `cowsay`, scoped
  bins, `-p` cases, `-c` cases, local-bin cases) comparing exit code and
  stdout after normalization.

Exit gate: 25/25 exec fixtures match on Linux, macOS, Windows; `oath x` cold
within 10% of npx and warm within 10% of bunx on the benchmark machine.

### Phase 2: npm daily install parity (weeks 4–14, ~10 ew)

Goal: `alias npm=oath` works for install, ci, add, remove, update, run, and
workspaces on real projects.

- L-01: read and write `package-lock.json` v3 (and read v1/v2 and
  `npm-shrinkwrap.json`), feed it to the planner, make it the frozen-install
  source of truth, keep `oath-lock.json` as a derived evidence file (or fold
  its extra fields into a sidecar `.oath/evidence.json`). Honor
  `--lockfile-version`, `format-package-lock`, `omit-lockfile-registry-resolved`,
  `replace-registry-host`.
- L-02: write and consume the hidden `node_modules/.package-lock.json`.
- L-03: `--package-lock-only` / `--lockfile-only`.
- I-01 through I-08: every install flag in §3.1 and §3.2, `add` with many
  packages and save flags, `--omit`/`--include` with `NODE_ENV` semantics,
  `engines`/`devEngines` checks, offline modes, `--cpu/--os/--libc`,
  `--before`, `--install-links`, `directories.bin`, out-of-root `file:` links.
- I-09: git specifiers: SHA refs on any host, `#semver:` resolved against
  tags, `prepare` executed under script policy in a temp install, `#pull/N`,
  `gist:`, SCP form, `GIT_*` env passthrough.
- R-01: `run` with full npm script environment (`npm_package_*` flattening,
  `npm_config_*` non-default export with the same exclusions, `npm_execpath`,
  `npm_node_execpath`, `INIT_CWD`, `npm_command`, `NODE_ENV`), ancestor
  `.bin` PATH, `--if-present`, `--silent`, `--ignore-scripts`, trailing args
  without `--`, `test`/`start`/`stop`/`restart` shortcuts, `pre`/`post` for
  the root lifecycle, `dependencies` hooks, hard failure on nonzero.
- R-02: dependency scripts in topological order, only for changed nodes, in
  their real install location, with the `node-gyp rebuild` default, bounded
  parallelism (`--concurrent-scripts`), and `--foreground-scripts`.
- R-03: Windows `cmd.exe` (`ComSpec`) and `script-shell` config; `.cmd`,
  `.ps1`, and sh shims per `cmd-shim`; junctions without Developer Mode.
- W-01: workspace install runs the same scan, script policy, frozen checks,
  and transparency logging as single-package install; `ci` in a workspace;
  negated globs; `workspace:` ranges resolved locally; workspace `prepare`
  concurrency.
- W-02: `-w`, `--workspaces`, `--include-workspace-root` on every
  workspace-aware command; `--filter` with npm-style name/path matching;
  topological `run` across workspaces.
- C-01: full `.npmrc` (four levels, builtin, `${VAR?}`, all auth forms,
  nerf-dart longest match, proxy and `noproxy`, `strict-ssl`, `ca`/`cafile`,
  `certfile`/`keyfile`), `npm_config_*` env, `--registry`/`--prefix`/
  `--userconfig`/`--loglevel`/`--json` globals, `config get/set/list/edit/
  fix`, and crucially passing registry and auth config to the planner and to
  `info`/`score`/metadata fetches. Replace the hand parser with an ini parser
  that matches npm/ini.
- G-01: global installs with shims, `remove -g`, `ls -g`, `update -g`,
  `prefix`/`root`/`bin` commands, `npm`-compatible prefix layout option.
- S-01: unified script policy that reads npm `allowScripts`, Bun
  `trustedDependencies` (with replace-not-extend and registry-only-default
  semantics), pnpm `allowBuilds`, and `oath-policy.toml`; `oath
  install-scripts ls|approve|deny|prune` and `oath pm trust|untrusted`
  aliases; wire up `block_install_scripts`, `banned_licenses`,
  `max_risk_level`, `require_approval`.
- T-04: widen the harness to scripts-on fixtures (esbuild, sharp, prisma,
  better-sqlite3, node-gyp), `run` fixtures with env snapshots, workspace
  flag fixtures, flag matrix fixtures (`--omit`, `--save-*`, `--prefer-offline`),
  and `package-lock.json` equivalence after normalization.

Exit gate: 100-workflow matrix extended to at least 200 IDs including
scripts, `run`, workspaces, and flags, passing on three OSes; the 250 pinned
projects install with scripts enabled under default policy with zero tree
differences; `npm ci` after `oath install` is a no-op on every fixture.

### Phase 3: registry operations and inspection (weeks 10–20, ~9 ew)

Goal: publishing and maintenance workflows never need `npm` on the machine.

- A-01: `login` (web auth via `/-/v1/login` polling, legacy couch login,
  OTP, `--scope`), `logout`, `whoami`, `token create/list/revoke` with
  granular-token fields, session-token semantics, credential storage in the
  right `.npmrc`.
- A-02: native `pack` with npm-packlist rules in Rust (drop the `npm pack`
  dependency), reproducible tarballs (fixed mtime, mode, uid, sorted
  entries), `--pack-destination`, `--json`, `--dry-run`, `prepack`/`postpack`.
- A-03: `publish` to the configured or scoped registry with `publishConfig`,
  OTP and web-OTP flows, the npm 11 tag rules (prerelease requires `--tag`,
  no implicit `latest` below the highest version), `prepublishOnly`/`prepare`/
  `publish`/`postpublish`, README in the payload, `--access private` alias,
  `--workspaces`.
- A-04: `version` with `preversion`/`version`/`postversion`, git commit and
  tag, `--preid`, `--no-git-tag-version`, `from-git`, signing options,
  `--workspaces-update`.
- A-05: Sigstore provenance (`--provenance`, `--provenance-file`) and OIDC
  trusted publishing (`NPM_ID_TOKEN`, Actions token minting, the
  `/-/npm/v1/oidc/token/exchange` endpoint) natively; `trust` and native
  `stage` without the host-npm requirement. Bun lacks this today; Oath should
  lead here because it already signs assessments.
- A-06: `dist-tag`, `deprecate`/`undeprecate`, `unpublish` with policy
  checks, `access`, `owner`, `team`, `org`, `ping`, `doctor`.
- A-07: first-class Oath registry client paths: stage, approve, reject,
  private verdicts, revocation state, transparency proofs, with
  `oath-registry` as a `publishConfig.registry` target and the install path
  consuming `RegistryVerdict v1` when the registry supplies one.
- Q-01: `ls`/`list` with the full flag set, `explain`/`why` rewritten on
  location keys, `--link`, extraneous/missing/invalid detection against the
  hidden lockfile.
- Q-02: `outdated` (Current/Wanted/Latest/Location/Depended by, `--long`,
  `--json`, `-g`, workspaces) and `update` with `--save`, `--latest`,
  `--interactive`, transitive updates, running scan and script policy.
- Q-03: `audit` against the bulk advisory endpoint with metavuln calculation
  (port `@npmcli/metavuln-calculator` semantics), `--audit-level`, `--ignore`
  GHSA ids, `--json` in `auditReportVersion: 2`, `audit fix` with
  `--force`/`--dry-run`/`--latest`, implicit audit on install with `audit=false`
  opt-out, and `audit signatures` with TUF keys fallback to `/-/npm/v1/keys`
  plus attestation verification. Rename today's behavioral scan to `oath
  scan` only and scope it to the project tree by default.
- Q-04: `dedupe`, `find-dupes`, `prune` (with `--omit=dev`), `rebuild`,
  `link`/`unlink`, `cache add|clean|ls|verify`, project-scoped `licenses`,
  `scan`, and `perms`.
- Q-05: `view`/`info` with dotted field selectors and `--json` arrays,
  `search` (wire the existing client), `fund`, `bugs`/`docs`/`repo`.
- Q-06: `query` selector engine (port the dependency-selectors grammar) and
  `sbom` (SPDX and CycloneDX) for the whole tree.
- Q-07: `oath diff` (npm `diff` semantics) and Bun-style `pm diff` summary
  that flags new install scripts, new `child_process`/`fs`/`net` imports,
  eval growth; this reuses the scanner's capability diff already computed for
  `PublishAssessment`.

Exit gate: a maintainer can `login`, `version`, `pack`, `publish
--provenance`, `dist-tag`, and `deprecate` a real scoped package to npmjs and
to an Oath registry without `npm` installed; `audit` output matches npm on a
fixture set with known advisories.

### Phase 4: performance and Node-free operation (weeks 12–26, ~12 ew)

Goal: meet the performance gates and remove the `node` requirement.

- P-00, P-01, P-02, P-04, P-05, P-07 as in §4, in that order; each lands with
  a benchmark JSON.
- P-03: native planner. Scope: ideal-tree build from `package.json` plus
  lockfile, `place-dep` hoisting rules, peer resolution with
  `legacy`/`strict` modes, overrides (nested, `$ref`, `@range`), aliases,
  bundled deps, optional/platform filtering via a Rust port of
  `npm-install-checks`, `workspace`/`file`/`link` handling, `--install-strategy`
  hoisted/nested/shallow/linked, and `prefer-dedupe`. Validation: run both
  planners on every fixture, every pinned project, and the 10,000 generated
  executions; any divergence is a failing test. Ship behind
  `OATH_RESOLVER=native` for a release, then flip the default and keep Arborist
  as the canary lane in CI for npm-upgrade detection, which is what ADR-0001
  already anticipates.
- Record planner identity in the lockfile sidecar so evidence remains
  attributable.

Exit gate: warm install at or below npm p95 and cold at most 20% slower on
the declared hardware; no-op install under 100 ms; `oath install`, `ci`, and
`x` run with no `node` on `PATH` (exec still needs Node to run JS, naturally).

### Phase 5: Bun-class features (weeks 18–32, ~10 ew)

Goal: a Bun user can switch without losing package-manager features.

- L-04: import `bun.lock`, `bun.lockb` (via a one-shot converter), `yarn.lock`
  v1, and `pnpm-lock.yaml` v7–9 including `pnpm-workspace.yaml` catalogs,
  overrides, and patches; `oath pm migrate`.
- C-02: `catalog`/`catalogs` in `workspaces` and `pnpm-workspace.yaml`,
  `catalog:` specifiers, `add --catalog`, `outdated`/`update` on catalog
  entries, `catalogMode`.
- C-03: `patchedDependencies`, `oath patch` / `patch --commit`, pnpm
  `patch-commit` alias, patches applied at link time and cached by patch hash;
  align with npm 12's `npm patch`.
- C-04: Yarn `resolutions` and pnpm `packageExtensions`,
  `allowedDeprecatedVersions`, `peerDependencyRules`.
- C-05: `--linker isolated` with a pnpm/Bun-style per-project store, peer-set
  encoding in store names, hoisting fallback layer with `hoistPattern`/
  `publicHoistPattern`, and P-06 global virtual store.
- C-06: `bunfig.toml [install]` and `[install.scopes]`/`[install.cache]`
  keys, `BUN_CONFIG_*` and `NPM_CONFIG_*` env, `.npmrc` keys Bun honors
  (`node-linker`, `hoist-pattern`, `public-hoist-pattern`, `link-workspace-packages`).
- W-02 extension: `run --filter`/`--parallel`/`--sequential`/
  `--no-exit-on-error` with Foreman-style prefixed output and glob script
  names.
- B-PM: the remaining `bun pm` utilities (`bin`, `ls --trusted`,
  `default-trusted` printing Oath's own curated list, `hash*`, `pkg`,
  `version`, `whoami`) and `bun add --trust`, `--only-missing`, `--analyze`
  limited to a regex import scan with a documented caveat.
- S-01 extension: `nativeDependencies`/`ignoreScripts` postinstall optimizer
  (link prebuilt platform binaries instead of running `postinstall`).
- S-07: a security-scanner plugin API compatible with Bun's contract so
  Socket's scanner can run inside Oath, and conversely publish Oath's scanner
  as a Bun scanner package. This is cheap adoption surface.
- `oath create`, `oath init` templates with `-y`, `--init-type`,
  `--init-private`, and Bun-style agent rule files.

Exit gate: a Bun-parity fixture set (bun.lock import, catalogs, patches,
trusted-deps semantics, isolated layout, `run --filter`) passes; the
documented out-of-scope list is published.

### Phase 6: security differentiation (continuous; weeks 6–32, ~8 ew)

These are the reasons to choose Oath once parity exists.

- S-03: run dependency install scripts inside the native sandbox by default
  on Linux and Windows (filesystem scoped to the package dir and build
  outputs, network denied unless policy grants it, environment stripped),
  with the sandbox plan recorded in evidence. No other package manager does
  this.
- S-04: `allow-git`/`allow-remote`/`allow-file`/`allow-directory` with npm
  12 defaults, and pnpm-style `blockExoticSubdeps`.
- S-05: SRI integrity for git and remote tarball dependencies recorded in the
  lockfile; refuse unverifiable off-registry resolutions under policy.
- S-06: trust-downgrade detection (provenance or trusted-publisher evidence
  weaker than the previous release) and named-registry pinning per package so
  a dependency cannot be substituted from another registry.
- S-08: manifest-confusion check (tarball `package.json` vs registry
  manifest) and lifecycle-change diff on update, surfaced in `pm diff` and
  `outdated`.
- Context-aware severity (dev vs prod, popularity, age) and a quiet default:
  silent when every package grades B or better, loud when not, as the earlier
  state-of-the-art notes recommended.
- Rerun the detection corpus on current source and publish the numbers; this
  is an open GA gate and the roadmap does not close it by itself.
- Agent surface: `oath x --json --dry-run` already exists; add a stable
  `oath install --json` assessment, and publish a Claude/Cursor skill that
  routes `npx` through `oath x` (the `.agents/skills` directory already holds
  the drafts).

### Phase 7: platform, distribution, and GA (weeks 20–40)

- D-01: Windows parity (shims, `cmd.exe`, junctions, path length, ACLs) with
  the parity harness run with scripts on; AppContainer outbound network
  grants so native exec can allow network on Windows.
- D-02: macOS signing and notarization, Windows Authenticode, Linux
  checksums plus attestations (already present).
- D-03: distribution: `npm i -g oath` wrapper package, winget, scoop, Homebrew
  core, GitHub Action (`setup-oath`), `oath upgrade`, shell completions.
- D-04: honor `devEngines.packageManager`/`packageManager` for `oath` and
  offer `oath env` style Node provisioning later (pnpm `runtime:`), since
  Corepack is gone from Node 25.
- GA itself follows `RELEASE_COMPLETE_PLAN.md` and `GA_GATE_TRACKER.md`
  unchanged: detection targets, service SLOs, external review, legal, and
  commercial gates are not shortened by this roadmap.

---

## 6. Sequencing summary

| Window | Phase | Headline deliverable |
| --- | --- | --- |
| Weeks 0–3 | 0 | No silent corruption; docs truthful; `.bin` in evidence |
| Weeks 2–8 | 1 | `oath x` is a drop-in npx and bunx |
| Weeks 4–14 | 2 | `alias npm=oath` works for install/run/workspaces on real projects; `package-lock.json` canonical |
| Weeks 10–20 | 3 | Publish, login, audit, ls, outdated, version without host npm |
| Weeks 12–26 | 4 | Native planner; performance gates met; no Node requirement |
| Weeks 18–32 | 5 | Bun lockfile, catalogs, patches, isolated linker, scanner API |
| Weeks 6–32 | 6 | Sandboxed install scripts, exotic-source policy, trust-downgrade detection |
| Weeks 20–40 | 7 | Windows parity, signing, distribution, then the existing GA gates |

Total: roughly 60 engineer-weeks of implementation plus evidence work. With
one engineer that is 14–16 months; with two, 8–10 months. The single-
maintainer governance gate in `RELEASE_READINESS.md` is the binding
constraint, not the code.

---

## 7. Decisions that need the owner

1. **Lockfile:** adopt `package-lock.json` v3 as canonical (recommended) or
   keep `oath-lock.json` primary and write `package-lock.json` as an export.
   The recommendation is driven by interop with Dependabot/Renovate, GitHub,
   and npm itself.
2. **Native planner timing:** Phase 4 as scheduled, or earlier at the cost of
   Phase 3. The recommendation is to land P-00 through P-02 (cheap, big wins)
   during Phase 2 and start the native planner once the harness covers
   scripts and workspaces, so the oracle comparison is meaningful.
3. **Default script policy:** match npm 12 (`allowScripts` allow-list,
   hard block) exactly, or keep the interactive prompt plus
   `trustedDependencies`. Recommendation: npm 12 semantics by default, with
   Oath's prompt as the interactive path to populate the allow-list, and the
   sandbox as the thing that makes "approve" safe.
4. **Bun `trustedDependencies` default list:** curate Oath's own
   default-trusted set (reviewed, with evidence) or import Bun's ~400-name
   list. Recommendation: curate, starting from the intersection of Bun's list
   and pnpm's auto-generated placeholders, each entry carrying a scan result.
5. **Registry client scope:** whether Phase 3's A-07 (first-class Oath
   registry client) ships before or after the npmjs operations. Recommendation:
   npmjs first, since adoption depends on it.
6. **Bun out-of-scope statement:** publish the explicit "Oath replaces Bun's
   package manager, not its runtime" position now, before anyone reads "full
   Bun replacement" as a runtime claim.

---

## 8. What this roadmap does not change

- The compatibility methodology: pinned npm reference, differential harness,
  monotonically growing fixtures, no silent fallback to npm. It gets wider,
  not weaker.
- The evidence discipline: no speed claim without a checked-in benchmark, no
  detection claim without a corpus run, no GA without every gate.
- The fail-closed sandbox contract and the signed contract schemas; new fields
  are additive and versioned.
- ADR-0001's intent: Arborist stays the oracle for npm semantics even after
  the native planner is default.
