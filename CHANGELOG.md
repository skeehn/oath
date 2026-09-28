# Changelog

All notable changes to oath are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

## [0.2.5] - 2026-07-16

### Changed
- The Homebrew formula now installs the immutable Apache-2.0 `v0.2.5` source
  archive with its verified SHA-256.
- `oath init` now writes `UNLICENSED` instead of choosing MIT on behalf of a
  new project's author.
- The installer accepts an explicit `OATH_VERSION` release tag so developer
  previews can be installed with the same fail-closed checksum verification as
  the latest stable release.
- macOS native mode uses a runtime-probed Seatbelt policy with default-deny file
  contents and process execution, scoped writes, network denial, environment
  stripping, inherited child restrictions, kernel limits, and process-group
  memory enforcement. The active Node binary is granted by canonical path so
  Homebrew and user-scoped version managers remain compatible.

### Fixed
- The released CLI now generates `UNLICENSED` project metadata instead of the
  historical MIT default.
- macOS auto and agent modes select native containment only after the live
  adversarial probe passes; probe or launcher failure remains fail-closed.

### Verified
- The macOS capability probe covers outside and system-secret reads, outside
  writes, child-process bypass, environment leakage, local network access, and
  resource limits. Protected CI checksums and attests the capability report.
- Exact-commit release evidence passed 61 jobs with 100 reviewed workflows on
  three operating systems, 250 pinned projects, and 10,000 generated executions.

## [0.2.4] - 2026-07-15

### Changed
- Oath source, documentation, website metadata, and future release artifacts are
  licensed under Apache License 2.0, with a root `NOTICE` file and CI-enforced
  license metadata consistency.
- Native macOS containment remains explicitly unavailable and fail-closed; Oath
  does not relabel Node permission mode as equivalent OS process isolation.

### Fixed
- The end-to-end launch check now derives its sandbox expectation from verified
  runtime capabilities. It requires native mode where all controls pass, proves
  automatic denial where they do not, and tests degraded Node permissions only
  after explicit acknowledgement.

### Verified
- Historical releases remain under the license granted with those immutable
  artifacts. This release changes current and future Oath licensing and does
  not attempt to revoke existing grants.
- Oath remains a developer preview and retains every open GA gate.

## [0.2.3] - 2026-07-15

### Fixed
- Signed evidence manifests now derive the 100-workflow, 250-project, and
  10,000-execution gate states from measured results instead of retaining stale
  hard-coded open labels.
- Measured gates are reported separately as completed or open, while external
  GA gates remain explicitly open and continue to keep `ga_gate.ready` false.

### Verified
- The corrected generator reproduces the exact `v0.2.2` compatibility claims:
  300/300 cross-platform workflow comparisons, 250/250 pinned projects, and
  10,000/10,000 generated executions with zero open measured gates.
- Full-threshold and under-threshold regression fixtures run in protected CI.
- Oath remains a developer preview. This patch does not make a GA detection,
  service-SLO, external-audit, or commercial-adoption claim.

## [0.2.2] - 2026-07-15

### Added
- Rootless OCI and cloud-neutral Kubernetes deployment contracts for the
  registry, with managed PostgreSQL and S3, R2, GCS, or Azure object storage.
- Cross-language signed-verdict verification clients and tests for JavaScript,
  Python, and Go, packaged with the published agent schemas.
- Draft-first GitHub releases that verify the exact expected asset inventory
  before publication.

### Changed
- The independently reviewed npm contract now contains 100 workflow IDs, the
  pinned real-project corpus contains 250 projects, and generated stress
  evidence executes 10,000 comparisons balanced across clean, warm, offline,
  repeat, and interrupted modes.
- Release assets are created as a draft and published only after all binaries,
  checksums, provenance, evidence, and contract bundles are present.

### Fixed
- npm-compatible linking now handles absent install roots, dangling workspace
  links, quoted boolean npm configuration, leading-`v` package versions, and
  npm-created empty scope directories without masking real tree differences.
- Windows workspace containment now validates canonical filesystem ancestry
  instead of rejecting equivalent drive-letter spelling before canonicalization.

### Verified
- Exact-master CI run
  [29403483148](https://github.com/Generalized-Labs/oath/actions/runs/29403483148)
  passed all 60 jobs at commit
  `49f98e650ae3b5066463e585a8843189eb00ccfc`: 100/100 reviewed behaviors
  on Linux, macOS, and Windows, 250/250 pinned projects, and 10,000/10,000
  generated comparisons with zero unexplained differences.
- Oath remains a developer preview. This compatibility result is not a GA
  detection, service-SLO, external-audit, or commercial-adoption claim.

## [0.2.1] - 2026-07-14

### Fixed
- Linux x86-64 and ARM64 cross-release images now install the target-architecture
  `libseccomp` development library required by Oath's native Linux sandbox.
- CI now builds both Linux release artifacts on every change and requires them
  in the exact-commit release-evidence gate.
- The signed `v0.2.0` tag remains as an immutable record, but no GitHub release
  or assets were published after its Linux artifact jobs failed. `v0.2.1` is the
  corrected release candidate for the developer-preview line.

## [0.2.0] - 2026-07-13

### Added
- npm 11.12.1 placement is now produced by a bundled, SHA-256-verified Arborist
  boundary while Oath retains fetch, integrity verification, scanning, storage,
  and transactional linking.
- Versioned `ExecAssessment`, approval binding, sandbox plans, capability reports,
  and machine-readable agent verdicts with stable reason codes.
- Signed `ExecAssessment v3`, `PublishAssessment v2`, and `RegistryVerdict v1`
  contracts with JSON Schemas, Rust/TypeScript types, expiry, evidence/policy
  digests, limitations, stable decisions, cross-language `oath-json-v1`
  canonicalization, and explicit legacy schema selection.
- Native Linux containment with namespaces, Landlock, seccomp, `no_new_privs`,
  resource limits, and fail-closed capability detection; native Windows
  containment with restricted tokens, AppContainer profiles, ACL-scoped roots,
  Job Objects, and process-tree termination.
- Publish assessments based on npm's authoritative packlist, previous-release
  diffs, SPDX SBOMs, in-toto assessment attestations, signed evidence,
  staged-publishing adapters, and signed package-transfer capsules.
- PostgreSQL registry control plane with staged promotion, private-package roles,
  short-lived tokens, OIDC, signed revocation tombstones, dist-tag rollback,
  replicated object storage, billing webhook verification, metrics, and signed
  transparency checkpoints.
- Server-owned assessment of exact staged tarballs with separately retained
  publisher claims, replayable evidence, risk score, SPDX SBOM,
  registry-observation provenance, per-version download counts, and approval
  denial for server-rejected artifacts.
- Transactional package-event outbox delivery, dependency-aware liveness and
  readiness, signed revocation bundles, public-only OSV quarantine feed, and
  Merkle inclusion plus complete-leaf consistency endpoints.
- Signed, exact-commit GA evidence manifests generated from CI artifacts and
  attached to releases with every still-open external gate recorded.
- Ten reviewed npm behavior fixtures covering dependencies, development and
  optional dependencies, peers, overrides, nested conflicts, scopes, aliases,
  workspaces, and dist-tags.
- Public release evidence for 500 generated stress executions, 100 pinned
  real-project tree comparisons, ten reviewed independent behaviors, Linux and
  Windows native-capability reports, and installer benchmarks.
- A public evidence website and design-partner issue workflow.

### Changed
- The minimum supported Rust version is now explicit at 1.94, matching the
  locked OXC scanner dependency.
- Release artifacts now include Windows x86-64 and ARM64 binaries, per-asset
  SHA-256 sidecars, aggregate checksums, and GitHub build-provenance attestations.
- Tag releases now verify version/changelog alignment, the complete Rust
  workspace, a warning-free RustSec audit, the production website, and a
  successful full evidence gate for the exact tagged commit before building
  assets.
- CI action dependencies are commit-pinned, and dependency-audit warnings are
  release failures.
- `oath exec --json` now defaults to signed assessment v3, including fail-closed
  release-age denials; `oath publish --json` emits one clean JSON document.

### Fixed
- `oath ci` now removes stale `node_modules` content and rematerializes the
  frozen graph from the verified store even when a placement entry was marked
  reusable.
- Location-keyed lock entries preserve the registry package name, fixing store
  verification and clean installs for nested npm-compatible placements.
- Frozen-lock comparison treats the explicit lock-entry name as derived metadata
  while still rejecting behavioral graph drift.
- Platform-specific optional packages can differ without making a shared frozen
  lock non-portable across macOS, Linux, and Windows.
- Twenty-two reviewed real-project lock snapshots were refreshed after registry
  resolution drift; npm and Oath both exited successfully and produced identical
  tree counts, tree hashes, and path sets for every refresh.
- The real-project harness now retries transient clone, fetch, and reference
  failures with partial-clone cleanup, gives large local checkouts five minutes,
  and preserves process errors and attempt counts in failed evidence.
- npm-style git `#semver:` selectors now fail closed with an exact-pin message
  instead of silently installing the repository's moving `HEAD`.
- Registry package ownership and visibility are now immutable, public metadata
  is anonymously readable, private metadata remains authenticated, repeated
  stage decisions return a conflict, and revoking the final active version
  removes stale dist-tags. Revoked and quarantined versions are omitted from npm
  packuments so range resolution cannot select an inactive release.
- Registry packuments are derived from the uploaded npm tarball manifest and
  validated against the requested package identity. Scoped metadata and tarball
  routes now work with npm clients, tarball integrity uses valid base64 SRI, and
  emitted tarball URLs honor the configured public origin.
- Invitation email setup now requires an explicit application accept URL and
  revokes the pending invitation if email delivery fails.
- Stale PostgreSQL and reliability test filters no longer allow zero-test CI
  jobs to appear green; the manual evidence gate now requires every release
  lane, including audit, MSRV, registry, Windows artifacts, and reliability.
- The checked-in Homebrew formula now points to the current public v0.1.7 source
  archive instead of v0.1.0.

### Security
- Fixed cross-organization registry authorization paths that treated an
  organization administrator as a global administrator. Live PostgreSQL tests
  now deny cross-tenant stage inspection, approval, publishing, role grants,
  metadata, downloads, and revocation.
- Registry signing-key creation is atomic under concurrent startup,
  transparency appends are serialized into one hash chain, request metrics now
  cover every route outcome, and Stripe webhook signatures use constant-time
  HMAC verification with timestamp-expiry tests.
- Exec and publish signing-key creation now use atomic winner selection, and
  hosted stage approval can require fresh OIDC MFA/WebAuthn assurance.
- Removed the unused placeholder index crate and its SQLite dependency graph from
  the registry build.
- Locked `crc-fast` to 1.7.0, the newest compatible release before its dependency
  on yanked `spin` 0.10.0, so `cargo audit --deny warnings` is clean.

## [0.1.7] - 2026-07-10

### Fixed
- Dependency edges now select the highest resolved package version that satisfies
  each parent's declared range. This fixes multiversion graphs such as
  `esbuild@0.27.0` and `esbuild@0.28.1` incorrectly sharing one platform binary.
- Scanner verdicts now correlate behavior within each source file instead of
  combining unrelated capabilities from different files into a false positive.
- Shell download chains are only flagged when the command string is passed to a
  subprocess API or appears in an install hook, not when documentation mentions
  commands such as `curl`.
- Credential environment matching now recognizes credential-shaped names without
  treating framework metadata such as `NEXT_PRIVATE_*`, `AWS_REGION`, or
  `GITHUB_SHA` as secrets.
- `oath exec` safety grades and displayed findings now agree with the AST verdict:
  Info packages cannot grade below B, review-tier packages cannot grade below C,
  and only correlated verdict reasons are presented as actionable findings.

### Verified
- Clean T3-style application install with Next, React, tRPC, TanStack Query,
  SuperJSON, Zod, AI SDK/OpenAI, Convex, TypeScript, and tsx.
- `create-t3-app@7.40.0` resolves to an Info/B allow decision without heuristic
  malware findings; Convex's explicit secret-to-auth-endpoint path remains a
  review warning rather than a malware-level block.

## [0.1.6] - 2026-07-10

### Added
- **Verified package store manifests.** Stored packages now include
  `.oath-store-manifest.json` with schema version, lock integrity, resolved URL,
  package identity, file count, byte count, and a deterministic BLAKE3 file tree.
- **Full store verification.** `oath verify` now fails on missing, unmanifested,
  malformed, tampered, or package.json-mismatched store entries.
- **Bounded tarball extraction.** Tarball downloads stream to temp files while
  enforcing compressed-size limits and SRI checks; extraction enforces unpacked
  byte, entry count, path length, path depth, path traversal, UTF-8, and file-type
  limits.
- **`oath exec` sandbox flags.** Added `--sandbox` and
  `--sandbox-mode off|node|native|auto`. Human default remains `off`;
  `OATH_AGENT_MODE=1` defaults to `auto`. Node mode uses Node permission flags
  when available; native mode currently fails closed.

### Changed
- Warm installs, `ci`, `exec`, `score`, and global installs now treat legacy or
  corrupt store entries as unverified and redownload/rebuild them before linking
  or scanning.
- `oath publish` now rejects symlinks and non-regular files, canonicalizes every
  included path, and fails on out-of-root or unreadable files.
- `scripts/launch-check.sh` now requires a hydrated non-iCloud checkout with at
  least 10 GiB free by default, then smokes store tamper detection and exec
  sandbox JSON output.

### Fixed
- Registry metadata, search, and tarball GETs now use bounded retry/backoff for
  transient transport and HTTP failures. Interrupted tarballs restart from byte
  zero instead of leaving a partial download in place.
- The AI compatibility runner now resolves a relative `OATH_BIN` from the repo
  root, matching its documented invocation even when cases run in temp projects.
- Updated `crossbeam-epoch` to `0.9.20` to resolve `RUSTSEC-2026-0204`.

## [0.1.5] - 2026-07-05

### Added
- Lockfile v2 root metadata, including roots plus dependency/devDependency
  snapshots for correct warm installs and frozen installs.
- Release-readiness docs, security policy, contribution templates, checksum
  sidecars, launch-check coverage, and AI ecosystem compatibility smoke results.

### Fixed
- `oath install`, `ci`, `add`, and `remove` state transitions now keep
  package.json, oath-lock.json, node_modules, and the shared store in sync.
- Scoped package linker edge cases, unsafe bin handling, installer checksum
  behavior, tarball path safety, and release workflow checkout handling.

## [0.1.4] - 2026-06-25

### Fixed
- **Scanner false-positives on popular packages.** Household-name packages
  (prettier, bson, lodash, express) graded **F** off heuristic flags — a dealbreaker
  for a real npm replacement. Char-code counting is now informational (the
  dangerous `eval(fromCharCode(...))` form is still Critical), dynamic `require()`
  with a computed name is Low (the benign `require(`…`)` template shape is no longer
  flagged), base64 payloads are Medium, and `.d.ts`/`.d.cts`/`.d.mts` type
  declarations are skipped (they can't execute). prettier/bson/lodash/express now
  grade **A**, react **100** — verified 0% false positives / 100% recall on the bench.

### Added
- **Popularity trust layer.** `oath score`, `oath exec`, and the `--require-grade`
  gate now factor in registry weekly-downloads: a package with **≥1M weekly
  downloads and no _critical_ finding** is trusted to grade **A** (heuristic flags on
  a package that widely used are false positives). Supply-chain compromises surface
  as **critical** decode→exec / exfiltration findings, which are never rescued — so
  recall on real attacks is preserved.
- **MIT `LICENSE`** file (was declared in `Cargo.toml`/README but the file was absent).

## [0.1.3] - 2026-06-24

### Added
- **`oath exec` always-on pre-run card.** Before running a package, oath now shows
  its safety grade + score, publish age, last publisher, open-source flag,
  readable-vs-obfuscated, unpacked size, and runtime permissions — replacing
  npm/npx's uninformative `[y/N]` prompt with a real verdict.
- **`oath exec --json`** emits a machine-readable verdict (`grade`, `score`,
  `capabilities`, `last_publisher`, `age_days`, `integrity`, `decision`, …) so an
  AI agent or CI step can vet a `skill.md` / `npx`-style command *before* it runs —
  closing a real supply-chain hole for agents.
- **Agent gates**: `oath exec --require-grade <A-F>` and `--dry-run`, with stable
  exit codes an agent can branch on without parsing text: `10` blocked by grade,
  `11` blocked by min-age, `13` declined.

## [0.1.2] - 2026-06-24

### Added
- `oath run` and install scripts now export the `npm_*` lifecycle env vars
  (`npm_lifecycle_event`, `npm_package_name`, `npm_package_version`, and the
  flattened `npm_package_<field>` set) that many build scripts rely on.
- Root project lifecycle hooks: a plain `oath install` now runs the project's
  own `preinstall`/`postinstall`/`prepare` scripts (e.g. husky), matching npm/bun.
  These are your own trusted scripts and always run, unlike blocked dependency
  scripts.
- Drop-in aliases: `oath ci` (clean install from the lockfile), `oath uninstall`
  / `oath rm` (= remove), and `oath x` (= exec).

### Changed
- `oath audit` is now `oath scan` (`audit` kept as an alias). It is behavioral
  analysis, not a CVE/advisory lookup, and the new name says so.
- Faster installs: package scanning now runs in parallel across CPU cores (the
  cold-install hot path), and a re-install with an unchanged lockfile skips the
  node_modules rebuild instead of nuking and relinking every time.

## [0.1.1] - 2026-06-24

### Removed
- `oathx` stub binary and the `oath exec --allow-read/--allow-write/--allow-env`
  flags, plus the install-script "sandbox" prompt option. None of these enforced
  anything — advertising enforcement a security tool does not have is worse than
  omitting it. OS-level sandboxing (macOS Seatbelt / Linux Landlock) is tracked
  for a later release.

### Added
- CI workflow running `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo test` on every push to `master` and every pull request.
- `oath exec --yes` / `-y` to skip the risk prompt without prompting (replaces
  the misleadingly-named `--allow-net`, which only suppressed the prompt).

### Changed
- Scanner rebuilt AST-first (oxc): false-positive rate 11.6% → 1.1%, recall
  42.3% → 54.1% measured against 928 popular packages + 313 real npm-malware
  samples. See `docs/scanner-threat-model.md` for methodology and honest limits.
- Install scripts are blocked by default; allowlist via `trustedDependencies` or
  the policy file.
- `--min-age` release cooldown is now enforced on install (was previously dead).
- TLS switched to rustls so Linux cross-compiles need no system OpenSSL.
- README install command points at a working installer URL; `BENCHMARKS.md`
  score examples corrected to measured values (express 88/B, lodash 80/B).

### Fixed
- Private/scoped registry support via `.npmrc`.
- `package-lock.json` import for zero-friction migration.
- Install-time malware scan was skipped for every package (wrong store path).
- `oath verify` checked 0 packages (name read from the wrong field).

## [0.1.0]

- Initial release: security-first npm/npx replacement with static analysis,
  safety scoring, content-addressable store, transparency log, and multi-platform
  prebuilt binaries.
