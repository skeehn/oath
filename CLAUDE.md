# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Oath is

Oath is a security-first npm package workflow and `npx` alternative written in Rust (edition 2024, MSRV 1.94). It resolves packages with npm 11 placement semantics, verifies bytes, statically analyzes code and lifecycle scripts, applies an explicit policy, optionally runs package code in a native OS sandbox, and records evidence. Everything is designed to **fail closed**: a missing sandbox boundary, an unknown schema/reason code, or a checksum mismatch is an error, never a silent downgrade.

Public claims are evidence-gated. Do not write docs, comments, or website copy that says static analysis proves safety, that Oath is faster than npm/Bun, or that npm compatibility is complete. See `docs/GA_EVIDENCE.md` and `.agents/skills/*/SKILL.md` for the sanctioned language.

## Commands

Build prerequisites: Rust 1.94+, Node.js (the Arborist planner shells out to `node`), and on Debian/Ubuntu `libseccomp-dev` for the Linux sandbox linker dependency.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings   # CI sets RUSTFLAGS=-D warnings
cargo test --workspace --locked
cargo build --release --locked --bin oath                        # binary at target/release/oath
cargo audit --deny warnings                                      # cargo install cargo-audit --locked
```

Always pass `--locked`; `Cargo.lock` is deliberately pinned (see comments in `Cargo.toml` about `crc-fast`, `object_store`, and the RSA-free dependency graph that CI asserts).

Single test / single crate:

```sh
cargo test --locked -p oath-store linker::tests::<name>
cargo test --locked -p oath-contracts published_signed_examples_verify
cargo test --locked -p oath-registry postgres_api::tests::live_postgres_enforces_tenants_publish_download_and_revoke -- --exact
```

Tests needing external resources:

- PostgreSQL registry tests skip unless `OATH_TEST_DATABASE_URL` is set (e.g. `postgresql://oath:oath@localhost:5432/oath_test`).
- Native Linux sandbox tests are `#[ignore]`d; run with `OATH_NATIVE_TEST_BIN=target/release/oath cargo test --locked -p oath-sandbox native_linux -- --ignored --test-threads=1` (needs bubblewrap and unprivileged user namespaces).
- `oath-fetch` and `oath-resolve` integration tests contact the real npm registry.

Full local gate before a PR that touches resolver/fetch/install/exec/release behavior (needs 10 GiB free, builds into a temp target dir):

```sh
scripts/launch-check.sh
```

Other checks CI runs that are easy to forget:

```sh
node scripts/license-check.mjs              # Apache-2.0 declarations
node scripts/validate-agent-skills.mjs      # .agents/skills frontmatter + evals + required safety markers
cargo run --locked -p oath-contracts --example generate_contract_examples -- contracts/examples  # then verify clean git diff
node scripts/compat-behavioral.mjs --execute # npm parity, needs OATH_BIN and npm 11.12.1 on PATH
(cd website && npm ci && npm run build)      # Vite/React evidence site
```

Run the registry service locally: `DATABASE_URL=postgres://... cargo run -p oath-registry` (SQLite is not supported; `OATH_REGISTRY_TOKEN`/`OATH_REGISTRY_ORG` bootstrap an admin token, `OATH_REGISTRY_BIND` defaults to `0.0.0.0:4873`).

## Workspace architecture

Cargo workspace under `crates/`. Dependency direction is strictly bottom-up; `oath-core` must not depend on `oath-analyze` (its `RiskLevel` enum is intentionally duplicated for that reason).

| Crate | Role |
| --- | --- |
| `oath-core` | Shared types: `OathError`, `OathConfig`, `OathPolicy` (merged from `~/.oath/policy.toml` then project `oath-policy.toml`), integrity helpers, manifest/permissions |
| `oath-contracts` | Versioned, Ed25519-signed JSON contracts (`ExecAssessment v3`, `PublishAssessment v2`, `RegistryVerdict v1`), closed `ReasonCode` set, `oath-json-v1` canonicalization |
| `oath-fetch` | npm registry HTTP client, packuments, `.npmrc` parsing, bounded tarball download/unpack (`TarballLimits`) |
| `oath-resolve` | Dependency graph, lockfile (`oath-lock.json`), npm lockfile import, git specs, and the **Arborist placement planner** |
| `oath-store` | BLAKE3 content-addressable store at `~/.oath/store/` with per-package `.oath-store-manifest.json`, plus the transactional `Linker` that materializes `node_modules` via hardlinks/symlinks |
| `oath-analyze` | OXC-based static analysis: capability detection (`net`, `fs`, `subprocess`, `env`, eval, obfuscation), `Behavior`/`Verdict`, `SafetyScore` |
| `oath-sandbox` | `SandboxPlan` (versioned) and per-OS backends: Linux bubblewrap + Landlock + seccomp, macOS Seatbelt, Windows AppContainer/Job Objects. `native_capabilities()` reports; `verified_native_capabilities()` proves by running a strict plan |
| `oath-transparency` | Append-only hash-chained JSONL log at `~/.oath/transparency.log` with Merkle checkpoints |
| `oath-workspace` | Monorepo detection (`pnpm-workspace.yaml`, `package.json#workspaces`), `workspace:*` specifiers |
| `oath-cli` | The `oath` binary (clap). `main.rs` is ~5.5k lines holding all subcommands; `exec_assessment.rs`, `publish_assessment.rs`, `approvals.rs`, `package_transfer.rs` hold the decision logic |
| `oath-registry` | Axum + PostgreSQL private registry service (`oath-registry` binary) with object-store backends, OIDC identity, billing, control plane, signed verdicts |

### Install pipeline (the part that spans several crates)

1. **Placement**: `ArboristPlanner` (`oath-resolve/src/placement.rs`) extracts a vendored `npm-11.12.1.tgz` (`crates/oath-resolve/vendor/`, SHA-256 pinned) and runs the embedded `arborist-plan.cjs` under `node` with `reify({dryRun: true, ignoreScripts: true})`. The result is a versioned `PlacementPlan` of exact `node_modules` locations. Non-dry reify is forbidden by design (ADR-0001 in `docs/adr/`). `OATH_RESOLVER=legacy` switches to the old Rust resolver as a diagnostic canary only. Plan node keys are locations, not `name@version`, because peer contexts can duplicate a version.
2. **Fetch + verify**: `oath-fetch` downloads each planned tarball, checks the lockfile integrity, and unpacks under `TarballLimits` (entry count / unpacked bytes, overridable with `OATH_MAX_TARBALL_ENTRIES` / `OATH_MAX_UNPACKED_BYTES`).
3. **Analyze + policy**: `PackageScanner` produces findings and a risk level; `OathPolicy` decides (banned packages/licenses, `block_install_scripts`, `max_risk_level`). Lifecycle scripts never run before this gate.
4. **Store + link**: `ContentStore` writes into the CAS; `Linker` builds a staging tree and commits it atomically, so a failed install leaves the previous `node_modules` intact. `oath verify` re-hashes store manifests and fails on tamper.
5. **Evidence**: `oath-transparency` appends a chained record.

### Exec / publish decision contracts

`oath exec` and `oath publish` produce signed assessments defined in `oath-contracts`. The contract surface is published in `contracts/` (JSON Schemas, `oath-contracts.ts`, OpenAPI, JS/Python/Go verifiers) and regenerated examples live in `contracts/examples/`. Adding a reason code requires synchronized changes to the Rust enum, TypeScript types, schema, examples, and bundle manifest; changing or removing one requires a new schema version. The previous schema version stays available via `--schema-version` for one major release. JSON output modes reserve stdout for exactly one document.

Sandbox mode semantics: `--sandbox-mode auto` must fail closed when the native backend lacks any of filesystem/network/process/resource controls, unless `--allow-degraded-sandbox` is passed, in which case the output records `sandbox_degraded_allowed`. Approvals are bound to the tarball integrity hash, not the package name.

## Evidence and compatibility assets

- `tests/compat/fixtures/` + `tests/compat/behavioral-contract.json` drive the npm parity gate (`scripts/compat-behavioral.mjs`, `scripts/npm-parity.mjs`). `behavioral-contract.json` is generated by `scripts/generate-behavioral-contract.mjs`; CI regenerates it and fails on diff.
- `tests/compat/projects.lock.json` pins the 250-project real-world corpus (`scripts/project-corpus.mjs`, `scripts/project-parity.mjs`).
- `tests/detection/self-test/` is the four-population detection corpus used by `cargo run -p oath-analyze --example detection_gate`.
- `compat-results/` holds committed evidence summaries; most generated subdirectories are gitignored.
- `scripts/*.test.mjs` are run with `node --test`.
- `.agents/skills/` contains agent skills whose required safety markers are enforced by `scripts/validate-agent-skills.mjs`; keep those phrases if you edit the skills.

## Roadmap and research

`docs/FULL_REPLACEMENT_ROADMAP.md` is the gap analysis and phased plan for reaching npm/npx/Bun parity, with work-item IDs. `docs/research/oath-cli-inventory.md` is a `file:line` inventory of what every subcommand does today, including known bugs; check it before changing CLI behavior.

## Conventions

- PR template requires fmt, clippy, test checkboxes and a "Security Notes" section; code touching tarball extraction, linking, script execution, registry auth, installer checksums, or release workflows should include a short threat model in the PR description.
- `code_review.yaml` configures Ellipsis review; `.github/CODEOWNERS` routes `oath-fetch`, `oath-store`, `oath-cli`, `install.sh`, and workflows to maintainers.
- Never commit `.npmrc`, `.env*`, or `.gstack/`.
- Release tags require a manually dispatched full CI run on the exact commit; a PR run does not execute every evidence lane.
