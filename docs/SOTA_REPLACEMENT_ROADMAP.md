# Oath SOTA replacement roadmap

Status: execution contract drafted from `codex/ga-evidence-foundation` at
`c8cf3ba6fac4df48d8bd40814bc2e566d3628343` on 2026-07-18.

Oath's next product goal is a complete, evidence-backed replacement for npm and
npx, plus the package-management portion of Bun. Replacing Bun's JavaScript
runtime, test runner, bundler, transpiler, shell, and application APIs is a
separate engine program. It is not part of this roadmap.

## Current position

Oath already has the hard-to-copy trust foundation:

- npm 11 placement through a pinned, checksum-verified Arborist runtime;
- integrity-verified fetches, bounded extraction, a content-addressed store,
  transactional linking, lockfile verification, and workspace installation;
- block-by-default dependency scripts, static capability analysis, versioned
  exec and publish assessments, hash-bound approvals, and native containment;
- staged publishing, signed transfer capsules, a registry control plane,
  transparency proofs, and fail-closed GA evidence contracts;
- 199 passing Rust tests after the first two-track implementation slice.

The checked-in evidence also states the present limits:

- the historical macOS installer sample records Oath at 2,683 ms cold and
  1,243 ms warm, versus npm at 728 ms and 428 ms and Bun at 406 ms and 23 ms;
- the published malware baseline missed 42.5% of its corpus and must be rerun
  on the exact release candidate after the scanner changes;
- compatibility evidence covers selected install, CI, workspace, exec, and
  publishing slices, not the entire npm command and configuration surface;
- production registry, external audit, cross-platform performance, witnessed
  transparency, legal, customer, and 60-day reliability evidence remain open.

Oath is therefore a strong developer preview, not yet a production-wide npm,
npx, or Bun package-manager replacement.

## What "2x better" means

Oath must not publish a single synthetic score. It earns a `2x better` claim
only for a named workflow and a reproducible metric.

| Dimension | Replacement gate | 2x-better gate |
| --- | --- | --- |
| npm compatibility | 100% of the declared npm 11 workflow contract, with zero unexplained tree, content, lifecycle, shim, lock, or exit-code differences | Migrate and roll back an eligible npm project in less than half the operator time, measured in partner studies |
| npx/agent safety | Every remote execution produces a noninteractive, signed, hash-bound decision before code runs | At least twice as many seeded takeover and exfiltration cases blocked as plain npx, with no more than 0.5% clean-corpus false positives |
| Cold install | No more than 20% slower than npm p95 with scanning enabled | At least 2x faster than npm p95 when comparison policy and materialized tree are equivalent |
| Warm install | No slower than npm p95 | At least 2x faster than npm p95; Bun is reported separately until Oath beats it on equivalent output |
| Cached exec decision | Under 2 seconds p95 | Under 1 second p95 with a verified local artifact |
| Cached assessment | Under 100 ms p95 | Under 50 ms p95 without weakening the detection gate |
| Supply-chain response | Signed revocation visible to resolvers in under 60 seconds p95 | Under 30 seconds p95, with a successful rollback and replay proof |
| Registry reliability | Metadata under 150 ms p95, tarballs at 99.95%, control plane at 99.9% | Half the npm-replacement workflow's measured failure rate over the same observation window |

All performance reports must use equivalent dependency graphs and package
contents, publish p50 and p95, include cold and warm cache definitions, run on
Linux, macOS, and Windows, and record hardware, versions, sample counts, raw
results, and confidence intervals.

## Product boundary

### Must replace

- `npm install`, `ci`, `add`, `remove`, `update`, `run`, `exec`/`npx`, `init`,
  `publish`, `pack`, `audit`, `outdated`, `why`/`explain`, `ls`, `view`, `search`,
  `version`, `link`, `dedupe`, `cache`, `config`, authentication, provenance,
  trusted publishing, dist-tags, deprecation, and access controls;
- npm lockfile import and stable Oath lockfiles, registry and scoped auth,
  aliases, overrides, peers, optional dependencies, git/file/tarball inputs,
  lifecycle behavior, native packages, workspaces, filters, catalogs, patches,
  production installs, offline installs, and global tools;
- Bun package-manager workflows: text lockfile migration, filtered workspace
  installs and runs, catalogs, overrides/resolutions, trusted dependencies,
  minimum-release-age policy, security-scanner integration, packing, and audit;
- interactive human UX and versioned JSON output for agents and CI, with stable
  reason codes and no silent fallback to npm or Bun.

### Must interoperate

- current Node LTS and current Node releases used by the compatibility matrix;
- npm-compatible registries and Oath registries, public and private;
- npm, pnpm, Yarn, and Bun project inputs through explicit, reversible migration;
- existing JavaScript runtimes. Oath selects and constrains a runtime; it does
  not pretend to be a JavaScript engine.

### Separate program

A literal full Bun replacement requires a JavaScript/TypeScript runtime, Node
compatibility layer, test runner, bundler, transpiler, package APIs, server and
Web APIs, database clients, shell, debugger, profiler, and editor integration.
Start that program only with its own team, benchmarks, compatibility contract,
and engine strategy. It must never block Oath's package-manager GA.

## Critical path

### P0: make the current claim complete

1. Merge PR #55 only after its exact-head CI, review, schema, and artifact gates
   pass. Regenerate every release artifact on the merge or release commit.
2. Expand the differential npm contract from selected fixtures to the declared
   command/configuration surface. Every fixed difference adds a permanent case.
3. Run the 250-project corpus and 10,000 generated executions on the exact
   candidate across Linux, macOS, and Windows.
4. Produce qualifying detection evidence, including the private holdout and
   false-positive corpus. Do not reuse the historical 57.5% recall result.
5. Close native-addon, lifecycle, authentication, offline, workspace-filter,
   lockfile-migration, and Windows shim/path gaps before calling Oath a drop-in.

Exit: ten design partners can replace npm and npx in development and CI, then
return to their previous lockfile and tool with a documented rollback.

### P1: win the hot path

1. Instrument resolve, planner startup, bundled-runtime extraction, metadata,
   download, unpack, store verification, link, scan, and lifecycle phases.
2. Remove repeated bundled npm-runtime extraction and avoid planner work when a
   verified manifest, placement plan, lockfile, store, and platform are unchanged.
3. Add a compact, verified metadata cache and request coalescing. Preserve
   registry freshness and revocation rules.
4. Use clone/reflink/hardlink backends per platform, update only changed
   placements, and retain atomic recovery.
5. Cache assessments by artifact, scanner, rule-bundle, and policy digests.
6. Run the versioned p95 harness in CI and block regressions beyond an agreed
   noise budget.

Exit: Oath meets the replacement gates in the table above on every supported OS.
Only then pursue named 2x wins. Bun comparisons must use equivalent trees and
security work, not headline timings from different semantics.

### P2: finish daily package-manager ergonomics

Maintain high-frequency commands and flags in order of partner usage,
not npm's alphabetical command list. The completed local tranche includes `pack`, `outdated`,
`ls`, `view`, workspace filters, production/omit modes, lockfile-only installs,
cache management, config inspection, login/whoami, versioning, linking, and
deduplication. Every command needs:

- npm/Bun differential fixtures where an equivalent exists;
- agent-safe JSON output and stable errors;
- offline, interrupted, repeated, and workspace cases;
- Windows, macOS, and Linux evidence;
- documentation that names intentional security differences.

### P3: production trust service

Deploy the same registry and evidence contracts in a managed multi-region
environment. Complete KMS-backed signing, CDN behavior, backups, restore,
failover, rotation, revocation, split-view, tenant-isolation, quota, and billing
drills. Add independent architecture, penetration, and sandbox reviews. Finish
the legal and support gates and run the full 60-day observation window.

Exit: every row in `GA_GATE_TRACKER.md` is backed by exact-release evidence and
ten partners confirm a production workflow replacement.

## Next three implementation slices

1. **Completed foundation slice.** `PerformanceEvidence v2`, twelve phase
   timings, the checksum-verified persistent npm runtime, verified tree/state
   no-op, and npm-compatible `pack` are implemented and covered by release
   smoke tests.
2. **Compatibility completion.** The required command surface, development
   linking, cache/config/auth commands, and transactional workspace selectors
   across install, run, mutation, exec, pack, and publish are implemented. The v2
   manifest has no partial or missing implementation entries; complete the exact-head
   Node 22/24 × three-OS differential qualification.
3. **Registry beta hardening.** Complete RLS-bound request transactions, Redis
   rate limiting, isolated analysis/signing workers, KMS signing, and the
   single-region invite-beta deployment and restore drills.

The earlier implementation order began with filters plus `pack`, `outdated`,
`ls`, and `view`, chosen because they unblock real monorepo and migration
workflows without widening the JavaScript-runtime boundary. The declared local
command surface is complete; unsupported platform containment still stays
fail-closed in `oath capabilities --json` and CompatibilityEvidence.

These next slices remain ordered: close the declared CLI surface before CLI RC,
then qualify the hosted Registry on its independent infrastructure timeline.
