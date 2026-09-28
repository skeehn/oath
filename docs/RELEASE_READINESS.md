# v0.2.5 release readiness

Audit date: 2026-07-16

## Decision

Oath `v0.2.5` is a **developer preview**. Its exact commit passed the manually
dispatched `release-evidence-gate`; the release workflow revalidated that
result before building and publishing the prerelease assets.

Oath is **not GA**. The hosted registry is a business-beta control plane for
isolated design-partner deployments with an operator. Detection quality,
service SLOs, code signing, external review, operational drills, and commercial
adoption have not met the complete GA contract.

## Repository governance

Oath currently has one active maintainer. Protected `master` therefore requires
pull requests with zero human approvals during this phase; requiring an
independent approval would deadlock every maintainer-authored change. The
repository still enforces its configured cross-platform checks, strict branch
freshness, verified commit signatures, linear history, conversation resolution,
administrator enforcement, and force-push/deletion blocking. Independent
approval becomes mandatory when a second active Oath maintainer is onboarded
and remains a GA governance gate.

## Audited full-evidence baseline

Exact-master run
[`29499711576`](https://github.com/Generalized-Labs/oath/actions/runs/29499711576)
passed all 61 jobs and `release-evidence-gate` at commit
`803f7883f8a663a5da56ab82a45c88d72ab9eee3`. The downloaded summaries
independently aggregate to 100 reviewed workflow IDs on each supported CI OS,
250 pinned projects, and 10,000 generated comparisons. This is the audited
implementation baseline for the signed `v0.2.5` tag and published prerelease.

| Gate | Result |
| --- | ---: |
| Rust format and warning-fatal Clippy | Pass |
| Rust workspace tests, including live PostgreSQL | Pass |
| Declared Rust 1.94 MSRV check | Pass |
| Rust and website dependency audits | Pass |
| Independently reviewed npm workflows | 100 / 100 on Linux, macOS, and Windows |
| Generated stress executions | 10,000 / 10,000; 2,000 per execution mode |
| Pinned real-project trees | 250 / 250 |
| Signed JavaScript, Python, and Go agent-contract verification | Pass |
| PostgreSQL, OCI-container, and registry reliability checks | Pass |
| Native Linux, macOS, and Windows containment checks | Pass |
| Public stable-release README smoke | Pass |
| Exact-commit release evidence gate | Pass |

The generated artifacts contain 2,000 comparisons each for clean, warm,
offline, repeat, and interrupted modes, all classified as compared and all
equivalent. The complete manually dispatched CI run repeats the cross-platform,
native-containment, registry, audit, reliability, 10,000-execution, and
250-project gates for the exact release commit.

## Current source validation

- The reviewed behavior contract contains 100 workflow IDs. Exact-master
  artifacts matched 100/100 against npm 11.12.1 on Linux, macOS, and Windows
  with zero tree differences.
- `ExecAssessment v3`, `PublishAssessment v2`, and `RegistryVerdict v1` have
  published schemas/types, stable decisions, digests, expiry, limitations, and
  Ed25519 signatures. JavaScript, Python, and Go verifiers accept the signed
  fixtures and reject mutations. Exec v2 and publish v1 remain selectable.
- The registry ships as a rootless OCI image and cloud-neutral Kubernetes base
  over managed PostgreSQL and S3, R2, GCS, or Azure object storage. This is a
  portable deployment contract, not a production-service SLO result.
- The live PostgreSQL test passes server-owned assessment, retained evidence,
  SPDX SBOM, registry-observation provenance, private verdict authorization,
  step-up approval enforcement, atomic outbox delivery, download accounting,
  revocation rollback, OSV quarantine output, and Merkle proof verification.
- Every later candidate still requires a manually dispatched full-evidence run
  and signed manifest bound to its exact commit before the developer-preview
  tag. This document intentionally does not maintain a mutable latest-run
  pointer.
- The signed `v0.2.0` tag points to commit
  `6147df33b5beee7a9a1c39e9cbb3173226490310`, whose exact evidence run
  [`29324736660`](https://github.com/Generalized-Labs/oath/actions/runs/29324736660)
  passed all 54 jobs. Release run
  [`29349917900`](https://github.com/Generalized-Labs/oath/actions/runs/29349917900)
  then failed only while linking the Linux x86-64 and ARM64 assets because the
  cross images lacked target `libseccomp`. No `v0.2.0` GitHub release or assets
  were published. The tag is not moved or deleted.
- The `v0.2.1` release corrected the Linux cross-image `libseccomp` packaging
  failure. `v0.2.2` added portable registry deployment, cross-language signed
  contract verification, immutable release assembly, and expanded npm parity.
  `v0.2.3` derives measured gate state from the evidence instead of retaining
  stale hard-coded open labels. `v0.2.4` changed the current and future Oath
  distribution license to Apache-2.0. `v0.2.5` adds runtime-probed native macOS
  containment and changes generated projects to `UNLICENSED`.
- The real-project corpus now commits and digest-verifies 250 compressed npm
  lockfiles. Evidence runs no longer regenerate dependency resolution from
  mutable registry state, and npm and Oath consume the same pinned bytes through
  the ordinary `npm install` path. Paired `devOptional: true` to `dev: true`
  normalization is recorded path by path; every other lock mutation is a hard
  failure.

## Honest measured limits

- The current installer sample does not support a speed claim. Oath measured
  slower than npm and Bun for both cold and warm installs; see
  [`BENCHMARKS.md`](../BENCHMARKS.md).
- The last published scanner corpus baseline measured 57.5% malware recall and
  0.6% false positives on the older v0.1.6 engine. It has not been rerun on the
  exact current source and does not meet the GA detection targets; see
  [`scanner-threat-model.md`](scanner-threat-model.md).
- The current source independently extracts and scans the exact staged tarball,
  signs a server `RegistryVerdict v1`, retains publisher claims separately, and
  prevents approval of a server-denied artifact. It becomes release proof only
  through the exact candidate's cross-platform run and signed manifest.
- Core stage, approval, rejection, and revocation mutations enqueue audit intent
  in the same PostgreSQL transaction. An idempotent worker appends signed log
  entries with retry. Full process-kill, restore, key-rotation, and regional
  failover drills remain operator gates.
- Native macOS Seatbelt containment is runtime-probed and covered by an
  attested macOS 15 adversarial job. Apple's launcher interface remains
  deprecated, and signing/notarization plus an external sandbox escape review
  remain open. A failed probe continues to deny strict execution.

## Required tag sequence

1. Merge the reviewed candidate to `master`.
2. Manually dispatch `.github/workflows/ci.yml` on the exact master commit.
3. Require every job in `release-evidence-gate` to pass without exceptions.
4. Create a signed version tag on that exact commit.
5. Let `.github/workflows/release.yml` revalidate version, changelog, MSRV,
   tests, dependency audits, website, exact-commit evidence, platform builds,
   checksums, and provenance before publishing the GitHub release.

Do not bypass or relabel a failed gate. A failure returns the candidate to
development; it is not a documentation exception.
