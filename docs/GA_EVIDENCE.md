# GA evidence contract

GA requires a reviewed independent behavioral contract, 10,000 generated stress
executions, and 250 named real projects. The stress and project targets are
enforced by `scripts/compat-scale.mjs`; independent behavior IDs live in
`tests/compat/behavioral-contract.json`. Changing any denominator requires a
reviewed contract change. A manifest is not a passing result. GA is green only
when every independent behavior and stress artifact passes (or records a
reviewed security divergence), and all real-project runs include commit SHA,
npm version, Oath version, platform, duration, graph/layout comparison, and
logs/checksums.

## Current evidence snapshot (2026-07-14)

- The post-placement-contract stress run executed 500 generated cases: 500 were
  equivalent and zero failed. These are repetitions of three independent
  behavioral templates (`basic`, `alias`, and `workspace`) across clean, warm,
  offline, repeat, and interrupted-recovery modes. They prove deterministic
  stress behavior; they do not count as 500 independent npm features.
- Independent behavioral coverage and generated stress coverage are separate
  release artifacts and public metrics. The reviewed contract contains ten
  behavior IDs. A complete run executes all ten on Linux, macOS, and Windows,
  producing 30 platform results; GA still requires 100 independently reviewed
  workflows, not a generated-case or platform-result count by itself.
- The pinned corpus now has 100/100 exact npm/Oath tree equivalents. The
  aggregate contains zero failures. Repositories rejected by reference npm or
  requiring another package manager are not eligible for the locked corpus and
  never count as passes.
- The GA foundation refresh in
  [`29366460579`](https://github.com/Generalized-Labs/oath/actions/runs/29366460579)
  tested 498 candidates and froze 250 exact project inputs, 25 in each category,
  with all 250 compressed lock digests validated. This is input-corpus evidence,
  not a 250-project parity result; the exact candidate still must execute and
  aggregate all 250 npm/Oath comparisons.
- Exact-master run
  [`29379054882`](https://github.com/Generalized-Labs/oath/actions/runs/29379054882)
  correctly failed before project execution because `project-parity.mjs` still
  enforced the historical 100-project denominator. All 20 shards rejected the
  250-input manifest, the run was cancelled, and zero project passes from it are
  claimed. The harness now validates an explicit 250-project target in PR CI.
- Corpus manifest version 2 stores the exact compressed npm lockfile for each
  project. The harness verifies the decompressed digest, supplies identical
  bytes to npm and Oath, and runs the ordinary `npm install` workflow. It records
  only paired `devOptional: true` to `dev: true` normalization path by path and
  rejects every other lock mutation. This replaced the earlier
  hash-only design after exact-master run `29310661010` correctly blocked on
  Express and Ant Design lock drift caused by mutable registry resolution even
  though both npm/Oath trees were identical.
- Exact-master run `29314277600` then exposed a second reproducibility flaw:
  replaying Snowpack's frozen lock with `npm install` under a fresh cache changed
  six `devOptional` flags to `dev`, despite an identical 46,695-entry dependency
  tree. The run correctly failed.
- Exact-master run `29316385773` tested `npm ci` as a possible byte-preserving
  reference. It produced 99/100 exact projects, but `npm/cli` had 964 npm-only
  installed files because `npm ci` and `npm install` have different bundled
  package materialization behavior. The run correctly failed. The final
  contract keeps `npm install`, accepts only paired Snowpack-style
  dependency-classification normalization as explained metadata.
- The corrected contract first passed a complete full-evidence run in
  [`29320179154`](https://github.com/Generalized-Labs/oath/actions/runs/29320179154)
  at commit `aafc55c7403bc859b68ec6785de29bb2f28802ae`. All 54 jobs
  passed: 30/30 independent platform results, 500/500 generated stress
  executions, and 100/100 exact real-project trees. Its checksum-verified
  manifest received GitHub OIDC/SLSA provenance bound to that workflow, run,
  branch, and commit. This is historical evidence for that exact commit only;
  every later candidate must produce its own signed manifest.
- Next.js HEAD was replaced by the npm-eligible
  `NextJSTemplates/play-nextjs` commit
  `f0a5c55ef1d6198c41ac6354595adadc4c41b924`, which passed exact comparison.
- The installer benchmark does not support a speed claim: Oath was slower than
  npm and Bun on both cold and warm runs. See
  `compat-results/benchmarks/installers.json` for versions and methodology.
- Native Linux enforcement passed on Ubuntu 24.04 with Landlock/seccomp active,
  and Ubuntu 22.04 proved strict mode fails closed when the required Landlock
  ABI is unavailable. Native Windows AppContainer, restricted-token, ACL, Job
  Object, environment, filesystem, and network-denial checks passed on Windows
  Server 2022 and 2025 in PRs 16 and 17.
- Full-evidence manifests retain the native capability reports. Ubuntu 24.04
  must report the strict Landlock/seccomp backend active; Ubuntu 22.04 must
  report explicit fail-closed degradation; Windows Server 2022 and 2025 must
  report the AppContainer/Job Object backend active.

Scheduled and manually dispatched CI produce release evidence. Pull-request CI
runs the independent behavioral baseline and native enforcement checks. Public
metrics must report evidence class, independent-behavior denominator, generated
stress denominator, failures, confidence intervals, and skipped projects;
skipped or network-failed runs never count as passes.

Successful full-evidence runs now produce `ga-evidence-manifest.json`. The
manifest hashes every input summary, binds them to the exact commit and run,
lists every still-open external GA gate, receives a GitHub OIDC artifact
attestation, and is attached to the corresponding release. This document is a
human index and intentionally does not maintain a mutable latest-run pointer;
the signed manifest attached to the exact candidate is the release claim source
of truth.

## Versioned qualifying reports

The manifest evaluator also consumes versioned, checksum-bound reports for
detection quality, cross-platform performance, production deployment,
independent audits, witnessed transparency, and the 60-day beta ledger. Every
report that represents a release candidate must bind to the same full Git
commit. Detection reports fail when any discovered sample was not scanned or a
scan error was hidden. Performance requires passing reports from Linux, macOS,
and Windows with the published minimum sample counts and equivalent npm/Oath
trees. Transparency requires an unexpired Rekor-bound checkpoint and at least
two distinct witness identities.

These contracts make the remaining work measurable; they are not evidence that
the measurements have passed. Until qualifying external and production reports
exist, `ga_gate.technical_ready` and `ga_gate.ready` remain false.
