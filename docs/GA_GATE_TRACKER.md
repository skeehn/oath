# CLI and Registry general-availability gate tracker

No row is complete because a feature exists in source. Completion requires the
linked evidence on the exact release commit and, where applicable, the full
observation window or external approval.

CLI and Registry are independent release tracks. A Registry infrastructure or
soak gate cannot block CLI GA, and CLI feature work cannot reset the Registry
qualification window unless it changes the deployed Registry contract.

## CLI track

| Gate | Current state | Required evidence |
| --- | --- | --- |
| 100 independent npm workflows | Infrastructure ready: 100 explicit command/state cases from 10 reviewed base fixtures; independent review open | Signed Linux/macOS/Windows reports, external review of every ID, zero unexplained differences |
| 10,000 generated executions | Infrastructure ready; last signed baseline 500/500 | Exact-commit 10,000-result manifest across clean/warm/offline/repeat/interrupted modes |
| 250 pinned projects | Inputs frozen: 250 exact locks, 25/category, from run 29366460579; last signed parity baseline 100/100 | Exact-commit 250-project tree/lock/exit results with zero unexplained differences |
| Detection quality | `DetectionEvidenceReport v2` producer and fail-closed aggregator implemented; historical quality still failing | Qualifying frozen malware/private holdout/benign/exfiltration run with corpus digests, exclusions, confidence intervals, and independent holdout custody |
| Native containment | Fail-closed selection implemented; native evidence partial | Zero escapes/leaks/writes/connections/bypasses on every supported OS and external corpus |
| Performance | `PerformanceEvidence v2`, twelve install phases, verified warm no-op, and checksum-verified persistent planner runtime implemented; cross-platform qualification remains open | Exact-commit Linux/macOS/Windows p50/p95 cold/warm/no-op/assessment/exec reports with 200/1,000 required samples, equivalent trees, and accepted phase baseline |
| npm/npx command surface | Command/subcommand/flag manifest, `CompatibilityEvidence v1`, and a 118-case executable command/exec/workspace differential suite are implemented; exact cross-platform qualification remains open | Produce Node 22/24 × Linux/macOS/Windows differential evidence for every command with zero unexplained differences |
| CLI RC window | Signed exact-candidate ledger, prerequisite enforcement, reset rules, and freshness monitor implemented; no real window started | Thirty consecutive public RC days on the exact signed candidate, with daily checksummed observations and no reset-triggering change |

## Registry track

| Gate | Current state | Required evidence |
| --- | --- | --- |
| Single-region beta | Provider-neutral RLS roles/policies, selectable PostgreSQL/Redis rate limits, verified remote-signing contract, isolated analyzer/outbox/maintenance modes, and controlled migrations are implemented locally; managed deployment remains open | Invite-beta deployment evidence, backup restore, hosted tenant-boundary tests, signer/analyzer failure drills |
| Registry durability | PostgreSQL/object storage, digest-verified reads, safe replica repair, atomic stage quotas, fixed-family SLO metrics, replaceable signing/analysis/rate-limit backends, and distributed request windows implemented | `ProductionDeploymentEvidence v1` from managed HA deployment, selected remote signer, CDN, restore/failover/key drills |
| Multi-region durability | Object replica read repair exists; regional routing/global database are not deployed | Two-region deployment, RPO ≤5 minutes, RTO ≤30 minutes, measured replication lag |
| Transparency | Compact inclusion/consistency proofs and signed checkpoints implemented | Rekor-compatible bundles, external/customer witnesses, split-view drill |
| Service objectives | Machine validator and `OperationalDrillReport v2` runner ready; observation window open | 60 consecutive production days meeting `SERVICE_LEVEL_OBJECTIVES.md` plus every required passed drill |
| Independent security | Checksum-locked audit input bundle ready; reviews open | Architecture review, penetration test, and sandbox escape review with no unresolved high/critical findings |
| Legal/compliance | Open | Approved and effective documents listed in `LEGAL_READINESS.md` |
| Customer validation | Open | 50 accepted partners, required active teams/tenants/publishers, retention/conversion/margin metrics, ten verified replacements |
| Registry production window | Signed exact-deployment ledger, prerequisite enforcement, reset rules, and freshness monitor implemented; no real window started | Sixty consecutive production days on the exact signed candidate after all hosted and external prerequisites pass |

The GA evidence generator now emits independent `release_tracks.cli` and
`release_tracks.registry` results while retaining the conservative aggregate
gate for older consumers. It evaluates compatibility, detection, witnessed
transparency, independent audits, the production deployment report, and the
60-day ledger against the exact candidate commit. It exposes
`ga_gate.technical_ready` only when every machine-verifiable technical gate is
green. `ga_gate.ready` remains false until legal and commercial approvals are
also represented by reviewed evidence. A missed gate moves the release date;
it does not change the denominator or threshold.
